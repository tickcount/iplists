import copy
import ipaddress
import json
from pathlib import Path
import random
import tempfile
import unittest
from unittest.mock import patch

import yaml
from scripts import compiler as c
from scripts.domain_policy import DomainPolicy, load_policy
from scripts.ip_coverage import coverage_delta


class MemoryDownloader:
    def __init__(self, value):
        self.body = json.dumps(value).encode()

    def get(self, url):
        return self.body


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.policy = DomainPolicy('com\nco.uk\ngithub.io\n*.ck\n!www.ck\n公司.cn\n',
                                   {'windows.net': 'Shared cloud'}, c.normalize_domain)

    def test_exact_wildcard_exception_idna_and_shared_boundaries(self):
        for value in ['co.uk', 'github.io', 'tenant.ck', 'xn--55qx5d.cn', 'windows.net']:
            self.assertTrue(self.policy.reason(value), value)
        for value in ['example.co.uk', 'user.github.io', 'www.ck', 'a.www.ck', 'a.tenant.ck',
                      'myapp.windows.net', 'notwindows.net']:
            self.assertIsNone(self.policy.reason(value), value)

    def test_source_exception_is_exact_and_recorded(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / 'domains').write_text('windows.net\n')
            source = dict(type='text', data='domains', file='domains')
            with self.assertRaisesRegex(c.BuildError, 'broad domain'):
                c.collect_source('example', source, None, root, self.policy)
            source['allow_broad_domains'] = {'windows.net': 'Reviewed Microsoft group scope'}
            data, report = c.collect_source('example', source, None, root, self.policy)
            self.assertEqual(data['domains'], {'windows.net'})
            self.assertEqual(report['broad_domains']['windows.net']['exception'],
                             'Reviewed Microsoft group scope')
            (root / 'domains').write_text('github.io\n')
            with self.assertRaises(c.BuildError):
                c.collect_source('example', source, None, root, self.policy)

    def test_exclusions_remove_broad_parent_but_preserve_specific_host(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / 'domains').write_text('windows.net\nmyapp.windows.net\n')
            source = dict(type='text', data='domains', file='domains',
                          exclude_domains={'windows.net': 'Shared parent'})
            data, report = c.collect_source('example', source, None, root, self.policy)
            self.assertEqual(data['domains'], {'myapp.windows.net'})
            self.assertIn('windows.net', report['excluded'])

    def test_incomplete_psl_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / 'psl').write_text('com\n')
            with self.assertRaisesRegex(ValueError, 'incomplete'):
                load_policy({'public_suffix_file': 'psl'}, root, c.normalize_domain)


class CoverageTests(unittest.TestCase):
    def test_different_prefix_representation_has_no_address_churn(self):
        result = coverage_delta(['8.8.8.0/25', '8.8.8.128/25'], ['8.8.8.0/24'], 4)
        self.assertEqual(result['addresses_added'], 0)
        self.assertEqual(result['addresses_removed'], 0)
        self.assertEqual(result['addresses_retained'], 256)
        self.assertTrue(result['representation_only'])

    def test_equal_sized_disjoint_sets_have_full_churn(self):
        result = coverage_delta(['8.8.8.0/24'], ['9.9.9.0/24'], 4)
        self.assertEqual(result['addresses_added'], 256)
        self.assertEqual(result['addresses_removed'], 256)
        self.assertEqual(result['addresses_retained'], 0)
        self.assertFalse(result['representation_only'])

    def test_ipv6_large_counts_and_partial_overlap(self):
        result = coverage_delta(['2001:4860::/32'], ['2001:4860::/33'], 6)
        self.assertEqual(result['addresses_removed'], 2**95)
        self.assertEqual(result['addresses_retained'], 2**95)
        self.assertEqual(result['removed_cidr_sample'], ['2001:4860:8000::/33'])

    def test_interval_algorithm_matches_independent_address_sets(self):
        rng = random.Random(921)
        base = int(ipaddress.ip_address('8.8.8.0'))
        for _ in range(100):
            inputs, expanded = [], []
            for side in range(2):
                values, addresses = [], set()
                for _ in range(rng.randrange(15)):
                    prefix = rng.randrange(27, 33)
                    net = ipaddress.ip_network((base + rng.randrange(64), prefix), strict=False)
                    values.append(str(net))
                    addresses.update(net)
                inputs.append(values)
                expanded.append(addresses)
            result = coverage_delta(*inputs, 4)
            self.assertEqual(result['addresses_added'], len(expanded[1] - expanded[0]))
            self.assertEqual(result['addresses_removed'], len(expanded[0] - expanded[1]))
            self.assertEqual(result['addresses_retained'], len(expanded[0] & expanded[1]))


class GitHubTests(unittest.TestCase):
    def setUp(self):
        self.settings = {'category': 'GitHub', 'fields': ['web', 'api']}
        self.normalized = {'GitHub': {'ipv4': ['8.8.8.0/25', '9.9.9.9/32'],
                                     'ipv6': ['2001:4860::1/128']}}
        self.meta = {'web': ['8.8.8.0/24'], 'api': ['8.8.8.0/25', '2001:4860::/126'],
                     'actions': ['1.1.1.0/24'], 'domains': {'website': ['*.github.com']}}

    def test_comparison_deduplicates_and_does_not_add_ranges(self):
        original = copy.deepcopy(self.normalized)
        result = c.verify_github(self.settings, self.normalized, MemoryDownloader(self.meta))
        self.assertEqual(self.normalized, original)
        self.assertEqual(result['mode'], 'comparison-only')
        v4 = result['families']['ipv4']
        self.assertEqual(v4['official_addresses'], 256)
        self.assertEqual(v4['core_addresses_in_official'], 128)
        self.assertEqual(v4['core_addresses_outside_official'], 1)
        self.assertEqual(v4['official_addresses_absent_from_core'], 128)
        self.assertEqual(result['families']['ipv6']['official_addresses_absent_from_core'], 3)
        self.assertNotIn('actions', result['selected_fields'])

    def test_missing_empty_malformed_and_nonpublic_fields_fail(self):
        for values in [None, [], '8.8.8.0/24', ['invalid'], ['10.0.0.0/8']]:
            with self.subTest(values=values), self.assertRaises(c.BuildError):
                c.verify_github(self.settings, self.normalized,
                                MemoryDownloader(dict(self.meta, api=values)))


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'domains.txt'
        self.source.write_text('example.com\n')
        (self.root / 'ips.txt').write_text('8.8.8.0/24\n')
        self.config = self.root / 'config.yml'
        self.settings = {'version': 2, 'sources': {
            'domains': {'type': 'text', 'data': 'domains', 'file': 'domains.txt'},
            'ips': {'type': 'text', 'data': 'ipv4', 'file': 'ips.txt'}},
            'categories': {'GitHub': {'sources': ['domains', 'ips']}}}
        self.out = self.root / 'rules'
        self.diff = self.root / 'diff.json'

    def build(self, **kwargs):
        self.config.write_text(yaml.safe_dump(self.settings))
        return c.build(self.config, self.out, kwargs.pop('downloader', None),
                       no_compile=True, diff_report=self.diff, **kwargs)

    def test_text_exports_match_json_and_empty_sets_are_empty_files(self):
        manifest = self.build()
        for field in c.OUTPUT_FIELDS:
            text = self.out / 'GitHub' / f'{field}.txt'
            rules = json.loads(text.with_suffix('.json').read_text())['rules']
            expected = rules[0][c.rule_key(field)] if rules else []
            self.assertEqual(text.read_text().splitlines(), expected)
            self.assertIn(f'GitHub/{field}.txt', manifest['artifacts'])
        self.assertEqual((self.out / 'GitHub/ip-extended.txt').read_bytes(), b'')
        self.assertFalse((self.out / 'GitHub/bundle.txt').exists())

    def test_equal_sized_change_reports_coverage(self):
        self.build()
        (self.root / 'ips.txt').write_text('9.9.9.0/24\n')
        self.build()
        change = json.loads(self.diff.read_text())['GitHub/ip.json']
        self.assertEqual(change['coverage']['ipv4']['addresses_added'], 256)
        self.assertEqual(change['coverage']['ipv4']['addresses_removed'], 256)

    def test_removed_category_reports_full_coverage_loss(self):
        self.settings['categories']['Old'] = {'sources': ['ips']}
        self.build()
        del self.settings['categories']['Old']
        self.build(allow_large_changes=True)
        change = json.loads(self.diff.read_text())['Old/ip.json']
        self.assertEqual(change['coverage']['ipv4']['addresses_removed'], 256)
        self.assertFalse((self.out / 'Old').exists())

    def test_domain_policy_failure_preserves_previous_tree(self):
        self.build()
        before = {str(p): p.read_bytes() for p in self.out.rglob('*') if p.is_file()}
        self.source.write_text('windows.net\n')
        policy = DomainPolicy('com\n', {'windows.net': 'Shared cloud'}, c.normalize_domain)
        with patch.object(c, 'load_policy', return_value=(policy, {})):
            with self.assertRaisesRegex(c.BuildError, 'broad domain'):
                self.build()
        self.assertEqual(before, {str(p): p.read_bytes() for p in self.out.rglob('*') if p.is_file()})

    def test_api_failure_preserves_previous_tree(self):
        self.build()
        before = {str(p): p.read_bytes() for p in self.out.rglob('*') if p.is_file()}
        self.settings['github_verification'] = {'category': 'GitHub', 'fields': ['web']}
        with self.assertRaises(c.BuildError):
            self.build(downloader=MemoryDownloader({'web': []}))
        self.assertEqual(before, {str(p): p.read_bytes() for p in self.out.rglob('*') if p.is_file()})

    def test_configuration_rejects_unexplained_exceptions_and_runner_ranges(self):
        self.settings['github_verification'] = {'category': 'GitHub', 'fields': ['actions']}
        with self.assertRaises(c.BuildError):
            self.build()
        del self.settings['github_verification']
        self.settings['sources']['domains']['allow_broad_domains'] = {'windows.net': ''}
        with self.assertRaises(c.BuildError):
            self.build()


if __name__ == '__main__':
    unittest.main()
