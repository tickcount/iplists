import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

import yaml
from scripts import compiler as c


def portal(name='example.com', **updates):
    row = dict(name=name, group='service', domains=[name], ip4=['8.8.8.8'],
               ip6=['2001:4860:4860::8888'], cidr4=['8.8.8.0/24'], cidr6=[], replace={})
    row.update(updates)
    return row


class MemoryDownloader:
    def __init__(self, value):
        self.value = value

    def get(self, url):
        return json.dumps(self.value).encode()


class NormalizationTests(unittest.TestCase):
    def test_invalid_entries_fail(self):
        for value in ['<html>error</html>', 'mailto', 'x.com @ads', '?.apple.com', '999.999.999.999', 'example.com..']:
            with self.subTest(value=value), self.assertRaises(c.BuildError):
                c.normalize_domain(value)
        for value in ['999.999.999.999/99', '2001:::1/999', '8.8.8.1/24', '0.0.0.0/0']:
            with self.subTest(value=value), self.assertRaises(c.BuildError):
                c.normalize_network(value)

    def test_domains_and_dns_labels(self):
        self.assertEqual(c.normalize_domain('EXAMPLE.COM.'), 'example.com')
        self.assertEqual(c.normalize_domain('пример.рф'), 'xn--e1afmkfd.xn--p1ai')
        self.assertEqual(c.normalize_domain('_domainkey.example.com'), '_domainkey.example.com')
        self.assertEqual(c.minimize_domains(['a.example.com', 'example.com', 'notexample.com']),
                         ['example.com', 'notexample.com'])

    def test_lossless_collapse(self):
        self.assertEqual(c.collapse(['8.8.8.0/25', '8.8.8.128/25', '8.8.8.1/32']), ['8.8.8.0/24'])
        self.assertEqual(c.collapse(['8.8.8.1/32', '8.8.8.3/32']), ['8.8.8.1/32', '8.8.8.3/32'])

    def test_domain_minimization_preserves_shared_hosting_boundaries(self):
        values = ['github.com', 'api.github.com', 'notgithub.com',
                  'github-cloud.s3.amazonaws.com', 'mavenregistryv2prod.blob.core.windows.net',
                  'a.example.co.uk', 'b.example.co.uk']
        result = c.minimize_domains(values)
        self.assertEqual(result, sorted(set(values) - {'api.github.com'}))
        self.assertEqual(c.minimize_domains(result), result)

    def test_ipv6_collapse_preserves_gaps(self):
        self.assertEqual(c.collapse(['2001:4860::/127', '2001:4860::2/127',
                                     '2001:4860::8/128']),
                         ['2001:4860::/126', '2001:4860::8/128'])

    def test_overlap_count(self):
        left = [c.normalize_network('8.8.8.0/24')]
        right = [c.normalize_network('8.8.8.128/25'), c.normalize_network('9.9.9.0/24')]
        self.assertEqual(c.intersect_size(left, right), 128)


class SourceTests(unittest.TestCase):
    def setUp(self):
        self.source = dict(type='iplist', url='https://example.test/', sites=['example.com'])

    def collect(self, rows, source=None):
        return c.collect_source('test', source or self.source, MemoryDownloader(rows), Path('.'))

    def test_observed_and_extended_are_separate_and_replace_is_applied(self):
        data, _ = self.collect({'example.com': portal(replace={'cidr4': {'8.8.8.0/24': ['8.8.8.8/32']}})})
        self.assertEqual(data['ipv4'], set())
        self.assertEqual(data['ipv4-observed'], {'8.8.8.8/32'})
        self.assertEqual(data['ipv4-extended'], {'8.8.8.8/32'})
        self.assertNotIn('8.8.8.0/24', data['ipv4-extended'])

    def test_missing_portal_and_missing_field_fail(self):
        for rows in [{}, {'other.com': portal('other.com')}, {'example.com': portal(ip4=None)}]:
            with self.subTest(rows=rows), self.assertRaises(c.BuildError):
                self.collect(rows)

    def test_empty_family_is_allowed_and_hosts_may_not_be_cidrs(self):
        data, _ = self.collect({'example.com': portal(ip6=[])})
        self.assertEqual(data['ipv6'], set())
        with self.assertRaises(c.BuildError):
            self.collect({'example.com': portal(ip4=['8.8.8.0/24'])})

    def test_group_membership_checked(self):
        source = dict(type='iplist', url='https://example.test/', groups=['service'], expected_sites=['example.com'])
        with self.assertRaises(c.BuildError):
            self.collect({'example.com': portal(group='other')}, source)

    def test_known_exclusions_are_reported_new_errors_fail(self):
        source = dict(self.source, exclude_domains={'bad @ entry': 'known upstream error'})
        data, report = self.collect({'example.com': portal(domains=['example.com', 'bad @ entry'], ip4=['127.0.0.1', '8.8.8.8'])}, source)
        self.assertEqual(data['domains'], {'example.com'})
        self.assertEqual(data['ipv4-observed'], {'8.8.8.8/32'})
        self.assertIn('bad @ entry', report['excluded'])
        self.assertIn('127.0.0.1', report['excluded'])
        with self.assertRaises(c.BuildError):
            self.collect({'example.com': portal(domains=['example.com', 'new @ error'])}, source)

    def test_text_relative_path_comments_bom_and_empty(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'list.txt'
            source = dict(type='text', file='list.txt', data='networks')
            path.write_text('\ufeff# comment\n8.8.8.0/24 # inline\n2001:4860::/32\n')
            data, _ = c.collect_source('local', source, None, Path(td))
            self.assertEqual(data['ipv4'], {'8.8.8.0/24'})
            self.assertEqual(data['ipv6'], {'2001:4860::/32'})
            path.write_text('# empty\n')
            with self.assertRaises(c.BuildError):
                c.collect_source('local', source, None, Path(td))

    def test_html_response_fails(self):
        downloader = MemoryDownloader(None)
        downloader.get = lambda url: b'<html>maintenance</html>'
        with self.assertRaises(c.BuildError):
            c.collect_source('html', self.source, downloader, Path('.'))


class DownloadTests(unittest.TestCase):
    def test_retry_then_offline_snapshot(self):
        with tempfile.TemporaryDirectory() as td:
            with patch('urllib.request.urlopen', side_effect=[TimeoutError(), io.BytesIO(b'example.com')]) as request, patch('time.sleep'):
                self.assertEqual(c.Downloader(td).get('https://example.test/'), b'example.com')
                self.assertEqual(request.call_count, 2)
            with patch('urllib.request.urlopen', side_effect=AssertionError('offline network access')):
                self.assertEqual(c.Downloader(td, offline=True).get('https://example.test/'), b'example.com')

    def test_failure_never_falls_back_to_old_cache(self):
        with tempfile.TemporaryDirectory() as td:
            with patch('urllib.request.urlopen', return_value=io.BytesIO(b'old')):
                c.Downloader(td).get('https://example.test/')
            with patch('urllib.request.urlopen', side_effect=TimeoutError()), patch('time.sleep'):
                with self.assertRaises(c.BuildError):
                    c.Downloader(td).get('https://example.test/')


class BuildTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = self.root / 'config.yml'
        self.output = self.root / 'rules'
        self.source = self.root / 'domains.txt'
        self.source.write_text('example.com\n')
        self.settings = dict(version=2, sources={'local': dict(type='text', file='domains.txt', data='domains')},
                             categories={'AI': {'sources': ['local']}})
        self.save_config()

    def save_config(self):
        self.config.write_text(yaml.safe_dump(self.settings))

    def build(self, **kwargs):
        return c.build(self.config, self.output, c.Downloader(self.root / 'cache'), **kwargs)

    def snapshot(self):
        return {str(p.relative_to(self.output)): p.read_bytes() for p in self.output.rglob('*') if p.is_file()}

    def test_deterministic_complete_tree_and_empty_family(self):
        self.build(no_compile=True)
        before = self.snapshot()
        self.build(no_compile=True)
        self.assertEqual(before, self.snapshot())
        self.assertEqual(json.loads((self.output / 'AI/ip.json').read_text())['rules'], [])
        self.assertEqual(len(list(self.output.glob('AI/*.json'))), 6)

    def test_bundle_contains_core_domains_and_both_ip_families_only(self):
        (self.root / 'ips.txt').write_text('8.8.8.8\n2001:4860:4860::8888\n')
        (self.root / 'extended.txt').write_text('8.8.0.0/16\n')
        self.settings['sources']['ips'] = dict(type='text', file='ips.txt', data='networks')
        self.settings['sources']['extended'] = dict(type='text', file='extended.txt', data='ipv4', profile='extended')
        self.settings['categories']['AI']['sources'] += ['ips', 'extended']
        self.save_config()
        self.build(no_compile=True)
        rule = json.loads((self.output / 'AI/bundle.json').read_text())['rules'][0]
        self.assertEqual(rule['domain_suffix'], ['example.com'])
        self.assertEqual(rule['ip_cidr'], ['8.8.8.8/32', '2001:4860:4860::8888/128'])
        self.assertNotIn('8.8.0.0/16', rule['ip_cidr'])
        if os.environ.get('SING_BOX'):
            c.compile_srs(self.output / 'AI/bundle.json', os.environ['SING_BOX'])
            for query, expected in [('example.com', True), ('8.8.8.8', True), ('2001:4860:4860::8888', True), ('8.8.1.1', False), ('unrelated.test', False)]:
                result = subprocess.run([os.environ['SING_BOX'], 'rule-set', 'match', '--format', 'binary',
                    str(self.output / 'AI/bundle.srs'), query], check=True, capture_output=True, text=True)
                self.assertEqual('match rules.' in result.stdout + result.stderr, expected, query)

    def test_observed_hosts_are_exported_but_never_enter_core_or_bundle(self):
        self.settings['sources']['observed'] = dict(type='iplist', url='https://example.test/', sites=['example.com'])
        self.settings['categories']['AI']['sources'].append('observed')
        (self.root / 'official.txt').write_text('9.9.9.0/24\n')
        self.settings['sources']['official'] = dict(type='text', file='official.txt', data='networks', profile='core')
        self.settings['categories']['AI']['sources'].append('official')
        self.save_config()
        c.build(self.config, self.output, MemoryDownloader({'example.com': portal()}), no_compile=True)
        bundle = json.loads((self.output / 'AI/bundle.json').read_text())['rules'][0]
        self.assertEqual(bundle['ip_cidr'], ['9.9.9.0/24'])
        self.assertEqual(bundle['domain_suffix'], ['example.com'])
        observed = json.loads((self.output / 'AI/ip-observed.json').read_text())['rules'][0]['ip_cidr']
        self.assertEqual(observed, ['8.8.8.8/32', '2001:4860:4860::8888/128'])
        self.assertEqual(json.loads((self.output / 'AI/ip.json').read_text())['rules'][0]['ip_cidr'], ['9.9.9.0/24'])
        self.assertEqual(json.loads((self.output / 'AI/ip-extended.json').read_text())['rules'][0]['ip_cidr'], ['8.8.8.0/24'])
        metrics = json.loads((self.output / 'manifest.json').read_text())['files']['AI/ip-observed.json']
        self.assertEqual((metrics['ipv4_addresses'], metrics['ipv6_addresses']), (1, 1))
        if os.environ.get('SING_BOX'):
            c.compile_srs(self.output / 'AI/bundle.json', os.environ['SING_BOX'])
            for query, expected in [('example.com', True), ('9.9.9.1', True), ('8.8.8.8', False), ('2001:4860:4860::8888', False), ('8.8.1.1', False)]:
                result = subprocess.run([os.environ['SING_BOX'], 'rule-set', 'match', '--format', 'binary',
                    str(self.output / 'AI/bundle.srs'), query], check=True, capture_output=True, text=True)
                self.assertEqual('match rules.' in result.stdout + result.stderr, expected, query)

    def test_explain_finds_original_source(self):
        report = c.explain(self.config, None, 'sub.example.com')
        self.assertEqual(report['matches'][0]['source'], 'local')
        self.assertEqual(report['matches'][0]['records'], ['example.com'])

    def test_same_size_change_is_present_in_diff(self):
        self.build(no_compile=True)
        self.source.write_text('changed.com\n')
        diff = self.root / 'diff.json'
        self.build(no_compile=True, diff_report=diff)
        change = json.loads(diff.read_text())['AI/domains.json']
        self.assertEqual(change['added_sample'], ['changed.com'])
        self.assertEqual(change['removed_sample'], ['example.com'])

    def test_diff_cannot_overwrite_output(self):
        with self.assertRaises(c.BuildError):
            self.build(no_compile=True, diff_report=self.output / 'manifest.json')

    def test_managed_directory_cannot_silently_delete_user_files(self):
        self.build(no_compile=True)
        extra = self.output / 'AI/notes.txt'
        extra.write_text('keep')
        with self.assertRaises(c.BuildError):
            self.build(no_compile=True)
        self.assertEqual(extra.read_text(), 'keep')

    def test_finder_metadata_is_preserved_outside_manifest(self):
        self.build(no_compile=True)
        metadata = self.output / '.DS_Store'
        metadata.write_bytes(b'finder metadata')
        manifest = self.build(no_compile=True)
        self.assertEqual(metadata.read_bytes(), b'finder metadata')
        self.assertNotIn('.DS_Store', manifest['artifacts'])

    def test_failed_source_preserves_tree(self):
        self.build(no_compile=True)
        before = self.snapshot()
        self.source.unlink()
        with self.assertRaises(c.BuildError):
            self.build(no_compile=True)
        self.assertEqual(before, self.snapshot())

    def test_compile_failure_preserves_tree(self):
        self.build(no_compile=True)
        before = self.snapshot()
        with patch.object(c, 'compile_srs', side_effect=c.BuildError('simulated failure')):
            with self.assertRaises(c.BuildError):
                self.build()
        self.assertEqual(before, self.snapshot())

    def test_category_removal_requires_review_and_removes_stale_files(self):
        self.settings['categories']['Old'] = {'sources': ['local']}
        self.save_config()
        self.build(no_compile=True)
        before = self.snapshot()
        del self.settings['categories']['Old']
        self.save_config()
        with self.assertRaises(c.BuildError):
            self.build(no_compile=True)
        self.assertEqual(before, self.snapshot())
        self.build(no_compile=True, allow_large_changes=True)
        self.assertFalse((self.output / 'Old').exists())

    def test_shrinking_nonempty_set_is_blocked(self):
        self.source.write_text('a.com\nb.com\nc.com\nd.com\n')
        self.build(no_compile=True)
        before = self.snapshot()
        self.source.write_text('a.com\n')
        with self.assertRaises(c.BuildError):
            self.build(no_compile=True)
        self.assertEqual(before, self.snapshot())

    def test_nested_output_config_and_unknown_directory_are_protected(self):
        with self.assertRaises(c.BuildError):
            c.build(self.config, self.root, None, no_compile=True)
        self.output.mkdir()
        (self.output / 'important.txt').write_text('keep')
        with self.assertRaises(c.BuildError):
            self.build(no_compile=True)
        self.assertTrue((self.output / 'important.txt').exists())

    def test_category_path_traversal_rejected(self):
        self.settings['categories'] = {'../escape': {'sources': ['local']}}
        self.save_config()
        with self.assertRaises(c.BuildError):
            self.build(no_compile=True)

    def test_lock_prevents_concurrent_publishing(self):
        with c.output_lock(self.output):
            with self.assertRaises(c.BuildError):
                self.build(no_compile=True)

    def test_publish_rollback(self):
        self.build(no_compile=True)
        before = self.snapshot()
        stage = self.root / 'stage'
        stage.mkdir()
        real_replace = Path.replace
        def fail_final(path, target):
            if path == stage:
                raise OSError('simulated rename failure')
            return real_replace(path, target)
        with patch.object(Path, 'replace', fail_final):
            with self.assertRaises(OSError):
                c.publish(stage, self.output)
        self.assertEqual(before, self.snapshot())

    @unittest.skipUnless(os.environ.get('SING_BOX'), 'Set SING_BOX for real binary integration')
    def test_real_srs_compilation_and_json_only_guard(self):
        self.build(binary=os.environ['SING_BOX'])
        self.assertEqual(len(list(self.output.glob('AI/*.srs'))), 6)
        before = self.snapshot()
        with self.assertRaises(c.BuildError):
            self.build(no_compile=True)
        self.assertEqual(before, self.snapshot())


class SingboxIPTests(unittest.TestCase):
    def collect(self, ruleset, profile='core'):
        source = dict(type='singbox-ip', url='https://example.test/rules.json', profile=profile)
        return c.collect_source('rkn', source, MemoryDownloader(ruleset), Path('.'))

    def test_ipv4_ipv6_and_normalization(self):
        data, report = self.collect({'version': 1, 'rules': [{'ip_cidr': ['8.8.8.0/24', '2001:4860::/32', '8.8.8.0/24']}]})
        self.assertEqual(data['ipv4'], {'8.8.8.0/24'})
        self.assertEqual(data['ipv6'], {'2001:4860::/32'})
        self.assertFalse(data['domains'])
        self.assertEqual(report['counts']['ipv4'], 1)

    def test_extended_profile_is_explicit(self):
        data, _ = self.collect({'version': 3, 'rules': [{'ip_cidr': ['8.8.8.0/24']}]}, 'extended')
        self.assertFalse(data['ipv4'])
        self.assertEqual(data['ipv4-extended'], {'8.8.8.0/24'})

    def test_conditional_rules_cannot_be_silently_broadened(self):
        for extra in [{'invert': True}, {'port': [443]}, {'domain_suffix': ['example.com']}, {'network': 'tcp'}]:
            with self.subTest(extra=extra), self.assertRaises(c.BuildError):
                self.collect({'version': 3, 'rules': [dict(ip_cidr=['8.8.8.0/24'], **extra)]})

    def test_bad_schemas_and_empty_lists_fail(self):
        cases = [None, [], {}, {'version': 99, 'rules': []}, {'version': True, 'rules': []},
                 {'version': 1, 'rules': []}, {'version': 1, 'rules': [{'ip_cidr': []}]},
                 {'version': 1, 'rules': [{'ip_cidr': '8.8.8.8'}]},
                 {'version': 1, 'rules': [{'ip_cidr': ['999.1.1.1']}]},
                 {'version': 1, 'rules': [{'ip_cidr': ['0.0.0.0/0']}]}]
        for case in cases:
            with self.subTest(case=case), self.assertRaises(c.BuildError):
                self.collect(case)

    def test_nonpublic_ranges_are_reported(self):
        data, report = self.collect({'version': 1, 'rules': [{'ip_cidr': ['10.0.0.0/8', '8.8.8.0/24']}]})
        self.assertEqual(data['ipv4'], {'8.8.8.0/24'})
        self.assertIn('10.0.0.0/8', report['excluded'])

    def test_only_nonpublic_ranges_is_an_error(self):
        with self.assertRaises(c.BuildError):
            self.collect({'version': 1, 'rules': [{'ip_cidr': ['10.0.0.0/8']}]})


if __name__ == '__main__':
    unittest.main()
