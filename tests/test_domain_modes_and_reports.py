import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml
from scripts import compiler as c
from scripts.ci_summary import render
from scripts.domain_policy import DomainPolicy


class DomainModeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / 'config.yml'
        self.out = self.root / 'rules'
        self.report = self.root / 'build-report.json'
        self.settings = {'version': 2, 'sources': {
            'suffix': {'type': 'text', 'data': 'domains', 'file': 'suffix.txt'},
            'exact': {'type': 'text', 'data': 'domains', 'file': 'exact.txt', 'domain_match': 'exact'}},
            'categories': {'Example': {'sources': ['suffix', 'exact']}}}
        (self.root / 'suffix.txt').write_text('example.com\n')
        (self.root / 'exact.txt').write_text('host.other.com\nsub.host.other.com\napi.example.com\n')

    def build(self, **kwargs):
        self.path.write_text(yaml.safe_dump(self.settings))
        return c.build(self.path, self.out, None, build_report=self.report, **kwargs)

    def test_exact_names_do_not_collapse_under_exact_parent(self):
        self.build(no_compile=True)
        rules = json.loads((self.out / 'Example/domains-exact.json').read_text())['rules']
        self.assertEqual(rules, [{'domain': ['host.other.com', 'sub.host.other.com']}])
        self.assertEqual((self.out / 'Example/domains-exact.txt').read_text(),
                         'host.other.com\nsub.host.other.com\n')
        self.assertEqual(c.explain(self.path, None, 'child.host.other.com')['matches'], [])
        self.assertEqual(c.explain(self.path, None, 'host.other.com')['matches'][0]['field'], 'domains-exact')

    @unittest.skipUnless(os.environ.get('SING_BOX'), 'requires sing-box')
    def test_binary_bundle_matches_exact_and_suffix_as_or(self):
        self.build(binary=os.environ['SING_BOX'])
        for name, expected in [('host.other.com', True), ('child.host.other.com', False),
                               ('sub.host.other.com', True), ('api.example.com', True),
                               ('unrelated.com', False)]:
            result = subprocess.run([os.environ['SING_BOX'], 'rule-set', 'match', '--format', 'binary',
                                     str(self.out / 'Example/bundle.srs'), name],
                                    check=True, capture_output=True, text=True)
            self.assertEqual('match rules.' in result.stdout + result.stderr, expected, name)

    def test_cloud_override_does_not_promote_parent_or_similar_suffix(self):
        (self.root / 'suffix.txt').write_text('bucket.s3.amazonaws.com\ns3.amazonaws.com\nevilamazonaws.com\n')
        source = dict(self.settings['sources']['suffix'], exact_domain_suffixes=['s3.amazonaws.com'])
        data, _ = c.collect_source('test', source, None, self.root)
        self.assertEqual(data['domains-exact'], {'bucket.s3.amazonaws.com'})
        self.assertEqual(data['domains'], {'s3.amazonaws.com', 'evilamazonaws.com'})

    def test_exact_name_does_not_need_suffix_exception(self):
        (self.root / 'exact.txt').write_text('tenant.ck\n')
        policy = DomainPolicy('*.ck\n', {}, c.normalize_domain)
        data, report = c.collect_source('test', self.settings['sources']['exact'], None, self.root, policy)
        self.assertEqual(data['domains-exact'], {'tenant.ck'})
        self.assertEqual(report['broad_domains'], {})

    def test_invalid_mode_fails(self):
        self.settings['sources']['exact']['domain_match'] = 'wildcard'
        with self.assertRaisesRegex(c.BuildError, 'domain_match'):
            self.build(no_compile=True)

    def test_failure_report_identifies_source_without_old_success(self):
        self.build(no_compile=True)
        (self.root / 'exact.txt').unlink()
        with self.assertRaises(c.BuildError):
            self.build(no_compile=True)
        report = json.loads(self.report.read_text())
        self.assertEqual(report['status'], 'failed')
        self.assertEqual(report['active_source'], 'exact')
        self.assertEqual(report['files'], {})
        self.assertIn('not published', render(report, 'failure'))
        self.assertNotIn('Build succeeded', render(report, 'failure'))

    def test_threshold_failure_report_retains_candidate_changes(self):
        (self.root / 'suffix.txt').write_text('one.com\ntwo.com\nthree.com\nfour.com\n')
        self.build(no_compile=True)
        (self.root / 'suffix.txt').write_text('one.com\n')
        with self.assertRaisesRegex(c.BuildError, 'large changes'):
            self.build(no_compile=True)
        report = json.loads(self.report.read_text())
        self.assertEqual(report['stage'], 'validating changes')
        self.assertEqual(report['changes']['Example/domains.json']['removed'], 3)

    def test_report_cannot_overwrite_config_or_generated_output(self):
        self.path.write_text(yaml.safe_dump(self.settings))
        for path in [self.path, self.out / 'report.json']:
            with self.assertRaises(c.BuildError):
                c.build(self.path, self.out, None, no_compile=True, build_report=path)

    def test_summary_escapes_source_data_and_handles_skipped_build(self):
        report = {'status': 'failed', 'error': '<script>|[click](url)\nrow',
                  'sources': {'unsafe|source': {'location': '<x>', 'sha256': 'abc',
                      'excluded': {'bad|domain': '<reason>'}}}}
        summary = render(report, 'failure')
        self.assertNotIn('<script>', summary)
        self.assertNotIn('unsafe|source', summary)
        self.assertIn('&lt;script&gt;', summary)
        self.assertIn('No build report', render({}, 'skipped'))
        self.assertNotIn('Build succeeded', render({'status': 'success'}, 'failure'))

    def test_split_ip_migration_keeps_baseline_and_removes_old_files(self):
        self.build(no_compile=True)
        folder = self.out / 'Example'
        (folder / 'ip.json').unlink()
        (folder / 'ip.txt').unlink()
        c.write_json(folder / 'ipv4.json', {'version': 3, 'rules': []})
        c.write_json(folder / 'ipv6.json', {'version': 3, 'rules': []})
        manifest = json.loads((self.out / 'manifest.json').read_text())
        del manifest['files']['Example/ip.json']
        for field in ['ipv4', 'ipv6']:
            manifest['files'][f'Example/{field}.json'] = {'entries': 0, 'addresses': 0}
        manifest['artifacts'] = {str(p.relative_to(self.out)): c.digest(p.read_bytes())
                                 for p in self.out.rglob('*') if p.is_file() and p.name != 'manifest.json'}
        c.write_json(self.out / 'manifest.json', manifest)
        self.build(no_compile=True)
        self.assertFalse((folder / 'ipv4.json').exists())
        self.assertFalse((folder / 'ipv6.json').exists())
        self.assertNotIn('Example/ip.json', json.loads(self.report.read_text())['changes'])


if __name__ == '__main__':
    unittest.main()
