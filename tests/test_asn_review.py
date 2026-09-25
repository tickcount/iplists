from datetime import datetime, timezone
import json
import unittest

import yaml

from scripts.asn_review import build_report, observations, parse_source, render


NOW = datetime(2026, 9, 25, tzinfo=timezone.utc)
SHA = 'a' * 40
SOURCES = [
    {'id': 'community', 'repo': 'example/lists', 'ref': 'main', 'path': 'workflow.yml',
     'parser': 'asn-heredoc', 'evidence_kind': 'community-selection'},
    {'id': 'diagnostic', 'repo': 'example/checker', 'ref': 'main', 'path': 'config.yml',
     'parser': 'dpi-targets', 'section': 'Foreign', 'evidence_kind': 'diagnostic-target'},
]


def workflow(block='13335 16509'):
    return yaml.safe_dump({'jobs': {'build': {'steps': [
        {'run': f'cat <<EOF > asn_numbers.txt\n{block}\nEOF\necho AS12345'}]}}}).encode()


def diagnostic():
    return yaml.safe_dump({'checkers': {'webhost': {'sections': [
        {'name': 'Foreign', 'targets': [
            {'name': 'One', 'filter': 'as(8075, 16509)'},
            {'name': 'Search', 'filter': 'org("some hoster")'},
            {'name': 'Constrained', 'filter': 'as(12345) && country("de")'}]},
        {'name': 'Controls', 'targets': [{'name': 'Control', 'filter': 'as(6789)'}]}
    ]}}}).encode()


class Downloader:
    offline = False

    def __init__(self, fail=False):
        self.fail = fail

    def get(self, url):
        if self.fail and 'example/lists' in url:
            raise ValueError('<upstream unavailable>')
        if url.startswith('https://api.github.com/'):
            return json.dumps({'sha': SHA, 'commit': {'committer': {'date': '2026-09-24T00:00:00Z'}}}).encode()
        if f'/{SHA}/' not in url:
            raise AssertionError('data download must use immutable revision')
        return workflow() if url.endswith('workflow.yml') else diagnostic()


class ASNReviewTests(unittest.TestCase):
    def build(self, downloader=None, observation_body=None):
        return build_report({'version': 1, 'sources': SOURCES}, b'AS13335\nAS999\n',
                            downloader or Downloader(), NOW, observation_body)

    def test_only_data_block_is_read_and_commands_never_executed(self):
        entries, _ = parse_source(workflow(), SOURCES[0])
        self.assertEqual(set(entries), {13335, 16509})
        for block in ('', '13335 $(echo 1)', '0', '4294967296', '13335 13335'):
            with self.subTest(block=block), self.assertRaises(ValueError):
                parse_source(workflow(block), SOURCES[0])

    def test_missing_or_duplicate_heredoc_fails(self):
        for run in ('echo AS13335', 'cat <<EOF > asn_numbers.txt\n1\nEOF\n' * 2):
            body = yaml.safe_dump({'jobs': {'a': {'steps': [{'run': run}]}}}).encode()
            with self.assertRaises(ValueError):
                parse_source(body, SOURCES[0])

    def test_controls_and_constrained_filters_do_not_become_candidates(self):
        entries, unresolved = parse_source(diagnostic(), SOURCES[1])
        self.assertEqual(set(entries), {8075, 16509})
        self.assertEqual(len(unresolved), 2)

    def test_report_compares_sources_separately_and_keeps_evidence(self):
        report = self.build()
        self.assertEqual(report['status'], 'complete')
        self.assertEqual([x['asn'] for x in report['candidates']], [8075, 16509])
        self.assertEqual(len(report['candidates'][1]['evidence']), 2)
        self.assertEqual(report['sources']['community']['selected_not_in_source'], [999])
        self.assertNotIn('selected_not_in_source', report['sources']['diagnostic'])
        self.assertEqual(report['sources']['community']['revision'], SHA)
        self.assertEqual(len(report['sources']['community']['sha256']), 64)

    def test_failed_source_is_unknown_not_empty_and_summary_escapes_html(self):
        report = self.build(Downloader(fail=True))
        self.assertEqual(report['status'], 'partial')
        self.assertNotIn('selected_not_in_source', report['sources']['community'])
        summary = render(report)
        self.assertIn('&lt;upstream unavailable&gt;', summary)
        self.assertIn('unknown', summary)

    def test_offline_snapshot_not_claimed_live(self):
        downloader = Downloader()
        downloader.offline = True
        self.assertEqual(self.build(downloader)['mode'], 'offline-snapshots')

    def observation(self, **overrides):
        return {'asn': 54321, 'operator': 'Test ISP', 'method': '64 KiB test, sampled IP',
                'source_url': 'https://example.org/report', 'observed_at': '2026-09-24T00:00:00Z',
                'result': 'restriction-observed', **overrides}

    def body(self, rows):
        return json.dumps({'version': 1, 'observations': rows}).encode()

    def test_only_recent_restriction_observations_propose_candidates(self):
        rows = [self.observation(), self.observation(asn=12345, observed_at='2025-01-01T00:00:00Z'),
                self.observation(asn=54322, result='reachable'),
                self.observation(asn=54323, result='inconclusive')]
        report = self.build(observation_body=self.body(rows))
        self.assertEqual([x['asn'] for x in report['candidates']], [8075, 16509, 54321])
        self.assertTrue(report['observations'][1]['stale'])

    def test_unattributed_invalid_and_future_observations_rejected(self):
        for fields in ({'operator': ''}, {'method': ''}, {'source_url': 'http://example.org'},
                       {'observed_at': '2026-09-26T00:00:00Z'}, {'observed_at': '2026-09-24'},
                       {'asn': True}, {'result': 'blocked'}):
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                observations(self.body([self.observation(**fields)]), NOW, 30)

    def test_bad_observation_input_keeps_source_report_but_fails_review(self):
        report = self.build(observation_body=b'not json')
        self.assertEqual(report['status'], 'partial')
        self.assertEqual(report['sources']['community']['status'], 'ok')
        self.assertIn('observations_error', report)

    def test_summary_is_bounded(self):
        report = self.build()
        report['candidates'] = [{'asn': n, 'evidence': [{'kind': 'diagnostic-target'}]} for n in range(1, 1001)]
        self.assertIn('AS100 ', render(report))
        self.assertNotIn('AS101 ', render(report))
