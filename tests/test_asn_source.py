import json
from pathlib import Path
import tempfile
import unittest
from urllib.parse import parse_qs, urlsplit

from scripts import compiler as c
from scripts.asn_source import read_asns


class RipeDownloader:
    def __init__(self, overrides=None):
        self.overrides = overrides or {}

    def get(self, url):
        asn = parse_qs(urlsplit(url).query)['resource'][0]
        response = {'status': 'ok', 'data': {'resource': asn,
            'prefixes': [{'prefix': '8.8.8.0/24'}, {'prefix': '2001:4860::/32'}],
            'query_starttime': '2026-09-01T00:00:00', 'query_endtime': '2026-09-15T00:00:00'}}
        return json.dumps(self.overrides.get(asn, response)).encode()


class ASNTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'asns.txt').write_text('AS13335\nAS16509\n')
        self.source = {'type': 'asn', 'file': 'asns.txt', 'profile': 'core'}

    def collect(self, downloader=None):
        return c.collect_source('asn', self.source, downloader or RipeDownloader(), self.root)

    def test_local_selection_validation(self):
        self.assertEqual(read_asns(b'AS16509 # example\n13335\n'), [13335, 16509])
        for body in [b'', b'AS0', b'-1', b'AS4294967296', b'AS13335\n13335', b'AS1 AS2']:
            with self.subTest(body=body), self.assertRaises(ValueError):
                read_asns(body)

    def test_public_prefix_union_provenance_and_extended_profile(self):
        data, report = self.collect()
        self.assertEqual(data['ipv4'], {'8.8.8.0/24'})
        self.assertEqual(data['ipv6'], {'2001:4860::/32'})
        self.assertEqual(len(report['asns']), 2)
        self.assertIn('stat.ripe.net', report['asns']['AS13335']['location'])
        self.assertEqual(report['empty_asns'], [])
        self.source['profile'] = 'extended'
        data, _ = self.collect()
        self.assertFalse(data['ipv4'])
        self.assertEqual(data['ipv4-extended'], {'8.8.8.0/24'})

    def test_explicit_empty_response_is_reported(self):
        empty = {'status': 'ok', 'data': {'resource': '13335', 'prefixes': []}}
        data, report = self.collect(RipeDownloader({'AS13335': empty}))
        self.assertTrue(data['ipv4'])
        self.assertEqual(report['empty_asns'], ['AS13335'])

    def test_any_invalid_response_fails_entire_source(self):
        invalid = [None, {}, {'status': 'error'},
                   {'status': 'ok', 'data': {'resource': 'AS999', 'prefixes': []}},
                   {'status': 'ok', 'data': {'resource': 'AS13335'}},
                   {'status': 'ok', 'data': {'resource': 'AS13335', 'prefixes': [{'prefix': '0.0.0.0/0'}]}}]
        for response in invalid:
            with self.subTest(response=response), self.assertRaisesRegex(c.BuildError, 'AS13335'):
                self.collect(RipeDownloader({'AS13335': response}))

    def test_whole_selection_without_public_prefixes_fails(self):
        responses = {asn: {'status': 'ok', 'data': {'resource': asn, 'prefixes': []}}
                     for asn in ['AS13335', 'AS16509']}
        with self.assertRaisesRegex(c.BuildError, 'no public networks'):
            self.collect(RipeDownloader(responses))


if __name__ == '__main__':
    unittest.main()
