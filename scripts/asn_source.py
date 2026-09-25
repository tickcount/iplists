"""Collect ASN announcements directly from RIPEstat, without generated Git lists."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import re


def read_asns(body):
    result = []
    for line in body.decode('utf-8-sig').splitlines():
        value = line.split('#', 1)[0].strip()
        if not value:
            continue
        if not re.fullmatch(r'(?:AS)?[1-9][0-9]*', value):
            raise ValueError(f'invalid ASN: {value!r}')
        number = int(value.removeprefix('AS'))
        if number > 4294967295 or number in result:
            raise ValueError(f'invalid or duplicate ASN: {value}')
        result.append(number)
    if not result:
        raise ValueError('empty ASN selection')
    return sorted(result)


def collect_asns(source, downloader, base, normalize):
    selection = (base / source['file']).read_bytes()
    asns = read_asns(selection)
    peers = source.get('min_peers_seeing', 10)

    def fetch(asn):
        url = f'https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}&min_peers_seeing={peers}'
        try:
            body = downloader.get(url)
            response = json.loads(body)
            if not isinstance(response, dict) or response.get('status') != 'ok':
                raise ValueError('RIPEstat response status is not ok')
            data = response.get('data')
            if not isinstance(data, dict) or str(data.get('resource')).removeprefix('AS') != str(asn):
                raise ValueError('RIPEstat resource does not match requested ASN')
            prefixes = data.get('prefixes')
            if not isinstance(prefixes, list):
                raise ValueError('RIPEstat prefixes must be a list')
            nets, excluded = {4: set(), 6: set()}, {}
            for row in prefixes:
                if not isinstance(row, dict) or not isinstance(row.get('prefix'), str):
                    raise ValueError('invalid RIPEstat prefix record')
                network = normalize(row['prefix'])
                if not network.is_global or network.is_multicast:
                    excluded[row['prefix']] = 'nonpublic or multicast address/network'
                else:
                    nets[network.version].add(str(network))
            return asn, nets, excluded, {
                'location': url, 'sha256': hashlib.sha256(body).hexdigest(),
                'ipv4': len(nets[4]), 'ipv6': len(nets[6]),
                'empty': not prefixes,
                'query_starttime': data.get('query_starttime'),
                'query_endtime': data.get('query_endtime'),
            }
        except Exception as exc:
            raise ValueError(f'AS{asn}: {exc}') from exc

    networks, excluded, reports = {4: set(), 6: set()}, {}, {}
    # Limit concurrent requests; failures are fatal, never skipped.
    with ThreadPoolExecutor(max_workers=source.get('workers', 4)) as pool:
        for asn, nets, skipped, report in pool.map(fetch, asns):
            networks[4].update(nets[4])
            networks[6].update(nets[6])
            excluded.update(skipped)
            reports[f'AS{asn}'] = report
    if not any(networks.values()):
        raise ValueError('ASN selection produced no public networks')
    return networks, {
        'location': source['file'], 'sha256': hashlib.sha256(selection).hexdigest(),
        'method': 'RIPEstat announced-prefixes; default two-week observation window',
        'min_peers_seeing': peers, 'asns': reports,
        'empty_asns': [asn for asn, report in reports.items() if report['empty']],
        'excluded': excluded, 'broad_domains': {}, 'portals': {},
    }
