#!/usr/bin/env python3
"""Collect advisory ASN candidates. Never edit the reviewed selection or rules."""
import argparse
from datetime import datetime, timezone, timedelta
import hashlib
import html
import json
from pathlib import Path
import re
from urllib.parse import quote, urlsplit

import yaml

if __package__:
    from .asn_source import read_asns
    from .compiler import Downloader, ROOT
else:
    from asn_source import read_asns
    from compiler import Downloader, ROOT


def parse_source(body, source):
    document = yaml.safe_load(body)
    entries, unresolved = {}, []
    if source['parser'] == 'asn-heredoc':
        # Read only the known data heredoc; never execute upstream workflow code.
        blocks = []
        for job in document['jobs'].values():
            for step in job.get('steps', []):
                run = step.get('run', '')
                blocks.extend(re.findall(
                    r"(?m)^\s*cat\s+<<EOF\s*>\s*asn_numbers\.txt\s*\n(.*?)^EOF\s*$",
                    run, re.DOTALL))
        if len(blocks) != 1:
            raise ValueError('expected exactly one ASN data heredoc')
        numbers = read_asns('\n'.join(blocks[0].split()).encode())
        entries = {number: ['upstream ASN selection'] for number in numbers}
    elif source['parser'] == 'dpi-targets':
        sections = [section for section in document['checkers']['webhost']['sections']
                    if section['name'] == source['section']]
        if len(sections) != 1 or not sections[0]['targets']:
            raise ValueError('expected one nonempty diagnostic section')
        for target in sections[0]['targets']:
            expression = target['filter'].strip()
            # Do not expand organization searches or discard country/subnet constraints.
            match = re.fullmatch(r'as\(\s*([0-9]+(?:\s*,\s*[0-9]+)*)\s*\)', expression)
            if not match:
                unresolved.append({'target': target['name'], 'filter': expression})
                continue
            for number in read_asns(match[1].replace(',', '\n').encode()):
                entries.setdefault(number, []).append(target['name'])
    else:
        raise ValueError('unknown source parser')
    if not entries:
        raise ValueError('source produced no explicit ASNs')
    return entries, unresolved


def fetch_source(source, downloader):
    repo, ref, path = source['repo'], source['ref'], source['path']
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repo):
        raise ValueError('invalid GitHub repository')
    api = f'https://api.github.com/repos/{repo}/commits/{quote(ref, safe="")}'
    commit = json.loads(downloader.get(api))
    revision = commit['sha']
    if not re.fullmatch(r'[0-9a-f]{40}', revision):
        raise ValueError('invalid GitHub revision')
    location = f'https://raw.githubusercontent.com/{repo}/{revision}/{quote(path, safe="/")}'
    body = downloader.get(location)
    entries, unresolved = parse_source(body, source)
    return entries, {
        'status': 'ok', 'evidence_kind': source['evidence_kind'],
        'location': location, 'revision': revision,
        # Repository commit date is not the date of an observation or file change.
        'repository_commit_at': commit['commit']['committer']['date'],
        'sha256': hashlib.sha256(body).hexdigest(),
        'unresolved_filters': unresolved,
    }


def timestamp(value):
    result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if result.tzinfo is None:
        raise ValueError('timestamps must include a timezone')
    return result


def observations(body, now, max_age_days):
    """Accept attributed external observations, not inferred availability claims."""
    document = json.loads(body)
    if document.get('version') != 1 or not isinstance(document.get('observations'), list):
        raise ValueError('expected observations schema version 1')
    result = []
    for row in document['observations']:
        if not isinstance(row, dict) or type(row.get('asn')) is not int:
            raise ValueError('observation requires an integer ASN')
        read_asns(str(row['asn']).encode())
        for key in ('operator', 'method', 'source_url', 'observed_at', 'result'):
            if not isinstance(row.get(key), str) or not row[key].strip():
                raise ValueError(f'observation requires {key}')
        url = urlsplit(row['source_url'])
        if url.scheme != 'https' or not url.netloc or url.username or url.password:
            raise ValueError('observation requires an HTTPS source without credentials')
        if row['result'] not in ('restriction-observed', 'reachable', 'inconclusive'):
            raise ValueError('unknown observation result')
        observed = timestamp(row['observed_at'])
        if observed > now:
            raise ValueError('observation is in the future')
        result.append({key: row[key] for key in
                       ('asn', 'operator', 'method', 'source_url', 'observed_at', 'result')} |
                      {'stale': now - observed > timedelta(days=max_age_days),
                       'scope': 'reported sample, not the entire ASN'})
    return result


def build_report(config, selection, downloader, now, observation_body=None, max_age_days=30):
    if config.get('version') != 1 or not isinstance(config.get('sources'), list) or not config['sources']:
        raise ValueError('expected nonempty review sources schema version 1')
    ids = [source['id'] for source in config['sources']]
    if len(ids) != len(set(ids)):
        raise ValueError('duplicate review source IDs')
    selected = set(read_asns(selection))
    report = {'version': 1, 'status': 'complete', 'generated_at': now.isoformat(),
              'mode': 'offline-snapshots' if downloader.offline else 'live-fetch',
              'selection_sha256': hashlib.sha256(selection).hexdigest(),
              'selected_count': len(selected), 'sources': {}, 'candidates': [],
              'observations': [], 'observation_max_age_days': max_age_days,
              'policy': 'Advisory only. No network probes or automatic selection changes.'}
    evidence = {}
    for source in config['sources']:
        try:
            expected_kind = {'asn-heredoc': 'community-selection', 'dpi-targets': 'diagnostic-target'}
            if source['evidence_kind'] != expected_kind[source['parser']]:
                raise ValueError('source evidence kind does not match parser')
            entries, metadata = fetch_source(source, downloader)
            upstream = set(entries)
            metadata.update({'asns': sorted(upstream),
                             'new_to_selection': sorted(upstream - selected)})
            if source['evidence_kind'] == 'community-selection':
                metadata['selected_not_in_source'] = sorted(selected - upstream)
            report['sources'][source['id']] = metadata
            for number in sorted(upstream - selected):
                evidence.setdefault(number, []).append({
                    'source': source['id'], 'kind': source['evidence_kind'],
                    'labels': entries[number], 'location': metadata['location'],
                })
        except Exception as exc:
            # A missing source is unknown, never an empty list or removal proposal.
            report['status'] = 'partial'
            report['sources'][source['id']] = {'status': 'error', 'error': str(exc)}
    if observation_body is not None:
        report['observations_sha256'] = hashlib.sha256(observation_body).hexdigest()
        try:
            report['observations'] = observations(observation_body, now, max_age_days)
        except (ValueError, TypeError, AttributeError) as exc:
            report['status'] = 'partial'
            report['observations_error'] = str(exc)
        for row in report['observations']:
            if row['asn'] not in selected and not row['stale'] and row['result'] == 'restriction-observed':
                evidence.setdefault(row['asn'], []).append({'kind': 'external-observation', **row})
    report['candidates'] = [{'asn': number, 'status': 'needs-review', 'evidence': items}
                            for number, items in sorted(evidence.items())]
    return report


def cell(value):
    return html.escape(str(value), quote=True).replace('|', '&#124;').replace('\n', ' ').replace('\r', ' ')


def render(report):
    lines = ['## ASN selection review', '',
             f'Status: **{report["status"]}**; mode: {report["mode"]}; collected: {report["generated_at"]}.',
             '', report['policy'],
             'Diagnostic targets are not evidence of blocking. Absence from a source is not a removal recommendation.',
             '', '| Source | Status | ASNs | New candidates | Selected absent |',
             '|---|---|---:|---:|---:|']
    for name, source in report['sources'].items():
        if source['status'] == 'ok':
            missing = source.get('selected_not_in_source')
            lines.append(f'| {cell(name)} | ok | {len(source["asns"])} | {len(source["new_to_selection"])} | {len(missing) if missing is not None else "n/a"} |')
        else:
            lines.append(f'| {cell(name)} | error: {cell(source["error"][:500])} | unknown | unknown | unknown |')
    lines += ['', '| Candidate | Evidence type |', '|---|---|']
    for candidate in report['candidates'][:100]:
        kinds = ', '.join(sorted({item['kind'] for item in candidate['evidence']}))
        lines.append(f'| AS{candidate["asn"]} | {cell(kinds)} |')
    if not report['candidates']:
        lines.append('| None in available sources | |')
    if report.get('observations_error'):
        lines += ['', f'External observations rejected: {cell(report["observations_error"])}.']
    lines += ['', f'External observations accepted: {len(report["observations"])}. '
              'No external measurement feed is configured by default.',
              'Full candidate evidence, source revisions/hashes, unresolved filters and per-source differences: asn-review.json.', '']
    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sources', type=Path, default=ROOT / 'data/asn-review-sources.json')
    parser.add_argument('--selection', type=Path, default=ROOT / 'data/rkn-asns.txt')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--summary', type=Path, required=True)
    parser.add_argument('--observations', type=Path)
    parser.add_argument('--offline', action='store_true')
    args = parser.parse_args()
    report = build_report(json.loads(args.sources.read_bytes()), args.selection.read_bytes(),
                          Downloader(ROOT / '.cache/asn-review', offline=args.offline),
                          datetime.now(timezone.utc),
                          args.observations.read_bytes() if args.observations else None)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    args.summary.parent.mkdir(parents=True, exist_ok=True)
    args.summary.write_text(render(report), encoding='utf-8')
    return 0 if report['status'] == 'complete' else 1


if __name__ == '__main__':
    raise SystemExit(main())
