"""Render a bounded GitHub Actions summary from this run's build report."""
import argparse
import html
import json
from pathlib import Path


def cell(value):
    text = html.escape(str(value), quote=True)
    for char in ('|', '`', '*', '_', '[', ']'):
        text = text.replace(char, f'&#{ord(char)};')
    return text.replace('\r', '').replace('\n', '<br>')


def number(value):
    return f'{value:,}' if isinstance(value, int) else '—'


def render(report, outcome):
    successful = outcome == 'success' and report.get('status') == 'success'
    lines = ['## Rule compilation', '',
             '**Build succeeded.** Publication is handled by the separate publish job.' if successful else
             '**Build did not succeed.** Candidate data below is incomplete and was not published.', '']
    if not report:
        lines += ['No build report was produced; see the failed or skipped setup/test step.', '']
    else:
        lines += [f'Stage: {cell(report.get("stage", "unknown"))}.', '']
    if report.get('active_source'):
        lines += [f'Source being collected: {cell(report["active_source"])}.', '']
    if report.get('error'):
        lines += [cell(report['error'][:8000]), '']

    files = report.get('files', {})
    categories = sorted({name.split('/')[0] for name in files})
    if categories:
        lines += ['| Category | Suffixes | Exact names | Core IPv4 | Core IPv6 | Observed IP entries (optional) |',
                  '|---|---:|---:|---:|---:|---:|']
        for name in categories[:100]:
            ip = files.get(f'{name}/ip.json', {})
            lines.append('| ' + ' | '.join([cell(name),
                number(files.get(f'{name}/domains.json', {}).get('entries')),
                number(files.get(f'{name}/domains-exact.json', {}).get('entries')),
                number(ip.get('ipv4_entries')), number(ip.get('ipv6_entries')),
                number(files.get(f'{name}/ip-observed.json', {}).get('entries'))]) + ' |')
        lines += ['']

    changes = report.get('changes', {})
    lines += ['### Changes', '']
    if not changes:
        lines += ['No list changes.' if successful else 'No change comparison available.', '']
    else:
        lines += ['| File / family | Entries before → after | Added addresses | Removed addresses |',
                  '|---|---:|---:|---:|']
        for name, change in sorted(changes.items())[:150]:
            if name.endswith('/bundle.json'):
                continue
            entries = number((change.get('before') or {}).get('entries')) + ' → ' + number((change.get('after') or {}).get('entries'))
            coverage = change.get('coverage', {})
            if coverage:
                for family, stats in sorted(coverage.items()):
                    family_entries = number((change.get('before') or {}).get(f'{family}_entries')) + ' → ' + number((change.get('after') or {}).get(f'{family}_entries'))
                    lines.append(f'| {cell(name)} / {cell(family)} | {family_entries} | {number(stats["addresses_added"])} | {number(stats["addresses_removed"])} |')
            else:
                lines.append(f'| {cell(name)} | {entries} | — | — |')
                if change.get('added') or change.get('removed'):
                    lines.append(f'| ↳ membership | +{change.get("added", 0)} / −{change.get("removed", 0)} | — | — |')
        lines += ['']

    sources = report.get('sources', {})
    lines += ['### Collected sources', '', '| Source | Location | SHA-256 | Exclusions |', '|---|---|---|---:|']
    for sid, source in sorted(sources.items())[:100]:
        lines.append(f'| {cell(sid)} | {cell(source.get("location", ""))} | {cell(source.get("sha256", "")[:12])} | {len(source.get("excluded", {}))} |')
        if 'asns' in source:
            lines.append(f'| ↳ RIPEstat | {len(source["asns"])} ASN responses; {len(source.get("empty_asns", []))} empty | | |')
    lines += ['', '### Applied exclusions and suffix exceptions', '']
    details = []
    for sid, source in sorted(sources.items()):
        for domain, reason in sorted(source.get('excluded', {}).items()):
            details.append(f'- {cell(sid)}: excluded {cell(domain)} — {cell(reason)}')
        for domain, entry in sorted(source.get('broad_domains', {}).items()):
            details.append(f'- {cell(sid)}: allowed suffix {cell(domain)} — {cell(entry["exception"])}')
    lines += details[:100] or ['None.']
    if len(details) > 100:
        lines.append(f'\nShowing 100 of {len(details)} entries; see the build-report artifact for the complete list.')
    verification = report.get('github_verification')
    if verification:
        lines += ['', '### GitHub Meta API comparison', '',
                  '| Family | Core addresses inside official ranges | Outside | Observed addresses inside | Outside |', '|---|---:|---:|---:|---:|']
        for family, stats in sorted(verification['families'].items()):
            lines.append(f'| {cell(family)} | {number(stats["core_addresses_in_official"])} | {number(stats["core_addresses_outside_official"])} | {number(stats.get("observed_addresses_in_official"))} | {number(stats.get("observed_addresses_outside_official"))} |')
        lines += ['', 'Informational comparison; the official list is not exhaustive.']
    lines += ['', 'Full details: build-report and changes artifacts.']
    output = '\n'.join(lines) + '\n'
    # Bound untrusted upstream strings below GitHub's 1 MiB summary limit.
    if len(output.encode()) > 900_000:
        output = output.encode()[:850_000].decode('utf-8', errors='ignore') + '\n\nSummary truncated; see artifacts.\n'
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--outcome', choices=['success', 'failure', 'cancelled', 'skipped'], required=True)
    args = parser.parse_args()
    report = json.loads(args.report.read_text()) if args.report.exists() else {}
    with args.output.open('a', encoding='utf-8') as stream:
        stream.write(render(report, args.outcome))


if __name__ == '__main__':
    main()
