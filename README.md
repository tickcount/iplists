# iplists

Domain and IP rule sets for sing-box, collected from public sources. The compiler validates inputs, removes duplicates, collapses networks without expanding coverage, and exports JSON, SRS and plain text. GitHub Actions is configured to update the lists every six hours.

Categories: **AI (including Gemini), Discord, Telegram, YouTube, Apple, Microsoft, Twitch, GitHub, RKNAsnBlock**.

## Use the lists

Files live in `rules/<Category>/`; names are case-sensitive.

| File | Contents |
|---|---|
| `bundle.srs` | Domains + core IPv4/IPv6 in one subscription |
| `domains.srs` | Domain suffixes |
| `domains-exact.srs` | Exact domain names, without their subdomains |
| `ip.srs` | IPv4 + IPv6: observed IPs and explicitly trusted service networks |
| `ip-extended.srs` | Additional broad IPv4/IPv6 infrastructure ranges, opt-in |

Every SRS has a `.json` equivalent. Individual lists also have `.txt` exports; there is no `bundle.txt`. Bundles include both domain modes and core IPs; extended ranges are excluded. Use both domain files for complete domain-only coverage. The former `ipv4.*`/`ipv6.*` files are replaced by `ip.*` (likewise for extended lists).

RKNAsnBlock is generated independently from [our ASN selection](data/rkn-asns.txt): RIPEstat announcements → public IPv4/IPv6 validation → lossless collapse → JSON/SRS/TXT. It uses the API's default two-week observation window and a minimum of 10 RIS peers. Each of the 389 ASN responses is hashed and reported; empty responses are explicit, request failures stop publication. No third-party generated RKN list is downloaded. Its core files intentionally cover broad ASN networks, not individually confirmed blocked IPs.

For example, merge this fragment into your sing-box config and replace `proxy` with your outbound tag:

```json
{
  "route": {
    "rule_set": [{
      "tag": "ai",
      "type": "remote",
      "format": "binary",
      "url": "https://raw.githubusercontent.com/tickcount/iplists/main/rules/AI/bundle.srs",
      "update_interval": "6h"
    }],
    "rules": [{ "rule_set": ["ai"], "outbound": "proxy" }]
  }
}
```

Replace `AI` with another category, or choose a specific file such as `GitHub/domains-exact.srs` or `Telegram/ip.txt`. IP lists may include shared or historical addresses; domain rules usually provide more precise service selection.

## Build locally

Requires Python **3.13.7** and **sing-box 1.13.12** in `PATH`. From the repository directory:

```sh
python3.13 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python scripts/compiler.py --diff-report /tmp/iplists-changes.json
```

Scripts live in `scripts/`; sources and categories are defined in [config.yml](config.yml). Outputs go to `rules/`; `manifest.json` records sources, hashes and validation results. Failed validation preserves the previous generation.

Domain sources default to `domain_match: suffix`; use `domain_match: exact` for an entire source, `exact_domains: [host.example.com]` for specific names, or `exact_domain_suffixes: [cloud.example.com]` for names strictly below a cloud boundary. Exact names never collapse into a parent; an existing suffix rule can make them redundant. `domains*.txt` preserves the respective file's matching mode.

Actions shows category counts, IPv4/IPv6 changes, sources and applied exceptions in its job summary, including build failures. Actions are pinned by commit SHA; the cached sing-box archive is SHA-256-verified on every run. For a local diagnostic report, add `--build-report /tmp/iplists-build.json`. `--offline` reuses downloaded snapshots without network access.

## Review ASN candidates

The separate **Review ASN Candidates** workflow runs every six hours. It compares the community ASN selection in `legiz-ru/sb-rule-sets` and explicit foreign-provider ASN targets in `hyperion-cs/dpi-checkers` with our selection. Its Actions summary and `asn-review` artifact contain candidates, per-source differences, source revisions/hashes and collection time. Diagnostic targets do not prove blocking; missing entries do not recommend removal. Failed sources are marked unknown and fail the review job without stopping rule publication. No probes run and no ASN is added or removed automatically. After reviewing the evidence, edit `data/rkn-asns.txt` explicitly.

```sh
python scripts/asn_review.py --output /tmp/asn-review.json --summary /tmp/asn-review.md
```

Sources are configured in `data/asn-review-sources.json`. Organization searches and constrained filters are reported as unresolved, never expanded into whole ASNs. `--offline` replays cached snapshots and labels the report accordingly.

There is no external measurement feed by default. To attach attributed observations, pass `--observations /path/to/observations.json` using this schema:

```json
{"version": 1, "observations": [{"asn": 13335, "operator": "Operator where the test ran", "method": "Describe the test and sampled targets", "source_url": "https://example.org/report", "observed_at": "2026-09-25T12:00:00Z", "result": "restriction-observed"}]}
```

Results may be `restriction-observed`, `reachable`, or `inconclusive`. Observations older than 30 days are marked stale; only recent restriction observations propose candidates. They describe the reported sample, never prove an entire ASN is blocked, and never change the rules. Observation dates are separate from collection and repository commit dates.
