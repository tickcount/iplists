#!/usr/bin/env python3
"""Build validated, reproducible sing-box service rules. See README.md."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import gzip
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

import yaml
if __package__:
    from .asn_source import collect_asns
    from .domain_policy import load_policy
    from .ip_coverage import coverage_delta
else:
    from asn_source import collect_asns
    from domain_policy import load_policy
    from ip_coverage import coverage_delta

ROOT = Path(__file__).resolve().parent.parent
DOMAIN_FIELDS = ("domains", "domains-exact")
IP_FIELDS = ("ipv4", "ipv6", "ipv4-extended", "ipv6-extended")
FIELDS = DOMAIN_FIELDS + IP_FIELDS
OUTPUT_FIELDS = DOMAIN_FIELDS + ("ip", "ip-extended")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]*\Z")
LABEL = re.compile(r"[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?\Z")
MAX_BYTES = 64 * 1024 * 1024


class BuildError(Exception):
    pass


def digest(data):
    return hashlib.sha256(data).hexdigest()


def json_bytes(value):
    return (json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True) + "\n").encode()


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(json_bytes(value))


def normalize_domain(value):
    value = (value[:-1] if value.endswith(".") else value).lower()
    if not value or any(c.isspace() for c in value) or any(c in value for c in "/:@*?<>"):
        raise BuildError(f"invalid domain: {value!r}")
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise BuildError(f"invalid IDNA domain: {value!r}") from exc
    labels = value.split(".")
    if (len(value) > 253 or len(labels) < 2 or labels[-1].isdigit()
            or any(len(label) > 63 or not LABEL.fullmatch(label) for label in labels)):
        raise BuildError(f"invalid domain: {value!r}")
    return value


def minimize_domains(values):
    # O(total labels), including very large Apple/YouTube domain lists.
    values = set(values)
    return sorted(d for d in values if not any(
        ".".join(d.split(".")[i:]) in values for i in range(1, len(d.split(".")))
    ))


def suffix_covers(domain, suffixes):
    labels = domain.split(".")
    return any(".".join(labels[i:]) in suffixes for i in range(len(labels)))


def rule_key(field):
    return {"domains": "domain_suffix", "domains-exact": "domain"}.get(field, "ip_cidr")


def normalize_network(value, version=None, hosts_only=False):
    try:
        if "%" in value or (hosts_only and "/" in value):
            raise ValueError("expected an unscoped host address")
        network = ipaddress.ip_network(value, strict=True)
    except ValueError as exc:
        raise BuildError(f"invalid IP/CIDR: {value!r}: {exc}") from exc
    if version and network.version != version:
        raise BuildError(f"expected IPv{version}, got {value!r}")
    if network.prefixlen == 0:
        raise BuildError(f"default route is not a service network: {value}")
    return network


def collapse(values):
    return [str(n) for n in ipaddress.collapse_addresses(
        ipaddress.ip_network(v) for v in values
    )]


def empty_data():
    return {field: set() for field in FIELDS}


class Downloader:
    def __init__(self, cache, offline=False, attempts=3, timeout=30):
        self.cache = Path(cache)
        self.offline = offline
        self.attempts = attempts
        self.timeout = timeout
        self.memory = {}

    def get(self, url):
        if url in self.memory:
            return self.memory[url]
        cached = self.cache / (digest(url.encode()) + ".gz")
        if self.offline:
            try:
                with gzip.open(cached, "rb") as f:
                    body = f.read(MAX_BYTES + 1)
            except (OSError, EOFError) as exc:
                raise BuildError(f"offline snapshot unavailable: {url}") from exc
        else:
            for attempt in range(self.attempts):
                try:
                    req = urllib.request.Request(url, headers={"User-Agent": "subnet-compiler/2.0"})
                    with urllib.request.urlopen(req, timeout=self.timeout) as response:
                        body = response.read(MAX_BYTES + 1)
                    break
                except (OSError, urllib.error.URLError) as exc:
                    if attempt + 1 == self.attempts:
                        raise BuildError(f"download failed after {self.attempts} attempts: {url}: {exc}") from exc
                    if isinstance(exc, urllib.error.HTTPError) and exc.code not in (408, 429, 500, 502, 503, 504):
                        raise BuildError(f"HTTP {exc.code}: {url}") from exc
                    time.sleep(2 ** attempt)
            else:
                raise BuildError("attempts must be positive")
        if len(body) > MAX_BYTES:
            raise BuildError(f"response exceeds {MAX_BYTES} bytes: {url}")
        if not self.offline:
            self.cache.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(dir=self.cache, delete=False) as f:
                temporary = Path(f.name)
                f.write(gzip.compress(body, mtime=0))
            temporary.replace(cached)
        self.memory[url] = body
        return body


def string_list(value, context, nonempty=False):
    if not isinstance(value, list) or any(not isinstance(x, str) or not x for x in value):
        raise BuildError(f"{context}: expected a list of nonempty strings")
    if nonempty and not value:
        raise BuildError(f"{context}: must not be empty")
    return value


def load_config(path):
    try:
        config = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise BuildError(f"cannot read config: {exc}") from exc
    if not isinstance(config, dict) or config.get("version") != 2:
        raise BuildError("config must declare version: 2")
    sources, categories = config.get("sources"), config.get("categories")
    if not isinstance(sources, dict) or not sources or not isinstance(categories, dict) or not categories:
        raise BuildError("sources and categories must be nonempty mappings")
    policy = config.get("domain_policy", {})
    if not isinstance(policy, dict):
        raise BuildError("domain_policy must be a mapping")
    if policy:
        if not isinstance(policy.get("public_suffix_file"), str) or not policy["public_suffix_file"]:
            raise BuildError("domain_policy requires public_suffix_file")
        validate_domain_reasons(policy.get("shared_suffixes", {}), "shared_suffixes")
    for sid, source in sources.items():
        if not isinstance(sid, str) or not NAME.fullmatch(sid) or not isinstance(source, dict):
            raise BuildError(f"invalid source: {sid!r}")
        kind = source.get("type")
        if source.get("domain_match", "suffix") not in ("exact", "suffix"):
            raise BuildError(f"{sid}: domain_match must be exact or suffix")
        for key in ("exact_domains", "exact_domain_suffixes"):
            values = string_list(source.get(key, []), f"{sid}.{key}")
            for domain in values:
                if normalize_domain(domain) != domain:
                    raise BuildError(f"{sid}.{key}: use normalized domain names")
        if any(key in source for key in ("domain_match", "exact_domains", "exact_domain_suffixes")):
            if kind != "iplist" and not (kind == "text" and source.get("data") == "domains"):
                raise BuildError(f"{sid}: domain matching options require a domain source")
        if kind == "iplist":
            if bool(source.get("sites")) == bool(source.get("groups")):
                raise BuildError(f"{sid}: specify either sites or groups")
            key = "sites" if source.get("sites") else "groups"
            string_list(source[key], f"{sid}.{key}", True)
            if key == "groups":
                string_list(source.get("expected_sites"), f"{sid}.expected_sites", True)
            fields = string_list(source.get("fields", ["domains", "ip4", "ip6", "cidr4", "cidr6"]), f"{sid}.fields", True)
            if any(field not in ("domains", "ip4", "ip6", "cidr4", "cidr6") for field in fields):
                raise BuildError(f"{sid}: invalid iplist fields")
        elif kind == "asn":
            if not isinstance(source.get("file"), str) or not source["file"] or "url" in source:
                raise BuildError(f"{sid}: ASN source requires a local selection file and no URL")
            if source.get("profile") not in ("core", "extended"):
                raise BuildError(f"{sid}: ASN source requires an explicit profile")
            for key, default, maximum in (("workers", 4, 4), ("min_peers_seeing", 10, 500)):
                value = source.get(key, default)
                if type(value) is not int or not 1 <= value <= maximum:
                    raise BuildError(f"{sid}: invalid {key}")
        elif kind == "singbox-ip":
            if not isinstance(source.get("url"), str):
                raise BuildError(f"{sid}: singbox-ip requires a URL")
            if source.get("profile") not in ("core", "extended"):
                raise BuildError(f"{sid}: singbox-ip requires an explicit core/extended profile")
        elif kind == "text":
            if bool(source.get("url")) == bool(source.get("file")):
                raise BuildError(f"{sid}: specify either url or file")
            if source.get("data") not in ("domains", "ipv4", "ipv6", "networks"):
                raise BuildError(f"{sid}: invalid text data type")
            if source.get("profile", "core") not in ("core", "extended"):
                raise BuildError(f"{sid}: invalid profile")
        else:
            raise BuildError(f"{sid}: unknown source type {kind!r}")
        if "url" in source:
            if not isinstance(source["url"], str):
                raise BuildError(f"{sid}: url must be a string")
            url = urllib.parse.urlsplit(source["url"])
            if url.scheme != "https" or not url.netloc or url.username or url.password:
                raise BuildError(f"{sid}: expected an HTTPS URL without credentials")
        if kind == "iplist" and "url" not in source:
            raise BuildError(f"{sid}: missing url")
        if "file" in source and not isinstance(source["file"], str):
            raise BuildError(f"{sid}: file must be a string")
        if "exclude_domains" in source:
            exclusions = source["exclude_domains"]
            if not isinstance(exclusions, dict) or any(not isinstance(k, str) or not isinstance(v, str) or not v for k, v in exclusions.items()):
                raise BuildError(f"{sid}: exclude_domains must map exact strings to reasons")
        if "allow_broad_domains" in source:
            validate_domain_reasons(source["allow_broad_domains"], f"{sid}.allow_broad_domains")
            if not policy:
                raise BuildError(f"{sid}: broad-domain exceptions require domain_policy")
            if source["allow_broad_domains"].keys() & source.get("exclude_domains", {}).keys():
                raise BuildError(f"{sid}: domain cannot be both excluded and allowed")
    names = set()
    for name, category in categories.items():
        if not isinstance(name, str) or not NAME.fullmatch(name) or name.casefold() in names:
            raise BuildError(f"invalid or case-colliding category name: {name!r}")
        names.add(name.casefold())
        if not isinstance(category, dict):
            raise BuildError(f"{name}: expected a mapping")
        for sid in string_list(category.get("sources"), f"{name}.sources", True):
            if sid not in sources:
                raise BuildError(f"{name}: unknown source {sid!r}")
    verification = config.get("github_verification")
    if verification is not None:
        if not isinstance(verification, dict) or verification.get("category") not in categories:
            raise BuildError("github_verification requires an existing category")
        fields = string_list(verification.get("fields"), "github_verification.fields", True)
        if len(fields) != len(set(fields)) or any(f not in ("web", "api", "git", "packages", "pages", "copilot") for f in fields):
            raise BuildError("github_verification: select distinct web/api/git/packages/pages/copilot fields")
    limits = config.get("limits", {})
    if not isinstance(limits, dict):
        raise BuildError("limits must be a mapping")
    for key, default in (("max_drop_fraction", 0.5), ("max_growth_fraction", 1.0)):
        value = limits.get(key, default)
        if type(value) not in (int, float) or not 0 <= value <= 10:
            raise BuildError(f"invalid limit {key}")
    return config


def validate_domain_reasons(value, context):
    if not isinstance(value, dict):
        raise BuildError(f"{context}: expected domain-to-reason mapping")
    for domain, reason in value.items():
        if not isinstance(domain, str) or not isinstance(reason, str) or not reason.strip():
            raise BuildError(f"{context}: domains require a nonempty reason")
        if normalize_domain(domain) != domain:
            raise BuildError(f"{context}: use normalized domain names")


def source_url(source):
    if source["type"] != "iplist":
        return source.get("url")
    key = "site" if source.get("sites") else "group"
    values = source.get("sites") or source["groups"]
    separator = "&" if "?" in source["url"] else "?"
    return source["url"] + separator + urllib.parse.urlencode(
        [("format", "json")] + [(key, value) for value in values]
    )


def collect_source(sid, source, downloader, config_dir, policy=None):
    data = empty_data()
    if source["type"] == "asn":
        try:
            networks, report = collect_asns(source, downloader, config_dir, normalize_network)
        except (OSError, ValueError) as exc:
            raise BuildError(f"{sid}: {exc}") from exc
        for version, values in networks.items():
            field = f"ipv{version}" + ("-extended" if source["profile"] == "extended" else "")
            data[field].update(values)
        report["counts"] = {field: len(values) for field, values in data.items()}
        return data, report
    excluded = {}
    broad_domains = {}
    url = source_url(source)
    try:
        body = downloader.get(url) if url else (config_dir / source["file"]).read_bytes()
        text = body.decode("utf-8-sig")
    except (OSError, UnicodeError) as exc:
        raise BuildError(f"{sid}: cannot read source: {exc}") from exc

    def add(value, field, location, hosts_only=False):
        if not isinstance(value, str):
            raise BuildError(f"{sid}/{location}: expected a string")
        try:
            if field == "domains":
                if value in source.get("exclude_domains", {}):
                    excluded[value] = source["exclude_domains"][value]
                    return
                domain = normalize_domain(value)
                exact = (source.get("domain_match") == "exact" or domain in source.get("exact_domains", [])
                         or any(domain.endswith("." + parent) for parent in source.get("exact_domain_suffixes", [])))
                if exact:
                    field = "domains-exact"
                # Exact names never include other tenants through a suffix match.
                reason = policy.reason(domain) if policy and not exact else None
                if reason:
                    exception = source.get("allow_broad_domains", {}).get(domain)
                    if not exception:
                        raise BuildError(f"broad domain suffix {domain!r}: {reason}; exclude it or add a reviewed allow_broad_domains reason")
                    broad_domains[domain] = {"risk": reason, "exception": exception}
                data[field].add(domain)
            else:
                network = normalize_network(value, 4 if field.startswith("ipv4") else 6, hosts_only)
                if not network.is_global or network.is_multicast:
                    excluded[value] = "nonpublic or multicast address/network"
                    return
                data[field].add(str(network))
        except BuildError as exc:
            raise BuildError(f"{sid}/{location}: {exc}") from exc

    sites = {}
    if source["type"] == "iplist":
        try:
            sites = json.loads(text)
        except ValueError as exc:
            raise BuildError(f"{sid}: expected iplist JSON, received invalid JSON") from exc
        if not isinstance(sites, dict) or not sites:
            raise BuildError(f"{sid}: empty/invalid iplist response")
        expected = set(source.get("sites") or source["expected_sites"])
        missing = expected - sites.keys()
        if missing:
            raise BuildError(f"{sid}: missing portals: {', '.join(sorted(missing))}")
        if source.get("sites") and set(sites) != expected:
            raise BuildError(f"{sid}: unexpected portals in response")
        selected_fields = source.get("fields", ["domains", "ip4", "ip6", "cidr4", "cidr6"])
        for site, row in sites.items():
            if not isinstance(row, dict) or row.get("name") != site:
                raise BuildError(f"{sid}: invalid portal {site}")
            if source.get("groups") and row.get("group") not in source["groups"]:
                raise BuildError(f"{sid}: unexpected group for {site}")
            string_list(row.get("domains"), f"{sid}/{site}.domains", True)
            for field in selected_fields:
                values = string_list(row.get(field), f"{sid}/{site}.{field}")
                if field.startswith("cidr"):
                    replacement = row.get("replace", {})
                    if not isinstance(replacement, dict):
                        raise BuildError(f"{sid}/{site}: invalid replace mapping")
                    mapping = replacement.get(field, {})
                    if not isinstance(mapping, dict):
                        raise BuildError(f"{sid}/{site}: invalid replace.{field}")
                    resolved = []
                    for value in values:
                        normalize_network(value, 4 if field == "cidr4" else 6)
                        resolved.extend(string_list(mapping[value], f"{sid}/{site}.replace.{field}") if value in mapping else [value])
                    values = resolved
                target = {"domains": "domains", "ip4": "ipv4", "ip6": "ipv6",
                          "cidr4": "ipv4-extended", "cidr6": "ipv6-extended"}[field]
                for index, value in enumerate(values, 1):
                    add(value, target, f"{site}/{field}/{index}", field in ("ip4", "ip6"))
    elif source["type"] == "singbox-ip":
        try:
            ruleset = json.loads(text)
        except ValueError as exc:
            raise BuildError(f"{sid}: expected sing-box JSON") from exc
        if (not isinstance(ruleset, dict) or set(ruleset) != {"version", "rules"}
                or type(ruleset["version"]) is not int or ruleset["version"] not in range(1, 6)
                or not isinstance(ruleset["rules"], list) or not ruleset["rules"]):
            raise BuildError(f"{sid}: invalid or empty sing-box IP rule set")
        for index, rule in enumerate(ruleset["rules"], 1):
            # Never flatten conditional/logical/inverted rules into unconditional IP matches.
            if not isinstance(rule, dict) or set(rule) != {"ip_cidr"}:
                raise BuildError(f"{sid}: rule {index} must contain only ip_cidr")
            values = string_list(rule["ip_cidr"], f"{sid}/rules/{index}/ip_cidr", True)
            for value in values:
                field = f"ipv{normalize_network(value).version}"
                if source["profile"] == "extended":
                    field += "-extended"
                add(value, field, f"rules/{index}")
    else:
        count = 0
        for lineno, raw in enumerate(text.splitlines(), 1):
            value = raw.split("#", 1)[0].strip()
            if not value:
                continue
            count += 1
            field = source["data"]
            if field == "networks":
                field = "ipv4" if normalize_network(value).version == 4 else "ipv6"
            if field != "domains" and source.get("profile") == "extended":
                field += "-extended"
            add(value, field, str(lineno))
        if not count:
            raise BuildError(f"{sid}: empty source")
    if not any(data.values()):
        raise BuildError(f"{sid}: no usable records")
    report = {"location": url or source["file"], "sha256": digest(body),
              "counts": {k: len(v) for k, v in data.items()}, "excluded": excluded,
              "broad_domains": broad_domains,
              "portals": {k: {f: len(v[f]) for f in ("domains", "ip4", "ip6", "cidr4", "cidr6") if isinstance(v.get(f), list)} for k, v in sites.items()}}
    return data, report


def file_metrics(field, values):
    result = {"entries": len(values)}
    if field in ("ip", "ip-extended"):
        parsed = [ipaddress.ip_network(v) for v in values]
        for version in (4, 6):
            family = [n for n in parsed if n.version == version]
            result[f"ipv{version}_entries"] = len(family)
            result[f"ipv{version}_addresses"] = sum(n.num_addresses for n in family)
    elif field not in DOMAIN_FIELDS:
        result["addresses"] = sum(ipaddress.ip_network(v).num_addresses for v in values)
    return result


def output_values(data):
    return {"domains": data["domains"], "domains-exact": data["domains-exact"],
            "ip": data["ipv4"] + data["ipv6"],
            "ip-extended": data["ipv4-extended"] + data["ipv6-extended"]}


def previous_values(out, name, field):
    path = out / name / f"{field}.json"
    if path.exists():
        return {v for rule in json.loads(path.read_text())["rules"] for v in rule.get(rule_key(field), [])}
    if field in ("ip", "ip-extended"):
        suffix = "-extended" if field.endswith("-extended") else ""
        return previous_values(out, name, "ipv4" + suffix) | previous_values(out, name, "ipv6" + suffix)
    return set()


def explain(config_path, downloader, value):
    """Find source records covering a domain or IP before output minimization."""
    config_path = Path(config_path).resolve()
    config = load_config(config_path)
    policy, _ = load_policy(config.get("domain_policy"), config_path.parent, normalize_domain)
    try:
        address = ipaddress.ip_address(value)
        domain = None
    except ValueError:
        address, domain = None, normalize_domain(value)
    matches = []
    for sid in sorted({sid for cat in config["categories"].values() for sid in cat["sources"]}):
        data, report = collect_source(sid, config["sources"][sid], downloader, config_path.parent, policy)
        for field, entries in data.items():
            if domain is not None:
                found = sorted(e for e in entries if domain == e or domain.endswith("." + e)) if field == "domains" else []
                if field == "domains-exact" and domain in entries:
                    found = [domain]
            elif field.startswith(f"ipv{address.version}"):
                found = sorted(e for e in entries if address in ipaddress.ip_network(e))
            else:
                found = []
            if found:
                matches.append({"source": sid, "field": field, "records": found,
                                "location": report["location"],
                                "categories": [name for name, cat in config["categories"].items() if sid in cat["sources"]]})
    return {"query": value, "matches": matches}


def intersect_size(left, right):
    # Inputs are collapsed and sorted: O(N+M), not O(N*M).
    i = j = total = 0
    while i < len(left) and j < len(right):
        a, b = left[i], right[j]
        low = max(int(a.network_address), int(b.network_address))
        high = min(int(a.broadcast_address), int(b.broadcast_address))
        total += max(0, high - low + 1)
        if a.broadcast_address < b.broadcast_address:
            i += 1
        else:
            j += 1
    return total


def check_changes(previous, current, limits, allow_large_changes=False):
    changes, violations = {}, []
    for path in sorted(previous.keys() | current.keys()):
        old, new = previous.get(path), current.get(path)
        if old == new:
            continue
        changes[path] = {"before": old, "after": new}
        if old is None:
            continue
        for metric in ("entries", "addresses", "ipv4_entries", "ipv6_entries", "ipv4_addresses", "ipv6_addresses"):
            before = old.get(metric, 0)
            after = (new or {}).get(metric, 0)
            if before and (after < before * (1 - limits.get("max_drop_fraction", 0.5))
                           or after > before * (1 + limits.get("max_growth_fraction", 1.0))):
                violations.append(f"{path} {metric}: {before} -> {after}")
    if violations and not allow_large_changes:
        raise BuildError("large changes require review (--allow-large-changes):\n  " + "\n  ".join(violations))
    return changes


def verify_github(settings, normalized, downloader):
    url = "https://api.github.com/meta"
    body = downloader.get(url)
    try:
        response = json.loads(body)
    except ValueError as exc:
        raise BuildError("GitHub Meta API returned invalid JSON") from exc
    if not isinstance(response, dict):
        raise BuildError("GitHub Meta API requires an object")
    official = {4: set(), 6: set()}
    counts = {}
    for field in settings["fields"]:
        values = string_list(response.get(field), f"github_meta.{field}", True)
        counts[field] = len(values)
        for value in values:
            network = normalize_network(value)
            if not network.is_global or network.is_multicast:
                raise BuildError(f"GitHub Meta API {field}: nonpublic network {value}")
            official[network.version].add(str(network))
    result = {"location": url, "sha256": digest(body), "category": settings["category"],
              "selected_fields": counts, "mode": "comparison-only", "families": {}}
    category = normalized[settings["category"]]
    for version in (4, 6):
        comparison = coverage_delta(official[version], category[f"ipv{version}"], version)
        result["families"][f"ipv{version}"] = {
            "official_addresses": sum(ipaddress.ip_network(n).num_addresses for n in collapse(official[version])),
            "core_addresses_in_official": comparison["addresses_retained"],
            "core_addresses_outside_official": comparison["addresses_added"],
            "official_addresses_absent_from_core": comparison["addresses_removed"],
            "core_outside_official_sample": comparison["added_cidr_sample"],
            "official_absent_from_core_sample": comparison["removed_cidr_sample"],
        }
    return result


def describe_changes(out, normalized, previous, current, limits):
    changes = check_changes(previous, current, limits, True)
    # Include removed categories and unchanged-size membership substitutions.
    paths = set(previous) | set(current)
    for rel in sorted(paths):
        name, filename = rel.split("/")
        field = Path(filename).stem
        if field not in OUTPUT_FIELDS:
            continue
        values = output_values(normalized[name])[field] if name in normalized else []
        old_values = previous_values(out, name, field)
        added, removed = set(values) - old_values, old_values - set(values)
        if added or removed:
            change = changes.setdefault(rel, {"before": previous.get(rel), "after": current.get(rel)})
            change.update({"added": len(added), "removed": len(removed),
                           "added_sample": sorted(added)[:20], "removed_sample": sorted(removed)[:20]})
            if field not in DOMAIN_FIELDS:
                change["coverage"] = {}
                for version in (4, 6):
                    before = [v for v in old_values if ipaddress.ip_network(v).version == version]
                    after = [v for v in values if ipaddress.ip_network(v).version == version]
                    change["coverage"][f"ipv{version}"] = coverage_delta(before, after, version)
    return changes


def compile_srs(path, binary):
    try:
        subprocess.run([binary, "rule-set", "compile", str(path), "-o", str(path.with_suffix(".srs"))],
                       check=True, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError) as exc:
        raise BuildError(f"sing-box compile failed: {path}: {getattr(exc, 'stderr', '') or exc}") from exc


@contextmanager
def output_lock(out):
    lock = out.parent / ("." + out.name + ".lock")
    try:
        fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise BuildError(f"output locked: {lock}; check for another build before removing a stale lock") from exc
    try:
        os.write(fd, str(os.getpid()).encode())
        os.close(fd)
        yield
    finally:
        lock.unlink()


def publish(stage, out):
    # Stage is complete. Restore the previous tree if the final rename fails.
    backup = Path(tempfile.mkdtemp(prefix="." + out.name + "-previous-", dir=out.parent))
    backup.rmdir()
    had_output = out.exists()
    published = False
    try:
        if had_output:
            out.replace(backup)
        try:
            stage.replace(out)
            published = True
        except OSError:
            if had_output:
                backup.replace(out)
            raise
    finally:
        if published and backup.exists():
            shutil.rmtree(backup)


def build(config_path, out, downloader, binary="sing-box", no_compile=False,
          allow_large_changes=False, diff_report=None, build_report=None):
    report = {"status": "failed", "stage": "initializing", "sources": {}, "files": {}, "changes": {}}
    if build_report:
        report_path, output_path = Path(build_report).resolve(), Path(out).resolve()
        if report_path == output_path or output_path in report_path.parents:
            raise BuildError("--build-report must be outside the output directory")
        if report_path == Path(config_path).resolve() or (diff_report and report_path == Path(diff_report).resolve()):
            raise BuildError("--build-report must not overwrite config or diff report")
    try:
        result = _build(config_path, out, downloader, binary, no_compile,
                        allow_large_changes, diff_report, report)
        report["status"] = "success"
        return result
    except Exception as exc:
        report["error"] = str(exc)
        raise
    finally:
        if build_report:
            write_json(Path(build_report), report)


def _build(config_path, out, downloader, binary, no_compile,
           allow_large_changes, diff_report, progress):
    config_path, out = Path(config_path).resolve(), Path(out).absolute()
    config = load_config(config_path)
    policy, policy_report = load_policy(config.get("domain_policy"), config_path.parent, normalize_domain)
    if out.is_symlink():
        raise BuildError("output must not be a symlink")
    out = out.resolve()
    if out == config_path.parent or out in config_path.parents:
        raise BuildError("output must be a dedicated, non-symlink directory")
    if diff_report and (Path(diff_report).resolve() == out or out in Path(diff_report).resolve().parents):
        raise BuildError("--diff-report must be outside the output directory")
    out.parent.mkdir(parents=True, exist_ok=True)
    with output_lock(out):
        previous = {}
        old_manifest = out / "manifest.json"
        if old_manifest.exists():
            old = json.loads(old_manifest.read_text())
            if not isinstance(old, dict) or old.get("version") != 1 or not isinstance(old.get("files"), dict) or not isinstance(old.get("artifacts"), dict):
                raise BuildError("invalid output manifest")
            previous = old["files"]
            # Preserve the old IP coverage baseline when migrating split-family outputs.
            for name in sorted({path.split("/")[0] for path in previous}):
                for field, suffix in (("ip", ""), ("ip-extended", "-extended")):
                    legacy = [f"{name}/ipv{v}{suffix}.json" for v in (4, 6)]
                    if f"{name}/{field}.json" not in previous and any(path in previous for path in legacy):
                        previous[f"{name}/{field}.json"] = file_metrics(field, previous_values(out, name, field))
                        for path in legacy:
                            previous.pop(path, None)
            managed = set(old["artifacts"]) | {"manifest.json"}
            if any(p.is_symlink() or (p.is_file() and p.name != ".DS_Store" and str(p.relative_to(out)) not in managed) for p in out.rglob("*")):
                raise BuildError("refusing to remove unmanaged files or symlinks from output")
        elif out.exists() and any(out.iterdir()):
            allowed = re.compile(r"(?:ai|discord|telegram)-(?:domains|ipv4|ipv6)\.(?:json|srs)\Z")
            if any(not p.is_file() or not allowed.fullmatch(p.name) for p in out.iterdir()):
                raise BuildError("refusing to replace an unmanaged output directory")
        if no_compile and any(out.rglob("*.srs")):
            raise BuildError("use a separate --out directory for --no-compile; published SRS files must not be removed")
        collected, reports = {}, {}
        progress.update(stage="fetching", sources=reports)
        used = sorted({sid for c in config["categories"].values() for sid in c["sources"]})
        for sid in used:
            progress["active_source"] = sid
            print(f"Fetching {sid}", flush=True)
            collected[sid], reports[sid] = collect_source(sid, config["sources"][sid], downloader, config_path.parent, policy)
        manifest = {"version": 1, "rule_set_version": 3, "sources": reports, "categories": {}, "files": {}}
        progress.pop("active_source", None)
        progress.update(stage="normalizing", files=manifest["files"], categories=manifest["categories"])
        if policy_report:
            manifest["domain_policy"] = policy_report
        normalized = {}
        with tempfile.TemporaryDirectory(prefix="." + out.name + "-build-", dir=out.parent) as temp:
            stage = Path(temp) / "output"
            stage.mkdir()
            for name, category in config["categories"].items():
                data = empty_data()
                for sid in category["sources"]:
                    for field in FIELDS:
                        data[field].update(collected[sid][field])
                normalized[name] = {}
                suffixes = set(minimize_domains(data["domains"]))
                manifest["categories"][name] = {"sources": category["sources"], "normalization": {}}
                for field, values in data.items():
                    input_count = len(values)
                    if field == "domains":
                        values = sorted(suffixes)
                    elif field == "domains-exact":
                        values = sorted(d for d in values if not suffix_covers(d, suffixes))
                    else:
                        values = collapse(values)
                    manifest["categories"][name]["normalization"][field] = {
                        "unique_input_entries": input_count, "output_entries": len(values)}
                    normalized[name][field] = values
                core = normalized[name]
                for field, values in output_values(core).items():
                    key = rule_key(field)
                    rel = f"{name}/{field}.json"
                    write_json(stage / rel, {"version": 3, "rules": [{key: values}] if values else []})
                    (stage / name / f"{field}.txt").write_text("".join(v + "\n" for v in values), encoding="utf-8")
                    manifest["files"][rel] = file_metrics(field, values)
                print(f"{name}: " + ", ".join(f"{field}={len(values)}" for field, values in normalized[name].items()), flush=True)
                bundled_rule = {}
                if core["domains"]:
                    bundled_rule["domain_suffix"] = core["domains"]
                if core["domains-exact"]:
                    bundled_rule["domain"] = core["domains-exact"]
                if core["ipv4"] or core["ipv6"]:
                    bundled_rule["ip_cidr"] = core["ipv4"] + core["ipv6"]
                # sing-box combines domain_suffix and ip_cidr with OR semantics.
                write_json(stage / name / "bundle.json", {"version": 3, "rules": [bundled_rule] if bundled_rule else []})
                manifest["files"][f"{name}/bundle.json"] = {
                    "entries": sum(len(core[k]) for k in (*DOMAIN_FIELDS, "ipv4", "ipv6")),
                    "ipv4_addresses": manifest["files"][f"{name}/ip.json"]["ipv4_addresses"],
                    "ipv6_addresses": manifest["files"][f"{name}/ip.json"]["ipv6_addresses"],
                }
            progress["stage"] = "validating changes"
            progress["changes"] = describe_changes(out, normalized, previous, manifest["files"], config.get("limits", {}))
            if diff_report:
                write_json(Path(diff_report), progress["changes"])
            check_changes(previous, manifest["files"], config.get("limits", {}), allow_large_changes)
            if config.get("github_verification"):
                progress["stage"] = "verifying GitHub"
                manifest["github_verification"] = verify_github(config["github_verification"], normalized, downloader)
                progress["github_verification"] = manifest["github_verification"]
            manifest["overlaps"] = {}
            for field in IP_FIELDS:
                networks = {name: [ipaddress.ip_network(v) for v in fields[field]] for name, fields in normalized.items()}
                names = sorted(networks)
                overlaps = {}
                for i, left in enumerate(names):
                    for right in names[i + 1:]:
                        size = intersect_size(networks[left], networks[right])
                        if size:
                            overlaps[f"{left}/{right}"] = size
                manifest["overlaps"][field] = overlaps
            if not no_compile:
                progress["stage"] = "compiling"
                for path in sorted(stage.rglob("*.json")):
                    compile_srs(path, binary)
            manifest["artifacts"] = {str(p.relative_to(stage)): digest(p.read_bytes()) for p in sorted(stage.rglob("*")) if p.is_file()}
            write_json(stage / "manifest.json", manifest)
            # Finder may create these while a user browses the generated tree.
            # Preserve metadata for retained folders without treating it as a rule artifact.
            for metadata in out.rglob(".DS_Store"):
                destination = stage / metadata.relative_to(out)
                if metadata.is_file() and destination.parent.is_dir():
                    shutil.copy2(metadata, destination)
            progress["stage"] = "replacing output"
            publish(stage, out)
            progress["stage"] = "complete"
        print(f"Published {len(config['categories'])} categories to {out}", flush=True)
        return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=ROOT / "config.yml")
    parser.add_argument("--out", type=Path, default=ROOT / "rules")
    parser.add_argument("--cache", type=Path, default=ROOT / ".cache" / "sources")
    parser.add_argument("--offline", action="store_true", help="Use saved snapshots only; never an automatic fallback")
    parser.add_argument("--no-compile", action="store_true", help="JSON-only build into a separate output directory")
    parser.add_argument("--sing-box", default="sing-box", help="sing-box binary path")
    parser.add_argument("--allow-large-changes", action="store_true", help="Accept reviewed count/coverage changes")
    parser.add_argument("--diff-report", type=Path, help="Write before/after metrics outside the output directory")
    parser.add_argument("--build-report", type=Path, help="Write build status and diagnostics, including failures, outside output")
    parser.add_argument("--explain", metavar="DOMAIN_OR_IP", help="Show matching source records instead of building")
    args = parser.parse_args()
    try:
        downloader = Downloader(args.cache, args.offline)
        if args.explain:
            print(json_bytes(explain(args.config, downloader, args.explain)).decode(), end="")
        else:
            build(args.config, args.out, downloader, args.sing_box,
                  args.no_compile, args.allow_large_changes, args.diff_report, args.build_report)
    except (BuildError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
