"""
dns_wordlist.py - DNS/subdomain fuzzing wordlist generator.

Inspired by alterx (projectdiscovery) and DNSCewl (codingo).

Features:
  - FQDN parsing with structural variables (sub, suffix, root, tld, sld)
  - ClusterBomb multi-payload templates (cartesian product of named payloads)
  - Built-in payloads: word (130+), region (AWS/cloud), number (years/digits)
  - Enrich mode: extract tokens from input subdomains as additional payloads
  - DNSCewl-style mutations: append/prepend with separators, numeric range
  - Template YAML files with {{variable}} syntax (alterx-compatible)
  - Regex match/filter on output
  - Multi-domain support
  - Estimate output size before generation

Author: André Henrique (@mrhenrike)
Version: 2.0.0
"""
from __future__ import annotations

import logging
import re
from itertools import permutations, product
from pathlib import Path
from typing import Generator, Optional

logger = logging.getLogger(__name__)

# ── Built-in payloads (alterx-compatible) ─────────────────────────────────────

PAYLOAD_WORD = [
    "api", "k8s", "v1", "v2", "origin", "raw", "stage", "test", "qa", "web",
    "prod", "service", "grafana", "beta", "admin", "staging", "wordpress", "wp",
    "dev", "app", "mta-sts", "tech", "private", "public", "login", "role",
    "backend", "cloud", "internal", "mail", "oauth", "oauth2", "vpn", "lab",
    "local", "live", "data", "mobile", "search", "stats", "final", "ldap",
    "media", "docs", "eng", "engineering", "market", "compute", "cdn", "acc",
    "access", "backup", "blogs", "blog", "careers", "client", "cms", "cms1",
    "conf", "dmz", "drupal", "corp", "faq", "ir", "legacy", "log", "logs",
    "dashboard", "monitor", "mysql", "mssql", "db", "partner", "payment", "pay",
    "office", "plugins", "shop", "prometheus", "stripe", "forum", "manager",
    "server", "core", "content", "ads", "shopify", "o1", "s1", "s3", "promotion",
    "temp", "my", "proxy", "asset", "assets", "atlas", "build", "builds", "code",
    "info", "image", "review", "developers", "developer", "administrator",
    "www", "www1", "www2", "netlify", "storage",
    "smtp", "pop", "ftp", "remote", "citrix", "intranet", "portal",
    "jira", "confluence", "wiki", "support", "crm", "erp", "db",
    "redis", "elastic", "kibana", "kube", "jenkins", "gitlab", "git", "ops",
    "rede", "sistema", "servico", "gestao", "ti", "suporte", "helpdesk",
    "financeiro", "rh", "fiscal", "auth", "sso", "iam", "connect",
    "gateway", "edge", "node", "worker", "queue", "cache", "vault",
    "registry", "harbor", "nexus", "sonar", "artifactory", "terraform",
    "ansible", "puppet", "chef", "consul", "nomad", "traefik", "nginx",
    "haproxy", "envoy", "istio", "linkerd", "argocd", "flux",
]

PAYLOAD_REGION = [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1",
    "eu-north-1", "eu-south-1", "eu-east-1",
    "ap-south-1", "ap-southeast-1", "ap-southeast-2",
    "ap-northeast-1", "ap-northeast-2", "ap-northeast-3",
    "sa-east-1", "ca-central-1", "me-south-1", "af-south-1",
    "eastus", "westus", "centralus", "northeurope", "westeurope",
    "southeastasia", "eastasia", "brazilsouth", "japaneast",
]

PAYLOAD_NUMBER = [
    "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10",
    "01", "02", "03", "04", "05",
    "11", "12", "15", "18", "20", "21", "22", "23", "24", "25",
    "100", "101", "200", "201", "301", "443", "8080", "8443",
    "2020", "2021", "2022", "2023", "2024", "2025", "2026",
]

DEFAULT_PATTERNS = [
    "{{word}}-{{sub}}.{{suffix}}",
    "{{sub}}-{{word}}.{{suffix}}",
    "{{word}}.{{sub}}.{{suffix}}",
    "{{sub}}.{{word}}.{{suffix}}",
    "{{sub}}{{number}}.{{suffix}}",
    "{{word}}.{{suffix}}",
    "{{sub}}{{word}}.{{suffix}}",
    "{{word}}{{sub}}.{{suffix}}",
    "{{region}}.{{sub}}.{{suffix}}",
    "{{word}}-{{sub}}{{number}}.{{suffix}}",
    "{{sub}}-{{word}}{{number}}.{{suffix}}",
]

COMMON_SUFFIXES_DNS = [
    "-old", "-new", "-bak", "-backup", "-temp",
    "-dev", "-test", "-prod", "-stg", "-uat",
    "-v2", "-v3", "-beta", "-alpha", "-legacy",
]

DNS_SEPARATORS = ["", "-", "."]


# ── FQDN parsing ─────────────────────────────────────────────────────────────

def parse_fqdn(fqdn: str) -> dict[str, str]:
    """Parse a FQDN into structural components (alterx-compatible).

    Returns dict with keys: sub, suffix, root, tld, sld, etld, sub1, sub2, ...
    """
    fqdn = fqdn.strip().rstrip(".")
    parts = fqdn.split(".")

    if len(parts) < 2:
        return {"sub": fqdn, "suffix": fqdn, "root": fqdn, "tld": "", "sld": fqdn, "etld": ""}

    tld_candidates = _detect_etld(parts)
    etld_len = tld_candidates

    if etld_len >= len(parts):
        etld_len = 1

    tld = parts[-1]
    etld = ".".join(parts[-etld_len:])
    sld = parts[-(etld_len + 1)] if len(parts) > etld_len else parts[0]
    root = f"{sld}.{etld}"

    if len(parts) > etld_len + 1:
        sub_parts = parts[:-(etld_len + 1)]
        sub = sub_parts[0] if sub_parts else ""
        suffix = ".".join(parts[1:]) if len(parts) > 1 else etld
    else:
        sub = sld
        suffix = etld

    result = {
        "sub": sub,
        "suffix": ".".join(parts[1:]) if len(parts) > 1 else "",
        "root": root,
        "tld": tld,
        "sld": sld,
        "etld": etld,
    }

    if len(parts) > etld_len + 1:
        sub_parts = parts[:-(etld_len + 1)]
        for i, part in enumerate(sub_parts[1:], start=1):
            result[f"sub{i}"] = part

    return result


def _detect_etld(parts: list[str]) -> int:
    """Heuristic eTLD detection for common suffixes."""
    known_etlds = {
        "co.uk", "com.br", "com.au", "co.jp", "com.mx", "com.ar",
        "co.in", "com.cn", "co.za", "com.tr", "co.kr", "co.nz",
        "org.br", "gov.br", "jus.br", "mil.br", "edu.br", "net.br",
        "com.pt", "org.uk", "gov.uk", "ac.uk", "edu.au", "gov.au",
        "co.il", "com.sg", "com.hk", "com.tw", "com.co", "com.ng",
    }
    if len(parts) >= 2:
        candidate = f"{parts[-2]}.{parts[-1]}"
        if candidate in known_etlds:
            return 2
    return 1


# ── Enrich: extract tokens from input FQDNs ──────────────────────────────────

def enrich_payloads(
    fqdns: list[str],
    base_words: list[str],
    base_numbers: list[str],
) -> tuple[list[str], list[str]]:
    """Extract word and number tokens from input FQDNs to enrich payloads.

    Args:
        fqdns: List of input FQDNs to mine tokens from.
        base_words: Existing word payloads.
        base_numbers: Existing number payloads.

    Returns:
        Tuple of (enriched_words, enriched_numbers).
    """
    extra_words: set[str] = set()
    extra_numbers: set[str] = set()
    word_set = set(base_words)
    num_set = set(base_numbers)

    for fqdn in fqdns:
        parsed = parse_fqdn(fqdn)
        sub = parsed.get("sub", "")
        if not sub:
            continue

        tokens = re.split(r"[-_.]", sub)
        for token in tokens:
            if not token:
                continue
            if re.match(r"^\d+$", token):
                if token not in num_set:
                    extra_numbers.add(token)
            elif re.match(r"^[a-zA-Z][a-zA-Z0-9]*$", token) and len(token) >= 2:
                if token.lower() not in word_set:
                    extra_words.add(token.lower())

    return (
        base_words + sorted(extra_words),
        base_numbers + sorted(extra_numbers),
    )


# ── ClusterBomb template engine ───────────────────────────────────────────────

_VAR_RE = re.compile(r"\{\{(\w+)\}\}")


def clusterbomb_generate(
    patterns: list[str],
    payloads: dict[str, list[str]],
    input_vars: dict[str, str],
    match_regex: Optional[str] = None,
    filter_regex: Optional[str] = None,
) -> Generator[str, None, None]:
    """Generate FQDNs via ClusterBomb: cartesian product of all payloads.

    Args:
        patterns: Template patterns with {{variable}} syntax.
        payloads: Named payload lists (word, number, region, etc.).
        input_vars: Input-derived variables (sub, suffix, root, tld, etc.).
        match_regex: Include filter.
        filter_regex: Exclude filter.

    Yields:
        Generated FQDNs.
    """
    match_re = re.compile(match_regex) if match_regex else None
    filter_re = re.compile(filter_regex) if filter_regex else None
    seen: set[str] = set()

    for pattern in patterns:
        var_names = _VAR_RE.findall(pattern)
        if not var_names:
            continue

        input_only = []
        payload_names = []
        for v in var_names:
            if v in input_vars:
                input_only.append(v)
            elif v in payloads:
                payload_names.append(v)

        resolved = pattern
        for v in input_only:
            resolved = resolved.replace("{{" + v + "}}", input_vars[v])

        if not payload_names:
            result = resolved
            if result and result not in seen:
                seen.add(result)
                if _passes_filter(result, match_re, filter_re):
                    yield result
            continue

        unique_names = list(dict.fromkeys(payload_names))
        lists = [payloads[n] for n in unique_names]

        for combo in product(*lists):
            result = resolved
            for name, val in zip(unique_names, combo):
                result = result.replace("{{" + name + "}}", val)

            if not result or result in seen:
                continue

            sub_part = result.split(".")[0] if "." in result else result
            if _has_duplicate_token(sub_part):
                continue

            seen.add(result)
            if _passes_filter(result, match_re, filter_re):
                yield result


def _passes_filter(s: str, match_re, filter_re) -> bool:
    if match_re and not match_re.search(s):
        return False
    if filter_re and filter_re.search(s):
        return False
    return True


def _has_duplicate_token(label: str) -> bool:
    """Skip results like 'api-api' where the same token repeats."""
    tokens = re.split(r"[-_.]", label)
    return len(tokens) != len(set(tokens))


# ── DNSCewl-style mutations ──────────────────────────────────────────────────

def dnscewl_mutations(
    words: list[str],
    domain: str,
    numeric_range: int = 10,
    extension_swap: Optional[list[str]] = None,
) -> Generator[str, None, None]:
    """Generate DNSCewl-style FQDN mutations.

    Includes: append/prepend with separators, numeric range, TLD extension swap.
    """
    seen: set[str] = set()
    parsed = parse_fqdn(domain)
    sub = parsed.get("sub", "")
    suffix = parsed.get("suffix", "")
    sld = parsed.get("sld", "")
    tld = parsed.get("tld", "")

    def emit(fqdn: str) -> Optional[str]:
        if fqdn in seen or not fqdn:
            return None
        seen.add(fqdn)
        return fqdn

    for word in words:
        for sep in ["", "-", "."]:
            r = emit(f"{word}{sep}{sub}.{suffix}" if suffix else f"{word}{sep}{domain}")
            if r:
                yield r
            r = emit(f"{sub}{sep}{word}.{suffix}" if suffix else f"{domain}{sep}{word}")
            if r:
                yield r

    if sub and re.search(r"\d+", sub):
        base = re.sub(r"\d+", "", sub)
        for n in range(max(0, -numeric_range), numeric_range + 1):
            num_str = str(abs(n)) if n >= 0 else str(abs(n))
            candidate = f"{base}{num_str}.{suffix}" if suffix else f"{base}{num_str}"
            r = emit(candidate)
            if r:
                yield r

    if extension_swap:
        for ext in extension_swap:
            ext = ext.lstrip(".")
            r = emit(f"{sld}.{ext}" if sub == sld else f"{sub}.{sld}.{ext}")
            if r:
                yield r

    for word in words:
        for dns_suf in COMMON_SUFFIXES_DNS:
            r = emit(f"{word}{dns_suf}.{domain}")
            if r:
                yield r


# ── Estimation ────────────────────────────────────────────────────────────────

def estimate_output(
    patterns: list[str],
    payloads: dict[str, list[str]],
    n_inputs: int = 1,
) -> int:
    """Estimate the number of lines the ClusterBomb will produce."""
    total = 0
    for pattern in patterns:
        var_names = _VAR_RE.findall(pattern)
        payload_names = [v for v in var_names if v in payloads]
        unique_names = list(dict.fromkeys(payload_names))
        if unique_names:
            count = 1
            for name in unique_names:
                count *= len(payloads[name])
            total += count * n_inputs
        else:
            total += n_inputs
    return total


# ── Legacy-compatible generators ──────────────────────────────────────────────

def generate_subdomain_permutations(
    words: list[str],
    domain: str,
    separators: Optional[list[str]] = None,
    use_prefixes: bool = True,
    use_suffixes: bool = True,
    match_regex: Optional[str] = None,
    filter_regex: Optional[str] = None,
) -> Generator[str, None, None]:
    """Generate subdomain permutations (legacy mode, enhanced)."""
    seps = separators or DNS_SEPARATORS
    match_re = re.compile(match_regex) if match_regex else None
    filter_re = re.compile(filter_regex) if filter_regex else None
    seen: set[str] = set()

    def emit(sub: str) -> Optional[str]:
        fqdn = f"{sub}.{domain}"
        if fqdn in seen:
            return None
        seen.add(fqdn)
        if not _passes_filter(fqdn, match_re, filter_re):
            return None
        return fqdn

    for word in words:
        r = emit(word)
        if r:
            yield r

    if use_prefixes:
        for prefix in PAYLOAD_WORD[:60]:
            for word in words:
                for sep in seps:
                    r = emit(f"{prefix}{sep}{word}")
                    if r:
                        yield r

    if use_suffixes:
        for word in words:
            for suf in COMMON_SUFFIXES_DNS:
                r = emit(f"{word}{suf}")
                if r:
                    yield r

    for w1, w2 in permutations(words[:20], 2):
        for sep in seps:
            r = emit(f"{w1}{sep}{w2}")
            if r:
                yield r


def generate_from_template(
    template: str,
    words: list[str],
    domain: str,
) -> Generator[str, None, None]:
    """Generate subdomains from a simple template with {word}/{domain}."""
    seen: set[str] = set()
    for word in words:
        result = template.replace("{word}", word).replace("{domain}", domain)
        if result not in seen:
            seen.add(result)
            yield result


def load_words_from_file(filepath: str) -> list[str]:
    """Load words from file, one per line."""
    try:
        with open(filepath, encoding="utf-8", errors="replace") as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        logger.error("File not found: %s", filepath)
        return []


def load_templates_from_yaml(filepath: str) -> list[str]:
    """Load templates from YAML file (alterx-compatible syntax).

    Supports both {{word}} and {word} notation.
    """
    try:
        import yaml
    except ImportError as exc:
        raise ImportError("PyYAML required for YAML templates: pip install pyyaml") from exc

    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"Template file not found: {filepath}")

    with path.open(encoding="utf-8") as f:
        data = yaml.safe_load(f)

    templates: list[str] = []
    payloads_from_yaml: dict[str, list[str]] = {}

    if isinstance(data, dict):
        raw = data.get("patterns", data.get("templates", []))
        for key, val in data.get("payloads", {}).items():
            if isinstance(val, list):
                payloads_from_yaml[key] = [str(v) for v in val]
    elif isinstance(data, list):
        raw = data
    else:
        raw = []

    for t in raw:
        if isinstance(t, str):
            templates.append(t)

    return templates, payloads_from_yaml


def generate_from_yaml_templates(
    templates: list[str],
    words: list[str],
    domain: str,
    match_regex: Optional[str] = None,
    filter_regex: Optional[str] = None,
    extra_payloads: Optional[dict[str, list[str]]] = None,
) -> Generator[str, None, None]:
    """Generate FQDNs from YAML templates using ClusterBomb engine.

    Supports all alterx variables: {{sub}}, {{suffix}}, {{root}}, {{word}}, etc.
    """
    parsed = parse_fqdn(domain) if domain else {}
    input_vars = {k: v for k, v in parsed.items() if v}

    payloads: dict[str, list[str]] = {
        "word": words if words else PAYLOAD_WORD,
        "number": PAYLOAD_NUMBER,
        "region": PAYLOAD_REGION,
    }
    if extra_payloads:
        payloads.update(extra_payloads)

    yield from clusterbomb_generate(
        templates, payloads, input_vars,
        match_regex=match_regex, filter_regex=filter_regex,
    )


def generate_multi_domain(
    domain_list_file: str,
    words: list[str],
    separators: Optional[list[str]] = None,
    use_prefixes: bool = True,
    use_suffixes: bool = True,
    match_regex: Optional[str] = None,
    filter_regex: Optional[str] = None,
) -> Generator[str, None, None]:
    """Process multiple domains from file."""
    domains = load_words_from_file(domain_list_file)
    if not domains:
        logger.error("No domains found in: %s", domain_list_file)
        return

    for domain in domains:
        domain = domain.strip()
        if not domain or domain.startswith("#"):
            continue
        yield from generate_subdomain_permutations(
            words, domain, separators, use_prefixes, use_suffixes,
            match_regex, filter_regex,
        )


def filter_dns_output(
    generator: Generator[str, None, None],
    match_regex: Optional[str] = None,
    filter_regex: Optional[str] = None,
) -> Generator[str, None, None]:
    """Apply regex filters to generator output."""
    match_re = re.compile(match_regex) if match_regex else None
    filter_re = re.compile(filter_regex) if filter_regex else None

    for entry in generator:
        if _passes_filter(entry, match_re, filter_re):
            yield entry
