"""
pattern_engine.py - Wordlist generation via templates and variables.

Inspired by the alterx (projectdiscovery) template system.

Supported variables:
  {empresa}       -> company name
  {empresa_lower} -> company name in lowercase
  {empresa_upper} -> company name in uppercase
  {cod}           -> store code (numeric)
  {cnpj}          -> CNPJ without punctuation (14 digits)
  {ano}           -> year (2016..2026)
  {cidade}        -> Brazilian city
  {dominio}       -> corporate domain
  {portal}        -> portal/system
  {seq6}          -> 6-digit sequential number

Usage examples:
  wlf.py pattern -t "SVC{cod}@acme.example" --vars cod=1000-9999
  wlf.py pattern -t "{empresa}#{ano}" --vars empresa=BrandX,CorpX ano=2020-2026
  wlf.py pattern -f patterns.txt --vars empresa=BrandX cod=1000-1999

Author: André Henrique (@mrhenrike)
Version: 1.0.0
"""
from __future__ import annotations

import logging
import re
from itertools import product
from pathlib import Path
from typing import Generator, Optional

logger = logging.getLogger(__name__)

# ── Default years for password variations ────────────────────────────────────
DEFAULT_ANOS = [str(a) for a in range(2016, 2027)]

# ── Brazilian cities for city@year patterns ───────────────────────────────────
DEFAULT_CIDADES = [
    "belem", "manaus", "natal", "recife", "fortaleza", "salvador",
    "saopaulo", "riodejaneiro", "curitiba", "goiania", "brasilia",
    "campinas", "londrina", "sorocaba", "maceio", "teresina",
    "cuiaba", "joinville", "florianopolis", "uberlandia", "joaopessoa",
    "saojoaodelrei", "niteroi", "osasco", "guarulhos", "belohorizonte",
    "portovelho", "macapa", "boa vista", "palmas", "maceioeduardo",
]

# ── Common password separators ───────────────────────────────────────────────
SEPARATORS = ["", "@", "#", ".", "-", "_", "!", "$", "%", "&"]

# ── Accent substitutions for variations ──────────────────────────────────────
ACCENT_MAP: dict[str, str] = {
    "á": "a", "à": "a", "â": "a", "ã": "a", "ä": "a",
    "é": "e", "ê": "e", "ë": "e",
    "í": "i", "î": "i", "ï": "i",
    "ó": "o", "ô": "o", "õ": "o", "ö": "o",
    "ú": "u", "û": "u", "ü": "u",
    "ç": "c",
    "Á": "A", "À": "A", "Â": "A", "Ã": "A",
    "É": "E", "Ê": "E",
    "Í": "I",
    "Ó": "O", "Ô": "O", "Õ": "O",
    "Ú": "U", "Û": "U",
    "Ç": "C",
}


def strip_accents(text: str) -> str:
    """
    Remove accents from a string using the PT-BR mapping.

    Args:
        text: String possibly containing accents.

    Returns:
        Unaccented string.
    """
    for accented, plain in ACCENT_MAP.items():
        text = text.replace(accented, plain)
    return text


def expand_variable(var_name: str, var_value: str) -> list[str]:
    """
    Expand a template variable to a list of values.

    Supports:
      - List: 'val1,val2,val3'
      - Numeric range: '1000-9999'
      - Year range: '2016-2026'
      - Single value: 'value'

    Args:
        var_name: Variable name.
        var_value: Value or variable specification.

    Returns:
        List of strings with all possible values.
    """
    # Numeric range: 1000-9999
    range_match = re.match(r"^(\d+)-(\d+)$", var_value.strip())
    if range_match:
        start, end = int(range_match.group(1)), int(range_match.group(2))
        return [str(i) for i in range(start, end + 1)]

    # Comma-separated list
    if "," in var_value:
        return [v.strip() for v in var_value.split(",") if v.strip()]

    return [var_value.strip()]


def render_template(template: str, variables: dict[str, list[str]]) -> Generator[str, None, None]:
    """
    Render a template by substituting all variables with their values.

    For each combination of variable values, yields a resulting string.

    Args:
        template: Template string with {var} placeholders.
        variables: Dict mapping variable name to list of values.

    Yields:
        Strings with all variable combinations substituted.
    """
    # Find all unique variables in the template
    var_names = list(dict.fromkeys(re.findall(r"\{(\w+)\}", template)))

    # For unresolved vars, fall back to the literal placeholder name
    resolved: list[list[str]] = []
    for var in var_names:
        values = variables.get(var, [f"{{{var}}}"])
        resolved.append(values)

    if not var_names:
        yield template
        return

    for combo in product(*resolved):
        result = template
        for var_name, value in zip(var_names, combo, strict=False):
            result = result.replace(f"{{{var_name}}}", value)
        yield result


def generate_company_patterns(
    empresa: str,
    anos: Optional[list[str]] = None,
    separators: Optional[list[str]] = None,
) -> Generator[str, None, None]:
    """
    Generate password variations based on a company name and years.

    Generated patterns:
      {empresa}{sep}{ano}    -> BrandX@2024
      {empresa}{sep}{cod}    -> BrandX#1206
      {empresa_upper}{ano}   -> BrandX2024
      {empresa_lower}{ano}   -> brandx2024

    Args:
        empresa: Company name.
        anos: List of years. Default: 2016-2026.
        separators: List of separators. Default: @, #, ., -, _.

    Yields:
        Generated password strings.
    """
    anos_list = anos or DEFAULT_ANOS
    seps = separators or ["@", "#", ".", "-", "_", "!", ""]

    empresa_plain = strip_accents(empresa)
    variants = [
        empresa_plain,
        empresa_plain.lower(),
        empresa_plain.upper(),
        empresa_plain.title(),
    ]

    seen: set[str] = set()

    for variant in variants:
        for sep in seps:
            for ano in anos_list:
                result = f"{variant}{sep}{ano}"
                if result not in seen:
                    seen.add(result)
                    yield result

    # City@year / city#year variations
    for cidade in DEFAULT_CIDADES:
        for sep in ["@", "#", "%", ""]:
            for ano in anos_list:
                result = f"{cidade}{sep}{ano}"
                if result not in seen:
                    seen.add(result)
                    yield result


def generate_pharma_patterns(
    store_codes: Optional[list[str]] = None,
    cnpjs: Optional[list[str]] = None,
    anos: Optional[list[str]] = None,
) -> Generator[str, None, None]:
    """
    Generate password variations based on patterns identified via OCR.

    Patterns:
      SVC{cod}@acme.example
      company{cnpj}
      Company#{cod}
      COMP{cod}
      company{cod}

    Args:
        store_codes: List of store codes (e.g. ['1206', '1207']).
        cnpjs: List of 14-digit CNPJs.
        anos: List of years for variations.

    Yields:
        Generated password/login strings.
    """
    base_cnpjs = cnpjs or []
    health_plan_prefixes = [
        "plan", "health", "saude", "med", "care", "vida", "seguro",
        "prevent", "assist", "clinica", "hospitalar", "dental",
    ]

    anos_list = anos or DEFAULT_ANOS

    # Store codes: if not provided, use a small OCR-derived sample
    if store_codes is None:
        store_codes = [str(c) for c in range(1200, 1215)]

    seen: set[str] = set()

    def emit(s: str) -> Generator[str, None, None]:
        if s not in seen:
            seen.add(s)
            yield s

    # Generic retail/healthcare chain patterns:
    #   {PREFIX}{store_code}@{domain}
    #   {PREFIX}#{store_code}
    #   {PREFIX}{store_code}
    chain_prefixes = ["DS", "LJ", "FIL", "UND", "SUC", "AG", "PDV", "CD"]
    for cod in store_codes:
        for pfx in chain_prefixes:
            yield from emit(f"{pfx}{cod}")
        yield from emit(f"IJ{cod}")

    for cnpj in base_cnpjs:
        for portal in ["portal", "sistema", "erp", "crm", "tickets"]:
            yield from emit(f"{portal}{cnpj}")

    # Health/insurance plan prefixes + separators + years
    for plan in health_plan_prefixes:
        for sep in ["@", "#", ".", ""]:
            for ano in anos_list:
                yield from emit(f"{plan}{sep}{ano}")
                yield from emit(f"{plan.upper()}{sep}{ano}")
                yield from emit(f"{plan.title()}{sep}{ano}")


def generate_from_template_file(
    template_file: str,
    variables: dict[str, list[str]],
) -> Generator[str, None, None]:
    """
    Read templates from a file (one per line) and render each one.

    Args:
        template_file: Path to the templates file.
        variables: Variables for substitution.

    Yields:
        Strings generated for each template.
    """
    path = Path(template_file)
    if not path.exists():
        raise FileNotFoundError(f"Template file not found: {template_file}")

    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        yield from render_template(line, variables)


def generate_pymangler_masks(
    words: list[str],
    masks: Optional[list[str]] = None,
    use_gpu: bool = False,
    target_time_hrs: float = 0.0,
    pps: int = 0,
    use_capswap: bool = False,
    min_len: int = 6,
    max_len: int = 32,
) -> Generator[str, None, None]:
    """Generate password candidates via PyMangler-style masks (w/d/s).

    Wraps :func:`mangler.overseer_expand` when a time budget is set, otherwise
    expands each mask with a per-mask cap to avoid combinatorial explosion.

    Args:
        words: Base word tokens for ``w`` positions in masks.
        masks: Mask strings (default: COMMON_MASKS from mangler).
        use_gpu: Optional GPU for Overseer PPS defaults.
        target_time_hrs: Crack time budget in hours (0 = no budget, use per-mask cap).
        pps: Passwords per second for budget (0 = auto CPU/GPU default).
        use_capswap: Apply positional case combinations to word tokens.
        min_len: Minimum candidate length.
        max_len: Maximum candidate length.

    Yields:
        Mask-expanded password candidates.
    """
    if not words:
        return

    try:
        from embedxpl.engines.wordlists.mangler import (
            COMMON_MASKS,
            OverseerConfig,
            mask_expand,
            overseer_expand,
        )
    except ImportError:
        logger.debug("mangler not available for pymangler masks")
        return

    clean_words = []
    seen: set[str] = set()
    for w in words:
        w = w.strip()
        if not w:
            continue
        key = w.lower()
        if key in seen:
            continue
        seen.add(key)
        clean_words.append(w)

    if not clean_words:
        return

    mask_list = masks or list(COMMON_MASKS)

    if target_time_hrs > 0:
        cfg = OverseerConfig(
            pps=pps,
            target_time_hrs=target_time_hrs,
            masks=mask_list,
            use_gpu=use_gpu,
            use_capswap=use_capswap,
        )
        gen: Generator[str, None, None] = overseer_expand(clean_words[:15], cfg)
    else:
        def _limited_masks() -> Generator[str, None, None]:
            for mask in mask_list[:12]:
                yield from mask_expand(
                    mask, clean_words[:10], max_output=256,
                )
        gen = _limited_masks()

    for candidate in gen:
        if min_len <= len(candidate) <= max_len:
            yield candidate
