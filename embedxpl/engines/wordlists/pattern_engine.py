"""
pattern_engine.py - Geração de wordlists por templates e variáveis.

Inspirado no sistema de templates do alterx (projectdiscovery).

Suporta variáveis:
  {empresa}       -> nome de empresa
  {empresa_lower} -> nome em minúsculas
  {empresa_upper} -> nome em maiúsculas
  {cod}           -> código de loja (numérico)
  {cnpj}          -> CNPJ sem pontuação (14 dígitos)
  {ano}           -> ano (2016..2026)
  {cidade}        -> cidade brasileira
  {dominio}       -> domínio corporativo
  {portal}        -> portal/sistema
  {seq6}          -> sequencial de 6 dígitos

Exemplos de uso:
  wlf.py pattern -t "SVC{cod}@acme.example" --vars cod=1000-9999
  wlf.py pattern -t "{empresa}#{ano}" --vars empresa=BrandX,CorpX ano=2020-2026
  wlf.py pattern -f patterns.txt --vars empresa=BrandX cod=1000-1999

Autor: André Henrique (@mrhenrike)
Versão: 1.0.0
"""
from __future__ import annotations

import logging
import re
from itertools import product
from pathlib import Path
from typing import Generator, Optional

logger = logging.getLogger(__name__)

# ── Anos padrão para variações de senha ─────────────────────────────────────
DEFAULT_ANOS = [str(a) for a in range(2016, 2027)]

# ── Cidades brasileiras para padrões cidade@ano ──────────────────────────────
DEFAULT_CIDADES = [
    "belem", "manaus", "natal", "recife", "fortaleza", "salvador",
    "saopaulo", "riodejaneiro", "curitiba", "goiania", "brasilia",
    "campinas", "londrina", "sorocaba", "maceio", "teresina",
    "cuiaba", "joinville", "florianopolis", "uberlandia", "joaopessoa",
    "saojoaodelrei", "niteroi", "osasco", "guarulhos", "belohorizonte",
    "portovelho", "macapa", "boa vista", "palmas", "maceioeduardo",
]

# ── Separadores comuns em senhas brasileiras ─────────────────────────────────
SEPARATORS = ["", "@", "#", ".", "-", "_", "!", "$", "%", "&"]

# ── Substituições de acentos para variações ──────────────────────────────────
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
    Remove acentos de uma string usando mapeamento PT-BR.

    Args:
        text: String com possíveis acentos.

    Returns:
        String sem acentos.
    """
    for accented, plain in ACCENT_MAP.items():
        text = text.replace(accented, plain)
    return text


def expand_variable(var_name: str, var_value: str) -> list[str]:
    """
    Expande uma variável de template para lista de valores.

    Suporta:
      - Lista: 'val1,val2,val3'
      - Faixa numérica: '1000-9999'
      - Faixa de anos: '2016-2026'
      - Valor único: 'valor'

    Args:
        var_name: Nome da variável.
        var_value: Valor ou especificação da variável.

    Returns:
        Lista de strings com todos os valores possíveis.
    """
    # Faixa numérica: 1000-9999
    range_match = re.match(r"^(\d+)-(\d+)$", var_value.strip())
    if range_match:
        start, end = int(range_match.group(1)), int(range_match.group(2))
        return [str(i) for i in range(start, end + 1)]

    # Lista separada por vírgula
    if "," in var_value:
        return [v.strip() for v in var_value.split(",") if v.strip()]

    return [var_value.strip()]


def render_template(template: str, variables: dict[str, list[str]]) -> Generator[str, None, None]:
    """
    Renderiza um template substituindo todas as variáveis com seus valores.

    Para cada combinação de valores das variáveis, gera uma string resultante.

    Args:
        template: String de template com variáveis {var}.
        variables: Dict mapeando nome de variável para lista de valores.

    Yields:
        Strings com todas as combinações de variáveis substituídas.
    """
    # Encontra todas as variáveis únicas no template
    var_names = list(dict.fromkeys(re.findall(r"\{(\w+)\}", template)))

    # Para vars não fornecidas, usa lista vazia substituída pelo nome
    resolved: list[list[str]] = []
    for var in var_names:
        values = variables.get(var, [f"{{{var}}}"])
        resolved.append(values)

    if not var_names:
        yield template
        return

    for combo in product(*resolved):
        result = template
        for var_name, value in zip(var_names, combo):
            result = result.replace(f"{{{var_name}}}", value)
        yield result


def generate_company_patterns(
    empresa: str,
    anos: Optional[list[str]] = None,
    separators: Optional[list[str]] = None,
) -> Generator[str, None, None]:
    """
    Gera variações de senha baseadas em nome de empresa e anos.

    Padrões gerados:
      {empresa}{sep}{ano}    -> BrandX@2024
      {empresa}{sep}{cod}    -> BrandX#1206
      {empresa_upper}{ano}   -> BrandX2024
      {empresa_lower}{ano}   -> brandx2024

    Args:
        empresa: Nome da empresa.
        anos: Lista de anos. Padrão: 2016-2026.
        separators: Lista de separadores. Padrão: @, #, ., -, _.

    Yields:
        Strings de senhas geradas.
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

    # Variações cidade@ano / cidade#ano
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
    Gera variações de senha baseadas nos padrões identificados via OCR.

    Padrões:
      SVC{cod}@acme.example
      company{cnpj}
      Company#{cod}
      COMP{cod}
      company{cod}

    Args:
        store_codes: Lista de códigos de loja (ex: ['1206', '1207']).
        cnpjs: Lista de CNPJs de 14 dígitos.
        anos: Lista de anos para variações.

    Yields:
        Strings de senhas/logins geradas.
    """
    base_cnpjs = cnpjs or []
    health_plan_prefixes = [
        "plan", "health", "saude", "med", "care", "vida", "seguro",
        "prevent", "assist", "clinica", "hospitalar", "dental",
    ]

    anos_list = anos or DEFAULT_ANOS

    # Códigos de loja: se não fornecidos, usa amostra pequena (OCR + vizinhos)
    if store_codes is None:
        store_codes = [str(c) for c in range(1200, 1215)]  # amostra OCR

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
    Lê templates de um arquivo (um por linha) e renderiza cada um.

    Args:
        template_file: Caminho para arquivo de templates.
        variables: Variáveis para substituição.

    Yields:
        Strings geradas para cada template.
    """
    path = Path(template_file)
    if not path.exists():
        raise FileNotFoundError(f"Arquivo de templates não encontrado: {template_file}")

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
            overseer_expand,
            OverseerConfig,
            mask_expand,
            COMMON_MASKS,
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
