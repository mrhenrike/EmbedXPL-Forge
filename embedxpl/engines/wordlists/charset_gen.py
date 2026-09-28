"""
charset_gen.py - Geração de wordlists por charset e pattern (estilo Crunch).

Suporta:
  - Placeholders Crunch-style: @ minúsculas, , maiúsculas, % números, ^ especiais
  - Hashcat-style masks: ?u ?l ?d ?s ?a ?b em qualquer posição
  - Geração com restrições de composição: N dígitos + M minúsculas em comprimento L
  - Charsets built-in: alpha, ualpha, lalpha, numeric, mixalpha, mixalpha-numeric
  - Charset files externos (.cfg) com charsets nomeados
  - Modo phone: geração de telefones com DDDs brasileiros
  - Estimativa de tamanho antes de gerar
  - Wizard interativo para criar charset files (--create-charset)

Exemplos:
  wlf.py charset 6 8 abc123
  wlf.py charset 8 8 -p "@,%,^" --pattern "Pass@@@%%%"
  wlf.py charset 8 8 --mask "?u?l?l?l?d?d?s"
  wlf.py charset 8 8 --digits 2 --lower 4 --upper 1 --special 1
  wlf.py charset 10 10 -t phone --prefix "+5511"
  wlf.py charset 6 8 -f my_charsets.cfg mixalpha-numeric
  wlf.py charset --create-charset my_charsets.cfg

Autor: André Henrique (@mrhenrike)
Versão: 1.1.0
"""
from __future__ import annotations

import logging
import os
import sys
from configparser import ConfigParser
from itertools import combinations, permutations, product
from math import log10
from pathlib import Path
from typing import Generator, Optional

logger = logging.getLogger(__name__)

# ── Charsets built-in ────────────────────────────────────────────────────────

BUILTIN_CHARSETS: dict[str, str] = {
    "lalpha":          "abcdefghijklmnopqrstuvwxyz",
    "ualpha":          "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "alpha":           "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "numeric":         "0123456789",
    "mixalpha":        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "mixalpha-numeric": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
    "special":         "!@#$%^&*()-_+=~`[]{}|\\:;\"'<>,.?/",
    "mixalpha-numeric-special":
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_+=",
    "pt-br-accented":  "abcdefghijklmnopqrstuvwxyzàáâãéêíóôõúüç",
    "hex-lower":       "0123456789abcdef",
    "hex-upper":       "0123456789ABCDEF",
}

# Mapeamento de placeholders estilo Crunch
PLACEHOLDER_MAP: dict[str, str] = {
    "@": BUILTIN_CHARSETS["lalpha"],
    ",": BUILTIN_CHARSETS["ualpha"],
    "%": BUILTIN_CHARSETS["numeric"],
    "^": BUILTIN_CHARSETS["special"],
}

# Mapeamento de placeholders estilo Hashcat (?u ?l ?d ?s ?a)
HASHCAT_MASK_MAP: dict[str, str] = {
    "?u": BUILTIN_CHARSETS["ualpha"],
    "?l": BUILTIN_CHARSETS["lalpha"],
    "?d": BUILTIN_CHARSETS["numeric"],
    "?s": BUILTIN_CHARSETS["special"],
    "?a": BUILTIN_CHARSETS["mixalpha-numeric-special"],
    "?h": "0123456789abcdef",
    "?H": "0123456789ABCDEF",
}

# DDDs brasileiros para modo phone
DDDS_BR = [
    "11", "12", "13", "14", "15", "16", "17", "18", "19",
    "21", "22", "24", "27", "28",
    "31", "32", "33", "34", "35", "37", "38",
    "41", "42", "43", "44", "45", "46", "47", "48", "49",
    "51", "53", "54", "55",
    "61", "62", "63", "64", "65", "66", "67", "68", "69",
    "71", "73", "74", "75", "77", "79",
    "81", "82", "83", "84", "85", "86", "87", "88", "89",
    "91", "92", "93", "94", "95", "96", "97", "98", "99",
]


def load_charset_file(filepath: str, charset_name: str) -> str:
    """
    Carrega um charset nomeado de um arquivo .cfg.

    Formato do arquivo:
      [mixalpha-numeric]
      abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789

    Args:
        filepath: Caminho para o arquivo .cfg.
        charset_name: Nome do charset a carregar.

    Returns:
        String com os caracteres do charset.

    Raises:
        FileNotFoundError: Se o arquivo não existir.
        KeyError: Se o charset_name não existir no arquivo.
    """
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"Charset file não encontrado: {filepath}")

    cfg = ConfigParser()
    cfg.read(str(path), encoding="utf-8")

    if charset_name not in cfg:
        available = list(cfg.sections())
        raise KeyError(
            f"Charset '{charset_name}' não encontrado em {filepath}. "
            f"Disponíveis: {available}"
        )

    # O valor do charset é a primeira key do bloco (pode ser multilinha)
    section = cfg[charset_name]
    chars = ""
    for key in section:
        chars += key + section[key]

    return chars.replace("\n", "").replace("\r", "")


def get_charset(
    charset: str,
    charset_file: Optional[str] = None,
) -> str:
    """
    Resolve um charset pelo nome (built-in ou de arquivo externo).

    Args:
        charset: Nome do charset ou string de caracteres direta.
        charset_file: Caminho para arquivo .cfg opcional.

    Returns:
        String com os caracteres únicos do charset.
    """
    if charset_file:
        return load_charset_file(charset_file, charset)
    if charset in BUILTIN_CHARSETS:
        return BUILTIN_CHARSETS[charset]
    # Trata como string de chars diretos
    return "".join(dict.fromkeys(charset))


def estimate_size(charset_len: int, min_len: int, max_len: int) -> tuple[int, str]:
    """
    Estima o número de palavras e tamanho em disco antes de gerar.

    Args:
        charset_len: Tamanho do charset.
        min_len: Comprimento mínimo.
        max_len: Comprimento máximo.

    Returns:
        Tupla (total_palavras, tamanho_formatado).
    """
    total = sum(charset_len ** length for length in range(min_len, max_len + 1))
    # Estimativa de bytes: tamanho médio de palavra + newline
    avg_len = (min_len + max_len) / 2
    bytes_est = total * (avg_len + 1)

    if bytes_est < 1024:
        size_str = f"{bytes_est:.0f} B"
    elif bytes_est < 1024**2:
        size_str = f"{bytes_est/1024:.1f} KB"
    elif bytes_est < 1024**3:
        size_str = f"{bytes_est/1024**2:.1f} MB"
    elif bytes_est < 1024**4:
        size_str = f"{bytes_est/1024**3:.1f} GB"
    else:
        size_str = f"{bytes_est/1024**4:.1f} TB"

    return total, size_str


def generate_by_charset(
    charset: str,
    min_len: int,
    max_len: int,
) -> Generator[str, None, None]:
    """
    Gera todas as combinações de caracteres do charset para comprimentos min..max.

    Args:
        charset: String de caracteres a usar.
        min_len: Comprimento mínimo.
        max_len: Comprimento máximo.

    Yields:
        Strings geradas em ordem lexicográfica.
    """
    chars = list(dict.fromkeys(charset))
    for length in range(min_len, max_len + 1):
        for combo in product(chars, repeat=length):
            yield "".join(combo)


def generate_by_pattern(
    pattern: str,
    charset_file: Optional[str] = None,
    extra_charset: Optional[str] = None,
) -> Generator[str, None, None]:
    """
    Gera strings com base em um pattern com placeholders.

    Placeholders suportados (estilo Crunch):
      @  -> letras minúsculas
      ,  -> letras maiúsculas
      %  -> dígitos
      ^  -> caracteres especiais
      ?  -> custom (requer extra_charset)

    Caracteres literais são mantidos como estão.

    Args:
        pattern: String de pattern com placeholders.
        charset_file: Arquivo de charset para lookup adicional.
        extra_charset: Charset extra para placeholder '?'.

    Yields:
        Strings geradas pelo pattern.
    """
    slots: list[list[str]] = []
    for ch in pattern:
        if ch in PLACEHOLDER_MAP:
            slots.append(list(PLACEHOLDER_MAP[ch]))
        elif ch == "?" and extra_charset:
            slots.append(list(dict.fromkeys(extra_charset)))
        else:
            slots.append([ch])

    for combo in product(*slots):
        yield "".join(combo)


def generate_phone_numbers(
    prefix: str = "+55",
    ddds: Optional[list[str]] = None,
) -> Generator[str, None, None]:
    """
    Gera números de telefone brasileiros com DDDs.

    Args:
        prefix: Prefixo internacional (ex: '+55', '0055').
        ddds: Lista de DDDs; se None, usa todos os DDDs BR.

    Yields:
        Números de telefone formatados.
    """
    ddd_list = ddds or DDDS_BR
    for ddd in ddd_list:
        # Celular: 9XXXX-XXXX (9 dígitos)
        for i in product("0123456789", repeat=8):
            yield f"{prefix}{ddd}9{''.join(i)}"
        # Fixo: XXXX-XXXX (8 dígitos)
        for i in product("0123456789", repeat=8):
            yield f"{prefix}{ddd}{''.join(i)}"


def generate_by_mask(
    mask: str,
    custom_charset: Optional[str] = None,
) -> Generator[str, None, None]:
    """
    Gera wordlist a partir de uma máscara estilo Hashcat.

    Tokens suportados:
      ?u  → uppercase letters (A-Z)
      ?l  → lowercase letters (a-z)
      ?d  → digits (0-9)
      ?s  → special chars (!@#$%...)
      ?a  → all printable (alpha+digits+special)
      ?h  → hex lowercase (0-9a-f)
      ?H  → hex uppercase (0-9A-F)
      ?1  → custom charset (requer custom_charset)
      Qualquer outro char → literal

    Args:
        mask: String de máscara (ex: "?u?l?l?l?d?d?s").
        custom_charset: Charset para ?1 (user-defined).

    Yields:
        Strings geradas.

    Examples:
        generate_by_mask("?u?l?l?d?d")   # Aabb12-style
        generate_by_mask("Pass?d?d?d?d") # Pass0000..Pass9999
    """
    slots: list[list[str]] = []
    i = 0
    while i < len(mask):
        if mask[i] == "?" and i + 1 < len(mask):
            token = mask[i : i + 2]
            if token in HASHCAT_MASK_MAP:
                slots.append(list(HASHCAT_MASK_MAP[token]))
                i += 2
                continue
            elif token == "?1" and custom_charset:
                slots.append(list(dict.fromkeys(custom_charset)))
                i += 2
                continue
        slots.append([mask[i]])
        i += 1

    for combo in product(*slots):
        yield "".join(combo)


def estimate_mask_size(mask: str, custom_charset: Optional[str] = None) -> tuple[int, str]:
    """
    Estima o número de entradas para uma máscara Hashcat.

    Args:
        mask: Máscara estilo Hashcat.
        custom_charset: Charset para ?1.

    Returns:
        Tupla (total_entradas, tamanho_formatado).
    """
    slot_sizes: list[int] = []
    i = 0
    fixed_len = 0
    while i < len(mask):
        if mask[i] == "?" and i + 1 < len(mask):
            token = mask[i : i + 2]
            if token in HASHCAT_MASK_MAP:
                slot_sizes.append(len(HASHCAT_MASK_MAP[token]))
                i += 2
                continue
            elif token == "?1" and custom_charset:
                slot_sizes.append(len(dict.fromkeys(custom_charset)))
                i += 2
                continue
        slot_sizes.append(1)  # literal
        fixed_len += 1
        i += 1

    total = 1
    for s in slot_sizes:
        total *= s

    mask_len = len(slot_sizes)
    bytes_est = total * (mask_len + 1)
    if bytes_est < 1024:
        size_str = f"{bytes_est:.0f} B"
    elif bytes_est < 1024**2:
        size_str = f"{bytes_est/1024:.1f} KB"
    elif bytes_est < 1024**3:
        size_str = f"{bytes_est/1024**2:.1f} MB"
    elif bytes_est < 1024**4:
        size_str = f"{bytes_est/1024**3:.1f} GB"
    else:
        size_str = f"{bytes_est/1024**4:.1f} TB"

    return total, size_str


def generate_constrained(
    length: int,
    n_digits: int = 0,
    n_lower: int = 0,
    n_upper: int = 0,
    n_special: int = 0,
) -> Generator[str, None, None]:
    """
    Gera combinações com composição exata de tipos de caracteres.

    Garante exatamente N dígitos, M minúsculas, K maiúsculas e P especiais
    no comprimento total L. Útil para atender políticas de senha.

    Args:
        length: Comprimento total da senha.
        n_digits: Quantidade exata de dígitos.
        n_lower: Quantidade exata de letras minúsculas.
        n_upper: Quantidade exata de letras maiúsculas.
        n_special: Quantidade exata de caracteres especiais.

    Yields:
        Strings geradas com a composição especificada.

    Raises:
        ValueError: Se a soma das restrições não cobrir o comprimento total.

    Examples:
        generate_constrained(8, n_digits=2, n_lower=4, n_upper=1, n_special=1)
    """
    required = n_digits + n_lower + n_upper + n_special
    free = length - required
    if free < 0:
        raise ValueError(
            f"Restrições somam {required} mas comprimento é {length}. "
            "Reduza as contagens ou aumente o comprimento."
        )

    digits_chars = list(BUILTIN_CHARSETS["numeric"])
    lower_chars = list(BUILTIN_CHARSETS["lalpha"])
    upper_chars = list(BUILTIN_CHARSETS["ualpha"])
    special_chars = list(BUILTIN_CHARSETS["special"])
    all_chars = list(BUILTIN_CHARSETS["mixalpha-numeric-special"])

    # Cada slot de posição → charsets possíveis
    # Construir pool de slots baseado nas restrições
    slot_pools: list[list[str]] = []
    slot_pools.extend([digits_chars] * n_digits)
    slot_pools.extend([lower_chars] * n_lower)
    slot_pools.extend([upper_chars] * n_upper)
    slot_pools.extend([special_chars] * n_special)
    slot_pools.extend([all_chars] * free)

    # Gerar todas as permutações de posições dos slots
    seen: set[str] = set()
    n_slots = len(slot_pools)

    for pos_order in set(permutations(range(n_slots))):
        ordered_pools = [slot_pools[i] for i in pos_order]
        for combo in product(*ordered_pools):
            word = "".join(combo)
            if word not in seen:
                seen.add(word)
                yield word


def estimate_constrained_size(
    length: int,
    n_digits: int = 0,
    n_lower: int = 0,
    n_upper: int = 0,
    n_special: int = 0,
) -> tuple[int, str]:
    """
    Estima o número de entradas para geração com restrições de composição.

    Args:
        length: Comprimento total.
        n_digits: Quantidade de dígitos obrigatórios.
        n_lower: Quantidade de minúsculas obrigatórias.
        n_upper: Quantidade de maiúsculas obrigatórias.
        n_special: Quantidade de especiais obrigatórios.

    Returns:
        Tupla (total_estimado, tamanho_formatado).
    """
    from math import factorial, comb

    d = len(BUILTIN_CHARSETS["numeric"])
    l_ = len(BUILTIN_CHARSETS["lalpha"])
    u = len(BUILTIN_CHARSETS["ualpha"])
    s = len(BUILTIN_CHARSETS["special"])
    a = len(BUILTIN_CHARSETS["mixalpha-numeric-special"])
    free = length - n_digits - n_lower - n_upper - n_special

    if free < 0:
        return 0, "0 B"

    # Combinações de valores × permutações de posições
    value_combos = (d ** n_digits) * (l_ ** n_lower) * (u ** n_upper) * (s ** n_special) * (a ** free)

    # Multinomial coefficient for position arrangements
    total_slots = n_digits + n_lower + n_upper + n_special + free
    denom = factorial(n_digits) * factorial(n_lower) * factorial(n_upper) * factorial(n_special) * factorial(free)
    arrangements = factorial(total_slots) // denom

    total = value_combos * arrangements
    bytes_est = total * (length + 1)
    if bytes_est < 1024:
        size_str = f"{bytes_est:.0f} B"
    elif bytes_est < 1024**2:
        size_str = f"{bytes_est/1024:.1f} KB"
    elif bytes_est < 1024**3:
        size_str = f"{bytes_est/1024**2:.1f} MB"
    elif bytes_est < 1024**4:
        size_str = f"{bytes_est/1024**3:.1f} GB"
    else:
        size_str = f"{bytes_est/1024**4:.1f} TB"

    return total, size_str


def create_charset_wizard(output_file: str) -> None:
    """
    Wizard interativo para criar um arquivo de charset .cfg.

    Guia o usuário pelo processo de definição de charsets nomeados
    e salva no formato .cfg compatível com wlf.py.

    Args:
        output_file: Caminho do arquivo de saída.
    """
    print("\n=== Wizard de Criação de Charset File ===\n")
    print(f"Destino: {output_file}")
    print("Defina charsets nomeados. Digite 'fim' para encerrar.\n")

    charsets: dict[str, str] = {}

    while True:
        name = input("Nome do charset (ex: 'mixalpha', 'custom-corp', ou 'fim' para encerrar): ").strip()
        if name.lower() == "fim":
            break
        if not name:
            print("Nome não pode ser vazio.")
            continue
        chars = input(f"Caracteres para '{name}': ").strip()
        if not chars:
            print("Charset não pode ser vazio.")
            continue
        charsets[name] = "".join(dict.fromkeys(chars))
        print(f"  OK '{name}' com {len(charsets[name])} caracteres únicos.\n")

    if not charsets:
        print("Nenhum charset definido. Abortando.")
        return

    # Gerar arquivo
    lines = []
    for name, chars in charsets.items():
        lines.append(f"[{name}]")
        lines.append(chars)
        lines.append("")

    Path(output_file).write_text("\n".join(lines), encoding="utf-8")
    print(f"\nCharset file salvo em: {output_file}")
    print(f"Charsets criados: {list(charsets.keys())}")
    print(f"\nUso: wlf.py charset 6 8 -f {output_file} <nome_do_charset>")
