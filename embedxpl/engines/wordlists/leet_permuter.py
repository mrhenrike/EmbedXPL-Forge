"""
leet_permuter.py - Geração de permutações leet speak e variações de escrita.

Modos disponíveis:
  basic      - Substituições mais comuns (a->@, e->3, i->1, o->0, s->$)
  medium     - Substituições expandidas (t->7, l->1, b->6, etc.)
  aggressive - Todas as substituições possíveis + combinações
  custom     - Mapeamento definido pelo usuário (ex: a=@,4;t=7;s=$)

Referência: C code permutation engine (GeekUniao), CUPP 1337 mode.
Autor: André Henrique (@mrhenrike)
Versão: 1.0.0
"""
from __future__ import annotations

import logging
import zlib
from itertools import product
from typing import Generator, Iterable

logger = logging.getLogger(__name__)

# ── Mapeamentos de substituição leet ────────────────────────────────────────

LEET_BASIC: dict[str, list[str]] = {
    "a": ["a", "@"],
    "A": ["A", "@", "4"],
    "e": ["e", "3"],
    "E": ["E", "3"],
    "i": ["i", "1"],
    "I": ["I", "1", "!"],
    "o": ["o", "0"],
    "O": ["O", "0"],
    "s": ["s", "$"],
    "S": ["S", "$"],
}

LEET_MEDIUM: dict[str, list[str]] = {
    **LEET_BASIC,
    "a": ["a", "@", "4"],
    "A": ["A", "@", "4"],
    "b": ["b", "6", "8"],
    "B": ["B", "6", "8"],
    "c": ["c", "(", "ç"],
    "C": ["C", "(", "Ç"],
    "g": ["g", "9"],
    "G": ["G", "9"],
    "h": ["h", "#"],
    "H": ["H", "#"],
    "i": ["i", "1", "!", "|"],
    "I": ["I", "1", "!", "|", "l"],
    "l": ["l", "1", "|", "!"],
    "L": ["L", "1", "|"],
    "n": ["n"],
    "N": ["N"],
    "q": ["q", "9"],
    "t": ["t", "7"],
    "T": ["T", "7"],
    "u": ["u", "v"],
    "U": ["U", "V"],
    "z": ["z", "2"],
    "Z": ["Z", "2"],
}

LEET_AGGRESSIVE: dict[str, list[str]] = {
    **LEET_MEDIUM,
    "a": ["a", "@", "4", "^", "∂"],
    "A": ["A", "@", "4", "^"],
    "b": ["b", "6", "8", "|3", "|}"],
    "B": ["B", "6", "8", "|3"],
    "c": ["c", "(", "ç", "<", "{"],
    "C": ["C", "(", "Ç", "<", "{"],
    "d": ["d", "|>", "cl"],
    "D": ["D", "|>"],
    "e": ["e", "3", "€", "&"],
    "E": ["E", "3", "€"],
    "f": ["f", "|=", "ph"],
    "F": ["F", "|="],
    "g": ["g", "9", "6", "&"],
    "G": ["G", "9", "6"],
    "h": ["h", "#", "|-|", "4"],
    "H": ["H", "#", "|-|"],
    "i": ["i", "1", "!", "|", "l", "eye"],
    "I": ["I", "1", "!", "|", "l"],
    "j": ["j", "_|"],
    "J": ["J", "_|"],
    "k": ["k", "|<", "|("],
    "K": ["K", "|<", "|("],
    "l": ["l", "1", "|", "!", "i"],
    "L": ["L", "1", "|", "!"],
    "m": ["m", "/\\/\\", "|v|"],
    "M": ["M", "/\\/\\"],
    "n": ["n", "|\\|"],
    "N": ["N", "|\\|"],
    "o": ["o", "0", "()", "[]"],
    "O": ["O", "0", "()", "[]"],
    "p": ["p", "|°", "ph"],
    "P": ["P", "|°"],
    "q": ["q", "9", "(,)", "0_"],
    "Q": ["Q", "9"],
    "r": ["r", "|2", "/2"],
    "R": ["R", "|2"],
    "s": ["s", "$", "5", "z"],
    "S": ["S", "$", "5"],
    "t": ["t", "7", "+", "†"],
    "T": ["T", "7", "+"],
    "u": ["u", "v", "|_|"],
    "U": ["U", "V", "|_|"],
    "v": ["v", "\\/"],
    "V": ["V", "\\/"],
    "w": ["w", "\\/\\/", "vv"],
    "W": ["W", "\\/\\/"],
    "x": ["x", "><", "*"],
    "X": ["X", "><"],
    "y": ["y", "¥", "j"],
    "Y": ["Y", "¥"],
    "z": ["z", "2", "7_"],
    "Z": ["Z", "2"],
}


ELPSCRK_LEVELS: dict[int, str] = {
    0: "basic (name+date only)",
    1: "standard (combos + suffixes)",
    2: "extended (leet + reversed + upper)",
    3: "full (OWASP chars appended)",
    4: "intensive (perm depth + custom years)",
    5: "max (unconstrained perm)",
}


def leet_perm_wordlist(
    words: Iterable[str],
    leet_map: dict[str, str] | None = None,
    max_per_word: int = 512,
) -> Generator[str, None, None]:
    """Apply cartesian leet permutation across an entire wordlist.

    Ports elpscrk's leet_perm: for each word, generates the full cartesian
    product of {original_char, leet_sub(char)} for every character position.
    Unlike token-level leet applied during generation, this is a global pass
    over the completed wordlist.

    Args:
        words: Input wordlist (list or any iterable of strings).
        leet_map: Simple char-to-char substitution map. Defaults to LEET_MEDIUM
                  (first non-original substitution per character).
        max_per_word: Maximum product iterations per word to prevent combinatorial
                      explosion.

    Yields:
        Unique word variants (including originals) deduplicated via CRC32.
    """
    if leet_map is None:
        leet_map = {
            k: (v[1] if len(v) > 1 else k)
            for k, v in LEET_MEDIUM.items()
        }

    seen_crc: set[int] = set()

    for word in words:
        char_sets = [{c, leet_map.get(c, c)} for c in word]
        count = 0
        for combo in product(*char_sets):
            if count >= max_per_word:
                break
            count += 1
            variant = "".join(combo)
            crc = zlib.crc32(variant.encode())
            if crc not in seen_crc:
                seen_crc.add(crc)
                yield variant


def parse_custom_mapping(mapping_str: str) -> dict[str, list[str]]:
    """
    Converte string de mapeamento customizado em dict de substituições.

    Formato: 'a=@,4;t=7;s=$;l=1,|'
    Cada par char=subs separado por ';', subs separadas por ','

    Args:
        mapping_str: String de mapeamento no formato descrito.

    Returns:
        Dict mapeando cada char para lista de substituições.
    """
    mapping: dict[str, list[str]] = {}
    if not mapping_str:
        return mapping
    for pair in mapping_str.split(";"):
        pair = pair.strip()
        if "=" not in pair:
            continue
        char, subs_raw = pair.split("=", 1)
        char = char.strip()
        subs = [s.strip() for s in subs_raw.split(",") if s.strip()]
        if char and subs:
            if char not in mapping:
                mapping[char] = [char]
            mapping[char].extend([s for s in subs if s not in mapping[char]])
    return mapping


def _get_table(mode: str, custom_mapping: str = "") -> dict[str, list[str]]:
    """
    Retorna a tabela de substituições para o modo especificado.

    Args:
        mode: 'basic', 'medium', 'aggressive' ou 'custom'.
        custom_mapping: String de mapeamento (apenas para modo 'custom').

    Returns:
        Dict de substituições leet para o modo escolhido.
    """
    if mode == "basic":
        return LEET_BASIC
    elif mode == "medium":
        return LEET_MEDIUM
    elif mode == "aggressive":
        return LEET_AGGRESSIVE
    elif mode == "custom":
        return parse_custom_mapping(custom_mapping)
    else:
        raise ValueError(f"Modo leet inválido: {mode}. Use basic|medium|aggressive|custom")


def generate_leet(
    word: str,
    mode: str = "basic",
    custom_mapping: str = "",
    max_results: int = 10000,
) -> Generator[str, None, None]:
    """
    Gera todas as permutações leet para uma palavra no modo especificado.

    No modo 'aggressive', o número de combinações pode ser muito alto.
    Use max_results para limitar o output.

    Args:
        word: Palavra de entrada.
        mode: Modo de substituição ('basic', 'medium', 'aggressive', 'custom').
        custom_mapping: Mapeamento customizado (apenas para mode='custom').
        max_results: Limite máximo de resultados gerados.

    Yields:
        Strings com variações leet da palavra.
    """
    table = _get_table(mode, custom_mapping)

    # Para cada caractere, obtém lista de possíveis substituições
    char_options: list[list[str]] = []
    for ch in word:
        opts = table.get(ch, [ch])
        if not opts:
            opts = [ch]
        char_options.append(opts)

    count = 0
    for combination in product(*char_options):
        if count >= max_results:
            logger.debug("Limite de %d resultados atingido para '%s'", max_results, word)
            break
        yield "".join(combination)
        count += 1


def generate_case_variations(word: str) -> Generator[str, None, None]:
    """
    Gera variações de caixa (uppercase, lowercase, title, toggle).

    Args:
        word: Palavra de entrada.

    Yields:
        Variações de escrita: original, upper, lower, title, swapcase.
    """
    seen: set[str] = set()
    for variant in [word, word.upper(), word.lower(), word.title(), word.swapcase()]:
        if variant not in seen:
            seen.add(variant)
            yield variant


def generate_all_variations(
    word: str,
    leet_mode: str = "basic",
    custom_mapping: str = "",
    include_case: bool = True,
    max_leet: int = 5000,
) -> Generator[str, None, None]:
    """
    Gera variações completas: case + leet para uma palavra.

    Args:
        word: Palavra base.
        leet_mode: Modo leet a aplicar.
        custom_mapping: Mapeamento customizado.
        include_case: Se True, aplica variações de case antes do leet.
        max_leet: Limite de permutações leet por variação de case.

    Yields:
        Todas as variações únicas geradas.
    """
    seen: set[str] = set()

    base_words = list(generate_case_variations(word)) if include_case else [word]

    for base in base_words:
        for leet in generate_leet(base, leet_mode, custom_mapping, max_leet):
            if leet not in seen:
                seen.add(leet)
                yield leet


def permute_geek_uniao(password: str) -> Generator[str, None, None]:
    """
    Porta Python do algoritmo C de permutação GeekUniao.

    Gera todas as combinações caractere-a-caractere para uma senha,
    usando o mapeamento agressivo de substituições.

    Equivalente ao código C fornecido com strU, strN, strI, strA, strO,
    strG, strE, strK e strNumEsp combinados em loops aninhados.

    Args:
        password: Senha base a permutar.

    Yields:
        Todas as permutações da senha.
    """
    yield from generate_leet(password, mode="aggressive", max_results=100000)
