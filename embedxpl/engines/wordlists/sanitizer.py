"""
sanitizer.py - Sanitização, ordenação e transformação de wordlists.

Funcionalidades:
  - Remover linhas em branco
  - Remover comentários (linhas iniciando com #)
  - Deduplicação (manter apenas linhas únicas)
  - Ordenação: alfabética, por comprimento, reversa, aleatória, frequência
  - Filtros de comprimento: --min-len, --max-len
  - Reverse de arquivo (cat -> tac, última linha primeiro)
  - Filtros customizados por regex
  - Strip control characters (tabs, null bytes, escape sequences)
  - Replace in-place ou para arquivo de saída

Uso:
  wlf.py sanitize lista.lst
  wlf.py sanitize lista.lst --min-len 8 --max-len 20 --sort alpha -o saida.lst
  wlf.py sanitize lista.lst --strip-control --sort frequency -o saida.lst
  wlf.py sanitize lista.lst --filter "^[a-zA-Z]" --no-comments --dedupe
  wlf.py reverse lista.lst -o invertida.lst

Autor: André Henrique (@mrhenrike)
Versão: 1.1.0
"""
from __future__ import annotations

import logging
import random
import re
from collections import Counter
from pathlib import Path
from typing import Generator, Optional

logger = logging.getLogger(__name__)

_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _is_comment_line(line: str) -> bool:
    """True only for metadata comments, not passwords starting with '#'."""
    s = line.lstrip()
    if not s.startswith("#"):
        return False
    if len(s) == 1:
        return True
    return s[1].isspace()


def _read_lines(filepath: str) -> list[str]:
    """
    Lê linhas de um arquivo preservando conteúdo original.

    Args:
        filepath: Caminho do arquivo.

    Returns:
        Lista de linhas sem terminadores.

    Raises:
        FileNotFoundError: Se o arquivo não existir.
    """
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"Arquivo não encontrado: {filepath}")
    with path.open(encoding="utf-8", errors="replace") as f:
        return [line.rstrip("\n\r") for line in f]


def sanitize(
    filepath: str,
    output: Optional[str] = None,
    no_blank: bool = True,
    no_comments: bool = True,
    dedupe: bool = True,
    sort_mode: Optional[str] = None,
    min_len: Optional[int] = None,
    max_len: Optional[int] = None,
    filter_pattern: Optional[str] = None,
    exclude_pattern: Optional[str] = None,
    inplace: bool = False,
    strip_control: bool = False,
) -> dict:
    """
    Sanitiza uma wordlist aplicando todos os filtros configurados.

    A ordem de aplicação é:
      0. Strip control characters (if strip_control=True)
      1. Remover comentários (# no início)
      2. Remover linhas em branco
      3. Filtro de comprimento (min_len / max_len)
      4. Filtro por regex (filter_pattern)
      5. Exclusão por regex (exclude_pattern)
      6. Deduplicação
      7. Ordenação (alpha, length, random, frequency)

    Args:
        filepath: Caminho do arquivo de entrada.
        output: Arquivo de saída. Se None e inplace=False, vai para stdout.
        no_blank: Remove linhas em branco.
        no_comments: Remove linhas iniciando com '#'.
        dedupe: Remove entradas duplicadas mantendo a primeira ocorrência.
        sort_mode: 'alpha', 'alpha-rev', 'length', 'length-rev', 'random' ou None.
        min_len: Comprimento mínimo (inclui linhas >= min_len).
        max_len: Comprimento máximo (inclui linhas <= max_len).
        filter_pattern: Regex - mantém apenas linhas que fazem match.
        exclude_pattern: Regex - remove linhas que fazem match.
        inplace: Se True, sobrescreve o arquivo de entrada.

    Returns:
        Dict com estatísticas: total_input, total_output, removed_blank,
        removed_comments, removed_length, removed_filter, removed_dupes.
    """
    lines = _read_lines(filepath)
    stats = {
        "total_input": len(lines),
        "removed_comments": 0,
        "removed_blank": 0,
        "removed_length": 0,
        "removed_filter": 0,
        "removed_exclude": 0,
        "removed_dupes": 0,
        "stripped_control": 0,
        "total_output": 0,
    }

    if strip_control:
        cleaned: list[str] = []
        for line in lines:
            new_line = _CONTROL_RE.sub("", line)
            if new_line != line:
                stats["stripped_control"] += 1
            cleaned.append(new_line)
        lines = cleaned

    result: list[str] = []

    for line in lines:
        # Remover comentários
        if no_comments and _is_comment_line(line):
            stats["removed_comments"] += 1
            continue

        # Remover linhas em branco
        if no_blank and not line.strip():
            stats["removed_blank"] += 1
            continue

        # Filtro de comprimento
        if min_len is not None and len(line) < min_len:
            stats["removed_length"] += 1
            continue
        if max_len is not None and len(line) > max_len:
            stats["removed_length"] += 1
            continue

        # Filtro de inclusão por regex
        if filter_pattern and not re.search(filter_pattern, line):
            stats["removed_filter"] += 1
            continue

        # Filtro de exclusão por regex
        if exclude_pattern and re.search(exclude_pattern, line):
            stats["removed_exclude"] += 1
            continue

        result.append(line)

    # Deduplicação preservando ordem de primeira ocorrência
    if dedupe:
        seen: set[str] = set()
        deduped: list[str] = []
        for line in result:
            if line not in seen:
                seen.add(line)
                deduped.append(line)
            else:
                stats["removed_dupes"] += 1
        result = deduped

    # Ordenação
    if sort_mode == "alpha":
        result.sort(key=str.lower)
    elif sort_mode == "alpha-rev":
        result.sort(key=str.lower, reverse=True)
    elif sort_mode == "length":
        result.sort(key=len)
    elif sort_mode == "length-rev":
        result.sort(key=len, reverse=True)
    elif sort_mode == "random":
        random.shuffle(result)
    elif sort_mode == "frequency":
        freq = Counter(result)
        result.sort(key=lambda x: freq[x], reverse=True)

    stats["total_output"] = len(result)

    # Destino de saída
    dest = output or (filepath if inplace else None)
    if dest:
        Path(dest).write_text("\n".join(result) + "\n", encoding="utf-8")
    else:
        for line in result:
            print(line)

    return stats


def reverse_file(
    filepath: str,
    output: Optional[str] = None,
    inplace: bool = False,
) -> int:
    """
    Inverte a ordem das linhas de um arquivo (cat -> tac).

    Args:
        filepath: Caminho do arquivo de entrada.
        output: Arquivo de saída. Se None e inplace=False, usa stdout.
        inplace: Se True, sobrescreve o arquivo de entrada.

    Returns:
        Total de linhas processadas.
    """
    lines = _read_lines(filepath)
    reversed_lines = list(reversed(lines))

    dest = output or (filepath if inplace else None)
    if dest:
        Path(dest).write_text("\n".join(reversed_lines) + "\n", encoding="utf-8")
    else:
        for line in reversed_lines:
            print(line)

    return len(reversed_lines)


def format_sanitize_stats(stats: dict, filepath: str) -> str:
    """
    Formata estatísticas de sanitização para exibição.

    Args:
        stats: Dict retornado por sanitize().
        filepath: Caminho do arquivo processado.

    Returns:
        String formatada com as estatísticas.
    """
    lines = [
        f"Sanitização: {filepath}",
        f"  Entrada:            {stats['total_input']:>10,}",
        f"  Comentários removidos: {stats['removed_comments']:>7,}",
        f"  Linhas em branco:   {stats['removed_blank']:>10,}",
        f"  Fora do comprimento:{stats['removed_length']:>10,}",
        f"  Filtro regex (excl):{stats['removed_filter']:>10,}",
        f"  Exclusão regex:     {stats['removed_exclude']:>10,}",
        f"  Duplicatas:         {stats['removed_dupes']:>10,}",
        f"  Control chars strip:{stats.get('stripped_control', 0):>10,}",
        f"  {'─'*30}",
        f"  Saída final:        {stats['total_output']:>10,}",
    ]
    return "\n".join(lines)
