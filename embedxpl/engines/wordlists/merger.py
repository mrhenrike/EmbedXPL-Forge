"""
merger.py - Fusão, filtragem e deduplicação de wordlists.

Funcionalidades:
  - Merge de múltiplos arquivos com deduplicação
  - Filtragem por comprimento, charset, padrão regex
  - Ordenação (alfabética, por comprimento, aleatória)
  - Remoção de entradas puramente numéricas
  - Output streaming para grandes volumes

Uso:
  wlf.py merge lista1.lst lista2.lst -o merged.lst
  wlf.py merge *.lst --min-len 8 --no-numeric --sort alpha
  wlf.py merge lista.lst --filter "^[a-z]+$" --dedupe

Autor: André Henrique (@mrhenrike)
Versão: 1.0.0
"""
from __future__ import annotations

import logging
import random
import re
from collections import Counter
from pathlib import Path
from typing import Generator, Optional

logger = logging.getLogger(__name__)


def _is_purely_numeric(s: str) -> bool:
    """
    Verifica se uma string é composta apenas de dígitos.

    Args:
        s: String a verificar.

    Returns:
        True se a string for puramente numérica.
    """
    return bool(re.fullmatch(r"\d+", s))


def stream_merged(
    filepaths: list[str],
    min_len: int = 6,
    max_len: int = 128,
    no_numeric: bool = False,
    filter_pattern: Optional[str] = None,
    dedupe: bool = True,
    sort_mode: Optional[str] = None,
) -> Generator[str, None, None]:
    """
    Faz merge de múltiplas wordlists com filtragem e deduplicação.

    Args:
        filepaths: Lista de caminhos das wordlists a fundir.
        min_len: Comprimento mínimo das entradas.
        max_len: Comprimento máximo das entradas.
        no_numeric: Se True, remove entradas puramente numéricas.
        filter_pattern: Regex para filtrar entradas (apenas matches passam).
        dedupe: Se True, remove duplicatas.
        sort_mode: 'alpha', 'length', 'random' ou None (ordem de input).

    Yields:
        Entradas filtradas e deduplicadas.
    """
    compiled_filter = re.compile(filter_pattern) if filter_pattern else None
    seen: set[str] = set()
    entries: list[str] = []

    for filepath in filepaths:
        path = Path(filepath)
        if not path.exists():
            logger.warning("Arquivo não encontrado: %s", filepath)
            continue

        with path.open(encoding="utf-8", errors="replace") as f:
            for line in f:
                entry = line.rstrip("\n\r")
                if not entry:
                    continue
                if len(entry) < min_len or len(entry) > max_len:
                    continue
                if no_numeric and _is_purely_numeric(entry):
                    continue
                if compiled_filter and not compiled_filter.search(entry):
                    continue
                if dedupe:
                    if entry in seen:
                        continue
                    seen.add(entry)
                entries.append(entry)

    # Ordenação
    if sort_mode == "alpha":
        entries.sort(key=str.lower)
    elif sort_mode == "length":
        entries.sort(key=len)
    elif sort_mode == "random":
        random.shuffle(entries)
    elif sort_mode == "frequency":
        freq = Counter(entries)
        entries.sort(key=lambda x: freq[x], reverse=True)

    yield from entries


def merge_to_file(
    filepaths: list[str],
    output_path: str,
    min_len: int = 6,
    max_len: int = 128,
    no_numeric: bool = False,
    filter_pattern: Optional[str] = None,
    dedupe: bool = True,
    sort_mode: Optional[str] = None,
) -> int:
    """
    Faz merge de wordlists e salva em arquivo.

    Args:
        filepaths: Lista de arquivos de entrada.
        output_path: Caminho do arquivo de saída.
        min_len: Comprimento mínimo.
        max_len: Comprimento máximo.
        no_numeric: Se True, remove entradas numéricas.
        filter_pattern: Regex de filtragem.
        dedupe: Se True, remove duplicatas.
        sort_mode: Modo de ordenação.

    Returns:
        Total de entradas escritas.
    """
    out = Path(output_path)
    count = 0
    with out.open("w", encoding="utf-8") as f:
        for entry in stream_merged(
            filepaths, min_len, max_len, no_numeric,
            filter_pattern, dedupe, sort_mode,
        ):
            f.write(entry + "\n")
            count += 1

    logger.info("Merge concluído: %d entradas em %s", count, output_path)
    return count
