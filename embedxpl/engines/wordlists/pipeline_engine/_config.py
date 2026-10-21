"""
pipeline_engine.py - Orquestrador multi-estágio para geração de wordlists de perfil.

Coordena os motores de geração na ordem correta, com deduplicação streaming,
controle de limite/timeout, e feedback loop contra alvos conhecidos.

Pipeline padrão (profile OSINT):
  1. Profiler core (tokens + depth combos + date tokens + CUPP)
  2. Módulos órfãos (osint_perm, password_dna, pattern_engine, num2text)
  3. Pós-processamento (rsmangler, builtin_mangle, prince)
  4. Ranking (pattern_ranker, anomaly_scorer)
  5. Feedback loop (benchmark vs known_targets)
  6. Finalização (sanitize + sort + archive export)

Author: André Henrique (@mrhenrike)
"""
from __future__ import annotations

import logging
import time
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Generator, Optional

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_PROJECT_TMP = _PROJECT_ROOT / ".tmp"
_PROJECT_TMP.mkdir(parents=True, exist_ok=True)


# ── Configuração de pipeline ───────────────────────────────────────────────────

@dataclass
class PipelineConfig:
    """Configuração completa de um pipeline de geração."""

    # Seleção de motores
    engine_ids: set[int] = field(default_factory=lambda: set())
    engine_preset: str = "default"  # light | medium | potent | nuclear | default

    # Limites globais
    max_candidates: int = 0   # 0 = ilimitado
    timeout_secs: float = 0.0  # 0 = sem timeout
    min_len: int = 6
    max_len: int = 32

    # Locale
    locale: str = "en"

    # Alvos conhecidos (para feedback loop pós-geração)
    known_targets: list[str] = field(default_factory=list)

    # Profundidade de combinações
    depth: int = 3

    # Opções de mangling
    leet_mode: str = "basic"
    with_spaces: bool = False

    # Opções de saída final
    output_path: str = ""
    output_format: str = "lst"  # lst | txt | tar | tar.gz | zip
    sanitize: bool = True
    dedupe: bool = True
    sort: str = "none"  # none | alpha | alpha-desc | length | length-desc

    # Mutações de keywords
    keyword_mutations_enabled: bool = False
    keyword_mutations_modes: list[str] = field(default_factory=list)

    @classmethod
    def from_profile(cls, profile: dict) -> "PipelineConfig":
        """Constrói PipelineConfig a partir de um dict de perfil."""
        cfg = cls()
        cfg.locale      = profile.get("locale", "en")
        cfg.depth       = profile.get("depth", 3)
        cfg.leet_mode   = profile.get("leet_mode", "basic")
        cfg.with_spaces = profile.get("with_spaces", False)
        cfg.min_len     = profile.get("min_len", 6)
        cfg.max_len     = profile.get("max_len", 32)
        cfg.known_targets = list(profile.get("known_targets") or [])
        if cfg.known_targets:
            cfg.max_len = max(cfg.max_len, max(len(t) for t in cfg.known_targets if t))
            cfg.min_len = min(cfg.min_len, min(len(t) for t in cfg.known_targets if t))

        # Engine selection
        engines_raw = profile.get("engines")
        if engines_raw:
            try:
                from embedxpl.engines.wordlists.generation_engines import parse_engine_selection, resolve_engines
                cfg.engine_ids = resolve_engines(str(engines_raw))
            except ImportError:
                pass
        preset_raw = profile.get("engine_presets")
        if preset_raw:
            cfg.engine_preset = preset_raw

        # Output
        out_block = profile.get("output") or profile.get("_export_options") or {}
        if isinstance(out_block, dict):
            cfg.output_format  = out_block.get("format", "lst")
            cfg.sanitize       = out_block.get("sanitize", True)
            cfg.dedupe         = out_block.get("dedupe", True)
            cfg.sort           = out_block.get("sort", "none")
        cfg.output_path = profile.get("output_path", "")

        # Keyword mutations
        km = profile.get("keyword_mutations") or {}
        if isinstance(km, dict):
            cfg.keyword_mutations_enabled = km.get("enabled", False)
            cfg.keyword_mutations_modes   = list(km.get("modes") or [])

        return cfg


# ── Deduplicação CRC32 streaming ──────────────────────────────────────────────

class CRC32Deduplicator:
    """Deduplicador leve usando CRC32 (menor footprint que set[str])."""

    def __init__(self) -> None:
        self._seen: set[int] = set()
        self.count_emitted = 0
        self.count_duped = 0

    def is_new(self, word: str) -> bool:
        crc = zlib.crc32(word.encode("utf-8", errors="replace")) & 0xFFFFFFFF
        if crc in self._seen:
            self.count_duped += 1
            return False
        self._seen.add(crc)
        self.count_emitted += 1
        return True

    def reset(self) -> None:
        self._seen.clear()
        self.count_emitted = 0
        self.count_duped = 0


# ── Orquestrador principal ─────────────────────────────────────────────────────

class ProfilePipeline:
