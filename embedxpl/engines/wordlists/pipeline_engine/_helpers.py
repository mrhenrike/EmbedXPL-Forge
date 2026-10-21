"""Module-level pipeline helpers."""

from __future__ import annotations

import logging
from typing import Optional

from embedxpl.engines.wordlists.pipeline_engine._config import PipelineConfig
from embedxpl.engines.wordlists.pipeline_engine._pipeline import ProfilePipeline

logger = logging.getLogger(__name__)


def _suggest_engines_for_misses(
    missing_targets: list[str],
    config: PipelineConfig,
) -> list[str]:
    """
    Analisa senhas não encontradas e sugere motores que aumentariam cobertura.

    Heurísticas baseadas em padrões dos alvos:
    - Leet agressivo → motor 1 (token_variants com leet=aggressive)
    - Separadores estruturados (_#@) → motor 11 (rsmangler), 21 (pattern_templates)
    - Anos 1990-atual → motor 2 (date_tokens), 11 (years)
    - Inversão de palavras → motor 9 (reversed_tokens), 28 (keyword_mutations)
    - Combinações PRINCE → motor 10
    """
    suggestions = []
    engines = config.engine_ids

    for pw in missing_targets:
        has_leet = any(c in pw for c in ("4", "@", "0", "1", "$", "3", "7"))
        has_year = any(str(y) in pw for y in range(1990, 2030))
        has_sep = any(c in pw for c in ("_", "#", "@", "!", "."))
        has_multi_token = len([c for c in pw if c.isupper()]) > 2

        if has_leet and 1 in engines:
            suggestions.append("Use leet_mode=aggressive (motor 1) para cobrir substituicoes numericas")
        if has_year and 11 not in engines:
            suggestions.append("Habilitar motor 11 (rsmangler com --years) para sufixos/prefixos de anos")
        if has_sep and 21 not in engines:
            suggestions.append("Habilitar motor 21 (pattern_templates) para padrões com separadores _#@")
        if has_multi_token and 10 not in engines:
            suggestions.append("Habilitar motor 10 (PRINCE) para combinacoes multi-token (marca + pet + ano)")
        if 28 not in engines:
            suggestions.append("Habilitar motor 28 (keyword_mutations) para reversões de sílabas")

    return list(dict.fromkeys(suggestions))  # dedup preservando ordem


# ── Função de conveniência ────────────────────────────────────────────────────

def run_profile_pipeline(
    profile: dict,
    config: Optional[PipelineConfig] = None,
    output_path: Optional[str] = None,
) -> dict:
    """
    Executa o pipeline completo para um perfil e retorna estatísticas.

    Args:
        profile: Dict de perfil (de load_profile_yaml ou interactive_profile).
        config: Configuração opcional; derivada do profile se None.
        output_path: Caminho de saída; usa profile['output_path'] se None.

    Returns:
        Dict com stats: lines_written, elapsed_secs, feedback (se known_targets).
    """
    if config is None:
        config = PipelineConfig.from_profile(profile)
    if output_path:
        config.output_path = output_path

    pipeline = ProfilePipeline(profile, config)
    return pipeline.run_to_file()
