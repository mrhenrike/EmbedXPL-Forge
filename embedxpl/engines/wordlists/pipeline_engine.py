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
    """
    Orquestrador multi-estágio para geração de wordlist de perfil.

    Uso:
        pipeline = ProfilePipeline(profile, config)
        for word in pipeline.run():
            write(word)
        pipeline.run_feedback()   # benchmark vs known_targets
        pipeline.finalize()       # archive export
    """

    def __init__(self, profile: dict, config: Optional[PipelineConfig] = None) -> None:
        self.profile = profile
        self.config = config or PipelineConfig.from_profile(profile)
        self._dedup = CRC32Deduplicator()
        self._start_time: float = 0.0
        self._word_count: int = 0

    def _active_engines(self) -> set[int]:
        """Resolve o set final de motores ativos."""
        if self.config.engine_ids:
            return self.config.engine_ids
        try:
            from embedxpl.engines.wordlists.generation_engines import resolve_engines
            return resolve_engines(None)
        except ImportError:
            return set(range(1, 16))  # fallback: motores 1-15

    def _within_limits(self) -> bool:
        """Retorna False se limite de candidatos ou timeout atingido."""
        if self.config.max_candidates and self._word_count >= self.config.max_candidates:
            return False
        if self.config.timeout_secs and (time.time() - self._start_time) >= self.config.timeout_secs:
            return False
        return True

    def _emit(self, word: str) -> Optional[str]:
        """Filtra por len e dedup; retorna a palavra ou None."""
        word = word.strip()
        if not word:
            return None
        if len(word) < self.config.min_len or len(word) > self.config.max_len:
            return None
        if self._dedup.is_new(word):
            self._word_count += 1
            return word
        return None

    def _collect_profile_tokens(self, limit: int = 30) -> list[str]:
        """Collect deduplicated name/keyword tokens from the active profile."""
        raw: list[str] = []
        for key in (
            "full_name", "short_name", "surname", "partner_name",
            "company_name", "company_legal",
        ):
            val = self.profile.get(key)
            if isinstance(val, str) and val.strip():
                raw.extend(val.strip().split())
        for key in ("nicknames", "keywords"):
            val = self.profile.get(key)
            if isinstance(val, list):
                raw.extend(str(v) for v in val if v)
        seen: set[str] = set()
        out: list[str] = []
        for token in raw:
            token = token.strip()
            if not token:
                continue
            key = token.lower()
            if key in seen:
                continue
            seen.add(key)
            out.append(token)
            if len(out) >= limit:
                break
        return out

    def _pattern_variables(self) -> dict[str, list[str]]:
        """Build template variables for pattern_engine from profile fields."""
        empresa = (
            self.profile.get("company_name")
            or self.profile.get("company_legal")
            or self.profile.get("full_name", "")
        )
        year_end = self.profile.get("year_end", 2026)
        year_start = self.profile.get("year_start", year_end - 5)
        anos = [str(y) for y in range(int(year_start), int(year_end) + 1)]
        keywords = [str(k) for k in (self.profile.get("keywords") or []) if k]
        variables: dict[str, list[str]] = {
            "empresa": [empresa] if empresa else [],
            "empresa_lower": [empresa.lower()] if empresa else [],
            "empresa_upper": [empresa.upper()] if empresa else [],
            "ano": anos,
            "dominio": [self.profile.get("company_domain", "")] if self.profile.get("company_domain") else [],
            "portal": ["portal", "sistema", "erp"],
            "keyword": keywords or self._collect_profile_tokens(10),
        }
        return {k: v for k, v in variables.items() if v}

    def _run_stage_profiler(self) -> Generator[str, None, None]:
        """Estágio 1: geração core do profiler (motores 1-8, 12, 20, 24, 25)."""
        try:
            from embedxpl.engines.wordlists.profiler import generate_from_profile
        except ImportError:
            return
        engines = self._active_engines()
        # O profiler executa todos os sub-geradores internamente
        # Os motores ativos são passados via profile["_active_engines"]
        profile_with_engines = dict(self.profile)
        profile_with_engines["_active_engines"] = engines
        for word in generate_from_profile(profile_with_engines):
            if not self._within_limits():
                return
            result = self._emit(word)
            if result:
                yield result

    def _run_stage_keyword_mutations(self) -> Generator[str, None, None]:
        """Estágio 2: mutações de keywords (motor 28)."""
        if not self.config.keyword_mutations_enabled:
            return
        engines = self._active_engines()
        if 28 not in engines:
            return
        try:
            from embedxpl.engines.wordlists.keyword_mutations import mutate, MutationMode
        except ImportError:
            logger.debug("keyword_mutations não disponível")
            return

        modes = []
        for m in self.config.keyword_mutations_modes:
            try:
                modes.append(MutationMode(m))
            except ValueError:
                pass
        if not modes:
            modes = [MutationMode.LETTER_REVERSE, MutationMode.SYLLABLE_REVERSE]

        tokens = []
        for key in ("full_name", "short_name", "nicknames", "keywords"):
            val = self.profile.get(key)
            if isinstance(val, str):
                tokens.append(val)
            elif isinstance(val, list):
                tokens.extend(str(v) for v in val if v)

        for word in mutate(tokens, modes, include_original=False):
            if not self._within_limits():
                return
            result = self._emit(word)
            if result:
                yield result

    def _run_stage_rsmangler(self) -> Generator[str, None, None]:
        """Estágio 3a: RSMangler pós-processamento (motor 11)."""
        engines = self._active_engines()
        if 11 not in engines:
            return
        try:
            from embedxpl.engines.wordlists.rsmangler_engine import mangle, ManglerOptions
        except ImportError:
            logger.debug("rsmangler_engine não disponível")
            return

        name_tokens = []
        for key in ("full_name", "short_name", "nicknames"):
            val = self.profile.get(key)
            if isinstance(val, str):
                name_tokens.append(val)
            elif isinstance(val, list):
                name_tokens.extend(str(v) for v in val if v)

        if not name_tokens:
            return

        opts = ManglerOptions(
            perms=len(name_tokens) <= 5,
            force_perms=False,
            full_leet=True,
            years=True,
            min_length=self.config.min_len,
            max_length=self.config.max_len,
        )
        for word in mangle(name_tokens[:8], opts):
            if not self._within_limits():
                return
            result = self._emit(word)
            if result:
                yield result

    def _run_stage_prince(self) -> Generator[str, None, None]:
        """Estágio 3b: PRINCE chains (motor 10)."""
        engines = self._active_engines()
        if 10 not in engines:
            return
        try:
            from embedxpl.engines.wordlists.prince_engine import generate_prince_candidates
        except ImportError:
            logger.debug("prince_engine não disponível")
            return

        tokens = []
        for key in ("full_name", "short_name", "nicknames", "keywords"):
            val = self.profile.get(key)
            if isinstance(val, str):
                tokens.extend(val.split())
            elif isinstance(val, list):
                tokens.extend(str(v) for v in val if v)

        if not tokens:
            return

        try:
            for word in generate_prince_candidates(
                tokens[:20],
                min_len=self.config.min_len,
                max_len=self.config.max_len,
                limit=min(self.config.max_candidates or 500_000, 500_000),
            ):
                if not self._within_limits():
                    return
                result = self._emit(word)
                if result:
                    yield result
        except TypeError:
            pass

    def _run_stage_osint_perm(self) -> Generator[str, None, None]:
        """Estágio 4: OSINT permutações elpscrk-style (motor 17)."""
        engines = self._active_engines()
        if 17 not in engines:
            return
        try:
            from embedxpl.engines.wordlists.osint_perm import generate_osint_permutations
        except (ImportError, AttributeError):
            logger.debug("osint_perm não disponível como generate_osint_permutations")
            return

        try:
            for word in generate_osint_permutations(
                self.profile,
                min_len=self.config.min_len,
                max_len=self.config.max_len,
            ):
                if not self._within_limits():
                    return
                result = self._emit(word)
                if result:
                    yield result
        except Exception as exc:
            logger.debug("osint_perm error: %s", exc)

    def _run_stage_num2text(self) -> Generator[str, None, None]:
        """Estágio 5: Anos/números por extenso multilíngue (motor 20)."""
        engines = self._active_engines()
        if 20 not in engines:
            return
        try:
            from embedxpl.engines.wordlists.num2text import num2text_variants
        except ImportError:
            logger.debug("num2text não disponível")
            return

        locale = self.config.locale
        lang_map = {"en": "en", "pt-br": "br", "pt-pt": "pt", "es": "es"}
        lang = lang_map.get(locale, "en")

        years_to_expand: list[int] = []
        for key in ("birth_year", "hire_year"):
            yr = self.profile.get(key)
            if yr and isinstance(yr, int) and 1900 <= yr <= 2100:
                years_to_expand.append(yr)
        # Também incluir year_range do DateProfile se disponível
        if self.profile.get("birth_year_min") and self.profile.get("birth_year_max"):
            for yr in range(self.profile["birth_year_min"], self.profile["birth_year_max"] + 1):
                if yr not in years_to_expand:
                    years_to_expand.append(yr)

        for yr in years_to_expand[:3]:  # limitar a 3 anos para não explodir
            try:
                for word in num2text_variants(yr, lang=lang):
                    if not self._within_limits():
                        return
                    result = self._emit(word)
                    if result:
                        yield result
            except Exception as exc:
                logger.debug("num2text error for %d: %s", yr, exc)

    def _run_stage_password_dna(self) -> Generator[str, None, None]:
        """Estágio 6: Password DNA mutations (motor 14), só se old_passwords."""
        engines = self._active_engines()
        if 14 not in engines:
            return
        old_passwords = self.profile.get("old_passwords") or []
        if not old_passwords:
            return
        try:
            from embedxpl.engines.wordlists.password_dna import PasswordDNA
        except ImportError:
            logger.debug("password_dna não disponível")
            return

        try:
            dna = PasswordDNA(old_passwords)
            for word in dna.generate_mutations():
                if not self._within_limits():
                    return
                result = self._emit(word)
                if result:
                    yield result
        except Exception as exc:
            logger.debug("password_dna error: %s", exc)

    def _run_stage_pattern_engine(self) -> Generator[str, None, None]:
        """Estágio 7: Pattern templates estruturados (motor 21), se patterns configurados."""
        engines = self._active_engines()
        if 21 not in engines:
            return
        patterns_file = self.profile.get("patterns_file")
        patterns_list = self.profile.get("patterns") or []
        if not patterns_file and not patterns_list:
            return
        try:
            from embedxpl.engines.wordlists.pattern_engine import (
                generate_from_template_file,
                render_template,
            )
            variables = self._pattern_variables()
            if patterns_file:
                gen = generate_from_template_file(patterns_file, variables)
                for word in gen:
                    if not self._within_limits():
                        return
                    result = self._emit(word)
                    if result:
                        yield result
            for pat in patterns_list:
                for word in render_template(str(pat), variables):
                    if not self._within_limits():
                        return
                    result = self._emit(word)
                    if result:
                        yield result
        except Exception as exc:
            logger.debug("pattern_engine error: %s", exc)

    def _run_stage_builtin_mangle(self) -> Generator[str, None, None]:
        """Estágio: builtin mangling rules (motor 12)."""
        engines = self._active_engines()
        if 12 not in engines:
            return
        tokens = self._collect_profile_tokens(20)
        if not tokens:
            return
        try:
            from embedxpl.engines.wordlists.mangler import apply_rules
            rules = self.profile.get("mangle_rules") or [
                "capitalize", "append_num", "append_special", "leet_basic",
            ]
            for word in apply_rules(tokens, rules):
                if not self._within_limits():
                    return
                result = self._emit(word)
                if result:
                    yield result
        except Exception as exc:
            logger.debug("builtin_mangle error: %s", exc)

    def _run_stage_pymangler_masks(self) -> Generator[str, None, None]:
        """Estágio: PyMangler mask expansion (profile pymangler block or motor 12)."""
        engines = self._active_engines()
        pm = self.profile.get("pymangler") or {}
        enabled = pm.get("enabled", 12 in engines)
        if not enabled:
            return
        tokens = self._collect_profile_tokens(15)
        if not tokens:
            return
        try:
            from embedxpl.engines.wordlists.pattern_engine import generate_pymangler_masks
            masks = pm.get("masks")
            gen = generate_pymangler_masks(
                tokens,
                masks=masks,
                use_gpu=bool(pm.get("use_gpu", False)),
                target_time_hrs=float(pm.get("target_time_hrs", 0.0)),
                pps=int(pm.get("pps", 0)),
                use_capswap=bool(pm.get("use_capswap", False)),
                min_len=self.config.min_len,
                max_len=self.config.max_len,
            )
            for word in gen:
                if not self._within_limits():
                    return
                result = self._emit(word)
                if result:
                    yield result
        except Exception as exc:
            logger.debug("pymangler_masks error: %s", exc)

    def _run_stage_cupp(self) -> Generator[str, None, None]:
        """Estágio: CUPP engine concat combos (motor 8)."""
        engines = self._active_engines()
        if 8 not in engines:
            return
        try:
            from embedxpl.engines.wordlists.cupp_engine import CuppEngine, CuppProfile
        except ImportError:
            logger.debug("cupp_engine não disponível")
            return

        full = (self.profile.get("full_name") or "").strip()
        parts = full.split(None, 1) if full else []
        first = parts[0] if parts else (self.profile.get("short_name") or "")
        last = parts[1] if len(parts) > 1 else (self.profile.get("surname") or "")

        birth = ""
        bd = self.profile.get("birth") or {}
        if isinstance(bd, dict) and bd.get("mode") == "full":
            d, m, y = bd.get("day", 0), bd.get("month", 0), bd.get("year", 0)
            if d and m and y:
                birth = f"{int(d):02d}{int(m):02d}{int(y)}"
        elif self.profile.get("birth_day"):
            birth = (
                f"{int(self.profile.get('birth_day', 0)):02d}"
                f"{int(self.profile.get('birth_month', 0)):02d}"
                f"{int(self.profile.get('birth_year', 0))}"
            )

        pet_name = ""
        pets = self.profile.get("pets") or []
        if pets:
            p0 = pets[0]
            if isinstance(p0, dict):
                pet_name = str(p0.get("name", ""))
            else:
                pet_name = str(p0)

        cp = CuppProfile(
            first_name=first,
            last_name=last,
            nickname=(self.profile.get("nicknames") or [""])[0] if self.profile.get("nicknames") else "",
            partner_first=(self.profile.get("partner_name") or "").split()[0] if self.profile.get("partner_name") else "",
            pet_name=pet_name,
            company=self.profile.get("company_name", "") or "",
            birth_date=birth,
            extra_words=[str(k) for k in (self.profile.get("keywords") or [])],
        )
        engine = CuppEngine()
        max_out = int(self.profile.get("cupp_max_output", 5000))
        for word in engine.generate(cp, max_output=max_out, leet=True):
            if not self._within_limits():
                return
            result = self._emit(word)
            if result:
                yield result

    def _run_stage_positional_leet(self) -> Generator[str, None, None]:
        """Estágio: combinatorial leet perm post-pass (motor 23)."""
        engines = self._active_engines()
        if 23 not in engines:
            return
        tokens = self._collect_profile_tokens(12)
        if not tokens:
            return
        try:
            from embedxpl.engines.wordlists.leet_permuter import leet_perm_wordlist
            max_per = int(self.profile.get("leet_perm_max", 128))
            for word in leet_perm_wordlist(tokens, max_per_word=max_per):
                if not self._within_limits():
                    return
                result = self._emit(word)
                if result:
                    yield result
        except Exception as exc:
            logger.debug("positional_leet error: %s", exc)

    def _run_stage_pcfg(self) -> Generator[str, None, None]:
        """Estágio: PCFG hybrid generation (motor 18)."""
        engines = self._active_engines()
        if 18 not in engines:
            return
        try:
            from embedxpl.engines.wordlists.pcfg_engine import PCFGGrammar
        except ImportError:
            logger.debug("pcfg_engine não disponível")
            return

        grammar = PCFGGrammar()
        trained = 0
        use_detection = bool(self.profile.get("pcfg_use_detection", True))
        for pw in self.profile.get("old_passwords") or []:
            if pw:
                grammar.train(str(pw), use_detection=use_detection)
                trained += 1
        for tok in self._collect_profile_tokens(20):
            if len(tok) >= 4:
                grammar.train(tok, use_detection=use_detection)
                trained += 1

        corpus = self.profile.get("pcfg_corpus")
        if corpus and Path(str(corpus)).is_file():
            grammar.train_from_file(str(corpus), max_lines=5000)

        if trained == 0 and grammar.total_trained == 0:
            return

        max_cand = int(self.profile.get("pcfg_max_candidates", 3000))
        try:
            for word in grammar.generate(
                max_candidates=max_cand,
                min_length=self.config.min_len,
                max_length=self.config.max_len,
                top_structures=20,
                top_terminals=10,
            ):
                if not self._within_limits():
                    return
                result = self._emit(word)
                if result:
                    yield result
        except Exception as exc:
            logger.debug("pcfg error: %s", exc)

    def _run_stage_rulegen(self) -> Generator[str, None, None]:
        """Estágio 8: Rule generation de senhas conhecidas (motor 22)."""
        engines = self._active_engines()
        if 22 not in engines:
            return
        old_passwords = self.profile.get("old_passwords") or []
        if not old_passwords:
            return
        try:
            from embedxpl.engines.wordlists.rulegen_engine import generate_rule_variants
        except (ImportError, AttributeError):
            logger.debug("rulegen_engine.generate_rule_variants não disponível")
            return

        tokens = []
        for key in ("full_name", "short_name", "nicknames"):
            val = self.profile.get(key)
            if isinstance(val, str):
                tokens.append(val)
            elif isinstance(val, list):
                tokens.extend(str(v) for v in val if v)

        try:
            for word in generate_rule_variants(old_passwords, base_tokens=tokens):
                if not self._within_limits():
                    return
                result = self._emit(word)
                if result:
                    yield result
        except Exception as exc:
            logger.debug("rulegen error: %s", exc)

    def _run_stage_markov(self) -> Generator[str, None, None]:
        """Estágio: OMEN Markov generation (motor 19)."""
        engines = self._active_engines()
        if 19 not in engines:
            return
        try:
            from embedxpl.engines.wordlists.markov_engine import MarkovModel
        except ImportError:
            logger.debug("markov_engine não disponível")
            return

        mk = self.profile.get("markov") or {}
        order = int(mk.get("order", 3))
        model = MarkovModel(order=order)

        model_path = mk.get("model")
        if model_path and Path(str(model_path)).is_file():
            model.load(str(model_path))
        else:
            for pw in self.profile.get("old_passwords") or []:
                if pw:
                    model.train(str(pw))
            for corpus_key in ("markov_corpus", "pcfg_corpus"):
                corpus = self.profile.get(corpus_key)
                if corpus and Path(str(corpus)).is_file():
                    model.train_from_file(
                        str(corpus),
                        max_lines=int(mk.get("train_max_lines", 5000)),
                    )

        if model.total_trained == 0:
            logger.debug("markov: sem corpus de treino; pulando estágio")
            return

        max_cand = int(mk.get("max_candidates", 2000))
        max_cost = int(mk.get("max_cost", 0))
        try:
            for word in model.generate(
                max_candidates=max_cand,
                min_length=self.config.min_len,
                max_length=self.config.max_len,
                max_cost=max_cost,
            ):
                if not self._within_limits():
                    return
                result = self._emit(word)
                if result:
                    yield result
        except Exception as exc:
            logger.debug("markov error: %s", exc)

    def _run_stage_osint_scrape(self) -> Generator[str, None, None]:
        """Estágio: OSINT web scrape tokens (motor 13)."""
        engines = self._active_engines()
        if 13 not in engines:
            return

        scrape_cfg = self.profile.get("scrape") or {}
        urls: list[str] = []
        primary = self.profile.get("target_url")
        if primary:
            urls.append(str(primary))
        for u in scrape_cfg.get("urls") or []:
            if u:
                urls.append(str(u))
        if not urls:
            return

        depth = int(scrape_cfg.get("depth", 1))
        max_words = int(scrape_cfg.get("max_words", 400))
        min_len = max(self.config.min_len, int(scrape_cfg.get("min_len", self.config.min_len)))
        emitted = 0

        for url in urls[:5]:
            if not self._within_limits() or emitted >= max_words:
                break
            try:
                from embedxpl.engines.wordlists.web_scraper import WebScraper
                if scrape_cfg.get("use_web_scraper", True):
                    scraper = WebScraper(
                        start_url=url,
                        depth=depth,
                        min_word_len=min_len,
                        max_word_len=self.config.max_len,
                        include_js=bool(scrape_cfg.get("include_js", False)),
                        include_css=bool(scrape_cfg.get("include_css", False)),
                        include_pdf=bool(scrape_cfg.get("include_pdf", False)),
                        delay=float(scrape_cfg.get("delay", 0.5)),
                    )
                    for word in scraper.crawl():
                        if emitted >= max_words or not self._within_limits():
                            break
                        result = self._emit(word)
                        if result:
                            yield result
                            emitted += 1
                    continue
            except Exception as exc:
                logger.debug("web_scraper error for %s: %s", url, exc)

            try:
                from embedxpl.engines.wordlists.target_spider import spider_words
                for word in spider_words(
                    url,
                    min_len=min_len,
                    max_words=max(0, max_words - emitted),
                    depth=depth,
                ):
                    if not self._within_limits():
                        return
                    result = self._emit(word)
                    if result:
                        yield result
                        emitted += 1
            except Exception as exc:
                logger.debug("target_spider error for %s: %s", url, exc)

    def _run_stage_scrape_merge(self) -> Generator[str, None, None]:
        """Estágio: merge de wordlists scrapeadas (motor 26)."""
        engines = self._active_engines()
        if 26 not in engines:
            return

        merge_cfg = self.profile.get("scrape_merge") or {}
        sources: list[str] = []
        for key in ("scrape_merge_files",):
            for item in self.profile.get(key) or []:
                sources.append(str(item))
        for item in merge_cfg.get("files") or []:
            sources.append(str(item))
        cewl_file = self.profile.get("cewl_wordlist")
        if cewl_file:
            sources.append(str(cewl_file))

        if not sources:
            return

        seen_src: set[str] = set()
        for src in sources:
            path = Path(src)
            if not path.is_file():
                continue
            try:
                with path.open("r", encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        if not self._within_limits():
                            return
                        word = line.strip()
                        if not word:
                            continue
                        key = word.lower()
                        if key in seen_src:
                            continue
                        seen_src.add(key)
                        result = self._emit(word)
                        if result:
                            yield result
            except OSError as exc:
                logger.debug("scrape_merge read error %s: %s", path, exc)

    def _run_stage_cewl_mut(self) -> Generator[str, None, None]:
        """Estágio 9: cewl_mut preset (scrape -> rsmangler -> john rules).

        Requires profile to have a 'target_url' or 'cewl_wordlist' key.
        If 'target_url' is set, attempts to scrape words via web_scraper.
        If 'cewl_wordlist' is a file path, reads words from it directly.
        Then applies RSMangler to the collected words.

        This preset is activated when engine_preset == 'cewl_mut' or
        engine_id 29 is in the active set.
        """
        preset = getattr(self.config, "engine_preset", "")
        engines = self._active_engines()
        if preset != "cewl_mut" and 29 not in engines:
            return

        scraped_words: list[str] = []

        # Source 1: pre-scraped wordlist file
        cewl_file = self.profile.get("cewl_wordlist")
        if cewl_file:
            from pathlib import Path as _Path
            cewl_path = _Path(str(cewl_file))
            if cewl_path.is_file():
                try:
                    with cewl_path.open("r", encoding="utf-8", errors="replace") as fh:
                        for line in fh:
                            word = line.strip()
                            if word and len(word) >= self.config.min_len:
                                scraped_words.append(word)
                except OSError as exc:
                    logger.debug("cewl_wordlist read error: %s", exc)

        # Source 2: live scrape via target_spider
        target_url = self.profile.get("target_url")
        if target_url and not scraped_words:
            try:
                from embedxpl.engines.wordlists.target_spider import spider_words
                for word in spider_words(target_url, min_len=self.config.min_len, max_words=500):
                    scraped_words.append(word)
            except (ImportError, Exception) as exc:
                logger.debug("target_spider error: %s", exc)

        if not scraped_words:
            logger.debug("cewl_mut: no source words found; skipping stage")
            return

        # Deduplicate source words
        seen_src: set[str] = set()
        unique_words = []
        for w in scraped_words:
            key = w.lower()
            if key not in seen_src:
                seen_src.add(key)
                unique_words.append(w)

        # Apply RSMangler pass
        try:
            from embedxpl.engines.wordlists.rsmangler_engine import mangle, ManglerOptions
            opts = ManglerOptions(
                perms=len(unique_words) <= 10,
                force_perms=False,
                full_leet=False,
                years=True,
                min_length=self.config.min_len,
                max_length=self.config.max_len,
            )
            mangled_source = list(mangle(unique_words[:50], opts))
        except ImportError:
            mangled_source = unique_words

        # Apply builtin mangler rules (john-style)
        try:
            from embedxpl.engines.wordlists.mangler import apply_rules
            john_rules = ["capitalize", "append_num", "append_special", "leet_basic"]
            all_words = list(apply_rules(mangled_source, john_rules))
        except ImportError:
            all_words = mangled_source

        for word in all_words:
            if not self._within_limits():
                return
            result = self._emit(word)
            if result:
                yield result

    def run(self) -> Generator[str, None, None]:
        """
        Executa todos os estágios em ordem, retornando um gerador de candidatos.

        Yields:
            Strings únicas que passam pelos filtros de comprimento e deduplicação.
        """
        self._start_time = time.time()
        self._word_count = 0
        self._dedup.reset()

        stages = [
            ("profiler",          self._run_stage_profiler),
            ("cupp",              self._run_stage_cupp),
            ("num2text_dates",    self._run_stage_num2text),
            ("keyword_mutations", self._run_stage_keyword_mutations),
            ("rsmangler",         self._run_stage_rsmangler),
            ("builtin_mangle",    self._run_stage_builtin_mangle),
            ("pymangler_masks",   self._run_stage_pymangler_masks),
            ("prince",            self._run_stage_prince),
            ("osint_perm",        self._run_stage_osint_perm),
            ("password_dna",      self._run_stage_password_dna),
            ("pattern_engine",    self._run_stage_pattern_engine),
            ("positional_leet",   self._run_stage_positional_leet),
            ("pcfg",              self._run_stage_pcfg),
            ("rulegen",           self._run_stage_rulegen),
            ("markov",            self._run_stage_markov),
            ("osint_scrape",      self._run_stage_osint_scrape),
            ("scrape_merge",      self._run_stage_scrape_merge),
            ("cewl_mut",          self._run_stage_cewl_mut),
        ]

        for stage_name, stage_fn in stages:
            if not self._within_limits():
                logger.info("Pipeline: limite atingido antes do estágio '%s'", stage_name)
                break
            stage_count = 0
            for word in stage_fn():
                if not self._within_limits():
                    break
                stage_count += 1
                yield word
            logger.debug("Pipeline estágio '%s': %d candidatos", stage_name, stage_count)

        elapsed = time.time() - self._start_time
        logger.info(
            "Pipeline concluído: %d candidatos únicos em %.1fs (dupes ignorados: %d)",
            self._word_count,
            elapsed,
            self._dedup.count_duped,
        )

    def run_to_file(self, output_path: Optional[str] = None) -> dict:
        """
        Executa o pipeline e escreve saída em arquivo.

        Args:
            output_path: Caminho de saída (usa config.output_path se None).

        Returns:
            Dict com stats: lines_written, elapsed_secs, feedback (se known_targets).
        """
        out = output_path or self.config.output_path
        if not out:
            out = str(_PROJECT_TMP / f"wfh_profile_{int(time.time())}.lst")

        out_path = Path(out)
        out_path.parent.mkdir(parents=True, exist_ok=True)

        lines_written = 0
        with out_path.open("w", encoding="utf-8") as fh:
            for word in self.run():
                fh.write(word + "\n")
                lines_written += 1

        elapsed = time.time() - self._start_time
        result: dict = {
            "output_path": str(out_path),
            "lines_written": lines_written,
            "elapsed_secs": round(elapsed, 2),
        }

        # Post-rank passes (motors 15 / 16)
        rank_info = self._apply_post_rank(str(out_path))
        if rank_info:
            result["post_rank"] = rank_info

        # Archive export (sanitize/sort) - before feedback so report matches final file
        if self.config.output_format not in ("lst", "txt") or self.config.sanitize:
            try:
                archive_result = self._run_archive_export(str(out_path))
                result["archive"] = archive_result
            except Exception as exc:
                logger.warning("archive_export falhou: %s", exc)

        # Feedback loop: benchmark vs known_targets (after final export)
        if self.config.known_targets:
            result["feedback"] = self.run_feedback(str(out_path))

        return result

    def run_feedback(self, wordlist_path: Optional[str] = None) -> dict:
        """
        Executa feedback loop: benchmark vs known_targets.

        Se houver misses, sugere motores adicionais que aumentariam cobertura.

        Args:
            wordlist_path: Caminho da wordlist gerada (usa output_path se None).

        Returns:
            Dict com resultado do benchmark e sugestões de motores.
        """
        if not self.config.known_targets:
            return {}

        from embedxpl.engines.wordlists.benchmark_suite import (
            benchmark_known_targets,
            format_known_targets_report,
        )

        wl = wordlist_path or self.config.output_path
        if not wl or not Path(wl).exists():
            return {"error": "wordlist não encontrada para feedback"}

        fb = benchmark_known_targets(wl, self.config.known_targets)

        if fb.get("misses", 0) > 0:
            missing = fb.get("missing_targets", [])
            suggestions = _suggest_engines_for_misses(missing, self.config)
            fb["suggestions"] = suggestions

        print(format_known_targets_report(fb))
        return fb

    def _apply_post_rank(self, output_path: str) -> dict:
        """Reordena wordlist final quando motores 15 ou 16 estão ativos."""
        engines = self._active_engines()
        info: dict = {}

        if 16 in engines:
            try:
                from embedxpl.engines.wordlists.maya_ranker import rank_wordlist
                ranked_tmp = str(Path(output_path).with_suffix(".maya_rank.tmp"))
                hints = {
                    k: self.profile.get(k)
                    for k in (
                        "full_name", "short_name", "surname",
                        "nicknames", "keywords", "company_name",
                    )
                }
                mk = self.profile.get("maya_rank") or {}
                rr = rank_wordlist(
                    output_path,
                    ranked_tmp,
                    use_gpu=bool(mk.get("use_gpu", False)),
                    top_n=int(mk.get("top_n", 0)),
                    backend=str(mk.get("backend", "auto")),
                    profile_hints=hints,
                    min_score=float(mk.get("min_score", 0.0)),
                )
                Path(ranked_tmp).replace(Path(output_path))
                info["maya_rank"] = {
                    "total_scored": rr.total_scored,
                    "top_score": rr.top_score,
                    "backend": rr.backend_used,
                }
            except Exception as exc:
                logger.warning("maya_rank post-pass falhou: %s", exc)
                info["maya_rank_error"] = str(exc)
            return info

        if 15 in engines:
            try:
                info["pattern_rank"] = self._post_rank_by_pattern(output_path)
            except Exception as exc:
                logger.warning("pattern_rank post-pass falhou: %s", exc)
                info["pattern_rank_error"] = str(exc)

        return info

    def _post_rank_by_pattern(self, output_path: str) -> dict:
        """Ordena wordlist por score de keyboard-walk (motor 15)."""
        from embedxpl.engines.wordlists.pattern_ranker import score_keyboard_walk

        layout = str((self.profile.get("pattern_rank") or {}).get("layout", "qwerty"))
        lines: list[str] = []
        with Path(output_path).open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                word = line.rstrip("\n\r")
                if word:
                    lines.append(word)

        if not lines:
            return {"lines": 0}

        ranked = sorted(
            lines,
            key=lambda w: (score_keyboard_walk(w, layout), len(w)),
        )
        with Path(output_path).open("w", encoding="utf-8") as fh:
            for word in ranked:
                fh.write(word + "\n")

        return {
            "lines": len(ranked),
            "layout": layout,
            "top_walk_score": round(score_keyboard_walk(ranked[0], layout), 4),
        }

    def _run_archive_export(self, wordlist_path: str) -> dict:
        """Pós-processa wordlist com sanitize/sort/export."""
        try:
            from embedxpl.engines.wordlists.archive_export import ExportOptions, ExportFormat, export_wordlist
        except ImportError:
            logger.debug("archive_export não disponível")
            return {}

        fmt_map = {
            "lst": ExportFormat.LST, "txt": ExportFormat.TXT,
            "tar": ExportFormat.TAR, "tar.gz": ExportFormat.TAR_GZ,
            "zip": ExportFormat.ZIP,
        }
        sort_map = {
            "none": "none", "alpha": "alpha", "alpha-desc": "alpha-desc",
            "length": "length", "length-desc": "length-desc",
        }

        opts = ExportOptions(
            format=fmt_map.get(self.config.output_format, ExportFormat.LST),
            sanitize=self.config.sanitize,
            dedupe=self.config.dedupe,
            sort=sort_map.get(self.config.sort, "none"),
            min_len=self.config.min_len if self.config.min_len > 0 else None,
            max_len=self.config.max_len if self.config.max_len < 65535 else None,
        )

        out = self.config.output_path or wordlist_path
        return export_wordlist(wordlist_path, out, opts)


# ── Sugestões de motores para misses ─────────────────────────────────────────

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
