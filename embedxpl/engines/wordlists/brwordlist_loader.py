"""brwordlist_loader.py - BRWordList integration for WordlistXPL-Forge.

Loads Brazilian name lists and PT-BR web discovery paths from the
BRWordList submodule located at ../Wordlists/BRWordList relative to
the WordlistXPL-Forge superproject root.

All file access is read-only. No raw entries are persisted by this
module - callers are responsible for downstream storage.

Author: Andre Henrique (@mrhenrike) | Uniao Geek
Version: 1.0.0
"""
from __future__ import annotations

import logging
import unicodedata
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Candidate locations for BRWordList (checked in order)
# ---------------------------------------------------------------------------

_KNOWN_BRWORDLIST_RELATIVES: List[Path] = [
    # Superproject layout: submodules/Wordlists/BRWordList
    # WFH is at submodules/Uniao-Geek/WordlistXPL-Forge
    # So we go up 3 levels to reach submodules/, then into Wordlists/BRWordList
    Path(__file__).resolve().parents[2].parent / "Wordlists" / "BRWordList",
    # Alternate: repo checked out side-by-side
    Path(__file__).resolve().parents[3] / "Wordlists" / "BRWordList",
    # Alternate: same parent directory
    Path(__file__).resolve().parents[2].parent / "BRWordList",
    Path(__file__).resolve().parents[2] / "BRWordList",
]

# ---------------------------------------------------------------------------
# Name file map: category -> relative path inside BRWordList
# ---------------------------------------------------------------------------

_CATEGORY_FILES: dict[str, str] = {
    "names":          "Nomes/nomes.txt",
    "surnames":       "Nomes/sobrenomes.txt",
    "full_names":     "Nomes/nome.sobrenomes.txt",
    "initials":       "Nomes/nome_primeiraletra.txt",
    "rev_initials":   "Nomes/primeiraletra_sobrenome.txt",
    "a-z":            "Nomes/a-z.txt",
}

# Built-in PT-BR web paths supplemented by BRWordList discovery files
_BUILTIN_PTBR_PATHS: List[str] = [
    # Common PT-BR portal/app paths
    "acesso",
    "acesso-restrito",
    "administracao",
    "administrador",
    "admin",
    "agencias",
    "api",
    "aplicativo",
    "area-restrita",
    "autenticacao",
    "backoffice",
    "banco",
    "cadastro",
    "central",
    "cliente",
    "clientes",
    "config",
    "configuracao",
    "configuracoes",
    "consulta",
    "contato",
    "conteudo",
    "controle",
    "corporativo",
    "cpanel",
    "dashboard",
    "dados",
    "documentos",
    "empresas",
    "extranet",
    "financeiro",
    "gerencia",
    "gerencial",
    "gestao",
    "homologacao",
    "hml",
    "identidade",
    "intranet",
    "login",
    "logout",
    "monitoramento",
    "minha-conta",
    "minhaconta",
    "meu-perfil",
    "painel",
    "parceiros",
    "portal",
    "producao",
    "prd",
    "qa",
    "relatorios",
    "reset",
    "seguranca",
    "servicos",
    "sistema",
    "suporte",
    "teste",
    "tst",
    "usuario",
    "usuarios",
    "vendas",
    "webmail",
    "wp-admin",
    "wp-login.php",
    # API versioning PT-BR style
    "api/v1",
    "api/v2",
    "api/v3",
    "api/auth",
    "api/login",
    "api/usuarios",
    "api/clientes",
    "api/dados",
]


class BRWordListLoader:
    """Loader for BRWordList name and discovery corpora.

    Locates the BRWordList submodule automatically and exposes clean
    iterators over its name lists and web discovery paths.
    """

    def __init__(self, base_path: Optional[Path] = None) -> None:
        """Initialise the loader.

        Args:
            base_path: Explicit BRWordList root. Auto-detected if None.
        """
        self._base: Optional[Path] = base_path or self.auto_detect_path()
        if self._base:
            logger.debug("BRWordListLoader using: %s", self._base)
        else:
            logger.warning(
                "BRWordList not found. Run: "
                "git submodule update --init submodules/Wordlists/BRWordList"
            )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @staticmethod
    def auto_detect_path() -> Optional[Path]:
        """Find BRWordList root directory.

        Checks known relative paths relative to this file. A valid root
        must contain a 'Nomes' subdirectory.

        Returns:
            Resolved Path to BRWordList root, or None if not found.
        """
        for candidate in _KNOWN_BRWORDLIST_RELATIVES:
            resolved = candidate.resolve()
            if resolved.is_dir() and (resolved / "Nomes").is_dir():
                logger.info("BRWordList auto-discovered at: %s", resolved)
                return resolved
        return None

    def load_names(self, category: str = "all") -> List[str]:
        """Load Brazilian names from BRWordList.

        Args:
            category: One of 'names', 'surnames', 'full_names', 'initials',
                      'rev_initials', 'a-z', or 'all' to load every category.

        Returns:
            Deduplicated list of name strings (lowercase, accent-stripped).
        """
        if not self._base:
            logger.error("BRWordList unavailable - cannot load names")
            return []

        targets: List[str]
        if category == "all":
            targets = list(_CATEGORY_FILES.values())
        else:
            rel = _CATEGORY_FILES.get(category)
            if not rel:
                logger.warning(
                    "Unknown BRWordList category: %s. Valid: %s",
                    category,
                    ", ".join(sorted(_CATEGORY_FILES)),
                )
                return []
            targets = [rel]

        seen: set[str] = set()
        result: List[str] = []
        for rel_path in targets:
            fpath = self._base / rel_path
            if not fpath.exists():
                logger.debug("BRWordList file missing: %s", fpath)
                continue
            try:
                with open(fpath, encoding="utf-8", errors="replace") as fh:
                    for raw in fh:
                        entry = raw.strip().lower()
                        if not entry or entry.startswith("#"):
                            continue
                        normalized = _strip_accents(entry)
                        if normalized and normalized not in seen:
                            seen.add(normalized)
                            result.append(normalized)
            except OSError as exc:
                logger.warning("Error reading %s: %s", fpath, exc)

        logger.debug("BRWordList loaded %d unique names (category=%s)", len(result), category)
        return result

    def load_web_paths(self) -> List[str]:
        """Load common PT-BR web discovery paths.

        Merges built-in PT-BR path list with entries from
        BRWordList/Descoberta/Web/comuns.txt when available.

        Returns:
            Deduplicated list of URL path segments.
        """
        seen: set[str] = set(_BUILTIN_PTBR_PATHS)
        result: List[str] = list(_BUILTIN_PTBR_PATHS)

        if self._base:
            candidates = [
                self._base / "Descoberta" / "Web" / "comuns.txt",
                self._base / "Descoberta" / "Web" / "API" / "openbanking.txt",
                self._base / "Vulnerabilidades" / "DirectoryTransversal.txt",
            ]
            for fpath in candidates:
                if not fpath.exists():
                    continue
                try:
                    with open(fpath, encoding="utf-8", errors="replace") as fh:
                        for raw in fh:
                            entry = raw.strip().lstrip("/")
                            if not entry or entry.startswith("#"):
                                continue
                            if entry not in seen:
                                seen.add(entry)
                                result.append(entry)
                except OSError as exc:
                    logger.warning("Error reading %s: %s", fpath, exc)

        logger.debug("BRWordList loaded %d web paths", len(result))
        return result

    def is_available(self) -> bool:
        """Return True if the BRWordList submodule is accessible."""
        return self._base is not None and self._base.is_dir()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _strip_accents(text: str) -> str:
    """Remove diacritics from a Unicode string."""
    nfd = unicodedata.normalize("NFD", text)
    return "".join(ch for ch in nfd if unicodedata.category(ch) != "Mn")


def generate_usernames_from_br_names(
    category: str = "names",
    base_path: Optional[Path] = None,
    include_leet: bool = False,
) -> List[str]:
    """Generate a username list from BRWordList name files.

    Convenience wrapper used by update_wordlists.py phase2 integration
    and the CLI br-names subcommand.

    Args:
        category: BRWordList name category (default: 'names').
        base_path: Explicit BRWordList root (auto-detect if None).
        include_leet: Also produce basic leet substitutions.

    Returns:
        Sorted, deduplicated username list.
    """
    loader = BRWordListLoader(base_path)
    names = loader.load_names(category)
    if not names:
        return []

    seen: set[str] = set()
    result: List[str] = []

    for name in names:
        _add_unique(name, seen, result)
        if include_leet:
            for variant in _basic_leet(name):
                _add_unique(variant, seen, result)

    return sorted(result)


def _add_unique(entry: str, seen: set[str], result: List[str]) -> None:
    """Append entry to result only if not already seen."""
    if entry and entry not in seen:
        seen.add(entry)
        result.append(entry)


_LEET_MAP: dict[str, str] = {
    "a": "4",
    "e": "3",
    "i": "1",
    "o": "0",
    "s": "5",
    "t": "7",
}


def _basic_leet(word: str) -> List[str]:
    """Apply basic single-character leet substitution to a word.

    Args:
        word: Input lowercase string.

    Returns:
        List of leet variants (excludes the original).
    """
    variants: List[str] = []
    for original, replacement in _LEET_MAP.items():
        if original in word:
            variants.append(word.replace(original, replacement))
    return variants
