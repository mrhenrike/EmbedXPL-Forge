"""EmbedXPL Suite — Banner Engine.

Exibe o banner figlet da ferramenta com estatísticas em tempo real.
Banners pré-gerados estão em embedxpl/resources/banners/*.txt.
Stats contadas via pkgutil.walk_packages() com cache em ~/.embedxpl/stats_cache.json.

Uso::
    from embedxpl.core.banner import show_banner
    show_banner("embedxpl")          # EmbedXPL principal
    show_banner("industrialxpl")     # IndustrialXPL
"""

from __future__ import annotations

import json
import os
import pkgutil
import sys
import time
from pathlib import Path
from typing import Dict, Optional

# ---------------------------------------------------------------------------
# Caminhos
# ---------------------------------------------------------------------------

_HERE = Path(__file__).resolve().parent          # embedxpl/core/
_ROOT = _HERE.parent                             # embedxpl/
_BANNERS_DIR = _ROOT / "resources" / "banners"
_CACHE_DIR = Path.home() / ".embedxpl"
_CACHE_FILE = _CACHE_DIR / "stats_cache.json"
_CACHE_TTL = 300   # segundos — recontar se cache tiver mais de 5 min

# ---------------------------------------------------------------------------
# Mapeamento tool_name → arquivo de banner
# ---------------------------------------------------------------------------

TOOL_BANNERS: Dict[str, Path] = {
    "embedxpl":     _BANNERS_DIR / "embedxpl.txt",
    "industrialxpl": _BANNERS_DIR / "industrialxpl.txt",
    "firewallxpl":  _BANNERS_DIR / "firewallxpl.txt",
    "printerxpl":   _BANNERS_DIR / "printerxpl.txt",
    "wirelessxpl":  _BANNERS_DIR / "wirelessxpl.txt",
    "wordlistxpl":  _BANNERS_DIR / "wordlistxpl.txt",
    "tupaxpl":      _BANNERS_DIR / "tupaxpl.txt",
    "tupa":         _BANNERS_DIR / "tupaxpl.txt",
}

# Cor ANSI
_CYAN   = "\033[96m"
_GREEN  = "\033[92m"
_YELLOW = "\033[93m"
_RED    = "\033[91m"
_BOLD   = "\033[1m"
_RESET  = "\033[0m"
_DIM    = "\033[2m"

# ---------------------------------------------------------------------------
# Contagem de módulos
# ---------------------------------------------------------------------------

def _count_modules() -> Dict[str, int]:
    """Conta módulos por categoria varrendo o pacote embedxpl."""
    counts: Dict[str, int] = {
        "exploits": 0,
        "scanners": 0,
        "payloads": 0,
        "encoders": 0,
        "creds":    0,
        "nse":      0,
        "wordlists": 0,
        "cves":     0,
        "kev":      0,
        "tested":   0,
        "untested": 0,
    }

    modules_root = _ROOT / "modules"

    # Exploits
    if (modules_root / "exploits").exists():
        for p in (modules_root / "exploits").rglob("*.py"):
            if p.name != "__init__.py":
                counts["exploits"] += 1

    # Scanners
    if (modules_root / "scanners").exists():
        for p in (modules_root / "scanners").rglob("*.py"):
            if p.name != "__init__.py" and p.name != "autopwn.py":
                counts["scanners"] += 1

    # Payloads
    if (modules_root / "payloads").exists():
        for p in (modules_root / "payloads").rglob("*.py"):
            if p.name != "__init__.py":
                counts["payloads"] += 1

    # Encoders
    if (modules_root / "encoders").exists():
        for p in (modules_root / "encoders").rglob("*.py"):
            if p.name != "__init__.py":
                counts["encoders"] += 1

    # Creds modules
    if (modules_root / "creds").exists():
        for p in (modules_root / "creds").rglob("*.py"):
            if p.name != "__init__.py":
                counts["creds"] += 1

    # NSE scripts
    nse_root = _ROOT / "resources" / "nse"
    if nse_root.exists():
        counts["nse"] = sum(1 for _ in nse_root.rglob("*.nse"))

    # Wordlists
    wl_root = _ROOT / "data" / "wordlists"
    if wl_root.exists():
        counts["wordlists"] = sum(
            1 for p in wl_root.rglob("*")
            if p.is_file() and p.suffix in {".txt", ".lst", ".json"}
        )

    # CVE catalog
    cve_db_path = _ROOT / "data" / "cve_catalog.db"
    if cve_db_path.exists():
        try:
            import sqlite3
            conn = sqlite3.connect(str(cve_db_path))
            cur = conn.cursor()
            row = cur.execute("SELECT COUNT(*) FROM cves WHERE covered=1").fetchone()
            if row:
                counts["cves"] = row[0]
            kev_row = cur.execute(
                "SELECT COUNT(*) FROM cves WHERE is_kev=1 AND covered=1"
            ).fetchone()
            if kev_row:
                counts["kev"] = kev_row[0]
            conn.close()
        except Exception:
            pass

    # Tested / Untested from module_test_status.json
    test_status_path = _ROOT / "data" / "module_test_status.json"
    if test_status_path.exists():
        try:
            import json as _json
            meta = _json.loads(test_status_path.read_text(encoding="utf-8")).get("_meta", {})
            counts["tested"]   = meta.get("tested", 0)
            counts["untested"] = meta.get("untested", 0)
        except Exception:
            pass

    return counts


def _load_stats() -> Dict[str, int]:
    """Carrega stats do cache ou recalcula se expirado."""
    _CACHE_DIR.mkdir(parents=True, exist_ok=True)

    if _CACHE_FILE.exists():
        try:
            data = json.loads(_CACHE_FILE.read_text())
            if time.time() - data.get("_ts", 0) < _CACHE_TTL:
                return data
        except Exception:
            pass

    stats = _count_modules()
    stats["_ts"] = int(time.time())
    try:
        _CACHE_FILE.write_text(json.dumps(stats, indent=2))
    except Exception:
        pass

    return stats


def invalidate_cache() -> None:
    """Força recontagem na próxima chamada (usar após instalar novos módulos)."""
    if _CACHE_FILE.exists():
        _CACHE_FILE.unlink(missing_ok=True)

# ---------------------------------------------------------------------------
# Exibição do banner
# ---------------------------------------------------------------------------

def _read_banner(tool_name: str) -> str:
    key = tool_name.lower().replace("-", "").replace("_", "")
    banner_path = TOOL_BANNERS.get(key)
    if banner_path and banner_path.exists():
        return banner_path.read_text()
    # fallback: gera via figlet se disponível
    try:
        import subprocess
        result = subprocess.run(
            ["figlet", tool_name],
            capture_output=True, text=True, timeout=3
        )
        if result.returncode == 0:
            return result.stdout
    except Exception:
        pass
    return f"\n  {tool_name.upper()}\n"


def show_banner(
    tool_name: str = "embedxpl",
    version: str = "v5.0.0",
    db=None,
    color: bool = True,
) -> None:
    """Exibe o banner figlet + stats em tempo real.

    Args:
        tool_name: Nome da ferramenta (embedxpl, industrialxpl, etc.)
        version:   String de versão exibida ao lado do banner.
        db:        Instância EXFDatabase (opcional — usado para stats de workspace).
        color:     Se False, desativa cores ANSI.
    """
    # Desativa cores se não for terminal
    if not sys.stdout.isatty():
        color = False

    c    = _CYAN   if color else ""
    g    = _GREEN  if color else ""
    y    = _YELLOW if color else ""
    bold = _BOLD   if color else ""
    dim  = _DIM    if color else ""
    rst  = _RESET  if color else ""

    art = _read_banner(tool_name)

    # Colorir a arte ASCII em ciano
    colored_art = f"{bold}{c}{art}{rst}"

    stats = _load_stats()

    exploits  = stats.get("exploits",  0)
    scanners  = stats.get("scanners",  0)
    payloads  = stats.get("payloads",  0)
    encoders  = stats.get("encoders",  0)
    creds_mod = stats.get("creds",     0)
    nse       = stats.get("nse",       0)
    wordlists = stats.get("wordlists", 0)
    cves      = stats.get("cves",      0)
    kev       = stats.get("kev",       0)
    tested    = stats.get("tested",    0)
    untested  = stats.get("untested",  0)

    # Total de módulos
    total = exploits + scanners + payloads + encoders + creds_mod

    print(colored_art, end="")
    print(f"  {bold}{c}{version}{rst}  "
          f"{dim}[ https://github.com/UniaoGeek/XPL-Suite ]{rst}")
    print()
    print(
        f"  {g}Exploits:{rst} {bold}{exploits:>6,}{rst}   "
        f"{g}Scanners:{rst} {bold}{scanners:>5,}{rst}   "
        f"{g}Creds:{rst} {bold}{creds_mod:>6,}{rst}"
    )
    print(
        f"  {g}Payloads:{rst} {bold}{payloads:>6,}{rst}   "
        f"{g}Encoders:{rst} {bold}{encoders:>5,}{rst}   "
        f"{g}NSE:  {rst} {bold}{nse:>6,}{rst}"
    )
    print(
        f"  {g}CVEs:{rst}     {bold}{cves:>6,}{rst}   "
        f"{g}KEV:     {rst} {bold}{kev:>5,}{rst}   "
        f"{g}WLists:{rst}{bold}{wordlists:>6,}{rst}"
    )
    print(
        f"  {g}Tested:{rst}   {bold}{tested:>6,}{rst}   "
        f"{g}Untested:{rst}{bold}{untested:>5,}{rst}"
    )
    print(
        f"  {dim}Total modules: {total:,} | "
        f"Arch: ARM/ARM64/MIPS/MIPS64/x64/x86/RISCV/PPC{rst}"
    )
    print()


def show_banner_for_suite(tool_name: str, **kwargs) -> None:
    """Alias público — usado pelos interpreters dos tools especializados."""
    show_banner(tool_name, **kwargs)


# ---------------------------------------------------------------------------
# CLI rápido para teste
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    name = sys.argv[1] if len(sys.argv) > 1 else "embedxpl"
    show_banner(name)
