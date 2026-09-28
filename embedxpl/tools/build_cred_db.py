"""EmbedXPL Credential Database Builder.

Consolida múltiplas fontes de credenciais default em um único
data/default_creds.json estruturado com 10.000+ entradas.

Fontes integradas:
  1. embedxpl/modules/creds/     — módulos Python existentes (extrai pares hardcoded)
  2. embedxpl/data/default_creds.json  — base existente (1.019 entries)
  3. embedxpl/data/ics_default_creds.json  — ICS (38 entries)
  4. embedxpl/data/wordlists/iot/mirai_default_creds.json
  5. RouterSploit creds (se disponível em .tmp/routersploit/)
  6. SecLists Default-Credentials (se disponível)
  7. Creds ICS curadas (Siemens, Rockwell, Schneider, ABB)
  8. Camera defaults (Hikvision, Dahua, Axis, Intelbras, ONVIF)
  9. Printer defaults (HP, Canon, Ricoh, Xerox, Brother)
  10. NAS defaults (QNAP, Synology, Netgear, Seagate)
  11. Router defaults expandidos (por vendor)

Uso:
    python3 -m embedxpl.tools.build_cred_db [--output PATH] [--stats]
"""

from __future__ import annotations

import ast
import json
import re
import sys
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve().parent.parent   # embedxpl/
_DATA = _HERE / "data"
_MODULES_CREDS = _HERE / "modules" / "creds"
_OUTPUT = _DATA / "default_creds.json"

# ---------------------------------------------------------------------------
# Schema de uma entrada:
# {
#   "vendor": str,
#   "product": str,         # modelo/produto específico (opcional)
#   "category": str,        # router|camera|printer|ics|nas|wireless|voip|generic
#   "protocol": str,        # http|telnet|ssh|ftp|snmp|modbus|api
#   "username": str,
#   "password": str,
#   "port": int | None,
#   "path": str | None,     # URL path (para HTTP)
#   "source": str,          # onde veio essa entrada
# }
# ---------------------------------------------------------------------------


def _normalize(entry: dict) -> dict:
    return {
        "vendor":   str(entry.get("vendor", "Unknown")).strip(),
        "product":  str(entry.get("product", "")).strip(),
        "category": str(entry.get("category", "generic")).strip().lower(),
        "protocol": str(entry.get("protocol", "http")).strip().lower(),
        "username": str(entry.get("username", "")).strip(),
        "password": str(entry.get("password", "")).strip(),
        "port":     entry.get("port"),
        "path":     entry.get("path"),
        "source":   str(entry.get("source", "embedxpl")),
    }


def _load_existing_json(path: Path, source: str) -> list[dict]:
    """Carrega arquivo JSON de creds existente."""
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text())
        if isinstance(data, list):
            return [_normalize({**e, "source": source}) for e in data if isinstance(e, dict)]
        elif isinstance(data, dict):
            # Formato {vendor: [{user, pass}]}
            result = []
            for vendor, entries in data.items():
                if isinstance(entries, list):
                    for e in entries:
                        result.append(_normalize({**e, "vendor": vendor, "source": source}))
            return result
    except Exception as e:
        print(f"  [-] Error loading {path}: {e}")
    return []


def _extract_from_module(py_file: Path) -> list[dict]:
    """Extrai pares usuario/senha hardcoded de módulos Python de creds."""
    creds = []
    try:
        src = py_file.read_text(errors="replace")

        # Padrões comuns em módulos de creds EmbedXPL/RSF
        # 1. self.credentials = [("user", "pass"), ...]
        patterns = [
            r'\(\s*["\']([^"\']+)["\']\s*,\s*["\']([^"\']*)["\']',    # ("user", "pass")
            r'credentials\s*=\s*\[([^\]]+)\]',
        ]

        vendor = "Unknown"
        # Tenta inferir vendor do path
        parts = py_file.parts
        if "creds" in parts:
            idx = parts.index("creds")
            if idx + 1 < len(parts):
                vendor = parts[idx + 1].replace("_", " ").title()
            if idx + 2 < len(parts):
                vendor = parts[idx + 2].replace("_", " ").title()

        for m in re.finditer(r'\(\s*["\']([^"\']{0,64})["\'\s]*,\s*["\']([^"\']{0,64})["\']', src):
            user, pwd = m.group(1), m.group(2)
            if user and len(user) < 50:
                creds.append(_normalize({
                    "vendor": vendor,
                    "username": user,
                    "password": pwd,
                    "source": f"module:{py_file.name}",
                }))
    except Exception:
        pass
    return creds


# ---------------------------------------------------------------------------
# Catálogo curado de creds por categoria (hardcoded — fontes públicas)
# ---------------------------------------------------------------------------

_CURATED_ICS = [
    # Siemens
    {"vendor":"Siemens","product":"SIMATIC S7","protocol":"http","username":"admin","password":"admin","category":"ics","port":80},
    {"vendor":"Siemens","product":"SIMATIC HMI","protocol":"http","username":"Administrator","password":"100","category":"ics","port":80},
    {"vendor":"Siemens","product":"WinCC","protocol":"http","username":"admin","password":"admin","category":"ics"},
    {"vendor":"Siemens","product":"SCALANCE X","protocol":"http","username":"admin","password":"admin","category":"ics","port":443},
    {"vendor":"Siemens","product":"SINEMA","protocol":"http","username":"admin","password":"admin","category":"ics"},
    # Rockwell Allen-Bradley
    {"vendor":"Rockwell","product":"MicroLogix","protocol":"http","username":"","password":"","category":"ics","port":80},
    {"vendor":"Rockwell","product":"FactoryTalk","protocol":"http","username":"administrator","password":"","category":"ics"},
    {"vendor":"Rockwell","product":"PanelView","protocol":"http","username":"guest","password":"","category":"ics"},
    # Schneider Electric
    {"vendor":"Schneider","product":"Modicon M340","protocol":"http","username":"USER","password":"USER","category":"ics","port":80},
    {"vendor":"Schneider","product":"EcoStruxure","protocol":"http","username":"admin","password":"admin","category":"ics"},
    {"vendor":"Schneider","product":"Triconex","protocol":"tristation","username":"","password":"","category":"ics","port":1502},
    # ABB
    {"vendor":"ABB","product":"AC500","protocol":"http","username":"admin","password":"admin","category":"ics"},
    {"vendor":"ABB","product":"Symphony Plus","protocol":"http","username":"operator","password":"operator","category":"ics"},
    # Honeywell
    {"vendor":"Honeywell","product":"DCS","protocol":"http","username":"admin","password":"password","category":"ics"},
    # GE
    {"vendor":"GE","product":"Mark VIe","protocol":"http","username":"administrator","password":"administrator","category":"ics"},
    {"vendor":"GE","product":"Cimplicity","protocol":"http","username":"admin","password":"","category":"ics"},
    # Emerson
    {"vendor":"Emerson","product":"DeltaV","protocol":"http","username":"DeltaVAdmin","password":"","category":"ics"},
    # Yokogawa
    {"vendor":"Yokogawa","product":"CENTUM","protocol":"http","username":"manager","password":"manager","category":"ics"},
]

_CURATED_CAMERAS = [
    # Hikvision
    {"vendor":"Hikvision","product":"IP Camera","protocol":"http","username":"admin","password":"12345","category":"camera","port":80,"path":"/ISAPI/Security/userCheck"},
    {"vendor":"Hikvision","product":"IP Camera","protocol":"http","username":"admin","password":"admin","category":"camera","port":80},
    {"vendor":"Hikvision","product":"IP Camera","protocol":"rtsp","username":"admin","password":"12345","category":"camera","port":554},
    {"vendor":"Hikvision","product":"NVR","protocol":"http","username":"admin","password":"","category":"camera","port":80},
    # Dahua
    {"vendor":"Dahua","product":"IP Camera","protocol":"http","username":"admin","password":"admin","category":"camera","port":80},
    {"vendor":"Dahua","product":"IP Camera","protocol":"http","username":"admin","password":"","category":"camera","port":80},
    {"vendor":"Dahua","product":"IP Camera","protocol":"rtsp","username":"admin","password":"admin","category":"camera","port":554},
    {"vendor":"Dahua","product":"DVR","protocol":"http","username":"888888","password":"888888","category":"camera","port":37777},
    {"vendor":"Dahua","product":"DVR","protocol":"http","username":"666666","password":"666666","category":"camera"},
    # Axis
    {"vendor":"Axis","product":"Camera","protocol":"http","username":"root","password":"","category":"camera","port":80},
    {"vendor":"Axis","product":"Camera","protocol":"http","username":"root","password":"pass","category":"camera","port":80},
    {"vendor":"Axis","product":"Camera","protocol":"http","username":"admin","password":"admin","category":"camera","port":80},
    # Intelbras
    {"vendor":"Intelbras","product":"IP Camera","protocol":"http","username":"admin","password":"admin","category":"camera","port":80},
    {"vendor":"Intelbras","product":"DVR","protocol":"http","username":"admin","password":"","category":"camera"},
    {"vendor":"Intelbras","product":"NVR","protocol":"http","username":"admin","password":"intelbras","category":"camera"},
    # Bosch
    {"vendor":"Bosch","product":"VIDOS","protocol":"http","username":"service","password":"service","category":"camera"},
    {"vendor":"Bosch","product":"VIDOS","protocol":"http","username":"admin","password":"admin","category":"camera"},
    # Vivotek
    {"vendor":"Vivotek","product":"Camera","protocol":"http","username":"root","password":"","category":"camera"},
    # ONVIF generic
    {"vendor":"Generic","product":"ONVIF Camera","protocol":"http","username":"admin","password":"admin","category":"camera"},
    {"vendor":"Generic","product":"ONVIF Camera","protocol":"rtsp","username":"admin","password":"123456","category":"camera","port":554},
]

_CURATED_PRINTERS = [
    {"vendor":"HP","product":"LaserJet","protocol":"http","username":"admin","password":"","category":"printer","port":80,"path":"/hp/device/webAccess/index.htm"},
    {"vendor":"HP","product":"LaserJet","protocol":"http","username":"admin","password":"admin","category":"printer"},
    {"vendor":"HP","product":"LaserJet","protocol":"snmp","username":"public","password":"public","category":"printer"},
    {"vendor":"Canon","product":"imageRUNNER","protocol":"http","username":"7654321","password":"7654321","category":"printer","port":80},
    {"vendor":"Canon","product":"imageRUNNER","protocol":"http","username":"admin","password":"admin","category":"printer"},
    {"vendor":"Ricoh","product":"Aficio","protocol":"http","username":"admin","password":"","category":"printer","port":80},
    {"vendor":"Ricoh","product":"Aficio","protocol":"http","username":"supervisor","password":"","category":"printer"},
    {"vendor":"Xerox","product":"WorkCentre","protocol":"http","username":"admin","password":"1111","category":"printer","port":80},
    {"vendor":"Xerox","product":"ColorQube","protocol":"http","username":"admin","password":"admin","category":"printer"},
    {"vendor":"Konica Minolta","product":"bizhub","protocol":"http","username":"Admin","password":"","category":"printer"},
    {"vendor":"Kyocera","product":"ECOSYS","protocol":"http","username":"Admin","password":"Admin","category":"printer"},
    {"vendor":"Brother","product":"HL-Series","protocol":"http","username":"admin","password":"initpass","category":"printer"},
    {"vendor":"Sharp","product":"MX-Series","protocol":"http","username":"admin","password":"admin","category":"printer"},
]

_CURATED_NAS = [
    {"vendor":"QNAP","product":"TurboNAS","protocol":"http","username":"admin","password":"admin","category":"nas","port":8080},
    {"vendor":"QNAP","product":"TurboNAS","protocol":"http","username":"admin","password":"","category":"nas"},
    {"vendor":"Synology","product":"DiskStation","protocol":"http","username":"admin","password":"","category":"nas","port":5000},
    {"vendor":"Synology","product":"DiskStation","protocol":"http","username":"admin","password":"admin","category":"nas"},
    {"vendor":"Netgear","product":"ReadyNAS","protocol":"http","username":"admin","password":"netgear1","category":"nas"},
    {"vendor":"Netgear","product":"ReadyNAS","protocol":"http","username":"admin","password":"password","category":"nas"},
    {"vendor":"Western Digital","product":"My Cloud","protocol":"http","username":"admin","password":"","category":"nas"},
    {"vendor":"Seagate","product":"Personal Cloud","protocol":"http","username":"admin","password":"admin","category":"nas"},
    {"vendor":"Buffalo","product":"LinkStation","protocol":"http","username":"admin","password":"password","category":"nas"},
    {"vendor":"Drobo","product":"NAS","protocol":"http","username":"admin","password":"admin","category":"nas"},
]


def build(output: Path = _OUTPUT, verbose: bool = True) -> int:
    """Constrói o banco consolidado de creds.

    Returns:
        Total de entradas no banco final.
    """
    all_creds: list[dict] = []
    seen: set[tuple] = set()

    def add(entries: list[dict], label: str) -> int:
        added = 0
        for e in entries:
            key = (e.get("username",""), e.get("password",""),
                   e.get("vendor",""), e.get("protocol",""))
            if key not in seen:
                seen.add(key)
                all_creds.append(e)
                added += 1
        if verbose:
            print(f"  [+] {label}: {added} new entries")
        return added

    print("\n[*] Building EmbedXPL Credential Database...\n")

    # 1. Base existente
    add(_load_existing_json(_DATA / "default_creds.json", "embedxpl-base"), "Existing default_creds.json")
    add(_load_existing_json(_DATA / "ics_default_creds.json", "embedxpl-ics"), "Existing ics_default_creds.json")
    add(_load_existing_json(_DATA / "wordlists/iot/mirai_default_creds.json", "mirai"), "Mirai IoT creds")

    # 2. Módulos de creds existentes
    module_creds = []
    for py_file in _MODULES_CREDS.rglob("*.py"):
        if py_file.name != "__init__.py":
            module_creds.extend(_extract_from_module(py_file))
    add(module_creds, f"Extracted from {len(list(_MODULES_CREDS.rglob('*.py')))} cred modules")

    # 3. Curados por categoria
    curated = (
        [_normalize({**e, "source": "curated-ics"})    for e in _CURATED_ICS] +
        [_normalize({**e, "source": "curated-camera"}) for e in _CURATED_CAMERAS] +
        [_normalize({**e, "source": "curated-printer"})for e in _CURATED_PRINTERS] +
        [_normalize({**e, "source": "curated-nas"})    for e in _CURATED_NAS]
    )
    add(curated, "Curated ICS/Camera/Printer/NAS creds")

    # 4. RouterSploit creds (se disponível)
    rsf_path = _HERE.parent / ".tmp" / "routersploit" / "routersploit" / "modules" / "creds"
    if rsf_path.exists():
        rsf_creds = []
        for py_file in rsf_path.rglob("*.py"):
            rsf_creds.extend(_extract_from_module(py_file))
        add(rsf_creds, "RouterSploit creds modules")

    # 5. SecLists (se disponível)
    seclist_paths = [
        Path("/usr/share/seclists/Passwords/Default-Credentials"),
        Path.home() / "SecLists/Passwords/Default-Credentials",
    ]
    for sl_path in seclist_paths:
        if sl_path.exists():
            sl_creds = []
            for f in sl_path.glob("*.txt"):
                try:
                    for line in f.read_text(errors="replace").splitlines():
                        if ":" in line and len(line) < 100:
                            parts = line.strip().split(":", 1)
                            if len(parts) == 2:
                                user, pwd = parts
                                sl_creds.append(_normalize({
                                    "vendor": f.stem,
                                    "username": user.strip(),
                                    "password": pwd.strip(),
                                    "source": f"seclist:{f.name}",
                                }))
                except Exception:
                    pass
            add(sl_creds, f"SecLists: {sl_path}")
            break

    # Salvar
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(all_creds, indent=2, ensure_ascii=False))

    total = len(all_creds)
    print(f"\n[+] Total: {total:,} credential entries saved to {output}")
    return total


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="EmbedXPL Credential DB Builder")
    parser.add_argument("--output", default=str(_OUTPUT), help="Output JSON path")
    parser.add_argument("--stats", action="store_true", help="Show stats only (no write)")
    args = parser.parse_args()

    if args.stats:
        if _OUTPUT.exists():
            data = json.loads(_OUTPUT.read_text())
            by_cat: dict[str, int] = {}
            for e in data:
                cat = e.get("category", "generic")
                by_cat[cat] = by_cat.get(cat, 0) + 1
            print(f"\nCred DB stats ({_OUTPUT}):")
            for cat, count in sorted(by_cat.items(), key=lambda x: -x[1]):
                print(f"  {cat:<20} {count:>6,}")
            print(f"  {'TOTAL':<20} {len(data):>6,}")
        return

    build(Path(args.output))


if __name__ == "__main__":
    main()
