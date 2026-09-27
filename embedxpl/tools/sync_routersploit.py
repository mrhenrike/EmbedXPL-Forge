"""EmbedXPL RouterSploit Absorption Tool.

Absorve módulos RouterSploit não importados ainda:
- exploits/cameras/  (21 modules)
- exploits/misc/     (4 modules)
- creds/             (156 restantes de 171)

Converte automaticamente para o padrão EmbedXPL:
- Import: embedxpl.core.exploit (não routersploit.core.exploit)
- Mantém __info__, execute/run, check
- Adiciona wrapper de compatibilidade para OptIP/OptPort

Uso:
    python3 -m embedxpl.tools.sync_routersploit [--dry-run] [--creds-only] [--cameras-only]
"""

from __future__ import annotations

import argparse
import ast
import re
import shutil
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent.parent     # embedxpl/
_RSF_ROOT = _HERE.parent / ".tmp" / "routersploit" / "routersploit" / "modules"
_EXF_EXPLOITS = _HERE / "modules" / "exploits"
_EXF_CREDS   = _HERE / "modules" / "creds" / "rsf"
_EXF_CREDS.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# Transformação de código RSF → EmbedXPL
# ---------------------------------------------------------------------------

_IMPORT_MAP = {
    "from routersploit.core.exploit import *": "from embedxpl.core.exploit import *",
    "from routersploit.core.exploit import shell": "# from routersploit.core.exploit import shell  # absorbed",
    "from routersploit.core.exploit.option import OptIP, OptPort": "from embedxpl.core.exploit.exploit import OptIP, OptPort",
    "from routersploit.core.http.http_client import HTTPClient": "from embedxpl.core.exploit.http_client import HTTPClient",
    "from routersploit.core.udp.udp_client import UDPClient": "from embedxpl.core.exploit.udp_client import UDPClient",
    "from routersploit.core.tcp.tcp_client import TCPClient": "from embedxpl.core.exploit.tcp_client import TCPClient",
    "from routersploit.core.ftp.ftp_client import FTPClient": "from embedxpl.core.exploit.ftp_client import FTPClient",
    "from routersploit.core.ssh.ssh_client import SSHClient": "from embedxpl.core.exploit.ssh_client import SSHClient",
    "from routersploit.core.telnet.telnet_client import TelnetClient": "from embedxpl.core.exploit.telnet_client import TelnetClient",
}

_HEADER = """\
# Absorbed from RouterSploit — rewritten for EmbedXPL v5.0.0
# Original authors preserved in __info__["authors"]
# EmbedXPL adaptation: André Henrique (@mrhenrike) | União Geek
"""


def _transform_source(src: str, vendor: str = "") -> str:
    """Transforma imports RSF em imports EmbedXPL."""
    result = _HEADER + "\n"

    for line in src.splitlines():
        mapped = False
        for rsf_import, exf_import in _IMPORT_MAP.items():
            if line.strip() == rsf_import.strip() or rsf_import in line:
                result += exf_import + "\n"
                mapped = True
                break
        if not mapped:
            # Remover imports RSF não mapeados
            if "routersploit" in line:
                result += f"# SKIPPED: {line}\n"
            else:
                result += line + "\n"

    # Adicionar crédito EmbedXPL aos authors
    result = result.replace(
        '"authors": (',
        '"authors": (\n            "EmbedXPL absorption: André Henrique (@mrhenrike) | União Geek",',
        1
    )

    return result


def _get_module_info(py_file: Path) -> dict:
    """Extrai __info__ de um módulo RSF via AST."""
    try:
        src = py_file.read_text(errors="replace")
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                for item in node.body:
                    if (isinstance(item, ast.Assign) and
                            any(isinstance(t, ast.Name) and t.id == "__info__" for t in item.targets)):
                        return ast.literal_eval(item.value)
    except Exception:
        pass
    return {}


# ---------------------------------------------------------------------------
# Absorção de camera exploits RSF
# ---------------------------------------------------------------------------

def absorb_cameras(dry_run: bool = False) -> int:
    cameras_dir = _RSF_ROOT / "exploits" / "cameras"
    if not cameras_dir.exists():
        print(f"[-] RSF cameras dir not found: {cameras_dir}")
        return 0

    absorbed = 0
    for vendor_dir in sorted(cameras_dir.iterdir()):
        if not vendor_dir.is_dir() or vendor_dir.name.startswith("_"):
            continue
        vendor = vendor_dir.name
        dst_dir = _EXF_EXPLOITS / "cameras" / f"rsf_{vendor}"

        if not dry_run:
            dst_dir.mkdir(parents=True, exist_ok=True)
            (dst_dir / "__init__.py").touch()

        py_files = [f for f in vendor_dir.rglob("*.py") if f.name != "__init__.py"]
        for py_file in py_files:
            dst_file = dst_dir / py_file.name
            if dst_file.exists():
                continue

            info = _get_module_info(py_file)
            src = py_file.read_text(errors="replace")
            transformed = _transform_source(src, vendor)

            if not dry_run:
                dst_file.write_text(transformed)
                print(f"  [+] camera/{vendor}/{py_file.name}")
            else:
                print(f"  [DRY] camera/{vendor}/{py_file.name} — {info.get('name', '?')}")
            absorbed += 1

    return absorbed


# ---------------------------------------------------------------------------
# Absorção de misc RSF
# ---------------------------------------------------------------------------

def absorb_misc(dry_run: bool = False) -> int:
    misc_dir = _RSF_ROOT / "exploits" / "misc"
    if not misc_dir.exists():
        return 0

    dst_dir = _EXF_EXPLOITS / "misc" / "rsf"
    if not dry_run:
        dst_dir.mkdir(parents=True, exist_ok=True)
        (dst_dir / "__init__.py").touch()

    absorbed = 0
    for py_file in misc_dir.rglob("*.py"):
        if py_file.name == "__init__.py":
            continue
        dst_file = dst_dir / py_file.name
        if dst_file.exists():
            continue
        src = py_file.read_text(errors="replace")
        if not dry_run:
            dst_file.write_text(_transform_source(src))
            print(f"  [+] misc/{py_file.name}")
        absorbed += 1
    return absorbed


# ---------------------------------------------------------------------------
# Absorção de creds RSF
# ---------------------------------------------------------------------------

def absorb_creds(dry_run: bool = False) -> int:
    creds_dir = _RSF_ROOT / "creds"
    if not creds_dir.exists():
        print(f"[-] RSF creds dir not found: {creds_dir}")
        return 0

    absorbed = 0
    for py_file in sorted(creds_dir.rglob("*.py")):
        if py_file.name == "__init__.py":
            continue

        # Preserve FULL relative path to avoid vendor collisions
        # RSF: creds/cameras/acti/ftp_default_creds.py
        # EXF: creds/rsf/cameras/acti/ftp_default_creds.py
        rel = py_file.relative_to(creds_dir)
        dst_file = _EXF_CREDS / rel   # preserves full path

        if dst_file.exists():
            continue

        if not dry_run:
            dst_file.parent.mkdir(parents=True, exist_ok=True)
            (dst_file.parent / "__init__.py").touch()
            src = py_file.read_text(errors="replace")
            dst_file.write_text(_transform_source(src))
            print(f"  [+] creds/{rel}")
        else:
            print(f"  [DRY] creds/{rel}")
        absorbed += 1

    return absorbed


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="EmbedXPL RouterSploit Absorber")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--cameras-only", action="store_true")
    parser.add_argument("--creds-only", action="store_true")
    parser.add_argument("--misc-only", action="store_true")
    args = parser.parse_args()

    total = 0
    print(f"\n[*] EmbedXPL RSF Absorber {'(DRY RUN)' if args.dry_run else ''}\n")

    if not args.creds_only and not args.misc_only:
        print("[*] Absorbing camera exploits...")
        n = absorb_cameras(args.dry_run)
        print(f"    → {n} camera modules absorbed\n")
        total += n

    if not args.cameras_only and not args.misc_only:
        print("[*] Absorbing cred modules...")
        n = absorb_creds(args.dry_run)
        print(f"    → {n} cred modules absorbed\n")
        total += n

    if not args.cameras_only and not args.creds_only:
        print("[*] Absorbing misc exploits...")
        n = absorb_misc(args.dry_run)
        print(f"    → {n} misc modules absorbed\n")
        total += n

    print(f"[+] Total absorbed: {total} modules")


if __name__ == "__main__":
    main()
