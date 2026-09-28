"""EmbedXPL HatSploit Absorption Tool.

Absorve os 210 módulos Python do HatSploit (EntySec) para EmbedXPL.
Categorias: exploit (android, apple_ios, generic, linux, ...) | auxiliary | post

Conversão:
- Imports HatSploit → EmbedXPL
- Preserva __info__, __categories__, execute/run
- Destino: modules/exploits/routers/hatsploit/ e sub-categorias

Uso:
    python3 -m embedxpl.tools.sync_hatsploit [--dry-run]
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent.parent
_HSF_ROOT = Path("/run/media/mrhenrike/Data/Projects/Submodulos/IoT/third-party-router-poc/EntySec__HatSploit/hatsploit/modules")
_EXF_DEST = _HERE / "modules" / "exploits" / "hatsploit"

_HEADER = """\
# Absorbed from HatSploit (EntySec) — rewritten for EmbedXPL v5.0.0
# Original authors preserved in __info__
# EmbedXPL adaptation: André Henrique (@mrhenrike) | União Geek
"""

_IMPORT_MAP = [
    (r'from hatsploit\.lib\.core\.exploit\.', '# from hatsploit.lib.core.exploit.'),
    (r'from hatsploit\.lib\.', '# from hatsploit.lib.'),
    (r'from hatsploit\.', '# from hatsploit.'),
    (r'import hatsploit', '# import hatsploit'),
]


def _transform(src: str) -> str:
    result = _HEADER + "\n"
    # Add HatSploit shim — provides all base classes HatSploit modules need
    result += "from embedxpl.core.compat.hatsploit_shim import *\n"
    result += "from embedxpl.core.exploit import *\n\n"

    for line in src.splitlines():
        stripped = line.strip()
        # Skip HatSploit imports
        if any(stripped.startswith(pat.replace(".*", "")) or
               stripped.startswith("from hatsploit") or
               stripped.startswith("import hatsploit")
               for pat in ["from hatsploit", "import hatsploit"]):
            result += f"# ABSORBED: {line}\n"
            continue
        result += line + "\n"

    return result


def absorb(dry_run: bool = False) -> int:
    if not _HSF_ROOT.exists():
        print(f"[-] HatSploit not found at {_HSF_ROOT}")
        return 0

    total = 0
    categories = ["exploit", "auxiliary", "post"]

    for cat in categories:
        cat_dir = _HSF_ROOT / cat
        if not cat_dir.exists():
            continue

        for py_file in sorted(cat_dir.rglob("*.py")):
            if py_file.name == "__init__.py":
                continue

            # Build destination path mirroring HSF structure
            rel = py_file.relative_to(_HSF_ROOT)
            dst_file = _EXF_DEST / rel

            if dst_file.exists():
                continue

            src = py_file.read_text(errors="replace")
            transformed = _transform(src)

            if not dry_run:
                dst_file.parent.mkdir(parents=True, exist_ok=True)
                (dst_file.parent / "__init__.py").touch()
                dst_file.write_text(transformed)
                print(f"  [+] hatsploit/{rel}")
            else:
                print(f"  [DRY] hatsploit/{rel}")
            total += 1

    return total


def main() -> None:
    parser = argparse.ArgumentParser(description="EmbedXPL HatSploit Absorber")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    print(f"\n[*] EmbedXPL HatSploit Absorber {'(DRY RUN)' if args.dry_run else ''}\n")
    n = absorb(args.dry_run)
    print(f"\n[+] Total: {n} HatSploit modules absorbed → modules/exploits/hatsploit/")


if __name__ == "__main__":
    main()
