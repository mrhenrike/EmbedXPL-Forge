"""EmbedXPL NSE Installer.

Detecta o Nmap no sistema, copia nossos NSE customizados para
/usr/share/nmap/scripts/ e executa 'nmap --script-updatedb'.

Apenas NSE *customizados* do EmbedXPL são instalados — os scripts
absorvidos do Nmap original não são reinstalados (já estão lá).

Uso:
    python3 -m embedxpl.tools.nse_installer [--dry-run] [--force]

Comandos no interpreter EmbedXPL:
    exf> nse install          # instala/atualiza
    exf> nse list             # lista status de cada script
    exf> nse run <script> <target>   # executa via nmap
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent.parent   # embedxpl/
_NSE_ROOT = _HERE / "resources" / "nse"
_NMAP_SCRIPTS = Path("/usr/share/nmap/scripts")

# NSE customizados do EmbedXPL (prefixo embedxpl-)
_EMBEDXPL_PREFIX = "embedxpl-"


def find_nmap() -> str | None:
    """Retorna caminho do nmap se instalado."""
    nmap = shutil.which("nmap")
    return nmap


def list_our_nse() -> list[Path]:
    """Lista todos os NSE customizados do EmbedXPL."""
    return sorted(_NSE_ROOT.rglob(f"{_EMBEDXPL_PREFIX}*.nse"))


def install(dry_run: bool = False, force: bool = False) -> dict:
    """Instala NSE customizados no diretório do Nmap.

    Returns:
        dict com listas: added, updated, skipped, errors
    """
    nmap = find_nmap()
    if not nmap:
        print("[-] nmap not found. Install nmap first.")
        return {"added": [], "updated": [], "skipped": [], "errors": ["nmap not found"]}

    if not _NMAP_SCRIPTS.exists():
        print(f"[-] Nmap scripts dir not found: {_NMAP_SCRIPTS}")
        return {"errors": [f"Directory not found: {_NMAP_SCRIPTS}"]}

    our_nse = list_our_nse()
    results = {"added": [], "updated": [], "skipped": [], "errors": []}

    for src in our_nse:
        dst = _NMAP_SCRIPTS / src.name
        action = "add"
        if dst.exists():
            # Compare content
            if dst.read_bytes() == src.read_bytes() and not force:
                results["skipped"].append(src.name)
                continue
            action = "update"

        if not dry_run:
            try:
                shutil.copy2(src, dst)
                results[action + "d" if action == "update" else "added"].append(src.name)
                print(f"[+] {action.upper()}: {src.name} → {dst}")
            except PermissionError:
                # Try with sudo
                try:
                    subprocess.run(["sudo", "cp", str(src), str(dst)], check=True)
                    results["added"].append(src.name)
                    print(f"[+] {action.upper()} (sudo): {src.name}")
                except Exception as e:
                    results["errors"].append(f"{src.name}: {e}")
                    print(f"[-] ERROR: {src.name}: {e}")
        else:
            print(f"[DRY-RUN] Would {action}: {src.name} → {dst}")
            results["added"].append(src.name)

    # Update nmap script DB
    if not dry_run and (results["added"] or results.get("updated")):
        print("[*] Running: nmap --script-updatedb")
        try:
            result = subprocess.run([nmap, "--script-updatedb"],
                                    capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                print("[+] Nmap script database updated")
            else:
                print(f"[-] updatedb failed: {result.stderr[:200]}")
        except Exception as e:
            print(f"[-] updatedb error: {e}")

    return results


def status() -> None:
    """Lista todos os NSE do EmbedXPL e seu status de instalação."""
    print("\n  NSE Scripts — EmbedXPL Arsenal\n  " + "─" * 60)
    print(f"  {'Script':<45} {'Category':<15} {'Installed'}")
    print("  " + "─" * 60)

    all_nse = sorted(_NSE_ROOT.rglob("*.nse"))
    for nse in all_nse:
        category = nse.parent.name
        dst = _NMAP_SCRIPTS / nse.name
        installed = "✓ YES" if dst.exists() else "  NO"
        origin = "[EXF]" if nse.name.startswith(_EMBEDXPL_PREFIX) else "[ABS]"
        print(f"  {origin} {nse.name:<42} {category:<15} {installed}")

    total = len(all_nse)
    installed_count = sum(1 for n in all_nse if (_NMAP_SCRIPTS / n.name).exists())
    print(f"\n  Total: {total} NSE | Installed in Nmap: {installed_count}\n")


def run_nse(script_name: str, target: str, extra_args: list | None = None) -> None:
    """Executa um NSE via nmap contra um alvo."""
    nmap = find_nmap()
    if not nmap:
        print("[-] nmap not installed")
        return

    # Tenta encontrar o script
    script_path = None
    for nse in _NSE_ROOT.rglob(f"*{script_name}*"):
        script_path = str(nse)
        break

    if not script_path:
        script_path = script_name  # usa como nome direto

    cmd = [nmap, "-sV", f"--script={script_path}", target]
    if extra_args:
        cmd.extend(extra_args)

    print(f"[*] Running: {' '.join(cmd)}")
    subprocess.run(cmd)


def main() -> None:
    parser = argparse.ArgumentParser(description="EmbedXPL NSE Installer")
    sub = parser.add_subparsers(dest="cmd")

    ins = sub.add_parser("install", help="Install/update NSE scripts in Nmap")
    ins.add_argument("--dry-run", action="store_true")
    ins.add_argument("--force", action="store_true")

    sub.add_parser("list", help="List NSE status")

    run_p = sub.add_parser("run", help="Run NSE against target")
    run_p.add_argument("script")
    run_p.add_argument("target")

    args = parser.parse_args()

    if args.cmd == "install":
        install(dry_run=args.dry_run, force=args.force)
    elif args.cmd == "list":
        status()
    elif args.cmd == "run":
        run_nse(args.script, args.target)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
