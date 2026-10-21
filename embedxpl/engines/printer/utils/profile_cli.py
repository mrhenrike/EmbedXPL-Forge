#!/usr/bin/env python3
"""CLI entry for pxf-profile console script."""
from __future__ import annotations

import sys

from utils.module_profile import (
    apply_pip_extra,
    list_profiles,
    profile_stats,
)


def main(argv=None) -> int:
    args = list(argv or sys.argv[1:])
    if not args or args[0] in ("-h", "--help"):
        print("Usage: pxf-profile [list|show|apply] [PROFILE]")
        print("  pxf-profile apply modern          # default: 2020+ modules")
        print("  pxf-profile apply full-depth      # all ~30 years")
        print("  pxf-profile apply vendor-hp       # HP only")
        print("  pxf-profile apply modern-vendor-hp")
        return 0

    cmd = args[0].lower()
    if cmd == "list":
        for name in list_profiles():
            print(f"  {name}")
        return 0

    if cmd == "show":
        st = profile_stats()
        print(f"Profile:     {st['profile']}")
        print(f"Description: {st['description']}")
        print(f"Active:      {st['active']} / {st['total_shipped']} modules")
        print(f"Config:      {st['config_file']}")
        return 0

    if cmd == "apply":
        if len(args) < 2:
            print("[!] Missing profile name")
            return 1
        name = apply_pip_extra(args[1])
    else:
        name = apply_pip_extra(args[0])

    st = profile_stats(name)
    print(f"[+] Profile: {name} ({st['active']}/{st['total_shipped']} modules)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
