# TODO/FIXME/HACK/XXX Triage Report

**Date:** 2026-10-20
**Total occurrences:** 73
**Wave:** 2.2

## Classification Summary

| Category | Count | Action |
|---|---|---|
| False positive (data strings, IP placeholders, model names) | 24 | None |
| Vendor code (DahuaConsole, esp32, ISF, pywinbox, xmir, cisco) | 35 | Do not modify upstream |
| Tool references (audit tools scanning for TODO patterns) | 5 | None |
| Core actionable | 5 | Tagged TODO(wave3) |
| Obsolete/removed | 3 | Removed |

## Core Actionable (tagged TODO(wave3))

1. `embedxpl/intel/shodan/alert.py:426`: Refactor shared code from `__main__.py:stats()`
2. `embedxpl/intel/shodan/worldmap.py:105-106`: Filter and zoom map support (in docstring)
3. `embedxpl/interpreter.py:900`: Test coverage for `_show_devices`

## Removed

1. `embedxpl/intel/shodan/worldmap.py:154`: FIXME position (functional)
2. `embedxpl/intel/shodan/worldmap.py:178`: FIXME window size check (functional)
3. `embedxpl/modules/exploits/routers/edb_48149.py:72`: `[TODO]` in description string

## Vendor Code (35 occurrences, do not modify)

| Directory | Count | Origin |
|---|---|---|
| engines/dahua_console/lib/DahuaConsole/ | 12 | DahuaConsole upstream |
| modules/exploits/hardware/cisco/ | 14 | Exploit-DB submissions |
| engines/firmware/esp32/ | 5 | esp32_image_parser upstream |
| modules/exploits/ics/isf/ | 7 | ISF/ICSSPLOIT upstream |
| modules/exploits/network_os/mikrotik/pywinbox/ | 5 | pywinbox upstream |
| modules/exploits/routers/xiaomi/xmir/ | 3 | xmir upstream |
| modules/exploits/cameras/dahua/ | 2 | Dahua exploit code |
| modules/exploits/nas/ | 2 | NAS exploit code |

## False Positives (24 occurrences)

- `XXX` in URI data strings (cisco edb_47442): 14
- `XXX` in device model names (dahua cameras, p2p scan): 3
- `XXX.XXX.XXX.XXX` IP placeholders: 1
- `AA26-XXX` CISA advisory reference: 1
- `HACK-PC` hostname in S7 PLC control: 2
- `XXX` in logger message (trisis decompiled): 1
- `TODO` in C code string literal (malware_builder): 1
- `XXX` in timezone response: 1
