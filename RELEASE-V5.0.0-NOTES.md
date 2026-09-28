# EmbedXPL v5.0.0 — Unified XPL Suite Framework

**Release Date:** 2026-09-26
**Author:** Andre Henrique (@mrhenrike) | Uniao Geek

---

## What's New

EmbedXPL v5.0.0 transforms from a focused IoT/router exploitation tool into the
**unified framework for the entire XPL Suite**, while each specialized tool
(WirelessXPL, PrinterXPL, FirewallXPL, IndustrialXPL, WordlistXPL) remains
active and maintains its own domain expertise.

## Key Additions

### Multi-Language Runtime
Run exploit modules in **Python, C, C++, Go, Rust, or Ruby** from a single framework:
```python
class CameradarRTSP(BaseExploit):
    native_language = "go"
    native_source   = "native_src/go/cameradar"

class MeltdownExploit(BaseExploit):
    native_language = "c"
    native_source   = "native_src/c/meltdown/meltdown.c"

class MsfModule(BaseExploit):
    native_language = "ruby"
    native_source   = "native_src/ruby/msf/exploits_linux_http/..."
    msf_module      = True
```

### MSF-style Search
```python
from embedxpl.tools.search import search, print_results
results = search("dlink")                    # keyword
results = search("cve-2021-36260")           # CVE
results = search("type:router")             # by category
results = search("vendor:hikvision")        # by vendor
print_results(results)
```

### AutoPwn by Segment
```python
from embedxpl.modules.autopwn import RouterAutoPwn, FirewallAutoPwn
ap = RouterAutoPwn("192.168.1.0/24", check_only=True)
report = ap.run()   # runs all 1055+ router modules in check mode
```

### Absorbed Tools
- **MikrotikAPI-BF** — fully absorbed into `modules/exploits/network_os/mikrotik/`
- MikrotikAPI-BF repo deprecated (see disclaimer banner on that repo)

### Specialized Tool Integration
All specialized XPL Suite tools are now synced into EmbedXPL:
- `wireless/`   — 477 modules from WirelessXPL (WiFi/BLE/LoRaWAN/drones)
- `printers/`   — 237 modules from PrinterXPL (HP/Canon/Ricoh/CUPS)
- `firewalls/`  — 685 modules from FirewallXPL (NGFW/UTM/IDS/IPS/NAC)
- `ics/`        — 1657 modules from IndustrialXPL (ICS/OT/PLC/SCADA)
- `engines/wordlists/` — from WordlistXPL

Keep tools in sync: `make sync` or `python -m embedxpl.tools.sync_from_suite`

### Native Source Research Material
- `native_src/c/mirai_iot/` — Mirai C source (cross-compile study)
- `native_src/go/cameradar/` — Cameradar RTSP scanner (80 .go)
- `native_src/ruby/msf/` — 1414 Metasploit Ruby modules
- `malware_research/` — TRISIS, Mirai, BlackEnergy, Industroyer2

## Module Count (approximate)

| Domain | Modules |
|---|---|
| routers/ | ~1.100 |
| firewalls/ | ~685 |
| ics/ | ~1.657 |
| wireless/ | ~477 |
| cameras/ | ~210 |
| printers/ | ~237 |
| network_os/mikrotik/ | ~60 |
| smart_tv/ | ~90 |
| **Total** | **~4.500+** |

## Installation

```bash
git clone https://github.com/UniaoGeek/EmbedXPL-Forge
cd EmbedXPL-Forge
pip install -r requirements.txt
python -m embedxpl
```

## Upgrade from v3.x

No breaking changes to existing module API. New features are additive.
The `multi_lang_module.py` mixin continues to work as before.
New `runtime/` package is the recommended path for new multi-language modules.

---

*EmbedXPL v5.0.0 — Security research and authorized offensive security tool.*
*Uniao Geek | https://github.com/UniaoGeek | security.research@uniaogeek.com.br*
