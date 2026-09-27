# Catalogs and Tools

**Language:** English (en-US) | **pt-BR:** [../pt-BR/10-catalogos-e-ferramentas.md](../pt-BR/10-catalogos-e-ferramentas.md)

---

## Overview

EmbedXPL-Forge ships a set of developer and CI tools under the `tools/` directory and a set of JSON/YAML data catalogs under `embedxpl/resources/`. These tools support module validation, CVE catalog maintenance, wiki generation, and environment diagnostics.

---

## Data Catalogs (`embedxpl/resources/`)

### `firmware_sources.yaml`

Vendor firmware download registry. Keys are lowercase vendor identifiers; each entry maps to portal URL, category, login requirement, and notes.

```yaml
vendors:
  hikvision:
    name: "Hikvision"
    category: "ip-cameras"
    portal_url: "https://www.hikvision.com/en/support/download/firmware/"
    requires_login: false
    notes: "Direct download links available for most models."
  tplink:
    name: "TP-Link"
    category: "routers"
    portal_url: "https://www.tp-link.com/en/support/download/"
    requires_login: false
  cisco:
    name: "Cisco"
    category: "routers-switches"
    portal_url: "https://software.cisco.com/download/home"
    requires_login: true
    notes: "Requires Cisco account with entitlement."
```

Consumed by `firmware-dl` CLI (`embedxpl/tools/firmware_downloader.py`).

---

### `infra_profiles.yaml`

Infrastructure context taxonomy for the `--infra` / `--context` orchestrator mode. Maps `(infra, context)` tuples to module path prefixes.

| Infra | Context | Label | Mapped module paths |
|-------|---------|-------|---------------------|
| `ot` | `ics` | ICS / SCADA | `exploits/ics/`, `scanners/ics/`, `creds/ics/`, `exploits/firewalls/siemens/`, `exploits/firewalls/moxa/`, `exploits/firewalls/hirschmann/`, `exploits/firewalls/schneider/`, `exploits/firewalls/phoenix/` |
| `ot` | `energy` | Energy / Smart Meters | `exploits/smart_meters/`, `scanners/smart_meters/` |
| `ot` | `building` | Building Automation (BACnet/HVAC) | `scanners/ics/`, `creds/ics/`, `exploits/bms/` |
| `it` | `enterprise_network` | Enterprise Network Perimeter | `exploits/firewalls/`, `exploits/switches/`, `exploits/vpn/`, `exploits/appliances/`, `exploits/ngfw/`, `exploits/network_os/`, `scanners/firewalls/`, `creds/firewalls/` |
| `it` | `hypervisor` | Hypervisors / Virtualization | `exploits/hypervisors/`, `creds/hypervisors/`, `scanners/hypervisors/` |
| `it` | `bmc_ipmi` | BMC / IPMI / Out-of-Band Management | `exploits/bmc/`, `scanners/bmc/`, `creds/bmc/` |
| `it` | `ups_power` | UPS / Power Management | `exploits/ups/`, `scanners/ups/`, `creds/ups/` |
| `iot` | `home` | Home / SOHO | `exploits/routers/`, `exploits/soho_edge/` |

---

### `catalogs/` resources

| File | Purpose |
|------|---------|
| `market_priority_devices_2010_2026.json` | Market-priority device coverage matrix — device models ranked by deployment volume and CVE density for module prioritization |
| `module_target_scope.json` | Module-to-target-scope mapping — specifies which target device classes each module addresses |
| `cve_extended_catalog.json` | Extended CVE reference data — CVSS scores, CWE, affected firmware versions, MITRE ATT&CK techniques, and associated EmbedXPL module paths |
| `arsenal_layout.json` | Arsenal layout descriptor — describes the visual grouping of modules by attack phase for the arsenal index tool |

---

## Tools (`tools/`)

| Script | Role |
|--------|------|
| `phase_gate.py` | Automated quality gate — validates modules before release across 7 sequential gate phases |
| `env_doctor.py` | Environment diagnostics — reports Python version, dependency status, missing optionals |
| `compat_smoke.py` | Compatibility smoke checks — quick import and interface test for all modules |
| `gen_wiki_module_index.py` | Regenerate wiki module annex from live module metadata |
| `generate_coverage_matrix.py` | Build HTML/JSON coverage matrix artifacts from device catalog |
| `generate_full_catalog.py` | Generate full catalog outputs (JSON + Markdown) for all modules |
| `refresh_cve_extended_catalog.py` | Fetch and update CVE extended catalog from NVD/MITRE feeds |
| `validate_market_priority_minimums.py` | Assert that high-priority device models have at least one module |
| `build_arsenal_index.py` | Build arsenal index JSON from module metadata |
| `sync_scope_wordlists.py` | Synchronize scope-related wordlists with device catalog |
| `audit_modules.py` | Audit module metadata completeness — reports missing `__info__` fields |
| `run_scoped_tests.py` | Run test suite scoped to specific module categories |
| `validate_governance.py` | Governance validator — checks license headers, author fields, docstrings |
| `validate_arsenal_architecture.py` | Assert that arsenal layout matches actual module file tree |
| `build_osi_tcpip_attack_matrix.py` | Generate OSI/TCP-IP attack surface matrix |
| `deep_intel_backlog.py` | Report modules in the deep intelligence research backlog |
| `sync_mibs.py` | Sync SNMP MIB files from vendor sources to `resources/mibs/` |

Run all scripts from the **repository root** unless the tool documents otherwise.

---

## Quality Gate (`phase_gate.py`)

### Full gate sequence

```bash
# Run all 7 gates in sequence (recommended for CI/CD)
python tools/phase_gate.py --all
```

### Individual gates

```bash
python tools/phase_gate.py --phase A1A2    # Import + __info__ validation
python tools/phase_gate.py --phase B       # check() and run() body validation
python tools/phase_gate.py --phase C       # Anti-false-positive on port 63994
python tools/phase_gate.py --phase A3      # Prohibited string check
python tools/phase_gate.py --phase D       # flake8 linting gate
python tools/phase_gate.py --phase E       # bandit security gate
python tools/phase_gate.py --phase final   # index_modules() full indexing check
```

### Sample `--all` output

```
$ python tools/phase_gate.py --all

EmbedXPL-Forge Phase Gate v3.1.0
=================================

[A1/A2] Import and __info__ Validation
---------------------------------------
  Checking 143 modules...
  [OK]  exploits/routers/tplink/wr841n_credential_disclosure_cve_2023_50224
  [OK]  exploits/routers/cisco/rv320_command_injection
  [OK]  exploits/firewalls/fortinet/fortios_auth_bypass_cve_2022_40684
  ...
  [OK]  143/143 modules import cleanly
  [OK]  143/143 modules have complete __info__ (name, description, authors, references, devices, cvss)

[B]    check() and run() Body Validation
-----------------------------------------
  [OK]  143/143 modules have non-stub check() bodies
  [OK]  143/143 modules have non-stub run() bodies

[C]    Anti-False-Positive Gate (port 63994)
---------------------------------------------
  [OK]  143/143 modules return False / None against closed port 63994

[A3]   Prohibited String Check
--------------------------------
  Checking for: em-dash, TODO, PLACEHOLDER, hardcoded IPs (192.168.x.x, 10.x.x.x)...
  [OK]  No prohibited strings found

[D]    flake8 Linting Gate
----------------------------
  [OK]  flake8 passed — 0 violations

[E]    bandit Security Gate
-----------------------------
  [OK]  bandit passed — 0 high-severity findings
  [INFO] 3 low-severity findings (eval, subprocess) — permitted by policy

[FINAL] index_modules() Full Indexing
---------------------------------------
  [OK]  index_modules() returned 143 modules
  [OK]  All modules appear in global index

=================================
GATE RESULT: PASS (7/7 gates)
Time: 12.4 s
=================================
```

### Gate failure example (A1/A2)

```
[A1/A2] Import and __info__ Validation
  [FAIL] exploits/routers/acme/new_module — ImportError: cannot import name 'OptString'
  [FAIL] exploits/cameras/brand/cve_test — __info__ missing required fields: ['cvss', 'references']

GATE RESULT: FAIL (0/7 gates — stopped at A1/A2)
Fix the 2 error(s) above and re-run.
```

---

## Environment Doctor (`env_doctor.py`)

```bash
python tools/env_doctor.py
```

**Sample output:**

```
EmbedXPL-Forge — Environment Doctor
=====================================
Python          3.12.3          [OK]
pip             24.0            [OK]
requests        2.31.0          [OK]
paramiko        3.4.0           [OK]
yaml            6.0.1           [OK]
rich            13.7.0          [OK]
pysnmp          6.1.1           [OK]
telnetlib3      2.0.1           [OK]   (required for Python 3.13+)
impacket        0.11.0          [OK]
pymodbus        3.7.0           [OK]
torch           2.2.1+cu121     [OK]   (optional — GPU compute)
tensorflow      MISSING         [WARN] (optional — install with pip install tensorflow)
binwalk         MISSING         [WARN] (optional — firmware analysis; install with apt-get install binwalk)
nmap            7.95            [OK]   (required for NSE scripts)

GPU / Compute
  CUDA available  : True  (driver 555.85, CUDA 12.1)
  torch backend   : cuda
  Visible devices : NVIDIA GeForce RTX 4070 (8192 MB)

Summary: 13/14 required deps OK | 1 optional missing | 0 errors
```

---

## Compatibility Smoke Check (`compat_smoke.py`)

```bash
python tools/compat_smoke.py
```

**Sample output:**

```
EmbedXPL-Forge — Compatibility Smoke
=======================================
[OK] embedxpl.interpreter imports cleanly
[OK] embedxpl.core.exploit.exploit imports cleanly
[OK] embedxpl.core.hw_profiler imports cleanly
[OK] embedxpl.core.session imports cleanly
[OK] embedxpl.core.apt_catalog imports cleanly
[OK] embedxpl.core.orchestrator imports cleanly
[OK] embedxpl.nse.manager imports cleanly
[OK] embedxpl.tools.firmware_downloader imports cleanly
[OK] embedxpl.tools.firmware_analyzer imports cleanly
[OK] 9/9 critical imports passed

Module scan:
[OK] 143 modules indexed by index_modules()

Smoke result: PASS
```

---

## Audit Modules (`audit_modules.py`)

```bash
python tools/audit_modules.py
```

**Sample output (all fields present):**

```
EmbedXPL-Forge Module Audit
============================
Scanning 143 modules...

Field coverage:
  name          143/143 (100%)
  description   143/143 (100%)
  authors       143/143 (100%)
  references    143/143 (100%)
  devices       143/143 (100%)
  cvss          141/143 (98.6%)  -- 2 missing
  cwe           128/143 (89.5%)  -- 15 missing
  date          143/143 (100%)

Modules missing 'cvss':
  exploits/generic/snmp/snmp_bruteforce
  generic/dns_hijack_detector

Audit complete: 2 warnings
```

---

## Wiki Module Index (`gen_wiki_module_index.py`)

Regenerates the module index annex from live module metadata. Run after adding new modules:

```bash
python tools/gen_wiki_module_index.py
```

Output is written to `docs/wiki/en-US/ANNEX-module-index.md` and `docs/wiki/pt-BR/ANNEX-module-index.md`.

---

## Full Catalog Generator (`generate_full_catalog.py`)

Generates `docs/catalog.json` and `docs/catalog.md` from all module `__info__` metadata:

```bash
python tools/generate_full_catalog.py
# Output:
#   docs/catalog.json    -- machine-readable full catalog
#   docs/catalog.md      -- human-readable Markdown table
#   docs/catalog.html    -- HTML rendering
```

**Sample `catalog.json` entry:**

```json
{
  "path": "exploits/firewalls/fortinet/fortios_auth_bypass_cve_2022_40684",
  "name": "FortiOS Authentication Bypass (CVE-2022-40684)",
  "description": "HTTP/HTTPS authentication bypass on FortiOS management interface allowing full admin access.",
  "authors": ["@mrhenrike"],
  "cvss": 9.8,
  "cves": ["CVE-2022-40684"],
  "mitre": ["T1190"],
  "devices": ["FortiGate", "FortiProxy", "FortiSwitch Manager"],
  "references": [
    "https://www.fortiguard.com/psirt/FG-IR-22-377"
  ]
}
```
