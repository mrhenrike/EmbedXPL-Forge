# Infrastructure Wizard Mode (`--infra`, `--context`, `--target`, `--wizard`)

**Language:** English (en-US) | **pt-BR:** [../pt-BR/19-infra-wizard-mode.md](../pt-BR/19-infra-wizard-mode.md)

---

## Overview

EmbedXPL-Forge's **infrastructure orchestrator mode** allows users to launch scans using a high-level taxonomy instead of specifying individual modules. The user declares the type of infrastructure (`ot`, `it`, `iot`) and the operational context (`ics`, `enterprise_network`, etc.); EmbedXPL automatically resolves the full set of modules that apply to that environment.

This mode is designed for OT/ICS security professionals and enterprise red teams who want to scope an assessment by environment type rather than by individual CVE.

---

## CLI flags (non-interactive mode)

| Flag | Type | Required | Description |
|------|------|----------|-------------|
| `--infra <type>` | string | yes | Infrastructure type: `ot`, `it`, `iot` |
| `--context <ctx>` | string | no | Operational context within the infra type (see table below) |
| `--target <IP/CIDR>` | string | no | IP address or CIDR range for the scan plan |
| `--wizard` | flag | no | Launch interactive wizard for infra/context selection |

When `--infra wizard` is specified, it activates the interactive wizard (equivalent to `--wizard`).

---

## Infrastructure type and context taxonomy

| `--infra` | `--context` | Label | Module paths resolved |
|-----------|-------------|-------|----------------------|
| `ot` | `ics` | ICS / SCADA | `exploits/ics/`, `scanners/ics/`, `creds/ics/`, `exploits/firewalls/siemens/`, `exploits/firewalls/moxa/`, `exploits/firewalls/hirschmann/`, `exploits/firewalls/schneider/`, `exploits/firewalls/phoenix/` |
| `ot` | `energy` | Energy / Smart Meters | `exploits/smart_meters/`, `scanners/smart_meters/` |
| `ot` | `building` | Building Automation (BACnet/HVAC) | `scanners/ics/`, `creds/ics/`, `exploits/bms/` |
| `it` | `enterprise_network` | Enterprise Network Perimeter | `exploits/firewalls/`, `exploits/switches/`, `exploits/vpn/`, `exploits/appliances/`, `exploits/ngfw/`, `exploits/network_os/`, `scanners/firewalls/`, `creds/firewalls/` |
| `it` | `hypervisor` | Hypervisors / Virtualization | `exploits/hypervisors/`, `creds/hypervisors/`, `scanners/hypervisors/` |
| `it` | `bmc_ipmi` | BMC / IPMI / Out-of-Band Management | `exploits/bmc/`, `scanners/bmc/`, `creds/bmc/` |
| `it` | `ups_power` | UPS / Power Management | `exploits/ups/`, `scanners/ups/`, `creds/ups/` |
| `iot` | `home` | Home / SOHO | `exploits/routers/`, `exploits/soho_edge/` |

---

## `--infra ot --context ics --target <CIDR>`

```bash
python -m embedxpl --infra ot --context ics --target 192.168.100.0/24
```

Output:

```
[*] ScanPlan Summary
  Target  : 192.168.100.0/24
  Infra   : ot
  Context : ics
  Modules : 47
  Priority: scanners/ics/modbus_scanner.py, scanners/ics/s7_scanner.py,
            exploits/ics/modbus/buspwn_modbus_scanner_dos.py,
            exploits/ics/siemens/s7_1200_plc_control.py,
            exploits/firewalls/siemens/profinet_set_ip.py

[*] Use -m <module> -s "target 192.168.100.0/24" to run individual modules.
[*] Or launch interactive shell and type 'use <module>' to explore.
```

---

## `--infra it --context enterprise_network --target <IP>`

```bash
python -m embedxpl --infra it --context enterprise_network --target 10.0.0.1
```

Output:

```
[*] ScanPlan Summary
  Target  : 10.0.0.1
  Infra   : it
  Context : enterprise_network
  Modules : 93
  Priority: scanners/firewalls/version_check.py,
            exploits/firewalls/fortinet/fortios_auth_bypass_cve_2022_40684.py,
            exploits/firewalls/cisco/asa_ftd_path_traversal_cve_2020_3452.py,
            exploits/firewalls/paloalto/panos_auth_bypass_cve_2025_0108.py,
            exploits/firewalls/sonicwall/sonicos_sslvpn_auth_bypass_cve_2024_53704.py

[*] Use -m <module> -s "target 10.0.0.1" to run individual modules.
[*] Or launch interactive shell and type 'use <module>' to explore.
```

---

## `--infra iot --context home --target <CIDR>`

```bash
python -m embedxpl --infra iot --context home --target 192.168.1.0/24
```

Output:

```
[*] ScanPlan Summary
  Target  : 192.168.1.0/24
  Infra   : iot
  Context : home
  Modules : 38
  Priority: scanners/routers/soho_port_scanner.py,
            exploits/routers/tplink/wr841n_credential_disclosure_cve_2023_50224.py,
            exploits/routers/mikrotik/winbox_cred_disclosure_cve_2018_14847.py,
            exploits/routers/cisco/rv320_command_injection.py,
            exploits/routers/asus/rt_n66u_remote_command_execution.py

[*] Use -m <module> -s "target 192.168.1.0/24" to run individual modules.
[*] Or launch interactive shell and type 'use <module>' to explore.
```

---

## `--infra ot` without `--context` (list contexts)

```bash
python -m embedxpl --infra ot
```

Output:

```
[*] Available contexts for --infra ot:
  building
  energy
  ics
```

---

## `--infra` with unknown value

```bash
python -m embedxpl --infra cloud
```

Output:

```
[-] Unknown infra type 'cloud'. Valid: it, iot, ot
```

---

## `--infra ot --context invalid`

```bash
python -m embedxpl --infra ot --context scada
```

Output:

```
[-] Unknown context 'scada' for infra 'ot'. Valid: building, energy, ics
```

---

## `--infra wizard` — interactive wizard

```bash
python -m embedxpl --infra wizard
# or equivalently:
python -m embedxpl --wizard
```

Interactive session:

```
EmbedXPL-Forge Infrastructure Wizard
=====================================

Select infrastructure type:
  1. OT - Operational Technology (ICS/SCADA/IIoT/AT environments)
  2. IT - Information Technology (Enterprise networks, servers, virtualization)
  3. IoT - Internet of Things (Consumer and corporate connected devices)

> 1

Select operational context for OT:
  1. ICS / SCADA          (exploits/ics/, scanners/ics/, exploits/firewalls/siemens/, ...)
  2. Energy / Smart Meters (exploits/smart_meters/, scanners/smart_meters/)
  3. Building Automation   (scanners/ics/, creds/ics/, exploits/bms/)

> 1

Enter target IP or CIDR (leave blank to skip):
> 192.168.100.0/24

[*] Scan plan ready: 47 modules for ot/ics
[*]
ScanPlan Summary
  Target  : 192.168.100.0/24
  Infra   : ot
  Context : ics
  Modules : 47
  Priority: scanners/ics/modbus_scanner.py, scanners/ics/s7_scanner.py, ...
```

---

## Wizard cancelled

```bash
python -m embedxpl --infra wizard
```

```
EmbedXPL-Forge Infrastructure Wizard
=====================================

Select infrastructure type:
  1. OT - Operational Technology
  2. IT - Information Technology
  3. IoT - Internet of Things

> ^C

[WARN] Wizard cancelled by user.
```

---

## `--infra` mode in a non-interactive pipeline

The `--infra` mode is designed for **plan display** — it shows which modules would be run and exits. It does not automatically run exploits. The user then selects and runs individual modules:

```bash
# Step 1 — view the plan
python -m embedxpl --infra it --context enterprise_network --target 10.0.0.1

# Step 2 — launch shell and run specific modules
python -m embedxpl
exf> use exploits/firewalls/fortinet/fortios_auth_bypass_cve_2022_40684
exf (fortios_auth_bypass_cve_2022_40684) > set target 10.0.0.1
exf (fortios_auth_bypass_cve_2022_40684) > check
exf (fortios_auth_bypass_cve_2022_40684) > run
```

Or run a single module non-interactively:

```bash
python -m embedxpl -m exploits/firewalls/fortinet/fortios_auth_bypass_cve_2022_40684 \
    -s "target 10.0.0.1" -s "port 443"
```

---

## Combining `--infra` with `-T` (multi-target file)

Use `discover -T` inside the shell or the `-T` flag in CLI mode to run against multiple targets, then use `--infra` to scope the module set:

```bash
# Generate the scan plan for a group of ICS targets
python -m embedxpl --infra ot --context ics

# Then run the top-priority module against all targets from a file
python -m embedxpl -m scanners/ics/modbus_scanner -T /path/to/ics_targets.txt
```

---

## `PyYAML` not installed (InfraOrchestrator dependency)

```bash
python -m embedxpl --infra ot --context ics --target 192.168.100.0/24
```

```
[-] InfraOrchestrator unavailable: PyYAML is required for InfraOrchestrator: pip install pyyaml
```

Fix:

```bash
pip install pyyaml
```

---

## `infra_profiles.yaml` not found

```
[-] Failed to load infra profiles: infra_profiles.yaml not found at .../embedxpl/resources/infra_profiles.yaml
```

Fix — reinstall package:

```bash
pip install --force-reinstall embedxpl
```
