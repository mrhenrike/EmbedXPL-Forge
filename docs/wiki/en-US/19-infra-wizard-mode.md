# Infrastructure Wizard Mode

**Language:** English (en-US) | **pt-BR:** [../pt-BR/19-infra-wizard-mode.md](../pt-BR/19-infra-wizard-mode.md)

---

## Overview

EmbedXPL-Forge includes an **Infrastructure Orchestrator** that resolves module sets and generates scan plans based on the infrastructure type (`--infra`) and operational context (`--context`). This is the recommended entry point for OT/ICS/IT network assessments.

There are two modes:

| Mode | Invocation | Behavior |
|------|-----------|----------|
| **Direct** | `exf --infra ot --context ics --target 10.0.0.0/24` | Resolves and prints the module plan for the given infra/context/target combination |
| **Wizard** | `exf --infra wizard` | Interactive step-by-step menu: prompts for infra type, context, and target, then prints the plan |

Neither mode automatically runs exploit modules — the plan is presented for review, and the user selects modules interactively afterward.

---

## Command-line flags

| Flag | Type | Required | Default | Accepted values | Description |
|------|------|----------|---------|-----------------|-------------|
| `--infra` | string | Yes | — | `ot`, `it`, `iot`, `wizard` | Infrastructure taxonomy type, or `wizard` for interactive mode |
| `--context` | string | Conditional | `""` | `ics`, `scada`, `plc`, `hmi`, `dcs`, `bms`, `smart_grid`, `oil_gas`, `manufacturing`, `datacenter`, `enterprise`, `campus`, `cloud`, `soho` | Operational context within the infra type |
| `--target` | string | No | `127.0.0.1` | IPv4 / CIDR | Target IP or network range for the scan plan |

If `--context` is omitted, the orchestrator lists available contexts for the given `--infra` type.

---

## Infra types and contexts

| `--infra` | Available `--context` values | Description |
|-----------|------------------------------|-------------|
| `ot` | `ics`, `scada`, `plc`, `hmi`, `dcs`, `bms`, `smart_grid`, `oil_gas`, `manufacturing` | Operational Technology — industrial networks |
| `it` | `datacenter`, `enterprise`, `campus`, `cloud` | Traditional IT infrastructure |
| `iot` | `soho`, `smart_home`, `industrial_iot`, `medical_iot`, `retail_iot` | Internet of Things networks |

---

## Direct mode — `--infra ot --context ics`

### List available contexts

```text
$ exf --infra ot

[*] Available contexts for --infra ot:
  ics
  scada
  plc
  hmi
  dcs
  bms
  smart_grid
  oil_gas
  manufacturing
```

### Build scan plan with target

```text
$ exf --infra ot --context ics --target 10.0.50.0/24

[*] Infrastructure scan plan — OT / ICS
    Target: 10.0.50.0/24
    Infra:  ot
    Context: ics

[*] Module plan (22 modules selected):

    Protocol discovery:
      scanners/ics/modbus_scanner         (Modbus TCP, port 502)
      scanners/ics/enip_scanner           (EtherNet/IP, port 44818)
      scanners/ics/cip_scanner            (Common Industrial Protocol)
      scanners/ics/dnp3_scanner           (DNP3, port 20000)
      scanners/ics/profinet_dcp_scanner   (PROFINET DCP, multicast)
      scanners/embedded_os/mqtt_broker_scan  (MQTT, port 1883)

    ICS exploit modules:
      exploits/ics/siemens/s7_1200_plc_control      (S7comm, port 102)
      exploits/ics/siemens/s7_300_400_plc_control   (S7comm, port 102)
      exploits/ics/siemens/profinet_set_ip           (PROFINET DCP)
      exploits/ics/rockwell/compactlogix_auth_bypass_cve_2021_22681  (CIP)
      exploits/ics/rockwell/compactlogix_cip_dos_cve_2024_6077
      exploits/ics/rockwell/compactlogix_code_injection_cve_2022_1161
      exploits/ics/schneider/modicon_modbus_control_cve_2018_7841
      exploits/ics/schneider/quantum_plc_control
      exploits/ics/modbus/buspwn_modbus_scanner_dos
      exploits/ics/modbus/dos_write_coils
      exploits/ics/modbus/dos_write_registers
      exploits/ics/modbus/read_holding_registers
      exploits/ics/modbus/write_single_coil

    ICS credential modules:
      creds/ics/siemens/ssh_default_creds
      creds/ics/siemens/webinterface_http_auth_default_creds
      creds/ics/rockwell/ssh_default_creds

[*] Use -m <module> -s "target 10.0.50.0/24" to run individual modules.
[*] Or launch interactive shell and type 'use <module>' to explore.
```

### Scan plan — IT datacenter

```text
$ exf --infra it --context datacenter --target 172.16.0.0/16

[*] Infrastructure scan plan — IT / Datacenter
    Target: 172.16.0.0/16
    Infra:  it
    Context: datacenter

[*] Module plan (31 modules selected):

    Discovery:
      scanners/bmc/bmc_discover           (IPMI, port 623)
      scanners/hypervisors/proxmox_discover (Proxmox VE, port 8006)
      scanners/embedded_os/embedded_os_fingerprint

    Exploit modules:
      exploits/bmc/supermicro/ipmi_auth_bypass_cve_2013_4786
      exploits/bmc/dell/idrac9_info_disclosure_cve_2021_36300
      exploits/bmc/asus/asmb8_default_creds_ipmi
      exploits/firewalls/cisco/ios_xe_webui_privesc_cve_2023_20198
      exploits/firewalls/cisco/cisco_fmc_auth_bypass_rce_cve_2026_20079
      exploits/appliances/f5/bigip_icontrol_rest_rce_cve_2022_1388
      exploits/appliances/citrix/netscaler_rce_cve_2023_3519
      ... (24 more)
```

### Scan plan — IoT SOHO

```text
$ exf --infra iot --context soho --target 192.168.1.0/24

[*] Infrastructure scan plan — IoT / SOHO
    Target: 192.168.1.0/24
    Infra:  iot
    Context: soho

[*] Module plan (47 modules selected):

    Discovery:
      scanners/cameras/rtsp_discover
      scanners/cameras/camera_scan
      scanners/embedded_os/mdns_iot_discovery
      scanners/protocols/iot/upnp_ssdp_scan
      generic/upnp/ssdp_msearch
      scanners/threat_detection/mirai_default_creds_sweep

    Exploit modules:
      exploits/cameras/hikvision/rtsp_rce_cve_2021_36260
      exploits/cameras/hikvision/info_disclosure_cve_2017_7921
      exploits/cameras/dahua/cctv_rce_cve_2021_36260
      exploits/cameras/dahua/auth_bypass_cve_2021_33044
      exploits/routers/tplink/*
      exploits/routers/netgear/*
      exploits/routers/asus/*
      generic/upnp/igd_exploit
      generic/snmp/snmp_bruteforce
      ... (39 more)
```

---

## Wizard mode — `--infra wizard`

The wizard presents a numbered interactive menu for infra type and context selection, then prints the resolved module plan.

### Full wizard terminal session

```text
$ exf --infra wizard

=================================================================
  EmbedXPL-Forge — Infrastructure Orchestrator Wizard
=================================================================

Select infrastructure type:
  [1] ot   — Operational Technology (ICS/SCADA/PLC networks)
  [2] it   — Information Technology (datacenter, enterprise)
  [3] iot  — Internet of Things (SOHO, smart home, industrial IoT)

Enter selection [1-3]: 1

Select operational context for OT:
  [1] ics            — Industrial Control Systems (generic)
  [2] scada          — Supervisory Control and Data Acquisition
  [3] plc            — PLC-focused environment
  [4] hmi            — Human Machine Interfaces
  [5] dcs            — Distributed Control Systems
  [6] bms            — Building Management Systems
  [7] smart_grid     — Smart Grid / Energy infrastructure
  [8] oil_gas        — Oil & Gas (refineries, pipelines)
  [9] manufacturing  — Manufacturing / factory floor

Enter selection [1-9]: 2

Enter target IP or CIDR (e.g. 10.0.0.1 or 10.0.50.0/24): 10.0.100.0/24

[*] Building scan plan for OT/SCADA, target: 10.0.100.0/24...

[*] Infrastructure scan plan — OT / SCADA
    Target: 10.0.100.0/24
    Infra:  ot
    Context: scada

[*] Module plan (26 modules selected):

    SCADA protocol discovery:
      scanners/ics/modbus_scanner
      scanners/ics/dnp3_scanner
      scanners/ics/enip_scanner

    SCADA exploit modules:
      exploits/ics/scada/fuxa_scheduler_rce_cve_2026_25939
      exploits/ics/scada/laquis_arb_file_write_cve_2021_41579
      exploits/ics/scadaflex/sc168_file_write_cve_2022_25359
      exploits/ics/schneider/modicon_modbus_control_cve_2018_7841
      exploits/ics/schneider/net55xx_encoder_rce_cve_2018_7784
      exploits/ics/schneider/quantum_plc_control
      exploits/ics/rockwell/compactlogix_auth_bypass_cve_2021_22681
      exploits/ics/siemens/siprotec_relay_dos_cve_2015_5374
      exploits/ics/siemens/s7_1200_plc_control
      exploits/ics/osprey/pump_controller_auth_bypass_cve_2023_28648
      exploits/ics/vxworks/vxworks_rpc_dos
      exploits/ics/qnx/qconn_remote_exec
      ... (14 more)

    SCADA credential modules:
      creds/ics/schneider/*
      creds/ics/siemens/*
      creds/ics/rockwell/*

[*] Scan plan ready: 26 modules for ot/scada
[*] Use -m <module> -s "target 10.0.100.0/24" to run individual modules.
[*] Or launch interactive shell and type 'use <module>' to explore.
```

### Wizard cancelled

```text
$ exf --infra wizard
...
Enter selection [1-3]: ^C

[!] Wizard cancelled by user.
```

---

## Error cases

### Unknown infra type

```text
$ exf --infra cloud

[!] Unknown infra type 'cloud'. Valid: ot, it, iot
```

### No context specified

```text
$ exf --infra ot

[*] Available contexts for --infra ot:
  ics
  scada
  plc
  hmi
  dcs
  bms
  smart_grid
  oil_gas
  manufacturing
```

### Invalid context for infra type

```text
$ exf --infra ot --context datacenter

[!] Unknown context 'datacenter' for infra 'ot'. Valid contexts: ics, scada, plc, hmi, dcs, bms, smart_grid, oil_gas, manufacturing
```

### InfraOrchestrator unavailable

```text
$ exf --infra ot --context ics

[!] InfraOrchestrator unavailable: No module named 'embedxpl.core.orchestrator'
[*] Verify installation: pip install -e .[full]
```

---

## Workflow: wizard to interactive shell

After reviewing the scan plan, launch the interactive shell and run modules individually:

```text
# Step 1: Review plan
$ exf --infra ot --context ics --target 10.0.50.0/24
[*] Module plan (22 modules selected)...

# Step 2: Start interactive shell
$ exf

# Step 3: Run selected module from plan
exf > use scanners/ics/modbus_scanner
exf (Modbus Scanner) > set target 10.0.50.0/24
[+] target => 10.0.50.0/24
exf (Modbus Scanner) > run
[*] Scanning 254 hosts on Modbus TCP port 502...
[+] 10.0.50.10  — Modbus device responding (Schneider Modicon M340)
[+] 10.0.50.11  — Modbus device responding (Siemens S7-1200)

exf > use exploits/ics/siemens/s7_1200_plc_control
exf (Siemens S7-1200 PLC Control) > set target 10.0.50.11
[+] target => 10.0.50.11
exf (Siemens S7-1200 PLC Control) > run
```

---

## Notes

- **No auto-exploitation**: The wizard and `--infra/--context` flags are read-only planning tools. They do not automatically run exploit modules.
- **Module ordering**: Modules within a plan are ordered by severity (critical first) and discovery phase first, exploits second.
- **CIDR targets**: When a CIDR range is provided as `--target`, the plan uses it for all scanner modules. Individual exploit modules require a single IP — use `discover` or scanner output to enumerate specific targets first.

> See also: [20-ics-ot-modules.md](20-ics-ot-modules.md) for full ICS/OT exploit module reference.

[Wiki hub](../README.md)
