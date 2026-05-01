# EmbedXPL-Forge

**Embedded Exploit Framework for IoT/OT Security Assessment**

EmbedXPL-Forge is an extensible exploitation and scanning framework
purpose-built for embedded systems, IoT devices, OT/ICS infrastructure,
and SOHO network equipment. It provides a modular architecture for
vulnerability research, penetration testing, and red-team operations
across dozens of device categories and communication protocols.

## Key Features

- 35+ device categories: routers, cameras, PLCs, smart home, BMC/IPMI,
  NAS, printers, VoIP, UPS, wearables, VPN appliances, and more.
- Protocol coverage: HTTP/S, SSH, Telnet, FTP, SNMP, RTSP, Modbus,
  S7comm, CIP, MQTT, CoAP, UPnP, CAN bus, BLE, 802.15.4, sub-GHz RF.
- Multi-language exploit orchestrator (Python, C, C++, Rust, ASM) with
  cross-compilation support for ARM, MIPS, x86, and x64.
- Async scan engine for concurrent module execution at scale.
- SmartPool with adaptive thread/process selection.
- Hardware gate system with purchasing guides and driver references.
- Shell engines: raw TCP/UDP, ICMP covert, DNS tunnel, HTTP poll,
  MQTT shell, Meterpreter bridge.
- ML-assisted banner fingerprinting and response classification.
- GPU-accelerated cracking backends (CUDA, OpenCL, ROCm).

## Quick Start

### Installation

```bash
git clone <repository-url> EmbedXPL-Forge
cd EmbedXPL-Forge
pip install -e .
```

### Interactive Shell

```bash
python -m embedxpl
```

```
exf > search cameras
exf > use exploits/cameras/hikvision/hikvision_backdoor_cve_2017_7921
exf > show options
exf > set target 192.168.1.100
exf > run
```

### Non-Interactive Mode

```bash
python -m embedxpl -m exploits/routers/dlink/dsl_2750b_rce \
    --target 10.0.0.1 --port 80 --run
```

### Generate Module Documentation

```bash
python -m embedxpl.tools.docgen --lang en-US --output docs/en-US/
python -m embedxpl.tools.docgen --stats
```

## Documentation Structure

| Path | Content |
|------|---------|
| [architecture.md](./architecture.md) | Framework internals and class hierarchy |
| [hardware-requirements.md](./hardware-requirements.md) | Physical adapter catalog |
| [modules/](./modules/) | Per-module documentation (auto-generated) |
| [protocols/](./protocols/) | Protocol-specific guides |
| [attack-chains/](./attack-chains/) | Multi-stage attack playbooks |

## Module Categories

### Exploits

appliances, aps, bmc, bms, cameras, cisco, embedded_os, firewalls,
firmware, generic, hypervisors, ics, ispcpes, lateral, misc, nas,
network_os, ngfw, ot_iiot, printers, protocols, routers, sdwan,
servers, smart_home, smart_meters, smart_tv, soho_edge, specialized,
switches, taps, ups, voip, vpn, wearables.

### Scanners

aruba, bmc, bms, cameras, embedded_os, firewalls, hypervisors, ics,
misc, nas, network_os, ot_iiot, printers, protocols, routers,
smart_home, smart_meters, smart_tv, soho_edge, specialized, switches,
taps, threat_detection, ups, voip, vpn, wearables.

### Credential Modules

BMC, cameras, firewalls, generic, hypervisors, ICS, IoT, ISP CPEs,
NAS, printers, routers, smart meters, smart TV, SOHO edge, switches,
taps, UPS, VoIP.

## Protocols

HTTP/S, SSH, Telnet, FTP/SFTP, SNMP v1/v2c/v3, RTSP, Modbus TCP,
Siemens S7/S7+, EtherNet/IP (CIP), WDB/VxWorks, MQTT, CoAP, UPnP/SSDP,
IPMI, RouterOS API, CAN 2.0/FD, BLE GATT, IEEE 802.15.4/Thread,
sub-GHz ISM (315/433/868/915 MHz), UART serial.

## License

Proprietary. Internal use only. Unauthorized distribution prohibited.

---

Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
