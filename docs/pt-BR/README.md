# EmbedXPL-Forge

**Framework de Exploit Embarcado para Avaliacao de Seguranca IoT/OT**

EmbedXPL-Forge e um framework extensivel de exploits e scanning
desenvolvido especificamente para sistemas embarcados, dispositivos IoT,
infraestrutura OT/ICS e equipamentos de rede SOHO. Oferece uma arquitetura
modular para pesquisa de vulnerabilidades, testes de penetracao e operacoes
de red team abrangendo dezenas de categorias de dispositivos e protocolos
de comunicacao.

## Principais Recursos

- 35+ categorias de dispositivos: roteadores, cameras, PLCs, smart home,
  BMC/IPMI, NAS, impressoras, VoIP, UPS, wearables, appliances VPN e mais.
- Cobertura de protocolos: HTTP/S, SSH, Telnet, FTP, SNMP, RTSP, Modbus,
  S7comm, CIP, MQTT, CoAP, UPnP, CAN bus, BLE, 802.15.4, sub-GHz RF.
- Orquestrador de exploits multi-linguagem (Python, C, C++, Rust, ASM) com
  suporte a compilacao cruzada para ARM, MIPS, x86 e x64.
- Engine de scan assincrono para execucao concorrente de modulos em escala.
- SmartPool com selecao adaptativa de threads/processos.
- Sistema de hardware gate com guias de compra e referencias de drivers.
- Shell engines: raw TCP/UDP, ICMP covert, DNS tunnel, HTTP poll,
  MQTT shell, Meterpreter bridge.
- Fingerprinting de banners assistido por ML e classificacao de respostas.
- Backends de cracking com aceleracao GPU (CUDA, OpenCL, ROCm).

## Inicio Rapido

### Instalacao

```bash
git clone <repository-url> EmbedXPL-Forge
cd EmbedXPL-Forge
pip install -e .
```

### Shell Interativo

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

### Modo Nao-Interativo

```bash
python -m embedxpl -m exploits/routers/dlink/dsl_2750b_rce \
    --target 10.0.0.1 --port 80 --run
```

### Gerar Documentacao de Modulos

```bash
python -m embedxpl.tools.docgen --lang en-US --output docs/en-US/
python -m embedxpl.tools.docgen --stats
```

## Estrutura da Documentacao

| Caminho | Conteudo |
|---------|----------|
| [architecture.md](./architecture.md) | Internos do framework e hierarquia de classes |
| [hardware-requirements.md](./hardware-requirements.md) | Catalogo de adaptadores fisicos |
| [modules/](./modules/) | Documentacao por modulo (gerada automaticamente) |
| [protocols/](./protocols/) | Guias especificos por protocolo |
| [attack-chains/](./attack-chains/) | Playbooks de ataques multi-estagio |

## Categorias de Modulos

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

### Modulos de Credenciais

BMC, cameras, firewalls, generic, hypervisors, ICS, IoT, ISP CPEs,
NAS, printers, routers, smart meters, smart TV, SOHO edge, switches,
taps, UPS, VoIP.

## Protocolos

HTTP/S, SSH, Telnet, FTP/SFTP, SNMP v1/v2c/v3, RTSP, Modbus TCP,
Siemens S7/S7+, EtherNet/IP (CIP), WDB/VxWorks, MQTT, CoAP, UPnP/SSDP,
IPMI, RouterOS API, CAN 2.0/FD, BLE GATT, IEEE 802.15.4/Thread,
sub-GHz ISM (315/433/868/915 MHz), UART serial.

## Licenca

Proprietario. Uso interno apenas. Distribuicao nao autorizada proibida.

---

Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
