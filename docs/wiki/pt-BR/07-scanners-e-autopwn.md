# Scanners e AutoPwn

**Idioma:** Português (pt-BR). **English:** [../en-US/07-scanners-and-autopwn.md](../en-US/07-scanners-and-autopwn.md)

---

## AutoPwn

O **AutoPwn** orquestra fluxos de trabalho de fingerprinting e seleção de módulos. Carregue o módulo AutoPwn com `use`, defina `target` (e opções de interface se necessário), depois execute `run` — o comportamento é definido dentro da implementação `run()` do módulo.

```text
exf > use scanners/autopwn
exf (AutoPwn) > set target 192.168.1.0/24
exf (AutoPwn) > run
[*] Discovery phase: scanning 254 hosts
[+] Discovered: 192.168.1.1 (Huawei EG8145X6)
[*] Testing 9 modules for this target...
[+] VULNERABLE: eg8145x6_csrf_static_token (CVSS 9.1)
[+] VULNERABLE: eg8145x6_info_disclosure (pre-auth)
```

---

## Scanners orientados a dispositivos

| Módulo | Função |
|--------|--------|
| `router_scan` | Descoberta focada em roteadores / ponto de entrada para encadeamento |
| `hootoo_scan` | Fluxo de scanner orientado a Hootoo |
| `soho_discover` | Descoberta HTTP universal SOHO (reconhece 12+ assinaturas de vendor) |
| `scanners/printers/hp_rawprint_9100` | Scanner HP PJL via porta 9100 |
| `scanners/protocols/iot/upnp_ssdp_scan` | Enumeração de dispositivos UPnP/SSDP |
| `scanners/embedded_os/mdns_iot_discovery` | Descoberta de dispositivos IoT via mDNS/Bonjour |
| `scanners/threat_detection/mirai_default_creds_sweep` | Varredura de credenciais padrão do botnet Mirai |
| `scanners/threat_detection/gpon_exploitation_scan` | Scanner de vulnerabilidades GPON |

### Scanners específicos de impressoras (novo na v3.1.0)

Use `exploits/printers/generic/wsd_printer_enum` para descoberta de impressoras WSD/mDNS:

```text
exf > use exploits/printers/generic/wsd_printer_enum
exf (WSD Printer Enum) > set target 239.255.255.250
exf (WSD Printer Enum) > set timeout 8
exf (WSD Printer Enum) > run
[*] WSD probe on 239.255.255.250:3702 (8s)
[+] Discovered 3 WSD device(s):
IP              Endpoint            Types              XAddrs
192.168.1.100   urn:uuid:abc123...  wsdl:Service       http://192.168.1.100:80/
192.168.1.101   urn:uuid:def456...  d:Device           http://192.168.1.101:631/
192.168.1.102   urn:uuid:ghi789...  d:Device           http://192.168.1.102:80/
```

---

## Lookup de Vendor OUI

O comando `discover` resolve endereços MAC para vendors usando:

1. Cache de sessão (instantâneo)
2. APIs online (`macvendors.com`, `maclookup.app`)
3. Banco de dados IEEE local (`embedxpl/data/oui.txt` - 39.000+ entradas)

```text
exf > discover 192.168.1.0/24
[*] OUI lookup: 38:6b:1c -> SHENZHEN MERCURY COMMUNICATION (Mercusys/TP-Link)
[*] OUI lookup: cc:29:bd -> ZTE CORPORATION
[*] OUI lookup: 3c:a3:7e -> HUAWEI TECHNOLOGIES CO.,LTD
[+] Suggested modules for 192.168.1.1:
    - exploits/routers/zte/zxhn_h168n_rce_auth_bypass
    - creds/routers/zte/ftp_default_creds
```

---

## Opções típicas

| Opção | Função |
|-------|--------|
| `target` | Host ou rede sob teste |
| `port` | Porta de serviço quando não implícita |
| `threads` | Concorrência para fases intensas em rede |
| `timeout` | Timeout por sonda em segundos |

Sempre confirme o escopo e os limites de taxa antes de executar scanners em redes ativas.

---

## Ferramenta Phase Gate (novo na v3.1.0)

`tools/phase_gate.py` é o sistema automatizado de controle de qualidade usado internamente para validar todos os módulos:

```bash
# Listar gates disponíveis
python tools/phase_gate.py --list

# Validar track específico
python tools/phase_gate.py --phase A1A2   # portas EDB/MSF de impressoras
python tools/phase_gate.py --phase B      # lote primário CVE 2026
python tools/phase_gate.py --phase C      # CVE 2026 estendido
python tools/phase_gate.py --phase A3     # módulos de pesquisa de impressoras
python tools/phase_gate.py --phase D      # backlog CVEs 2025/2024

# Executar todos os gates (suite completa de validação)
python tools/phase_gate.py --all
```

Saída esperada (aprovado):

```text
============================================================
  GATE B
============================================================
  [ PASS ] import:gnu_inetutils_telnetd_auth_bypass
  [ PASS ] import:cups_pwn2own_chain_cve_2026_34480
  [ PASS ] cvss_present
  [ PASS ] cups_chain_stages    (3 .run() calls confirmed)
  [ PASS ] indexed              (All 11 modules indexed)
  [ PASS ] total_module_count   (2760 modules indexed)

Results: 27/27 passed  (all passed)
Gate B PASSED.
```

---

[Hub da Wiki](../README.md)
