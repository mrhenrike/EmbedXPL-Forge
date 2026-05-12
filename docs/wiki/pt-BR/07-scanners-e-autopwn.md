# Scanners e AutoPwn

**Idioma: Portugues (pt-BR)**. **en-US:** [../en-US/07-scanners-and-autopwn.md](../en-US/07-scanners-and-autopwn.md)

## AutoPwn

**AutoPwn** orquestra fluxos de fingerprint e escolha de modulos. Carregue o modulo AutoPwn com `use`, defina `target` (e opcoes de interface se necessario) e `run` - o comportamento esta no `run()` do modulo.

```text
exf > use scanners/autopwn
exf (AutoPwn) > set target 192.168.1.0/24
exf (AutoPwn) > run
[*] Fase de discovery: escaneando 254 hosts
[+] Descoberto: 192.168.1.1 (Huawei EG8145X6)
[*] Testando 9 modulos para este alvo...
[+] VULNERAVEL: eg8145x6_csrf_static_token (CVSS 9.1)
[+] VULNERAVEL: eg8145x6_info_disclosure (pre-auth)
```

## Scanners orientados a device

| Modulo | Funcao |
|--------|--------|
| `router_scan` | Ponto de entrada de discovery / encadeamento focado em router |
| `hootoo_scan` | Fluxo scanner para Hootoo |
| `soho_discover` | Discovery HTTP universal SOHO (identifica 12+ assinaturas de vendor) |
| `scanners/printers/hp_rawprint_9100` | Scanner HP PJL via porta 9100 |
| `scanners/protocols/iot/upnp_ssdp_scan` | Enumeracao de dispositivos UPnP/SSDP |
| `scanners/embedded_os/mdns_iot_discovery` | Discovery de dispositivos IoT via mDNS/Bonjour |
| `scanners/threat_detection/mirai_default_creds_sweep` | Varredura de credenciais padrao de botnet Mirai |
| `scanners/threat_detection/gpon_exploitation_scan` | Scanner de vulnerabilidades GPON |

### Scanners de impressoras (novo em v3.1.0)

Use `exploits/printers/generic/wsd_printer_enum` para descoberta WSD/mDNS de impressoras:

```text
exf > use exploits/printers/generic/wsd_printer_enum
exf (WSD Printer Enum) > set target 239.255.255.250
exf (WSD Printer Enum) > set timeout 8
exf (WSD Printer Enum) > run
[*] WSD probe em 239.255.255.250:3702 (8s)
[+] Descobertos 3 dispositivos WSD:
IP              Endpoint            Types              XAddrs
192.168.1.100   urn:uuid:abc123...  wsdl:Service       http://192.168.1.100:80/
192.168.1.101   urn:uuid:def456...  d:Device           http://192.168.1.101:631/
192.168.1.102   urn:uuid:ghi789...  d:Device           http://192.168.1.102:80/
```

## Lookup OUI de Vendor

O comando `discover` resolve enderecos MAC em vendors usando:

1. Cache de sessao (instantaneo)
2. APIs online (`macvendors.com`, `maclookup.app`)
3. Banco de dados IEEE local (`embedxpl/data/oui.txt` - 39.000+ entradas)

```text
exf > discover 192.168.1.0/24
[*] OUI lookup: 38:6b:1c -> SHENZHEN MERCURY COMMUNICATION (Mercusys/TP-Link)
[*] OUI lookup: cc:29:bd -> ZTE CORPORATION
[*] OUI lookup: 3c:a3:7e -> HUAWEI TECHNOLOGIES CO.,LTD
[+] Modulos sugeridos para 192.168.1.1:
    - exploits/routers/zte/zxhn_h168n_rce_auth_bypass
    - creds/routers/zte/ftp_default_creds
```

## Opcoes tipicas

| Opcao | Funcao |
|-------|--------|
| `target` | Host ou rede sob teste |
| `port` | Porta de servico quando nao implicita |
| `threads` | Concorrencia para fases pesadas em rede |
| `timeout` | Timeout por sonda em segundos |

Confirme escopo e limites de taxa antes de rodar scanners em redes em producao.

## Ferramenta Phase Gate (novo em v3.1.0)

`tools/phase_gate.py` e o sistema de gates de qualidade automatizados usado internamente para validar todos os modulos:

```bash
# Listar gates disponiveis
python tools/phase_gate.py --list

# Executar todos os gates
python tools/phase_gate.py --all
```

Saida esperada (aprovado):

```text
============================================================
  GATE B
============================================================
  [ PASS ] import:gnu_inetutils_telnetd_auth_bypass
  [ PASS ] import:cups_pwn2own_chain_cve_2026_34480
  [ PASS ] cvss_present
  [ PASS ] cups_chain_stages    (3 .run() calls confirmados)
  [ PASS ] indexed              (Todos os 11 modulos indexados)
  [ PASS ] total_module_count   (2760 modulos indexados)

Results: 27/27 passed  (all passed)
Gate B PASSED.
```


[Hub wiki](../README.md)
