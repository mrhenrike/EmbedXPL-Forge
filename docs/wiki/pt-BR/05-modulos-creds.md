# Módulos de Credenciais

**Idioma:** Português (pt-BR). **English:** [../en-US/05-creds-modules.md](../en-US/05-creds-modules.md)

---

## Visão geral

Os módulos de credenciais testam interfaces de login **SSH**, **Telnet**, **FTP**, **HTTP Basic/Digest/Form**, **SNMP** e específicas de vendor contra alvos **autorizados**, usando listas de credenciais padrão embutidas ou wordlists personalizadas.

Cada módulo de credenciais herda de uma classe base de protocolo genérico e adiciona pares de credenciais padrão específicos do vendor. Todos os módulos executam ataques de dicionário com concorrência e comportamento configuráveis.

> **Autorização obrigatória.** Use apenas em sistemas que você possui ou para os quais possui permissão escrita explícita para testar.

---

## Estrutura de diretório dos módulos

```
embedxpl/modules/creds/
├── cameras/        Câmeras IP, NVRs, DVRs — 40+ pastas de vendor de câmeras
│   ├── acti/           ftp_default_creds, ssh_default_creds, telnet_default_creds, webinterface_http_form_default_creds
│   ├── axis/           + webinterface_http_auth_default_creds
│   ├── basler/         + webinterface_http_form_default_creds
│   ├── bosch/          + webinterface_http_auth_default_creds
│   ├── dahua/          + webinterface_http_auth_default_creds
│   ├── hikvision/      ftp, ssh, telnet
│   ├── intelbras/      webinterface_default_creds
│   └── ...muitos mais...
│
├── bmc/            Baseboard Management Controllers
│   ├── asus_asmb/
│   ├── dell_idrac/
│   └── supermicro/
│
└── (routers, firewalls, switches, nas, printers — muitas subpastas de vendor)
```

---

## Opções comuns (todos os módulos de credenciais)

| Opção | Tipo | Obrigatório | Padrão | Valores aceitos | Descrição |
|-------|------|-------------|--------|-----------------|-----------|
| `target` | `OptIP` | Sim | `""` | IPv4, IPv6, hostname, `file://caminho` | Host alvo ou arquivo com IPs (um por linha para multi-alvo) |
| `port` | `OptPort` | Não | Padrão do protocolo | 1–65535 | Porta do serviço a testar |
| `threads` | `OptInteger` | Não | `8` | 1–300 | Número de threads de conexão paralelas |
| `defaults` | `OptWordlist` | Não | Específico do vendor | `user:pass`, pares separados por vírgula, ou `file://caminho` | Lista de credenciais a tentar |
| `stop_on_success` | `OptBool` | Não | `True` | `true`, `false` | Parar após a primeira credencial bem-sucedida |
| `verbosity` | `OptBool` | Não | `True` | `true`, `false` | Exibir cada tentativa de credencial na saída |
| `timeout` | `OptInteger` | Não | `10` | 1–120 | Timeout por conexão em segundos |

**Portas padrão por protocolo:**

| Protocolo | Porta padrão |
|-----------|-------------|
| Telnet | 23 |
| SSH | 22 |
| FTP | 21 |
| HTTP Basic/Digest | 80 |
| HTTP Form / HTTPS | 443 |
| SNMP | 161 |

---

## Tipos de módulo por protocolo

### `telnet_default_creds` — Telnet

Testa login Telnet com credenciais padrão do vendor. Usa `telnetlib3` no Python 3.13+ e `telnetlib` em versões anteriores.

**Sessão de terminal (câmera Hikvision):**

```text
exf > use creds/cameras/hikvision/telnet_default_creds
exf (Hikvision Camera Default Telnet Creds) > set target 192.168.1.100
[+] target => 192.168.1.100
exf (Hikvision Camera Default Telnet Creds) > run
[*] Running module ...
[*] Trying admin:12345 on 192.168.1.100:23
[+] SUCCESS: admin:12345 — telnet session obtained
```

**Sessão de terminal (todas as credenciais falham):**

```text
exf (Hikvision Camera Default Telnet Creds) > run
[*] Running module ...
[*] Trying admin:12345 on 192.168.1.100:23
[-] FAIL: admin:12345
[-] No valid credentials found
```

**Sessão de terminal (câmera Dahua — múltiplos padrões):**

```text
exf > use creds/cameras/dahua/telnet_default_creds
exf (Dahua Camera/DVR/NVR Default Telnet Creds) > set target 192.168.1.50
[+] target => 192.168.1.50
exf (Dahua Camera/DVR/NVR Default Telnet Creds) > run
[*] Running module ...
[*] Trying admin:admin on 192.168.1.50:23
[-] FAIL: admin:admin
[*] Trying 888888:888888 on 192.168.1.50:23
[+] SUCCESS: 888888:888888 — telnet session obtained
```

---

### `ssh_default_creds` — SSH

Testa login SSH com credenciais padrão do vendor usando Paramiko.

| Opção | Tipo | Padrão | Descrição |
|-------|------|--------|-----------|
| `target` | `OptIP` | `""` | IP alvo ou file:// |
| `port` | `OptPort` | `22` | Porta SSH |
| `threads` | `OptInteger` | `8` | Concorrência |
| `defaults` | `OptWordlist` | Específico do vendor | Pares de credenciais padrão |
| `stop_on_success` | `OptBool` | `True` | Parar no primeiro sucesso |
| `verbosity` | `OptBool` | `True` | Exibir tentativas |

**Sessão de terminal (câmera Hikvision SSH):**

```text
exf > use creds/cameras/hikvision/ssh_default_creds
exf (Hikvision Camera Default SSH Creds) > set target 192.168.1.100
[+] target => 192.168.1.100
exf (Hikvision Camera Default SSH Creds) > run
[*] Running module ...
[*] Trying admin:12345 on 192.168.1.100:22
[-] FAIL: admin:12345
[*] Trying root:hikadmin on 192.168.1.100:22
[+] SUCCESS: root:hikadmin — SSH session opened
```

**Sessão de terminal (câmera Axis SSH):**

```text
exf > use creds/cameras/axis/ssh_default_creds
exf (Axis Camera Default SSH Creds) > set target 192.168.1.110
[+] target => 192.168.1.110
exf (Axis Camera Default SSH Creds) > run
[*] Running module ...
[*] Trying root: on 192.168.1.110:22
[+] SUCCESS: root: (empty password) — SSH session opened
```

---

### `ftp_default_creds` — FTP

Testa login FTP usando credenciais padrão do vendor.

**Sessão de terminal:**

```text
exf > use creds/cameras/hikvision/ftp_default_creds
exf (Hikvision Camera Default FTP Creds) > set target 192.168.1.100
[+] target => 192.168.1.100
exf (Hikvision Camera Default FTP Creds) > run
[*] Running module ...
[*] Trying admin:12345 on 192.168.1.100:21
[+] SUCCESS: admin:12345 — FTP session opened
230 Login successful.
```

---

### `webinterface_http_auth_default_creds` — HTTP Basic/Digest Auth

Testa endpoints de autenticação HTTP Basic ou Digest com credenciais padrão do vendor.

**Sessão de terminal (interface web câmera Dahua):**

```text
exf > use creds/cameras/dahua/webinterface_http_auth_default_creds
exf (Dahua Camera/DVR/NVR Default HTTP Auth Creds) > set target 192.168.1.50
[+] target => 192.168.1.50
exf (Dahua Camera/DVR/NVR Default HTTP Auth Creds) > run
[*] Running module ...
[*] Trying admin:admin on http://192.168.1.50:80
[-] FAIL: admin:admin (HTTP 401)
[*] Trying admin:888888 on http://192.168.1.50:80
[+] SUCCESS: admin:888888 (HTTP 200)
```

---

### `webinterface_http_form_default_creds` — Login por Formulário HTTP

Testa endpoints de formulário de login HTTP específicos do vendor (autenticação baseada em POST).

**Sessão de terminal (câmera ACTi):**

```text
exf > use creds/cameras/acti/webinterface_http_form_default_creds
exf (ACTi Camera Default HTTP Form Creds) > set target 192.168.1.120
[+] target => 192.168.1.120
exf (ACTi Camera Default HTTP Form Creds) > run
[*] Running module ...
[*] Trying admin:123456 on http://192.168.1.120:80/cgi-bin/encoder?USER=admin&PWD=123456
[+] SUCCESS: admin:123456 — HTTP form login successful
```

---

## Cobertura de vendors (câmeras)

Os seguintes vendors de câmeras possuem pelo menos um módulo de credenciais:

| Vendor | ftp | ssh | telnet | webinterface |
|--------|-----|-----|--------|--------------|
| ACTi | Sim | Sim | Sim | form |
| American Dynamics | Sim | Sim | Sim | — |
| Arecont | Sim | Sim | Sim | auth |
| Avigilon | Sim | Sim | Sim | — |
| AVTech | Sim | Sim | Sim | — |
| Axis | Sim | Sim | Sim | auth |
| Basler | Sim | Sim | Sim | form |
| Bosch | Sim | Sim | Sim | auth |
| Brickcom | Sim | Sim | Sim | auth |
| Canon | Sim | Sim | Sim | auth |
| CBC/GANZ | Sim | Sim | Sim | auth |
| Cisco (câmeras) | Sim | Sim | Sim | — |
| Dahua | Sim | Sim | Sim | auth |
| D-Link (câmeras) | Sim | Sim | Sim | — |
| DVTel | Sim | Sim | Sim | auth |
| Dynacolor | Sim | Sim | Sim | auth |
| EverFocus | Sim | Sim | Sim | auth |
| FLIR | Sim | Sim | Sim | auth |
| Foscam | Sim | Sim | Sim | auth |
| GeoVision | Sim | Sim | Sim | — |
| Grandstream | Sim | Sim | Sim | — |
| Hikvision | Sim | Sim | Sim | — |
| Honeywell | Sim | Sim | Sim | — |
| Intelbras | — | — | — | combinado |

---

## Teste de credenciais em múltiplos alvos

Use o protocolo `file://` para a opção `target` para testar múltiplos hosts a partir de um arquivo:

```text
exf > use creds/cameras/hikvision/telnet_default_creds
exf (Hikvision Camera Default Telnet Creds) > set target file:///tmp/hikvision_hosts.txt
[+] target => file:///tmp/hikvision_hosts.txt
exf (Hikvision Camera Default Telnet Creds) > run
[*] Running module ...
[*] Trying admin:12345 on 192.168.1.100:23
[*] Trying admin:12345 on 192.168.1.101:23
[*] Trying admin:12345 on 192.168.1.102:23
[+] SUCCESS: admin:12345 on 192.168.1.100:23
[+] SUCCESS: admin:12345 on 192.168.1.102:23
[-] FAIL: all credentials exhausted for 192.168.1.101
```

Formato do arquivo `/tmp/hikvision_hosts.txt`:

```text
192.168.1.100
192.168.1.101
192.168.1.102:23
```

---

## Wordlist personalizada

Substitua os padrões embutidos por um arquivo de wordlist personalizado:

```text
exf (Hikvision Camera Default Telnet Creds) > set defaults file:///tmp/custom_creds.txt
[+] defaults => file:///tmp/custom_creds.txt
```

Formato da wordlist — um par de credenciais por linha, separados por dois-pontos:

```text
admin:admin
admin:password
admin:12345
admin:
root:root
root:
guest:guest
service:service
```

---

## Exemplos não interativos

### Varredura Telnet (roteador D-Link)

```bash
embedxpl -m creds/routers/dlink/telnet_default_creds -s "target 192.168.1.1"
```

```text
[*] Running module ...
[*] Trying admin:admin on 192.168.1.1:23
[-] FAIL: admin:admin
[*] Trying admin:1234 on 192.168.1.1:23
[+] SUCCESS: admin:1234 — telnet session obtained
```

### Varredura SSH (roteador TP-Link)

```bash
embedxpl -m creds/routers/tplink/ssh_default_creds -s "target 192.168.0.1"
```

```text
[*] Running module ...
[*] Trying admin:admin on 192.168.0.1:22
[-] FAIL: admin:admin
[*] Trying admin:tplink on 192.168.0.1:22
[+] SUCCESS: admin:tplink — SSH session opened
```

### Interface web HTTPS (câmera Dahua)

```bash
embedxpl \
    -m creds/cameras/dahua/webinterface_http_auth_default_creds \
    -s "target 192.168.1.50" \
    -s "port 443" \
    -s "ssl true"
```

```text
[*] Running module ...
[*] Trying admin:admin on https://192.168.1.50:443
[-] FAIL: admin:admin (HTTP 401)
[*] Trying admin:888888 on https://192.168.1.50:443
[+] SUCCESS: admin:888888 (HTTP 200)
```

---

## Casos de erro

**Alvo não especificado:**

```text
exf (Hikvision Camera Default Telnet Creds) > run
[*] Running module ...
[-] target is required but not set
```

**Conexão recusada:**

```text
exf (Hikvision Camera Default Telnet Creds) > run
[*] Trying admin:12345 on 192.168.1.100:23
[-] Connection refused: 192.168.1.100:23
```

**Timeout de conexão:**

```text
exf (Hikvision Camera Default Telnet Creds) > run
[*] Trying admin:12345 on 192.168.1.100:23
[-] Connection timed out after 10s: 192.168.1.100:23
```

---

## Brute-force de comunidade SNMP (genérico)

O teste de strings de comunidade SNMP está disponível via:
- `generic/snmp/snmp_bruteforce` — bruteforcer SNMP genérico standalone

Consulte [08-modulos-generic.md](08-modulos-generic.md) para a referência do módulo SNMP.

---

## Dicas

1. Defina `verbosity false` para suprimir a saída por tentativa ao executar varreduras em lote.
2. Defina `threads 16` para varredura mais rápida em alvos LAN (padrão 8).
3. Use `stop_on_success false` para coletar todas as credenciais válidas (ex.: quando múltiplas contas têm senhas padrão).
4. Combine com `discover` para encontrar hosts e depois alvejá-los: discover → obter IPs → alimentar o módulo de creds via `file://`.
5. Para roteadores com SNMP: sempre tente as strings de comunidade `public` e `private` — são padrões embutidos na maioria dos vendors.

---

[Hub da Wiki](../README.md)
