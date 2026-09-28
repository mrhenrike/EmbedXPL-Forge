# Solução de Problemas

**Idioma:** Português (pt-BR). **English:** [../en-US/11-troubleshooting.md](../en-US/11-troubleshooting.md)

---

## Diagnóstico rápido

Antes de registrar um bug, execute o diagnóstico de ambiente:

```bash
python tools/env_doctor.py
```

E a verificação de compatibilidade:

```bash
python tools/compat_smoke.py
```

---

## Problemas na inicialização

### `ImportError` ou `ModuleNotFoundError` na inicialização

```
ModuleNotFoundError: No module named 'embedxpl'
```

**Causa:** Pacote não instalado ou ambiente Python incorreto ativo.

```bash
# Instalar a partir do código-fonte
pip install -e .

# Ou instalar do PyPI
pip install embedxpl

# Reinstalar todas as dependências
pip install -r requirements.txt

# Verificar ambiente
python tools/env_doctor.py
```

Confirme que está usando o executável Python correto:

```bash
which python        # Linux/macOS
where python        # Windows
python --version    # deve ser >= 3.8
```

---

### Erro `stdin is not a TTY`

```
[-] stdin is not a TTY. Ensure `stdin_open` and `tty` are set
```

**Causa:** O shell interativo do EmbedXPL-Forge requer um TTY real. Este erro aparece quando stdin está redirecionado ou executando dentro de um container Docker não interativo sem alocação de TTY.

**Opções de correção:**

```bash
# Opção 1 — modo não interativo (sem TTY necessário)
python -m embedxpl -m exploits/routers/tplink/wr841n_credential_disclosure_cve_2023_50224 \
    -s "target 192.168.1.1" -s "port 80"

# Opção 2 — Docker: alocar um pseudo-TTY
docker run -it --rm embedxpl-forge embedxpl

# Opção 3 — SSH: solicitar um TTY
ssh -t user@host 'embedxpl'
```

---

### Módulo não encontrado após `use <modulo>`

```
[-] Unknown module: 'exploits/routers/tplink/nonexistent'
```

**Causa:** Caminho do módulo incorreto, arquivo de módulo ausente, ou você não está executando a partir da raiz do repositório.

```bash
# Verificar se o módulo existe
ls embedxpl/modules/exploits/routers/tplink/

# Re-indexar módulos
python -c "from embedxpl.core.exploit.utils import index_modules; print(len(index_modules()), 'modules')"

# Buscar por nome parcial
exf> search tplink
```

---

### `EmbedXPL stopped` ao pressionar `Ctrl+C`

```
[-] Use Ctrl+D to exit
```

Este é o comportamento esperado. `Ctrl+C` cancela a operação atual. Para sair do shell de forma limpa, use `Ctrl+D` ou digite `exit`.

---

## Problemas de versão do Python

### Python 3.13+ — `telnetlib` removido

```
ModuleNotFoundError: No module named 'telnetlib'
```

`telnetlib` foi removido no Python 3.13. O EmbedXPL-Forge inclui `telnetlib3` como substituto:

```bash
pip install telnetlib3
# ou
pip install embedxpl[all]
```

---

### Requisito mínimo Python 3.8

```
SyntaxError: ...
```

A maioria dos módulos usa f-strings, operadores walrus e `dataclasses` que requerem Python 3.8+. Verifique:

```bash
python --version
# Esperado: Python 3.8.x ou superior (3.10+ recomendado)
```

---

### `readline` não disponível (Windows)

```
[WARN] readline not available — tab completion disabled
```

Este é um aviso não crítico no Windows. O interpretador usa um shim que desabilita o completamento por Tab, mas todos os comandos funcionam normalmente. Para habilitar o completamento por Tab no Windows, instale `pyreadline3`:

```bash
pip install pyreadline3
```

---

## Problemas específicos de protocolo

### SSH — `Authentication failed`

```
[-] Authentication failed for 192.168.1.1:22
```

**Causas comuns e correções:**

| Causa | Correção |
|-------|---------|
| Credenciais erradas | Use `set username admin` e `set password admin` |
| Incompatibilidade de tipo de chave SSH | Adicione `set ssh_key_type rsa-sha2-256` |
| Chave de host rejeitada | Adicione o host a `~/.ssh/known_hosts` ou use `set strict_host_key False` |
| Porta não aberta | Execute `discover 192.168.1.1` primeiro para confirmar que o SSH está ouvindo |
| `paramiko` não instalado | `pip install paramiko` |

---

### Telnet — conexão recusada

```
[-] Connection refused: 192.168.1.1:23
```

O Telnet está desabilitado na maioria dos dispositivos modernos. Confirme se a porta está aberta:

```bash
python -m embedxpl -m scanners/generic/port_scanner -s "target 192.168.1.1" -s "ports 23"
```

Se `telnetlib3` estiver ausente:

```bash
pip install telnetlib3
```

---

### HTTP/HTTPS — erros de certificado SSL

```
ssl.SSLCertVerificationError: [SSL: CERTIFICATE_VERIFY_FAILED]
```

**Correção:** A maioria dos dispositivos IoT usa certificados autoassinados. Defina a opção `ssl_verify` como `false`:

```
exf (modulo) > set ssl_verify false
```

Ou globalmente:

```
exf> setg ssl_verify false
```

---

### SNMP — sem resposta

```
[-] SNMP: no response from 192.168.1.1 (timeout after 5s)
```

**Causas comuns:**

| Causa | Correção |
|-------|---------|
| String de comunidade errada | `set community public` / `set community private` |
| SNMP v1/v2 desabilitado | Tente `set snmp_version 3` |
| Firewall bloqueando UDP 161 | Confirme com `nmap -sU -p 161 192.168.1.1` |
| `pysnmp` não instalado | `pip install pysnmp` |

---

### Modbus TCP — erros de conexão

```
[-] Modbus: connection refused on 192.168.1.100:502
```

O Modbus TCP ouve na porta 502. Confirme:

```bash
nmap -p 502 192.168.1.100
```

Se a porta estiver filtrada, o alvo pode exigir acesso serial direto RS-485 (Modbus RTU) em vez de TCP.

---

### FTP — `530 Login incorrect`

```
[-] FTP authentication failed: 530 Login incorrect
```

Use o módulo de creds para bruteforce ou tente os padrões do fabricante:

```
exf> use creds/routers/tplink/ftp_default_creds
exf (tplink/ftp_default_creds) > set target 192.168.1.1
exf (tplink/ftp_default_creds) > run
```

---

## Problemas específicos de NSE

### `nmap: command not found`

```
[ERROR] Nmap not found. Install Nmap to use this command.
```

Instale o Nmap para o seu SO:

| SO | Comando |
|----|---------|
| Debian/Ubuntu | `sudo apt-get install nmap` |
| Fedora/RHEL | `sudo dnf install nmap` |
| Arch | `sudo pacman -S nmap` |
| macOS (Homebrew) | `brew install nmap` |
| Windows (winget) | `winget install insecure.nmap` |
| Windows (Chocolatey) | `choco install nmap` |
| Windows (manual) | https://nmap.org/download.html |

Após instalar:

```bash
embedxpl-nse install
```

---

### Diretório de scripts NSE não encontrado

```
[ERR] Could not locate Nmap scripts directory.
```

Especifique o diretório manualmente:

```bash
embedxpl-nse install --nse-dir /usr/share/nmap/scripts
# Windows:
embedxpl-nse install --nse-dir "C:\Program Files (x86)\Nmap\scripts"
```

---

### `Permission denied` ao instalar scripts NSE

```
[ERR] Permission denied: /usr/share/nmap/scripts/embedxpl-iot-cve-check.nse
```

Execute com privilégios elevados:

```bash
# Linux/macOS
sudo embedxpl-nse install

# Windows (execute como Administrador no PowerShell)
embedxpl-nse install
```

---

### Script NSE não encontrado após instalação

```
nmap: warning: 'embedxpl-iot-cve-check.nse' not found in nmap-scripts
```

O banco de dados de scripts precisa ser atualizado:

```bash
sudo nmap --script-updatedb
```

Ou reinstale com force:

```bash
sudo embedxpl-nse install --force
```

---

## Problemas específicos de CVE

### CVE-2022-40684 (FortiOS auth bypass) — HTTP 404

```
[-] HTTP 404 on /api/v2/cmdb/system/admin/admin
```

O alvo pode estar executando FortiOS 7.2.2+ (corrigido). Confirme o banner de versão:

```
exf> use scanners/firewalls/fortinet/fortios_version_check
exf (fortios_version_check) > set target 192.168.1.1
exf (fortios_version_check) > run
```

Versões afetadas: FortiOS 5.x, 6.x, 7.0.0–7.0.6, 7.2.0–7.2.1.

---

### CVE-2021-36260 (Hikvision RCE) — comando não executado

```
[*] Sent payload but no connection received on 0.0.0.0:4444
```

**Causas comuns:**

| Causa | Correção |
|-------|---------|
| Dispositivo corrigido (firmware >= V5.5.800) | Use `check` para verificar antes de `run` |
| Firewall bloqueando reverse shell | Use `set shell_type bind` |
| LHOST errado | `set lhost <seu-IP-atacante>` |
| Porta em uso | `set lport 4445` |

---

### CVE-2018-14847 (MikroTik Winbox) — conexão recusada

```
[-] Connection refused on port 8291
```

O Winbox ouve na TCP 8291. Confirme se a porta está aberta:

```bash
nmap -p 8291 192.168.1.1
```

Versões afetadas: RouterOS < 6.42.

---

## Problemas de GPU / computação

### `No GPU detected` na inicialização

```
[yellow][system][/yellow] Intel Core i7-11800H (16T) | 32768MB RAM | No GPU detected | compute_mode: auto->cpu
```

Esta é uma mensagem informativa. A computação GPU é necessária apenas para módulos baseados em ML. O modo CPU funciona para todos os módulos padrão.

Se você tem uma GPU e ela não está sendo detectada:

```bash
# Verificar CUDA
python -c "import torch; print(torch.cuda.is_available())"

# Verificar ROCm (AMD)
python -c "import torch; print(torch.version.hip)"

# Instalar PyTorch habilitado para CUDA
pip install torch --index-url https://download.pytorch.org/whl/cu121
```

---

### Fallback `GPU mode requested but no GPU detected`

```
[WARN] No GPU detected -- falling back to compute_mode=cpu
```

Este é o comportamento esperado quando `compute gpu` ou `compute hybrid` está definido em uma máquina sem GPU. Para suprimir, defina:

```
exf> compute cpu
[+] compute_mode => cpu
```

---

## Problemas de sessão

### `No saved sessions` após executar `discover`

```
[*] No saved sessions. Run 'discover <target>' to create one.
```

As sessões são armazenadas em `~/.exf_sessions/` por padrão. Se o diretório não for gravável:

```bash
ls -la ~/.exf_sessions/
# Se ausente:
mkdir -p ~/.exf_sessions && chmod 700 ~/.exf_sessions
```

---

### Dados de sessão aparecem desatualizados após atualização de firmware no alvo

Se um dispositivo alvo foi reiniciado ou atualizado com firmware novo, seu endereço MAC ou portas abertas podem ter mudado. Force uma nova descoberta para resetar a sessão:

```
exf> discover 192.168.1.0/24 --fresh
```

Ou exclua a sessão específica:

```
exf> sessions delete 192.168.1.1
```

---

## Problemas com ferramentas de firmware

### `firmware_sources.yaml not found`

```
[ERROR] firmware_sources.yaml not found at .../embedxpl/resources/firmware_sources.yaml
```

O diretório de recursos não foi empacotado. Reinstale:

```bash
pip install --force-reinstall embedxpl
# ou a partir do código-fonte:
pip install -e .
```

---

### `binwalk not installed`

```
[WARN] binwalk not found. Install: pip install binwalk or apt-get install binwalk
```

```bash
# Linux
sudo apt-get install binwalk

# Wrapper Python (limitado)
pip install binwalk

# Substituto moderno (recomendado)
pip install unblob
```

---

### `EMBA not found`

```
[WARN] EMBA not found. Clone from: https://github.com/e-m-b-a/emba and run sudo ./installer.sh
```

```bash
git clone https://github.com/e-m-b-a/emba /opt/emba
cd /opt/emba && sudo ./installer.sh
```

---

## Problemas específicos do Windows

### Separadores de caminho no comando `use`

Tanto barra e contrabarra são aceitas. A forma recomendada usa barras:

```
exf> use exploits/routers/tplink/wr841n_credential_disclosure_cve_2023_50224
```

---

### Problemas de completamento por Tab no Windows

O completamento por Tab requer `pyreadline3` no Windows:

```bash
pip install pyreadline3
```

---

## Problemas específicos do macOS

### `libedit` em vez de GNU readline

No macOS, o Python vincula-se ao `libedit` em vez do GNU readline. O EmbedXPL-Forge detecta isso automaticamente e usa `bind ^I rl_complete`. O completamento por Tab funciona normalmente.

---

## Referência de códigos de erro comuns

| Erro | Significado | Ação |
|------|-------------|------|
| `Unknown command: 'foo'` | Comando digitado incorretamente | Digite `help` para listar comandos válidos |
| `You can't set option 'foo'` | Opção não existe para o módulo carregado | Digite `show options` para listar opções válidas |
| `A module is required when running non-interactively` | Flag `-m` ausente no modo CLI | Adicione `-m <caminho_modulo>` |
| `Invalid target: 'foo'` | Alvo não é um IP ou CIDR válido | Use notação decimal com pontos |
| `Discovery failed: ...` | Erro de varredura de rede | Verifique se `nmap` está instalado, verifique regras de firewall |
| `No live hosts found on ...` | Todos os hosts inacessíveis | Verifique a faixa CIDR e a conectividade de rede |
| `Module loaded. Set target and run` | `apt run` carregou um módulo | `set target <IP>` e então `run` |
| `Unknown infra type 'foo'` | Argumento `--infra` inválido | Valores válidos: `ot`, `it`, `iot` |
| `Unknown context 'foo' for infra 'ot'` | Argumento `--context` inválido | Execute sem `--context` para ver as opções válidas |

---

[Hub da Wiki](../README.md)
