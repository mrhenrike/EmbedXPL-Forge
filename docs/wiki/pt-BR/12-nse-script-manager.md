# Gerenciador de Scripts NSE

**Idioma:** Portugues (pt-BR) | **English (en-US):** [../en-US/12-nse-script-manager.md](../en-US/12-nse-script-manager.md)

---

## Visao geral

O EmbedXPL-Forge inclui **11 scripts Nmap NSE** que estendem o Nmap com deteccao de CVEs em IoT, fingerprinting de dispositivos e links diretos para modulos de exploit do EmbedXPL-Forge e FirewallXPL-Forge.

O comando `embedxpl-nse` gerencia a instalacao, validacao e execucao desses scripts.

---

## Instalacao (pip)

```bash
pip install "embedxpl[nse]"    # inclui suporte a NSE
embedxpl-nse install            # instala scripts no Nmap
```

---

## Referencia de comandos

### `check` -- validar instalacao do Nmap

```bash
embedxpl-nse check
```

Verifica se o Nmap esta instalado e se o diretorio de scripts foi encontrado. Sai com 0 se OK, 1 se nao encontrado.

**Saida -- Nmap encontrado:**

```text
[OK] Nmap encontrado: /usr/bin/nmap (Nmap version 7.94 ( https://nmap.org ))
[OK] Diretorio de scripts Nmap: /usr/share/nmap/scripts
```

**Saida -- Nmap NAO encontrado:**

```text
================================================================
  Nmap NAO esta instalado ou nao foi encontrado no PATH.
================================================================

Instale o Nmap para usar os scripts NSE com integracao automatica:

  Debian / Ubuntu:   sudo apt-get install nmap
  Fedora / RHEL:     sudo dnf install nmap
  Arch:              sudo pacman -S nmap

Apos instalar, execute:  embedxpl-nse install

----------------------------------------------------------------
  Os arquivos de script NSE estao disponiveis em:
    /home/usuario/.local/lib/python3.11/site-packages/nse/embedxpl-rtsp-discover.nse
    ...

  Uso manual (sem instalacao):
  nmap --script <caminho/para/script.nse> -p 80,443 <alvo>
================================================================
```

---

### `install` -- instalar scripts no Nmap

```bash
embedxpl-nse install
embedxpl-nse install --force        # sobrescreve scripts ja instalados
embedxpl-nse install --nse-dir DIR  # especifica diretorio de scripts Nmap manualmente
```

| Flag | Tipo | Padrao | Descricao |
|------|------|--------|-----------|
| `--force` / `-f` | bool | false | Sobrescreve scripts existentes |
| `--nse-dir` | caminho | auto | Substitui o diretorio de scripts Nmap |

**Saida esperada:**

```text
EmbedXPL-Forge NSE Script Installer v2.0.0
--------------------------------------------------
[1/4] Verificando instalacao do Nmap...
[OK] Nmap encontrado: /usr/bin/nmap (Nmap version 7.94)
[OK] Diretorio de scripts: /usr/share/nmap/scripts

[2/4] Localizando diretorio de scripts Nmap...
      Destino: /usr/share/nmap/scripts

[3/4] Verificando arquivos NSE de origem...

[4/4] Instalando scripts...
      [OK]  embedxpl-rtsp-discover.nse -> /usr/share/nmap/scripts/
      [OK]  embedxpl-camera-identify.nse -> /usr/share/nmap/scripts/
      ...
      [OK]  embedxpl-suite-ref.nse -> /usr/share/nmap/scripts/

Resultados:
  Instalados  : 11

Atualizando banco de dados de scripts nmap...
  [OK] nmap --script-updatedb completo

Instalacao concluida.
```

**Se o Nmap nao estiver instalado**, o instalador sai normalmente com caminhos locais -- **nao retorna erro**.

**Erro de permissao (Linux):** use `sudo embedxpl-nse install`

---

### `list` -- listar todos os scripts e status

```bash
embedxpl-nse list
```

---

### `run` -- executar scripts contra um alvo

```bash
embedxpl-nse run --target 192.168.1.0/24 --scripts all
embedxpl-nse run -t 10.0.0.1 -s perimeter-vuln,router-vuln
embedxpl-nse run -t 192.168.1.100 -s hikvision-vuln -p 80,443,8080
embedxpl-nse run -t 10.0.0.0/24 -s iot-cve-check --output /tmp/scan.txt
```

| Flag | Short | Tipo | Padrao | Descricao |
|------|-------|------|--------|-----------|
| `--target` | `-t` | `str` | **obrigatorio** | IP, CIDR, intervalo ou hostname |
| `--scripts` | `-s` | `str` | `all` | `all` ou nomes curtos separados por virgula |
| `--ports` | `-p` | `str` | `80,443,554,5554,8080,8443,8554,9100,37777,631` | Lista de portas Nmap |
| `--output` | `-o` | `str` | -- | Grava saida em arquivo (`-oN`) |
| `--args` | -- | `str` | -- | Argumentos extras para o Nmap |

Nomes curtos dos scripts (sem o prefixo `embedxpl-`):

```
rtsp-discover, camera-identify, camera-snapshot, hikvision-vuln,
dahua-vuln, rtsp-creds, iot-cve-check, perimeter-vuln,
router-vuln, printer-vuln, suite-ref
```

---

### `info` -- exibir detalhes de um script

```bash
embedxpl-nse info hikvision-vuln
embedxpl-nse info embedxpl-perimeter-vuln
```

---

### `uninstall` -- remover scripts do Nmap

```bash
embedxpl-nse uninstall
sudo nmap --script-updatedb
```

---

## Uso manual do Nmap (apos instalacao)

```bash
# Descoberta de cameras RTSP
nmap -p 554,5554,8554 --script embedxpl-rtsp-discover 192.168.1.0/24

# Checagem de CVEs em firewalls/VPN (Fortinet, Cisco, PAN-OS, SonicWall...)
nmap -p 443,8443 --script embedxpl-perimeter-vuln 10.0.0.0/24

# Checagem de CVEs em roteadores SOHO
nmap -p 80,443,8080 --script embedxpl-router-vuln 192.168.1.0/24

# Checagem de CVEs em impressoras
nmap -p 80,443,631,9100 --script embedxpl-printer-vuln 10.0.0.0/24

# Todos os scripts EmbedXPL de uma vez
nmap -p 80,443,554,9100 --script 'embedxpl-*' 192.168.1.100
```

---

## Scripts NSE disponiveis

| Script | Alvo | CVEs / Tecnicas |
|--------|------|-----------------|
| `embedxpl-rtsp-discover` | Cameras IP | Descoberta RTSP, banner, fingerprint de fabricante |
| `embedxpl-camera-identify` | Cameras/NVR | Fingerprinting multi-protocolo (HTTP + RTSP + ONVIF) |
| `embedxpl-camera-snapshot` | Cameras IP | Acesso a snapshot sem autenticacao (30+ endpoints) |
| `embedxpl-hikvision-vuln` | Hikvision | CVE-2021-36260 (RCE), CVE-2017-7921 (bypass de auth) |
| `embedxpl-dahua-vuln` | Dahua/OEM | CVE-2021-33044, CVE-2020-25078, CVE-2013-6117 |
| `embedxpl-rtsp-creds` | Cameras RTSP | Teste de credenciais padrao (Basic auth) |
| `embedxpl-iot-cve-check` | IoT multi-fabricante | 15+ CVEs: Hikvision, Dahua, D-Link NAS, SonicWall, GPON, Fortinet, PAN-OS, TP-Link |
| `embedxpl-perimeter-vuln` | Firewalls/VPN | 19 CVEs -- 15 fabricantes: Fortinet, Cisco, PAN-OS, SonicWall, Sophos, Juniper, Zyxel, Check Point, Ivanti, Citrix, pfSense, WatchGuard, Barracuda |
| `embedxpl-router-vuln` | Roteadores SOHO | 14 CVEs -- 15 fabricantes: TP-Link, D-Link, Netgear, ASUS, Linksys, MikroTik, Huawei, ZTE, Intelbras, Tenda, Totolink, DrayTek, GPON, Zyxel, OpenWrt |
| `embedxpl-printer-vuln` | Impressoras/MFPs | 14 CVEs -- 11 fabricantes: HP, Canon, Lexmark, Xerox, Ricoh, Brother, Kyocera, CUPS, Epson, Konica, Samsung |
| `embedxpl-suite-ref` | Qualquer | Referencia da suite XPL-Forge + guia rapido GTFOBins |


[Hub da wiki](../README.md)
