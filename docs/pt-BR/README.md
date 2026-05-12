# Hub de Documentacao EmbedXPL-Forge (pt-BR)

**Versao:** 3.1.0 | Idioma padrao da documentacao: `en-US`

Versao em ingles disponivel em `../en-US/README.md`.

Autor: André Henrique (@mrhenrike) | União Geek - https://github.com/Uniao-Geek

## Novidades na v3.1.0

- **54 novos modulos** em impressoras, SO embarcado, ICS/OT, smart home, IoT maritimo e chains Pwn2Own 2026
- **Dominio de impressoras habilitado** (185+ modulos de impressoras ativos)
- **7 gates de qualidade automatizados** via `tools/phase_gate.py`
- Novos CVEs: wolfSSL CVE-2026-5194 (CVSS 9.3), PAN-OS CVE-2026-0300 (CVSS 9.8), CUPS CVE-2026-34477/78/79/80 (CVSS 9.9), UR PolyScope5 CVE-2026-8153 (CVSS 9.8), Cisco IOS XE CVE-2025-20188 (CVSS 10.0), e 30+ mais
- Novos vendors: EnGenius, Universal Robots, Metis Maritime, eNet SMART HOME, OpenRemote

## Escopo

Este conjunto de documentos cobre:

- instalacao e execucao;
- uso interativo e nao interativo;
- exemplos de entrada e saida esperada;
- referencias de modulos e protocolos;
- requisitos de hardware para auditorias.

Guias principais no repositorio:

- `README.md` (en-US padrao);
- `README.pt-BR.md` (traducao em portugues);
- Wiki `../wiki/en-US/README.md` e `../wiki/pt-BR/README.md`.

## Instalacao

### PyPI

```bash
pip install embedxpl
embedxpl
```

Saida esperada:

```text
EmbedXPL-Forge vX.Y.Z
exf >
```

### Codigo-fonte

```bash
git clone https://github.com/mrhenrike/EmbedXPL-Forge.git
cd EmbedXPL-Forge
pip install -r requirements.txt
python exf.py
```

Saida esperada:

```text
[*] Carregando modulos...
[+] Modulos carregados: <quantidade>
exf >
```

## Uso Interativo

### 1) Buscar modulo

```text
exf > search huawei
```

Saida esperada:

```text
[+] Found <n> module(s)
...
```

### 2) Selecionar modulo

```text
exf > use exploits/routers/huawei/eg8145x6_info_disclosure
```

Saida esperada:

```text
exf (EG8145X6 Info Disclosure) >
```

### 3) Ver opcoes

```text
exf (EG8145X6 Info Disclosure) > show options
```

Saida esperada:

```text
Name    Current Value  Required  Description
target                 yes       Target IPv4/IPv6
port    80             no        HTTP port
```

### 4) Definir entradas

```text
exf (EG8145X6 Info Disclosure) > set target 192.168.18.1
exf (EG8145X6 Info Disclosure) > set port 80
```

### 5) Validar e executar

```text
exf (EG8145X6 Info Disclosure) > check
exf (EG8145X6 Info Disclosure) > run
```

Saida esperada:

```text
[+] Target appears vulnerable
[*] Collecting metadata...
[+] ProductName: ...
```

## Uso Nao Interativo

### Execucao direta de modulo

```bash
python -m embedxpl -m exploits/routers/huawei/eg8145x6_info_disclosure -s target 192.168.18.1 -s port 80
```

Saida esperada:

```text
[*] Running module: exploits/routers/huawei/eg8145x6_info_disclosure
[+] ...
```

### Descoberta de rede

```bash
embedxpl -c "discover 192.168.1.0/24 --timing T3"
```

Saida esperada:

```text
[*] Discovery started
[+] Hosts discovered: <n>
[+] Suggested modules: <n>
```

## Convencoes de Entrada e Saida

- Entradas sao definidas via opcoes (`set <nome> <valor>`) ou `-s chave valor`.
- `check` valida pre-condicoes de exploracao:
  - positivo: alvo compativel com o modulo;
  - negativo: alvo nao aplicavel, corrigido ou indisponivel.
- `run` executa o scanner ou exploit e imprime os resultados.

Marcadores de status:

- `[*]` status de execucao;
- `[+]` sucesso ou achado positivo;
- `[-]` resultado negativo, bloqueio ou condicao ausente.

## Mapa da Documentacao

| Caminho | Descricao |
|---------|-----------|
| `architecture.md` | arquitetura do framework e fluxo de execucao |
| `hardware-requirements.md` | adaptadores, monitor mode e pre-requisitos de captura |
| `../wiki/en-US/` | wiki completa em ingles |
| `../wiki/pt-BR/` | wiki completa em portugues |
| `../modules/` | documentacao gerada por modulo |
| `../diagrams/architecture/` | fontes Mermaid e diagramas de arquitetura |

## Notas de Seguranca e Legalidade

- Utilize somente em ambientes autorizados.
- Valide autorizacao legal antes de escanear ou explorar.
- Siga procedimentos de divulgacao responsavel para vulnerabilidades.

## Licenca

Consulte o arquivo `LICENSE` do repositorio.
