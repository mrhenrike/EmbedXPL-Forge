# Arquitetura do Framework

Este documento descreve a arquitetura interna do EmbedXPL-Forge,
cobrindo as classes principais, o pipeline de execucao e os pontos
de extensao.

## Visao Geral de Alto Nivel

```
 CLI / Interpreter
       |
       v
 +-- Discovery & Module Loader --+
 |                                |
 v                                v
Exploit base class            Scanner base class
(ExploitOptionsAggregator)    (inherits Exploit)
       |
       v
 Options system (Option descriptors)
       |
       v
 +-- Execution Layer -----------+
 |   SmartPool (threads/procs)  |
 |   AsyncScanEngine (asyncio)  |
 |   Orchestrator (multi-lang)  |
 +------------------------------+
       |
       v
 +-- Transport / Shell Layer ---+
 |   ShellEngine (abstract)     |
 |   raw_tcp, raw_udp, icmp,   |
 |   dns_tunnel, http_poll,    |
 |   mqtt, meterpreter_bridge  |
 +------------------------------+
       |
       v
 +-- Support Subsystems --------+
 |   Hardware Gate              |
 |   ML Advisor / Fingerprint   |
 |   GPU Backends               |
 |   CVE Database               |
 |   Credential Database        |
 +------------------------------+
```

## Classe Base de Exploit

Todos os modulos de exploit e scanner herdam de `embedxpl.core.exploit.exploit.Exploit`.
A classe fornece:

- `run()`: Logica principal de exploracao (override obrigatorio).
- `check()`: Deteccao nao-destrutiva de vulnerabilidades (override obrigatorio).
- `run_threads()`: Execucao concorrente via SmartPool.
- `target_protocol`: Enum de protocolo para selecao de transporte.

### ExploitOptionsAggregator (Metaclass)

A metaclass `ExploitOptionsAggregator` intercepta a criacao de classes para:

1. Agregar todas as instancias de descriptors `Option` da hierarquia de classes
   em `exploit_attributes` para tab-completion no shell interativo.
2. Renomear `__info__` para `_ClassName__info__` para evitar colisoes em
   cadeias de heranca profundas.

Isso significa que cada modulo define `__info__` como atributo de classe simples,
mas em tempo de execucao ele e acessado pelo nome mangled. A ferramenta `docgen`
trata ambas as formas durante a varredura de modulos.

## Sistema de Options

Option descriptors sao validadores tipados que existem como atributos de classe:

| Classe | Tipo Python | Validacao |
|--------|-------------|-----------|
| `OptIP` | str | IPv4/IPv6 ou URI file:// |
| `OptPort` | int | Faixa 1-65535 |
| `OptBool` | bool | Strings "true"/"false" |
| `OptInteger` | int | Decimal ou hex |
| `OptFloat` | float | Float padrao |
| `OptString` | str | Qualquer string |
| `OptMAC` | str | Formato XX:XX:XX:XX:XX:XX |
| `OptWordlist` | list | URI file:// ou separado por virgula |
| `OptEncoder` | encoder | Busca de encoder registrado |

Cada descriptor implementa `__get__` e `__set__` para validacao transparente
quando o usuario define valores no shell interativo.

## SmartPool

`embedxpl.core.pool.SmartPool` fornece concorrencia adaptativa:

- **Estrategia THREADS**: `ThreadPoolExecutor` para trabalho I/O-bound
  (requisicoes HTTP, conexoes socket, captura de banners).
- **Estrategia PROCESSES**: `ProcessPoolExecutor` para trabalho CPU-bound
  (hash cracking, mutacao de payloads, geracao de wordlists).
- **Estrategia AUTO**: Seleciona com base na heuristica
  `max_workers` vs `cpu_count()`.

O pool expoe `run_threaded_workers()` para modulos de exploit que
necessitam execucao paralela contra multiplos alvos ou pares de credenciais.

## AsyncScanEngine

`embedxpl.core.engine.AsyncScanEngine` encapsula modulos sincronos em
`asyncio` + `ThreadPoolExecutor`:

- Despacha centenas de modulos concorrentemente sem bloqueio.
- Gerencia timeouts e cancelamento por modulo.
- Produz objetos `ScanResult` com alvo, porta, protocolo,
  status de vulnerabilidade, informacoes de erro e tempo decorrido.

A engine e utilizada pelo scanner `autopwn` e pelo modo batch
nao-interativo.

## Exploit Orchestrator

`embedxpl.core.orchestrator.orchestrator.ExploitOrchestrator` gerencia
a execucao de exploits multi-linguagem:

- **RunnerRegistry**: Mapeia labels de linguagem para instancias de `ExploitRunner`.
- **CrossCompiler**: Compila fontes C/C++/Rust/ASM para arquiteturas-alvo
  (ARM, MIPS, x86, x64) usando configuracoes `BuildProfile`.
- **ArtifactCache**: Cache de binarios compilados para evitar builds redundantes.
- **RunResult**: Captura stdout, stderr, exit code e tempo de execucao.

Linguagens suportadas: Python, C, C++, Rust, Assembly.

## Shell Engines

`embedxpl.core.shells.shell_engine.ShellEngine` e a classe base abstrata
para todos os transportes de shell pos-exploracao:

| Engine | Transporte | Caso de Uso |
|--------|------------|-------------|
| `RawTcpShell` | TCP socket | Reverse/bind shells padrao |
| `RawUdpShell` | UDP socket | Ambientes stateless |
| `IcmpCovertShell` | ICMP echo | Bypass de firewall (sem portas abertas) |
| `DnsTunnelShell` | DNS TXT/CNAME | Redes com restricao de egress |
| `HttpPollShell` | HTTP/S polling | Ambientes com web proxy |
| `MqttShell` | MQTT pub/sub | C2 para dispositivos IoT |
| `MeterpreterBridge` | MSF RPC | Handoff de sessao Metasploit |

Cada engine implementa: `connect()`, `disconnect()`, `send()`,
`recv()`, `interactive()`, com rastreamento de status via enum `ShellStatus`.

## Hardware Gate

`embedxpl.core.hardware` fornece um gate de pre-execucao para modulos
que requerem adaptadores fisicos (Wi-Fi monitor, BLE, SDR, RFID,
CAN bus, UART, ultrassonico, Thread/802.15.4):

1. Le `__info__["required_hardware"]` do modulo.
2. Resolve cada identificador contra o enum `HWReq`.
3. Exibe uma tabela detalhada com recomendacoes de produtos, precos,
   drivers e suporte de SO.
4. Em modo interativo: solicita confirmacao do operador.
5. Em modo nao-interativo: levanta `RuntimeError` para pular o modulo.

## Contrato de Info do Modulo

Todo modulo deve definir `__info__` como um dict a nivel de classe com:

| Chave | Tipo | Obrigatorio | Descricao |
|-------|------|-------------|-----------|
| `name` | str | sim | Nome legivel do modulo |
| `description` | str | sim | Resumo em um paragrafo |
| `authors` | tuple/list | sim | Atribuicao de autoria |
| `references` | tuple/list | nao | URLs (NVD, advisories, blogs) |
| `devices` | tuple/list | sim | Modelos de dispositivos afetados |
| `severity` | str | nao | "critical", "high", "medium", "low" |
| `cvss` | str | nao | Score CVSS como string |
| `cve` | str | nao | Identificador CVE |
| `status` | str | nao | "confirmed", "untested-prod", etc. |
| `mitre` | tuple/list | nao | IDs de tecnicas MITRE ATT&CK |
| `apt_groups` | tuple/list | nao | Uso conhecido por grupos de ameaca |
| `required_hardware` | list | nao | Valores do enum HWReq |

## Pontos de Extensao

- **Novos modulos**: Crie um arquivo Python em `modules/exploits/` ou
  `modules/scanners/` herdando de `Exploit`. Defina `__info__`,
  options, `check()` e `run()`.
- **Novos transportes de shell**: Herde de `ShellEngine` e implemente os
  metodos abstratos.
- **Novos backends GPU**: Implemente o ABC `Backend` em `core/gpu/`.
- **Novos protocolos**: Adicione bibliotecas cliente em `core/` e
  referencie-as a partir dos modulos.

---

Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
