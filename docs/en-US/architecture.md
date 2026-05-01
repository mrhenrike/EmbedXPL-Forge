# Framework Architecture

This document describes the internal architecture of EmbedXPL-Forge,
covering the core classes, execution pipeline, and extension points.

## High-Level Overview

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

## Exploit Base Class

All exploit and scanner modules inherit from `embedxpl.core.exploit.exploit.Exploit`.
The class provides:

- `run()`: Main exploitation logic (override required).
- `check()`: Non-destructive vulnerability detection (override required).
- `run_threads()`: Concurrent execution via SmartPool.
- `target_protocol`: Protocol enum for transport selection.

### ExploitOptionsAggregator (Metaclass)

The `ExploitOptionsAggregator` metaclass intercepts class creation to:

1. Aggregate all `Option` descriptor instances from the class hierarchy
   into `exploit_attributes` for tab-completion in the interactive shell.
2. Rename `__info__` to `_ClassName__info__` to avoid collisions in
   deep inheritance chains.

This means each module defines `__info__` as a plain class attribute,
but at runtime it is accessed through the mangled name. The `docgen`
tool handles both forms during module scanning.

## Options System

Option descriptors are typed validators that live as class attributes:

| Class | Python Type | Validation |
|-------|-------------|------------|
| `OptIP` | str | IPv4/IPv6 or file:// URI |
| `OptPort` | int | 1-65535 range |
| `OptBool` | bool | "true"/"false" strings |
| `OptInteger` | int | Decimal or hex |
| `OptFloat` | float | Standard float |
| `OptString` | str | Any string |
| `OptMAC` | str | XX:XX:XX:XX:XX:XX format |
| `OptWordlist` | list | file:// URI or comma-separated |
| `OptEncoder` | encoder | Registered encoder lookup |

Each descriptor implements `__get__` and `__set__` for transparent
validation when the user sets values in the interactive shell.

## SmartPool

`embedxpl.core.pool.SmartPool` provides adaptive concurrency:

- **THREADS strategy**: `ThreadPoolExecutor` for I/O-bound work
  (HTTP requests, socket connections, banner grabs).
- **PROCESSES strategy**: `ProcessPoolExecutor` for CPU-bound work
  (hash cracking, payload mutation, wordlist generation).
- **AUTO strategy**: Selects based on `max_workers` vs `cpu_count()`
  heuristic.

The pool exposes `run_threaded_workers()` for exploit modules that
need parallel execution across multiple targets or credential pairs.

## AsyncScanEngine

`embedxpl.core.engine.AsyncScanEngine` wraps synchronous modules in
`asyncio` + `ThreadPoolExecutor`:

- Dispatches hundreds of modules concurrently without blocking.
- Manages per-module timeouts and cancellation.
- Produces `ScanResult` objects with target, port, protocol,
  vulnerability status, error info, and elapsed time.

The engine is used by the `autopwn` scanner and the non-interactive
batch mode.

## Exploit Orchestrator

`embedxpl.core.orchestrator.orchestrator.ExploitOrchestrator` handles
multi-language exploit execution:

- **RunnerRegistry**: Maps language labels to `ExploitRunner` instances.
- **CrossCompiler**: Compiles C/C++/Rust/ASM sources for target
  architectures (ARM, MIPS, x86, x64) using `BuildProfile` configs.
- **ArtifactCache**: Caches compiled binaries to avoid redundant builds.
- **RunResult**: Captures stdout, stderr, exit code, and execution time.

Supported languages: Python, C, C++, Rust, Assembly.

## Shell Engines

`embedxpl.core.shells.shell_engine.ShellEngine` is the abstract base
for all post-exploitation shell transports:

| Engine | Transport | Use Case |
|--------|-----------|----------|
| `RawTcpShell` | TCP socket | Standard reverse/bind shells |
| `RawUdpShell` | UDP socket | Stateless environments |
| `IcmpCovertShell` | ICMP echo | Firewall bypass (no open ports) |
| `DnsTunnelShell` | DNS TXT/CNAME | Egress-restricted networks |
| `HttpPollShell` | HTTP/S polling | Web proxy environments |
| `MqttShell` | MQTT pub/sub | IoT device C2 |
| `MeterpreterBridge` | MSF RPC | Metasploit session handoff |

Each engine implements: `connect()`, `disconnect()`, `send()`,
`recv()`, `interactive()`, with status tracking via `ShellStatus` enum.

## Hardware Gate

`embedxpl.core.hardware` provides a pre-execution gate for modules
that require physical adapters (Wi-Fi monitor, BLE, SDR, RFID,
CAN bus, UART, ultrasonic, Thread/802.15.4):

1. Reads `__info__["required_hardware"]` from the module.
2. Resolves each identifier against the `HWReq` enum.
3. Displays a detailed table with product recommendations, pricing,
   drivers, and OS support.
4. In interactive mode: prompts the operator for confirmation.
5. In non-interactive mode: raises `RuntimeError` to skip the module.

## Module Info Contract

Every module must define `__info__` as a class-level dict with:

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `name` | str | yes | Human-readable module name |
| `description` | str | yes | One-paragraph summary |
| `authors` | tuple/list | yes | Author attribution |
| `references` | tuple/list | no | URLs (NVD, advisories, blogs) |
| `devices` | tuple/list | yes | Affected device models |
| `severity` | str | no | "critical", "high", "medium", "low" |
| `cvss` | str | no | CVSS score as string |
| `cve` | str | no | CVE identifier |
| `status` | str | no | "confirmed", "untested-prod", etc. |
| `mitre` | tuple/list | no | MITRE ATT&CK technique IDs |
| `apt_groups` | tuple/list | no | Known threat actor usage |
| `required_hardware` | list | no | HWReq enum values |

## Extension Points

- **New modules**: Create a Python file under `modules/exploits/` or
  `modules/scanners/` inheriting from `Exploit`. Define `__info__`,
  options, `check()`, and `run()`.
- **New shell transports**: Subclass `ShellEngine` and implement the
  abstract methods.
- **New GPU backends**: Implement the `Backend` ABC in `core/gpu/`.
- **New protocols**: Add client libraries under `core/` and reference
  them from modules.

---

Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
