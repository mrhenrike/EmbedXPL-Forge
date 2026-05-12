# Credential Modules

**Language:** English (en-US). **pt-BR:** [../pt-BR/05-modulos-creds.md](../pt-BR/05-modulos-creds.md)

## Scope

Credential modules exercise **SSH**, **Telnet**, **FTP**, **HTTP**, **SNMP**, and related login surfaces against **authorized** targets.

## Typical flow

1. `use` a `creds/...` module.
2. `set target` (and `port` if needed).
3. Optional: tune threads, wordlists, and verbosity.
4. `run`.

## Common options

| Option | Role |
|--------|------|
| `target` | Hostname or IP |
| `port` | Service port |
| `threads` | Parallelism for brute-force style modules |
| `defaults` | Try vendor default username/password pairs when supported |
| `stop_on_success` | Stop after first success |
| `verbosity` | Log detail level |

## Generic vs vendor modules

- **Vendor** modules live under `creds/routers/`, `creds/switches/`, etc.
- **Generic** helpers complement vendor coverage.

## Wordlists

External wordlists ship under `embedxpl/resources/wordlists/vendors/` and related paths; point modules to them when an option accepts a file path.

## HTTP authentication

HTTP `401/407`-style login checks live under the `creds` tree; combine with `target`, `port`, and path options as documented per module.


[Wiki hub](../README.md)
