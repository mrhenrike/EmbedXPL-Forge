# Shell Interativo — Comandos

**Idioma:** Português (pt-BR). **en-US:** [../en-US/02-interactive-shell-commands.md](../en-US/02-interactive-shell-commands.md)

## Referência de Comandos

| Comando | Finalidade |
|---------|-----------|
| `use <módulo>` | Carregar um módulo pelo caminho |
| `back` | Sair do contexto do módulo atual |
| `show options` | Listar opções do módulo |
| `show info` | Exibir metadados do módulo |
| `show devices` | Listar devices conhecidos / catálogo |
| `set <opção> <valor>` | Configurar uma opção local do módulo |
| `setg <opção> <valor>` | Configurar uma opção global (persiste entre módulos) |
| `unset <opção>` | Limpar uma opção local |
| `unsetg <opção>` | Limpar uma opção global |
| `check` | Executar verificação de vulnerabilidade do módulo |
| `run` / `exploit` | Executar o módulo carregado |
| `search <termo>` | Buscar módulos por palavra-chave, CVE ou vendor |
| `discover [subnet] [--timing T0-T5] [--fresh]` | Descobrir e fingerprinting de targets na subnet |
| `sessions <subcomando>` | Gerenciar histórico persistente de scans |
| `help` | Ajuda integrada |
| `exit` | Sair da aplicação |

## Sessão de Exemplo

```text
EmbedXPL-Forge > use exploits/routers/dlink/dir_300_600_rce
EmbedXPL-Forge (dir_300_600_rce) > show options
EmbedXPL-Forge (dir_300_600_rce) > set target 192.168.0.1
EmbedXPL-Forge (dir_300_600_rce) > check
EmbedXPL-Forge (dir_300_600_rce) > run
```

## Discovery de Rede

O comando `discover` realiza varredura multi-fase para identificar devices conhecidos:

```text
# Varrer a subnet padrão (detectada automaticamente pelas interfaces ativas)
EmbedXPL-Forge > discover

# Varrer subnet específica com timing T4 (agressivo)
EmbedXPL-Forge > discover 192.168.1.0/24 --timing T4

# Varrer um host único
EmbedXPL-Forge > discover 192.168.1.1

# Ignorar histórico de sessão e fazer varredura completa
EmbedXPL-Forge > discover --fresh
```

### Perfis de Timing (T0–T5)

| Perfil | Delay entre probes | Caso de uso |
|--------|-------------------|-------------|
| `T0` | paranóico — 300 s | Evasão extrema de IDS |
| `T1` | furtivo — 15 s | Auditorias silenciosas |
| `T2` | educado — 2 s | Impacto mínimo na rede |
| `T3` | normal — 0,5 s | **Padrão** |
| `T4` | agressivo — 0,1 s | Scans rápidos em LAN |
| `T5` | insano — 0 s | CTF / laboratório isolado |

Pipeline de discovery: **ARP sweep → Nmap (probes multi-método) → Scapy → TCP connect fallback**.

A resolução de vendor por MAC usa a [base OUI da IEEE](https://standards-oui.ieee.org/oui/oui.txt) com busca online prioritária e fallback local (`embedxpl/data/oui.txt`).

Quando um host descoberto expõe capacidades wireless, o EmbedXPL-Forge exibe uma recomendação para usar [WirelessXPL-Forge](https://github.com/mrhenrike/WirelessXPL-Forge) para ataques específicos de WiFi.

## Gerenciamento de Sessões

Sessões persistem o histórico de scan por host único (indexado por SHA-256 de IP + MAC). Em re-discovery de um host conhecido, módulos já testados aparecem como `[Testado]` e são pulados por padrão.

Sessões são armazenadas em `~/.exf_sessions/`.

```text
# Listar todos os hosts com histórico
EmbedXPL-Forge > sessions list

# Exibir histórico completo de um host: módulos testados, findings, timestamps
EmbedXPL-Forge > sessions show 192.168.1.1

# Exportar sessão como arquivo JSON
EmbedXPL-Forge > sessions export 192.168.1.1

# Deletar sessão de um host
EmbedXPL-Forge > sessions delete 192.168.1.1

# Deletar todas as sessões
EmbedXPL-Forge > sessions purge
```

## Completação por Tab

Completação automática está disponível para comandos e caminhos de módulos onde a camada readline estiver ativa.


[Hub da Wiki](../README.md)
