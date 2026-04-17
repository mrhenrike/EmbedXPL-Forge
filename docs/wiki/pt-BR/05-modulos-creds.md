# Módulos de credenciais

**Idioma: Português (pt-BR)**. **en-US:** [../en-US/05-creds-modules.md](../en-US/05-creds-modules.md)

## Escopo

Módulos de credenciais exercitam **SSH**, **Telnet**, **FTP**, **HTTP**, **SNMP** e superfícies de login relacionadas em alvos **autorizados**.

## Fluxo típico

1. `use` em um módulo `creds/...`.
2. `set target` (e `port` se necessário).
3. Opcional: ajustar `threads`, wordlists e verbosidade.
4. `run`.

## Opções comuns

| Opção | Função |
|-------|--------|
| `target` | Hostname ou IP |
| `port` | Porta do serviço |
| `threads` | Paralelismo em módulos estilo brute-force |
| `defaults` | Tentar pares usuário/senha padrão do vendor quando suportado |
| `stop_on_success` | Parar no primeiro sucesso |
| `verbosity` | Nível de detalhe do log |

## Genérico vs vendor

- Módulos **vendor** ficam em `creds/routers/`, `creds/switches/`, etc.
- Ajudantes **genéricos** complementam a cobertura por vendor.

## Wordlists

Wordlists externas ficam em `embedxpl/resources/wordlists/vendors/` e caminhos relacionados; aponte os módulos para elas quando a opção aceitar arquivo.

## Autenticação HTTP

Verificações de login HTTP (`401/407`) ficam na árvore `creds`; combine `target`, `port` e opções de path conforme cada módulo documenta.

---

[Hub wiki](../README.md)

---

> **Author:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) \| **União Geek** — [https://github.com/Uniao-Geek](https://github.com/Uniao-Geek)
