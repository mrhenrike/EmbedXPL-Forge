# Scanners e AutoPwn

**Idioma: Português (pt-BR)**. **en-US:** [../en-US/07-scanners-and-autopwn.md](../en-US/07-scanners-and-autopwn.md)

## AutoPwn

**AutoPwn** orquestra fluxos de fingerprint e escolha de módulos. Carregue o módulo AutoPwn com `use`, defina `target` (e opções de interface se necessário) e `run` — o comportamento está no `run()` do módulo.

## Scanners orientados a device

| Módulo | Função |
|--------|--------|
| `router_scan` | Ponto de entrada de descoberta / encadeamento focado em router |
| `hootoo_scan` | Fluxo scanner para Hootoo |

## Opções típicas

| Opção | Função |
|-------|--------|
| `target` | Host ou rede sob teste |
| `port` | Porta de serviço quando não implícita |
| `threads` | Concorrência para fases pesadas em rede |

Confirme escopo e limites de taxa antes de rodar scanners em redes em produção.

---

[Hub wiki](../README.md)

---

> **Author:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) \| **União Geek** — [https://github.com/Uniao-Geek](https://github.com/Uniao-Geek)
