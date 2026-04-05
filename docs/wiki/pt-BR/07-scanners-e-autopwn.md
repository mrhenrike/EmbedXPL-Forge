# Scanners e AutoPwn

**Idioma:** pt-BR. **English (en-US):** [../en-US/07-scanners-and-autopwn.md](../en-US/07-scanners-and-autopwn.md)

## `scanners/routers/router_scan`

Orquestra verificação ampla (`modules = generic + routers`). Útil como ponto de entrada sem escolher um exploit isolado.

```text
use scanners/routers/router_scan
set target 192.168.1.1
run
```

## `scanners/autopwn` — opções principais

AutoPwn executa uma **varredura paralela** com *checks* de credenciais e exploits, respeitando um **perfil de tempo** semelhante ao Nmap (`T0`–`T5`).

### Alvo e classe de dispositivo

| Opção | Descrição |
|-------|-----------|
| `target` | IP do alvo |
| `target_device_class` | Filtra módulos aplicáveis: `multi`, `router`, `switch`, `tap`, `fw`, `ngfw`, `isp_cpe` (ver `routerxpl/resources/catalogs/module_target_scope.json`) |
| `vendor` | Restringe por *vendor* quando suportado |

### Perfis de tempo

| Template | Apelidos | Comportamento (resumo) |
|----------|----------|-------------------------|
| `t0` | `paranoid` | Poucas *threads*, atrasos, mais confirmações |
| `t1` | `sneaky` | Ainda conservador |
| `t2` | `polite` | Intermédio |
| `t3` | `balanced`, `normal` | Padrão equilibrado |
| `t4` | `aggressive` | Mais *threads*, menos confirmações |
| `t5` | `insane` | Máxima velocidade (mais risco a FP e impacto no alvo) |

Opção `timing_template` aceita `t0`..`t5` ou o apelido.

### Serviços a testar

Flags booleansas (com portas avançadas onde aplicável):

- `http_use`, `http_port`, `http_ssl`
- `ftp_use`, `ssh_use`, `sftp_use`, `telnet_use`
- `snmp_use`, `snmp_community`, `snmp_version`, `snmp_port`
- `tcp_use`, `udp_use`

### O que executar

- `check_exploits` — correr *checks* de exploits
- `check_creds` — testar módulos de credenciais
- `threads` — limite global (o perfil também influi)
- `verify_positive_twice` — reduzir falsos positivos em *exploits*
- `module_timeout_s` — tempo máximo por módulo (proteção contra *hang*)

### ML advisor (opcional, `show advanced`)

Reordenar filas de módulos e sugerir ou aplicar `timing_template` com base num modelo leve (vetor de opções + pesos em JSON). **Desligado por omissão.**

| Opção | Descrição |
|-------|-----------|
| `ml_advisor` | `true` para ativar; mostra avisos sobre CPU/RAM (o grosso do custo continua a ser `threads` e I/O de rede). |
| `ml_auto_timing` | Com `ml_advisor true`, **substitui** `timing_template` pela sugestão do advisor. |
| `ml_use_gpu` | Se PyTorch+CUDA estiver instalado (`pip install .[ml-gpu]` no projeto), calcula logits do *timing* na GPU — ganho marginal; testes HTTP/SSH não ficam “GPU-acelerados”. |

Para cargas criptográficas em massa (ex.: WPA/PMKID), use ferramentas externas (hashcat), não este *advisor*.

### Exemplo

```text
use scanners/autopwn
set target 192.168.50.1
set timing_template polite
set target_device_class router
set check_creds true
set check_exploits true
run
```

Consulte `show advanced` para todas as opções finas.

## Scanners de perímetro / NGFW

Módulos de reconhecimento SSL-VPN / FortiGate estão em [**FirewallXPL-Forge**](https://github.com/mrhenrike/FirewallXPL-Forge) após a divisão do repositório (uso autorizado apenas).

## `scanners/routers/hootoo_scan`

AutoPwn específico para *vendor* HooToo (subconjunto de módulos).

## `scanners/misc/soho_exploit_catalog_server`

Serve o **catálogo SOHO** embutido (HTML/JS em `routerxpl/resources/arsenal/pocs/soho_exploit_catalog/`) via HTTP (**`127.0.0.1:8765`** por omissão). Uso em laboratório; `open_browser true` abre o *browser* predefinido.

---

[Wiki hub](../README.md)
