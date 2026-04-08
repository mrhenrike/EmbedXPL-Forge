# Architecture Diagrams — RouterXPL-Forge

**Author:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) | **União Geek** — [https://github.com/Uniao-Geek](https://github.com/Uniao-Geek)

**Languages:** Diagram labels are **English (en-US)** by default. **Português (pt-BR):** [README.pt-BR.md](README.pt-BR.md).

Diagrams show device attack surfaces with coverage indicators for RouterXPL-Forge modules (`creds`, `exploits`, `scanners`, `generic`).

## Files

| File | Category |
|------|----------|
| [01-router-soho.mmd](01-router-soho.mmd) | SOHO / home gateway (Linux / RTOS firmware) |
| [02-switch-l2-l3.mmd](02-switch-l2-l3.mmd) | Managed L2/L3 switch |
| [03-ngfw-utm.mmd](03-ngfw-utm.mmd) | NGFW / UTM / enterprise firewall appliance |
| [04-isp-cpe.mmd](04-isp-cpe.mmd) | ISP CPE / GPON ONT (Huawei EchoLife/OptiXstar, validated) |
| [05-edge-mixed.mmd](05-edge-mixed.mmd) | Mixed small-office edge (router + UTM-lite) |
| [06-network-tap.mmd](06-network-tap.mmd) | Network TAP / passive broker (mgmt-only vectors) |
| [07-gpon-ont-attack.mmd](07-gpon-ont-attack.mmd) | GPON ONT full attack surface map (validated on EG8145X6-10) |

## Rendered PNGs

| PNG | Source |
|-----|--------|
| [rxf_arch_router_soho.png](../../img/architecture/rxf_arch_router_soho.png) | SOHO router |
| [rxf_arch_switch_l2l3.png](../../img/architecture/rxf_arch_switch_l2l3.png) | Switch |
| [rxf_arch_ngfw_utm.png](../../img/architecture/rxf_arch_ngfw_utm.png) | NGFW / UTM |
| [rxf_arch_isp_cpe.png](../../img/architecture/rxf_arch_isp_cpe.png) | ISP CPE |
| [rxf_arch_edge_mixed.png](../../img/architecture/rxf_arch_edge_mixed.png) | Mixed edge |

### Gallery

| SOHO Router | Switch |
|:---:|:---:|
| ![SOHO router](../../img/architecture/rxf_arch_router_soho.png) | ![Switch](../../img/architecture/rxf_arch_switch_l2l3.png) |

| NGFW / UTM | ISP CPE |
|:---:|:---:|
| ![NGFW / UTM](../../img/architecture/rxf_arch_ngfw_utm.png) | ![ISP CPE](../../img/architecture/rxf_arch_isp_cpe.png) |

| Mixed Edge |
|:---:|
| ![Mixed edge](../../img/architecture/rxf_arch_edge_mixed.png) |

**TAP / passive devices:** see Mermaid source [06-network-tap.mmd](06-network-tap.mmd) — PNG optional (low remote attack surface).

**GPON ONT attack map:** see [07-gpon-ont-attack.mmd](07-gpon-ont-attack.mmd) — validated against Huawei EG8145X6-10 (OptiXstar, Loga Internet) and EG8145V5-V2 (EchoLife, Sumicity/Giga+).

## Render Locally

With [Mermaid CLI](https://github.com/mermaid-js/mermaid-cli):

```bash
npx @mermaid-js/mermaid-cli -i docs/diagrams/architecture/01-router-soho.mmd -o docs/img/architecture/router_soho.png -b transparent
```

---

> **Author:** André Henrique ([@mrhenrike](https://github.com/mrhenrike)) | **União Geek** — [https://github.com/Uniao-Geek](https://github.com/Uniao-Geek)