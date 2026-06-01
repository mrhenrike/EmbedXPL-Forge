# Modo Infra e Wizard de Infraestrutura

**Idioma:** Português (pt-BR). **English:** — *(página exclusiva pt-BR)*

---

## Visão geral

O **modo infra** (`--infra`) é um orquestrador de varredura baseado em contexto que seleciona automaticamente os módulos EmbedXPL mais relevantes com base no tipo e contexto da infraestrutura alvo. Ele é projetado para engajamentos onde a superfície de ataque é conhecida (OT/ICS, TI corporativa, SOHO, IoT) mas os módulos específicos não foram escolhidos manualmente.

Há duas formas de usar o modo infra:

1. **Modo wizard** (`--infra wizard`) — assistente interativo numerado que guia o usuário na seleção do tipo e contexto
2. **Modo direto** (`--infra <tipo> --context <contexto> --target <ip>`) — execução não interativa para automação e scripts

---

## Wizard interativo (`--infra wizard`)

### Sintaxe

```bash
embedxpl --infra wizard
```

### Fluxo do wizard

O wizard apresenta menus numerados em sequência:

**Passo 1 — Seleção do tipo de infraestrutura:**

```text
$ embedxpl --infra wizard

Select infrastructure type:
  1. ot    (Operational Technology / ICS/SCADA)
  2. it    (Enterprise IT)
  3. soho  (Small Office / Home Office)
  4. iot   (IoT/Embedded Edge)
Choice:
```

**Passo 2 — Seleção do contexto:**

```text
Choice: 1

Select context for 'ot':
  1. ics       (Industrial Control Systems)
  2. scada     (SCADA/HMI)
  3. plc       (PLC-focused)
  4. historian (Historian/Data Server)
  5. energy    (Energy / Smart Meters)
  6. building  (Building Automation BACnet/HVAC)
Choice:
```

**Passo 3 — Resultado do plano de varredura:**

```text
Choice: 1

[*] Scan plan ready: 18 modules for ot/ics

Modules selected:
  scanners/ics/modbus_scanner
  scanners/ics/bacnet_scanner
  scanners/ics/s7_comm_scanner
  scanners/ics/enip_scanner
  scanners/ics/dnp3_scanner
  scanners/ics/profinet_dcp_scanner
  scanners/ics/vxworks_scanner
  scanners/ics/rockwell_discover
  scanners/ics/modbus_id_fuzzer
  scanners/ics/cip_scanner
  scanners/ics/s7comm_plus_scanner
  exploits/ics/...
  creds/ics/...

[*] Use -m <module> -s "target <ip>" to run individual modules.
[*] Or launch interactive shell and type 'use <module>' to explore.
```

**Cancelamento com Ctrl+C:**

```text
^C
[!] Wizard cancelled by user.
```

---

## Modo direto (`--infra` + `--context` + `--target`)

### Sintaxe

```bash
embedxpl --infra <tipo> --context <contexto> --target <ip_ou_cidr>
```

### Parâmetros

| Flag | Tipo | Obrigatório | Descrição |
|------|------|-------------|-----------|
| `--infra` | string | Sim | Tipo de infraestrutura: `ot`, `it`, `soho`, `iot` |
| `--context` | string | Não | Contexto operacional dentro do tipo (veja tabela abaixo) |
| `--target` | string | Não | IP ou faixa CIDR alvo |

### Tipos de infraestrutura e contextos disponíveis

| Tipo (`--infra`) | Contextos disponíveis (`--context`) | Descrição |
|-----------------|-------------------------------------|-----------|
| `ot` | `ics`, `scada`, `plc`, `historian`, `energy`, `building` | Tecnologia Operacional / ICS/SCADA |
| `it` | `enterprise_network`, `hypervisor`, `bmc_ipmi`, `ups_power` | TI Corporativa |
| `soho` | `home`, `smb` | Escritório/Residência |
| `iot` | `home`, `cameras`, `printers`, `nas` | IoT/Embedded Edge |

### Exemplos de uso

**Plano OT/ICS:**

```text
$ embedxpl --infra ot --context ics --target 192.168.100.0/24

[*] OT/ICS scan plan for 192.168.100.0/24:
    18 modules selected

    Scan plan:
      scanners/ics/modbus_scanner
      scanners/ics/bacnet_scanner
      scanners/ics/s7_comm_scanner
      scanners/ics/enip_scanner
      scanners/ics/dnp3_scanner
      scanners/ics/profinet_dcp_scanner
      scanners/ics/vxworks_scanner
      scanners/ics/rockwell_discover
      scanners/ics/modbus_id_fuzzer
      scanners/ics/cip_scanner
      scanners/ics/s7comm_plus_scanner
      ...

[*] Use -m <module> -s "target 192.168.100.0/24" to run individual modules.
```

**Plano IT corporativo:**

```text
$ embedxpl --infra it --context enterprise_network --target 10.0.0.0/24

[*] Enterprise Network scan plan for 10.0.0.0/24:
    32 modules selected

    Scan plan:
      exploits/firewalls/fortinet/fortios_auth_bypass_cve_2022_40684
      exploits/firewalls/paloalto/globalprotect_auth_bypass_cve_2026_0257
      exploits/firewalls/fortinet/fortios_sslvpn_path_traversal_cve_2018_13379
      exploits/appliances/f5/bigip_icontrol_rest_rce_cve_2022_1388
      exploits/appliances/citrix/netscaler_rce_cve_2023_3519
      scanners/firewalls/fortinet/fortigate_sslvpn_scan
      creds/firewalls/...
      ...
```

**Plano BMC/IPMI:**

```text
$ embedxpl --infra it --context bmc_ipmi --target 10.1.0.0/24

[*] BMC/IPMI scan plan for 10.1.0.0/24:
    8 modules selected

    Scan plan:
      exploits/bmc/supermicro/ipmi_auth_bypass_cve_2013_4786
      exploits/bmc/dell/idrac9_info_disclosure_cve_2021_36300
      exploits/bmc/asus/asmb8_default_creds_ipmi
      scanners/bmc/bmc_discover
      creds/bmc/asus_asmb
      creds/bmc/dell_idrac
      creds/bmc/supermicro
      ...
```

**Plano SOHO:**

```text
$ embedxpl --infra soho --context home --target 192.168.1.0/24

[*] SOHO/Home scan plan for 192.168.1.0/24:
    24 modules selected

    Scan plan:
      exploits/routers/tplink/wr841n_credential_disclosure_cve_2023_50224
      exploits/routers/dlink/dir_300_600_rce
      exploits/routers/huawei/eg8145x6_csrf_static_token
      exploits/routers/zte/zxhn_h168n_rce_auth_bypass
      creds/routers/tplink/telnet_default_creds
      creds/routers/dlink/telnet_default_creds
      ...
```

---

## Casos de erro

**Tipo infra desconhecido:**

```text
$ embedxpl --infra unknown_type --context ics
[-] Unknown infra type 'unknown_type'. Valid: ot, it, soho, iot
```

**Infra válida, sem contexto (lista contextos disponíveis):**

```text
$ embedxpl --infra ot
[*] Available contexts for --infra ot:
  ics
  scada
  plc
  historian
  energy
  building
```

**Contexto desconhecido para o tipo infra:**

```text
$ embedxpl --infra ot --context invalid_context
[-] Unknown context 'invalid_context' for infra 'ot'.
    Available: ics, scada, plc, historian, energy, building
```

---

## Integração com catálogo `infra_profiles.yaml`

O modo infra é alimentado pelo arquivo `embedxpl/resources/infra_profiles.yaml`. Os perfis mapeiam tuplas `(infra, contexto)` para prefixos de caminho de módulo e critérios de correspondência adicionais.

Para adicionar um perfil personalizado, edite o arquivo YAML e adicione uma nova entrada seguindo o esquema existente:

```yaml
profiles:
  ot:
    ics:
      label: "ICS / SCADA"
      module_prefixes:
        - "exploits/ics/"
        - "scanners/ics/"
        - "creds/ics/"
        - "exploits/firewalls/siemens/"
        - "exploits/firewalls/moxa/"
      description: "Industrial Control Systems — Modbus, S7comm, EtherNet/IP, BACnet"
```

---

## Uso em modo não interativo via script

O modo infra é ideal para integração em pipelines de avaliação automatizados:

```bash
#!/bin/bash
# Exemplo de avaliação automatizada OT/ICS

TARGET="192.168.100.0/24"
REPORT_DIR="/tmp/assessment_$(date +%Y%m%d)"
mkdir -p "$REPORT_DIR"

# Gerar plano de varredura
embedxpl --infra ot --context ics --target "$TARGET" \
    2>&1 | tee "$REPORT_DIR/scan_plan.txt"

# Executar módulos individualmente
for module in \
    scanners/ics/modbus_scanner \
    scanners/ics/bacnet_scanner \
    scanners/ics/s7_comm_scanner; do
    embedxpl -m "$module" -s "target $TARGET" \
        2>&1 | tee "$REPORT_DIR/${module//\//_}.txt"
done

echo "Avaliação concluída. Relatórios em: $REPORT_DIR"
```

---

[Hub da Wiki](../README.md)
