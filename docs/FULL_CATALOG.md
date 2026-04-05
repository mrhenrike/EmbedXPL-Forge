# RouterXPL-Forge — Full Module Catalog

> Generated: 2026-04-05T05:04:38.857197+00:00
> Author: Andre Henrique (@mrhenrike) | Uniao Geek

## Summary

| Category | Modules | Vendor / group buckets |
|---|---:|---:|
| Exploits | 120 | 34 |
| Credential Modules | 88 | 38 |
| Scanners | 5 | 3 |
| Generic Modules | 20 | 7 |
| Encoders | 13 | 3 |
| Payloads | 32 | 9 |
| **Total Modules** | **278** | — |
| Distinct CVEs | 23 | — |

## Program footprint

Approximate on-disk size (file bytes only; binary prefixes). Walk skips caches such as ``__pycache__`` and ``.git``.

| Metric | Value |
|---|---|
| Repository root | `D:/Projetos-SafeLabs/submodules/IoT/RouterXPL-Forge` |
| Total file bytes | 1.80 GiB |
| Files (repo walk) | 55464 |
| Files under ``routerxpl/`` | 54786 |

### Largest top-level paths (repository)

| Path | Size | Share of total |
|---|---:|---:|
| `routerxpl` | 1.79 GiB | 99.7% |
| `docs` | 4.57 MiB | 0.2% |
| `tests` | 319.00 KiB | 0.0% |
| `tools` | 277.29 KiB | 0.0% |
| `routerxpl.egg-info` | 58.36 KiB | 0.0% |
| `(repo root files)` | 44.07 KiB | 0.0% |

### ``routerxpl/`` breakdown (first-level folders)

| Area | Size | Share of total |
|---|---:|---:|
| `resources` | 1.79 GiB | 99.7% |
| `modules` | 666.30 KiB | 0.0% |
| `core` | 226.88 KiB | 0.0% |
| `(routerxpl root files)` | 27.00 KiB | 0.0% |
| `libs` | 13.68 KiB | 0.0% |

### ``routerxpl/resources/*`` (largest direct children)

| Subfolder | Size | Share of total |
|---|---:|---:|
| `arsenal` | 1.68 GiB | 93.5% |
| `mibs` | 83.21 MiB | 4.5% |
| `catalogs` | 25.03 MiB | 1.4% |
| `vendors` | 4.52 MiB | 0.2% |
| `wordlists` | 44.91 KiB | 0.0% |
| `ssh_keys` | 9.89 KiB | 0.0% |
| `ml` | 1.22 KiB | 0.0% |

### First-party Python files (``.py`` count, excluding ``__pycache__``)

| Tree | Files |
|---|---:|
| `routerxpl/core` | 46 |
| `routerxpl/modules` | 365 |
| `routerxpl/libs` | 5 |
| `tools` | 37 |
| `rxf.py` | 1 |

---

## Exploits (120)

### 2wire (2)

1. **2Wire 4011G & 5012NV Path Traversal**
   - Path: `exploits/routers/2wire/4011g_5012nv_path_traversal.py`
   - Module exploits path traversal vulnerability in 2Wire 4011G and 5012NV devices. If the target is vulnerable it is possible to read file from the filesystem.
   - Devices: 2Wire 4011G, 2Wire 5012NV

2. **2Wire Gateway Auth Bypass**
   - Path: `exploits/routers/2wire/gateway_auth_bypass.py`
   - Module exploits 2Wire Gateway authentication bypass vulnerability. If the target is vulnerable link to bypass authentication is provided.
   - Devices: 2Wire 2701HGV-W, 2Wire 3800HGV-B, 2Wire 3801HGV

### 3com (5)

3. **3Com AP8760 Password Disclosure**
   - Path: `exploits/routers/3com/ap8760_password_disclosure.py`
   - Exploits 3Com AP8760 password disclosure vulnerability.If the target is vulnerable it is possible to fetch credentials for administration user.
   - Devices: 3Com AP8760

4. **3Com IMC Info Disclosure**
   - Path: `exploits/routers/3com/imc_info_disclosure.py`
   - Exploits 3Com Intelligent Management Center information disclosure vulnerability that allows to fetch credentials for SQL sa account
   - Devices: 3Com Intelligent Management Center

5. **3Com IMC Path Traversal**
   - Path: `exploits/routers/3com/imc_path_traversal.py`
   - Exploits 3Com Intelligent Management Center path traversal vulnerability. If the target is vulnerable it is possible to read file from the filesystem.
   - Devices: 3Com Intelligent Management Center

6. **3Com OfficeConnect Info Disclosure**
   - Path: `exploits/routers/3com/officeconnect_info_disclosure.py`
   - Exploits 3Com OfficeConnect information disclosure vulnerability. If the target is vulnerable it is possible to read sensitive information.
   - Devices: 3Com OfficeConnect

7. **3Com OfficeConnect RCE**
   - Path: `exploits/routers/3com/officeconnect_rce.py`
   - Module exploits 3Com OfficeConnect remote command execution vulnerability which allows executing command on operating system level.
   - Devices: 3Com OfficeConnect

### asmax (2)

8. **Asmax AR 804 RCE**
   - Path: `exploits/routers/asmax/ar_804_gu_rce.py`
   - Module exploits Asmax AR 804 Remote Code Execution vulnerability which allows executing command on operating system level with root privileges.
   - Devices: Asmax AR 804 gu

9. **Asmax AR1004G Password Disclosure**
   - Path: `exploits/routers/asmax/ar_1004g_password_disclosure.py`
   - Exploits Asmax AR1004G Password Disclosure vulnerability that allows to fetch credentials for: Admin, Support and User accounts.
   - Devices: Asmax AR 1004g

### asus (4)

10. **Asus B1M Projector RCE**
   - Path: `exploits/misc/asus/b1m_projector_rce.py`
   - Module exploits Asus B1M Projector Remote Code Execution vulnerability which allows executing command on operating system level with root privileges.
   - Devices: Asus B1M Projector

11. **Asus Infosvr Backdoor RCE**
   - Path: `exploits/routers/asus/infosvr_backdoor_rce.py`
   - Module exploits remote command execution in multiple ASUS devices. If the target is vulnerable, command loop is invoked that allows executing commands on operating system level.
   - Devices: ASUS RT-N66U, ASUS RT-AC87U, ASUS RT-N56U, ASUS RT-AC68U, ASUS DSL-N55U, ASUS DSL-AC68U, ASUS RT-AC66R, ASUS RT-AC66R, ASUS RT-AC55U, ASUS RT-N12HP_B1

12. **Asus RT-N16 Password Disclosure**
   - Path: `exploits/routers/asus/rt_n16_password_disclosure.py`
   - Module exploits password disclosure vulnerability in Asus RT-N16 devices that allows to fetch credentials for the device.
   - Devices: ASUS RT-N10U, firmware 3.0.0.4.374_168, ASUS RT-N56U, firmware 3.0.0.4.374_979, ASUS DSL-N55U, firmware 3.0.0.4.374_1397, ASUS RT-AC66U, firmware 3.0.0.4.374_2050, ASUS RT-N15U, firmware 3.0.0.4.374_16, ASUS RT-N53, firmware 3.0.0.4.374_311

13. **AsusWRT Lan RCE**
   - Path: `exploits/routers/asus/asuswrt_lan_rce.py`
   - Module exploits multiple vulnerabilities to achieve remote code execution in AsusWRT firmware. The HTTP server contains vulnerability that allows bypass authentication via POST requests. Combining thi
   - CVEs: CVE-2018-5999, CVE-2018-6000
   - Devices: AsusWRT < v3.0.0.4.384.10007

### belkin (6)

14. **Belkin Auth Bypass**
   - Path: `exploits/routers/belkin/auth_bypass.py`
   - Module exploits Belkin authentication using MD5 password disclosure.
   - Devices: Belkin Play Max (F7D4401), Belkin F5D8633, Belkin N900 (F9K1104), Belkin N300 (F7D7301), Belkin AC1200

15. **Belkin G & N150 Password Disclosure**
   - Path: `exploits/routers/belkin/g_n150_password_disclosure.py`
   - Module exploits Belkin G and N150 Password MD5 Disclosure vulnerability which allows fetching administration's password in md5 format
   - CVEs: CVE-2012-2765
   - Devices: Belkin G, Belkin N150

16. **Belkin G Info Disclosure**
   - Path: `exploits/routers/belkin/g_plus_info_disclosure.py`
   - Module exploits Belkin Wireless G Plus MIMO Router F5D9230-4 information disclosure vulnerability which allows fetching sensitive information such as credentials.
   - CVEs: CVE-2008-0403
   - Devices: Belkin G

17. **Belkin N150 Path Traversal**
   - Path: `exploits/routers/belkin/n150_path_traversal.py`
   - Module exploits Belkin N150 Path Traversal vulnerability which allows to read any file on the system.
   - Devices: Belkin N150 1.00.07, Belkin N150 1.00.08, Belkin N150 1.00.09

18. **Belkin N750 RCE**
   - Path: `exploits/routers/belkin/n750_rce.py`
   - Module exploits Belkin N750 Remote Code Execution vulnerability which allows executing commands on operation system level.
   - CVEs: CVE-2014-1635
   - Devices: Belkin N750

19. **Belkin Play Max Persistent RCE**
   - Path: `exploits/routers/belkin/play_max_prce.py`
   - Module exploits Belkin SSID injection vuln, allowing to execute arbitrary command at every boot.
   - Devices: Belkin Play Max (F7D4401)

### bhu (1)

20. **BHU uRouter RCE**
   - Path: `exploits/routers/bhu/bhu_urouter_rce.py`
   - Module exploits BHU uRouter unauthenticated remote code execution vulnerability, which allows executing commands on the router with root privileges.
   - Devices: BHU uRouter

### billion (2)

21. **Billion 5200W-T RCE**
   - Path: `exploits/routers/billion/billion_5200w_rce.py`
   - Module exploits Remote Command Execution vulnerability in Billion 5200W-T devices. If the target is vulnerable it allows to execute commands on operating system level.
   - Devices: Billion 5200W-T

22. **Billion 7700NR4 Password Disclosure**
   - Path: `exploits/routers/billion/billion_7700nr4_password_disclosure.py`
   - Exploits Billion 7700NR4 password disclosure vulnerability that allows to fetch credentials for admin account.
   - Devices: Billion 7700NR4

### cisco (4)

23. **Cisco Catalyst 2960 ROCEM RCE**
   - Path: `exploits/routers/cisco/catalyst_2960_rocem.py`
   - Module exploits Cisco Catalyst 2960 ROCEM RCE vulnerability. If target is vulnerable, it is possible to patch execution flow to allow credless telnet interaction with highest privilege level.
   - CVEs: CVE-2017-3881
   - Devices: Cisco Catalyst 2960 IOS 12.2(55)SE1, Cisco Catalyst 2960 IOS 12.2(55)SE11

24. **Cisco DPC2420 Info Disclosure**
   - Path: `exploits/routers/cisco/dpc2420_info_disclosure.py`
   - Module exploits Cisco DPC2420 information disclosure vulnerability which allows reading sensitive information from the configuration file.
   - Devices: Cisco DPC2420

25. **Cisco IOS HTTP Unauthorized Administrative Access**
   - Path: `exploits/routers/cisco/ios_http_authorization_bypass.py`
   - HTTP server for Cisco IOS 11.3 to 12.2 allows attackers to bypass authentication and execute arbitrary commands, when local authorization is being used, by specifying a high access level in the URL.
   - CVEs: CVE-2001-0537
   - Devices: IOS 11.3 -> 12.2 are reportedly vulnerable

26. **Cisco RV320 Command Injection**
   - Path: `exploits/routers/cisco/rv320_command_injection.py`
   - Module exploits Cisco RV320 Remote Command Injection vulnerability in the web-based certificate generator feature.
   - CVEs: CVE-2019-1652
   - Devices: Cisco RV320 from 1.4.2.15 to 1.4.2.22, Cisco RV325

### comtrend (1)

27. **Comtrend CT 5361T Password Disclosure**
   - Path: `exploits/routers/comtrend/ct_5361t_password_disclosure.py`
   - WiFi router Comtrend CT 5361T suffers from a Password Disclosure Vulnerability
   - Devices: Comtrend CT 5361T (more likely CT 536X)

### dlink (27)

28. **D-Link DCS-930L Auth RCE**
   - Path: `exploits/routers/dlink/dcs_930l_auth_rce.py`
   - Module exploits D-Link DCS-930L Remote Code Execution vulnerability which allows executing command on the device.
   - Devices: D-Link DCS-930L

29. **D-Link DGS-1510 Add User**
   - Path: `exploits/routers/dlink/dgs_1510_add_user.py`
   - D-Link DGS-1510-28XMP, DGS-1510-28X, DGS-1510-52X, DGS-1510-52, DGS-1510-28P, DGS-1510-28 and DGS-1510-20 Websmart devices with firmware before 1.31.B003 allow attackers to conduct Unauthenticated Inf
   - Devices: D-Link DGS-1510-28XMP, D-Link DGS-1510-28X, D-Link DGS-1510-52X, D-Link DGS-1510-52, D-Link DGS-1510-28P, D-Link DGS-1510-28, D-Link DGS-1510-20

30. **D-Link DIR-300 & DIR-320 & DIR-600 & DIR-615 Info Disclosure**
   - Path: `exploits/routers/dlink/dir_300_320_600_615_info_disclosure.py`
   - Module explois information disclosure vulnerability in D-Link DIR-300, DIR-320, DIR-600,DIR-615 devices. It is possible to retrieve sensitive information such as credentials.
   - Devices: D-Link DIR-300 (all), D-Link DIR-320 (all), D-Link DIR-600 (all), D-Link DIR-615 (fw 4.0)

31. **D-Link DIR-300 & DIR-320 & DIR-615 Auth Bypass**
   - Path: `exploits/routers/dlink/dir_300_320_615_auth_bypass.py`
   - Module exploits authentication bypass vulnerability in D-Link DIR-300, DIR-320, DIR-615 revD devices. It is possible to access administration panel without providing password.
   - Devices: D-Link DIR-300, D-Link DIR-600, D-Link DIR-615 revD

32. **D-Link DIR-300 & DIR-600 RCE**
   - Path: `exploits/routers/dlink/dir_300_600_rce.py`
   - Module exploits D-Link DIR-300, DIR-600 Remote Code Execution vulnerability which allows executing command on operating system level with root privileges.
   - Devices: D-Link DIR 300, D-Link DIR 600

33. **D-Link DIR-300 & DIR-645 & DIR-815 UPNP RCE**
   - Path: `exploits/routers/dlink/dir_300_645_815_upnp_rce.py`
   - Module exploits D-Link DIR-300, DIR-645 and DIR-815 UPNP Remote Code Execution vulnerability which allows executing command on the device.
   - Devices: D-Link DIR-300, D-Link DIR-645, D-Link DIR-815

34. **D-Link DIR-645 & DIR-815 RCE**
   - Path: `exploits/routers/dlink/dir_645_815_rce.py`
   - Module exploits D-Link DIR-645 and DIR-815 Remote Code Execution vulnerability which allows executing command on the device.
   - Devices: DIR-815 v1.03b02, DIR-645 v1.02, DIR-645 v1.03, DIR-600 below v2.16b01, DIR-300 revB v2.13b01, DIR-300 revB v2.14b01, DIR-412 Ver 1.14WWB02, DIR-456U Ver 1.00ONG, DIR-110 Ver 1.01

35. **D-Link DIR-645 Password Disclosure**
   - Path: `exploits/routers/dlink/dir_645_password_disclosure.py`
   - Module exploits D-Link DIR-645 password disclosure vulnerability.
   - Devices: D-Link DIR-645 (Versions < 1.03)

36. **D-Link DIR-815 & DIR-850L RCE**
   - Path: `exploits/routers/dlink/dir_815_850l_rce.py`
   - Module exploits D-Link DIR-815 and DIR-850L Remote Code Execution vulnerability which allows executing command on the device.
   - Devices: D-Link DIR-815, D-Link DIR-850L

37. **D-Link DIR-825 Path Traversal**
   - Path: `exploits/routers/dlink/dir_825_path_traversal.py`
   - Module exploits D-Link DIR-825 path traversal vulnerability, which allows reading files from the device.
   - Devices: D-Link DIR-825

38. **D-Link DIR-850L Creds Disclosure**
   - Path: `exploits/routers/dlink/dir_850l_creds_disclosure.py`
   - Module exploits D-Link DIR-850L credentials disclosure vulnerability, which allows retrieving administrative credentials.
   - Devices: D-Link DIR-850L

39. **D-Link DIR-8XX Password Disclosure**
   - Path: `exploits/routers/dlink/dir_8xx_password_disclosure.py`
   - Module exploits D-Link DIR-8XX password disclosure vulnerability, which allows retrieving administrative credentials.
   - Devices: D-Link DIR-8XX

40. **D-Link DNS-320L & DIR-327L RCE**
   - Path: `exploits/routers/dlink/dns_320l_327l_rce.py`
   - Module exploits D-Link DNS-320L, DNS-327L Remote Code Execution vulnerability which allows executing command on the device.
   - Devices: D-Link DNS-320L 1.03b04, D-Link DNS-327L, 1.02

41. **D-Link DSL-2640B DNS Change**
   - Path: `exploits/routers/dlink/dsl_2640b_dns_change.py`
   - Module exploits D-Link DSL-2640B dns change vulnerability. If the target is vulnerable it is possible to change dns settings.
   - Devices: D-Link DSL-2640B

42. **D-Link DSL-2730U/2750U/2750E Path Traversal**
   - Path: `exploits/routers/dlink/dsl_2730_2750_path_traversal.py`
   - Module exploits D-Link DSL-2730U/2750U/2750E Path Traversal vulnerability which allows to read any file on the system.
   - Devices: D-Link DSL-2730U, D-Link DSL-2750U, D-Link DSL-2750E

43. **D-Link DSL-2740R DNS Change**
   - Path: `exploits/routers/dlink/dsl_2740r_dns_change.py`
   - Module exploits D-Link DSL-2740R dns change vulnerability. If the target is vulnerable it is possible to change dns settings.
   - Devices: D-Link DSL-2740R

44. **D-Link DSL-2750B Info Disclosure**
   - Path: `exploits/routers/dlink/dsl_2750b_info_disclosure.py`
   - Module explois information disclosure vulnerability in D-Link DSL-2750B devices. It is possible to retrieve sensitive information such as SSID, Wi-Fi password, PIN code.
   - Devices: D-Link DSL-2750B EU_1.01

45. **D-Link DSL-2750B RCE**
   - Path: `exploits/routers/dlink/dsl_2750b_rce.py`
   - Module exploits remote code execution vulnerability in D-Link DSL-2750B devices.
   - Devices: D-Link DSL-2750B

46. **D-Link DSL-2780B & DSL-2730B & DSL-526B DNS Change**
   - Path: `exploits/routers/dlink/dsl_2730b_2780b_526b_dns_change.py`
   - Module exploits D-Link DSL-2780B, DSL-2730B and DSL-526B dns change vulnerability. If the target is vulnerable it is possible to change dns settings.
   - Devices: D-Link DSL-2780B, D-Link DSL-2730B, D-Link DSL-526B

47. **D-Link DSP-W110 RCE**
   - Path: `exploits/routers/dlink/dsp_w110_rce.py`
   - Module exploits D-Link DSP-W110 Remote Command Execution vulnerability which allows executing command on the operating system level.
   - Devices: D-Link DSP-W110 (Rev A) - v1.05b01

48. **D-Link DVG-N5402SP Path Traversal**
   - Path: `exploits/routers/dlink/dvg_n5402sp_path_traversal.py`
   - Module exploits D-Link DVG-N5402SP path traversal vulnerability, which allows reading files form the device.
   - Devices: D-Link DVG-N5402SP

49. **D-Link DWL-3200AP Password Disclosure**
   - Path: `exploits/routers/dlink/dwl_3200ap_password_disclosure.py`
   - Exploits D-Link DWL3200 access points weak cookie value.
   - Devices: D-Link DWL-3200AP

50. **D-Link DWR-932 Info Disclosure**
   - Path: `exploits/routers/dlink/dwr_932_info_disclosure.py`
   - Module explois information disclosure vulnerability in D-Link DWR-932 devices. It is possible to retrieve sensitive information such as credentials.
   - Devices: D-Link DWR-932

51. **D-Link DWR-932B**
   - Path: `exploits/routers/dlink/dwr_932b_backdoor.py`
   - Module exploits D-Link DWR-932B backdoor vulnerability which allows executing command on operating system level with root privileges.
   - Devices: D-Link DWR-932B

52. **D-Link Hedwig CGI RCE**
   - Path: `exploits/routers/dlink/multi_hedwig_cgi_exec.py`
   - Module exploits buffer overflow vulnerablity in D-Link Hedwig CGI component, which leads to remote code execution.
   - Devices: D-Link DIR-645 Ver. 1.03, D-Link DIR-300 Ver. 2.14, D-Link DIR-600

53. **D-Link Multi HNAP RCE**
   - Path: `exploits/routers/dlink/multi_hnap_rce.py`
   - Module exploits HNAP remote code execution vulnerability in multiple D-Link devices which allows executing commands on the device.
   - Devices: D-Link DIR-645, D-Link AP-1522 revB, D-Link DAP-1650 revB, D-Link DIR-880L, D-Link DIR-865L, D-Link DIR-860L revA, D-Link DIR-860L revB, D-Link DIR-815 revB, D-Link DIR-300 revB, D-Link DIR-600 revB

54. **D-Link PingTest RCE**
   - Path: `exploits/routers/dlink/dir_655_866_652_rce.py`
   - Module exploits unauthenticated remote code execution occurs in D-Link products such as DIR-655C, DIR-866L, DIR-652, and DHP-1565. The issue occurs when the attacker sends an arbitrary input to a "Pin
   - CVEs: CVE-2019-16920
   - Devices: DAP-1533 < v1.02B, DGL-5500 < v1.13b04, DIR-130 < v1.23b20, DIR-330 < v1.23b18, DIR-615 < v9.04NAb02, DIR-655 < v3.02b05, DIR-825 < v3.02, DIR-835 < v104b02Beta01, DIR-855L < v1.03b01, DIR-866L < v1.03b04

### heartbleed.py (1)

55. **OpenSSL Heartbleed**
   - Path: `exploits/generic/heartbleed.py`
   - Exploits OpenSSL Heartbleed vulnerability. Vulnerability exists in the handling of heartbeat requests, where fake length can be used to leak memory data in the response. This module is heavily based o
   - Devices: Multi

### hootoo (3)

56. **HooToo TripMate protocol.csp open_forwarding RCE**
   - Path: `exploits/routers/hootoo/tripmate_open_forwarding_rce.py`
   - Module exploits TripMate unauthenticated OS command injection vulnerability in protocol.csp, in function open_forwarding, which allows executing commands on the router with root privileges.
   - Devices: HooToo TripMate HT-TM01, firmware fw-WiFiDGRJ-HooToo-TM01-2.000.046, HooToo TripMate Nano HT-TM02, firmware fw-WiFiPort-HooToo-TM02-2.000.072, HooToo TripMate Mini HT-TM03, firmware fw-WiFiSDRJ-HooToo-TM03-2.000.016, HooToo TripMate Elite HT-TM04, firmware fw-WiFiDGRJ2-HooToo-TM04-2.000.008, HooToo TripMate Titan HT-TM05, firmware fw-7620-WiFiDGRJ-HooToo-HT-TM05-2.000.080.080, HooToo TripMate Elite U HT-TM06, firmware fw-7620-WiFiDGRJ-HooToo-633-HT-TM06-2.000.048

57. **HooToo TripMate sysfirm.csp RCE**
   - Path: `exploits/routers/hootoo/tripmate_sysfirm_rce.py`
   - Module exploits TripMate unauthenticated remote code execution vulnerability in sysfirm.csp, which allows executing commands on the router with root privileges.
   - Devices: HooToo TripMate HT-TM01, firmware fw-WiFiDGRJ-HooToo-TM01-2.000.046, HooToo TripMate Nano HT-TM02, firmware fw-WiFiPort-HooToo-TM02-2.000.072, HooToo TripMate Mini HT-TM03, firmware fw-WiFiSDRJ-HooToo-TM03-2.000.016, HooToo TripMate Elite HT-TM04, firmware fw-WiFiDGRJ2-HooToo-TM04-2.000.008, HooToo TripMate Titan HT-TM05, firmware fw-7620-WiFiDGRJ-HooToo-HT-TM05-2.000.080.080, HooToo TripMate Elite U HT-TM06, firmware fw-7620-WiFiDGRJ-HooToo-633-HT-TM06-2.000.048

58. **HooToo TripMate unauthenticated protocol.csp arbitrary file upload**
   - Path: `exploits/routers/hootoo/tripmate_arbitrary_file_upload.py`
   - Module exploits TripMate unauthenticated arbitrary file upload in protocol.csp to overwrite selected system files.
   - Devices: HooToo TripMate HT-TM01, firmware fw-WiFiDGRJ-HooToo-TM01-2.000.046, HooToo TripMate Nano HT-TM02, firmware fw-WiFiPort-HooToo-TM02-2.000.072, HooToo TripMate Mini HT-TM03, firmware fw-WiFiSDRJ-HooToo-TM03-2.000.016, HooToo TripMate Elite HT-TM04, firmware fw-WiFiDGRJ2-HooToo-TM04-2.000.008, HooToo TripMate Titan HT-TM05, firmware fw-7620-WiFiDGRJ-HooToo-HT-TM05-2.000.080.080, HooToo TripMate Elite U HT-TM06, firmware fw-7620-WiFiDGRJ-HooToo-633-HT-TM06-2.000.048

### http_form_char_by_char_oracle.py (1)

59. **HTTP Form Char-by-Char Oracle**
   - Path: `exploits/generic/http_form_char_by_char_oracle.py`
   - Generic framework for character-by-character password probing when the login page leaks a content or timing oracle. Not bound to a specific vendor/model/year in the market-priority catalog — you must 
   - Devices: Any in-scope device with a vulnerable web login oracle (lab-validated only)

### huawei (7)

60. **Huawei E5331 Info Disclosure**
   - Path: `exploits/routers/huawei/e5331_mifi_info_disclosure.py`
   - Module exploits information disclosure vulnerability in Huawei E5331 MiFi Mobile Hotspotdevices. If the target is vulnerable it allows to read sensitive information.
   - Devices: Huawei E5331 MiFi Mobile Hotspot

61. **Huawei HG520 Information Disclosure**
   - Path: `exploits/routers/huawei/hg520_info_disclosure.py`
   - Module exploits Huawei EchoLife HG520 information disclosure vulnerablity. If the target is vulnerable it is possible to retrieve sensitive information.
   - Devices: Huawei HG520

62. **Huawei HG530 & HG520b Password Disclosure**
   - Path: `exploits/routers/huawei/hg530_hg520b_password_disclosure.py`
   - Module exploits password disclosure vulnerability in Huawei HG530 and HG520b devices. If the target is vulnerable it allows to read credentials.
   - Devices: Huawei Home Gateway HG530, Huawei Home Gateway HG520b

63. **Huawei HG824* Authenticated Command Injection**
   - Path: `exploits/routers/huawei/hg8240_auth_rce.py`
   - Module exploits Huawei HG824* authenticated command injection vulnerability.
   - Devices: Huawei EchoLife HG8240 V1, Huawei EchoLife HG8245 V1, Huawei EchoLife HG8245Q

64. **Huawei HG824* File Traversal**
   - Path: `exploits/routers/huawei/hg8240_file_traversal.py`
   - Module exploits Huawei HG824* file traversal vulnerability allowing arbitrary file reads.
   - Devices: Huawei EchoLife HG8240 V1, Huawei EchoLife HG8245 V1, Huawei EchoLife HG8245Q

65. **Huawei HG866 Password Change**
   - Path: `exploits/routers/huawei/hg866_password_change.py`
   - Module exploits password change vulnerability in Huawei HG866 devices. If the target is vulnerable it allows to change administration password.
   - Devices: Huawei HG866

66. **Huawei Router HG532 RCE**
   - Path: `exploits/routers/huawei/hg532_rce.py`
   - Module exploits remote command execution in Huawei Router HG532 devices. If the target is vulnerable, command loop is invoked that allows executing commands on operating system level.
   - CVEs: CVE-2017-17215
   - Devices: Huawei HG532

### ipfire (3)

67. **IPFire Oinkcode RCE**
   - Path: `exploits/routers/ipfire/ipfire_oinkcode_rce.py`
   - Module exploits IPFire < 2.19 Core Update 110 Remote Code Execution vulnerability which allows executing command on operating system level.
   - Devices: IPFire < 2.19 Core Update 110

68. **IPFire Proxy RCE**
   - Path: `exploits/routers/ipfire/ipfire_proxy_rce.py`
   - Module exploits IPFire < 2.19 Core Update 101 Remote Code Execution vulnerability which allows executing commands on operating system level.
   - Devices: IPFire < 2.19 Core Update 101

69. **IPFire Shellshock**
   - Path: `exploits/routers/ipfire/ipfire_shellshock.py`
   - Exploits shellshock vulnerability in IPFire <= 2.15 Core Update 82. If the target is vulnerable it is possible to execute commands on operating system level.
   - Devices: IPFire <= 2.15 Core Update 82

### lg (1)

70. **LG_NAS_3718.510.a0_RCE**
   - Path: `exploits/routers/lg/nas_3718.py`
   - Module exploits LG-NAS Storage Remote Command Execution vulnerability in the web-based certificate generator feature.
   - Devices: 3718.510.a0

### linksys (5)

71. **Linksys E-Series TheMoon RCE**
   - Path: `exploits/routers/linksys/eseries_themoon_rce.py`
   - Module exploits remote code execution vulnerability in multiple Linksys E-Series devices. Vulnerability was actively used by TheMoon Worm.
   - Devices: Linksys E900, Linksys E1000, Linksys E1200, Linksys E1500, Linksys E1550, Linksys E2000, Linksys E2100L, Linksys E2500, Linksys E3000, Linksys E3200

72. **Linksys E1500/E2500**
   - Path: `exploits/routers/linksys/1500_2500_rce.py`
   - Module exploits remote command execution in Linksys E1500/E2500 devices. Diagnostics interface allows executing root privileged shell commands is available on dedicated web pages on the device.
   - Devices: Linksys E1500/E2500

73. **Linksys SMART WiFi Password Disclosure**
   - Path: `exploits/routers/linksys/smartwifi_password_disclosure.py`
   - Exploit implementation for Linksys SMART WiFi Password Disclosure vulnerability. If target is vulnerable administrator's MD5 passsword is retrieved.
   - CVEs: CVE-2014-8243
   - Devices: Linksys EA2700 < Ver.1.1.40 (Build 162751), Linksys EA3500 < Ver.1.1.40 (Build 162464), Linksys E4200v2 < Ver.2.1.41 (Build 162351), Linksys EA4500 < Ver.2.1.41 (Build 162351), Linksys EA6200 < Ver.1.1.41 (Build 162599), Linksys EA6300 < Ver.1.1.40 (Build 160989), Linksys EA6400 < Ver.1.1.40 (Build 160989), Linksys EA6500 < Ver.1.1.40 (Build 160989), Linksys EA6700 < Ver.1.1.40 (Build 160989), Linksys EA6900 < Ver.1.1.42 (Build 161129)

74. **Linksys WAP54Gv3**
   - Path: `exploits/routers/linksys/wap54gv3_rce.py`
   - Module exploits remote command execution in Linksys WAP54Gv3 devices. Debug interface allows executing root privileged shell commands is available on dedicated web pages on the device.
   - Devices: Linksys WAP54Gv3

75. **Linksys WRT100/WRT110 RCE**
   - Path: `exploits/routers/linksys/wrt100_110_rce.py`
   - Module exploits remote command execution in Linksys WRT100/WRT110 devices. If the target is vulnerable, command loop is invoked that allows executing commands on operating system level.
   - CVEs: CVE-2013-3568
   - Devices: Linksys WRT100, Linksys WRT110

### miele (1)

76. **Miele Professional PG 8528 Path Traversal**
   - Path: `exploits/misc/miele/pg8528_path_traversal.py`
   - Module exploits Miele Professional PG 8528 Path Traversal vulnerability which allows to read any file on the system.
   - CVEs: CVE-2017-7240
   - Devices: Miele Professional PG 8528 PST10

### mikrotik (2)

77. **Mikrotik RouterOS Jailbreak**
   - Path: `exploits/routers/mikrotik/routeros_jailbreak.py`
   - Module creates "devel" user on RouterOS from 2.9.8 to 6.41rc56.
   - Devices: Mikrotik RoutersOS versions from 2.9.8 up to 6.41rc56

78. **Mikrotik WinBox Auth Bypass - Creds Disclosure**
   - Path: `exploits/routers/mikrotik/winbox_auth_bypass_creds_disclosure.py`
   - Module bypass authentication through WinBox service in Mikrotik devices versions from 6.29 (release date: 2015/28/05) to 6.42 (release date 2018/04/20) and retrieves administrative credentials.
   - Devices: Mikrotik RouterOS versions from 6.29 (release date: 2015/28/05) to 6.42 (release date 2018/04/20)

### movistar (1)

79. **Movistar ADSL Router BHS_RTA Path Traversal**
   - Path: `exploits/routers/movistar/adsl_router_bhs_rta_path_traversal.py`
   - Module exploits Movistar ADSL Router BHS_RTA Path Traversal vulnerability which allows to read any file on the system.
   - Devices: Movistar ADSL Router BHS_RTA

### multi (5)

80. **GPON Home Gateway RCE**
   - Path: `exploits/routers/multi/gpon_home_gateway_rce.py`
   - Module exploits GPON Home Gatewa command injection vulnerability, that allows executing commands on operating system level.
   - Devices: GPON Home Gateway

81. **Misfortune Cookie**
   - Path: `exploits/routers/multi/misfortune_cookie.py`
   - Exploit implementation for Misfortune Cookie Authentication Bypass vulnerability.
   - CVEs: CVE-2014-9222
   - Devices: {'name': 'Azmoon     AZ-D140W        2.11.89.0(RE2.C29)3.11.11.52_PMOFF.1', 'number': 107367693, 'offset': 13}, {'name': 'Billion    BiPAC 5102S     Av2.7.0.23 (UE0.B1C)', 'number': 107369694, 'offset': 13}, {'name': 'Billion    BiPAC 5102S     Bv2.7.0.23 (UE0.B1C)', 'number': 107369694, 'offset': 13}, {'name': 'Billion    BiPAC 5200      2.11.84.0(UE2.C2)3.11.11.6', 'number': 107369545, 'offset': 9}, {'name': 'Billion    BiPAC 5200      2_11_62_2_ UE0.C2D_3_10_16_0', 'number': 107371218, 'offset': 21}, {'name': 'Billion    BiPAC 5200A     2_10_5 _0(RE0.C2)3_6_0_0', 'number': 107366366, 'offset': 25}, {'name': 'Billion    BiPAC 5200A     2_11_38_0 (RE0.C29)3_10_5_0', 'number': 107371453, 'offset': 9}, {'name': 'Billion    BiPAC 5200GR4   2.11.91.0(RE2.C29)3.11.11.52', 'number': 107367690, 'offset': 21}, {'name': 'Billion    BiPAC 5200SRD   2.10.5.0 (UE0.C2C) 3.6.0.0', 'number': 107368270, 'offset': 1}, {'name': 'Billion    BiPAC 5200SRD   2.12.17.0_UE2.C3_3.12.17.0', 'number': 107371378, 'offset': 37}

82. **RomPager ROM-0**
   - Path: `exploits/routers/multi/rom0.py`
   - Exploits RomPager ROM-0 authentication bypass vulnerability that allows downloading rom file and extract password without credentials.
   - Devices: AirLive WT-2000ARM (2.11.6.0(RE0.C29)3.7.6.1), D-Link DSL-2520U (1.08 Hardware Version: B1), D-Link DSL-2640R, D-Link DSL-2740R (EU_1.13 Hardware Version: A1), Huawei 520 HG, Huawei 530 TRA, Pentagram Cerberus P 6331-42, TP-Link TD-8816, TP-Link TD-8817 (3.0.1 Build 110402 Rel.02846), TP-LINK TD-8840T (3.0.0 Build 101208 Rel.36427)

83. **TCP-32764 Info Disclosure**
   - Path: `exploits/routers/multi/tcp_32764_info_disclosure.py`
   - Exploits backdoor functionality that allows fetching credentials for administrator user.
   - Devices: Cisco RVS4000 fwv 2.0.3.2 & 1.3.0.5, Cisco WAP4410N, Cisco WRVS4400N, Cisco WRVS4400N, Diamond DSL642WLG / SerComm IP806Gx v2 TI, LevelOne WBR3460B, Linksys RVS4000 Firmware V1.3.3.5, Linksys WAG120N, Linksys WAG160n v1 and v2, Linksys WAG200G

84. **TCP-32764 RCE**
   - Path: `exploits/routers/multi/tcp_32764_rce.py`
   - Exploits backdoor functionality that allows executing commands on operating system level.
   - Devices: Cisco RVS4000 fwv 2.0.3.2 & 1.3.0.5, Cisco WAP4410N, Cisco WRVS4400N, Cisco WRVS4400N, Diamond DSL642WLG / SerComm IP806Gx v2 TI, LevelOne WBR3460B, Linksys RVS4000 Firmware V1.3.3.5, Linksys WAG120N, Linksys WAG160n v1 and v2, Linksys WAG200G

### netcore (1)

85. **Netcore/Netis UDP 53413 RCE**
   - Path: `exploits/routers/netcore/udp_53413_rce.py`
   - Exploits Netcore/Netis backdoor functionality that allows executing commands on operating system level.
   - Devices: Netcore Router, Netis Router

### netgear (10)

86. **Netgear DGN2200 RCE**
   - Path: `exploits/routers/netgear/dgn2200_dnslookup_cgi_rce.py`
   - Exploits Netgear DGN2200 RCE vulnerability through dnslookup.cgi resource.
   - CVEs: CVE-2017-6334
   - Devices: Netgear DGN2200v1, Netgear DGN2200v2, Netgear DGN2200v3, Netgear DGN2200v4

87. **Netgear DGN2200 RCE**
   - Path: `exploits/routers/netgear/dgn2200_ping_cgi_rce.py`
   - Exploits Netgear DGN2200 RCE vulnerability in the ping.cgi script.
   - CVEs: CVE-2017-6077
   - Devices: Netgear DGN2200v1, Netgear DGN2200v2, Netgear DGN2200v3, Netgear DGN2200v4

88. **Netgear JNR1010 Path Traversal**
   - Path: `exploits/routers/netgear/jnr1010_path_traversal.py`
   - Module exploits Netgear JNR1010 Path Traversal vulnerability which allows to read any file on the system.
   - Devices: Netgear JNR1010

89. **Netgear Multi Password Disclosure**
   - Path: `exploits/routers/netgear/multi_password_disclosure-2017-5521.py`
   - Module exploits Password Disclosure vulnerability in multiple Netgear devices. If target is vulnerable administrator's password is retrieved. This exploit only works if 'password recovery' in router s
   - CVEs: CVE-2017-5521
   - Devices: Netgear D6220, Netgear D6400, Netgear R6200v2, Netgear R6250, Netgear R6300v2, Netgear R6400, Netgear R6700, Netgear R6900, Netgear R7000, Netgear R7100LG

90. **Netgear Multi RCE**
   - Path: `exploits/routers/netgear/multi_rce.py`
   - Module exploits remote command execution in multiple Netgear devices. If the target is vulnerable, command loop is invoked that allows executing commands on operating system level.
   - Devices: Netgear WG102, Netgear WG103, Netgear WN604, Netgear WNDAP350, Netgear WNDAP360, Netgear WNAP320, Netgear WNAP210, Netgear WNDAP660, Netgear WNDAP620, Netgear WNDAP380R

91. **Netgear N300 Auth Bypass**
   - Path: `exploits/routers/netgear/n300_auth_bypass.py`
   - Module exploits authentication bypass vulnerability in Netgear N300 devices. It is possible to access administration panel without providing password.
   - Devices: Netgear N300, Netgear JNR1010v2, Netgear JNR3000, Netgear JWNR2000v5, Netgear JWNR2010v5, Netgear R3250, Netgear WNR2020, Netgear WNR614, Netgear WNR618

92. **Netgear ProSafe RCE**
   - Path: `exploits/routers/netgear/prosafe_rce.py`
   - Module exploits remote command execution vulnerability in Netgear ProSafe WC9500, WC7600, WC7520 devices. If the target is vulnerable command shell is invoked.
   - Devices: Netgear ProSafe WC9500, Netgear ProSafe WC7600, Netgear ProSafe WC7520

93. **Netgear R7000 & R6400 RCE**
   - Path: `exploits/routers/netgear/r7000_r6400_rce.py`
   - Module exploits remote command execution in Netgear R7000 and R6400 devices. If the target is vulnerable, command loop is invoked that allows executing commands on operating system level.
   - Devices: R6400 (AC1750), R7000 Nighthawk (AC1900, AC2300), R7500 Nighthawk X4 (AC2350), R7800 Nighthawk X4S(AC2600), R8000 Nighthawk (AC3200), R8500 Nighthawk X8 (AC5300), R9000 Nighthawk X10 (AD7200)

94. **Netgear RAX30 RCE**
   - Path: `exploits/routers/netgear/rax30_rce.py`
   - Module exploits remote command execution in Netgear RAX30 devices. If the target is vulnerable, command loop is invoked that allows executing commands on operating system level.
   - Devices: Netgear RAX30

95. **Netgear WNR500/WNR612v3/JNR1010/JNR2010 Path Traversal**
   - Path: `exploits/routers/netgear/wnr500_612v3_jnr1010_2010_path_traversal.py`
   - Module exploits Netgear WNR500/WNR612v3/JNR1010/JNR2010 Path Traversal vulnerability which allows to read any file on the system.
   - Devices: Netgear WNR500, Netgear WNR612v3, Netgear JNR1010, Netgear JNR2010

### netsys (1)

96. **Netsys Multi RCE**
   - Path: `exploits/routers/netsys/multi_rce.py`
   - Exploits Netsys multiple remote command execution vulnerabilities that allows executing commands on operating system level.
   - Devices: Multiple Netsys

### shellshock.py (1)

97. **Shellshock**
   - Path: `exploits/generic/shellshock.py`
   - Exploits shellshock vulnerability that allows executing commands on operating system level.
   - CVEs: CVE-2014-6271, CVE-2014-6278, CVE-2014-7169
   - Devices: Multi

### shuttle (1)

98. **Shuttle 915 WM DNS Change**
   - Path: `exploits/routers/shuttle/915wm_dns_change.py`
   - Module exploits Shuttle Tech ADSL Modem-Router 915 WM dns change vulnerability. If the target is vulnerable it is possible to change dns settings.
   - Devices: Shuttle Tech ADSL Modem-Router 915 WM

### ssh_auth_keys.py (1)

99. **Multi SSH Authorized Keys**
   - Path: `exploits/generic/ssh_auth_keys.py`
   - Module exploits private key exposure vulnerability. If the target is vulnerable it is possible to authentiate to the device.
   - Devices: ExaGrid firmware < 4.8 P26, Quantum DXi V1000, Array Networks vxAG 9.2.0.34 and vAPV 8.3.2.17 appliances, Barracuda Load Balancer, Ceragon FibeAir IP-10, F5 BigIP, Loadbalancer.org Enterprise VA 7.5.2, Digital Alert Systems DASDEC and Monroe Electronics One-Net E189 Emergency Alert System

### technicolor (4)

100. **Technicolor DWG-855 Auth Bypass**
   - Path: `exploits/routers/technicolor/dwg855_authbypass.py`
   - Module exploits Technicolor DWG-855 Authentication Bypass vulnerability which allows changing administrator's password.  NOTE: This module will errase previous credentials, this is NOT stealthy.
   - Devices: Technicolor DWG-855

101. **Technicolor TC7200 Password Disclosure**
   - Path: `exploits/routers/technicolor/tc7200_password_disclosure.py`
   - Module exploits Technicolor TC7200 password disclosure vulnerability which allows fetching administration's password.
   - Devices: Technicolor TC7200

102. **Technicolor TC7200 Password Disclosure V2**
   - Path: `exploits/routers/technicolor/tc7200_password_disclosure_v2.py`
   - Module exploits Technicolor TC7200 password disclosure vulnerability which allows fetching administration's password.
   - Devices: Technicolor TC7200

103. **Technicolor TG784n-v3 Auth Bypass**
   - Path: `exploits/routers/technicolor/tg784_authbypass.py`
   - Module exploits Technicolor TG784n-v3 authentication bypass vulnerability.
   - Devices: Technicolor TG784n-v3, Unknown number of Technicolor and Thompson routers

### thomson (2)

104. **Thomson TWG849 Info Disclosure**
   - Path: `exploits/routers/thomson/twg849_info_disclosure.py`
   - Module exploits Thomson TWG849 information disclosure vulnerability which allows reading sensitive information.
   - Devices: Thomson TWG849

105. **Thomson TWG850 Password Disclosure**
   - Path: `exploits/routers/thomson/twg850_password_disclosure.py`
   - Module exploits Thomson TWG850 password disclosure vulnerability which allows fetching administration's password.
   - Devices: Thomson TWG850

### tplink (5)

106. **TP-Link Archer C2 & C20i**
   - Path: `exploits/routers/tplink/archer_c2_c20i_rce.py`
   - Exploits TP-Link Archer C2 and Archer C20i remote code execution vulnerability that allows executing commands on operating system level with root privileges.
   - Devices: TP-Link Archer C2, TP-Link Archer C20i

107. **TP-Link Archer C9 admin password reset (CVE-2017-11519)**
   - Path: `exploits/routers/tplink/archer_c9_admin_password_reset.py`
   - Module exploits TP-Link Archer C9 password reset feature by leveraging a predictable random number generator seed.
   - CVEs: CVE-2017-11519
   - Devices: TP-Link Archer C60, TP-Link Archer C9

108. **TP-Link WDR740ND & WDR740N Backdoor RCE**
   - Path: `exploits/routers/tplink/wdr740nd_wdr740n_backdoor.py`
   - Exploits TP-Link WDR740ND and WDR740N backdoor vulnerability that allows executing commands on operating system level.
   - Devices: TP-Link WDR740ND, TP-Link WDR740N

109. **TP-Link WDR740ND & WDR740N Path Traversal**
   - Path: `exploits/routers/tplink/wdr740nd_wdr740n_path_traversal.py`
   - Exploits TP-Link WDR740ND and WDR740N path traversal vulnerabilitythat allowsto read files from the filesystem.
   - Devices: TP-Link WDR740ND, TP-Link WDR740N

110. **TP-Link WDR842ND configure Disclosure**
   - Path: `exploits/routers/tplink/wdr842nd_wdr842n_configure_disclosure.py`
   - Module exploits TP-Link WDR842ND configure disclosure vulnerability which allows fetching configure.
   - Devices: TP-Link WDR842ND

### ubiquiti (1)

111. **AirOS 6.x - Arbitrary File Upload**
   - Path: `exploits/routers/ubiquiti/airos_6_x.py`
   - Exploit implementation for AirOS 6.x - Arbitrary File Upload. If the target is vulnerable is possible to take full control of the router.
   - Devices: AirOS 6.x

### wepresent (1)

112. **WePresent WiPG-1000 RCE**
   - Path: `exploits/misc/wepresent/wipg1000_rce.py`
   - Module exploits WePresent WiPG-1000 Command Injection vulnerability which allows executing commands on operating system level.
   - Devices: WePresent WiPG-1000 <=2.0.0.7

### zte (4)

113. **ZTE F460 & F660 Backdoor RCE**
   - Path: `exploits/routers/zte/f460_f660_backdoor.py`
   - Exploits ZTE F460 and F660 backdoor vulnerability that allows executing commands on operating system level.
   - Devices: ZTE F460, ZTE F660

114. **ZTE ZXHN H108N Wifi Password Disclosure**
   - Path: `exploits/routers/zte/zxhn_h108n_wifi_password_disclosure.py`
   - Module exploits ZTE ZXHN H108N WiFi Password Disclosure vulnerability that allows to retrieve password for wifi connection.
   - Devices: ZTE ZXHN H108N

115. **ZTE ZXV10 RCE**
   - Path: `exploits/routers/zte/zxv10_rce.py`
   - Exploits ZTE ZXV10 H108L remote code execution vulnerability that allows executing commands on operating system level.
   - Devices: ZTE ZXV10 H108L

116. **ZTE ZXV10 W812N Information Disclosure**
   - Path: `exploits/routers/zte/zxv10_w812n.py`
   - Exploits ZTE ZXV10 W812N information disclosure vulnerability that allows downloading configuration.
   - Devices: ZTE ZXV10 W812N V2

### zyxel (4)

117. **Zyxel Eir D1000 RCE**
   - Path: `exploits/routers/zyxel/d1000_rce.py`
   - Module exploits Remote Command Execution vulnerability in Zyxel/Eir D1000 devices. If the target is vulnerable it allows to execute commands on operating system level.
   - Devices: Zyxel EIR D1000

118. **Zyxel Eir D1000 WiFi Password Disclosure**
   - Path: `exploits/routers/zyxel/d1000_wifi_password_disclosure.py`
   - Module exploits WiFi Password Disclosure vulnerability in Zyxel/Eir D1000 devices. If the target is vulnerable it allows to read WiFi password.
   - Devices: Zyxel EIR D1000

119. **Zyxel P660HN-T v1 RCE**
   - Path: `exploits/routers/zyxel/p660hn_t_v1_rce.py`
   - Module exploits Remote Command Execution vulnerability in Zyxel P660HN-T v1 devices. If the target is vulnerable it allows to execute commands on operating system level.
   - Devices: Zyxel P660HN-T v1

120. **Zyxel P660HN-T v2 RCE**
   - Path: `exploits/routers/zyxel/p660hn_t_v2_rce.py`
   - Module exploits Remote Command Execution vulnerability in Zyxel P660HN-T V2 devices. If the target is vulnerable it allows to execute commands on operating system level.
   - Devices: Zyxel P660HN-T v2

## Credential Modules (88)

### 2wire (3)

1. **2Wire Router Default FTP Creds**
   - Path: `creds/routers/2wire/ftp_default_creds.py`
   - Module performs dictionary attack against 2Wire Router FTP service. If valid credentials are found, they are displayed to the user.
   - Devices: 2Wire Router

2. **2Wire Router Default SSH Creds**
   - Path: `creds/routers/2wire/ssh_default_creds.py`
   - Module performs dictionary attack against 2Wire Router SSH service. If valid credentials are found, they are displayed to the user.
   - Devices: 2Wire Router

3. **2Wire Router Default Telnet Creds**
   - Path: `creds/routers/2wire/telnet_default_creds.py`
   - Module performs dictionary attack against Asmax Router Telnet service. If valid credentials are found, they are displayed to the user.
   - Devices: 2Wire Router

### 3com (3)

4. **3Com Router Default FTP Creds**
   - Path: `creds/routers/3com/ftp_default_creds.py`
   - Module performs dictionary attack against 3Com Router FTP service. If valid credentials are found, they are displayed to the user.
   - Devices: 3Com Router

5. **3Com Router Default SSH Creds**
   - Path: `creds/routers/3com/ssh_default_creds.py`
   - Module performs dictionary attack against 3Com Router SSH service. If valid credentials are found, they are displayed to the user.
   - Devices: 3Com Router

6. **3Com Router Default Telnet Creds**
   - Path: `creds/routers/3com/telnet_default_creds.py`
   - Module performs dictionary attack against 3Com Router Telnet service. If valid credentials are found, they are displayed to the user.
   - Devices: 3Com Router

### asmax (4)

7. **Asmax Router Default FTP Creds**
   - Path: `creds/routers/asmax/ftp_default_creds.py`
   - Module performs dictionary attack against Asmax Router FTP service. If valid credentials are found, they are displayed to the user.
   - Devices: Asmax Router

8. **Asmax Router Default SSH Creds**
   - Path: `creds/routers/asmax/ssh_default_creds.py`
   - Module performs dictionary attack against Asmax Router SSH service. If valid credentials are found, they are displayed to the user.
   - Devices: Asmax Router

9. **Asmax Router Default Telnet Creds**
   - Path: `creds/routers/asmax/telnet_default_creds.py`
   - Module performs dictionary attack against Asmax Router Telnet service. If valid credentials are found, they are displayed to the user.
   - Devices: Asmax Router

10. **Asmax Router Default Web Interface Creds - HTTP Auth**
   - Path: `creds/routers/asmax/webinterface_http_auth_default_creds.py`
   - Module performs dictionary attack against Asmax Router web interface. If valid credentials are found, they are displayed to the user.
   - Devices: Asmax Router

### asus (3)

11. **Asus Router Default FTP Creds**
   - Path: `creds/routers/asus/ftp_default_creds.py`
   - Module performs dictionary attack against Asus Router FTP service. If valid credentials are found, they are displayed to the user.
   - Devices: Asus Router

12. **Asus Router Default SSH Creds**
   - Path: `creds/routers/asus/ssh_default_creds.py`
   - Module performs dictionary attack against Asus Router SSH service. If valid credentials are found, they are displayed to the user.
   - Devices: Asus Router

13. **Asus Router Default Telnet Creds**
   - Path: `creds/routers/asus/telnet_default_creds.py`
   - Module performs dictionary attack against Asus Router Telnet service. If valid credentials are found, they are displayed to the user.
   - Devices: Asus Router

### belkin (3)

14. **Belkin Router Default FTP Creds**
   - Path: `creds/routers/belkin/ftp_default_creds.py`
   - Module performs dictionary attack against Belkin Router FTP service. If valid credentials are found, they are displayed to the user.
   - Devices: Belkin Router

15. **Belkin Router Default SSH Creds**
   - Path: `creds/routers/belkin/ssh_default_creds.py`
   - Module performs dictionary attack against Belkin Router SSH service. If valid credentials are found, they are displayed to the user.
   - Devices: Belkin Router

16. **Belkin Router Default Telnet Creds**
   - Path: `creds/routers/belkin/telnet_default_creds.py`
   - Module performs dictionary attack against Belkin Router Telnet service. If valid credentials are found, they are displayed to the user.
   - Devices: Belkin Router

### bhu (3)

17. **Belkin Router Default FTP Creds**
   - Path: `creds/routers/bhu/ftp_default_creds.py`
   - Module performs dictionary attack against Belkin Router FTP service. If valid credentials are found, they are displayed to the user.
   - Devices: Belkin Router

18. **Belkin Router Default SSH Creds**
   - Path: `creds/routers/bhu/ssh_default_creds.py`
   - Module performs dictionary attack against Belkin Router SSH service. If valid credentials are found, they are displayed to the user.
   - Devices: Belkin Router

19. **Belkin Router Telnet Creds**
   - Path: `creds/routers/bhu/telnet_default_creds.py`
   - Module performs dictioanry attack against Belkin Router Telnet service. If valid credentials are found, they are displayed to the user.
   - Devices: Belkin Router

### billion (3)

20. **Billion Router Default FTP Creds**
   - Path: `creds/routers/billion/ftp_default_creds.py`
   - Module performs dictionary attack against Billion Router FTP service. If valid credentials are found, they are displayed to the user.
   - Devices: Billion Router

21. **Billion Router Default SSH Creds**
   - Path: `creds/routers/billion/ssh_default_creds.py`
   - Module performs dictionary attack against Billion Router SSH service. If valid credentials are found, they are displayed to the user.
   - Devices: Billion Router

22. **Billion Router Default Telnet Creds**
   - Path: `creds/routers/billion/telnet_default_creds.py`
   - Module performs dictionary attack against Billion Router Telnet service. If valid credentials are found, they are displayed to the user.
   - Devices: Billion Router

### cisco (3)

23. **Cisco Router Default FTP Creds**
   - Path: `creds/routers/cisco/ftp_default_creds.py`
   - Module performs dictionary attack against Cisco Router FTP service. If valid credentials are found, they are displayed to the user.
   - Devices: Cisco Router

24. **Cisco Router Default SSH Creds**
   - Path: `creds/routers/cisco/ssh_default_creds.py`
   - Module performs dictionary attack against Cisco Router SSH service. If valid credentials are found, they are displayed to the user.
   - Devices: Cisco Router

25. **Cisco Router Default Telnet Creds**
   - Path: `creds/routers/cisco/telnet_default_creds.py`
   - Module performs dictionary attack against Cisco Router Telnet service. If valid credentials are found, they are displayed to the user.
   - Devices: Cisco Router

### comtrend (3)

26. **Comtrend Router Default FTP Creds**
   - Path: `creds/routers/comtrend/ftp_default_creds.py`
   - Module performs dictionary attack against Comtrend Router FTP service. If valid credentials are found, they are displayed to the user.
   - Devices: Comtrend Router

27. **Comtrend Router Default SSH Creds**
   - Path: `creds/routers/comtrend/ssh_default_creds.py`
   - Module performs dictionary attack against Comtrend Router SSH service. If valid credentials are found, they are displayed to the user.
   - Devices: Comtrend Router

28. **Comtrend Router Default Telnet Creds**
   - Path: `creds/routers/comtrend/telnet_default_creds.py`
   - Module performs dictionary attack against Comtrend Router Telnet service. If valid credentials are found, they are displayed to the user.
   - Devices: Comtrend Router

### dlink (3)

29. **D-Link Router Default FTP Creds**
   - Path: `creds/routers/dlink/ftp_default_creds.py`
   - Module performs dictionary attack against D-Link Router FTP service. If valid credentials are found, they are displayed to the user.
   - Devices: D-Link Router

30. **D-Link Router Default SSH Creds**
   - Path: `creds/routers/dlink/ssh_default_creds.py`
   - Module performs dictionary attack against D-Link Router SSH service. If valid credentials are found, they are displayed to the user.
   - Devices: D-Link Router

31. **D-Link Router Default Telnet Creds**
   - Path: `creds/routers/dlink/telnet_default_creds.py`
   - Module performs dictionary attack against D-Link Router Telnet service. If valid credentials are found, they are displayed to the user.
   - Devices: D-Link Router

### ftp_bruteforce.py (1)

32. **FTP Bruteforce**
   - Path: `creds/generic/ftp_bruteforce.py`
   - Module performs bruteforce attack against FTP service.If valid credentials are found, the are displayed to the user.
   - Devices: Multiple devices

### ftp_default.py (1)

33. **FTP Default Creds**
   - Path: `creds/generic/ftp_default.py`
   - Module performs dictionary attack with default credentials against FTP service.If valid credentials are found, the are displayed to the user.
   - Devices: Multiple devices

### http_basic_digest_bruteforce.py (1)

34. **HTTP Basic/Digest Bruteforce**
   - Path: `creds/generic/http_basic_digest_bruteforce.py`
   - Module performs bruteforce attack against HTTP Basic/Digest Auth service. If valid credentials are found, they are displayed to the user.
   - Devices: Multiple devices

### http_basic_digest_default.py (1)

35. **HTTP Basic/Digest Default Creds**
   - Path: `creds/generic/http_basic_digest_default.py`
   - Module performs dictionary attack with default credentials against HTTP Basic/Digest Auth service. If valid credentials are found, they are displayed to the user.
   - Devices: Multiple devices

### http_multi_auth_default.py (1)

36. **HTTP/HTTPS Multi-Auth Default Creds**
   - Path: `creds/generic/http_multi_auth_default.py`
   - Module validates multiple HTTP auth methods (basic, digest, bearer, custom headers, form).
   - Devices: Routers, Switches, TAPs, FW, NGFW

### http_web_form_bruteforce.py (1)

37. **HTTP Web Form Bruteforce (Hydra-style)**
   - Path: `creds/generic/http_web_form_bruteforce.py`
   - Dictionary attack against HTTP/HTTPS login forms. Set failure/success body substrings, status codes, or Location fragments—similar to Hydra/JtR web modules. Respect rate limits and authorization; for 
   - Devices: Routers, Switches, Gateways, CPE

### huawei (3)

38. **Huawei Router Default FTP Creds**
   - Path: `creds/routers/huawei/ftp_default_creds.py`
   - Module performs dictionary attack against Huawei Router FTP service. If valid credentials are found, they are displayed to the user.
   - Devices: Huawei Router

39. **Huawei Router Default SSH Creds**
   - Path: `creds/routers/huawei/ssh_default_creds.py`
   - Module performs dictionary attack against Huawei Router SSH service. If valid credentials are found, they are displayed to the user.
   - Devices: Huawei Router

40. **Huawei Router Default Telnet Creds**
   - Path: `creds/routers/huawei/telnet_default_creds.py`
   - Module performs dictionary attack against Huawei Router Telnet service. If valid credentials are found, they are displayed to the user.
   - Devices: Huawei Router

### juniper (3)

41. **Juniper Router Default FTP Creds**
   - Path: `creds/routers/juniper/ftp_default_creds.py`
   - Module performs dictionary attack against Juniper Router FTP service. If valid credentials are foundm they are displayed to the user.
   - Devices: Juniper Router

42. **Juniper Router Default SSH Creds**
   - Path: `creds/routers/juniper/ssh_default_creds.py`
   - Module performs dictionary attack against Juniper Router SSH service. If valid credentials are foundm they are displayed to the user.
   - Devices: Juniper Router

43. **Juniper Router Default Telnet Creds**
   - Path: `creds/routers/juniper/telnet_default_creds.py`
   - Module performs dictionary attack against Juniper Router Telnet service. If valid credentials are foundm they are displayed to the user.
   - Devices: Juniper Router

### linksys (3)

44. **Linksys Router Default FTP Creds**
   - Path: `creds/routers/linksys/ftp_default_creds.py`
   - Module performs dictionary attack against Linksys Router FTP service.If valid credentials are found, they are displayed to the user.
   - Devices: Linksys Router

45. **Linksys Router Default SSH Creds**
   - Path: `creds/routers/linksys/ssh_default_creds.py`
   - Module performs dictionary attack against Linksys Router SSH service.If valid credentials are found, they are displayed to the user.
   - Devices: Linksys Router

46. **Linksys Router Default Telnet Creds**
   - Path: `creds/routers/linksys/telnet_default_creds.py`
   - Module performs dictionary attack against Linksys Router Telnet service.If valid credentials are found, they are displayed to the user.
   - Devices: Linksys Router

### mikrotik (4)

47. **Mikrotik Default Creds - API ROS**
   - Path: `creds/routers/mikrotik/api_ros_default_creds.py`
   - Module performs dictionary attack against Mikrotik API and API-SSL. If valid credentials are found they are displayed to the user.
   - Devices: Mikrotik Router

48. **Mikrotik Router Default FTP Creds**
   - Path: `creds/routers/mikrotik/ftp_default_creds.py`
   - Module performs dictionary attack against Mikrotik Router FTP service.If valid credentials are found they are displayed to the user.
   - Devices: Mikrotik Router

49. **Mikrotik Router Default SSH Creds**
   - Path: `creds/routers/mikrotik/ssh_default_creds.py`
   - Module performs dictionary attack against Mikrotik Router SSH service.If valid credentials are found they are displayed to the user.
   - Devices: Mikrotik Router

50. **Mikrotik Router Default Telnet Creds**
   - Path: `creds/routers/mikrotik/telnet_default_creds.py`
   - Module performs dictionary attack against Mikrotik Router Telnet service.If valid credentials are found they are displayed to the user.
   - Devices: Mikrotik Router

### movistar (3)

51. **Movistar Router Default FTP Creds**
   - Path: `creds/routers/movistar/ftp_default_creds.py`
   - Module performs dictionary attack against Movistar Router FTP service.If valid credentials are found, they are displayed to the user.
   - Devices: Movistar Router

52. **Movistar Router Default SSH Creds**
   - Path: `creds/routers/movistar/ssh_default_creds.py`
   - Module performs dictionary attack against Movistar Router SSH service.If valid credentials are found, they are displayed to the user.
   - Devices: Movistar Router

53. **Movistar Router Default Telnet Creds**
   - Path: `creds/routers/movistar/telnet_default_creds.py`
   - Module performs dictionary attack against Movistar Router Telnet service.If valid credentials are found, they are displayed to the user.
   - Devices: Movistar Router

### netcore (3)

54. **Netcore Router Default FTP Creds**
   - Path: `creds/routers/netcore/ftp_default_creds.py`
   - Module performs dictionary attack against Netcore Router FTP service.If valid credentials are found, they are displayed to the user.
   - Devices: Netcore Router

55. **Netcore Router Default SSH Creds**
   - Path: `creds/routers/netcore/ssh_default_creds.py`
   - Module performs dictionary attack against Netcore Router SSH service.If valid credentials are found, they are displayed to the user.
   - Devices: Netcore Router

56. **Netcore Router Default Telnet Creds**
   - Path: `creds/routers/netcore/telnet_default_creds.py`
   - Module performs dictionary attack against Netcore Router Telnet service.If valid credentials are found, they are displayed to the user.
   - Devices: Netcore Router

### netgear (3)

57. **Netgear Router Default FTP Creds**
   - Path: `creds/routers/netgear/ftp_default_creds.py`
   - Module performs dictionary attack against Netgear Router FTP service. If valid credentials are found, they are displayed to the user.
   - Devices: Netgear Router

58. **Netgear Router Default SSH Creds**
   - Path: `creds/routers/netgear/ssh_default_creds.py`
   - Module performs dictionary attack against Netgear Router SSH service. If valid credentials are found, they are displayed to the user.
   - Devices: Netgear Router

59. **Netgear Router Default Telnet Creds**
   - Path: `creds/routers/netgear/telnet_default_creds.py`
   - Module performs dictionary attack against Netgear Router Telnet service. If valid credentials are found, they are displayed to the user.
   - Devices: Netgear Router

### netsys (3)

60. **Netsys Router Default FTP Creds**
   - Path: `creds/routers/netsys/ftp_default_creds.py`
   - Module performs dictionary attack against Netsys Router FTP service. If valid credentials are found, they are displayed to the user.
   - Devices: Netsys Router

61. **Netsys Router Default SSH Creds**
   - Path: `creds/routers/netsys/ssh_default_creds.py`
   - Module performs dictionary attack against Netsys Router SSH service. If valid credentials are found, they are displayed to the user.
   - Devices: Netsys Router

62. **Netsys Router Default Telnet Creds**
   - Path: `creds/routers/netsys/telnet_default_creds.py`
   - Module performs dictionary attack against Netsys Router Telnet service. If valid credentials are found, they are displayed to the user.
   - Devices: Netsys Router

### sftp_bruteforce.py (1)

63. **SFTP Bruteforce**
   - Path: `creds/generic/sftp_bruteforce.py`
   - Module performs bruteforce attack against SFTP service. If valid credentials are found, they are displayed to the user.
   - Devices: Multiple devices

### sftp_default.py (1)

64. **SFTP Default Creds**
   - Path: `creds/generic/sftp_default.py`
   - Module performs dictionary attack with default credentials against SFTP service. If valid credentials are found, they are displayed to the user.
   - Devices: Multiple devices

### snmp_bruteforce.py (1)

65. **SNMP Bruteforce**
   - Path: `creds/generic/snmp_bruteforce.py`
   - Module performs bruteforce attack against SNMP service. If valid community string is found, it is displayed to the user
   - Devices: Multiple devices

### snmpv3_default.py (1)

66. **SNMPv3 Default Creds**
   - Path: `creds/generic/snmpv3_default.py`
   - Module validates default SNMPv3 credentials against target service.
   - Devices: Routers, Switches, TAPs, FW, NGFW

### ssh_bruteforce.py (1)

67. **SSH Bruteforce**
   - Path: `creds/generic/ssh_bruteforce.py`
   - Module performs bruteforce attack against SSH service. If valid credentials are found, they are displayed to the user.
   - Devices: Multiple devices

### ssh_default.py (1)

68. **SSH Default Creds**
   - Path: `creds/generic/ssh_default.py`
   - Module performs bruteforce attack against SSH service. If valid credentials are found, they are displayed to the user.
   - Devices: Multiple devices

### technicolor (3)

69. **Technicolor Router Default FTP Creds**
   - Path: `creds/routers/technicolor/ftp_default_creds.py`
   - Module performs dictionary attack against Technicolor Router FTP service. If valid credentials are found, they are displayed to the user.
   - Devices: Technicolor Router

70. **Technicolor Router Default SSH Creds**
   - Path: `creds/routers/technicolor/ssh_default_creds.py`
   - Module performs dictionary attack against Technicolor Router SSH service. If valid credentials are found, they are displayed to the user.
   - Devices: Technicolor Router

71. **Technicolor Router Default Telnet Creds**
   - Path: `creds/routers/technicolor/telnet_default_creds.py`
   - Module performs dictionary attack against Technicolor Router Telnet service. If valid credentials are found, they are displayed to the user.
   - Devices: Technicolor Router

### telnet_bruteforce.py (1)

72. **Telnet Bruteforce**
   - Path: `creds/generic/telnet_bruteforce.py`
   - Module performs bruteforce attack against Telnet service. If valid credentials are found, they are displayed to the user.
   - Devices: Multiple devices

### telnet_default.py (1)

73. **Telnet Default Creds**
   - Path: `creds/generic/telnet_default.py`
   - Module performs dictionary attack with default credentials against Telnet service. If valid credentials are found, they are displayed to the user.
   - Devices: Multiple devices

### thomson (3)

74. **Thomson Router Default FTP Creds**
   - Path: `creds/routers/thomson/ftp_default_creds.py`
   - Module performs dictionary attack against Thomson Router FTP service. If valid credentials are found, they are displayed to the user.
   - Devices: Thomson Router

75. **Thomson Router Default SSH Creds**
   - Path: `creds/routers/thomson/ssh_default_creds.py`
   - Module performs dictionary attack against Thomson Router SSH service. If valid credentials are found, they are displayed to the user.
   - Devices: Thomson Router

76. **Thomson Router Default Telnet Creds**
   - Path: `creds/routers/thomson/telnet_default_creds.py`
   - Module performs dictionary attack against Thomson Router Telnet service. If valid credentials are found, they are displayed to the user.
   - Devices: Thomson Router

### tplink (3)

77. **TP-Link Router Default FTP Creds**
   - Path: `creds/routers/tplink/ftp_default_creds.py`
   - Module performs dictionary attack against TP-Link Router FTP service. If valid credentials are found, they are displayed to the user.
   - Devices: TP-Link Router

78. **TP-Link Router Default SSH Creds**
   - Path: `creds/routers/tplink/ssh_default_creds.py`
   - Module performs dictionary attack against TP-Link Router SSH service. If valid credentials are found, they are displayed to the user.
   - Devices: TP-Link Router

79. **TP-Link Router Default Telnet Creds**
   - Path: `creds/routers/tplink/telnet_default_creds.py`
   - Module performs dictionary attack against TP-Link Router Telnet service. If valid credentials are found, they are displayed to the user.
   - Devices: TP-Link Router

### ubiquiti (3)

80. **Ubiquiti Router Default FTP Creds**
   - Path: `creds/routers/ubiquiti/ftp_default_creds.py`
   - Module performs dictionary attack against Ubiquiti Router FTP service. If valid credentials are found, they are displayed to the user.
   - Devices: Ubiquiti Router

81. **Ubiquiti Router Default SSH Creds**
   - Path: `creds/routers/ubiquiti/ssh_default_creds.py`
   - Module performs dictionary attack against Ubiquiti Router SSH service. If valid credentials are found, they are displayed to the user.
   - Devices: Ubiquiti Router

82. **Ubiquiti Router Default Telnet Creds**
   - Path: `creds/routers/ubiquiti/telnet_default_creds.py`
   - Module performs dictionary attack against Ubiquiti Router Telnet service. If valid credentials are found, they are displayed to the user.
   - Devices: Ubiquiti Router

### zte (3)

83. **ZTE Router Default FTP Creds**
   - Path: `creds/routers/zte/ftp_default_creds.py`
   - Module performs dictioanry attack against ZTE Router FTP service. If valid credentials are found, they are displayed to the user.
   - Devices: ZTE Router

84. **ZTE Router Default SSH Creds**
   - Path: `creds/routers/zte/ssh_default_creds.py`
   - Module performs dictionary attack against ZTE Router SSH service. If valid credentials are found, they are displayed to the user.
   - Devices: ZTE Router

85. **ZTE Router Default Telnet Creds**
   - Path: `creds/routers/zte/telnet_default_creds.py`
   - Module performs dictionary attack against ZTE Router Telnet service. If valid credentials are found, they are displayed to the user.
   - Devices: ZTE Router

### zyxel (3)

86. **Zyxel Router Default FTP Creds**
   - Path: `creds/routers/zyxel/ftp_default_creds.py`
   - Module performs dictionary attack against Zyxel Router FTP service. If valid credentials are found, they are displayed to the user.
   - Devices: Zyxel Router

87. **Zyxel Router Default SSH Creds**
   - Path: `creds/routers/zyxel/ssh_default_creds.py`
   - Module performs dictionary attack against Zyxel Router SSH service. If valid credentials are found, they are displayed to the user.
   - Devices: Zyxel Router

88. **Zyxel Router Default Telnet Creds**
   - Path: `creds/routers/zyxel/telnet_default_creds.py`
   - Module performs dictionary attack against Zyxel Router Telnet service. If valid credentials are found, they are displayed to the user.
   - Devices: Zyxel Router

## Scanners (5)

### autopwn.py (1)

1. **AutoPwn**
   - Path: `scanners/autopwn.py`
   - Module scans for vulnerabilities and weaknesses. Supports timing templates T0..T5 (default: balanced/T3).
   - Devices: Routers, Switches, TAPs, FW, NGFW

### misc (2)

2. **Misc Scanner**
   - Path: `scanners/misc/misc_scan.py`
   - Module that scans for misc devices vulnerablities and weaknesses.
   - Devices: Misc Device

3. **SOHO Exploit Catalog (local HTTP)**
   - Path: `scanners/misc/soho_exploit_catalog_server.py`
   - Serves the embedded SOHO router exploit catalog (HTML + includes/scripts.js) over HTTP so browser one-click actions resolve relative assets offline.
   - Devices: SOHO routers / CPEs (catalog scope)

### routers (2)

4. **HooToo Scanner**
   - Path: `scanners/routers/hootoo_scan.py`
   - Scanner module for HooToo routers
   - Devices: HooToo TripMate

5. **Router Scanner**
   - Path: `scanners/routers/router_scan.py`
   - Module that scans for routers vulnerablities and weaknesses.
   - Devices: Router

## Generic Modules (20)

### bluetooth (3)

1. **Bluetooth LE Enumerate**
   - Path: `generic/bluetooth/btle_enumerate.py`
   - Enumerating services and characteristics of a given Bluetooth Low Energy devices.

2. **Bluetooth LE Scan**
   - Path: `generic/bluetooth/btle_scan.py`
   - Scans for Bluetooth Low Energy devices.

3. **Bluetooth LE Write**
   - Path: `generic/bluetooth/btle_write.py`
   - Writes data to target Bluetooth Low Energy device to given characteristic.

### cve (1)

4. **CVE Lookup by Banner / Vendor / Product**
   - Path: `generic/cve/cve_lookup.py`
   - Queries the embedded CVE database for known vulnerabilities matching a target's vendor, product, version or raw banner. Classifies each CVE as REMOTE (exploitable by rxf), LOCAL or PHYSICAL. Lists ava
   - Devices: Any — database covers routers, switches, firewalls, NGFW in scope

### external (4)

5. **ExploitDB embedded lookup (CSV)**
   - Path: `generic/external/exploitdb_embedded_lookup.py`
   - Searches files_exploits.csv in the bundled exploit-database__exploitdb tree (arsenal/pocs/incorporated_third_party). No searchsploit / external CLI.
   - Devices: Research / catalog

6. **Metasploit Console Bridge**
   - Path: `generic/external/metasploit_console_bridge.py`
   - Invokes local msfconsole with 'use <module>; setg RHOSTS; …; check|run'. MSF modules and license remain under Rapid7/BSD at your install path — this module only orchestrates the CLI. Not legal advice:
   - Devices: Any (depends on chosen Metasploit module)

7. **Metasploit Ruby Module Metadata (read-only)**
   - Path: `generic/external/metasploit_rb_inspect.py`
   - Loads a .rb path from your Metasploit tree and prints Name/Author/References heuristics. Does not run Ruby or MSF; original file is not modified. Credit remains with module authors and Rapid7 license.
   - Devices: Documentation

8. **MikrotikAPI-BF Bridge**
   - Path: `generic/external/mikrotikapi_bf_bridge.py`
   - Runs MikrotikAPI-BF (https://github.com/mrhenrike/MikrotikAPI-BF) via subprocess. Set script_path to your repo's mikrotikapi-bf.py or leave empty to use PATH (mikrotikapi-bf).
   - Devices: MikroTik RouterOS

### pcap (9)

9. **PCAP AP & Station Mapper**
   - Path: `generic/pcap/pcap_ap_station_mapper.py`
   - Offline analysis of PCAP/PCAPNG captures to enumerate access points (BSSID, SSID, channel, encryption) and client stations (probed SSIDs, associated BSSID, data frames). Useful after wardriving captur
   - Devices: Any 802.11 wireless capture

10. **PCAP Offline Credential Sniffer**
   - Path: `generic/pcap/pcap_credential_sniffer.py`
   - Offline extraction of cleartext credentials from PCAP/PCAPNG captures. Detects HTTP Basic/Form auth, FTP USER/PASS, Telnet logins and SNMP community strings.
   - Devices: Any network capture with cleartext protocols

11. **PCAP Offline EAP/WPE Credential Harvester**
   - Path: `generic/pcap/pcap_wpe_harvest.py`
   - Extracts EAP identities and challenge-response pairs from 802.1X authentication captures (WPA-Enterprise). Supports EAP-MD5, LEAP, MSCHAPv2, PEAP, EAP-TTLS, EAP-FAST. Produces hashcat-ready hashes for
   - Devices: Any WPA-Enterprise / 802.1X network capture

12. **PCAP Offline PMKID Attack (WPA/WPA2 Clientless)**
   - Path: `generic/pcap/pcap_pmkid_attack.py`
   - Extracts PMKID from EAPOL message 1 for clientless WPA/WPA2 offline attacks. No full 4-way handshake required. Outputs hashcat mode 22000 format and optionally runs hashcat.
   - Devices: Any WPA/WPA2-PSK network (most modern APs include PMKID)

13. **PCAP Offline TKIP/Michael Attack Analysis**
   - Path: `generic/pcap/pcap_tkip_downgrade.py`
   - Analyzes PCAP captures for TKIP vulnerabilities including Beck-Tews (QoS injection), Ohigashi-Morii (man-in-the-middle), and ChopChop (frame decryption) attack feasibility. Detects MIC failure deauths
   - Devices: Any WPA-TKIP or WPA2-TKIP mixed-mode network capture

14. **PCAP Offline WEP Key Recovery**
   - Path: `generic/pcap/pcap_wep_crack.py`
   - Extracts WEP IVs from PCAP captures and runs offline statistical key recovery using aircrack-ng (FMS/PTW/KoreK). Reports IV counts, weak IV statistics and crackability assessment.
   - Devices: Any WEP-encrypted 802.11 network capture

15. **PCAP Offline WPA/WPA2 Dictionary Attack**
   - Path: `generic/pcap/pcap_offline_wpa_crack.py`
   - Runs an offline dictionary attack against WPA/WPA2 handshakes captured in PCAP files. Supports aircrack-ng (default) and hashcat. Requires a wordlist and a capture file with a valid handshake.
   - Devices: Any WPA/WPA2 PSK network (captured handshake required)

16. **PCAP Offline WPA3 Dragonblood Analysis**
   - Path: `generic/pcap/pcap_dragonblood.py`
   - Analyzes WPA3 SAE (Dragonfly) handshakes in PCAP captures for Dragonblood vulnerabilities: CVE-2019-9494 (timing side-channel), CVE-2019-9496 (transition mode downgrade), weak group detection, and cac
   - CVEs: CVE-2019-9494, CVE-2019-9496
   - Devices: Any WPA3-SAE or WPA3-Transition mode network capture

17. **PCAP WPA/WPA2 Handshake Extractor**
   - Path: `generic/pcap/pcap_handshake_extractor.py`
   - Offline extraction of EAPOL 4-way handshakes from PCAP/PCAPNG captures. Exports usable handshakes to individual PCAP files ready for cracking with aircrack-ng or hashcat.
   - Devices: Any 802.11 WPA/WPA2 wireless capture

### snmp (1)

18. **SNMP Trap Listener**
   - Path: `generic/snmp/snmp_trap_listener.py`
   - Operational validation module for SNMP trap reception over UDP.
   - Devices: Routers, Switches, TAPs, FW, NGFW

### upnp (1)

19. **SSDP M-SEARCH Info Discovery**
   - Path: `generic/upnp/ssdp_msearch.py`
   - Sends M-SEARCH request to target and retrieve information from UPnP enabled systems.

### wordlist (1)

20. **Interactive Wordlist Generator**
   - Path: `generic/wordlist/wordlist_generator.py`
   - Generates custom password and username wordlists based on target profile (corporate or personal). Applies mutation rules (leet speak, case variations, number suffixes, date fragments, word combination
   - Devices: Any target — wordlist generation is target-independent

## Encoders (13)

### perl (4)

1. **Perl Base64 Encoder**
   - Path: `encoders/perl/base64.py`
   - Module encodes PERL payload to Base64 format.

2. **Perl Hex Encoder**
   - Path: `encoders/perl/hex.py`
   - Module encodes PERL payload to Hex format.

3. **Perl ROT13 Encoder**
   - Path: `encoders/perl/rot13.py`
   - Module encodes PERL payload to ROT13 format.

4. **Perl URL Encoder**
   - Path: `encoders/perl/url.py`
   - Module encodes PERL payload to URL-encoded format.

### php (4)

5. **PHP Base64 Encoder**
   - Path: `encoders/php/base64.py`
   - Module encodes PHP payload to Base64 format.

6. **PHP Hex Encoder**
   - Path: `encoders/php/hex.py`
   - Module encodes PHP payload to Hex format.

7. **PHP ROT13 Encoder**
   - Path: `encoders/php/rot13.py`
   - Module encodes PHP payload to ROT13 format.

8. **PHP URL Encoder**
   - Path: `encoders/php/url.py`
   - Module encodes PHP payload to URL-encoded format.

### python (5)

9. **Python Base32 Encoder**
   - Path: `encoders/python/base32.py`
   - Module encodes Python payload to Base32 format.

10. **Python Base64 Encoder**
   - Path: `encoders/python/base64.py`
   - Module encodes Python payload to Base64 format.

11. **Python Hex Encoder**
   - Path: `encoders/python/hex.py`
   - Module encodes Python payload to Hex format.

12. **Python ROT13 Encoder**
   - Path: `encoders/python/rot13.py`
   - Module encodes Python payload to ROT13 format.

13. **Python URL Encoder**
   - Path: `encoders/python/url.py`
   - Module encodes Python payload to URL-encoded format.

## Payloads (32)

### armle (2)

1. **ARMLE Bind TCP**
   - Path: `payloads/armle/bind_tcp.py`
   - Creates interactive tcp bind shell for ARMLE architecture.

2. **ARMLE Reverse TCP**
   - Path: `payloads/armle/reverse_tcp.py`
   - Creates interactive tcp reverse shell for ARMLE architecture.

### cmd (14)

3. **Awk Bind TCP**
   - Path: `payloads/cmd/awk_bind_tcp.py`
   - Creates an interactive tcp bind shell by using (g)awk.

4. **Awk Bind UDP**
   - Path: `payloads/cmd/awk_bind_udp.py`
   - Creates an interactive udp bind shell by using (g)awk.

5. **Awk Reverse TCP**
   - Path: `payloads/cmd/awk_reverse_tcp.py`
   - Creates an interactive tcp reverse shell by using (g)awk.

6. **Bash Reverse TCP**
   - Path: `payloads/cmd/bash_reverse_tcp.py`
   - Creates interactive tcp reverse shell by using bash.

7. **Netcat Bind TCP**
   - Path: `payloads/cmd/netcat_bind_tcp.py`
   - Creates interactive tcp bind shell by using netcat.

8. **Netcat Reverse TCP**
   - Path: `payloads/cmd/netcat_reverse_tcp.py`
   - Creates interactive tcp reverse shell by using netcat.

9. **PHP Bind TCP One-Liner**
   - Path: `payloads/cmd/php_bind_tcp.py`
   - Creates interactive tcp bind shell by using php one-liner.

10. **PHP Reverse TCP One-Liner**
   - Path: `payloads/cmd/php_reverse_tcp.py`
   - Creates interactive tcp reverse shell by using php one-liner.

11. **Perl Bind TCP One-Liner**
   - Path: `payloads/cmd/perl_bind_tcp.py`
   - Creates interactive tcp bind shell by using perl one-liner.

12. **Perl Reverse TCP One-Liner**
   - Path: `payloads/cmd/perl_reverse_tcp.py`
   - Creates interactive tcp reverse shell by using perl one-liner.

13. **Python Bind UDP One-Liner**
   - Path: `payloads/cmd/python_bind_udp.py`
   - Creates interactive udp bind shell by using python one-liner.

14. **Python Reverse TCP One-Liner**
   - Path: `payloads/cmd/python_bind_tcp.py`
   - Creates interactive tcp bind shell by using python one-liner.

15. **Python Reverse TCP One-Liner**
   - Path: `payloads/cmd/python_reverse_tcp.py`
   - Creates interactive tcp reverse shell by using python one-liner.

16. **Python Reverse UDP One-Liner**
   - Path: `payloads/cmd/python_reverse_udp.py`
   - Creates interactive udp reverse shell by using python one-liner.

### mipsbe (2)

17. **MIPSBE Bind TCP**
   - Path: `payloads/mipsbe/bind_tcp.py`
   - Creates interactive tcp bind shell for MIPSBE architecture.

18. **MIPSBE Reverse TCP**
   - Path: `payloads/mipsbe/reverse_tcp.py`
   - Creates interactive tcp reverse shell for MIPSBE architecture.

### mipsle (2)

19. **MIPSLE Bind TCP**
   - Path: `payloads/mipsle/bind_tcp.py`
   - Creates interactive tcp bind shell for MIPSLE architecture.

20. **MIPSLE Reverse TCP**
   - Path: `payloads/mipsle/reverse_tcp.py`
   - Creates interactive tcp reverse shell for MIPSLE architecture.

### perl (2)

21. **Perl Bind TCP**
   - Path: `payloads/perl/bind_tcp.py`
   - Creates interactive tcp bind shell by using perl.

22. **Perl Reverse TCP**
   - Path: `payloads/perl/reverse_tcp.py`
   - Creates interactive tcp reverse shell by using perl.

### php (2)

23. **PHP Bind TCP**
   - Path: `payloads/php/bind_tcp.py`
   - Creates interactive tcp bind shell by using php.

24. **PHP Reverse TCP**
   - Path: `payloads/php/reverse_tcp.py`
   - Creates interactive tcp reverse shell by using php.

### python (4)

25. **Python Bind TCP**
   - Path: `payloads/python/bind_tcp.py`
   - Creates interactive tcp bind shell by using python.

26. **Python Bind UDP**
   - Path: `payloads/python/bind_udp.py`
   - Creates interactive udp bind shell by using python.

27. **Python Reverse TCP**
   - Path: `payloads/python/reverse_tcp.py`
   - Creates interactive tcp reverse shell by using python.

28. **Python Reverse UDP**
   - Path: `payloads/python/reverse_udp.py`
   - Creates interactive udp reverse shell by using python.

### x64 (2)

29. **X64 Bind TCP**
   - Path: `payloads/x64/bind_tcp.py`
   - Creates interactive tcp bind shell for X64 architecture.

30. **X64 Reverse TCP**
   - Path: `payloads/x64/reverse_tcp.py`
   - Creates interactive tcp reverse shell for X64 architecture.

### x86 (2)

31. **X86 Bind TCP**
   - Path: `payloads/x86/bind_tcp.py`
   - Creates interactive tcp bind shell for X86 architecture.

32. **X86 Reverse TCP**
   - Path: `payloads/x86/reverse_tcp.py`
   - Creates interactive tcp reverse shell for X86 architecture.

---

## CVE Master List (23)

| # | CVE ID | Modules |
|---:|---|---|
| 1 | CVE-2001-0537 | `exploits/routers/cisco/ios_http_authorization_bypass.py` |
| 2 | CVE-2008-0403 | `exploits/routers/belkin/g_plus_info_disclosure.py` |
| 3 | CVE-2012-2765 | `exploits/routers/belkin/g_n150_password_disclosure.py` |
| 4 | CVE-2013-3568 | `exploits/routers/linksys/wrt100_110_rce.py` |
| 5 | CVE-2014-1635 | `exploits/routers/belkin/n750_rce.py` |
| 6 | CVE-2014-6271 | `exploits/generic/shellshock.py` |
| 7 | CVE-2014-6278 | `exploits/generic/shellshock.py` |
| 8 | CVE-2014-7169 | `exploits/generic/shellshock.py` |
| 9 | CVE-2014-8243 | `exploits/routers/linksys/smartwifi_password_disclosure.py` |
| 10 | CVE-2014-9222 | `exploits/routers/multi/misfortune_cookie.py` |
| 11 | CVE-2017-11519 | `exploits/routers/tplink/archer_c9_admin_password_reset.py` |
| 12 | CVE-2017-17215 | `exploits/routers/huawei/hg532_rce.py` |
| 13 | CVE-2017-3881 | `exploits/routers/cisco/catalyst_2960_rocem.py` |
| 14 | CVE-2017-5521 | `exploits/routers/netgear/multi_password_disclosure-2017-5521.py` |
| 15 | CVE-2017-6077 | `exploits/routers/netgear/dgn2200_ping_cgi_rce.py` |
| 16 | CVE-2017-6334 | `exploits/routers/netgear/dgn2200_dnslookup_cgi_rce.py` |
| 17 | CVE-2017-7240 | `exploits/misc/miele/pg8528_path_traversal.py` |
| 18 | CVE-2018-5999 | `exploits/routers/asus/asuswrt_lan_rce.py` |
| 19 | CVE-2018-6000 | `exploits/routers/asus/asuswrt_lan_rce.py` |
| 20 | CVE-2019-1652 | `exploits/routers/cisco/rv320_command_injection.py` |
| 21 | CVE-2019-16920 | `exploits/routers/dlink/dir_655_866_652_rce.py` |
| 22 | CVE-2019-9494 | `generic/pcap/pcap_dragonblood.py` |
| 23 | CVE-2019-9496 | `generic/pcap/pcap_dragonblood.py` |

## CVEs by Vendor

| Vendor | CVE Count | CVE IDs |
|---|---:|---|
| asus | 2 | CVE-2018-5999, CVE-2018-6000 |
| belkin | 3 | CVE-2008-0403, CVE-2012-2765, CVE-2014-1635 |
| cisco | 3 | CVE-2001-0537, CVE-2017-3881, CVE-2019-1652 |
| dlink | 1 | CVE-2019-16920 |
| huawei | 1 | CVE-2017-17215 |
| linksys | 2 | CVE-2013-3568, CVE-2014-8243 |
| miele | 1 | CVE-2017-7240 |
| multi | 1 | CVE-2014-9222 |
| netgear | 3 | CVE-2017-5521, CVE-2017-6077, CVE-2017-6334 |
| pcap | 2 | CVE-2019-9494, CVE-2019-9496 |
| shellshock.py | 3 | CVE-2014-6271, CVE-2014-6278, CVE-2014-7169 |
| tplink | 1 | CVE-2017-11519 |

---

> Generated by tools/generate_full_catalog.py