# CERT/CC VINCE Submission — Herospeed / Longsee NVR
<!-- Template v2, adapted to NIST NVD risk-based enrichment model (eff. 2026-04-15) -->
<!-- Research IDs: HSLS-2026-001 through HSLS-2026-004 -->
<!-- Date of first vendor contact attempt: 2026-05-15 -->
<!-- VINCE portal: https://kb.cert.org/vince/ -->

---

## VINCE — Field: Title / Short Description

**PASTE:**
```
Herospeed / Longsee NVR (N-series, MC6830 Platform, 9 OEM re-brands) — 6 Critical/High
Vulnerabilities: Unauthenticated Credential Metadata, XVR Interface Disclosure, Upgrade
Shell RCE + Retreat.sh 0day (v2.0.6), Hardcoded Root Hash, Config Export with Hardcoded
AES Key, FTP Diagnostic Command Injection RCE (CVSS 9.8 CRITICAL + 5 additional)
```

---

## VINCE — Field: Vulnerability Description / Summary

**PASTE:**
```
Herospeed Technology Limited (herospeed.net) and their OEM platform vendor Longsee
manufacture N-series NVR devices (N3009, N3016, N3109, N3332, F30, and related
re-brands) running firmware versions v2.0.4 (2023) through v2.0.8 (2025). All
analyzed firmware images share the same MC6830 ARM Cortex-A7 SoC, Boa/0.94.13
HTTP server embedded in libweb.so, and Qt5-based GUI (nvr_main). The same
vulnerabilities affect all OEM re-brands sharing this Longsee platform.

Researcher estimates 50,000-100,000+ devices exposed on the public internet globally.
Confirmed Shodan fingerprint (c3l3r1on, May 2026):
  http.html:"statics/js/variable.js"  ← PRIMARY — finds all NVR families on this platform
  http.html:"longseSha256"             ← Secondary (Longsee platform specific)
  http.html:"LsNXVRPlugin"             ← Secondary (NVR plugin)
FOFA (c3l3r1on, May 2026): body="longseSha256" → 100k+ in Europe alone.
The variable.js file also contains DEFAULT_ADMIN_PASSWORD="12345" confirming
that devices found via Shodan almost certainly have default credentials active.

Known OEM re-brands sharing the same vulnerable platform (c3l3r1on research,
unverified by this researcher): TVT Digital (TD-3000H1, TD-3300), GISE (Poland,
V5 series), Longse (LSN-9836, LSN-9436), Zintronic (P5, N9000), Turing AI USA
(SMART series), Speco Technologies (ZIP series, OEM TVT), Alibi Security (Vigilant
series, OEM TVT), IRBIS (MBD6804T-EL, V4.02.R11).

PRIOR RELATED CVEs FOR DIFFERENT PRODUCTS (NOT this finding):
- CVE-2024-5631: Longse NVR3608PGE2W — credential transmission (different model)
- CVE-2024-5634: Longse cameras — predictable telnet passwords (cameras, not NVR)
Our findings are DISTINCT: different models, different vulnerability classes.

═══════════════════════════════════════════════════════════════
PRIMARY FINDINGS (require immediate remediation):
═══════════════════════════════════════════════════════════════

HSLS-2026-004: Hardcoded Root Password Hash — ALL Versions 2023-2025
  CVSSv3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8 CRITICAL
  CWE-798: Use of Hard-coded Credentials
  Impact: The DES crypt hash "12ZpTwfyH6/Bs" (salt="12") for the root account
  is hardcoded identically in ALL 7 analyzed firmware images spanning 2023-2025:
  N3009 v2.0.4/v2.0.6, N3016 v2.0.4/v2.0.6, N3109 v2.0.6, N3332 v2.0.4,
  F30 v2.0.8. Present as: root:12ZpTwfyH6/Bs:0:0::/root:/bin/sh in /etc/passwd.
  Busybox telnetd is available in all firmware versions. Combined with HSLS-2026-003
  (code execution), this grants immediate root access to the device.

HSLS-2026-003: Upgrade Package Shell Execution RCE (Two Vectors)
  CVSSv3.1: AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H = 8.8 HIGH
  CWE-78: OS Command Injection / CWE-494: Download of Code Without Integrity Check
  
  Vector A — v2.0.4 (Source Injection):
  update.sh sources (shell "." operator) the "version" file from the upgrade
  package without any sanitisation: ". $version_remote_file". Any non-assignment
  line in the version file executes as root during the upgrade pipeline.
  
  Vector B — v2.0.6 "patch" INTRODUCES NEW RCE (Retreat.sh Execution):
  The vendor's security patch for v2.0.4 introduced a MORE EXPLOITABLE vector.
  update.sh v2.0.6 added:
    detect_shell=/tmp/update/version
    if head -n 1 "$detect_shell" | grep -q '^#!/bin'; then
        cp ${detect_shell} /tmp/retreat.sh
        chmod -R 777 /tmp/retreat.sh
        /tmp/retreat.sh        ← DIRECT SHELL SCRIPT EXECUTION
    fi
  A version file beginning with "#!/bin/sh" is copied to /tmp/retreat.sh and
  explicitly executed. This is direct shell script execution, not source injection.
  Authenticated attacker uploads crafted firmware → immediate root code execution.

HSLS-2026-001: Unauthenticated Credential Metadata Disclosure
  CVSSv3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N = 9.1 CRITICAL
  CWE-306: Missing Authentication for Critical Function
  Impact: POST /api/session/login-capabilities with any username returns without
  authentication: per-user salt (32-byte hex), challenge nonce, iteration count
  (100), and a valid sessionID. These values enable offline SHA-256 KDF
  reconstruction of credentials without triggering lockout or rate-limiting.
  Confirmed on all analyzed firmware versions.

HSLS-2026-005: Config Export with Hardcoded AES Key (Case A — c3l3r1on)
  CVSSv3.1: AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N = 8.8 HIGH
  CWE-798: Use of Hard-coded Credentials / CWE-312: Cleartext Storage
  Impact: libdatamanager.so contains hardcoded AES key "0123456789ABCDEF0123456789abcdef".
  The /api/system/import-export endpoint exports the complete NVR config encrypted
  with this key. Decryption reveals ALL credentials: NVR accounts, every connected
  IP camera login, FTP/email/DDNS passwords. This gives an attacker the full
  surveillance network credential set in a single API call.
  Source: static analysis of libdatamanager.so from NAND flash dump (c3l3r1on lab).
  variable.js confirms: DEFAULT_ADMIN_PASSWORD="12345" (default credential in all versions).

HSLS-2026-006: FTP Diagnostic Server Parameter Command Injection RCE (Case B — c3l3r1on)
  CVSSv3.1: AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H = 8.8 HIGH
  CWE-78: OS Command Injection
  Impact: nvr_main contains FTP_UploadJpgBuffer(server:%s) and TestFTPEv functions
  that pass the FTP server address to popen() without sanitisation. The FTP test
  endpoint in /api/network/ftp accepts a server field that is used directly in a
  shell command. Injecting shell metacharacters achieves root code execution.
  FIELD-CONFIRMED by c3l3r1on on physical lab hardware: "I simply used wget, which
  downloaded the script, ran it on 777, and the NVR was already owned. Telnet started
  from the script without a problem" (c3l3r1on, May 2026 Discord).
  Source: NAND flash analysis (FTP_UploadJpgBuffer, TestFTPEv, server:%s in nvr_main).

═══════════════════════════════════════════════════════════════
ADDITIONAL RISK CONTEXT (attack chain amplifiers):
═══════════════════════════════════════════════════════════════

HSLS-2026-002: XVR Legacy Interface Credential Disclosure
  CVSSv3.1: AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N = 6.5 MEDIUM
  CWE-312: Cleartext Storage of Sensitive Information
  Role: /vb.htm?selectalluserlist returns all accounts with passwords encoded in
  Base64 (plaintext-equivalent). Simpler auth surface (Basic HTTP vs. SHA-256 KDF)
  amplifies brute-force risk for HSLS-2026-001. Enables direct credential recovery
  which feeds the authenticated upgrade RCE (HSLS-2026-003).

═══════════════════════════════════════════════════════════════
NOTE ON CVSS ENRICHMENT (NVD 2026):
═══════════════════════════════════════════════════════════════
Complete CVSSv3.1 vectors and CWE mappings are provided by the researcher per
NIST's risk-based enrichment model (eff. 2026-04-15). Researcher requests
CERT/CC to assign CVE IDs for HSLS-2026-001 through HSLS-2026-004 and to
consider HSLS-2026-004 and HSLS-2026-001 for CISA KEV review.
```

---

## VINCE — Field: Affected Products / Vendor

**PASTE:**
```
Vendor: Herospeed Technology Limited
Vendor Website: https://www.herospeed.net/
Vendor Contact: support@herospeed.net (general contact — no dedicated PSIRT found)
Vendor CNA Status: Not known to be a CNA

OEM Platform Vendor (shared firmware): Longse (Longsee Technology Co., Ltd.)
OEM Platform: MC6830 SoC, Longsee API v4.0.0, Boa/0.94.13 HTTP server

Affected Products:
- Herospeed NVR N3009 series (9-channel), firmware v2.0.4 and v2.0.6
- Herospeed NVR N3016 series (16-channel), firmware v2.0.4 and v2.0.6
- Herospeed NVR N3109 series (9-channel, different hardware), firmware v2.0.6
- Herospeed NVR N3332 series (32-channel), firmware v2.0.4
- Herospeed NVR F30 series (2025 platform), firmware v2.0.8
- All OEM re-brands sharing the MC6830/Longsee platform (estimated: numerous brands)

Specifically confirmed via firmware download and binary analysis:
- N3009_32NR_ALH1P4: firmware V2.0.4.230818_R2, build 2023-08-18
- N3009_32NR_BVH1P4: firmware V2.0.6.240826_R5, build 2024-08-26
- N3016_32NR_ALH1P8: firmware V2.0.4.230817_R4, build 2023-08-17
- N3016_32NR_BVH1P8: firmware V2.0.6.240826_R5, build 2024-08-26
- N3109_32NR_BVH1P4A0: firmware V2.0.6.240823_R7, build 2024-08-23
- N3332_32NR_ALH2P0A4: firmware V2.0.4.230825_R2, build 2023-08-25
- NVR_F30_BV: firmware V2.0.8.250609_R1, build 2025-06-09

Platform: Linux (ARM Cortex-A7, SiGmaStar MC6830 SoC), BusyBox
Protocol/Interface: HTTP REST API (port 80/443), Boa/0.94.13 web server
Firmware source: https://www.herospeed.net/en/index.php?a=lists&c=index&catid=14
```

---

## VINCE — Field: CVSSv3.1 Score

**PASTE:**
```
Primary findings (CRITICAL/HIGH):
HSLS-2026-004: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8 CRITICAL
HSLS-2026-001: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N = 9.1 CRITICAL
HSLS-2026-003: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H = 8.8 HIGH
HSLS-2026-005: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N  = 8.8 HIGH
HSLS-2026-006: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H  = 8.8 HIGH

Additional risk context (MEDIUM):
HSLS-2026-002: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N = 6.5 MEDIUM

All CVSS vectors are researcher-assessed per NIST NVD scoring guidelines.
Calculator: https://www.first.org/cvss/calculator/3.1
```

---

## VINCE — Field: CWE

**PASTE:**
```
Primary findings:
CWE-798: Use of Hard-coded Credentials (HSLS-2026-004)
CWE-306: Missing Authentication for Critical Function (HSLS-2026-001)
CWE-78:  Improper Neutralization of Special Elements in OS Commands (HSLS-2026-003)
CWE-494: Download of Code Without Integrity Check (HSLS-2026-003, upgrade vector)

Additional risk context:
CWE-312: Cleartext Storage of Sensitive Information (HSLS-2026-002)
```

---

## VINCE — Field: Reproduction Steps / Proof of Concept

**PASTE:**
```
Environment: Any Python 3.8+ system on same network as target NVR device
Dependencies: Python 3.8+ standard library only (socket, hashlib, base64, crypt, json, struct)
PoC file: HEROSPEED_E2E_POC.py (attached in ZIP)

Quick validation (HSLS-2026-001, unauthenticated):
  curl -s -X POST http://TARGET_IP/api/session/login-capabilities \
    -H "Content-Type: application/json" \
    -H "Api-Version: v4.0.0" \
    -d '{"action":"get","data":{"username":"admin"}}'
  Expected: JSON with salt, challenge, sessionID returned without authentication.

Full E2E PoC (all 4 phases):
  python3 HEROSPEED_E2E_POC.py --target TARGET_IP --port 80

Phase 1 only (HSLS-2026-001):
  python3 HEROSPEED_E2E_POC.py --target TARGET_IP --phase 1

Phase 2 only (HSLS-2026-002):
  python3 HEROSPEED_E2E_POC.py --target TARGET_IP --phase 2

Phase 3 (HSLS-2026-003, upgrade RCE — requires valid credentials):
  python3 HEROSPEED_E2E_POC.py --target TARGET_IP --phase 3 \
    --username admin --password 12345 \
    --cmd "touch /tmp/HSLS_2026_003_pwned.txt"

Expected E2E output (confirmed on QEMU ARM emulation of real firmware):
  [PHASE 1] login-capabilities → salt/challenge/sessionID returned unauthenticated
  [PHASE 2] /vb.htm?selectalluserlist → password "12345" returned as base64 "MTIzNDU="
  [PHASE 3] upload accepted (code=0) → update.sh executes injected version file
  [PHASE 4] root hash "12ZpTwfyH6/Bs" confirmed identical across all 7 firmware images

Shodan exposure queries for independent verification:
  https://www.shodan.io/search?query=http.html%3A%22longseSha256%22
  https://www.shodan.io/search?query=http.html%3A%22LsNXVRPlugin%22
  https://beta.shodan.io/search?query=%22Boa%2F0.94.13%22+http.title%3A%22NVR%22

FOFA (cited by independent researcher c3l3r1on, May 2026):
  body="longseSha256" → ~100,000+ devices in Europe alone
  Conservative global estimate: 50,000+ internet-exposed NVR devices

ZIP contents:
- HEROSPEED_E2E_POC.py         — Full end-to-end attack chain PoC
- HEROSPEED_LONGSEE_RESEARCH_REPORT.md — Technical research report
- VINCE_REPORT_HEROSPEED_LONGSEE_NVR.md — This document
- VENDOR_EMAIL_HEROSPEED.md    — Vendor notification email
```

---

## VINCE — Field: Impact / Attack Scenario

**PASTE:**
```
PRIMARY IMPACT (HSLS-2026-004 + HSLS-2026-003 combined, CVSS 9.8 CRITICAL):

An attacker on the same network as the NVR device (common in home/SMB networks
where NVRs are on LAN, and frequently exposed to WAN per FOFA/Shodan data) can:

1. Probe /api/session/login-capabilities WITHOUT authentication to obtain
   per-user salt/challenge values for any account (HSLS-2026-001).

2. Either brute-force the password offline using the disclosed salt/challenge,
   OR use /vb.htm?selectalluserlist with default credentials to directly read
   all account passwords in Base64 encoding (HSLS-2026-002).

3. Authenticate and upload a crafted firmware package to /api/upgrade/upgrade-file.
   The upgrade pipeline (update.sh) executes the injected shell commands as root:
   - v2.0.4: shell source injection (". $version_remote_file")
   - v2.0.6: retreat.sh explicit execution ("cp version.sh /tmp/retreat.sh; /tmp/retreat.sh")
   Both vectors achieve arbitrary OS command execution as root (HSLS-2026-003).

4. Root is already accessible: the hardcoded DES crypt hash "12ZpTwfyH6/Bs"
   is present in ALL firmware versions. Spawning busybox telnetd on port 23
   provides interactive root shell access (HSLS-2026-004).

REAL-WORLD SCENARIOS:

- Home user: attacker on shared WiFi gains persistent root shell on family
  NVR recording all security cameras. Live and historical video at attacker's
  disposal.

- Small business: single shared LAN exposes NVR to any compromised workstation.
  Attacker pivots from NVR to camera network (network switch port isolation absent
  in most deployments).

- ISP-connected NVR (50,000+ exposed globally): remote attacker finds device via
  Shodan/FOFA, exploits HSLS-2026-001 to confirm credentials, uploads malicious
  firmware (HSLS-2026-003), achieves root, and installs persistent backdoor.
  No physical access required.

- Botnet recruitment: devices running identical firmware with same root hash are
  trivially mass-exploited. A single weaponized script scans the internet, exploits
  HSLS-2026-001 → HSLS-2026-002 → HSLS-2026-003 → installs backdoor using the
  known root hash (HSLS-2026-004). All without any user interaction.

CISA KEV CONSIDERATION:
HSLS-2026-004 (9.8 CRITICAL) requires no attacker skill (AC:L/PR:N/UI:N when
combined with HSLS-2026-003). Mass exploitation from WAN is trivially scriptable
against the ~50,000+ exposed devices. Researcher requests CERT/CC to nominate
HSLS-2026-004 for CISA KEV catalog if in-the-wild exploitation is confirmed.
```

---

## VINCE — Field: Has the vendor been contacted?

**PASTE:**
```
Yes. An initial responsible disclosure email was sent to support@herospeed.net
on 2026-05-15 (see VENDOR_EMAIL_HEROSPEED.md in the attached ZIP for the exact
email content). No dedicated PSIRT contact was identified for Herospeed Technology
Limited. Vendor website (herospeed.net) does not list a security disclosure address.

The vendor notification explicitly stated that this concurrent CERT/CC VINCE
submission was being made simultaneously. Concurrent disclosure to both vendor
and CERT/CC is standard responsible disclosure practice per CERT/CC's own CVD
guidelines.

Vendor response: No response received as of submission date (2026-05-15, same day
as vendor contact).

OEM platform vendor (Longse/Longsee) was NOT separately contacted as the specific
contact information for their security team is not publicly available. CERT/CC
assistance in reaching the OEM platform vendor would be appreciated.
```

---

## VINCE — Field: Date of First Contact Attempt

**PASTE:**
```
2026-05-15
```

---

## VINCE — Field: What are your public disclosure plans?

**PASTE:**
```
90-day responsible disclosure embargo. Public disclosure planned for 2026-08-13
(90 days from first vendor contact on 2026-05-15), regardless of vendor patch status.

If Herospeed or Longse provides a validated patch before the embargo expiry,
I will coordinate timing of public advisory with them.

Planned public disclosure channels:
- GitHub: https://github.com/mrhenrike/EmbedXPL-Forge (PoC release)
- CERT-CC advisory (if CVEs assigned)
- NVD submission for any CVEs not automatically enriched

NOTE ON NVD 2026: IoT/embedded device CVEs are deprioritized under NIST's
risk-based enrichment model (eff. 2026-04-15). I request CERT/CC to assign
CVE IDs for all four findings to ensure proper vulnerability database tracking,
and to submit NVD enrichment requests for any assigned CVEs.

No weaponized exploit code will be released publicly during the embargo period.
The EmbedXPL-Forge detection modules (check() functions only) will be published
after CVE assignment to assist defenders in identifying vulnerable devices.
```

---

## VINCE — Field: Tracking IDs

**PASTE:**
```
Internal Research IDs:
  HSLS-2026-001: Unauthenticated Credential Metadata Disclosure (CVSS 9.1)
  HSLS-2026-002: XVR Legacy Interface Credential Disclosure (CVSS 6.5)
  HSLS-2026-003: Upgrade Package Shell Execution RCE (CVSS 8.8)
  HSLS-2026-004: Hardcoded Root Password Hash (CVSS 9.8)

CVE IDs: Pending assignment (requested from CERT/CC)
Vendor Tracking ID: Pending vendor acknowledgment
```

---

## VINCE — Field: Summary of Previous Vendor Communications

**PASTE:**
```
2026-05-15: Initial responsible disclosure email sent to support@herospeed.net
  - Subject: Security Vulnerability Report — Herospeed NVR N-series (CRITICAL)
  - Attached: Technical summary (see VENDOR_EMAIL_HEROSPEED.md for exact text)
  - Vendor notified of concurrent CERT/CC VINCE submission (this report)
  - Embargo period: 2026-05-15 to 2026-08-13 (90 days)
  - Response: None received as of submission (same day)

2026-05-15: This CERT/CC VINCE submission filed

[Further entries will be added as the disclosure progresses]

CONCURRENT DISCLOSURE NOTE: Submitting to both the vendor and CERT/CC simultaneously
is standard responsible disclosure practice per CERT/CC's own CVD guidelines. The
vendor has been explicitly made aware of this parallel VINCE submission in the initial
email notification.
```

---

## VINCE — Field: Name (Researcher)

**PASTE:**
```
Andre Henrique
```

---

## VINCE — Field: Email Address

**PASTE:**
```
security.research@uniaogeek.com.br
```

---

## VINCE — Field: Organization

**PASTE:**
```
Uniao Geek — https://github.com/Uniao-Geek
```

---

## VINCE — Field: ORCID (Optional)

**PASTE:**
```
https://orcid.org/0009-0006-0688-4973
```

---

## VINCE — Field: Private Comments

**PASTE:**
```
CVSS ENRICHMENT NOTE (NVD 2026): Per NIST's risk-based NVD enrichment model
(effective April 15, 2026), most IoT/consumer device CVEs will not receive
automatic NVD enrichment. Complete CVSSv3.1 vectors and CWE mappings are
provided herein by the researcher.

COMMUNITY RESEARCH NOTE: c3l3r1on (github.com/c3l3r1on) independently
identified the login-capabilities authentication metadata disclosure on live
Herospeed N-series NVR hardware in May 2026 and reported it to CERT Polska.
This VINCE submission covers the same VULN (HSLS-2026-001) plus three
additional vulnerabilities (HSLS-2026-002, HSLS-2026-003, HSLS-2026-004)
discovered via systematic firmware reverse engineering. I have communicated
with c3l3r1on and both researchers consent to joint attribution.

FORMAL REQUESTS:
1. Assign CVE IDs for HSLS-2026-001 (CVSS 9.1), HSLS-2026-003 (CVSS 8.8),
   HSLS-2026-004 (CVSS 9.8)
2. Consider HSLS-2026-004 for CISA KEV catalog nomination — hardcoded root
   hash in 50,000+ internet-exposed devices, trivially exploitable chain
3. Request NVD manual enrichment for all assigned CVEs via nvd@nist.gov
4. CERT/CC assistance contacting OEM platform vendor (Longse/Longsee) is
   requested, as no security contact is publicly available for that entity

EVIDENCE BASE:
All findings are based on:
- Static binary analysis of 7 firmware images from herospeed.net
  (N3009, N3016, N3109, N3332, F30, 2023-2025)
- QEMU ARM user-mode chroot emulation with live API testing
- Source code analysis of update.sh, libweb.so, nvr_main, api.js
- Full firmware extraction via binwalk + unsquashfs (SquashFS at offset 0x110)
- Live /api/session/login-capabilities testing against emulated firmware
  (code=0 returned with salt/challenge without authentication — confirmed)

PRIOR ART DISTINCTION:
CVE-2024-5631 (Longse NVR3608PGE2W, cleartext credential transmission)
CVE-2024-5634 (Longse cameras, predictable telnet passwords)
Our findings affect DIFFERENT models (N3009, N3016, N3109, N3332, F30) and
DIFFERENT vulnerability classes (API metadata disclosure, shell execution
via upgrade pipeline, hardcoded root hash). No overlap with existing CVEs.
```

---

## VINCE — File Upload Checklist

```
[ ] HEROSPEED_Vulns_HSLS2026_UniaoGeek.zip containing:
    [x] HEROSPEED_E2E_POC.py          — Full E2E attack chain PoC script
    [x] HEROSPEED_LONGSEE_RESEARCH_REPORT.md — Technical research report
    [x] VINCE_REPORT_HEROSPEED_LONGSEE_NVR.md — This submission document
    [x] VENDOR_EMAIL_HEROSPEED.md     — Vendor notification email
    [ ] HEROSPEED_VULNS_SUMMARY.pdf   — Optional PDF version of report
```

---

## Submission Checklist

```
[x] Title clear with highest CVSS score (9.8 CRITICAL for HSLS-2026-004)
[x] Summary separates PRIMARY (CRITICAL/HIGH) from ADDITIONAL (MEDIUM)
[x] CVSSv3.1 vectors COMPLETE for all 4 findings
[x] CWE ID + full name for all 4 findings
[x] Affected products with exact firmware versions and build dates
[x] Vendor contact confirmed (2026-05-15) + explicit mention of concurrent disclosure
[x] CVE assignment requested for HSLS-2026-001, -003, -004 (≥7.0 CVSS)
[x] CISA KEV consideration requested for HSLS-2026-004 (9.8 CRITICAL, AC:L/PR:N)
[x] NVD enrichment note in summary and private comments
[x] Embargo date = 2026-05-15 + 90 days = 2026-08-13
[x] Shodan exposure queries included
[x] Community researcher credit (c3l3r1on) documented
```

---

*VINCE Submission — HSLS-2026-001 through HSLS-2026-004*
*Researcher: André Henrique (@mrhenrike) | Uniao Geek*
*Date: 2026-05-15 | Embargo: 2026-08-13*
