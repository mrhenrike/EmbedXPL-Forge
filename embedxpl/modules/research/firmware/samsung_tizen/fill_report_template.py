#!/usr/bin/env python3
"""Fill Samsung Report_template.docx with TIZEN vulnerability data."""
from docx import Document
from docx.shared import Pt
import os

TEMPLATE = r"D:\Projetos-SafeLabs\submodules\IoT\Embedded-Firmware-Research\reports\samsung_tizen\Samsung_Report_template.docx"
OUTPUT   = r"D:\Projetos-SafeLabs\submodules\IoT\Embedded-Firmware-Research\reports\samsung_tizen\Samsung_Report_template_FILLED.docx"

BUG_TITLE = (
    "Samsung Tizen Smart TV - Unauthenticated Smart Hub API Full Control "
    "(CVSS 9.8 CRITICAL) + 4 Additional CVE Candidates "
    "(TIZEN-2026-001 to TIZEN-2026-005)"
)

DESCRIPTION = """\
====================================================================
RESPONSIBLE DISCLOSURE - SAMSUNG TIZEN SMART TV
TIZEN-2026-001 to TIZEN-2026-005
Researcher: Andre Henrique | Uniao Geek | security.research@uniaogeek.com.br
ORCID: https://orcid.org/0009-0006-0688-4973
Date: 2026-04-21 | Embargo Expiry: 2026-07-21 (90 days)
====================================================================

CONCURRENT DISCLOSURE NOTICE:
This report is submitted concurrently to CERT/CC VINCE for coordinated
vulnerability disclosure, as is standard practice. Samsung has been
notified of this concurrent submission. CERT/CC will not release any
information during the 90-day embargo period.

--------------------------------------------------------------------
RESEARCHER CONTACT
--------------------------------------------------------------------
Name:    Andre Henrique
Company: Uniao Geek (registered company, Brazil)
Email:   security.research@uniaogeek.com.br
GitHub:  https://github.com/mrhenrike
Org:     https://github.com/Uniao-Geek
ORCID:   https://orcid.org/0009-0006-0688-4973

--------------------------------------------------------------------
SCOPE / FIRMWARE ANALYZED
--------------------------------------------------------------------
Firmware packages from official Samsung support portal
(downloadcenter.samsung.com):

  Model:   QN55Q60BAG
  File:    T-NKLBUABC.zip
  Version: 01710.2025-09-04

  Model:   UN55BU8000G
  File:    T-KSU2EBUABC.zip
  Version: 01710.2025-09-05

  Model:   UN50CU8000G
  File:    T-X22UDCUABC-0090_2202.0_USB_OSU.zip
  Version: 06500.2025-09-05

Network API: Samsung Smart Hub REST API (TCP/8001, TCP/8002)
based on public Samsung developer documentation + LAN testing.

--------------------------------------------------------------------
VULNERABILITY SUMMARY - RESEARCHER-PROVIDED CVSS (NIST NVD 2026)
--------------------------------------------------------------------
Per NIST NVD risk-based model (eff. 2026-04-15), IoT/consumer CVEs
may not receive automatic NVD enrichment. Full vectors provided.

ID             | Score | Severity | CWE     | Title
---------------|-------|----------|---------|-----------------------------
TIZEN-2026-001 |  9.8  | CRITICAL | CWE-306 | Smart Hub Missing Auth
TIZEN-2026-005 |  8.8  | HIGH     | CWE-284 | Token Reuse/Replay
TIZEN-2026-002 |  8.1  | HIGH     | CWE-494 | FOTA Downgrade Attack
TIZEN-2026-003 |  7.5  | HIGH     | CWE-91  | UPnP/DLNA XML Injection
TIZEN-2026-004 |  5.3  | MEDIUM   | CWE-400 | SSDP Amplification DoS

Full CVSSv3.1 vectors:
TIZEN-2026-001: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8 CRITICAL
TIZEN-2026-005: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N = 8.8 HIGH
TIZEN-2026-002: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H = 8.1 HIGH
TIZEN-2026-003: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N = 7.5 HIGH
TIZEN-2026-004: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L = 5.3 MEDIUM

CISA KEV: TIZEN-2026-001 (CVSS 9.8, no auth, trivially exploitable
from LAN) - recommend CERT/CC KEV nomination.

--------------------------------------------------------------------
FINDING 1 - TIZEN-2026-001 (CVSS 9.8 CRITICAL)
Smart Hub API - Missing Authentication for Critical Function
CWE-306 | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
--------------------------------------------------------------------
The Samsung Smart Hub REST API (TCP/8001) and WebSocket API (TCP/8002)
do not require authentication for device enumeration or remote control.
Any device on the local network can:

1. Query full device info without credentials:
   GET http://<TV_IP>:8001/api/v2/
   Response: 200 OK - model, firmware version, device ID in JSON

2. Open WebSocket and inject arbitrary key presses:
   ws://<TV_IP>:8002/api/v2/channels/samsung.remote.control
   Payload: {"method":"ms.remote.control",
             "params":{"Cmd":"Click","DataOfCmd":"KEY_MUTE"}}
   Result: TV mutes immediately - no PIN, no pairing, no auth

Full remote control (channel, volume, apps, power, source) available
to any attacker on the same LAN.

Affected: All Samsung Tizen TVs with Smart Hub enabled (Tizen 4.x-6.x)

--------------------------------------------------------------------
FINDING 2 - TIZEN-2026-005 (CVSS 8.8 HIGH)
Smart Hub Pairing Token Reuse and Replay Attack
CWE-284 | CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N
--------------------------------------------------------------------
The Smart Hub WebSocket pairing token has no expiration, no session
binding, and no replay protection. A captured token can be replayed
indefinitely after device reboot, enabling persistent unauthorized
control without re-pairing.

--------------------------------------------------------------------
FINDING 3 - TIZEN-2026-002 (CVSS 8.1 HIGH)
FOTA Firmware Downgrade Attack
CWE-494 | CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H
--------------------------------------------------------------------
The FOTA update mechanism does not enforce cryptographic version pinning.
Consistent with CVE-2021-25436/CVE-2021-25437 behavior in Tizen 4.x.
An attacker with network control can trigger re-installation of older
vulnerable firmware, re-exposing previously patched vulnerabilities.

--------------------------------------------------------------------
FINDING 4 - TIZEN-2026-003 (CVSS 7.5 HIGH)
UPnP/DLNA SOAP XML Injection
CWE-91 | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N
--------------------------------------------------------------------
UPnP DLNA SOAP endpoint accepts XML without sanitization. Injected
payloads (XXE, XPath traversal, SSRF-style URIs) processed without
input validation. Potential for filesystem disclosure and SSRF.

--------------------------------------------------------------------
FINDING 5 - TIZEN-2026-004 (CVSS 5.3 MEDIUM)
SSDP Amplification - DoS Attack Chain Amplifier
CWE-400 | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L
--------------------------------------------------------------------
SSDP returns ~1,200-byte responses to ~200-byte queries (~6x amplif.).
Enables reflected/amplified DoS against third-party targets.
Included as attack chain amplifier and disclosure completeness.

--------------------------------------------------------------------
POSITIVE SECURITY FINDING - F-001 (Informational, Commended)
Firmware Encryption Upgrade (AES-256-CBC + SHA-512 + TrustZone, 2022+)
--------------------------------------------------------------------
Samsung 2022+ firmware uses AES-256-CBC / SHA-512 key derivation /
hardware-bound RSA keys in TrustZone TEE (vs AES-128-CBC pre-2022).
This is a significant security improvement, commended by the researcher.

--------------------------------------------------------------------
ATTACK SCENARIO
--------------------------------------------------------------------
1. Attacker on same Wi-Fi as Samsung TV (apartment, hotel, hospital)
2. Discovers TV via SSDP broadcast (no credentials required)
3. Queries Smart Hub API - extracts model, firmware, device ID (no auth)
4. Opens WebSocket - injects arbitrary key presses (TIZEN-2026-001)
5. Captures token - replays indefinitely (TIZEN-2026-005)
All steps require NO user interaction, NO pairing, NO PIN entry.
Enterprise environments (hospitals, hotels, offices) at highest risk.

--------------------------------------------------------------------
PROOF OF CONCEPT
--------------------------------------------------------------------
Attached ZIP: Samsung_Tizen_ZeroDay_PoC_TIZEN-2026_UniaoGeek.zip

- e2e_poc_tizen_smarthub.py   : Full attack chain (TIZEN-2026-001+005)
- tizen_smarthub_audit.py     : Smart Hub API audit tool
- tizen_upnp_audit.py         : UPnP/DLNA XML injection test
- samsung_firmware_analysis.py: Firmware cryptographic analysis (F-001)
- pocs/README.md              : Step-by-step reproduction guide

Quick test (Python 3, no external dependencies):
  import urllib.request, json
  info = json.loads(urllib.request.urlopen(
      "http://<TV_IP>:8001/api/v2/").read())
  print(info)  # Full device info without any authentication

--------------------------------------------------------------------
DISCLOSURE TIMELINE
--------------------------------------------------------------------
2026-04-21 : Research completed, all vulnerabilities validated
2026-04-21 : This report submitted to secbugbounty@samsung.com
2026-04-21 : Concurrent CERT/CC VINCE submission (standard practice)
2026-07-21 : Embargo expiry (90 days from initial contact)

--------------------------------------------------------------------
REQUESTED ACTIONS
--------------------------------------------------------------------
1. Confirm receipt and assign a tracking ID
2. Validate TIZEN-2026-001 (CVSS 9.8) as highest priority
3. Provide remediation timeline and firmware update schedule
4. Coordinate CVE ID assignment (or confirm Samsung CNA status)
5. Consider CISA KEV nomination for TIZEN-2026-001
6. Notify researcher before any public advisory or disclosure

====================================================================
RESEARCHER CONTACT
====================================================================
Name:    Andre Henrique
Company: Uniao Geek (registered company, Brazil)
Email:   security.research@uniaogeek.com.br
GitHub:  https://github.com/mrhenrike
Org:     https://github.com/Uniao-Geek
ORCID:   https://orcid.org/0009-0006-0688-4973
====================================================================
"""


def fill_cell(cell, text, font_size=9):
    """Clear a table cell and fill it with text, one paragraph per line."""
    # Clear existing paragraphs (keep first, clear its runs)
    paragraphs = cell.paragraphs
    for para in paragraphs:
        for run in para.runs:
            run.text = ""

    lines = text.split("\n")

    # Use the first existing paragraph for the first line
    first_para = paragraphs[0] if paragraphs else cell.add_paragraph()
    run = first_para.add_run(lines[0])
    run.font.size = Pt(font_size)

    # Add remaining lines as new paragraphs
    for line in lines[1:]:
        p = cell.add_paragraph()
        run = p.add_run(line)
        run.font.size = Pt(font_size)


doc = Document(TEMPLATE)

# Table[0] = Bug Title field
fill_cell(doc.tables[0].rows[0].cells[0], BUG_TITLE, font_size=10)

# Table[1] = Description field
fill_cell(doc.tables[1].rows[0].cells[0], DESCRIPTION, font_size=9)

doc.save(OUTPUT)
sz = os.path.getsize(OUTPUT) // 1024
print(f"[+] Saved: {OUTPUT}")
print(f"    Size : {sz} KB")
print(f"    Ready to PGP-encrypt and send to secbugbounty@samsung.com")
