# Vendor Disclosure Email — Herospeed Technology Limited

**To:** support@herospeed.net
**CC:** security.research@uniaogeek.com.br (researcher)
**Subject:** Security Vulnerability Report — Herospeed NVR N-series (4 Critical/High Findings)
**Date:** 2026-05-15
**Embargo Expires:** 2026-08-13 (90 days)

---

```
To: support@herospeed.net
Subject: Security Vulnerability Report — Herospeed NVR N-series (4 Critical/High Findings)
Importance: High

Dear Herospeed Technology Security Team,

My name is André Henrique, a security researcher at Uniao Geek
(https://github.com/Uniao-Geek). I am writing to report four security
vulnerabilities affecting your NVR N-series product line (N3009, N3016,
N3109, N3332, F30) running firmware versions v2.0.4 (2023) through
v2.0.8 (2025).

This disclosure follows responsible disclosure practices. I am notifying
you simultaneously with a submission to CERT/CC VINCE, as is standard
coordinated vulnerability disclosure practice. I request a 90-day embargo
period (until 2026-08-13) to allow patch development.

═══════════════════════════════════════════════════════════
AFFECTED PRODUCTS
═══════════════════════════════════════════════════════════

The following firmware images were obtained from herospeed.net and
analyzed via static binary analysis and QEMU ARM emulation:

- N3009_32NR_ALH1P4: V2.0.4.230818_R2 (9CH, ALIIOT platform)
- N3009_32NR_BVH1P4: V2.0.6.240826_R5 (9CH, BV variant)
- N3016_32NR_ALH1P8: V2.0.4.230817_R4 (16CH)
- N3016_32NR_BVH1P8: V2.0.6.240826_R5 (16CH)
- N3109_32NR_BVH1P4A0: V2.0.6.240823_R7 (9CH, alt hardware)
- N3332_32NR_ALH2P0A4: V2.0.4.230825_R2 (32CH)
- NVR_F30_BV: V2.0.8.250609_R1 (F30 series, 2025)

Platform: SiGmaStar MC6830 ARM Cortex-A7, Boa/0.94.13 HTTP server
         (libweb.so), Linux BusyBox.

═══════════════════════════════════════════════════════════
VULNERABILITY SUMMARY
═══════════════════════════════════════════════════════════

FINDING 1 — CRITICAL (CVSS 9.8): Hardcoded Root Password Hash
The DES crypt hash "12ZpTwfyH6/Bs" for the root account is present
identically in ALL 7 analyzed firmware images from 2023 to 2025.
This hash appears in /etc/passwd as:
  root:12ZpTwfyH6/Bs:0:0::/root:/bin/sh
Busybox telnetd is available in all firmware versions. Combined with
any code execution vulnerability, this provides immediate root access.

FINDING 2 — CRITICAL (CVSS 9.1): Unauthenticated Credential Metadata
The /api/session/login-capabilities endpoint returns per-user salt,
challenge nonce, and sessionID without any prior authentication.
This enables offline SHA-256 KDF credential reconstruction without
triggering any lockout or rate-limiting mechanism.

Proof (curl command, no credentials required):
  curl -s -X POST http://DEVICE_IP/api/session/login-capabilities \
    -H "Content-Type: application/json" \
    -H "Api-Version: v4.0.0" \
    -d '{"action":"get","data":{"username":"admin"}}'
  Response includes: salt, challenge, sessionID — all without auth.

FINDING 3 — HIGH (CVSS 8.8): Upgrade Package Shell Execution RCE

Vector A (v2.0.4): update.sh sources the "version" file from the
upgrade package using the shell "." operator without sanitisation:
  . $version_remote_file
Any shell command in the version file executes as root.

Vector B (v2.0.6 — NOTE: This is in your PATCHED version):
Your v2.0.6 patch introduced a NEW, MORE EXPLICIT execution path.
update.sh now contains:
  detect_shell=/tmp/update/version
  if head -n 1 "$detect_shell" | grep -q '^#!/bin'; then
      cp ${detect_shell} /tmp/retreat.sh
      chmod -R 777 /tmp/retreat.sh
      /tmp/retreat.sh          ← DIRECT EXECUTION OF UPLOADED SCRIPT
  fi
A "version" file starting with "#!/bin/sh" is explicitly executed.
This is not a partial fix — it introduces a cleaner attack vector.

An authenticated attacker uploads a crafted firmware to:
  POST /api/upgrade/upgrade-file
The upgrade pipeline then executes the injected commands as root.

FINDING 4 — MEDIUM (CVSS 6.5): XVR Legacy Interface Credential Disclosure
The /vb.htm?selectalluserlist endpoint (accessible with Basic HTTP auth
using any valid account) returns all user credentials with passwords
encoded in Base64. This is simpler to exploit than the SHA-256 KDF API
and enables direct credential recovery:
  Response: "1=default_id, 2=admin, 3=MTIzNDU=, ..." where field 3
  is the admin password base64-encoded (e.g., "MTIzNDU=" = "12345").

═══════════════════════════════════════════════════════════
PROOF OF CONCEPT
═══════════════════════════════════════════════════════════

A full end-to-end PoC script is attached (HEROSPEED_E2E_POC.py) which
demonstrates all four vulnerabilities. The script has been validated
against emulated Herospeed NVR firmware (QEMU ARM user-mode chroot).

To demonstrate FINDING 2 (no auth required, safe to test):
  python3 HEROSPEED_E2E_POC.py --target DEVICE_IP --phase 1

═══════════════════════════════════════════════════════════
ESTIMATED EXPOSURE
═══════════════════════════════════════════════════════════

Independent security researcher c3l3r1on (Poland) identified 100,000+
exposed devices in Europe via FOFA (query: body="longseSha256"). Our
conservative global estimate is 50,000+ internet-exposed NVR devices
sharing these vulnerabilities.

Shodan queries for verification:
  https://www.shodan.io/search?query=http.html%3A%22longseSha256%22
  https://www.shodan.io/search?query=http.html%3A%22LsNXVRPlugin%22

═══════════════════════════════════════════════════════════
REMEDIATION RECOMMENDATIONS
═══════════════════════════════════════════════════════════

1. CRITICAL — Remove the hardcoded root hash from all firmware.
   Generate device-unique root credentials at factory.

2. CRITICAL — Require authentication before returning any data from
   /api/session/login-capabilities (return an error for unauthenticated
   requests, or remove the salt/challenge from the unauthenticated response).

3. HIGH — Rewrite update.sh to validate upgrade package integrity before
   sourcing or executing the version file. Use an allowlist of permitted
   variable names; do NOT use "." (source) or execute the file directly.
   Remove the retreat.sh execution mechanism entirely.

4. MEDIUM — Disable or remove the /vb.htm legacy XVR interface from NVR
   firmware. If retained for compatibility, require session-based auth and
   never return passwords in any encoding.

5. Replace DES crypt in /etc/passwd with SHA-512 crypt or bcrypt.

═══════════════════════════════════════════════════════════
TIMELINE AND COORDINATION
═══════════════════════════════════════════════════════════

2026-05-15: This email sent to support@herospeed.net
2026-05-15: Concurrent submission to CERT/CC VINCE
2026-08-13: Embargo expires (90 days from today)

I am requesting:
1. Acknowledgment of receipt within 5 business days
2. A vendor tracking number for this report
3. Expected patch timeline within 30 days of acknowledgment
4. Coordination on CVE assignment (via CERT/CC CNA)

If I do not receive acknowledgment by 2026-05-22, I will proceed with
CERT/CC-coordinated public disclosure on 2026-08-13.

I am happy to provide additional technical details, test artifacts,
or firmware samples to assist in reproducing and patching these issues.

Sincerely,

André Henrique
Security Researcher | Uniao Geek
Email: security.research@uniaogeek.com.br
GitHub: https://github.com/mrhenrike
ORCID: https://orcid.org/0009-0006-0688-4973

Research IDs: HSLS-2026-001, HSLS-2026-002, HSLS-2026-003, HSLS-2026-004
Embargo: 2026-05-15 to 2026-08-13 (90 days)
CERT/CC VINCE: Submitted concurrently
```

---

## Attachments to include in the email

| File | Description |
|---|---|
| `HEROSPEED_E2E_POC.py` | End-to-end proof of concept script (Python 3) |
| `HEROSPEED_LONGSEE_RESEARCH_REPORT.md` | Full technical research report |
| `HEROSPEED_Vulns_HSLS2026_UniaoGeek.zip` | ZIP with all files for VINCE upload |

---

## Follow-up communication template (14 days after no response)

**Subject:** RE: Security Vulnerability Report — Herospeed NVR N-series (FINAL NOTICE before CERT/CC)

```
Dear Herospeed Security Team,

This is a follow-up to my initial responsible disclosure email sent on
2026-05-15 regarding four security vulnerabilities in your NVR N-series
product line (HSLS-2026-001 through HSLS-2026-004, CVSS 9.8 CRITICAL).

I have not received any acknowledgment or response after 14 business days.

As stated in my initial email, I will proceed with CERT/CC-coordinated
public disclosure on 2026-08-13. CERT/CC VINCE has already been notified
and is actively coordinating on this case.

This is a final notice. To avoid uncoordinated public disclosure of
critical vulnerabilities affecting 50,000+ internet-exposed devices,
I strongly encourage you to acknowledge this report immediately.

André Henrique
security.research@uniaogeek.com.br
CERT/CC VINCE Case: [VU#XXXXXX — to be updated after assignment]
```
