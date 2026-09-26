# Changelog — EmbedXPL-Forge

## [3.11.0] — 2026-09-26

### Added
- CVE-2026-95675: D-Link DAP-1360 Unauthenticated Root RCE (CVSS 9.8, NO FIX AVAILABLE, firmware ≤6.14)
- CVE-2026-34473: ZTE Router Unauthenticated DoS (CVSS 7.5)
- CVE-2026-20971: Samsung Android Kernel PROCA/FIVE UAF LPE (Galaxy S9–S25, Qualcomm + Exynos)
- CVE-2026-93958: D-Link R95 BE9500 NTP Command Injection (CVSS 9.4)

### Restored (lost in Sep 2026 rollback)
- iOS 26.5 lockdownd 5-chain auth bypass module
- WAF Bypass Engine (80+ obfuscation variants)
- HTTP 403 Bypass (24 standalone techniques)
- Mirai IoT async scanner (62 hardcoded cred pairs)
- TP-Link Archer exploit suite (CVE-2023-1389, CVE-2024-48957, CVE-2022-30024)
- Realtek/MediaTek SDK RCE (CVE-2021-35394, CVE-2022-27255, CVE-2024-20017)
- macOS DesktopServices LPE (CVE-2026-43783)

### Infrastructure
- GitHub LFS configured (.gitattributes) for firmware/binary files

## [3.10.1] — 2026-09-24
### Fixed
- Catalog updated: +5 new CVEs (CVE-2026-35616, CVE-2025-20333, CVE-2025-20362, CVE-2024-50562, CVE-2026-24858)
- Hikvision ISAPI pre-auth RCE (CVE-2025-34067 CVSS 10.0)
- TP-Link/D-Link EOL RCE suite (CVE-2024-54887, CVE-2024-12987, CVE-2024-11068)

## [3.10.0] — 2026-09-23
### Added — Sep 2026 Batch Integration
- RTSP camera scanner (cameradar native port)
- iOS 26.5 lockdownd 5-chain auth bypass
- macOS DesktopServices LPE (CVE-2026-43783)
- WAF Bypass Engine (80+ variants)
- HTTP 403 Bypass (24 techniques)
- Mirai IoT Scanner (62 default creds)
- TP-Link Archer: CVE-2023-1389 / CVE-2024-48957 / CVE-2022-30024
- Realtek/MediaTek SDK RCE: CVE-2021-35394 / CVE-2022-27255 / CVE-2024-20017
- Base class refactor: simulate+destructive dual-flag guardrail
- Full en-US output migration

## [3.9.0] — 2026-09-19 (previous release)