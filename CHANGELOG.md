# Changelog

All notable changes to RouterXPL-Forge are documented here.

Format: [Semantic Versioning](https://semver.org) — `MAJOR.MINOR.PATCH`.

---

## [0.6.0] — 2026-04-08

### Added
- **11 Huawei EG8145X6-10 exploit modules** — info disclosure, brute-force (rate-limit bypass), CSRF static token, pre-auth user enum, config AES decrypt, Epuser firewall bypass (CVE-2025-49599), MitM credential intercept, Telnet enable, CSRF payload generator, DNS poison via CSRF, WiFi credential extractor
- **`eg8145x6_autopwn`** — 9-phase chained exploitation: fingerprint → info disclosure → CSRF → user enum → brute-force → config decrypt → JS capture → port scan → report + generic fallback (v1.1.0)
- **`generic/upnp/igd_exploit`** — UPnP IGD full exploitation: SSDP discovery, GetExternalIPAddress, AddPortMapping (firewall bypass without auth), GetGenericPortMappingEntry, traffic stats, ForceTermination DoS check, event SUBSCRIBE
- **`core/oui.py`** — IEEE OUI database with online-first lookup and local fallback
- **`core/session.py`** — Persistent scan history per host (SHA-256 of IP+MAC), `~/.rxf_sessions/`
- **`core/discovery.py`** — T0–T5 timing profiles, multi-method host discovery, wireless detection, WirelessXPL-Forge recommendations, session integration
- **`routerxpl/data/oui.txt`** — Full IEEE OUI database (39k+ entries)
- **`routerxpl/__main__.py`** — `python -m routerxpl` and `rxf` / `routerxpl` console scripts
- **`pyproject.toml`** — PEP 517/518 packaging (replaces legacy setup.py)
- **GitHub Actions** — `publish-pypi.yml` for Trusted Publishing (OIDC, no API tokens)
- Wiki pages 01–12 (en-US + pt-BR)
- GPON ONT attack surface diagram (`07-gpon-ont-attack.mmd` + PNG)

### Changed
- `interpreter.py` — Added `discover` and `sessions` commands, WiFi recommendation panel
- `cve_extended_catalog.json` — 338 total CVEs (+8: RXPL-2026-HW-001..008, CVE-2025-49599 expanded)
- `huawei_defaults.txt` — 50+ credentials including ISP-specific Brazil (Sumicity, Loga, Vivo, Claro, Oi)
- `setup.py` — Reduced to a PEP 517 shim; all metadata in `pyproject.toml`
- README, diagrams, and wiki updated: removed NGFW/UTM and TAP (no dedicated modules), corrected module counts

### Removed
- `docs/diagrams/architecture/03-ngfw-utm.mmd` — no dedicated NGFW modules
- `docs/diagrams/architecture/06-network-tap.mmd` — TAP support was planned only
- `docs/img/architecture/rxf_arch_ngfw_utm.png`

### Module Counts

| Category | 0.5.x | 0.6.0 |
|----------|-------|-------|
| Exploits | 429 | 500 |
| Creds | 88 | 88 |
| Scanners | 5 | 5 |
| Payloads | 32 | 32 |
| Encoders | 13 | 13 |
| Generic | 8 | 9 |
| **Total** | **575** | **647** |
| CVEs | 330 | **338** |

---

## [0.5.0] — 2026-04-04

### Added
- Machine Learning advisor (CVSS scoring, module prioritization)
- ML response classifier (TF-IDF + Logistic Regression)
- Banner fingerprinter (regex, substring, GPU-accelerated cosine similarity)
- System hardware profiler (CPU, RAM, GPU detection)
- GPU multi-backend: CUDA, AMD ROCm, OpenCL, CPU fallback
- SmartPool adaptive thread/process pool
- AsyncScanEngine with async HTTP client
- Rich-based TUI — all console output migrated from ANSI to Rich
- Network discovery engine (Nmap + Scapy + ARP + TCP fallback)

### Changed
- 60 new exploit modules imported from third-party-router-poc
- Module audit and enrichment across all 575 modules

---

## [0.4.0-beta] — 2026-04-03

### Added
- Major exploit incorporation: 575 modules, 330 CVEs, 49 vendors
- Architecture diagrams (Mermaid + PNG)
- Coverage matrix
- Bilingual documentation (en-US + pt-BR)

---

*Author: André Henrique ([@mrhenrike](https://github.com/mrhenrike)) | [União Geek](https://github.com/Uniao-Geek)*
