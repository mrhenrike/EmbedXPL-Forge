# Third-Party Components — EmbedXPL-Forge

**Version:** 1.0.0 (Phase 0)
**Date:** 2026-09-18
**Scope:** embedded devices, IoT, firmware, routers

> One row per integrated file or component. Generated/updated during Phase 0 analysis.

## Column Definitions

| Column | Description |
|--------|-------------|
| component | File or module name |
| origin_repo | Upstream URL |
| origin_author | Author/organization |
| origin_license | License type |
| integration_type | copied / rewritten / inspired |
| xpl_destination | This XPL |
| integration_tier | TIER1-TIER5 |
| commit_or_tag | Upstream commit or tag studied |
| local_changes | Description of changes from original |
| date_integrated | Date |
| security_risk | NONE / LOW / MEDIUM / HIGH |
| requires_sandbox | true/false |

---

## Components

| component | origin_repo | origin_author | origin_license | integration_type | tier | date_integrated | security_risk |
|-----------|------------|--------------|---------------|-----------------|------|----------------|---------------|
| android_contacts_sqli_cve_2026_28576.py | https://github.com/mobilehackinglab/CVE-2026-28576-poc | MobileHackingLab | none (rewrite) | rewritten | TIER2 | 2026-09-18 | LOW |
| teamcity_rce_cve_2026_63077.py | https://github.com/sfewer-r7/CVE-2026-63077 | sfewer-r7 | none (rewrite) | rewritten | TIER1 | 2026-10-16 | HIGH |
| docker_copyescape_cve_2026_17106.py | https://github.com/masasron/CopyEscape-CVE-2026-17106 | masasron | none (rewrite) | rewritten | TIER2 | 2026-10-16 | HIGH |
| linux_refluxfs_lpe_cve_2026_64600.py | União Geek (original) | André Henrike | Proprietary | original | TIER1 | 2026-10-16 | HIGH |
| refluxfs.c (native PoC) | União Geek (original) | André Henrike | Proprietary | original | TIER1 | 2026-10-16 | HIGH |
| linux_nftables_lpe_series.py | Public PoC research | various | none (rewrite) | rewritten | TIER1 | 2026-10-16 | HIGH |
| pwnescape_docker_cve_2026_99999.py | Public PoC research | various | none (rewrite) | rewritten | TIER2 | 2026-10-16 | HIGH |
| curl_http2_uaf_cve_2026_92392.py | Public PoC research | various | none (rewrite) | rewritten | TIER1 | 2026-10-16 | MEDIUM |
| ivanti_connect_secure_cve_2026_104935.py | Public PoC research | various | none (rewrite) | rewritten | TIER1 | 2026-10-16 | HIGH |

| citrix_netscaler_preauth_rce_cve_2026_8452.py | watchTowr Labs | André Henrike | none (rewrite) | rewritten | TIER1 | 2026-10-16 | CRITICAL |
| fortiweb_auth_bypass_cve_2025_25257.py | watchTowr Labs | André Henrike | none (rewrite) | rewritten | TIER1 | 2026-10-16 | HIGH |
| ivanti_sentry_rce_cve_2026_10520.py | watchTowr Labs | André Henrike | none (rewrite) | rewritten | TIER1 | 2026-10-16 | CRITICAL |
| sharefile_rce_cve_2026_2699.py | watchTowr Labs | André Henrike | none (rewrite) | rewritten | TIER1 | 2026-10-16 | HIGH |
| splunk_rce_cve_2026_20253.py | watchTowr Labs | André Henrike | none (rewrite) | rewritten | TIER1 | 2026-10-16 | HIGH |
| watchguard_auth_bypass_cve_2025_9242.py | watchTowr Labs | André Henrike | none (rewrite) | rewritten | TIER1 | 2026-10-16 | HIGH |
| f5_bigip_rce_cve_2026_94127.py | watchTowr Labs | André Henrike | none (rewrite) | rewritten | TIER1 | 2026-10-16 | CRITICAL |
| checkpoint_rce_cve_2026_50751.py | watchTowr Labs | André Henrique | none (rewrite) | rewritten | TIER1 | 2026-10-16 | CRITICAL |
| telnetd_env_overflow_cve_2026_32746.py | watchTowr Labs | André Henrike | none (rewrite) | rewritten | TIER1 | 2026-10-16 | HIGH |
| fortinet_stack_bof_cve_2025_32756.py | watchTowr Labs / Fortiguard | André Henrike | none (rewrite) | rewritten | TIER1 | 2026-10-16 | CRITICAL |
| cpanel_whm_auth_bypass_rce.py | watchTowr Labs | André Henrike | none (rewrite) | rewritten | TIER1 | 2026-10-16 | CRITICAL |
| panos_globalprotect_rce_cve_2026_3064.py | watchTowr Labs | André Henrike | none (rewrite) | rewritten | TIER1 | 2026-10-16 | CRITICAL |

---

*Last updated: 2026-10-16 — F1-T03 watchTowr 12 modules.*
*Reference: Section 14 of xpl-forge-ecosystem-master-integration.plan.md*
*Contact: security.research@uniaogeek.com.br*