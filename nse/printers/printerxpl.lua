---
-- printerxpl.lua — Shared library for PrinterXPL-Forge NSE scripts
--
-- Provides: vendor detection, CVE cross-reference, severity formatting,
-- PrinterXPL-Forge / EmbedXPL-Forge exploit suggestions, and shared
-- protocol helpers (PJL, IPP, HTTP, SNMP).
--
-- Author: André Henrique (@mrhenrike) | União Geek
-- Repo  : https://github.com/mrhenrike/PrinterXPL-Forge
-- Docs  : https://github.com/mrhenrike/PrinterXPL-Forge/wiki/NSE
---

local stdnse   = require "stdnse"
local string   = require "string"
local table    = require "table"
local math     = require "math"

local _M = {}

-- ── Version ──────────────────────────────────────────────────────────────────
_M.VERSION = "5.0.0"

-- ── Severity colour tags (nmap output) ───────────────────────────────────────
_M.SEV = {
  CRITICAL = "CRITICAL",
  HIGH     = "HIGH",
  MEDIUM   = "MEDIUM",
  LOW      = "LOW",
  INFO     = "INFO",
}

-- ── Verdict strings ──────────────────────────────────────────────────────────
_M.VERDICT = {
  VULN      = "VULNERABLE",
  POSSIBLE  = "POSSIBLY VULNERABLE",
  NOT_VULN  = "NOT VULNERABLE",
  UNKNOWN   = "UNKNOWN",
}

-- ── Vendor fingerprint table ─────────────────────────────────────────────────
-- Each entry: { pattern (case-insensitive), vendor, product_hint }
_M.VENDOR_PATTERNS = {
  { pat="hewlett.packard|hp laserjet|hp officejet|hp pagewide|jetdirect|hp enterprise",
    vendor="HP",        family="LaserJet/OfficeJet/PageWide" },
  { pat="canon imagerunner|canon imagepress|canon imageclass|canon lbp|canon mf",
    vendor="Canon",     family="imageCLASS/imageRUNNER/LBP" },
  { pat="ricoh aficio|ricoh mp|ricoh sp|ricoh im|savin|gestetner|lanier|nashuatec|nrg",
    vendor="Ricoh",     family="Aficio/MP/SP/IM" },
  { pat="lexmark",
    vendor="Lexmark",   family="MX/CX/XC/MB/MC series" },
  { pat="xerox workcentre|xerox versalink|xerox altalink|xerox phaser|xerox colorqube",
    vendor="Xerox",     family="WorkCentre/VersaLink/AltaLink" },
  { pat="brother mfc|brother dcp|brother hl|brother fax",
    vendor="Brother",   family="MFC/DCP/HL" },
  { pat="epson workforce|epson ecotank|epson expression|epson stylus",
    vendor="Epson",     family="WorkForce/EcoTank" },
  { pat="konica minolta|bizhub|konicaminolta",
    vendor="Konica Minolta", family="bizhub" },
  { pat="kyocera ecosys|kyocera taskalfa|kyocera fs",
    vendor="Kyocera",   family="ECOSYS/TASKalfa" },
  { pat="sharp mx|sharp ar|sharp bp",
    vendor="Sharp",     family="MX/AR/BP" },
  { pat="toshiba e.studio|toshiba estudio",
    vendor="Toshiba",   family="e-STUDIO" },
  { pat="samsung multifunction|samsung clx|samsung scx|samsung ml",
    vendor="Samsung",   family="CLX/SCX/ML" },
  { pat="oki data|okidata|oki mc|oki es",
    vendor="OKI",       family="ES/MC" },
  { pat="dell multifunction|dell color",
    vendor="Dell",      family="Color MFP" },
  { pat="cups|openprinting",
    vendor="Linux/CUPS", family="CUPS scheduler" },
  { pat="zebra technologies|zebra zpl|zpl ii",
    vendor="Zebra",     family="Label/Industrial" },
}

-- ── CVE quick-reference table ────────────────────────────────────────────────
-- Compact: { id, cvss, vendor_pat, desc, xpl_module, check_fn_name }
_M.CVE_DB = {
  -- HP
  { id="CVE-2025-26506", cvss=9.8, sev=_M.SEV.CRITICAL, vendor="HP",
    desc="HP LaserJet/OfficeJet Enterprise PostScript RCE — unauthenticated RCE via malformed PS job",
    xpl="xpl/edb-cve-2025-26506", port=9100 },
  { id="CVE-2023-6018",  cvss=9.8, sev=_M.SEV.CRITICAL, vendor="HP",
    desc="HP LaserJet Enterprise firmware auth bypass — arbitrary firmware upload",
    xpl="xpl/research/research-hp-fw-bypass", port=443 },
  { id="CVE-2023-1707",  cvss=9.1, sev=_M.SEV.CRITICAL, vendor="HP",
    desc="HP FutureSmart 5.6 scan job data disclosure when IPsec enabled",
    xpl="xpl/research/research-hp-futuresmart-leak", port=443 },
  { id="CVE-2017-2741",  cvss=9.8, sev=_M.SEV.CRITICAL, vendor="HP",
    desc="HP PageWide/OfficeJet PJL path traversal to RCE",
    xpl="xpl/edb-cve-2017-2741", port=9100 },
  -- Canon
  { id="CVE-2022-24673", cvss=9.8, sev=_M.SEV.CRITICAL, vendor="Canon",
    desc="Canon imageCLASS SLP pre-auth stack buffer overflow → root RCE (ZDI-22-515)",
    xpl="xpl/edb-cve-2022-24673", port=427 },
  { id="CVE-2025-14235", cvss=9.8, sev=_M.SEV.CRITICAL, vendor="Canon",
    desc="Canon imageCLASS PCL buffer overflow → RCE",
    xpl="xpl/research/research-canon-pcl-bof", port=9100 },
  -- Lexmark
  { id="CVE-2023-23560", cvss=9.0, sev=_M.SEV.CRITICAL, vendor="Lexmark",
    desc="Lexmark SSRF-to-RCE via Web Services interface (Pwn2Own Toronto 2022)",
    xpl="xpl/edb-51928", port=80 },
  { id="CVE-2023-50739", cvss=8.8, sev=_M.SEV.HIGH, vendor="Lexmark",
    desc="Lexmark IPP heap buffer overflow → RCE (ZDI-CAN-22549) — 100+ models",
    xpl="xpl/edb-cve-2023-50739", port=631 },
  { id="CVE-2023-50733", cvss=6.5, sev=_M.SEV.MEDIUM, vendor="Lexmark",
    desc="Lexmark EWS SSRF — printer as pivot to internal network",
    xpl="xpl/edb-cve-2023-50733", port=80 },
  { id="CVE-2023-26067", cvss=9.1, sev=_M.SEV.CRITICAL, vendor="Lexmark",
    desc="Lexmark post-auth RCE via device configuration API",
    xpl="xpl/edb-cve-2023-26067", port=80 },
  -- Xerox
  { id="CVE-2024-6333",  cvss=8.1, sev=_M.SEV.HIGH, vendor="Xerox",
    desc="Xerox VersaLink OS command injection — authenticated RCE",
    xpl="xpl/edb-cve-2024-6333", port=80 },
  { id="CVE-2021-27508", cvss=8.0, sev=_M.SEV.HIGH, vendor="Xerox",
    desc="Xerox WorkCentre 78xx OS command injection via clone_group param",
    xpl="xpl/research/research-xerox-workcentre-cmdinject", port=80 },
  -- Ricoh
  { id="CVE-2024-34161", cvss=8.8, sev=_M.SEV.HIGH, vendor="Ricoh",
    desc="Ricoh MP EWS malformed HTTP → RCE",
    xpl="xpl/research/research-ricoh-ews-rce", port=80 },
  { id="CVE-2021-33945", cvss=7.5, sev=_M.SEV.HIGH, vendor="Ricoh",
    desc="Ricoh SP wpa_supplicant stack overflow → DoS/RCE",
    xpl="xpl/research/research-ricoh-wpa-bof", port=80 },
  -- Brother
  { id="CVE-2024-51977", cvss=7.5, sev=_M.SEV.HIGH, vendor="Brother",
    desc="Brother serial-based admin password derivation — info disclosure",
    xpl="xpl/research/research-brother-serial-pwd", port=80 },
  { id="CVE-2024-51978", cvss=9.1, sev=_M.SEV.CRITICAL, vendor="Brother",
    desc="Brother default credential auth bypass via serial derivation",
    xpl="xpl/research/research-brother-serial-pwd", port=80 },
  -- Sharp
  { id="CVE-2022-45796", cvss=9.8, sev=_M.SEV.CRITICAL, vendor="Sharp",
    desc="Sharp MX OS command injection → RCE (no auth)",
    xpl="xpl/research/research-sharp-rce", port=80 },
  -- Toshiba
  { id="CVE-2024-21911", cvss=8.8, sev=_M.SEV.HIGH, vendor="Toshiba",
    desc="Toshiba e-STUDIO TopAccess authentication bypass",
    xpl="xpl/research/research-toshiba-auth-bypass", port=80 },
  -- Kyocera
  { id="CVE-2022-1026",  cvss=7.5, sev=_M.SEV.HIGH, vendor="Kyocera",
    desc="Kyocera ECOSYS unauthenticated address book / credential dump",
    xpl="xpl/edb-cve-2022-1026", port=9100 },
  -- Windows Print Spooler
  { id="CVE-2021-1675",  cvss=9.8, sev=_M.SEV.CRITICAL, vendor="Microsoft",
    desc="PrintNightmare — Windows Print Spooler RCE/LPE (unauthenticated network)",
    xpl="xpl/edb-50498", port=445 },
  { id="CVE-2022-38028", cvss=7.8, sev=_M.SEV.HIGH, vendor="Microsoft",
    desc="GooseEgg — APT28 Windows Print Spooler LPE (CISA KEV)",
    xpl="xpl/research/research-gooseegg-spooler", port=445 },
  -- CUPS
  { id="CVE-2024-47176", cvss=9.9, sev=_M.SEV.CRITICAL, vendor="Linux/CUPS",
    desc="CUPS cups-browsed unauthenticated RCE chain (2024)",
    xpl="xpl/edb-cve-2024-47176", port=631 },
  { id="CVE-2026-34980", cvss=9.1, sev=_M.SEV.CRITICAL, vendor="Linux/CUPS",
    desc="CUPS 2.4.16 unauthenticated RCE via PPD injection (2026)",
    xpl="xpl/research/research-cups-chain-2026", port=631 },
  -- HP fax
  { id="CVE-2018-5924",  cvss=9.8, sev=_M.SEV.CRITICAL, vendor="HP",
    desc="Faxploit — HP/Samsung fax stack overflow via malformed fax (port 9100 / PSTN)",
    xpl="xpl/edb-cve-2018-5924", port=9100 },
}

-- ── Helper: detect vendor from banner string ──────────────────────────────────
function _M.detect_vendor(banner)
  if not banner then return nil, nil end
  local b = banner:lower()
  for _, entry in ipairs(_M.VENDOR_PATTERNS) do
    if b:match(entry.pat) then
      return entry.vendor, entry.family
    end
  end
  return nil, nil
end

-- ── Helper: match CVEs for a detected vendor (+ optional port filter) ────────
function _M.match_cves(vendor, port)
  local matches = {}
  if not vendor then return matches end
  local v = vendor:lower()
  for _, cve in ipairs(_M.CVE_DB) do
    local cv = (cve.vendor or ""):lower()
    if cv == v or cv == "generic" then
      if (not port) or (cve.port == port) or (cve.port == 0) then
        table.insert(matches, cve)
      end
    end
  end
  return matches
end

-- ── Helper: format a single CVE finding for nmap output ──────────────────────
function _M.fmt_cve(cve, verdict, details)
  local lines = {}
  table.insert(lines, string.format("  [%s] %s (CVSS %.1f — %s)",
    verdict, cve.id, cve.cvss, cve.sev))
  table.insert(lines, string.format("    Description : %s", cve.desc))
  table.insert(lines, string.format("    PrinterXPL  : printerxpl-forge run --module %s", cve.xpl))
  table.insert(lines, string.format("    Reference   : https://nvd.nist.gov/vuln/detail/%s", cve.id))
  if details then
    table.insert(lines, string.format("    Evidence    : %s", details))
  end
  return table.concat(lines, "\n")
end

-- ── Helper: build a suggestion block when vendor is confirmed ─────────────────
function _M.suggest_xpl(vendor, family, cves)
  local lines = {}
  table.insert(lines, string.format("\n  Detected: %s — %s", vendor, family or "Unknown model"))
  table.insert(lines, "  Full exploitation available via:")
  table.insert(lines, "    printerxpl-forge  →  pip install printerxpl-forge")
  if vendor and vendor:lower():match("router|embedded|iot|zyxel|dlink|tplink|netgear|mikrotik") then
    table.insert(lines, "    embedxpl-forge    →  pip install embedxpl-forge")
  end
  if #cves > 0 then
    table.insert(lines, string.format("  %d matching CVE module(s) available:", #cves))
    for _, c in ipairs(cves) do
      table.insert(lines, string.format("    printerxpl-forge run --module %s --target <IP>", c.xpl))
    end
  end
  return table.concat(lines, "\n")
end

-- ── PJL helper: build PJL command with UEL wrapper ───────────────────────────
function _M.pjl_cmd(cmd)
  return "\x1b%-12345X@PJL\r\n" .. cmd .. "\r\n\x1b%-12345X"
end

-- ── Verdict helper ────────────────────────────────────────────────────────────
function _M.verdict(is_vuln, is_possible)
  if is_vuln     then return _M.VERDICT.VULN     end
  if is_possible then return _M.VERDICT.POSSIBLE  end
  return _M.VERDICT.NOT_VULN
end

return _M
