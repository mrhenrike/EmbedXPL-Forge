local description = [[
printer-cups-rce — CUPS vulnerability detection (CVE-2024-47176 / CVE-2026-34980).

Specifically targets CUPS schedulers to detect:
  - CVE-2024-47176: cups-browsed listens on UDP 631 and accepts any browsing packet
    that can redirect to an attacker-controlled IPP server → unauthenticated RCE
  - CVE-2026-34980: CUPS 2.4.16 accepts newline characters in print job-name option,
    allowing injection of PPD: FoomaticRIPCommandLine directives → unauthenticated RCE

Detection is passive + version-based; no actual exploit payload is sent.

Author: André Henrique (@mrhenrike) | União Geek
]]

---
-- @usage
--   nmap -sU -sT -p U:631,T:631 --script printer-cups-rce <target>
--   nmap -p 631 --script printer-cups-rce <target>
-- @output
-- PORT    STATE SERVICE
-- 631/tcp open  ipp
-- | printer-cups-rce:
-- |   CUPS-Version  : 2.4.16
-- |   cups-browsed  : DETECTED (listening on UDP 631)
-- |   [CRITICAL] CVE-2026-34980 — CUPS 2.4.16 unauthenticated RCE via PPD injection
-- |   [CRITICAL] CVE-2024-47176 — cups-browsed unauthenticated RCE chain
-- |   Verdict       : VULNERABLE
-- |_  Suggest       : printerxpl-forge run --module xpl/research/research-cups-chain-2026
---

categories = { "vuln", "safe" }
author     = "André Henrique (@mrhenrike) | União Geek"
license    = "Same as Nmap -- See https://nmap.org/book/man-legal.html"

local stdnse    = require "stdnse"
local shortport = require "shortport"
local http      = require "http"
local comm      = require "comm"
local string    = require "string"
local table     = require "table"

portrule = shortport.port_or_service(631, { "ipp", "cups" }, { "tcp", "udp" })

local V = { VULN = "VULNERABLE", POSS = "POSSIBLY VULNERABLE", NOT = "NOT VULNERABLE" }

-- IPP Get-Printer-Attributes minimal request
local function ipp_probe(host, port)
  local printer_uri = string.format("ipp://%s:%d/", host.ip, port.number)
  local req =
    "\x02\x00\x00\x0b\x00\x00\x00\x01\x01" ..
    "\x47\x00\x12attributes-charset\x00\x05utf-8" ..
    "\x48\x00\x1battributes-natural-language\x00\x05en-us" ..
    "\x45\x00\x0bprinter-uri" ..
    string.char(0x00, #printer_uri >> 8, #printer_uri & 0xff) .. printer_uri ..
    "\x03"
  local resp = http.post(
    host, port.number, "/printers/",
    { header = { ["Content-Type"] = "application/ipp" }, timeout = 6000 },
    nil, req
  )
  if resp and resp.body then return resp.body end
  return nil
end

-- cups-browsed UDP probe: send a CUPS browse packet to port 631 UDP
local function probe_cups_browsed(host, port)
  -- Legacy CUPS browse packet (type=3 = printer, uri format)
  local browse_pkt = "3 5 http://nmap-probe:631/printers/ ipp://nmap-probe/printers/default\n"
  local ok, resp = comm.exchange(host, { number = 631, protocol = "udp" },
    browse_pkt, { timeout = 3000, bytes = 256 })
  -- If port sends any response or error, cups-browsed likely running
  return ok
end

-- HTTP check on CUPS web interface
local function get_cups_web(host, port)
  local r = http.get(host, port.number, "/", { timeout = 4000 })
  if r and r.body then return r.body end
  return nil
end

action = function(host, port)
  local out = stdnse.output_table()

  -- 1. IPP probe
  local ipp_body = ipp_probe(host, port)

  -- 2. HTTP CUPS web interface
  local web_body = get_cups_web(host, port)

  -- Combine for analysis
  local combined = (ipp_body or "") .. (web_body or "")

  if #combined < 10 then
    return "No IPP/CUPS response on port " .. port.number
  end

  -- Check if CUPS
  local is_cups = combined:lower():match("cups")
  if not is_cups then
    return "CUPS not detected on port " .. port.number .. " — try printer-ipp-info for generic IPP"
  end

  out["Service"] = "CUPS"

  -- Extract version
  local version = combined:match("CUPS%s+([%d%.]+)")
               or combined:match("cups%-(%d+%.%d+%.%d+)")
               or combined:match("<version>([%d%.]+)</version>")
  if version then out["CUPS-Version"] = version end

  -- cups-browsed probe
  local browsed = probe_cups_browsed(host, port)
  out["cups-browsed"] = browsed and "DETECTED (UDP 631 responding)" or "Not detected / filtered"

  -- CVE determination
  local cves = {}

  if version == "2.4.16" then
    table.insert(cves, {
      id   = "CVE-2026-34980",
      sev  = "CRITICAL",
      cvss = 9.1,
      desc = "CUPS 2.4.16 unauthenticated RCE via job-name newline → PPD FoomaticRIPCommandLine injection",
      xpl  = "xpl/research/research-cups-chain-2026",
    })
    table.insert(cves, {
      id   = "CVE-2026-34990",
      sev  = "HIGH",
      cvss = 7.8,
      desc = "CUPS 2.4.16 LPE to root via local printer race condition (chain with CVE-2026-34980)",
      xpl  = "xpl/research/research-cups-root-2026",
    })
  end

  if browsed then
    table.insert(cves, {
      id   = "CVE-2024-47176",
      sev  = "CRITICAL",
      cvss = 9.9,
      desc = "cups-browsed accepts any UDP browse packet → redirects print jobs to attacker IPP server → RCE chain",
      xpl  = "xpl/edb-cve-2024-47176",
    })
    table.insert(cves, {
      id   = "CVE-2024-47076",
      sev  = "HIGH",
      cvss = 8.6,
      desc = "libcupsfilters cfGetPrinterAttributes5 — no IPP attribute validation → data poisoning",
      xpl  = "xpl/edb-cve-2024-47176",
    })
    table.insert(cves, {
      id   = "CVE-2024-47175",
      sev  = "HIGH",
      cvss = 8.6,
      desc = "libppd ppdCreatePPDFromIPP2 — unsanitized IPP attrs written to PPD → code injection",
      xpl  = "xpl/edb-cve-2024-47176",
    })
    table.insert(cves, {
      id   = "CVE-2024-47177",
      sev  = "CRITICAL",
      cvss = 9.9,
      desc = "cups-filters FoomaticRIPCommandLine arbitrary command execution",
      xpl  = "xpl/edb-cve-2024-47176",
    })
  end

  if #cves > 0 then
    local lines = {}
    for _, c in ipairs(cves) do
      table.insert(lines, string.format("[%s] %s (CVSS %.1f) — %s",
        c.sev, c.id, c.cvss, c.desc))
    end
    out["CVEs"] = lines

    local is_vuln = version == "2.4.16" or browsed
    if is_vuln then
      out["Verdict"] = V.VULN .. " — " .. cves[1].id
    else
      out["Verdict"] = V.POSS .. " — check printer-vuln-check for confirmation"
    end
    out["Suggest"] = "printerxpl-forge run --module " .. cves[1].xpl .. " --target " .. host.ip
  else
    out["Verdict"] = V.NOT .. " — CUPS version not in vulnerable range and cups-browsed not detected"
  end

  out["Full-Scan"] = "pip install printerxpl-forge  |  printerxpl-forge run --module xpl/research/research-cups-chain-2026 --target " .. host.ip

  return out
end
