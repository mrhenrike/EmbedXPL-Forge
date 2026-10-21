local description = [[
printer-lexmark-ipp — Lexmark-specific IPP vulnerability assessment.

Targets Lexmark MFPs and printers via port 631 (IPP) and port 80 (EWS).
Detects and validates:
  - CVE-2023-50739: IPP heap buffer overflow → RCE (100+ models, ZDI-CAN-22549)
  - CVE-2023-23560: Lexmark Web Services SSRF → RCE (Pwn2Own Toronto 2022)
  - CVE-2023-26067: Post-auth RCE via device configuration API
  - CVE-2023-50733: EWS SSRF — printer as lateral movement pivot
  - CVE-2023-50738: Firmware downgrade bypass
  - CVE-2022-24935: Lexmark authentication bypass

Author: André Henrique (@mrhenrike) | União Geek
]]

---
-- @usage
--   nmap -p 631,80 --script printer-lexmark-ipp <target>
-- @output
-- PORT    STATE SERVICE
-- 631/tcp open  ipp
-- | printer-lexmark-ipp:
-- |   Vendor  : Lexmark
-- |   Model   : CX622 (detected from IPP attributes)
-- |   [CRITICAL] CVE-2023-23560 (CVSS 9.0) — Lexmark SSRF-to-RCE
-- |   [HIGH]    CVE-2023-50739 (CVSS 8.8) — Lexmark IPP heap BOF (100+ models)
-- |   [MEDIUM]  CVE-2023-50733 (CVSS 6.5) — Lexmark EWS SSRF pivot
-- |   Verdict : POSSIBLY VULNERABLE
-- |_  Suggest : printerxpl-forge run --module xpl/edb-51928 --target <IP>
---

categories = { "vuln", "safe" }
author     = "André Henrique (@mrhenrike) | União Geek"
license    = "Same as Nmap -- See https://nmap.org/book/man-legal.html"

local stdnse    = require "stdnse"
local shortport = require "shortport"
local http      = require "http"
local string    = require "string"
local table     = require "table"

portrule = shortport.port_or_service({ 631, 80, 443 }, { "ipp", "http", "https" }, "tcp")

local LEXMARK_CVES = {
  { id="CVE-2023-23560", cvss=9.0, sev="CRITICAL",
    desc="Lexmark SSRF-to-RCE via Web Services interface — unauthenticated (Pwn2Own Toronto 2022)",
    xpl="xpl/edb-51928",
    port_check=80 },
  { id="CVE-2023-26067", cvss=9.1, sev="CRITICAL",
    desc="Lexmark post-auth RCE via device configuration API",
    xpl="xpl/edb-cve-2023-26067",
    port_check=80 },
  { id="CVE-2023-50739", cvss=8.8, sev="HIGH",
    desc="Lexmark IPP heap buffer overflow → RCE (100+ models, ZDI-CAN-22549)",
    xpl="xpl/edb-cve-2023-50739",
    port_check=631 },
  { id="CVE-2023-50733", cvss=6.5, sev="MEDIUM",
    desc="Lexmark EWS SSRF — pivot to internal network resources",
    xpl="xpl/edb-cve-2023-50733",
    port_check=80 },
  { id="CVE-2023-50738", cvss=7.2, sev="HIGH",
    desc="Lexmark firmware downgrade bypass → re-expose historical vulnerabilities",
    xpl="xpl/research/research-lexmark-fw-decrypt",
    port_check=80 },
  { id="CVE-2022-24935", cvss=8.0, sev="HIGH",
    desc="Lexmark authentication bypass via crafted POST to NPS endpoint",
    xpl="xpl/research/research-lexmark-auth",
    port_check=80 },
}

-- IPP probe to detect Lexmark
local function ipp_fingerprint(host, port)
  if port.number ~= 631 then return nil end
  local req =
    "\x02\x00\x00\x0b\x00\x00\x00\x01\x01" ..
    "\x47\x00\x12attributes-charset\x00\x05utf-8" ..
    "\x48\x00\x1battributes-natural-language\x00\x05en-us" ..
    "\x45\x00\x0bprinter-uri\x00\x0cipp://0.0.0.0/" ..
    "\x03"
  local resp = http.post(host, 631, "/printers/",
    { header = { ["Content-Type"] = "application/ipp" }, timeout = 5000 },
    nil, req)
  if resp and resp.body then return resp.body end
  return nil
end

-- HTTP EWS probe to detect Lexmark
local function http_fingerprint(host, port)
  local paths = { "/", "/cgi-bin/dynamic/", "/lexmark/", "/printer.html" }
  for _, p in ipairs(paths) do
    local r = http.get(host, port.number, p, { timeout = 5000 })
    if r and r.status == 200 and r.body then
      if r.body:lower():match("lexmark") then
        return r.body
      end
    end
  end
  return nil
end

-- Test CVE-2023-23560 SSRF surface
local function check_ssrf_surface(host, port)
  local r = http.get(host, port.number, "/cgi-bin/dynamic/config/webservices.html",
    { timeout = 4000 })
  if r and (r.status == 200 or r.status == 302) then
    return true
  end
  -- Try alternate
  r = http.get(host, port.number, "/webservices", { timeout = 3000 })
  if r and (r.status == 200 or r.status == 302) then return true end
  return false
end

-- Test CVE-2022-24935 auth bypass surface
local function check_nps_bypass(host, port)
  local r = http.post(host, port.number, "/cgi-bin/dynamic/nps",
    { header = { ["Content-Type"] = "application/x-www-form-urlencoded" },
      timeout = 4000 },
    nil, "auth=probe")
  if r and r.status == 200 then
    if r.body and r.body:lower():match("lexmark") then
      return true
    end
  end
  return false
end

action = function(host, port)
  local out = stdnse.output_table()

  -- Fingerprint
  local banner = nil
  local is_lexmark = false

  if port.number == 631 then
    banner = ipp_fingerprint(host, port)
    if banner and banner:lower():match("lexmark") then is_lexmark = true end
  end

  if not is_lexmark then
    banner = http_fingerprint(host, port)
    if banner then is_lexmark = true end
  end

  if not is_lexmark then
    return "Lexmark not detected on port " .. port.number ..
           " — use printer-cve-detect for generic CVE matching"
  end

  out["Vendor"] = "Lexmark"

  -- Extract model if possible
  if banner then
    local model = banner:match("[Ll]exmark%s+([%w%-]+%s*[%w%-]*)")
    if model then out["Model"] = model:match("^%s*(.-)%s*$"):sub(1, 60) end
  end

  -- Active surface checks
  local ssrf_exposed  = check_ssrf_surface(host, port)
  local nps_exposed   = check_nps_bypass(host, port)

  if ssrf_exposed  then out["SSRF-Surface"]  = "Web Services config accessible — CVE-2023-23560" end
  if nps_exposed   then out["NPS-Surface"]   = "NPS endpoint responding — CVE-2022-24935" end

  -- Match CVEs
  local matched = {}
  for _, cve in ipairs(LEXMARK_CVES) do
    local relevant = (not cve.port_check) or (cve.port_check == port.number)
    if not relevant then
      relevant = cve.cvss >= 9.0  -- always include critical
    end
    local triggered = relevant
    if cve.id == "CVE-2023-23560" and not ssrf_exposed then triggered = relevant end
    if cve.id == "CVE-2022-24935" and not nps_exposed  then triggered = relevant end
    if triggered then table.insert(matched, cve) end
  end

  -- Sort by CVSS
  table.sort(matched, function(a, b) return a.cvss > b.cvss end)

  if #matched > 0 then
    local cve_lines = {}
    for _, c in ipairs(matched) do
      table.insert(cve_lines, string.format("[%s] %s (CVSS %.1f) — %s\n            module: %s",
        c.sev, c.id, c.cvss, c.desc, c.xpl))
    end
    out["CVEs"] = cve_lines
  end

  -- Verdict
  local is_vuln = ssrf_exposed or nps_exposed
  if is_vuln then
    out["Verdict"] = "POSSIBLY VULNERABLE — active surface exposure confirmed"
    out["Suggest"] = "printerxpl-forge run --module " .. matched[1].xpl .. " --target " .. host.ip
  else
    out["Verdict"] = "POSSIBLY VULNERABLE — Lexmark confirmed but active surfaces not exposed"
    out["Suggest"] = "printerxpl-forge run --module " .. matched[1].xpl .. " --dry-run --target " .. host.ip
  end

  out["Full-Scan"] = "pip install printerxpl-forge  |  printerxpl-forge scan --target " .. host.ip

  return out
end
