local description = [[
printer-ipp-info — IPP (Internet Printing Protocol) enumeration on port 631.

Sends IPP Get-Printer-Attributes to enumerate: printer make/model, firmware version,
supported document formats, color capabilities, duplex support, media types, and
printer state. Performs secondary CVE check for CUPS and Lexmark IPP vulnerabilities.

Checks for:
  - CUPS CVE-2024-47176 / CVE-2026-34980 (unauthenticated RCE)
  - Lexmark CVE-2023-50739 (IPP heap buffer overflow)
  - Anonymous print job acceptance (no auth required)

Author: André Henrique (@mrhenrike) | União Geek
]]

---
-- @usage
--   nmap -p 631 --script printer-ipp-info <target>
-- @output
-- PORT    STATE SERVICE
-- 631/tcp open  ipp
-- | printer-ipp-info:
-- |   Make-Model    : CUPS 2.4.16 (Linux)
-- |   State         : idle
-- |   Auth-Required : NO (anonymous print accepted)
-- |   Formats       : application/pdf, image/jpeg, application/postscript
-- |   [CRITICAL] CVE-2026-34980 — CUPS 2.4.16 unauthenticated RCE via PPD injection
-- |   Verdict       : POSSIBLY VULNERABLE
-- |_  Suggest       : printerxpl-forge run --module xpl/research/research-cups-chain-2026
---

categories = { "discovery", "safe", "vuln" }
author     = "André Henrique (@mrhenrike) | União Geek"
license    = "Same as Nmap -- See https://nmap.org/book/man-legal.html"

local stdnse    = require "stdnse"
local shortport = require "shortport"
local http      = require "http"
local string    = require "string"
local table     = require "table"

portrule = shortport.port_or_service(631, "ipp", "tcp")

-- IPP attribute tag constants
local IPP_TAG_OPERATION  = "\x01"
local IPP_TAG_END        = "\x03"
local IPP_TAG_CHARSET    = "\x47"
local IPP_TAG_LANG       = "\x48"
local IPP_TAG_URI        = "\x45"
local IPP_TAG_KEYWORD    = "\x44"
local IPP_TAG_ENUM       = "\x23"
local IPP_TAG_NAME       = "\x42"

-- Build IPP Get-Printer-Attributes request
local function build_get_printer_attrs(host, port)
  local printer_uri = string.format("ipp://%s:%d/printers/", host.ip, port.number)
  local uri_bytes = printer_uri

  return
    "\x02\x00"   ..  -- IPP 2.0
    "\x00\x0b"   ..  -- Get-Printer-Attributes op
    "\x00\x00\x00\x01" ..  -- request-id = 1
    IPP_TAG_OPERATION ..
    IPP_TAG_CHARSET .. "\x00\x12" .. "attributes-charset" .. "\x00\x05" .. "utf-8" ..
    IPP_TAG_LANG    .. "\x00\x1b" .. "attributes-natural-language" .. "\x00\x05" .. "en-us" ..
    IPP_TAG_URI     .. "\x00\x0b" .. "printer-uri" ..
      string.char(0x00, #uri_bytes >> 8, #uri_bytes & 0xff) .. uri_bytes ..
    IPP_TAG_KEYWORD .. "\x00\x14" .. "requested-attributes" .. "\x00\x03" .. "all" ..
    IPP_TAG_END
end

-- Extract string value from IPP binary response after a keyword
local function ipp_extract(resp, keyword)
  local pos = resp:find(keyword, 1, true)
  if not pos then return nil end
  -- Skip keyword + length, grab value
  local val_start = pos + #keyword + 2
  if val_start > #resp then return nil end
  local val_len = string.byte(resp, val_start - 1) * 256 + string.byte(resp, val_start)
  if val_start + val_len > #resp + 1 then return nil end
  return resp:sub(val_start + 1, val_start + val_len)
end

-- Try anonymous print job to test auth
local function test_anon_print(host, port)
  local printer_uri = string.format("ipp://%s:%d/printers/default", host.ip, port.number)
  local jn = "nmap-probe"
  local jn_bytes = jn
  local payload =
    "\x02\x00\x00\x02\x00\x00\x00\x02" ..  -- Print-Job
    IPP_TAG_OPERATION ..
    IPP_TAG_CHARSET .. "\x00\x12" .. "attributes-charset" .. "\x00\x05" .. "utf-8" ..
    IPP_TAG_LANG    .. "\x00\x1b" .. "attributes-natural-language" .. "\x00\x05" .. "en-us" ..
    IPP_TAG_URI     .. "\x00\x0b" .. "printer-uri" ..
      string.char(0x00, #printer_uri >> 8, #printer_uri & 0xff) .. printer_uri ..
    IPP_TAG_NAME    .. "\x00\x08" .. "job-name" ..
      string.char(0x00, #jn_bytes >> 8, #jn_bytes & 0xff) .. jn_bytes ..
    IPP_TAG_END     .. "%!PS\n"  -- tiny PostScript body

  local resp = http.post(
    host, port.number, "/printers/default",
    { header = { ["Content-Type"] = "application/ipp" } },
    nil, payload
  )
  if resp then
    -- 200 = accepted, 401/403 = auth required, 426 = client error (no job but auth ok)
    return resp.status, resp.body or ""
  end
  return nil, ""
end

action = function(host, port)
  local attrs_req = build_get_printer_attrs(host, port)
  local resp = http.post(
    host, port.number, "/printers/",
    { header = { ["Content-Type"] = "application/ipp" } },
    nil, attrs_req
  )

  if not resp or not resp.body or resp.status ~= 200 then
    -- Try /ipp/print as fallback
    resp = http.post(
      host, port.number, "/ipp/print",
      { header = { ["Content-Type"] = "application/ipp" } },
      nil, attrs_req
    )
    if not resp or not resp.body then
      return "No IPP response — server may not support IPP or requires TLS"
    end
  end

  local body = resp.body
  local out  = stdnse.output_table()

  -- Extract key attributes
  local model = ipp_extract(body, "printer-make-and-model")
  if model then out["Make-Model"] = model end

  local state = ipp_extract(body, "printer-state")
  if state then
    local states = { ["\x03"] = "idle", ["\x04"] = "processing", ["\x05"] = "stopped" }
    out["State"] = states[state] or ("state-" .. state:byte(1))
  end

  local formats = ipp_extract(body, "document-format-supported")
  if formats then out["Formats"] = formats:gsub("[%c]", ","):sub(1, 120) end

  local uri_security = ipp_extract(body, "uri-security-supported")
  out["TLS"] = (uri_security and uri_security ~= "none") and "Supported" or "None/Unknown"

  -- Test anonymous print
  local auth_status, _ = test_anon_print(host, port)
  local anon_print = false
  if auth_status and (auth_status == 200 or auth_status == 426) then
    out["Auth-Required"] = "NO — anonymous print jobs accepted"
    anon_print = true
  elseif auth_status == 401 or auth_status == 403 then
    out["Auth-Required"] = "YES"
  else
    out["Auth-Required"] = "UNKNOWN"
  end

  -- CVE checks
  local cves_found = {}
  local body_lower = body:lower()
  local snippet = body:gsub("[%c]", " ")

  -- CUPS version check
  local cups_ver = model and model:match("CUPS%s+([%d%.]+)")
  if cups_ver then
    out["CUPS-Version"] = cups_ver
    if cups_ver == "2.4.16" then
      table.insert(cves_found, {
        id = "CVE-2026-34980",
        sev = "CRITICAL",
        cvss = 9.1,
        desc = "CUPS 2.4.16 unauthenticated RCE via PPD newline injection",
        xpl  = "xpl/research/research-cups-chain-2026",
      })
    end
    if cups_ver >= "2.4.0" and cups_ver <= "2.4.9" then
      table.insert(cves_found, {
        id = "CVE-2024-47176",
        sev = "CRITICAL",
        cvss = 9.9,
        desc = "CUPS cups-browsed unauthenticated RCE chain",
        xpl  = "xpl/edb-cve-2024-47176",
      })
    end
  end

  -- Lexmark check
  if snippet:lower():match("lexmark") then
    table.insert(cves_found, {
      id = "CVE-2023-50739",
      sev = "HIGH",
      cvss = 8.8,
      desc = "Lexmark IPP heap buffer overflow → RCE (100+ models)",
      xpl  = "xpl/edb-cve-2023-50739",
    })
  end

  -- Output CVEs
  if #cves_found > 0 then
    local cve_lines = {}
    for _, c in ipairs(cves_found) do
      table.insert(cve_lines, string.format(
        "[%s] %s (CVSS %.1f) — %s | module: %s",
        c.sev, c.id, c.cvss, c.desc, c.xpl))
    end
    out["CVEs"] = table.concat(cve_lines, "  |  ")
  end

  -- Verdict
  local is_vuln     = #cves_found > 0 and anon_print
  local is_possible = #cves_found > 0 or anon_print

  if is_vuln then
    out["Verdict"] = "VULNERABLE — CVE match + anonymous print accepted"
    if cves_found[1] then
      out["Suggest"] = "printerxpl-forge run --module " .. cves_found[1].xpl .. " --target " .. host.ip
    end
  elseif is_possible then
    out["Verdict"] = "POSSIBLY VULNERABLE — CVE match or anon print (verify with printer-vuln-check)"
    if cves_found[1] then
      out["Suggest"] = "printerxpl-forge run --module " .. cves_found[1].xpl .. " --dry-run --target " .. host.ip
    end
  else
    out["Verdict"] = "NOT VULNERABLE (no matching CVEs detected on IPP)"
  end

  out["Full-Scan"] = "pip install printerxpl-forge  |  printerxpl-forge scan --target " .. host.ip

  return out
end
