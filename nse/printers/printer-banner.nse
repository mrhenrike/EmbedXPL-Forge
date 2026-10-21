local description = [[
printer-banner — Multi-protocol printer banner grabber and vendor fingerprinting.

Probes ports 9100 (PJL/RAW), 631 (IPP), 80/443 (HTTP EWS), 515 (LPD), and 23 (Telnet)
to collect the printer's manufacturer, model, firmware version, and serial number.
Fingerprint results are cross-referenced against the PrinterXPL-Forge CVE database to
list potentially exploitable vulnerabilities and suggest specific exploit modules.

References:
  https://github.com/mrhenrike/PrinterXPL-Forge
  https://github.com/mrhenrike/PrinterXPL-Forge/wiki/NSE

Author: André Henrique (@mrhenrike) | União Geek
]]

---
-- @usage
--   nmap -sV -p 9100,631,80,443,515,23 --script printer-banner <target>
-- @output
-- PORT     STATE SERVICE
-- 9100/tcp open  jetdirect
-- | printer-banner:
-- |   Vendor   : HP
-- |   Family   : LaserJet/OfficeJet/PageWide
-- |   Banner   : HP LaserJet M606 / FutureSmart 5.6
-- |   Firmware : FY5L.04.A.00.00
-- |   Serial   : JPGD12345
-- |   CVEs     : 3 matching (run printer-cve-detect for details)
-- |_  Suggest  : printerxpl-forge run --module xpl/edb-cve-2025-26506 --target <IP>
--
-- @xmloutput
-- <table key="banner">...</table>
---

categories = { "discovery", "safe", "default" }
author     = "André Henrique (@mrhenrike) | União Geek"
license    = "Same as Nmap -- See https://nmap.org/book/man-legal.html"

local stdnse  = require "stdnse"
local nmap    = require "nmap"
local shortport = require "shortport"
local comm    = require "comm"
local http    = require "http"
local string  = require "string"
local table   = require "table"

-- Load shared library (must be placed in nmap/nselib/ or nse/lib/ during install)
local ok, printerxpl = pcall(require, "printerxpl")
if not ok then
  printerxpl = nil
end

-- ── Port rule: fire on any of the typical printer ports ──────────────────────
portrule = shortport.port_or_service(
  { 9100, 631, 80, 443, 515, 23 },
  { "jetdirect", "ipp", "http", "https", "printer", "telnet" },
  "tcp"
)

-- ── PJL probe: send @PJL INFO ID and @PJL INFO CONFIG ────────────────────────
local function pjl_probe(host, port)
  local uel = "\x1b%-12345X"
  local cmd = uel .. "@PJL\r\n@PJL INFO ID\r\n@PJL INFO CONFIG\r\n@PJL INFO STATUS\r\n" .. uel
  local status, result = comm.exchange(host, port, cmd, { timeout = 5000, bytes = 4096 })
  if status then return result end
  return nil
end

-- ── IPP probe: Get-Printer-Attributes (minimal) ───────────────────────────────
local function ipp_probe(host, port)
  local resp = http.post(
    host, port, "/ipp/print",
    { header = { ["Content-Type"] = "application/ipp" } },
    nil,
    -- IPP Get-Printer-Attributes request (version 1.1)
    "\x01\x01\x00\x0b\x00\x00\x00\x01" ..
    "\x01" ..
    "\x47\x00\x12attributes-charset\x00\x05utf-8" ..
    "\x48\x00\x1battributes-natural-language\x00\x05en-us" ..
    "\x03"
  )
  if resp and resp.status then
    return resp.body or ""
  end
  return nil
end

-- ── HTTP EWS probe ───────────────────────────────────────────────────────────
local function http_probe(host, port)
  local paths = { "/", "/hp/device/", "/cgi-bin/dynamic/", "/TopAccess/", "/web/index.html" }
  for _, path in ipairs(paths) do
    local resp = http.get(host, port, path, { timeout = 5000 })
    if resp and resp.status == 200 and resp.body and #resp.body > 50 then
      return resp.body
    end
  end
  return nil
end

-- ── LPD probe: send LPD short-status request ─────────────────────────────────
local function lpd_probe(host, port)
  local status, result = comm.exchange(host, port, "\x01\n", { timeout = 3000, bytes = 512 })
  if status then return result end
  return nil
end

-- ── Extract fields from combined banner text ──────────────────────────────────
local function extract_info(text)
  local info = {}
  -- Firmware / version
  local fw = text:match("[Ff]irmware[Vv]ersion[^:]*:%s*([%w%.%-]+)")
              or text:match("DATECODE=%s*([%w%.]+)")
              or text:match("[Vv]ersion[^:]*:%s*([%w%.%-]+)")
  if fw then info.firmware = fw end
  -- Serial
  local sn = text:match("[Ss]erial[Nn]umber[^:]*:%s*([%w%-]+)")
              or text:match("SERIALNUMBER=%s*([%w%-]+)")
  if sn then info.serial = sn end
  -- Model (PJL style: DESCRIPTION="HP LaserJet P3015")
  local model = text:match('[Dd][Ee][Ss][Cc][Rr][Ii][Pp][Tt][Ii][Oo][Nn]="([^"]+)"')
                or text:match("[Mm]odel[^:]*:%s*([^\r\n]+)")
                or text:match("[Pp]roduct:%s*([^\r\n]+)")
  if model then info.model = model:match("^%s*(.-)%s*$") end
  -- IP address (from CUPS / IPP response)
  local ip = text:match("printer%-name%s*=%s*([%w%.%-]+)")
  if ip then info.printer_name = ip end
  return info
end

-- ── Main action ──────────────────────────────────────────────────────────────
action = function(host, port)
  local portnum = port.number
  local banner_text = ""
  local source = ""

  if portnum == 9100 then
    local r = pjl_probe(host, port)
    if r then banner_text = r; source = "PJL" end
  elseif portnum == 631 then
    local r = ipp_probe(host, port)
    if r then banner_text = r; source = "IPP" end
  elseif portnum == 80 or portnum == 443 then
    local r = http_probe(host, port)
    if r then banner_text = r; source = "HTTP-EWS" end
  elseif portnum == 515 then
    local r = lpd_probe(host, port)
    if r then banner_text = r; source = "LPD" end
  end

  if banner_text == "" then
    return nil
  end

  -- Vendor detection
  local vendor, family = nil, nil
  if printerxpl then
    vendor, family = printerxpl.detect_vendor(banner_text)
  else
    -- Fallback inline detection
    local b = banner_text:lower()
    if b:match("hp") or b:match("hewlett") or b:match("laserjet") then
      vendor, family = "HP", "LaserJet/OfficeJet"
    elseif b:match("canon") then vendor, family = "Canon", "imageCLASS/imageRUNNER"
    elseif b:match("lexmark") then vendor, family = "Lexmark", "MX/CX series"
    elseif b:match("ricoh") or b:match("aficio") then vendor, family = "Ricoh", "Aficio/MP"
    elseif b:match("xerox") then vendor, family = "Xerox", "WorkCentre/VersaLink"
    elseif b:match("brother") then vendor, family = "Brother", "MFC/DCP"
    elseif b:match("epson") then vendor, family = "Epson", "WorkForce"
    elseif b:match("konica") or b:match("bizhub") then vendor, family = "Konica Minolta", "bizhub"
    elseif b:match("kyocera") then vendor, family = "Kyocera", "ECOSYS"
    elseif b:match("sharp") then vendor, family = "Sharp", "MX"
    elseif b:match("toshiba") then vendor, family = "Toshiba", "e-STUDIO"
    elseif b:match("samsung") then vendor, family = "Samsung", "CLX/SCX"
    elseif b:match("cups") then vendor, family = "Linux/CUPS", "CUPS scheduler"
    end
  end

  local info = extract_info(banner_text)

  -- Collect CVE count hint
  local cve_count = 0
  local best_xpl = nil
  if printerxpl and vendor then
    local cves = printerxpl.match_cves(vendor)
    cve_count = #cves
    if cve_count > 0 then
      best_xpl = cves[1].xpl
    end
  end

  -- Build output
  local out = stdnse.output_table()
  out["Protocol"] = source
  if vendor then
    out["Vendor"]   = vendor
    out["Family"]   = family or "Unknown"
  end
  if info.model    then out["Model"]    = info.model    end
  if info.firmware then out["Firmware"] = info.firmware end
  if info.serial   then out["Serial"]   = info.serial   end

  -- Banner snippet (first 200 printable chars)
  local snippet = banner_text:gsub("[%c]", " "):sub(1, 200):match("^%s*(.-)%s*$")
  if #snippet > 0 then out["Banner"] = snippet end

  if cve_count > 0 then
    out["CVE-Count"] = string.format("%d matching CVEs (run printer-cve-detect for details)", cve_count)
    out["Suggest"]   = string.format(
      "printerxpl-forge run --module %s --target %s", best_xpl, host.ip)
  elseif vendor then
    out["CVE-Count"] = "0 matching (vendor known but no specific CVE match on this port)"
  end

  out["Full-Scan"] = "pip install printerxpl-forge  |  printerxpl-forge scan --target " .. host.ip

  return out
end
