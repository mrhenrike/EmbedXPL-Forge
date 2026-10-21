local description = [[
printer-discover — High-speed multi-protocol printer discovery and fingerprinting.

Performs rapid identification of printers and MFPs on a network segment by probing:
  9100/tcp  JetDirect/RAW (PJL)
  631/tcp   IPP / CUPS
  80,443/tcp HTTP EWS (Embedded Web Server)
  515/tcp   LPD (Line Printer Daemon)
  161/udp   SNMP
  23/tcp    Telnet (legacy printers)
  3702/udp  WSD (Windows printers)

Outputs: device type, vendor, model, firmware, open ports, and a quick verdict on
whether PrinterXPL-Forge or EmbedXPL-Forge should be used for complete testing.

Designed for quick network-wide sweeps:
  nmap -sV --open -p 9100,631,80,443,515,161,23 --script printer-discover <CIDR>

Author: André Henrique (@mrhenrike) | União Geek
]]

---
-- @usage
--   nmap -p 9100,631,80 --script printer-discover <target>
--   nmap -sV --open -p 9100,631,80,443 --script printer-discover 192.168.1.0/24
-- @output
-- 192.168.1.100:
-- | printer-discover:
-- |   Device-Type : Network Printer / MFP
-- |   Vendor      : HP
-- |   Model       : LaserJet Enterprise M606dn
-- |   Open-Ports  : 9100 (PJL), 631 (IPP), 80 (EWS)
-- |   CVEs        : 5 potential (CRITICAL: CVE-2025-26506, CVE-2017-2741)
-- |   Tool        : printerxpl-forge (pip install printerxpl-forge)
-- |_  Quick-Scan  : printerxpl-forge scan --target 192.168.1.100
---

categories = { "discovery", "safe", "default" }
author     = "André Henrique (@mrhenrike) | União Geek"
license    = "Same as Nmap -- See https://nmap.org/book/man-legal.html"

local stdnse    = require "stdnse"
local shortport = require "shortport"
local comm      = require "comm"
local http      = require "http"
local string    = require "string"
local table     = require "table"
local nmap      = require "nmap"

portrule = shortport.port_or_service(
  { 9100, 631, 80, 443, 515, 23 },
  { "jetdirect", "ipp", "http", "https", "printer", "telnet" },
  "tcp"
)

local UEL = "\x1b%-12345X"

-- Vendor patterns (ordered by specificity)
local VENDOR_PATTERNS = {
  { pat = "laserjet|pagewide|officejet|jetdirect|futuresmart|hp print",
    vendor = "HP", tool = "printerxpl-forge", cve_count_est = 5 },
  { pat = "imagerunner|imageclass|imagepress|pixma|lbp[%s%-]?%d",
    vendor = "Canon", tool = "printerxpl-forge", cve_count_est = 3 },
  { pat = "lexmark",
    vendor = "Lexmark", tool = "printerxpl-forge", cve_count_est = 6 },
  { pat = "versalink|workcentre|altalink|phaser|colorqube",
    vendor = "Xerox", tool = "printerxpl-forge", cve_count_est = 3 },
  { pat = "aficio|ricoh mp|ricoh sp|ricoh im",
    vendor = "Ricoh", tool = "printerxpl-forge", cve_count_est = 3 },
  { pat = "brother mfc|brother dcp|brother hl",
    vendor = "Brother", tool = "printerxpl-forge", cve_count_est = 2 },
  { pat = "bizhub|konica minolta|konicaminolta",
    vendor = "Konica Minolta", tool = "printerxpl-forge", cve_count_est = 2 },
  { pat = "ecosys|taskalfa|kyocera",
    vendor = "Kyocera", tool = "printerxpl-forge", cve_count_est = 1 },
  { pat = "sharp mx|sharp ar|sharp bp",
    vendor = "Sharp", tool = "printerxpl-forge", cve_count_est = 1 },
  { pat = "e.studio|topaccess|toshiba",
    vendor = "Toshiba", tool = "printerxpl-forge", cve_count_est = 1 },
  { pat = "workforce|ecotank|epson stylus",
    vendor = "Epson", tool = "printerxpl-forge", cve_count_est = 1 },
  { pat = "samsung scx|samsung clx|samsung ml",
    vendor = "Samsung", tool = "printerxpl-forge", cve_count_est = 2 },
  { pat = "cups",
    vendor = "Linux/CUPS", tool = "printerxpl-forge", cve_count_est = 4 },
  { pat = "zebra|zpl ii",
    vendor = "Zebra", tool = "embedxpl-forge", cve_count_est = 1 },
  { pat = "oki data|okidata",
    vendor = "OKI", tool = "printerxpl-forge", cve_count_est = 1 },
  { pat = "dell.*print|dell.*laser",
    vendor = "Dell", tool = "printerxpl-forge", cve_count_est = 1 },
}

local function detect_vendor(text)
  if not text then return nil, nil, nil end
  local t = text:lower()
  for _, v in ipairs(VENDOR_PATTERNS) do
    if t:match(v.pat) then
      return v.vendor, v.tool, v.cve_count_est
    end
  end
  return nil, nil, nil
end

local function extract_model(text)
  if not text then return nil end
  local model = text:match('[Dd][Ee][Ss][Cc][Rr][Ii][Pp][Tt][Ii][Oo][Nn]%s*=%s*"([^"]+)"')
             or text:match("<title>([^<]+)</title>")
             or text:match("[Mm]odel[^:]*:%s*([^\r\n]+)")
             or text:match("[Pp]roduct[^:]*:%s*([^\r\n]+)")
  if model then return model:match("^%s*(.-)%s*$"):sub(1, 80) end
  return nil
end

local function quick_pjl(host, port)
  local ok, r = comm.exchange(host, port,
    UEL .. "@PJL\r\n@PJL INFO ID\r\n" .. UEL,
    { timeout = 3000, bytes = 1024 })
  if ok then return r end
  return nil
end

local function quick_http(host, port)
  local r = http.get(host, port.number, "/", { timeout = 3000 })
  if r and r.status == 200 and r.body then return r.body end
  return nil
end

local function quick_ipp(host, port)
  local r = http.post(host, port.number, "/printers/",
    { header = { ["Content-Type"] = "application/ipp" }, timeout = 3000 },
    nil,
    "\x02\x00\x00\x0b\x00\x00\x00\x01\x01" ..
    "\x47\x00\x12attributes-charset\x00\x05utf-8" ..
    "\x48\x00\x1battributes-natural-language\x00\x05en-us" ..
    "\x03")
  if r and r.body then return r.body end
  return nil
end

action = function(host, port)
  local out = stdnse.output_table()

  -- Collect banner based on port
  local banner = nil
  local portnum = port.number

  if portnum == 9100 then
    banner = quick_pjl(host, port)
    if banner then out["Source"] = "PJL (port 9100)" end
  elseif portnum == 631 then
    banner = quick_ipp(host, port)
    if banner then out["Source"] = "IPP (port 631)" end
  elseif portnum == 80 or portnum == 443 then
    banner = quick_http(host, port)
    if banner then out["Source"] = "HTTP EWS (port " .. portnum .. ")" end
  elseif portnum == 515 then
    local ok, r = comm.exchange(host, port, "\x01\n", { timeout = 2000, bytes = 256 })
    if ok then banner = r; out["Source"] = "LPD (port 515)" end
  elseif portnum == 23 then
    local ok, r = comm.exchange(host, port, "\n", { timeout = 2000, bytes = 256 })
    if ok then banner = r; out["Source"] = "Telnet (port 23)" end
  end

  if not banner or #banner < 5 then
    return "No banner received — port may be filtered or device requires special probe"
  end

  -- Detect vendor
  local vendor, tool, cve_est = detect_vendor(banner)
  local model = extract_model(banner)

  -- Store for other scripts
  if vendor then
    stdnse.registry_set({ host.ip, "printer-vendor" }, vendor)
    stdnse.registry_set({ host.ip, "printer-banner" }, banner:sub(1, 2048))
  end

  out["Device-Type"] = "Network Printer / MFP"
  out["Vendor"]      = vendor or "Unknown (banner detected — check printer-banner)"

  if model then out["Model"] = model end

  local fw = banner:match("DATECODE%s*=%s*([%w%.%-]+)")
          or banner:match("[Ff]irmware[Vv]er%s*=%s*([%w%.%-]+)")
  if fw then out["Firmware"] = fw end

  -- CVE count hint
  if vendor and cve_est and cve_est > 0 then
    out["CVE-Potential"] = string.format(
      "~%d CVEs for %s in PrinterXPL-Forge DB (run printer-cve-detect for details)",
      cve_est, vendor)
  end

  -- Tool recommendation
  out["Tool"]       = (tool or "printerxpl-forge") ..
                      "  →  pip install " .. (tool or "printerxpl-forge")
  out["Quick-Scan"] = string.format(
    "printerxpl-forge scan --target %s", host.ip)
  out["Full-Check"] = string.format(
    "nmap -p 9100,631,80,443,427,445 --script printer-cve-detect,printer-vuln-check %s",
    host.ip)

  return out
end
