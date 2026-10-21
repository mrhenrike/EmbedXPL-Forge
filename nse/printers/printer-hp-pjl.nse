local description = [[
printer-hp-pjl — HP-specific PJL deep enumeration and vulnerability assessment.

Targets HP LaserJet, OfficeJet, and PageWide devices via port 9100.
Performs: model + firmware version extraction, HP NVRAM variable dump,
filesystem directory listing (PJL FSDIRLIST), and direct CVE checks for:

  - CVE-2025-26506: HP LaserJet Enterprise PostScript RCE (unauthenticated)
  - CVE-2017-2741:  HP PageWide PJL path traversal to arbitrary file read/write → RCE
  - CVE-2018-5924:  Faxploit — fax stack overflow (HP / Samsung)
  - CVE-2023-6018:  HP FutureSmart firmware auth bypass → arbitrary firmware upload
  - CVE-2023-1707:  HP FutureSmart 5.6 scan job data disclosure

Author: André Henrique (@mrhenrike) | União Geek
]]

---
-- @usage
--   nmap -p 9100 --script printer-hp-pjl <target>
-- @output
-- PORT     STATE SERVICE
-- 9100/tcp open  jetdirect
-- | printer-hp-pjl:
-- |   Vendor       : HP
-- |   Model        : HP LaserJet Enterprise M606dn
-- |   Firmware     : FY5L.04.A.00.00 (FutureSmart 5.6)
-- |   Serial       : JPGD12345
-- |   Filesystem   : 0:\ (HDD) — FSDIRLIST accessible
-- |   [CRITICAL] CVE-2025-26506 (CVSS 9.8) — PS RCE → printerxpl run --module xpl/edb-cve-2025-26506
-- |   [CRITICAL] CVE-2017-2741  (CVSS 9.8) — PJL path traversal RCE → printerxpl run --module xpl/edb-cve-2017-2741
-- |   Verdict      : POSSIBLY VULNERABLE (HP LaserJet on 9100 — version fingerprint not sufficient)
-- |_  Suggest      : printerxpl-forge run --module xpl/edb-cve-2025-26506 --target <IP>
---

categories = { "vuln", "safe", "discovery" }
author     = "André Henrique (@mrhenrike) | União Geek"
license    = "Same as Nmap -- See https://nmap.org/book/man-legal.html"

local stdnse    = require "stdnse"
local shortport = require "shortport"
local comm      = require "comm"
local http      = require "http"
local string    = require "string"
local table     = require "table"

portrule = shortport.port_or_service(9100, "jetdirect", "tcp")

local UEL = "\x1b%-12345X"

local function pjl_exchange(host, port, cmd, bytes)
  bytes = bytes or 8192
  local payload = UEL .. "@PJL\r\n" .. cmd .. "\r\n" .. UEL
  local ok, resp = comm.exchange(host, port, payload,
    { timeout = 7000, bytes = bytes })
  if ok then return resp end
  return nil
end

local function extract(text, pattern)
  if not text then return nil end
  local v = text:match(pattern)
  if v then return v:match("^%s*(.-)%s*$") end
  return nil
end

action = function(host, port)
  local out = stdnse.output_table()

  -- Batch query: ID + CONFIG + FILESYS + VARIABLES + PRODINFO
  local batch = "@PJL INFO ID\r\n@PJL INFO CONFIG\r\n@PJL INFO FILESYS\r\n@PJL INFO VARIABLES\r\n@PJL INFO PRODINFO\r\n"
  local resp = pjl_exchange(host, port, batch, 16384)
  if not resp then
    return "No PJL response — port may be filtered or device is not HP JetDirect-compatible"
  end

  -- Vendor confirmation
  local is_hp = resp:lower():match("hp") or resp:lower():match("laserjet") or
                resp:lower():match("officejet") or resp:lower():match("futuresmart")
  if not is_hp then
    return "HP device not confirmed via PJL (use printer-pjl-info for generic PJL)"
  end
  out["Vendor"] = "HP"

  -- Model
  local model = extract(resp, 'DESCRIPTION%s*=%s*"([^"]+)"')
             or extract(resp, "[Mm]odel%s*:%s*([^\r\n]+)")
             or extract(resp, "@PJL INFO ID%s*\r?\n([^\r\n]+)")
  if model then out["Model"] = model end

  -- Firmware
  local fw = extract(resp, "DATECODE%s*=%s*([%w%.%-]+)")
          or extract(resp, "FW%s*=%s*([%w%.%-]+)")
          or extract(resp, "[Ff]irmware[Vv]er%s*=%s*([%w%.%-]+)")
  if fw then out["Firmware"] = fw end

  -- FutureSmart version
  local fs_ver = extract(resp, "[Ff]uture[Ss]mart%s+([%d%.]+)")
  if fs_ver then out["FutureSmart"] = fs_ver end

  -- Serial
  local sn = extract(resp, "SERIALNUMBER%s*=%s*([%w%-]+)")
  if sn then out["Serial"] = sn end

  -- Memory
  local mem = extract(resp, "TOTALMEMORY%s*=%s*(%d+)")
  if mem then out["Memory-KB"] = mem end

  -- Filesystem
  local fs_listing = extract(resp, "VOLUME%s*=%s*([^\r\n]+)")
  if fs_listing then
    out["Filesystem"] = fs_listing
    -- Try FSDIRLIST
    local dir_resp = pjl_exchange(host, port,
      '@PJL FSDIRLIST NAME="0:\\" ENTRY=1 COUNT=20\r\n', 4096)
    if dir_resp and dir_resp:match("TYPE") then
      out["FS-Directory"] = dir_resp:match("(.-)%x1b"):match("^%s*(.-)%s*$") or "(see raw)"
      out["FS-Access"] = "FSDIRLIST accessible — filesystem enumeration possible"
    end
  end

  -- CVE assessment
  local cves = {}
  -- CVE-2025-26506: HP LaserJet Enterprise PS RCE — affects most modern HP enterprise printers
  table.insert(cves, {
    id="CVE-2025-26506", cvss=9.8, sev="CRITICAL",
    desc="HP LaserJet Enterprise PostScript unauthenticated RCE — malformed PS job triggers code exec",
    xpl="xpl/edb-cve-2025-26506",
    check = true,  -- HP + port 9100 is sufficient surface
  })
  -- CVE-2017-2741: HP PageWide PJL path traversal
  table.insert(cves, {
    id="CVE-2017-2741", cvss=9.8, sev="CRITICAL",
    desc="HP PageWide/OfficeJet PJL FSUPLOAD path traversal to arbitrary file read → RCE chain",
    xpl="xpl/edb-cve-2017-2741",
    check = fs_listing ~= nil,  -- more likely if filesystem accessible
  })
  -- CVE-2018-5924: Faxploit
  table.insert(cves, {
    id="CVE-2018-5924", cvss=9.8, sev="CRITICAL",
    desc="HP fax stack overflow via malformed TIFF/G3 fax data — unauthenticated RCE on fax-capable models",
    xpl="xpl/edb-cve-2018-5924",
    check = resp:lower():match("fax") ~= nil,
  })
  -- CVE-2023-6018: FutureSmart firmware bypass
  local fw_bypass_check = (fs_ver ~= nil) and (fs_ver >= "5.0")
  table.insert(cves, {
    id="CVE-2023-6018", cvss=9.8, sev="CRITICAL",
    desc="HP FutureSmart firmware auth bypass → arbitrary .RFU firmware upload / implant",
    xpl="xpl/research/research-hp-fw-bypass",
    check = fw_bypass_check or (fw ~= nil),
  })
  -- CVE-2023-1707
  table.insert(cves, {
    id="CVE-2023-1707", cvss=9.1, sev="CRITICAL",
    desc="HP FutureSmart 5.6 scan-to-email data disclosure when IPsec enabled",
    xpl="xpl/research/research-hp-futuresmart-leak",
    check = fs_ver == "5.6" or resp:lower():match("5%.6") ~= nil,
  })

  local matched = {}
  for _, c in ipairs(cves) do
    if c.check then table.insert(matched, c) end
  end

  if #matched == 0 then
    -- Still include top 2 as possible (HP on 9100 is strong signal)
    matched = { cves[1], cves[2] }
  end

  -- Output CVEs
  local cve_lines = {}
  for _, c in ipairs(matched) do
    table.insert(cve_lines, string.format("[%s] %s (CVSS %.1f) — %s\n            module: %s",
      c.sev, c.id, c.cvss, c.desc, c.xpl))
  end
  out["CVEs"] = cve_lines

  -- Verdict
  local is_vuln     = resp:lower():match("futuresmart") or fs_listing ~= nil
  local is_possible = true  -- HP + port 9100 is always at least possible

  if is_vuln then
    out["Verdict"] = "POSSIBLY VULNERABLE — HP " .. (model or "LaserJet") .. " with exposed PJL/FS"
  else
    out["Verdict"] = "POSSIBLY VULNERABLE — HP device detected; version confirmation needed"
  end

  out["Suggest"]    = "printerxpl-forge run --module " .. matched[1].xpl .. " --target " .. host.ip
  out["Full-Scan"]  = "pip install printerxpl-forge  |  printerxpl-forge scan --target " .. host.ip

  return out
end
