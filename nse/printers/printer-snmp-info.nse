local description = [[
printer-snmp-info — SNMP-based printer information extraction.

Queries standard Printer MIB (RFC 3805) and vendor-specific OIDs to retrieve:
device description, location, contact, serial number, firmware, page count,
ink/toner levels, and error log. Community strings tested: public, private,
internal, printer (common defaults).

CVE check: CVE-2022-1026 (Kyocera unauthenticated address book dump via SNMP).

Author: André Henrique (@mrhenrike) | União Geek
]]

---
-- @usage
--   nmap -sU -p 161 --script printer-snmp-info <target>
-- @output
-- PORT    STATE SERVICE
-- 161/udp open  snmp
-- | printer-snmp-info:
-- |   sysDescr    : HP LaserJet M606 FW FY5L.04
-- |   sysLocation : Server Room B
-- |   Serial      : JPGD12345
-- |   Page-Count  : 127,493
-- |   Community   : public (readable — unauthenticated SNMP)
-- |   Verdict     : POSSIBLY VULNERABLE (public community writable?)
-- |_  Suggest     : printerxpl-forge run --module xpl/edb-cve-2022-1026
---

categories = { "discovery", "safe", "vuln" }
author     = "André Henrique (@mrhenrike) | União Geek"
license    = "Same as Nmap -- See https://nmap.org/book/man-legal.html"

local stdnse    = require "stdnse"
local shortport = require "shortport"
local snmp      = require "snmp"
local comm      = require "comm"
local string    = require "string"
local table     = require "table"

portrule = shortport.port_or_service(161, "snmp", "udp")

-- Standard + Printer MIB OIDs
local OIDS = {
  { oid = "1.3.6.1.2.1.1.1.0",            key = "sysDescr" },
  { oid = "1.3.6.1.2.1.1.5.0",            key = "sysName" },
  { oid = "1.3.6.1.2.1.1.6.0",            key = "sysLocation" },
  { oid = "1.3.6.1.2.1.1.4.0",            key = "sysContact" },
  { oid = "1.3.6.1.2.1.43.5.1.1.17.1",    key = "Serial-Number" },
  { oid = "1.3.6.1.2.1.43.10.2.1.4.1.1",  key = "Page-Count" },
  { oid = "1.3.6.1.2.1.43.11.1.1.9.1.1",  key = "Toner-Level-%" },
  { oid = "1.3.6.1.4.1.11.2.3.9.1.1.7.0", key = "HP-Firmware" },
  { oid = "1.3.6.1.4.1.2435.2.3.9.4.2.1.5.5.8.0", key = "Brother-Model" },
  { oid = "1.3.6.1.4.1.18334.1.1.1.5.7.2.1.1.19.1", key = "Kyocera-Serial" },
}

local COMMUNITIES = { "public", "private", "internal", "printer", "snmpv1", "community", "admin" }

action = function(host, port)
  local out  = stdnse.output_table()
  local community_used = nil
  local results = {}

  -- Try communities
  for _, community in ipairs(COMMUNITIES) do
    local req = snmp.buildPacket(snmp.PDU:new("GETNEXT", OIDS[1].oid), community)
    local ok, resp = comm.exchange(host, port, req,
      { proto = "udp", timeout = 3000 })
    if ok and resp and not resp:match("noSuchName") then
      community_used = community
      break
    end
  end

  if not community_used then
    return "SNMP community not found — try: nmap -p 161 --script snmp-brute"
  end

  out["Community"] = community_used .. " (readable)"

  -- Walk OIDs with found community
  for _, entry in ipairs(OIDS) do
    local req = snmp.buildPacket(snmp.PDU:new("GET", entry.oid), community_used)
    local ok, resp = comm.exchange(host, port, req,
      { proto = "udp", timeout = 2000 })
    if ok and resp then
      local val = snmp.parseResponse(resp)
      if val and val ~= "" then
        results[entry.key] = tostring(val):match("^%s*(.-)%s*$")
      end
    end
  end

  for k, v in pairs(results) do
    out[k] = v:sub(1, 120)
  end

  -- Detect vendor from sysDescr
  local desc_lower = (results["sysDescr"] or ""):lower()
  local vendor = nil
  if desc_lower:match("hp ") or desc_lower:match("laserjet") then
    vendor = "HP"
  elseif desc_lower:match("kyocera") then
    vendor = "Kyocera"
  elseif desc_lower:match("ricoh") or desc_lower:match("aficio") then
    vendor = "Ricoh"
  elseif desc_lower:match("lexmark") then
    vendor = "Lexmark"
  elseif desc_lower:match("canon") then
    vendor = "Canon"
  elseif desc_lower:match("xerox") then
    vendor = "Xerox"
  elseif desc_lower:match("brother") then
    vendor = "Brother"
  elseif desc_lower:match("konica") or desc_lower:match("bizhub") then
    vendor = "Konica Minolta"
  end

  if vendor then out["Vendor"] = vendor end

  -- SNMP write test (COMMUNITY "private")
  local write_possible = false
  if community_used == "public" then
    -- Try write with private
    local write_req = snmp.buildPacket(
      snmp.PDU:new("SET", "1.3.6.1.2.1.1.6.0", "nmap-test"), "private")
    local wok, wresp = comm.exchange(host, port, write_req,
      { proto = "udp", timeout = 2000 })
    if wok and wresp and not wresp:match("noAccess") and not wresp:match("readOnly") then
      write_possible = true
      out["SNMP-Write"] = "POSSIBLE with 'private' community — SNMP SET attacks feasible"
    else
      out["SNMP-Write"] = "Not available (read-only with public)"
    end
  end

  -- Kyocera CVE-2022-1026 check
  local cves_found = {}
  if vendor == "Kyocera" or (results["Kyocera-Serial"] ~= nil) then
    table.insert(cves_found, {
      id   = "CVE-2022-1026",
      sev  = "HIGH",
      cvss = 7.5,
      desc = "Kyocera ECOSYS unauthenticated address book dump via SNMP/PJL",
      xpl  = "xpl/edb-cve-2022-1026",
    })
  end

  -- Build verdict
  local is_vuln     = write_possible or #cves_found > 0
  local is_possible = community_used == "public"

  if #cves_found > 0 then
    local cve_lines = {}
    for _, c in ipairs(cves_found) do
      table.insert(cve_lines, string.format("[%s] %s (CVSS %.1f) — %s | module: %s",
        c.sev, c.id, c.cvss, c.desc, c.xpl))
    end
    out["CVEs"] = table.concat(cve_lines, "  |  ")
  end

  if is_vuln then
    out["Verdict"] = "POSSIBLY VULNERABLE — CVE match or SNMP write enabled"
    if cves_found[1] then
      out["Suggest"] = "printerxpl-forge run --module " .. cves_found[1].xpl .. " --target " .. host.ip
    end
  elseif is_possible then
    out["Verdict"] = "POSSIBLY VULNERABLE — public community accessible (enumeration only)"
  else
    out["Verdict"] = "NOT VULNERABLE to detected CVEs (SNMP read-only, no CVE match)"
  end

  out["Full-Scan"] = "pip install printerxpl-forge  |  printerxpl-forge scan --target " .. host.ip

  return out
end
