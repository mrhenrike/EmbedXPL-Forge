-- embedxpl-ups-pdu-vuln.nse
-- EmbedXPL-Forge NSE Script
-- UPS and PDU Device CVE Fingerprinting and Validation
--
-- Author : Andre Henrique (@mrhenrike) | Uniao Geek -- https://github.com/Uniao-Geek
-- Version: 1.0.0
-- License: Same as Nmap -- See https://nmap.org/book/man-legal.html
--
-- DESCRIPTION:
--   Fingerprints UPS Network Management Cards and PDU management interfaces.
--
--   Covered CVEs:
--     CVE-2025-46412 -- Vertiv Liebert UPS auth bypass (CVSS 9.8)
--     CVE-2025-41426 -- Vertiv Liebert NMC stack BOF (CVSS 9.8)
--     Dataprobe iBoot -- Multi-CVE unauth RCE (CVSS 9.8, Claroty)
--     ICSR-2026-02-001 -- PDUExperts Smart PDU unauth RCE (CVSS 9.8)
--
-- USAGE:
--   nmap -p 80,443 --script embedxpl-ups-pdu-vuln <target>

local http   = require "http"
local nmap   = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table  = require "table"

description = [[
Fingerprints UPS NMC and PDU management interfaces. Validates CVE-2025-46412
(Vertiv Liebert auth bypass), Dataprobe iBoot multi-CVE, and PDUExperts RCE.
]]

author     = "Andre Henrique (@mrhenrike) | Uniao Geek"
license    = "Same as Nmap -- See https://nmap.org/book/man-legal.html"
categories = { "vuln", "safe", "discovery" }

portrule = function(host, port)
  return port.protocol == "tcp" and (
    port.number == 80 or port.number == 443 or port.number == 8080
  )
end

local function probe(host, port, path, hdrs)
  return http.get(host, port, path, { header = hdrs or {}, timeout = 6000 })
end

local function contains_any(s, patterns)
  for _, p in ipairs(patterns) do
    if string.find(s, p, 1, true) then return true end
  end
  return false
end

action = function(host, port)
  local output = {}

  -- Vertiv Liebert
  local rl = probe(host, port, "/api/system/info")
  if rl and contains_any(rl.body or "", {"Liebert", "Vertiv", "GXT5", "EXM", "NMC"}) then
    table.insert(output, "Vendor : Vertiv Liebert UPS NMC")
    table.insert(output, "CVE-2025-46412 (Auth Bypass CVSS 9.8) : POSSIBLY VULNERABLE -- system/info accessible")
    table.insert(output, "CVE-2025-41426 (Stack BOF CVSS 9.8) : POSSIBLY VULNERABLE -- same NMC firmware")
    table.insert(output, "EmbedXPL : use exploits/ups/vertiv/liebert_auth_bypass_cve_2025_46412")
  end

  -- Dataprobe iBoot
  local ri = probe(host, port, "/api/v1/system/info")
  if ri and contains_any(ri.body or "", {"iBoot", "Dataprobe", "IPDU"}) then
    table.insert(output, "Vendor : Dataprobe iBoot PDU")
    -- Test XFF bypass
    local ri2 = probe(host, port, "/api/v1/outlets", { ["X-Forwarded-For"] = "127.0.0.1" })
    if ri2 and ri2.status == 200 then
      table.insert(output, "Dataprobe iBoot Multi-CVE (CVSS 9.8) : VULNERABLE -- XFF bypass confirmed, outlets accessible")
    else
      table.insert(output, "Dataprobe iBoot Multi-CVE : POSSIBLY VULNERABLE -- iBoot detected")
    end
    table.insert(output, "EmbedXPL : use exploits/ups/dataprobe/iboot_multi_cve_unauth_rce")
  end

  -- PDUExperts
  local rp = probe(host, port, "/api/system/info")
  if rp and contains_any(rp.body or "", {"PDUExperts", "Smart PDU", "SmartPDU"}) then
    table.insert(output, "Vendor : PDUExperts Smart PDU")
    table.insert(output, "ICSR-2026-02-001 (Unauth RCE CVSS 9.8) : POSSIBLY VULNERABLE -- Smart PDU detected")
    table.insert(output, "EmbedXPL : use exploits/ups/pduexperts/smart_pdu_unauth_rce_icsr_2026_02_001")
  end

  if #output == 0 then return nil end
  return stdnse.format_output(true, output)
end
