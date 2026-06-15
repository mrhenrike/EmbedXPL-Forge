-- embedxpl-switch-vuln.nse
-- EmbedXPL-Forge NSE Script
-- Network Switch CVE Fingerprinting and Validation
--
-- Author : Andre Henrique (@mrhenrike) | Uniao Geek -- https://github.com/Uniao-Geek
-- Version: 1.0.0
-- License: Same as Nmap -- See https://nmap.org/book/man-legal.html
--
-- DESCRIPTION:
--   Fingerprints managed network switches and validates recent CVEs.
--
--   Covered CVEs:
--     CVE-2026-1668  -- TP-Link Omada unauth RCE (CVSS 9.8)
--     CVE-2026-3828  -- Hikvision PoE switch auth RCE (CVSS 7.2, EOL)
--     CVE-2026-3823  -- Atop EHG2408 industrial stack BOF (CVSS 9.3)
--     CVE-2026-7473  -- Arista EOS privesc CISA KEV (detection only)
--
-- USAGE:
--   nmap -p 80,443 --script embedxpl-switch-vuln <target>

local http   = require "http"
local nmap   = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table  = require "table"

description = [[
Fingerprints managed network switches (TP-Link Omada, Hikvision, Atop, Arista)
and validates recent CVEs with lightweight HTTP probes.
]]

author     = "Andre Henrique (@mrhenrike) | Uniao Geek"
license    = "Same as Nmap -- See https://nmap.org/book/man-legal.html"
categories = { "vuln", "safe", "discovery" }

portrule = function(host, port)
  return port.protocol == "tcp" and (
    port.number == 80 or port.number == 443 or port.number == 8080 or port.number == 8443
  )
end

local function probe(host, port, path)
  return http.get(host, port, path, { timeout = 6000 })
end

local function contains_any(s, patterns)
  for _, p in ipairs(patterns) do
    if string.find(s, p, 1, true) then return true end
  end
  return false
end

action = function(host, port)
  local output = {}

  -- TP-Link Omada check
  local r = probe(host, port, "/api/v1/device/info")
  if r and r.status == 200 and contains_any(r.body or "", {"Omada", "TP-Link", "TL-SG"}) then
    table.insert(output, "Vendor : TP-Link Omada Switch")
    -- CVE-2026-1668: probe privileged endpoint with model string
    local r2 = http.get(host, port, "/api/v1/system/status",
      { header = { ["X-Omada-Header"] = "TL-SG2024" }, timeout = 6000 })
    if r2 and r2.status == 200 then
      table.insert(output, "CVE-2026-1668 (Unauth RCE CVSS 9.8) : POSSIBLY VULNERABLE -- system/status returned 200 with model-header bypass")
      table.insert(output, "EmbedXPL : use exploits/switches/tplink/omada_unauth_rce_cve_2026_1668")
    else
      table.insert(output, "CVE-2026-1668 : CHECK MANUALLY")
    end
  end

  -- Hikvision ISAPI check
  local rh = probe(host, port, "/ISAPI/System/deviceInfo")
  if rh and rh.status == 200 and contains_any(rh.body or "", {"Hikvision", "DS-3E", "ISAPI"}) then
    table.insert(output, "Vendor : Hikvision Switch")
    table.insert(output, "CVE-2026-3828 (Auth RCE EOL CVSS 7.2) : POSSIBLY VULNERABLE -- ISAPI endpoint accessible")
    table.insert(output, "EmbedXPL : use exploits/switches/hikvision/poe_switch_auth_rce_cve_2026_3828")
  end

  -- Atop EHG check
  local ra = probe(host, port, "/")
  if ra and ra.status ~= nil and contains_any(ra.body or "", {"Atop", "EHG"}) then
    table.insert(output, "Vendor : Atop Technology EHG Industrial Switch")
    table.insert(output, "CVE-2026-3823 (Unauth Stack BOF CVSS 9.3) : POSSIBLY VULNERABLE -- Atop EHG detected")
    table.insert(output, "EmbedXPL : use exploits/switches/atop/ehg2408_stack_bof_cve_2026_3823")
  end

  -- Arista EOS REST API check
  local rar = probe(host, port, "/rest/v1/system/version")
  if rar and rar.status == 200 and contains_any(rar.body or "", {"Arista", "EOS"}) then
    table.insert(output, "Vendor : Arista EOS")
    table.insert(output, "CVE-2026-7473 (Privesc CISA KEV) : POSSIBLY VULNERABLE -- EOS REST API accessible, no patch available")
    table.insert(output, "EmbedXPL : use exploits/switches/arista/eos_privesc_detection_cve_2026_7473")
  end

  if #output == 0 then return nil end
  return stdnse.format_output(true, output)
end
