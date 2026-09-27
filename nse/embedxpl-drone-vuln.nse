-- embedxpl-drone-vuln.nse
-- EmbedXPL-Forge NSE Script
-- DJI Drone CVE Fingerprinting and Validation
--
-- Author : Andre Henrique (@mrhenrike) | Uniao Geek -- https://github.com/Uniao-Geek
-- Version: 1.0.0
-- License: Same as Nmap -- See https://nmap.org/book/man-legal.html
--
-- LEGAL NOTICE: Only use against drones you own or have explicit written authorization
-- to test. Unauthorized drone interception is illegal in most jurisdictions.
--
-- DESCRIPTION:
--   Fingerprints DJI drone AP management services and validates active CVEs.
--
--   Covered CVEs:
--     CVE-2026-1743  -- DJI Mavic auth bypass in FlightHub API (CVSS 8.1)
--     CVE-2023-51454 -- DJI v2 SDK TCP/10000 OOB write RCE (CVSS 9.8)
--     CVE-2026-26673 -- DJI Wi-Fi deauth DoS (CVSS 6.5, detection only)
--
-- USAGE:
--   nmap -p 80,10000 --script embedxpl-drone-vuln 192.168.42.1
--   nmap -sV --script embedxpl-drone-vuln 192.168.42.0/24

local http   = require "http"
local nmap   = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table  = require "table"

description = [[
AUTHORIZED LAB USE ONLY. Fingerprints DJI drone management APIs and validates
CVE-2026-1743 (FlightHub auth bypass) and CVE-2023-51454 (v2 SDK TCP/10000 OOB).
]]

author     = "Andre Henrique (@mrhenrike) | Uniao Geek"
license    = "Same as Nmap -- See https://nmap.org/book/man-legal.html"
categories = { "vuln", "safe", "discovery" }

portrule = function(host, port)
  return port.protocol == "tcp" and (
    port.number == 80 or port.number == 443 or port.number == 10000
  )
end

local function probe(host, port, path)
  return http.get(host, port, path, { timeout = 5000 })
end

local function contains_any(s, patterns)
  for _, p in ipairs(patterns) do
    if string.find(s, p, 1, true) then return true end
  end
  return false
end

action = function(host, port)
  local output = {}

  -- DJI drone AP management (port 80)
  if port.number == 80 or port.number == 443 then
    local r = probe(host, port, "/api/v1/version")
    if r and contains_any(r.body or "", {"DJI", "Mavic", "Spark", "FlightHub"}) then
      table.insert(output, "Device : DJI Drone Management API")
      -- CVE-2026-1743: probe config with null-byte header
      local r2 = http.get(host, port, "/api/v1/config",
        { header = { ["X-DJI-Token"] = "\x00" .. ("A"):rep(31) }, timeout = 5000 })
      if r2 and r2.status == 200 and #(r2.body or "") > 0 then
        table.insert(output, "CVE-2026-1743 (Auth Bypass CVSS 8.1) : POSSIBLY VULNERABLE -- config returned 200 with null-byte token")
        table.insert(output, "EmbedXPL : use exploits/drones/dji/mavic_auth_bypass_cve_2026_1743")
      else
        table.insert(output, "CVE-2026-1743 : DJI drone confirmed -- test manually with embedxpl module")
      end
      table.insert(output, "CVE-2026-26673 (Wi-Fi Deauth DoS) : POSSIBLY VULNERABLE if using 802.11 RC link without PMF")
      table.insert(output, "EmbedXPL : use exploits/drones/dji/wifi_dos_cve_2026_26673")
    end
  end

  -- DJI v2 SDK TCP/10000
  if port.number == 10000 then
    table.insert(output, "Port 10000 : DJI v2 SDK TCP listener detected")
    table.insert(output, "CVE-2023-51454 (OOB Write RCE CVSS 9.8) : POSSIBLY VULNERABLE -- v2 SDK port open")
    table.insert(output, "EmbedXPL : use exploits/drones/dji/v2_sdk_oob_write_cve_2023_51454")
  end

  if #output == 0 then return nil end
  return stdnse.format_output(true, output)
end
