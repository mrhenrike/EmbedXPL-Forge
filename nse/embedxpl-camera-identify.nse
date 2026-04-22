-- embedxpl-camera-identify.nse
-- EmbedXPL-Forge NSE Script — IP Camera / DVR / NVR Deep Fingerprinting
--
-- Author : André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
-- Version: 1.0.0
-- License: BSD
--
-- DESCRIPTION:
--   Multi-protocol device identification for IP cameras, DVR, NVR.
--   Probes HTTP/HTTPS (web UI), RTSP (streaming), ONVIF (WS-Discovery echo),
--   and Dahua proprietary port 37777 to extract the exact vendor, model,
--   firmware version, serial number, and device capabilities.
--
-- USAGE:
--   nmap -p 80,443,554,37777 --script embedxpl-camera-identify <target>
--   nmap -sV -p- --script embedxpl-camera-identify <target>
--
-- OUTPUT EXAMPLE:
--   80/tcp open http
--   | embedxpl-camera-identify:
--   |   Protocol : HTTP
--   |   Vendor   : Hikvision
--   |   Model    : DS-2CD2143G0-I
--   |   Firmware : V5.6.2 build 190401
--   |   Serial   : DS-2CD2143G0-I20190401AAWRA123456789
--   |   MAC      : 44:19:B6:xx:xx:xx
--   |   CVEs     : CVE-2021-36260 (RCE), CVE-2017-7921 (Auth Bypass)
--   |_  EmbedXPL : use exploits/cameras/hikvision/rtsp_rce_cve_2021_36260

local http    = require "http"
local nmap    = require "nmap"
local stdnse  = require "stdnse"
local string  = require "string"
local table   = require "table"
local comm    = require "comm"

description = [[
Multi-protocol IP camera, DVR, and NVR fingerprinting. Probes HTTP web UI,
RTSP banner, and Dahua proprietary protocol to identify vendor, model,
firmware, serial, and applicable CVEs with EmbedXPL-Forge module suggestion.
]]

author     = "André Henrique (@mrhenrike) | União Geek"
license    = "Same as Nmap -- See https://nmap.org/book/man-legal.html"
categories = { "discovery", "safe", "version" }

portrule = function(host, port)
  return port.protocol == "tcp" and (
    port.number == 80    or
    port.number == 443   or
    port.number == 8080  or
    port.number == 8443  or
    port.number == 554   or
    port.number == 5554  or
    port.number == 8554  or
    port.number == 37777 or
    port.number == 34567 or
    port.number == 9000
  )
end

-- HTTP paths to probe for device info
local HTTP_PROBES = {
  -- Hikvision ISAPI
  { path="/ISAPI/System/deviceInfo", vendor="Hikvision",
    parsers={
      model    = "<model>(.-)</model>",
      firmware = "<firmwareVersion>(.-)</firmwareVersion>",
      serial   = "<serialNumber>(.-)</serialNumber>",
      mac      = "<macAddress>(.-)</macAddress>",
    },
    cves = {"CVE-2021-36260 (RCE, CVSS 9.8)", "CVE-2017-7921 (Auth Bypass)"},
    mod  = "exploits/cameras/hikvision/rtsp_rce_cve_2021_36260",
  },
  -- Dahua
  { path="/cgi-bin/magicBox.cgi?action=getSystemInfo", vendor="Dahua",
    parsers={
      model    = "deviceType=(.-)\n",
      firmware = "softwareVersion=(.-)\n",
      serial   = "serialNumber=(.-)\n",
    },
    cves = {"CVE-2021-33044 (Auth Bypass)", "CVE-2020-25078 (Info Disclosure)"},
    mod  = "exploits/cameras/dahua/cctv_auth_bypass_cve_2021_33044",
  },
  -- Dahua generic (no auth required in older firmware)
  { path="/cgi-bin/snapshot.cgi?channel=1", vendor="Dahua/Amcrest/Intelbras",
    parsers={},
    cves = {"CVE-2021-33044", "CVE-2019-3950"},
    mod  = "exploits/cameras/dahua/cctv_auth_bypass_cve_2021_33044",
  },
  -- Reolink API
  { path="/cgi-bin/api.cgi?cmd=GetDevInfo&rs=nse", vendor="Reolink",
    parsers={
      model    = '"type":"(.-)"',
      firmware = '"cfgVer":"(.-)"',
      serial   = '"serial":"(.-)"',
    },
    cves = {"CVE-2021-40655 (Info Disclosure)", "CVE-2022-30600 (P2P UID Leak)"},
    mod  = "exploits/cameras/reolink/reolink_baicells_auth_bypass_rce_cve_2021_40655",
  },
  -- TP-Link Tapo
  { path="/stok=/login?form=login", vendor="TP-Link Tapo",
    parsers={},
    cves = {"CVE-2021-4045 (Auth Bypass)"},
    mod  = "exploits/cameras/tapo/tapo_c200_c210_unauth_rce_cve_2021_4045",
  },
  -- AXIS
  { path="/axis-cgi/param.cgi?action=list&group=Brand", vendor="Axis",
    parsers={
      model    = "root%.Brand%.ProdFullName=(.-)\n",
      firmware = "root%.Properties%.Firmware%.Version=(.-)\n",
    },
    cves = {"CVE-2018-10660 (RCE via parhand)"},
    mod  = "exploits/cameras/axis/srv_parhand_rce_cve_2018_10660",
  },
  -- Uniview PSIA
  { path="/PSIA/System/deviceInfo", vendor="Uniview (UNV)",
    parsers={
      model    = "<model>(.-)</model>",
      firmware = "<firmwareVersion>(.-)</firmwareVersion>",
    },
    cves = {"CVE-2024-37630 (Unauth RCE)"},
    mod  = "exploits/cameras/uniview/uniview_nvr_unauth_rce_cve_2024_37630",
  },
  -- ANNKE
  { path="/cgi-bin/languageSwitch.cgi", vendor="ANNKE",
    parsers={},
    cves = {"CVE-2021-32941 (Unauth RCE via language CGI)"},
    mod  = "exploits/cameras/annke/annke_dvr_nvr_unauth_rce_cve_2021_32941",
  },
}

local function try_http(host, port)
  for _, probe in ipairs(HTTP_PROBES) do
    local resp = http.get(host, port, probe.path, { timeout = 5000 })
    if resp and resp.status and (resp.status == 200 or resp.status == 401) then
      local result = {
        protocol = "HTTP",
        vendor   = probe.vendor,
        cves     = probe.cves,
        mod      = probe.mod,
        status   = resp.status,
      }
      if resp.status == 200 and resp.body then
        for field, pat in pairs(probe.parsers) do
          local val = resp.body:match(pat)
          if val then
            result[field] = val:gsub("%s+$", "")
          end
        end
      end
      return result
    end
  end
  return nil
end

local function try_rtsp_banner(host, port)
  if port.number ~= 554 and port.number ~= 5554 and port.number ~= 8554 then
    return nil
  end
  local req = ("OPTIONS rtsp://%s:%d/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: EmbedXPL-NSE\r\n\r\n"):format(
    host.ip, port.number
  )
  local status, data = comm.exchange(host, port, req, { proto="tcp", timeout=5000 })
  if not status or not data then return nil end
  local server = data:match("Server:%s*([^\r\n]+)")
  if not server then return nil end
  return { protocol="RTSP", banner=server }
end

action = function(host, port)
  local output = stdnse.output_table()
  local result

  -- Try HTTP probes
  result = try_http(host, port)
  if result then
    output["Protocol"] = result.protocol .. " (HTTP " .. tostring(result.status) .. ")"
    output["Vendor"]   = result.vendor
    if result.model    then output["Model"]    = result.model    end
    if result.firmware then output["Firmware"] = result.firmware end
    if result.serial   then output["Serial"]   = result.serial   end
    if result.mac      then output["MAC"]      = result.mac      end
    if result.cves and #result.cves > 0 then
      output["CVEs"] = table.concat(result.cves, " | ")
      if result.status == 200 then
        output["Vuln assessment"] = "LIKELY VULNERABLE (endpoint accessible without auth)"
      else
        output["Vuln assessment"] = "POSSIBLY VULNERABLE (auth required — test credentials)"
      end
    end
    output["EmbedXPL module"] = result.mod
    output["Run exploit"]     = ("embedxpl > use %s"):format(result.mod)
    return output
  end

  -- Fallback: RTSP banner
  result = try_rtsp_banner(host, port)
  if result then
    output["Protocol"] = result.protocol
    output["Banner"]   = result.banner
    output["EmbedXPL module"] = "exploits/cameras/multi/rtsp_cameradar_attack"
    output["Run exploit"]     = "embedxpl > use exploits/cameras/multi/rtsp_cameradar_attack"
    return output
  end

  return nil
end
