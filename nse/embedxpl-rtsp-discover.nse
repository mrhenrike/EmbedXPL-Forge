-- embedxpl-rtsp-discover.nse
-- EmbedXPL-Forge NSE Script — RTSP Service Discovery & Banner Grab
--
-- Author : André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
-- Version: 1.0.0
-- License: BSD
--
-- DESCRIPTION:
--   Detects RTSP-speaking services on target ports, grabs the Server banner,
--   extracts Public header (supported RTSP methods), and identifies the
--   camera vendor/model from the server string.
--   On positive detection, suggests the EmbedXPL-Forge module to use for
--   full exploitation.
--
-- USAGE:
--   nmap -p 554,5554,8554 --script embedxpl-rtsp-discover <target>
--   nmap -p 554,5554,8554 --script embedxpl-rtsp-discover --script-args rtsp.timeout=3 <target>
--
-- OUTPUT EXAMPLE:
--   554/tcp open rtsp
--   | embedxpl-rtsp-discover:
--   |   Server: Hikvision IP Camera NVRA (V5.4.5)
--   |   Methods: OPTIONS, DESCRIBE, SETUP, PLAY, TEARDOWN
--   |   Vendor: Hikvision
--   |   Model fingerprint: DS-2CD series (H.265 NVRA)
--   |   Known CVEs: CVE-2021-36260 (RCE), CVE-2017-7921 (Auth Bypass)
--   |_  EmbedXPL: use exploits/cameras/hikvision/rtsp_rce_cve_2021_36260
--
-- REFERENCES:
--   RFC 2326 — Real Time Streaming Protocol
--   https://github.com/mrhenrike/EmbedXPL-Forge

local nmap   = require "nmap"
local stdnse = require "stdnse"
local comm   = require "comm"
local string = require "string"
local table  = require "table"

description = [[
Discovers RTSP streaming services, grabs server banners, identifies camera
vendor/model, and cross-references known CVEs. Suggests the corresponding
EmbedXPL-Forge module for complete exploitation.
]]

author     = "André Henrique (@mrhenrike) | União Geek"
license    = "Same as Nmap -- See https://nmap.org/book/man-legal.html"
categories = { "discovery", "safe", "version" }

portrule = function(host, port)
  return port.protocol == "tcp" and (
    port.number == 554  or
    port.number == 5554 or
    port.number == 8554 or
    port.number == 10554 or
    port.number == 3554 or
    port.number == 1935 or
    port.number == 7447
  )
end

-- Vendor fingerprint table: pattern → {vendor, model_hint, cves, embedxpl_module}
local FINGERPRINTS = {
  { pat = "Hikvision",         vendor = "Hikvision",
    cves = {"CVE-2021-36260 (RCE, CVSS 9.8)", "CVE-2017-7921 (Auth Bypass)"},
    mod  = "exploits/cameras/hikvision/rtsp_rce_cve_2021_36260" },
  { pat = "Dahua",             vendor = "Dahua",
    cves = {"CVE-2021-33044 (Auth Bypass)", "CVE-2020-25078 (Info Disclosure)"},
    mod  = "exploits/cameras/dahua/cctv_auth_bypass_cve_2021_33044" },
  { pat = "AXIS",              vendor = "Axis",
    cves = {"CVE-2018-10660 (RCE)"},
    mod  = "exploits/cameras/axis/srv_parhand_rce_cve_2018_10660" },
  { pat = "Reolink",           vendor = "Reolink",
    cves = {"CVE-2021-40655 (Info Disclosure + Default Creds)"},
    mod  = "exploits/cameras/reolink/reolink_baicells_auth_bypass_rce_cve_2021_40655" },
  { pat = "Edimax",            vendor = "Edimax",
    cves = {"CVE-2025-1316 (Unauth RCE, CISA KEV)"},
    mod  = "exploits/cameras/edimax/ic7100_unauth_rce_cve_2025_1316" },
  { pat = "Amcrest",           vendor = "Amcrest",
    cves = {"CVE-2019-3950 (Config Disclosure)"},
    mod  = "exploits/cameras/amcrest/amcrest_camera_unauth_info_disclosure_cve_2019_3950" },
  { pat = "TP%-LINK",          vendor = "TP-Link Tapo",
    cves = {"CVE-2021-4045 (Auth Bypass)"},
    mod  = "exploits/cameras/tapo/tapo_c200_c210_unauth_rce_cve_2021_4045" },
  { pat = "Uniview",           vendor = "Uniview (UNV)",
    cves = {"CVE-2024-37630 (Unauth RCE)"},
    mod  = "exploits/cameras/uniview/uniview_nvr_unauth_rce_cve_2024_37630" },
  { pat = "Intelbras",         vendor = "Intelbras",
    cves = {"CVE-2021-36260 (via Dahua OEM)"},
    mod  = "exploits/cameras/intelbras/cctv_dahua_rce_cve_2021_36260" },
  { pat = "GrandStream",       vendor = "Grandstream",
    cves = {"SQLi (GXV3611HD)"},
    mod  = "exploits/cameras/grandstream/gxv3611hd_ip_camera_sqli" },
  { pat = "ANNKE",             vendor = "ANNKE",
    cves = {"CVE-2021-32941 (Unauth RCE via CGI)"},
    mod  = "exploits/cameras/annke/annke_dvr_nvr_unauth_rce_cve_2021_32941" },
  { pat = "MVPower",           vendor = "MVPower DVR",
    cves = {"JAWS DVR RCE"},
    mod  = "exploits/cameras/mvpower/dvr_jaws_rce" },
  { pat = "Xiongmai",          vendor = "Xiongmai (OEM)",
    cves = {"uc-httpd path traversal (generic)"},
    mod  = "exploits/cameras/xiongmai/uc_httpd_path_traversal" },
}

local function rtsp_options(host, port)
  local req = ("OPTIONS rtsp://%s:%d/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: EmbedXPL-NSE\r\n\r\n"):format(
    host.ip, port.number
  )
  local timeout = tonumber(stdnse.get_script_args("rtsp.timeout")) or 5
  local status, data = comm.exchange(
    host, port, req,
    { proto = "tcp", timeout = timeout * 1000 }
  )
  if not status then
    return nil
  end
  return data
end

local function parse_header(data, name)
  if not data then return nil end
  local val = data:match(name .. ":%s*([^\r\n]+)")
  return val
end

local function fingerprint(server_str)
  if not server_str then return nil end
  for _, fp in ipairs(FINGERPRINTS) do
    if server_str:match(fp.pat) then
      return fp
    end
  end
  return nil
end

action = function(host, port)
  local data = rtsp_options(host, port)
  if not data then
    return nil
  end

  -- Must have RTSP status line
  local status_code = data:match("RTSP/1%.%d+%s+(%d+)")
  if not status_code then
    return nil
  end

  local output = stdnse.output_table()
  local server  = parse_header(data, "Server") or "(unknown)"
  local methods = parse_header(data, "Public") or "(not disclosed)"
  local session = parse_header(data, "Session") or ""

  output["Status"]  = status_code
  output["Server"]  = server
  output["Methods"] = methods
  if session ~= "" then
    output["Session"] = session
  end

  -- Fingerprint
  local fp = fingerprint(server)
  if fp then
    output["Vendor"] = fp.vendor
    if #fp.cves > 0 then
      output["Known CVEs"] = table.concat(fp.cves, ", ")
    end
    output["EmbedXPL module"] = fp.mod
    output["Exploit hint"] = ("embedxpl > use %s"):format(fp.mod)
  else
    output["Vendor"] = "Unknown (generic RTSP)"
    output["EmbedXPL module"] = "scanners/cameras/rtsp_scanner"
    output["Exploit hint"] = "embedxpl > use scanners/cameras/rtsp_scanner"
  end

  -- RTSP attack suggestion
  output["Full attack"] = "embedxpl > use exploits/cameras/multi/rtsp_cameradar_attack"

  return output
end
