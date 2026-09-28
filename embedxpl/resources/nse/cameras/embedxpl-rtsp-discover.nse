-- embedxpl-rtsp-discover.nse
-- EmbedXPL v5.0.0 — Custom NSE
-- Discovers RTSP cameras by banner, probes common streams.
-- Based on: embedxpl/modules/scanners/cameras/rtsp_discover.py
-- Authors: André Henrique (@mrhenrike) | União Geek

local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"
local comm = require "comm"

description = [[
EmbedXPL RTSP Camera Discovery.
Probes common RTSP paths on cameras (Hikvision, Dahua, Axis, Intelbras, generic).
Extracts stream URLs, model info, and authentication status.
]]

categories = {"discovery", "safe", "embedxpl"}

portrule = shortport.port_or_service({554, 8554, 5554}, "rtsp")

-- Common RTSP paths by vendor
local RTSP_PATHS = {
    "/",                               -- generic
    "/live",                          -- generic
    "/stream",                        -- generic
    "/channel1",                      -- generic
    "/Streaming/Channels/101",        -- Hikvision main stream
    "/Streaming/Channels/102",        -- Hikvision sub stream
    "/cam/realmonitor?channel=1&subtype=0",  -- Dahua
    "/axis-media/media.amp",          -- Axis
    "/live/ch00_0",                   -- Hikvision variant
    "/user=admin&password=&channel=1&stream=0.sdp",  -- generic
}

local function probe_rtsp(host, port, path)
    local status, data = comm.exchange(host, port.number,
        "OPTIONS " .. path .. " RTSP/1.0\r\nCSeq: 1\r\n\r\n",
        {timeout=3000})
    if status then
        return data
    end
    return nil
end

local function detect_vendor(banner)
    if banner:find("Hikvision") or banner:find("HIKVISION") then return "Hikvision"
    elseif banner:find("Dahua") or banner:find("DAHUA") then return "Dahua"
    elseif banner:find("Axis") then return "Axis"
    elseif banner:find("Intelbras") then return "Intelbras"
    elseif banner:find("Amcrest") then return "Amcrest"
    elseif banner:find("Foscam") then return "Foscam"
    elseif banner:find("Reolink") then return "Reolink"
    end
    return "Unknown"
end

action = function(host, port)
    local results = {}
    local found_paths = {}

    for _, path in ipairs(RTSP_PATHS) do
        local resp = probe_rtsp(host, port, path)
        if resp then
            if resp:find("200 OK") or resp:find("401") or resp:find("RTSP/1") then
                local vendor = detect_vendor(resp)
                local auth_required = resp:find("401") and "YES" or "NO"
                table.insert(found_paths, {
                    path = path,
                    vendor = vendor,
                    auth = auth_required,
                    stream = "rtsp://" .. host.ip .. ":" .. port.number .. path
                })
            end
        end
    end

    if #found_paths == 0 then return nil end

    results[#results+1] = "EmbedXPL RTSP Camera:"
    for _, f in ipairs(found_paths) do
        results[#results+1] = string.format("  Stream: %s", f.stream)
        results[#results+1] = string.format("  Vendor: %s | Auth Required: %s", f.vendor, f.auth)
    end

    return table.concat(results, "\n")
end
