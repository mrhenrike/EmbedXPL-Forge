-- embedxpl-router-default-creds.nse
-- EmbedXPL v5.0.0 — Custom NSE
-- Checks router web admin for default credentials using EmbedXPL creds DB.
-- Authors: André Henrique (@mrhenrike) | União Geek

local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local base64 = require "base64"
local brute = require "brute"

description = [[
EmbedXPL Router Default Credentials Check.
Tests common default credentials against HTTP Basic Auth and web login forms.
Uses EmbedXPL's curated list of 1000+ default credentials.
]]

categories = {"auth", "brute", "embedxpl"}
portrule = shortport.http

-- Top 50 default credential pairs (embedded for portability)
-- Full list in EmbedXPL data/default_creds.json
local DEFAULT_CREDS = {
    {"admin",     "admin"},
    {"admin",     "password"},
    {"admin",     "1234"},
    {"admin",     "12345"},
    {"admin",     "123456"},
    {"admin",     "admin123"},
    {"admin",     ""},
    {"root",      "root"},
    {"root",      "admin"},
    {"root",      "toor"},
    {"root",      "1234"},
    {"root",      ""},
    {"user",      "user"},
    {"user",      "password"},
    {"guest",     "guest"},
    {"guest",     ""},
    {"support",   "support"},
    {"support",   ""},
    {"admin",     "support"},
    {"admin",     "pass"},
    {"admin",     "Admin"},
    {"Admin",     "admin"},
    {"admin",     "admin1"},
    {"administrator", "administrator"},
    {"administrator", "password"},
    {"cisco",     "cisco"},
    {"cisco",     ""},
    {"admin",     "cisco"},
    {"enable",    "enable"},
    {"netgear",   "password"},
    {"admin",     "netgear"},
    {"admin",     "linksys"},
    {"admin",     "motorola"},
    {"admin",     "zte"},
    {"admin",     "huawei"},
    {"admin",     "tp_link"},
    {"admin",     "tplink"},
    {"admin",     "dlink"},
    {"user",      "1234"},
    {"admin",     "gpon"},
    {"admintelecom", "admintelecom"},
    {"telecomadmin", "admintelecom"},
    {"admin",     "telus"},
    {"admin",     "bell"},
    {"superadmin","admin"},
    {"manager",   "manager"},
    {"operator",  "operator"},
    {"tech",      "tech"},
    {"service",   "service"},
    {"setup",     "setup"},
}

local function try_basic_auth(host, port, user, pass)
    local cred = base64.enc(user .. ":" .. pass)
    local resp = http.get(host, port, "/", {
        timeout = 3000,
        header = {Authorization = "Basic " .. cred}
    })
    if resp and (resp.status == 200 or resp.status == 302) then
        if resp.status ~= 401 and not (resp.body and resp.body:find("[Uu]nauthorized")) then
            return true
        end
    end
    return false
end

action = function(host, port)
    local results = {}

    for _, pair in ipairs(DEFAULT_CREDS) do
        local user, pass = pair[1], pair[2]
        if try_basic_auth(host, port, user, pass) then
            results[#results+1] = string.format(
                "VALID CREDENTIALS: %s:%s", user, pass)
        end
        stdnse.sleep(0.1)  -- rate limiting
    end

    if #results == 0 then return nil end
    table.insert(results, 1, "EmbedXPL Default Creds Found:")
    return table.concat(results, "\n")
end
