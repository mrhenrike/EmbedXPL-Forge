-- embedxpl-ics-asset-discover.nse
-- EmbedXPL v5.0.0 — Custom NSE
-- Industrial asset fingerprinting: PLCs, HMIs, RTUs, engineering workstations.
-- Probes multiple ICS protocols to identify vendor and model.
-- Authors: André Henrique (@mrhenrike) | União Geek

local comm = require "comm"
local shortport = require "shortport"
local stdnse = require "stdnse"
local nmap = require "nmap"

description = [[
EmbedXPL ICS Asset Discovery.
Fingerprints industrial devices by probing Modbus, S7, ENIP, BACnet, DNP3 ports.
Reports vendor, model, firmware when available.
]]

categories = {"discovery", "safe", "ics", "embedxpl"}

-- Port → protocol mapping
local ICS_PORTS = {
    [502]   = "Modbus TCP",
    [102]   = "Siemens S7",
    [44818] = "EtherNet/IP",
    [47808] = "BACnet",
    [20000] = "DNP3",
    [4840]  = "OPC-UA",
    [1089]  = "FF HSE",
    [1090]  = "FF HSE",
    [2404]  = "IEC 60870-5-104",
    [1502]  = "TriStation",
    [9600]  = "Omron FINS",
    [102]   = "S7/TSAP",
}

portrule = function(host, port)
    return ICS_PORTS[port.number] ~= nil
end

-- Modbus Read Device Identification (FC43)
local function probe_modbus(host, port)
    local req = string.char(0x00,0x01, 0x00,0x00, 0x00,0x05, 0x01, 0x2b,0x0e,0x01,0x00)
    local status, data = comm.exchange(host, port.number, req, {timeout=3000, proto="tcp"})
    if status and #data > 8 then
        return "Modbus device: " .. stdnse.tohex(data:sub(9,20))
    end
    return nil
end

-- S7 Identification
local function probe_s7(host, port)
    -- COTP + S7 Read SZL (system status list)
    local cotp_cr = string.char(0x03,0x00,0x00,0x16, 0x11,0xe0, 0x00,0x00,
                                0x00,0x01, 0x00,0xc1,0x02,0x01,0x00,
                                0xc2,0x02,0x01,0x02, 0xc0,0x01,0x09)
    local status, data = comm.exchange(host, port.number, cotp_cr, {timeout=3000, proto="tcp"})
    if status and data:find("\x03\x00") then
        return "Siemens S7 PLC detected"
    end
    return nil
end

action = function(host, port)
    local proto = ICS_PORTS[port.number] or "ICS"
    local detail = nil

    if port.number == 502 then
        detail = probe_modbus(host, port)
    elseif port.number == 102 then
        detail = probe_s7(host, port)
    end

    local result = string.format("ICS Asset: Protocol=%s Port=%d", proto, port.number)
    if detail then result = result .. "\n  " .. detail end

    return result
end
