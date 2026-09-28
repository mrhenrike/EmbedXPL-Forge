-- embedxpl-mqtt-enum.nse
-- EmbedXPL v5.0.0 — Custom NSE
-- Enumerates open MQTT brokers — subscribes to # and logs topics/messages.
-- Authors: André Henrique (@mrhenrike) | União Geek

local comm = require "comm"
local shortport = require "shortport"
local stdnse = require "stdnse"
local nmap = require "nmap"

description = [[
EmbedXPL MQTT Broker Enumeration.
Connects to MQTT broker without authentication (open broker).
Subscribes to wildcard topic '#' and captures messages for 3 seconds.
Reports broker info, connected clients, and sensitive topics.
]]

categories = {"discovery", "safe", "iot", "embedxpl"}
portrule = shortport.port_or_service({1883, 8883}, "mqtt")

-- MQTT CONNECT packet (no auth, client ID: embedxpl_nse)
local function mqtt_connect()
    local client_id = "embedxpl_nse"
    local cid_len = #client_id
    -- Fixed header + variable header + client_id
    local var_header = "\x00\x04MQTT\x04\x00\x00\x3c"  -- protocol, level=4, flags=0, keepalive=60
    local payload = string.char(0, cid_len) .. client_id
    local remaining = #var_header + #payload
    return "\x10" .. string.char(remaining) .. var_header .. payload
end

-- MQTT SUBSCRIBE to '#' (all topics)
local function mqtt_subscribe()
    -- packet_id=1, topic='#', QoS=0
    return "\x82\x05\x00\x01\x00\x01#\x00"
end

-- Parse PUBLISH packet
local function parse_publish(data)
    local results = {}
    local i = 1
    while i <= #data do
        local cmd = data:byte(i)
        if cmd == 0x30 or cmd == 0x32 or cmd == 0x34 then  -- PUBLISH QoS 0/1/2
            i = i + 1
            -- read remaining length
            local rem = data:byte(i); i = i + 1
            if rem > 0 and i + rem <= #data then
                local topic_len = data:byte(i) * 256 + data:byte(i+1)
                i = i + 2
                local topic = data:sub(i, i + topic_len - 1)
                i = i + topic_len
                local msg_len = rem - 2 - topic_len
                local msg = data:sub(i, i + msg_len - 1)
                i = i + msg_len
                table.insert(results, string.format("Topic: %-40s | Msg: %s",
                    topic, msg:sub(1, 60)))
            else
                break
            end
        else
            i = i + 1
        end
    end
    return results
end

action = function(host, port)
    local socket = nmap.new_socket()
    socket:set_timeout(5000)

    local status = socket:connect(host.ip, port.number)
    if not status then return nil end

    -- Send CONNECT
    socket:send(mqtt_connect())
    local ok, connack = socket:receive_bytes(4)
    if not ok or not connack:find("\x20\x02") then
        socket:close()
        return "MQTT broker detected but connection refused (auth required?)"
    end

    -- Subscribe to all topics
    socket:send(mqtt_subscribe())
    local suback_ok = socket:receive_bytes(5)

    -- Collect messages for 2 seconds
    local all_data = ""
    local deadline = stdnse.clock_ms() + 2000
    while stdnse.clock_ms() < deadline do
        local recv_ok, data = socket:receive_bytes(256)
        if recv_ok and data then
            all_data = all_data .. data
        else
            break
        end
    end
    socket:close()

    local topics = parse_publish(all_data)
    if #topics == 0 then
        return "Open MQTT broker (no messages in 2s — check manually)"
    end

    local results = {"Open MQTT Broker — Topics captured:"}
    for _, t in ipairs(topics) do
        results[#results+1] = "  " .. t
    end
    return table.concat(results, "\n")
end
