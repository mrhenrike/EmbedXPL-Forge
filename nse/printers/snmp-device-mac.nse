local snmp = require "snmp"
local shortport = require "shortport"

description = [[
Get MAC address from printers
]]

---
-- @usage
-- nmap -sS -p 161 --script snmp-device-mac <target>
--
-- @output
-- |_snmp-device-mac: 00:01:02:03:04:AB
-- <snip>
--


author = "Esteban Dauksis"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}
dependecies = {"snmp-brute"}

-- I prefer a portrule for common tcp ports than upd 161 for printer/scanner discovery

-- portrule = shortport.portnumber(161, "udp", {"open", "open|filtered"})
portrule = shortport.portnumber({515, 631, 9100, 1865}, "tcp", "open")

action = function(host,port)

	local socket = nmap.new_socket()

	socket:set_timeout(5000)

	local catch = function()
		socket:close()
	end

	local try = nmap.new_try(catch)	

	try(socket:connect(host, 161, "udp"))

	local payload
	local options = {}
	options.reqId = 28428 -- pa que?
	payload = snmp.encode(snmp.buildPacket(snmp.buildGetRequest(options,"1.3.6.1.2.1.2.2.1.6.1")))

        try(socket:send(payload))
        
        local status
        local response
        
        status, response = socket:receive_bytes(1)

        if (not status) or (response == "TIMEOUT") then 
                return
        end
	
	nmap.set_port_state(host, port, "open")

	local result

        local r = snmp.fetchFirst(response)
	if r ~= "" and r ~= nil then
		res1 = string.format("%02x:%02x:%02x:%02x:%02x:%02x",string.byte(r),string.byte(r,2),string.byte(r,3),string.byte(r,4),string.byte(r,5),string.byte(r,6)) 
		return res1
	end


	local payload
	local options = {}
	options.reqId = 28429 -- pa que?
        payload = snmp.encode(snmp.buildPacket(snmp.buildGetRequest(options, "1.3.6.1.2.1.2.2.1.6.2")))
        
        try(socket:send(payload))
        
        status, response = socket:receive_bytes(1)

        if (not status) or (response == "TIMEOUT") then
                return
        end
        
	local r2 = snmp.fetchFirst(response)
	if r2 ~= "" and r2 ~= nil then
		res2 = string.format("%02x:%02x:%02x:%02x:%02x:%02x",string.byte(r2),string.byte(r2,2),string.byte(r2,3),string.byte(r2,4),string.byte(r2,5),string.byte(r2,6))
		return res2
	end


	try(socket:close())
	
	
end

