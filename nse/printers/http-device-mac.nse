local shortport = require "shortport"
local http = require "http"

description = [[
Get MAC address from network devices such printers and scanners
]]

---
-- @usage
-- nmap -sS -p 9100 --script http-device-mac <target>
--
-- @output
-- |_http-device-mac: 00:01:02:03:04:AB
-- <snip>
--

author = "Esteban Dauksis"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.http

action = function(host,port)

	local socket = nmap.new_socket()

	socket:set_timeout(5000)

	local catch = function()
		socket:close()
	end

	local try = nmap.new_try(catch)	

	-- I have identified some useful config urls
	local answer1 = http.get(host, port, "/en/mnt/sysinfo.htm" )
	local answer2 = http.get(host, port, "/hp/jetdirect/configpage.htm" )
	local answer3 = http.get(host, port, "/configpage.htm" )
	local answer4 = http.get(host, port, "/card.asp?Lang=en" )
	local answer5 = http.get(host, port, "/cgi-bin/admin/management.cgi?_la=4")
	local answer6 = http.get(host, port, "/web/guest/es/websys/netw/getInterface.cgi")
	local answer7 = http.get(host, port, "/info_config_network.html?tab=Status&menu=NetConfig")
	local answer8 = http.get(host, port, "/hp/device/info_configuration.htm")
	local answer9 = http.get(host, port, "/start/start.htm")
	local answer10 = http.get(host, port, "/Istatus.htm")
	
	if answer1.status ~= 200 
		and answer2.status ~= 200 
		and answer3.status ~= 200
		and answer4.status ~= 200
		and answer5.status ~= 200
		and answer6.status ~= 200
		and answer7.status ~= 200
		and answer8.status ~= 200
		and answer9.status ~= 200
		and answer10.status ~= 200
					then
		return nil
	end

	-- Regex for each url
	if answer1.status == 200 then
		return answer1.body:match("%x%x:%x%x:%x%x:%x%x:%x%x:%x%x")
	end

	if answer2.status == 200 then
		mac = answer2.body:match("%x%x%x%x%x%x%x%x%x%x%x%x")
		return string.format("%s:%s:%s:%s:%s:%s",mac:sub(1,2),mac:sub(3,4),mac:sub(5,6),mac:sub(7,8),mac:sub(9,10),mac:sub(11,12))
		-- return answer2.body:match("%x%x%x%x%x%x%x%x%x%x%x%x")
	end

	if answer3.status == 200 then
		mac = answer3.body:match("%x%x%x%x%x%x%x%x%x%x%x%x")
		return string.format("%s:%s:%s:%s:%s:%s",mac:sub(1,2),mac:sub(3,4),mac:sub(5,6),mac:sub(7,8),mac:sub(9,10),mac:sub(11,12))
	end

	if answer4.status == 200 then
		return answer4.body:match("%x%x:%x%x:%x%x:%x%x:%x%x:%x%x")
	end

	if answer5.status == 200 then
		return answer5.body:match("%x%x:%x%x:%x%x:%x%x:%x%x:%x%x")
	end	

	if answer6.status == 200 then
		return answer6.body:match("%x%x:%x%x:%x%x:%x%x:%x%x:%x%x")
	end	

	if answer7.status == 200 then
		return answer7.body:match("%x%x:%x%x:%x%x:%x%x:%x%x:%x%x")
	end

	if answer8.status == 200 then
		mac = answer8.body:match("%x%x%x%x%x%x%x%x%x%x%x%x")
		return string.format("%s:%s:%s:%s:%s:%s",mac:sub(1,2),mac:sub(3,4),mac:sub(5,6),mac:sub(7,8),mac:sub(9,10),mac:sub(11,12))
	end

	if answer9.status == 200 then
		return answer9.body:match("%x%x:%x%x:%x%x:%x%x:%x%x:%x%x")
	end

	if answer10.status == 200 then
		return answer10.body:match("%x%x:%x%x:%x%x:%x%x:%x%x:%x%x")
	end	

end

