local http = require("http")
local stdnse = require "stdnse"
local string = require "string"

description = [[
Enumerates usernames, hostnames and documents from the print history 
of Xerox Centreware Internet Services printers.

Use the argument <code>xerox.port</code> to specify a non standard port.

Note: it is normal for the document names to be truncated as they are
normally truncated in the response.
]]

--@usage
--@arg xerox.port specify non standard port
--nmap -p 80 --script=http-printer.nse --script-args xerox.port=80 192.168.50.46 
--@output
--Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-14 11:44 EDT
--Nmap scan report for PHRACK-PNT-MAIN.phrack.com.au (192.168.50.46)
--Host is up (0.024s latency).
--
--PORT   STATE SERVICE
--80/tcp open  http
--| http-printer: 
--| -- Usernames:
--| slakin
--| jburrows
--| citrix-svr
--| -- Hostnames:
--| PHRACK-HQ-PRN
--| PHRACK-HQ-ADDS
--| PHRACK-HQ-MAINT
--| -- Documents:
--| Microsoft Outlook - Memo Style
--| Microsoft Word - Rach.doc
--| Microsoft Word - Document1
--| PayAdvicesEx.pdf
--| Payslip - 10May2023 - John.pdf
--|_Test Page


author = "Shain Lakin"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = function(host, port)
  local port_number = tonumber(stdnse.get_script_args('xerox.port')) or 80 
  return port.number == port_number and port.protocol == "tcp"
end

local function insert_unique(t, value)
  for _,v in ipairs(t) do
    if v == value then return end
  end
  table.insert(t,value)
end

action = function(host, port)
  local url = "/job/logsys.htm"
  -- Fetch job history 
  local response = http.get(host, port.number, url)
  stdnse.print_debug(response.body)
  if not (response.status == 200) then
    return("Invalid target")
  end

  -- Parse document names
  local documents = {}
  for document in string.gmatch(response.body, '<td class=jobhistory_1>(.-)</td>') do
    if document ~= "" then
      insert_unique(documents, document)
    end
  end

  -- Parse usernames
  local usernames = {}
  for username in string.gmatch(response.body, '<td class=jobhistory_2>(.-)</td>') do
    if username ~= "" then
      insert_unique(usernames, username)
    end
  end

  -- Parse hostnames
  local hostnames = {}
  for hostname in string.gmatch(response.body, '<td class=jobhistory_3>(.-)</td>') do
    if hostname ~= "" then
      insert_unique(hostnames, hostname)
    end
  end

  if #usernames > 0 and #hostnames > 0 and #documents > 0 then
    local output = "\n-- Usernames:\n" .. table.concat(usernames,'\n') 
    output = output .. "\n-- Hostnames:\n" .. table.concat(hostnames, '\n') 
    output = output .. "\n-- Documents:\n" .. table.concat(documents, '\n')
    return output
  else
    return "No job history found"
  end
end

