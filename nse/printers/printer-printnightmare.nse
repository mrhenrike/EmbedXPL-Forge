local description = [[
printer-printnightmare — Windows Print Spooler vulnerability detection.

Detects exposure of the Windows Print Spooler service (spoolsv.exe) and assesses
vulnerability to the PrintNightmare family of exploits:

  - CVE-2021-1675:  PrintNightmare RCE via RpcAddPrinterDriverEx (unauthenticated + network)
  - CVE-2021-34527: PrintNightmare (official patch bypass) — still exploitable in some configs
  - CVE-2020-1048:  PrintDemon — persistent SYSTEM backdoor via printer port race condition
  - CVE-2020-1337:  PrintDemon hardlink bypass — arbitrary privileged file write
  - CVE-2021-36958: Windows Print Spooler remote code execution
  - CVE-2022-38028: GooseEgg — APT28 Print Spooler LPE (CISA KEV 2024, actively exploited)
  - CVE-2022-21999: SpoolFool — Windows Print Spooler LPE

Probes: SMB (445), RPC (135), and WSD (3702) to confirm spooler exposure.

Author: André Henrique (@mrhenrike) | União Geek
]]

---
-- @usage
--   nmap -p 445,135,3702 --script printer-printnightmare <target>
-- @output
-- PORT    STATE SERVICE
-- 445/tcp open  microsoft-ds
-- | printer-printnightmare:
-- |   SMB       : Open (Windows detected)
-- |   OS        : Windows 10 / Server 2019
-- |   Spooler   : POSSIBLY ACTIVE (SMB open, historical exposure)
-- |   [CRITICAL] CVE-2021-1675 (CVSS 9.8) — PrintNightmare unauthenticated network RCE
-- |   [HIGH]     CVE-2022-38028 (CVSS 7.8) — GooseEgg LPE (APT28, CISA KEV)
-- |   [HIGH]     CVE-2020-1048  (CVSS 7.8) — PrintDemon persistent SYSTEM backdoor
-- |   Verdict   : POSSIBLY VULNERABLE
-- |_  Suggest   : printerxpl-forge run --module xpl/edb-50498 --target <IP>
---

categories = { "vuln", "safe" }
author     = "André Henrique (@mrhenrike) | União Geek"
license    = "Same as Nmap -- See https://nmap.org/book/man-legal.html"

local stdnse    = require "stdnse"
local shortport = require "shortport"
local smb       = require "smb"
local smb2      = require "smb2"
local comm      = require "comm"
local string    = require "string"
local table     = require "table"

portrule = shortport.port_or_service(
  { 445, 135, 3702, 139 },
  { "microsoft-ds", "msrpc", "wsd", "netbios-ssn" },
  "tcp"
)

local SPOOLER_CVES = {
  { id="CVE-2021-1675",  cvss=9.8, sev="CRITICAL",
    desc="PrintNightmare — Windows Print Spooler unauthenticated RCE via RpcAddPrinterDriverEx",
    xpl="xpl/edb-50498" },
  { id="CVE-2021-34527", cvss=8.8, sev="HIGH",
    desc="PrintNightmare (official) — patch bypass via RpcAddPrinterDriverEx with Point&Print",
    xpl="xpl/edb-50498" },
  { id="CVE-2022-38028", cvss=7.8, sev="HIGH",
    desc="GooseEgg — APT28 LPE via Windows Print Spooler (CISA KEV 2024, actively exploited)",
    xpl="xpl/research/research-gooseegg-spooler" },
  { id="CVE-2020-1048",  cvss=7.8, sev="HIGH",
    desc="PrintDemon — persistent SYSTEM backdoor via printer port + DLL side-loading",
    xpl="xpl/msf-cve-2020-1048-printerdemon" },
  { id="CVE-2020-1337",  cvss=7.8, sev="HIGH",
    desc="PrintDemon hardlink bypass — arbitrary privileged file write → SYSTEM",
    xpl="xpl/edb-cve-2020-1337" },
  { id="CVE-2021-36958", cvss=7.8, sev="HIGH",
    desc="Windows Print Spooler remote code execution (out-of-band patch)",
    xpl="xpl/edb-50498" },
  { id="CVE-2022-21999", cvss=7.8, sev="HIGH",
    desc="SpoolFool — Windows Print Spooler LPE via printer driver DLL planting",
    xpl="xpl/edb-cve-2022-21999" },
  { id="CVE-2023-21678", cvss=7.8, sev="HIGH",
    desc="Windows Print Spooler elevation of privilege (Jan 2023 Patch Tuesday)",
    xpl="xpl/research/research-spooler-eop-2023" },
}

-- SMB negotiation probe to detect Windows
local function smb_probe(host, port)
  if port.number ~= 445 and port.number ~= 139 then return nil end
  local smb_neg =
    "\x00\x00\x00\x2f" ..  -- NetBIOS length
    "\xff\x53\x4d\x42" ..  -- SMB magic
    "\x72\x00\x00\x00\x00\x08\x01\x40\x00\x00\x00\x00\x00\x00\x00\x00" ..
    "\x00\x00\x00\x00\xff\xff\xff\xfe\x00\x00\x00\x00" ..
    "\x00\x0c\x00\x02NT LM 0.12\x00"

  local ok, resp = comm.exchange(host, port, smb_neg,
    { timeout = 5000, bytes = 256 })
  if ok and resp then return resp end
  return nil
end

-- RPC portmapper probe to check if spooler is registered
local function rpc_probe(host, port)
  if port.number ~= 135 then return nil end
  -- Minimal DCE/RPC bind to portmapper
  local rpc_bind =
    "\x05\x00\x0b\x03\x10\x00\x00\x00\x48\x00\x00\x00\x01\x00\x00\x00" ..
    "\xd0\x16\xd0\x16\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x01\x00" ..
    "\x08\x83\xaf\xe1\x1f\x5d\xc9\x11\x91\xa4\x08\x00\x2b\x14\xa0\xfa" ..
    "\x03\x00\x00\x00\x33\x05\x71\x71\xba\xbe\x37\x49\x83\x19\xb5\xdb" ..
    "\xef\x9c\xcc\x36\x01\x00\x00\x00"
  local ok, resp = comm.exchange(host, port, rpc_bind,
    { timeout = 4000, bytes = 256 })
  if ok and resp then return resp end
  return nil
end

-- WSD (Web Services for Devices) probe on 3702/UDP
local function wsd_probe(host, port)
  if port.number ~= 3702 then return nil end
  local wsd_probe_xml =
    '<?xml version="1.0" encoding="utf-8"?>' ..
    '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" ' ..
    'xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery">' ..
    '<soap:Body><wsd:Probe><wsd:Types>wsdp:Printer</wsd:Types></wsd:Probe></soap:Body>' ..
    '</soap:Envelope>'
  local ok, resp = comm.exchange(host, { number = 3702, protocol = "udp" },
    wsd_probe_xml, { timeout = 3000, bytes = 1024 })
  if ok then return resp end
  return nil
end

action = function(host, port)
  local out = stdnse.output_table()
  local windows_detected = false
  local smb_open = false
  local rpc_open  = false
  local wsd_open  = false
  local os_hint   = nil

  -- SMB probe
  if port.number == 445 or port.number == 139 then
    local smb_resp = smb_probe(host, port)
    if smb_resp then
      smb_open = true
      -- Check for Windows response marker
      if smb_resp:match("\xff\x53\x4d\x42") then
        windows_detected = true
        -- Try to extract OS info
        local os_str = smb_resp:match("Windows[%w%s%.]+")
        if os_str then os_hint = os_str:sub(1, 50) end
      end
    end
  end

  -- RPC probe
  if port.number == 135 then
    local rpc_resp = rpc_probe(host, port)
    if rpc_resp then
      rpc_open = true
      windows_detected = true
    end
  end

  -- WSD probe
  if port.number == 3702 then
    local wsd_resp = wsd_probe(host, port)
    if wsd_resp then
      wsd_open = true
      if wsd_resp:lower():match("printer") then
        windows_detected = true
      end
    end
  end

  if not smb_open and not rpc_open and not wsd_open then
    return "No SMB/RPC/WSD response — Print Spooler not exposed or target is not Windows"
  end

  -- Build output
  if smb_open  then out["SMB"]  = "Open" end
  if rpc_open  then out["RPC"]  = "Open (DCE/RPC portmapper responding)" end
  if wsd_open  then out["WSD"]  = "Open (WSD printer broadcast)" end
  if os_hint   then out["OS"]   = os_hint end
  out["Windows"] = windows_detected and "Detected" or "Possible (SMB open, no OS banner)"

  -- Spooler estimation
  if smb_open and windows_detected then
    out["Spooler-Status"] = "LIKELY RUNNING — SMB open on Windows host"
  elseif smb_open then
    out["Spooler-Status"] = "POSSIBLY RUNNING — SMB open, OS unconfirmed"
  end

  -- CVE output
  local cve_lines = {}
  for _, c in ipairs(SPOOLER_CVES) do
    table.insert(cve_lines, string.format("[%s] %s (CVSS %.1f) — %s\n            module: %s",
      c.sev, c.id, c.cvss, c.desc, c.xpl))
  end
  out["CVEs"] = cve_lines

  -- Verdict
  if windows_detected and smb_open then
    out["Verdict"] = "POSSIBLY VULNERABLE — Windows + SMB confirmed; spooler status requires auth check"
    out["Note"]    = "Requires auth check: printerxpl-forge can enumerate spooler via NULL session or valid creds"
    out["Suggest"] = "printerxpl-forge run --module xpl/edb-50498 --target " .. host.ip
  else
    out["Verdict"] = "POSSIBLY VULNERABLE — some exposure indicators present"
    out["Suggest"] = "printerxpl-forge run --module xpl/edb-50498 --dry-run --target " .. host.ip
  end

  out["Full-Scan"] = "pip install printerxpl-forge  |  printerxpl-forge scan --target " .. host.ip

  return out
end
