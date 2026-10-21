local description = [[
printer-pjl-info — Deep PJL enumeration via port 9100.

Sends multiple @PJL INFO commands to extract: device identity (ID, MODEL),
environment variables (TIMEOUT, RESOLUTION, COPIES), filesystem listing (FSLIST),
status (JOB status, READY state), and network configuration.

Also tests for PJL password protection — unprotected devices are flagged.

References:
  https://github.com/mrhenrike/PrinterXPL-Forge
  https://h20195.www2.hp.com/v2/GetDocument.aspx?docname=bpl13208 (HP PJL Tech Ref)

Author: André Henrique (@mrhenrike) | União Geek
]]

---
-- @usage
--   nmap -p 9100 --script printer-pjl-info <target>
-- @output
-- PORT     STATE SERVICE
-- 9100/tcp open  jetdirect
-- | printer-pjl-info:
-- |   ID           : HP LASERJET M606
-- |   Model        : HP LaserJet Enterprise M606dn
-- |   Firmware     : FY5L.04.A.00.00
-- |   Serial       : JPGD12345
-- |   Resolution   : 1200
-- |   Timeout      : 15
-- |   Filesystem   : 0:\ [HDD 40GB]
-- |   PJL-Password : NOT SET (unprotected — PJL job injection possible)
-- |_  Verdict      : POSSIBLY VULNERABLE (unrestricted PJL access)
---

categories = { "discovery", "safe", "vuln" }
author     = "André Henrique (@mrhenrike) | União Geek"
license    = "Same as Nmap -- See https://nmap.org/book/man-legal.html"

local stdnse    = require "stdnse"
local shortport = require "shortport"
local comm      = require "comm"
local string    = require "string"

portrule = shortport.port_or_service(9100, "jetdirect", "tcp")

local UEL = "\x1b%-12345X"

local PJL_QUERIES = {
  { cmd = "@PJL INFO ID\r\n",          key = "ID" },
  { cmd = "@PJL INFO CONFIG\r\n",      key = "Config" },
  { cmd = "@PJL INFO VARIABLES\r\n",   key = "Variables" },
  { cmd = "@PJL INFO FILESYS\r\n",     key = "Filesystem" },
  { cmd = "@PJL INFO STATUS\r\n",      key = "Status" },
  { cmd = "@PJL INFO PRODINFO\r\n",    key = "ProductInfo" },
  { cmd = "@PJL INFO MEMORY\r\n",      key = "Memory" },
}

local function pjl_send(host, port, cmds)
  local payload = UEL .. "@PJL\r\n"
  for _, q in ipairs(cmds) do
    payload = payload .. q.cmd
  end
  payload = payload .. UEL

  local status, resp = comm.exchange(host, port, payload,
    { timeout = 7000, bytes = 16384 })
  if status then return resp end
  return nil
end

local function extract_field(text, pattern)
  local val = text:match(pattern)
  if val then return val:match("^%s*(.-)%s*$") end
  return nil
end

action = function(host, port)
  local resp = pjl_send(host, port, PJL_QUERIES)
  if not resp then
    return "No PJL response — port may be closed or require credentials"
  end

  local out = stdnse.output_table()

  -- Basic identity
  local id_val = extract_field(resp, "@PJL INFO ID%s*\r?\n(.-)%r?\n%s*@PJL")
                 or extract_field(resp, 'ID%s*=%s*"([^"]+)"')
                 or extract_field(resp, "ID%s*\r?\n%s*([^\r\n]+)")
  if id_val then out["ID"] = id_val end

  -- Firmware
  local fw = extract_field(resp, "DATECODE%s*=%s*([%w%.%-]+)")
             or extract_field(resp, "[Ff]irmware[Vv]ersion%s*=%s*([%w%.%-]+)")
  if fw then out["Firmware"] = fw end

  -- Serial
  local sn = extract_field(resp, "SERIALNUMBER%s*=%s*([%w%-]+)")
             or extract_field(resp, "SERIAL%s*=%s*([%w%-]+)")
  if sn then out["Serial"] = sn end

  -- Resolution
  local res = extract_field(resp, "RESOLUTION%s*=%s*(%d+)")
  if res then out["Resolution-DPI"] = res end

  -- Memory
  local mem = extract_field(resp, "TOTALMEMORY%s*=%s*(%d+)")
  if mem then out["Memory-KB"] = mem end

  -- Filesystem
  local fs = extract_field(resp, "VOLUME%s*=%s*([^\r\n]+)")
             or extract_field(resp, "NAME%s*=%s*\"([^\"]+)\"")
  if fs then out["Filesystem"] = fs end

  -- Job count / status
  local jobs = extract_field(resp, "JOBNAME%s*=%s*\"([^\"]+)\"")
  if jobs then out["Last-Job"] = jobs end

  -- PJL Password check: try @PJL DEFAULT PASSWORD test
  local pwd_check = UEL .. "@PJL\r\n@PJL DEFAULT PASSWORD=0\r\n" .. UEL
  local ps, pr = comm.exchange(host, port, pwd_check, { timeout = 3000, bytes = 512 })
  local pwd_set = false
  if ps and pr and (pr:match("PASSWORD") or pr:match("ACCESS")) then
    pwd_set = true
    out["PJL-Password"] = "SET (access control enabled)"
  else
    out["PJL-Password"] = "NOT SET — PJL unrestricted (job injection / NVRAM access possible)"
    pwd_set = false
  end

  -- Verdict
  local is_vuln = not pwd_set
  local is_possible = resp and resp:match("READY") ~= nil

  if is_vuln then
    out["Verdict"] = "POSSIBLY VULNERABLE — unrestricted PJL: use printer-vuln-check for deep scan"
    out["Suggest"] = "printerxpl-forge run --module xpl/edb-cve-2017-2741 --target " .. host.ip
  elseif is_possible then
    out["Verdict"] = "NOT VULNERABLE to unrestricted PJL (password set)"
  else
    out["Verdict"] = "UNKNOWN — partial PJL response"
  end

  out["Full-Exploitation"] = "pip install printerxpl-forge  |  printerxpl-forge run --target " .. host.ip

  return out
end
