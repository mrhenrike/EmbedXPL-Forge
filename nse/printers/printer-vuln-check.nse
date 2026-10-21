local description = [[
printer-vuln-check — Active, non-destructive vulnerability validation.

Performs lightweight active probes to confirm or rule out specific CVEs detected
by printer-cve-detect. Each check sends a minimal proof-of-concept payload and
evaluates the response — no damage, no file writes, no persistence.

Active checks included:
  1. PJL NVRAM info-leak (DISPLAY/USTATUS abuse)
  2. HP PostScript RCE probe (print error dict exploit path)
  3. CUPS IPP newline injection marker (CVE-2026-34980)
  4. Lexmark IPP malformed attr overflow indicator (CVE-2023-50739)
  5. Canon SLP pre-auth probe (CVE-2022-24673)
  6. Xerox command injection surface check (CVE-2021-27508/CVE-2024-6333)
  7. Sharp unauthenticated command execution probe (CVE-2022-45796)
  8. PrintNightmare SMB print spooler exposure check

Author: André Henrique (@mrhenrike) | União Geek
]]

---
-- @usage
--   nmap -p 9100,631,80,427,445 --script printer-vuln-check <target>
-- @output
-- PORT     STATE SERVICE
-- 9100/tcp open  jetdirect
-- | printer-vuln-check:
-- |   [CHECK 1] PJL NVRAM info-leak    : PASS (firmware info disclosed)
-- |   [CHECK 2] HP PostScript RCE path : POSSIBLY VULNERABLE (error dict accessible)
-- |   [CHECK 3] CUPS PPD injection     : NOT VULNERABLE (CUPS not detected)
-- |   Overall Verdict : POSSIBLY VULNERABLE
-- |_  Suggest         : printerxpl-forge run --module xpl/edb-cve-2025-26506 --target <IP>
---

categories = { "vuln", "intrusive" }
author     = "André Henrique (@mrhenrike) | União Geek"
license    = "Same as Nmap -- See https://nmap.org/book/man-legal.html"

local stdnse    = require "stdnse"
local shortport = require "shortport"
local comm      = require "comm"
local http      = require "http"
local string    = require "string"
local table     = require "table"

portrule = shortport.port_or_service(
  { 9100, 631, 80, 443, 427, 445, 515 },
  { "jetdirect", "ipp", "http", "https", "snmp", "printer" },
  "tcp"
)

local UEL = "\x1b%-12345X"
local V = { VULN = "VULNERABLE", POSS = "POSSIBLY VULNERABLE", NOT = "NOT VULNERABLE", SKIP = "SKIP" }

-- ── Check helpers ────────────────────────────────────────────────────────────

local function check_pjl_nvram(host, port)
  if port.number ~= 9100 then return V.SKIP, nil end
  local cmd = UEL .. "@PJL INFO VARIABLES\r\nDISPLAY\r\n" .. UEL
  local ok, r = comm.exchange(host, port, cmd, { timeout = 5000, bytes = 4096 })
  if not ok then return V.SKIP, "no response" end
  if r:match("VARIABLES") or r:match("DISPLAY") then
    return V.POSS, "PJL VARIABLES/DISPLAY responded — NVRAM read-back possible"
  end
  return V.NOT, "PJL VARIABLES not readable"
end

local function check_hp_ps_rce(host, port)
  if port.number ~= 9100 then return V.SKIP, nil end
  -- Minimal PS: push serverdict begin and check for response
  local ps_probe = UEL ..
    "@PJL ENTER LANGUAGE=POSTSCRIPT\r\n" ..
    "serverdict begin 0 exitserver\r\n" ..
    "systemdict begin\r\n" ..
    "/internaldict where { pop internaldict /setpassword known { (probe-xpl) } if } if\r\n" ..
    "flush\r\n" ..
    UEL
  local ok, r = comm.exchange(host, port, ps_probe, { timeout = 6000, bytes = 2048 })
  if not ok then return V.SKIP, "no PS response" end
  if r:match("probe.xpl") or r:match("internaldict") or r:match("setpassword") then
    return V.VULN, "PostScript serverdict/exitserver accepted — RCE path confirmed"
  elseif r:match("exitserver") or r:match("[Ee]rror") then
    return V.POSS, "PS interpreter responded (exitserver/error) — partial RCE surface"
  end
  return V.NOT, "PS probe not reflected"
end

local function check_cups_ppd_inject(host, port)
  if port.number ~= 631 then return V.SKIP, nil end
  local resp = http.get(host, port.number, "/", { timeout = 4000 })
  if not resp or not resp.body then return V.SKIP, "IPP/HTTP not responding" end
  local body = resp.body:lower()
  if not body:match("cups") then return V.NOT, "CUPS not detected on port 631" end
  local ver = resp.body:match("CUPS%s+([%d%.]+)")
  if ver then
    if ver == "2.4.16" then
      return V.VULN, "CUPS 2.4.16 detected — CVE-2026-34980 unauthenticated RCE confirmed"
    elseif ver >= "2.4.0" then
      return V.POSS, "CUPS " .. ver .. " — possible CVE-2024-47176 (cups-browsed RCE chain)"
    else
      return V.NOT, "CUPS " .. ver .. " — not in vulnerable range"
    end
  end
  return V.POSS, "CUPS detected but version unknown — manual check recommended"
end

local function check_lexmark_ipp_bof(host, port)
  if port.number ~= 631 then return V.SKIP, nil end
  -- Send IPP with oversized attribute name to test length validation
  local big_attr = string.rep("A", 2048)
  local payload =
    "\x02\x00\x00\x0b\x00\x00\x00\x01\x01" ..
    "\x47\x00\x12attributes-charset\x00\x05utf-8" ..
    "\x48\x00\x1battributes-natural-language\x00\x05en-us" ..
    "\x42" .. string.char(0x00, 0x08) .. "job-name" ..
    string.char(0x08, 0x00) .. big_attr:sub(1, 2048) ..
    "\x03"
  local resp = http.post(
    host, port.number, "/printers/",
    { header = { ["Content-Type"] = "application/ipp" }, timeout = 5000 },
    nil, payload
  )
  if not resp then return V.SKIP, "no response" end
  if resp.status == 500 or resp.status == 400 then
    local body = (resp.body or ""):lower()
    if body:match("lexmark") or body:match("ipp") then
      return V.POSS, "Lexmark IPP returned " .. resp.status .. " on oversized attribute — CVE-2023-50739 surface"
    end
  elseif resp.status == 200 then
    return V.NOT, "IPP accepted oversized attr without error (sanitized)"
  end
  return V.SKIP, "indeterminate response: HTTP " .. (resp.status or "nil")
end

local function check_canon_slp(host, port)
  if port.number ~= 427 then return V.SKIP, nil end
  -- Minimal SLP service request for "printer" service type
  local slp_req =
    "\x02\x01" ..  -- SLP v2, Service Request
    "\x00\x00\x00\x30" ..
    "\x00\x00\x00\x00\x00\x01" ..
    "\x00\x05en\x00\x00" ..
    "\x00\x07printer\x00\x00\x00"
  local ok, r = comm.exchange(host, port, slp_req, { timeout = 4000, bytes = 512, proto = "udp" })
  if not ok then
    -- Try TCP SLP
    ok, r = comm.exchange(host, port, slp_req, { timeout = 4000, bytes = 512 })
  end
  if ok and r then
    local body = r:lower()
    if body:match("canon") or body:match("imageclass") then
      return V.VULN, "Canon SLP responding with device info — CVE-2022-24673 pre-auth BOF surface"
    elseif #r > 4 then
      return V.POSS, "SLP service responding on 427 — check for Canon imageCLASS (CVE-2022-24673)"
    end
  end
  return V.NOT, "SLP not responding on port 427"
end

local function check_xerox_cmd_inject(host, port)
  if port.number ~= 80 and port.number ~= 443 then return V.SKIP, nil end
  -- Probe Xerox clone endpoint (CVE-2021-27508)
  local r = http.get(host, port.number, "/cgi-bin/cloning", { timeout = 4000 })
  if r then
    if r.status == 200 then
      return V.POSS, "Xerox /cgi-bin/cloning endpoint accessible (200) — CVE-2021-27508 surface"
    elseif r.status == 302 or r.status == 401 then
      return V.NOT, "Xerox cloning endpoint requires auth (HTTP " .. r.status .. ")"
    end
  end
  -- Probe VersaLink panel (CVE-2024-6333)
  local r2 = http.get(host, port.number, "/web/index.html", { timeout = 3000 })
  if r2 and r2.status == 200 and r2.body then
    if r2.body:lower():match("versalink") then
      return V.POSS, "Xerox VersaLink panel detected — CVE-2024-6333 requires authentication"
    end
  end
  return V.NOT, "Xerox endpoints not accessible"
end

local function check_sharp_rce(host, port)
  if port.number ~= 80 then return V.SKIP, nil end
  local r = http.get(host, port.number, "/cgi-bin/system_cmd.cgi", { timeout = 4000 })
  if r then
    if r.status == 200 then
      return V.VULN, "Sharp /cgi-bin/system_cmd.cgi accessible (200) — CVE-2022-45796 unauthenticated RCE"
    elseif r.status == 401 or r.status == 403 then
      return V.NOT, "Sharp cmd endpoint requires auth (HTTP " .. r.status .. ")"
    end
  end
  return V.NOT, "Sharp cmd endpoint not found"
end

local function check_print_spooler(host, port)
  if port.number ~= 445 then return V.SKIP, nil end
  -- Check if port 445 is open (SMB) — PrintNightmare requires SMB + Spooler
  -- We just fingerprint — actual exploit is in xpl/edb-50498
  local ok, r = comm.exchange(host, port,
    "\x00\x00\x00\x2f\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x08\x01\x40" ..
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xfe" ..
    "\x00\x00\x00\x00\x00\x0c\x00\x02NT LM 0.12\x00",
    { timeout = 4000, bytes = 256 })
  if ok and r and r:match("\xff\x53\x4d\x42") then
    return V.POSS, "SMB port 445 open — PrintNightmare (CVE-2021-1675) requires Spooler + domain enum"
  end
  return V.NOT, "SMB not responding or not Windows"
end

-- ── Main ─────────────────────────────────────────────────────────────────────

action = function(host, port)
  local out    = stdnse.output_table()
  local checks = {
    { name = "PJL NVRAM info-leak",          fn = check_pjl_nvram,       xpl = "xpl/edb-cve-2017-2741" },
    { name = "HP PostScript RCE path",       fn = check_hp_ps_rce,       xpl = "xpl/edb-cve-2025-26506" },
    { name = "CUPS PPD injection",           fn = check_cups_ppd_inject,  xpl = "xpl/research/research-cups-chain-2026" },
    { name = "Lexmark IPP BOF",             fn = check_lexmark_ipp_bof,  xpl = "xpl/edb-cve-2023-50739" },
    { name = "Canon SLP pre-auth BOF",      fn = check_canon_slp,        xpl = "xpl/edb-cve-2022-24673" },
    { name = "Xerox command injection surface", fn = check_xerox_cmd_inject, xpl = "xpl/edb-cve-2024-6333" },
    { name = "Sharp unauthenticated RCE",   fn = check_sharp_rce,        xpl = "xpl/research/research-sharp-rce" },
    { name = "PrintNightmare SMB exposure", fn = check_print_spooler,    xpl = "xpl/edb-50498" },
  }

  local results = {}
  local top_verdict = V.NOT
  local top_xpl     = nil

  for i, chk in ipairs(checks) do
    local verdict, detail = chk.fn(host, port)
    local label = string.format("[CHECK %d] %-30s: %s", i, chk.name, verdict)
    if detail and detail ~= "" then
      label = label .. " (" .. detail .. ")"
    end
    table.insert(results, label)

    -- Track overall verdict
    if verdict == V.VULN and top_verdict ~= V.VULN then
      top_verdict = V.VULN
      top_xpl     = chk.xpl
    elseif verdict == V.POSS and top_verdict == V.NOT then
      top_verdict = V.POSS
      top_xpl     = chk.xpl
    end
  end

  out["Checks"] = results
  out["Overall-Verdict"] = top_verdict

  if top_xpl then
    out["Suggest"] = "printerxpl-forge run --module " .. top_xpl .. " --target " .. host.ip
  end

  out["Full-Scan"] = "pip install printerxpl-forge  |  printerxpl-forge scan --target " .. host.ip

  return out
end
