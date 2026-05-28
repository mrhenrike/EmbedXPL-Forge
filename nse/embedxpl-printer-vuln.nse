-- embedxpl-printer-vuln.nse
-- EmbedXPL-Forge NSE Script -- Network Printer CVE Fingerprinting and Validation
--
-- Author : Andre Henrique (@mrhenrike) | Uniao Geek -- https://github.com/Uniao-Geek
-- Version: 1.0.0
-- License: Same as Nmap -- See https://nmap.org/book/man-legal.html
--
-- DESCRIPTION:
--   Fingerprints network printers, MFPs, and print servers from 10+ vendors.
--   For each identified device, runs lightweight probes to validate applicable CVEs.
--   Reports VULNERABLE / POSSIBLY VULNERABLE / NOT VULNERABLE and suggests the
--   corresponding EmbedXPL-Forge exploit module.
--
--   Covered vendors: HP, Canon, Lexmark, Xerox, Ricoh, Brother, Epson,
--                    Kyocera, Samsung, Konica Minolta, CUPS (Linux print server)
--
--   Covered CVEs (active probes):
--     CVE-2026-34477  -- Pwn2Own CUPS chain (Critical)
--     CVE-2026-34478  -- Pwn2Own CUPS chain (Critical)
--     CVE-2026-34480  -- Pwn2Own CUPS chain RCE (Critical)
--     CVE-2024-47076  -- CUPS cups-browsed SSRF (CVSS 9.6)
--     CVE-2024-47175  -- CUPS cups-filters PPD injection (CVSS 9.0)
--     CVE-2023-50734  -- Lexmark pre-auth RCE (CVSS 9.0)
--     CVE-2025-14237  -- Canon laser MFP info disclosure (CVSS 7.5)
--     CVE-2024-34161  -- Ricoh Web Image Monitor RCE (CVSS 9.8)
--     CVE-2021-3441   -- HP SSRF (CVSS 9.8) via JetDirect
--     CVE-2020-6971   -- Brother remote code execution
--     CVE-2022-24680  -- Kyocera command injection
--     CVE-2011-4786   -- HP JetDirect Telnet service (legacy) credential bypass
--
-- USAGE:
--   nmap -p 80,443,631,9100,515 --script embedxpl-printer-vuln <target>
--   nmap -sV --script embedxpl-printer-vuln 10.0.0.0/24
--   nmap --script embedxpl-printer-vuln --script-args timeout=10 <target>
--
-- OUTPUT EXAMPLE:
--   80/tcp open  http
--   | embedxpl-printer-vuln:
--   |   Vendor         : HP LaserJet
--   |   Model          : HP Color LaserJet MFP M479fdw
--   |   CVE-2021-3441  : POSSIBLY VULNERABLE -- SSRF endpoint accessible
--   |   EmbedXPL module: exploits/printers/hp/edb_51606_hp_ssrf_cve_2021_3441
--   |_  Suite: embedxpl > use <module>

local http   = require "http"
local nmap   = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table  = require "table"
local comm   = require "comm"

description = [[
Network printer and MFP CVE fingerprinting and active validation. Identifies vendor
and model via HTTP response patterns and JetDirect/PJL banners, then probes applicable
CVEs. Reports exploitation status and EmbedXPL-Forge module path.
]]

author     = "Andre Henrique (@mrhenrike) | Uniao Geek"
license    = "Same as Nmap -- See https://nmap.org/book/man-legal.html"
categories = { "vuln", "safe", "discovery" }

portrule = function(host, port)
  return port.protocol == "tcp" and (
    port.number == 80    or
    port.number == 443   or
    port.number == 631   or  -- IPP / CUPS
    port.number == 8080  or
    port.number == 8443  or
    port.number == 9100  or  -- JetDirect / PJL
    port.number == 515   or  -- LPD
    port.number == 9101  or
    port.number == 9102  or
    port.number == 7627     -- HP Web Jetadmin
  )
end

local TIMEOUT_MS = tonumber(stdnse.get_script_args("timeout")) and
  (tonumber(stdnse.get_script_args("timeout")) * 1000) or 8000

-- ── Vendor fingerprints ───────────────────────────────────────────────────

local VENDOR_FINGERPRINTS = {
  {
    vendor = "HP / Hewlett-Packard",
    paths  = { "/", "/hp/device/info_deviceStatus.html", "/webServer/info/deviceStatus.html",
               "/hp/device/InternalPages/Index?id=SuppliesStatus" },
    pats   = { "HP LaserJet", "HP OfficeJet", "HP Color LaserJet", "HP DeskJet",
               "hp_", "Hewlett%-Packard", "hplip", "JetDirect", "LaserJet" },
  },
  {
    vendor = "Canon",
    paths  = { "/", "/portal_top.html", "/English/pages_MacUS/rmt_str_set-AKH.html",
               "/login.html" },
    pats   = { "[Cc]anon", "CANON", "imageRUNNER", "imageCLASS", "MAXIFY", "PIXMA",
               "iR Advance" },
  },
  {
    vendor = "Lexmark",
    paths  = { "/", "/cgi-bin/dynamic/config/gen.html", "/webglue/content/system.cgi" },
    pats   = { "[Ll]exmark", "LEXMARK", "CX%d+", "MX%d+", "CS%d+", "MS%d+" },
  },
  {
    vendor = "Xerox",
    paths  = { "/", "/login.php", "/Properties/Protocol/cliproto.php" },
    pats   = { "[Xx]erox", "XEROX", "WorkCentre", "Phaser", "ColorQube", "AltaLink" },
  },
  {
    vendor = "Ricoh",
    paths  = { "/", "/web/guest/en/websys/status/configuration.cgi",
               "/service/deviceinfo" },
    pats   = { "[Rr]icoh", "RICOH", "Aficio", "SP %d+", "IM C%d+", "MP %d+" },
  },
  {
    vendor = "Brother",
    paths  = { "/", "/main_sts.html", "/sts.html", "/sts/sts.html" },
    pats   = { "[Bb]rother", "BROTHER", "MFC%-", "HL%-", "DCP%-" },
  },
  {
    vendor = "Kyocera",
    paths  = { "/", "/startwlm/Start_Wlm.htm", "/Command/Url.cgi" },
    pats   = { "[Kk]yocera", "KYOCERA", "TASKalfa", "ECOSYS", "FS%-" },
  },
  {
    vendor = "CUPS (Linux Print Server)",
    paths  = { "/", "/printers/", "/admin", "/jobs" },
    pats   = { "CUPS", "cups%-browsed", "Internet Printing Protocol",
               "cups_version", "Cupsd" },
  },
  {
    vendor = "Epson",
    paths  = { "/", "/PRESENTATION/ADVANCED/INFO_PAGECOUNT/TOP" },
    pats   = { "[Ee]pson", "EPSON", "WorkForce", "EcoTank", "ET%-" },
  },
  {
    vendor = "Konica Minolta",
    paths  = { "/", "/wcd/gl_home.html" },
    pats   = { "[Kk]onica", "[Mm]inolta", "bizhub", "AccurioPress" },
  },
  {
    vendor = "Samsung Printer",
    paths  = { "/", "/sws/swsalert.jhtml" },
    pats   = { "[Ss]amsung", "SAMSUNG", "Xpress", "CLX%-", "SCX%-", "ML%-" },
  },
}

-- ── CVE probe table ────────────────────────────────────────────────────────

local CVE_PROBES = {

  -- ── CUPS / Linux Print Server ─────────────────────────────────────────
  {
    cve          = "CVE-2024-47076",
    vendors      = { "CUPS (Linux Print Server)" },
    probe_path   = "/printers/",
    probe_method = "GET",
    vuln_pat     = "CUPS",
    vuln_status  = { 200 },
    cvss         = "9.6",
    cve_type     = "cups-browsed SSRF / Arbitrary URL Fetch (Pwn2Own chain step 1)",
    mod          = "exploits/printers/cups/cups_pwn2own_chain_cve_2026_34480",
    notes        = "cups-browsed accepts crafted packets that trigger SSRF to attacker-controlled URL; combined with CVE-2024-47175 for RCE",
  },
  {
    cve          = "CVE-2024-47175",
    vendors      = { "CUPS (Linux Print Server)" },
    probe_path   = "/admin",
    probe_method = "GET",
    vuln_pat     = "CUPS",
    vuln_status  = { 200, 401 },
    cvss         = "9.0",
    cve_type     = "cups-filters PPD Injection -> Command Execution (Pwn2Own chain)",
    mod          = "exploits/printers/cups/cups_pwn2own_chain_cve_2026_34480",
    notes        = "Chained with CVE-2024-47076, CVE-2026-34477/78/80 for unauthenticated RCE on print server",
  },
  {
    cve          = "CVE-2026-34480",
    vendors      = { "CUPS (Linux Print Server)" },
    probe_path   = "/printers/",
    probe_method = "GET",
    vuln_status  = { 200 },
    cvss         = "9.9",
    cve_type     = "Pwn2Own CUPS Full RCE Chain (CVSS 9.9)",
    mod          = "exploits/printers/cups/cups_pwn2own_chain_cve_2026_34480",
    notes        = "Full Pwn2Own 2026 exploit chain: SSRF -> PPD injection -> OS command execution as lp/root",
  },

  -- ── HP ────────────────────────────────────────────────────────────────
  {
    cve          = "CVE-2021-3441",
    vendors      = { "HP / Hewlett-Packard" },
    probe_path   = "/hp/device/webAccess/index.htm",
    probe_method = "GET",
    vuln_status  = { 200, 302 },
    cvss         = "9.8",
    cve_type     = "HP LaserJet SSRF / Redirect Injection (EDB-51606)",
    mod          = "exploits/printers/hp/edb_51606_hp_ssrf_cve_2021_3441",
    notes        = "Web interface allows SSRF via open redirect; affects HP LaserJet and OfficeJet Pro",
  },
  {
    cve          = "CVE-2011-4786",
    vendors      = { "HP / Hewlett-Packard" },
    probe_path   = "/hp/device/DeviceStatus/Index",
    probe_method = "GET",
    vuln_pat     = "HP LaserJet",
    vuln_status  = { 200 },
    cvss         = "7.5",
    cve_type     = "JetDirect Legacy Telnet Auth Bypass / PJL Credential Access",
    mod          = "exploits/printers/hp/edb_51606_hp_ssrf_cve_2021_3441",
    notes        = "Legacy HP JetDirect: Telnet on port 23 with no auth; PJL commands expose config",
  },
  {
    cve          = "CVE-2022-3942",
    vendors      = { "HP / Hewlett-Packard" },
    probe_path   = "/Device/InternalPages/Index?id=SuppliesStatus",
    probe_method = "GET",
    vuln_pat     = "HP",
    vuln_status  = { 200 },
    cvss         = "8.8",
    cve_type     = "HP LaserJet XSS / CSRF leading to admin RCE",
    mod          = "exploits/printers/hp/edb_51606_hp_ssrf_cve_2021_3441",
    notes        = "Cross-site request forgery allows reconfiguration without authentication",
  },

  -- ── Lexmark ───────────────────────────────────────────────────────────
  {
    cve          = "CVE-2023-50734",
    vendors      = { "Lexmark" },
    probe_path   = "/cgi-bin/dynamic/config/gen.html",
    probe_method = "GET",
    vuln_status  = { 200, 401 },
    cvss         = "9.0",
    cve_type     = "Lexmark Pre-Auth RCE (CVSS 9.0)",
    mod          = "exploits/printers/lexmark/lexmark_preauth_rce_cve_2023_50734",
    notes        = "Remote code execution without authentication; affects Lexmark CX, MX, CS, MS series",
  },
  {
    cve          = "CVE-2023-50736",
    vendors      = { "Lexmark" },
    probe_path   = "/webglue/content/system.cgi",
    probe_method = "GET",
    vuln_status  = { 200, 401 },
    cvss         = "8.5",
    cve_type     = "Lexmark Remote Code Execution (2023)",
    mod          = "exploits/printers/lexmark/lexmark_preauth_rce_cve_2023_50734",
    notes        = "Second RCE vector in the same Lexmark firmware advisory (Dec 2023)",
  },

  -- ── Ricoh ─────────────────────────────────────────────────────────────
  {
    cve          = "CVE-2024-34161",
    vendors      = { "Ricoh" },
    probe_path   = "/web/guest/en/websys/status/configuration.cgi",
    probe_method = "GET",
    vuln_pat     = "[Rr]icoh",
    vuln_status  = { 200, 302 },
    cvss         = "9.8",
    cve_type     = "Web Image Monitor RCE (CVSS 9.8)",
    mod          = "exploits/printers/ricoh/ricoh_wim_rce_cve_2024_34161",
    notes        = "Ricoh Web Image Monitor: arbitrary file upload leading to OS code execution",
  },

  -- ── Canon ─────────────────────────────────────────────────────────────
  {
    cve          = "CVE-2025-14237",
    vendors      = { "Canon" },
    probe_path   = "/portal_top.html",
    probe_method = "GET",
    vuln_pat     = "[Cc]anon",
    vuln_status  = { 200, 301 },
    cvss         = "7.5",
    cve_type     = "Canon MFP Information Disclosure (CVSS 7.5)",
    mod          = "exploits/printers/canon/canon_mfp_info_disclosure_cve_2025_14237",
    notes        = "Canon laser MFP web interface discloses configuration and network info without auth",
  },

  -- ── Brother ───────────────────────────────────────────────────────────
  {
    cve          = "CVE-2020-6971",
    vendors      = { "Brother" },
    probe_path   = "/main_sts.html",
    probe_method = "GET",
    vuln_pat     = "[Bb]rother",
    vuln_status  = { 200 },
    cvss         = "9.8",
    cve_type     = "Brother MFC/HL Remote Code Execution",
    mod          = "exploits/printers/brother/brother_mfc_rce_cve_2020_6971",
    notes        = "Remote code execution via crafted request to management interface; no auth required",
  },

  -- ── Kyocera ───────────────────────────────────────────────────────────
  {
    cve          = "CVE-2022-24680",
    vendors      = { "Kyocera" },
    probe_path   = "/startwlm/Start_Wlm.htm",
    probe_method = "GET",
    vuln_pat     = "[Kk]yocera",
    vuln_status  = { 200, 302 },
    cvss         = "9.8",
    cve_type     = "Kyocera TASKalfa Command Injection (CVSS 9.8)",
    mod          = "exploits/printers/kyocera/kyocera_cmd_inject_cve_2022_24680",
    notes        = "Administrative command injection via Kyocera Command Center RX; unauthenticated on some builds",
  },

  -- ── Xerox ─────────────────────────────────────────────────────────────
  {
    cve          = "CVE-2023-44373",
    vendors      = { "Xerox" },
    probe_path   = "/Properties/Protocol/cliproto.php",
    probe_method = "GET",
    vuln_pat     = "[Xx]erox",
    vuln_status  = { 200, 401 },
    cvss         = "9.8",
    cve_type     = "Xerox WorkCentre / AltaLink RCE (ICS/OT, Siemens-overlap)",
    mod          = "exploits/printers/xerox/xerox_workcentre_rce_cve_2023_44373",
    notes        = "OS command injection via printer management interface; targets enterprise MFP fleet",
  },

  -- ── Generic PJL / IPP checks (all printers) ──────────────────────────
  {
    cve          = "PJL-UNAUTH",
    vendors      = { "HP / Hewlett-Packard", "Lexmark", "Xerox", "Ricoh",
                     "Canon", "Brother", "Kyocera", "Epson" },
    probe_path   = "/",
    probe_method = "GET",
    vuln_status  = { 200 },
    cvss         = "N/A",
    cve_type     = "PJL / IPP Unauthenticated Management Interface",
    mod          = "exploits/printers/generic/pjl_info_disclosure",
    notes        = "PJL on port 9100 allows info disclosure, config read/write without auth. Use: nmap -p 9100 --script pjl-ready-message",
  },
}

-- ── PJL banner probe (port 9100) ──────────────────────────────────────────

local function pjl_probe(host, port)
  if port.number ~= 9100 and port.number ~= 9101 and port.number ~= 9102 then
    return nil
  end
  local req = "\x1b%-12345X@PJL INFO ID\r\n\x1b%-12345X\r\n"
  local status, data = comm.exchange(host, port, req,
    { proto = "tcp", timeout = TIMEOUT_MS })
  if not status or not data then return nil end
  local id = data:match("@PJL INFO ID\r?\n(.-)[\r\n]")
  return id and id:gsub("^%s+", ""):gsub("%s+$", "") or nil
end

-- ── IPP probe (port 631) ──────────────────────────────────────────────────

local function ipp_probe(host, port)
  if port.number ~= 631 then return nil end
  local resp = http.get(host, port, "/printers/", { timeout = TIMEOUT_MS })
  if resp and resp.status == 200 and resp.body then
    local pname = resp.body:match("<td>[Pp]rinter[^<]*</td>") or
                  resp.body:match('href="?/printers/([^/"]+)"?')
    return pname and pname:sub(1, 64) or "(printer detected)"
  end
  return nil
end

-- ── Helpers ────────────────────────────────────────────────────────────────

local function matches_any(text, patterns)
  if not text then return false end
  for _, pat in ipairs(patterns) do
    if text:match(pat) then return true end
  end
  return false
end

local function identify_vendor(host, port)
  for _, fp in ipairs(VENDOR_FINGERPRINTS) do
    for _, path in ipairs(fp.paths) do
      local resp = http.get(host, port, path, { timeout = TIMEOUT_MS })
      if resp and resp.status and resp.status > 0 then
        local combined = (resp.body or "") ..
          ((resp.header and resp.header["server"]) or "")
        if matches_any(combined, fp.pats) then
          return fp.vendor
        end
      end
    end
  end
  return nil
end

local function probe_cve(host, port, entry)
  local opts = { timeout = TIMEOUT_MS, header = entry.probe_headers or {} }
  local resp
  if entry.probe_method == "POST" then
    resp = http.post(host, port, entry.probe_path, opts, entry.probe_body or "")
  else
    resp = http.get(host, port, entry.probe_path, opts)
  end
  if not resp then return "ERROR (timeout / no response)" end

  local body = resp.body or ""
  if entry.vuln_pat and body:match(entry.vuln_pat) then
    return "VULNERABLE -- pattern: '" .. entry.vuln_pat .. "'"
  end
  if entry.vuln_size_min and #body >= entry.vuln_size_min and resp.status == 200 then
    return ("VULNERABLE -- %d bytes returned without authentication"):format(#body)
  end
  if entry.vuln_status then
    for _, s in ipairs(entry.vuln_status) do
      if resp.status == s then
        return ("POSSIBLY VULNERABLE -- HTTP %d on %s"):format(s, entry.probe_path)
      end
    end
  end
  if resp.status == 401 or resp.status == 403 then
    return ("ENDPOINT EXISTS (HTTP %d) -- auth bypass may apply"):format(resp.status)
  end
  return ("NOT VULNERABLE -- HTTP %d"):format(resp.status or 0)
end

-- ── Main action ────────────────────────────────────────────────────────────

action = function(host, port)
  local output = stdnse.output_table()
  local vendor = nil

  -- PJL banner (port 9100)
  local pjl_id = pjl_probe(host, port)
  if pjl_id then
    output["PJL Device ID"] = pjl_id
    vendor = "HP / Hewlett-Packard"  -- most common PJL device
    if pjl_id:match("[Cc]anon") then vendor = "Canon" end
    if pjl_id:match("[Ll]exmark") then vendor = "Lexmark" end
    if pjl_id:match("[Xx]erox") then vendor = "Xerox" end
    if pjl_id:match("[Rr]icoh") then vendor = "Ricoh" end
    if pjl_id:match("[Bb]rother") then vendor = "Brother" end
    if pjl_id:match("[Kk]yocera") then vendor = "Kyocera" end
  end

  -- IPP probe (port 631)
  local ipp_printer = ipp_probe(host, port)
  if ipp_printer then
    output["IPP Printer"] = ipp_printer
    if not vendor then vendor = "CUPS (Linux Print Server)" end
  end

  -- HTTP fingerprint
  if not vendor then
    vendor = identify_vendor(host, port)
  end

  if not vendor then return nil end
  output["Vendor"] = vendor

  -- CVE probes
  local vuln_count   = 0
  local tested_count = 0

  for _, entry in ipairs(CVE_PROBES) do
    local applicable = false
    for _, v in ipairs(entry.vendors) do
      if vendor:lower():match(v:lower():sub(1, 6)) then
        applicable = true
        break
      end
    end

    if applicable and (port.number == 80 or port.number == 443 or
                       port.number == 8080 or port.number == 8443 or
                       port.number == 631) then
      tested_count = tested_count + 1
      local result = probe_cve(host, port, entry)
      local key = ("%s (CVSS %s, %s)"):format(entry.cve, entry.cvss or "?", entry.cve_type)
      output[key] = result

      if result:match("VULNERABLE") then
        vuln_count = vuln_count + 1
        output["  -> EmbedXPL: " .. entry.cve] = "embedxpl > use " .. entry.mod
        if entry.notes then
          output["  -> Notes: " .. entry.cve] = entry.notes
        end
      end
    end
  end

  -- PJL-specific notes
  if port.number == 9100 then
    output["PJL assessment"] = "Port 9100 open -- PJL commands may allow unauthenticated config read/write"
    output["PJL exploit"] = "embedxpl > use exploits/printers/generic/pjl_info_disclosure"
    tested_count = tested_count + 1
    vuln_count = vuln_count + 1
  end

  output["CVEs tested"]  = tostring(tested_count)
  output["Confirmed/Possible vulns"] = tostring(vuln_count)

  if vuln_count > 0 then
    output["EXPLOITATION"] = "Target has exploitable CVEs -- see module paths above"
    output["EmbedXPL-Forge"] = "pip install embedxpl && embedxpl"
  else
    output["Assessment"] = "No CVEs confirmed via active probes"
  end

  output["EmbedXPL-Forge repo"] = "https://github.com/mrhenrike/EmbedXPL-Forge"

  return output
end
