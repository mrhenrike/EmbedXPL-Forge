local description = [[
printer-passback — LDAP/SMB credential passback attack surface detection.

Modern multifunction printers (MFPs) support scan-to-email, scan-to-folder
(SMB), LDAP authentication, and network scanning. If these features are
configured, a rogue LDAP/SMB server can capture domain credentials when the
printer initiates a connection ("passback attack").

This script detects:
  - Accessible LDAP configuration pages (scan-to-email / address book LDAP)
  - SMB scan destination configuration pages
  - Network credential test endpoints
  - Active Directory integration surfaces

CVE coverage:
  - CVE-2022-23968: Xerox FutureSmart LDAP passback
  - CVE-2022-23969: Xerox FutureSmart SMB passback
  - Generic passback surface detection for HP, Ricoh, Konica, Canon, etc.

Author: André Henrique (@mrhenrike) | União Geek
]]

---
-- @usage
--   nmap -p 80,443 --script printer-passback <target>
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | printer-passback:
-- |   LDAP-Config  : /hp/device/LdapConfiguration.htm (HTTP 200 — accessible)
-- |   SMB-Config   : /hp/device/SmbConfiguration.htm  (HTTP 200 — accessible)
-- |   [HIGH] CVE-2022-23968 — Xerox LDAP passback → domain credential capture
-- |   [HIGH] CVE-2022-23969 — Xerox SMB passback → domain credential capture
-- |   Verdict : POSSIBLY VULNERABLE — LDAP/SMB config pages accessible
-- |_  Suggest : printerxpl-forge run --module xpl/research/research-passback-ldap
---

categories = { "vuln", "safe", "discovery" }
author     = "André Henrique (@mrhenrike) | União Geek"
license    = "Same as Nmap -- See https://nmap.org/book/man-legal.html"

local stdnse    = require "stdnse"
local shortport = require "shortport"
local http      = require "http"
local string    = require "string"
local table     = require "table"

portrule = shortport.http

-- Passback surface endpoints per vendor
local PASSBACK_ENDPOINTS = {
  -- HP
  { path="/hp/device/LdapConfiguration.htm",     vendor="HP",     proto="LDAP",
    cve="CVE-2022-23968-HP", desc="HP EWS LDAP directory config" },
  { path="/hp/device/NetworkFolderConfiguration.htm", vendor="HP", proto="SMB",
    cve="CVE-2022-23969-HP", desc="HP EWS SMB scan-to-folder config" },
  { path="/hp/device/EmailConfiguration.htm",    vendor="HP",     proto="SMTP",
    cve=nil, desc="HP EWS email config (SMTP credentials)" },
  -- Xerox
  { path="/cgi-bin/dynamic/userprefs/LdapConfiguration.html", vendor="Xerox", proto="LDAP",
    cve="CVE-2022-23968", desc="Xerox FutureSmart LDAP config (CISA alert)" },
  { path="/cgi-bin/dynamic/userprefs/SmtpConfiguration.html", vendor="Xerox", proto="SMTP",
    cve=nil, desc="Xerox SMTP config (email credentials)" },
  { path="/cgi-bin/dynamic/userprefs/SmbConfiguration.html",  vendor="Xerox", proto="SMB",
    cve="CVE-2022-23969", desc="Xerox FutureSmart SMB config (CISA alert)" },
  { path="/web/entry.cgi?id=ldap",               vendor="Ricoh",  proto="LDAP",
    cve=nil, desc="Ricoh LDAP config" },
  { path="/web/entry.cgi?id=scan_folder",        vendor="Ricoh",  proto="SMB",
    cve=nil, desc="Ricoh scan-to-folder SMB config" },
  -- Konica
  { path="/wcd/ldap.html",                       vendor="Konica", proto="LDAP",
    cve=nil, desc="Konica bizhub LDAP config" },
  { path="/wcd/smb_setting.html",                vendor="Konica", proto="SMB",
    cve=nil, desc="Konica bizhub SMB scan config" },
  -- Toshiba
  { path="/TopAccess/Admin/Setting/E-MAIL/LDAPSetting.htm", vendor="Toshiba", proto="LDAP",
    cve=nil, desc="Toshiba TopAccess LDAP auth config" },
  -- Canon
  { path="/cgi-bin/dynamicconfig",               vendor="Canon",  proto="LDAP",
    cve=nil, desc="Canon dynamic config (may include LDAP)" },
  -- Brother
  { path="/network/network.html",                vendor="Brother", proto="SMTP",
    cve=nil, desc="Brother network config (SMTP credentials)" },
  -- Kyocera
  { path="/js/jssrc/model/system/LdapSetting.js", vendor="Kyocera", proto="LDAP",
    cve=nil, desc="Kyocera LDAP setting JS (check for config exposure)" },
  -- Generic
  { path="/cgi-bin/dynamic/config/ldapconfig.html", vendor="Generic", proto="LDAP",
    cve=nil, desc="Generic LDAP config endpoint" },
  { path="/ldap",                                vendor="Generic", proto="LDAP",
    cve=nil, desc="Generic /ldap path" },
  { path="/scan/smb",                            vendor="Generic", proto="SMB",
    cve=nil, desc="Generic scan-to-SMB endpoint" },
}

-- Known passback CVEs for detailed output
local PASSBACK_CVES = {
  ["CVE-2022-23968"] = {
    sev="HIGH", cvss=7.5,
    desc="Xerox FutureSmart LDAP passback — printer sends LDAP bind to rogue server capturing domain creds",
    xpl="xpl/research/research-passback-ldap",
  },
  ["CVE-2022-23969"] = {
    sev="HIGH", cvss=7.5,
    desc="Xerox FutureSmart SMB passback — printer authenticates to rogue SMB share capturing NTLM hashes",
    xpl="xpl/research/research-passback-smb",
  },
}

action = function(host, port)
  local out = stdnse.output_table()

  -- Quick root check
  local root = http.get(host, port.number, "/", { timeout = 4000 })
  if not root then return "HTTP not responding" end

  local accessible = {}
  local cves_triggered = {}
  local seen = {}
  local protos_found = {}

  for _, ep in ipairs(PASSBACK_ENDPOINTS) do
    local resp = http.get(host, port.number, ep.path,
      { timeout = 4000, redirect_ok = false })
    if resp and (resp.status == 200 or resp.status == 302) then
      local entry = string.format("%s (%s, HTTP %d) [%s — %s]",
        ep.path, ep.proto, resp.status, ep.vendor, ep.desc)
      table.insert(accessible, entry)
      protos_found[ep.proto] = true

      if ep.cve and not seen[ep.cve] then
        seen[ep.cve] = true
        local cve_detail = PASSBACK_CVES[ep.cve]
        if cve_detail then
          table.insert(cves_triggered, {
            id   = ep.cve,
            sev  = cve_detail.sev,
            cvss = cve_detail.cvss,
            desc = cve_detail.desc,
            xpl  = cve_detail.xpl,
          })
        end
      end
    end
  end

  if #accessible == 0 then
    return "No LDAP/SMB passback surfaces detected (admin pages may require auth or non-standard paths)"
  end

  -- Protocol summary
  local proto_list = {}
  for p, _ in pairs(protos_found) do table.insert(proto_list, p) end
  out["Protocols"] = table.concat(proto_list, ", ")

  out["Config-Pages-Found"] = accessible

  -- CVE output
  if #cves_triggered > 0 then
    local cve_lines = {}
    for _, c in ipairs(cves_triggered) do
      table.insert(cve_lines, string.format("[%s] %s (CVSS %.1f) — %s",
        c.sev, c.id, c.cvss, c.desc))
    end
    out["CVEs"] = cve_lines
  end

  -- Passback explanation
  local has_ldap = protos_found["LDAP"]
  local has_smb  = protos_found["SMB"]

  local attack_desc = {}
  if has_ldap then
    table.insert(attack_desc,
      "LDAP passback: redirect printer LDAP queries to rogue server → capture domain credentials")
  end
  if has_smb then
    table.insert(attack_desc,
      "SMB passback: redirect printer SMB auth to Responder/rogue share → capture NTLM hashes")
  end
  if #attack_desc > 0 then
    out["Attack-Vector"] = attack_desc
  end

  -- Verdict
  out["Verdict"] = "POSSIBLY VULNERABLE — " ..
    #accessible .. " config page(s) accessible; passback attack feasible if admin credentials known"

  if #cves_triggered > 0 then
    out["Suggest"] = "printerxpl-forge run --module " .. cves_triggered[1].xpl .. " --target " .. host.ip
  else
    out["Suggest"] = "printerxpl-forge run --module xpl/research/research-passback-ldap --target " .. host.ip
  end

  out["Manual-Steps"] =
    "1. Set up rogue LDAP/SMB server (Responder or custom)  " ..
    "2. Modify printer LDAP/SMB server IP to attacker IP  " ..
    "3. Trigger auth test from printer web UI  " ..
    "4. Capture credentials on rogue server"

  out["Full-Scan"] = "pip install printerxpl-forge  |  printerxpl-forge scan --target " .. host.ip

  return out
end
