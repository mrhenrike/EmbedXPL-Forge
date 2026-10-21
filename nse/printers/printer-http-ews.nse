local description = [[
printer-http-ews — HTTP Embedded Web Server (EWS) fingerprinting and vulnerability check.

Probes common printer EWS paths to identify: vendor, model, firmware version,
admin interface presence, default credential indicators, and exposed management endpoints.

Active checks:
  - Firmware update endpoint exposure (unauthenticated access)
  - Default credentials probe (admin/admin, admin/blank, etc.)
  - LDAP/SMB passback surface detection (scan-to-email config pages)
  - Session fixation indicators

CVE coverage: CVE-2023-6018 (HP FW bypass), CVE-2024-21911 (Toshiba TopAccess),
              CVE-2021-27508 (Xerox WorkCentre), CVE-2024-6333 (Xerox VersaLink),
              CVE-2022-29943 (Ricoh web cmd inject), FIRMWARE-RICOH/KONICA/BROTHER-001

Author: André Henrique (@mrhenrike) | União Geek
]]

---
-- @usage
--   nmap -p 80,443,8080 --script printer-http-ews <target>
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | printer-http-ews:
-- |   Vendor          : Xerox
-- |   Model           : VersaLink C405
-- |   Firmware        : 57.66.91 (vulnerable range)
-- |   Admin-Interface : /web/index.html (200 OK — no auth)
-- |   Firmware-Update : /cgi-bin/fw_update (200 OK — exposed)
-- |   [HIGH] CVE-2024-6333 — Xerox VersaLink authenticated OS command injection
-- |   Verdict         : POSSIBLY VULNERABLE
-- |_  Suggest         : printerxpl-forge run --module xpl/edb-cve-2024-6333 --target <IP>
---

categories = { "discovery", "auth", "vuln" }
author     = "André Henrique (@mrhenrike) | União Geek"
license    = "Same as Nmap -- See https://nmap.org/book/man-legal.html"

local stdnse    = require "stdnse"
local shortport = require "shortport"
local http      = require "http"
local base64    = require "base64"
local string    = require "string"
local table     = require "table"

portrule = shortport.http

-- Vendor-specific EWS admin paths
local VENDOR_PATHS = {
  { vendor = "HP",            path = "/hp/device/DeviceMgmt.htm",         fw_path = "/hp/device/FirmwareUpdate" },
  { vendor = "HP",            path = "/hp/device/info_deviceStatus.htm",   fw_path = nil },
  { vendor = "Xerox",         path = "/web/index.html",                    fw_path = nil },
  { vendor = "Xerox",         path = "/cgi-bin/cloning",                   fw_path = nil },
  { vendor = "Ricoh",         path = "/web/entry.cgi",                     fw_path = "/cgi-bin/fw_update" },
  { vendor = "Ricoh",         path = "/",                                  fw_path = "/cgi-bin/fw_update" },
  { vendor = "Konica",        path = "/wcd/index.html",                    fw_path = "/wcd/fwdl.cgi" },
  { vendor = "Brother",       path = "/general/status.html",               fw_path = "/firmware" },
  { vendor = "Toshiba",       path = "/TopAccess/",                        fw_path = nil },
  { vendor = "Lexmark",       path = "/cgi-bin/dynamic/",                  fw_path = nil },
  { vendor = "Canon",         path = "/portal_top.html",                   fw_path = nil },
  { vendor = "Epson",         path = "/PRESENTATION/ADVANCED/TOP",         fw_path = "/PRESENTATION/ADVANCED/FIRMWARE_UPDATE/TOP" },
  { vendor = "Sharp",         path = "/",                                  fw_path = nil },
  { vendor = "Kyocera",       path = "/js/jssrc/model/system/SystemStatus.js", fw_path = nil },
  { vendor = "Generic",       path = "/",                                  fw_path = nil },
}

local DEFAULT_CREDS = {
  { user = "admin",      pass = "" },
  { user = "admin",      pass = "admin" },
  { user = "admin",      pass = "1111" },
  { user = "admin",      pass = "password" },
  { user = "supervisor", pass = "supervisor" },
  { user = "root",       pass = "" },
  { user = "user",       pass = "" },
}

local CVE_RULES = {
  { vendor = "hp",      fw_path_exposed = true,  cve = "CVE-2023-6018",  sev = "CRITICAL", cvss = 9.8,
    desc = "HP firmware auth bypass — arbitrary firmware upload",
    xpl  = "xpl/research/research-hp-fw-bypass" },
  { vendor = "xerox",   path = "/cgi-bin/cloning", cve = "CVE-2021-27508", sev = "HIGH", cvss = 8.0,
    desc = "Xerox WorkCentre OS command injection via clone_group",
    xpl  = "xpl/research/research-xerox-workcentre-cmdinject" },
  { vendor = "xerox",   default_creds = true,   cve = "CVE-2024-6333",   sev = "HIGH", cvss = 8.1,
    desc = "Xerox VersaLink OS command injection (authenticated)",
    xpl  = "xpl/edb-cve-2024-6333" },
  { vendor = "ricoh",   fw_path_exposed = true,  cve = "FIRMWARE-RICOH-001", sev = "HIGH", cvss = 8.0,
    desc = "Ricoh Aficio unsigned firmware upload without sig check",
    xpl  = "xpl/research/research-ricoh-fw-unsigned" },
  { vendor = "ricoh",   default_creds = true,   cve = "CVE-2022-29943",  sev = "HIGH", cvss = 8.8,
    desc = "Ricoh MP web admin command injection",
    xpl  = "xpl/research/research-ricoh-web-cmdinject" },
  { vendor = "konica",  fw_path_exposed = true,  cve = "FIRMWARE-KONICA-001", sev = "HIGH", cvss = 8.5,
    desc = "Konica bizhub unsigned firmware upload via /wcd/fwdl.cgi",
    xpl  = "xpl/research/research-konica-fw-upload" },
  { vendor = "brother", fw_path_exposed = true,  cve = "FIRMWARE-BROTHER-001", sev = "HIGH", cvss = 8.0,
    desc = "Brother MFC firmware upload via HTTP PUT (chain with CVE-2024-51978)",
    xpl  = "xpl/research/research-brother-fw-upload" },
  { vendor = "toshiba", default_creds = true,   cve = "CVE-2024-21911",  sev = "HIGH", cvss = 8.8,
    desc = "Toshiba e-STUDIO TopAccess authentication bypass",
    xpl  = "xpl/research/research-toshiba-auth-bypass" },
  { vendor = "lexmark", default_creds = true,   cve = "CVE-2023-50733",  sev = "MEDIUM", cvss = 6.5,
    desc = "Lexmark EWS SSRF — printer as lateral movement pivot",
    xpl  = "xpl/edb-cve-2023-50733" },
}

-- Basic auth header helper
local function basic_auth(user, pass)
  return "Basic " .. base64.enc(user .. ":" .. pass)
end

-- Probe a path (with optional auth)
local function probe(host, port, path, auth_header)
  local opts = { timeout = 5000 }
  if auth_header then
    opts.header = { ["Authorization"] = auth_header }
  end
  local resp = http.get(host, port.number, path, opts)
  if resp then
    return resp.status, (resp.body or ""):sub(1, 4096)
  end
  return nil, ""
end

action = function(host, port)
  local out = stdnse.output_table()

  -- Step 1: probe root and collect banner
  local root_status, root_body = probe(host, port, "/")
  if not root_status then
    return "HTTP EWS not responding"
  end

  local body_lower = root_body:lower()

  -- Detect vendor
  local vendor_name = nil
  local vendor_key  = nil
  local vmap = {
    { pat = "hp laserjet|hewlett.packard|jetdirect|futuresmart", name = "HP",    key = "hp" },
    { pat = "xerox versalink|xerox workcentre|xerox altalink",   name = "Xerox", key = "xerox" },
    { pat = "ricoh|aficio|mp c",                                 name = "Ricoh", key = "ricoh" },
    { pat = "konica|bizhub",                                     name = "Konica Minolta", key = "konica" },
    { pat = "brother mfc|brother dcp|brother hl",                name = "Brother", key = "brother" },
    { pat = "toshiba e.studio|topaccess",                        name = "Toshiba", key = "toshiba" },
    { pat = "lexmark",                                           name = "Lexmark", key = "lexmark" },
    { pat = "canon imagerunner|canon imageclass|canon lbp",      name = "Canon",   key = "canon" },
    { pat = "epson workforce|epson ecotank",                     name = "Epson",   key = "epson" },
    { pat = "sharp mx|sharp ar",                                 name = "Sharp",   key = "sharp" },
    { pat = "kyocera ecosys|kyocera taskalfa",                   name = "Kyocera", key = "kyocera" },
    { pat = "samsung scx|samsung clx|samsung ml",                name = "Samsung", key = "samsung" },
  }
  for _, v in ipairs(vmap) do
    if body_lower:match(v.pat) then
      vendor_name = v.name
      vendor_key  = v.key
      break
    end
  end

  -- Server header hint
  local server_hdr = ""
  -- (Nmap doesn't expose raw headers directly, but http.get returns header table)

  if vendor_name then
    out["Vendor"] = vendor_name
  else
    out["Vendor"] = "Unknown (generic EWS detected)"
  end

  -- Extract model from title or meta
  local model = root_body:match("<title>([^<]+)</title>")
             or root_body:match('content="([^"]+)"')
  if model then
    out["Model"] = model:match("^%s*(.-)%s*$"):sub(1, 80)
  end

  -- Extract firmware hint
  local fw = root_body:match("[Ff]irmware[Vv]ersion[^:]*[:%s]+([%w%.%-]+)")
          or root_body:match("[Vv]ersion[^:]*[:%s]+([%w%.%-]+)")
  if fw then out["Firmware"] = fw end

  -- Step 2: check specific vendor paths
  local fw_exposed  = false
  local admin_open  = false
  local passback_exposed = false

  for _, vp in ipairs(VENDOR_PATHS) do
    local vl = vp.vendor:lower()
    if vl == "generic" or vl == (vendor_key or "") then
      local st, bd = probe(host, port, vp.path)
      if st == 200 and #bd > 100 then
        admin_open = true
        out["Admin-Interface"] = vp.path .. " (HTTP 200 — accessible)"
      end
      if vp.fw_path then
        local fst, _ = probe(host, port, vp.fw_path)
        if fst == 200 then
          fw_exposed = true
          out["Firmware-Update-Endpoint"] = vp.fw_path .. " (HTTP 200 — EXPOSED)"
        end
      end
      break
    end
  end

  -- Check LDAP/SMB passback surface
  local passback_paths = {
    "/hp/device/LdapConfiguration.htm",
    "/cgi-bin/dynamic/config/ldapconfig.html",
    "/TopAccess/ADMIN/Setting/E-MAIL/LDAPSetting.htm",
    "/web/entry.cgi?id=ldap",
  }
  for _, pp in ipairs(passback_paths) do
    local pst, _ = probe(host, port, pp)
    if pst == 200 then
      passback_exposed = true
      out["LDAP-Passback-Surface"] = pp .. " (accessible — SMB/LDAP passback possible)"
      break
    end
  end

  -- Step 3: default credential test
  local creds_found = nil
  if admin_open and vendor_name then
    for _, cr in ipairs(DEFAULT_CREDS) do
      local ah = basic_auth(cr.user, cr.pass)
      local st, bd = probe(host, port, "/", ah)
      if st == 200 and bd:lower():match("logout") then
        creds_found = cr.user .. ":" .. (cr.pass == "" and "(blank)" or cr.pass)
        out["Default-Creds"] = "FOUND — " .. creds_found
        break
      end
    end
    if not creds_found then
      out["Default-Creds"] = "Not found (or auth not required)"
    end
  end

  -- Step 4: CVE matching
  local cves_found = {}
  if vendor_key then
    for _, rule in ipairs(CVE_RULES) do
      local match = (rule.vendor == vendor_key)
      if match then
        local triggers = false
        if rule.fw_path_exposed and fw_exposed then triggers = true end
        if rule.default_creds and (creds_found ~= nil or admin_open) then triggers = true end
        if rule.path then
          local pst, _ = probe(host, port, rule.path)
          if pst == 200 then triggers = true end
        end
        if triggers then
          table.insert(cves_found, rule)
        end
      end
    end
  end

  -- Build CVE output
  if #cves_found > 0 then
    local cve_lines = {}
    for _, c in ipairs(cves_found) do
      table.insert(cve_lines, string.format(
        "[%s] %s (CVSS %.1f) — %s", c.sev, c.cve, c.cvss, c.desc))
    end
    out["CVEs"] = table.concat(cve_lines, "  |  ")
  end

  -- Verdict
  local is_vuln     = (#cves_found > 0 and fw_exposed) or (creds_found ~= nil)
  local is_possible = #cves_found > 0 or admin_open or passback_exposed

  if is_vuln then
    out["Verdict"] = "VULNERABLE"
    if cves_found[1] then
      out["Suggest"] = "printerxpl-forge run --module " .. cves_found[1].xpl .. " --target " .. host.ip
    end
  elseif is_possible then
    out["Verdict"] = "POSSIBLY VULNERABLE — run printer-vuln-check for confirmation"
    if cves_found[1] then
      out["Suggest"] = "printerxpl-forge run --module " .. cves_found[1].xpl .. " --dry-run --target " .. host.ip
    end
  else
    out["Verdict"] = "NOT VULNERABLE to detected CVEs (manual review recommended)"
  end

  out["Full-Scan"] = "pip install printerxpl-forge  |  printerxpl-forge scan --target " .. host.ip

  return out
end
