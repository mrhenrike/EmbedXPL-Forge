local description = [[
printer-firmware-exposed — Firmware update endpoint exposure detection.

Probes vendor-specific HTTP endpoints commonly used for firmware updates to detect:
  - Unauthenticated firmware upload interfaces
  - Exposed firmware management APIs
  - Insecure firmware download endpoints (prone to MitM firmware replacement)

Covers: HP, Ricoh, Konica Minolta, Brother, Epson, Kyocera, Lexmark, Canon,
        Toshiba, Xerox, Sharp, Samsung, OKI.

CVE coverage: CVE-2023-6018, FIRMWARE-RICOH-001, FIRMWARE-KONICA-001,
              FIRMWARE-BROTHER-001, FIRMWARE-EPSON-001, CVE-2023-50738

Author: André Henrique (@mrhenrike) | União Geek
]]

---
-- @usage
--   nmap -p 80,443,8080 --script printer-firmware-exposed <target>
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | printer-firmware-exposed:
-- |   Exposed Endpoints (3):
-- |     /hp/device/FirmwareUpdate (HTTP 200 — no auth required)
-- |     /cgi-bin/fw_update        (HTTP 200 — no auth required)
-- |     /firmware                 (HTTP 302 → /firmware/upload)
-- |   [CRITICAL] CVE-2023-6018 — HP firmware auth bypass → arbitrary .RFU upload
-- |   [HIGH] FIRMWARE-RICOH-001  — Ricoh Aficio unsigned firmware upload
-- |   Verdict : VULNERABLE — 3 unprotected firmware endpoints found
-- |_  Suggest : printerxpl-forge run --module xpl/research/research-hp-fw-bypass
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

-- Firmware endpoint database: { path, vendor, method, cve, sev, cvss, xpl, desc }
local FW_ENDPOINTS = {
  -- HP
  { path="/hp/device/FirmwareUpdate",          vendor="HP",     method="GET",  auth_check=true,
    cve="CVE-2023-6018", sev="CRITICAL", cvss=9.8,
    desc="HP FutureSmart firmware auth bypass → arbitrary .RFU upload",
    xpl="xpl/research/research-hp-fw-bypass" },
  { path="/hp/device/info_firmwareupdate.htm", vendor="HP",     method="GET",  auth_check=true,
    cve="CVE-2023-6018", sev="CRITICAL", cvss=9.8,
    desc="HP firmware update info page (EWS unauthenticated)",
    xpl="xpl/research/research-hp-fw-bypass" },
  -- Ricoh
  { path="/cgi-bin/fw_update",                 vendor="Ricoh",  method="GET",  auth_check=true,
    cve="FIRMWARE-RICOH-001", sev="HIGH", cvss=8.0,
    desc="Ricoh Aficio unsigned firmware upload via /cgi-bin/fw_update",
    xpl="xpl/research/research-ricoh-fw-unsigned" },
  { path="/web/entry.cgi?id=fw",               vendor="Ricoh",  method="GET",  auth_check=true,
    cve="FIRMWARE-RICOH-001", sev="HIGH", cvss=8.0,
    desc="Ricoh web firmware management entry (no signature check)",
    xpl="xpl/research/research-ricoh-fw-unsigned" },
  -- Konica Minolta
  { path="/wcd/fwdl.cgi",                      vendor="Konica", method="GET",  auth_check=true,
    cve="FIRMWARE-KONICA-001", sev="HIGH", cvss=8.5,
    desc="Konica bizhub firmware download/upload via /wcd/fwdl.cgi",
    xpl="xpl/research/research-konica-fw-upload" },
  { path="/wcd/index.html",                    vendor="Konica", method="GET",  auth_check=false,
    cve="FIRMWARE-KONICA-001", sev="HIGH", cvss=8.5,
    desc="Konica bizhub admin page (check for firmware menu)",
    xpl="xpl/research/research-konica-fw-upload" },
  -- Brother
  { path="/firmware",                          vendor="Brother", method="GET", auth_check=true,
    cve="FIRMWARE-BROTHER-001", sev="HIGH", cvss=8.0,
    desc="Brother MFC/DCP firmware upload endpoint",
    xpl="xpl/research/research-brother-fw-upload" },
  { path="/general/firmware_update.html",      vendor="Brother", method="GET", auth_check=true,
    cve="FIRMWARE-BROTHER-001", sev="HIGH", cvss=8.0,
    desc="Brother firmware update page (chain with CVE-2024-51978)",
    xpl="xpl/research/research-brother-fw-upload" },
  -- Epson
  { path="/PRESENTATION/ADVANCED/FIRMWARE_UPDATE/TOP", vendor="Epson", method="GET", auth_check=true,
    cve="FIRMWARE-EPSON-001", sev="HIGH", cvss=7.5,
    desc="Epson firmware update presentation layer (WorkForce/EcoTank)",
    xpl="xpl/research/research-epson-fw-update" },
  -- Canon
  { path="/portal_top.html",                   vendor="Canon",  method="GET",  auth_check=false,
    cve=nil, sev="INFO", cvss=0,
    desc="Canon imageRUNNER admin portal (check for firmware menu)",
    xpl=nil },
  { path="/cgi-bin/fwdl.cgi",                  vendor="Canon",  method="GET",  auth_check=true,
    cve="CVE-2025-14235", sev="CRITICAL", cvss=9.8,
    desc="Canon imageCLASS firmware download endpoint",
    xpl="xpl/research/research-canon-pcl-bof" },
  -- Kyocera
  { path="/js/jssrc/model/system/FirmwareUpdate.js", vendor="Kyocera", method="GET", auth_check=false,
    cve=nil, sev="INFO", cvss=0,
    desc="Kyocera ECOSYS firmware update JS source detected",
    xpl=nil },
  -- Lexmark
  { path="/cgi-bin/dynamic/printer/PrinterStatus.html", vendor="Lexmark", method="GET", auth_check=false,
    cve="CVE-2023-50738", sev="HIGH", cvss=7.2,
    desc="Lexmark firmware downgrade bypass surface",
    xpl="xpl/research/research-lexmark-fw-decrypt" },
  -- Toshiba
  { path="/TopAccess/Admin/FirmwareUpdate",    vendor="Toshiba", method="GET", auth_check=true,
    cve="CVE-2024-21911", sev="HIGH", cvss=8.8,
    desc="Toshiba e-STUDIO TopAccess firmware update (auth bypass CVE-2024-21911)",
    xpl="xpl/research/research-toshiba-auth-bypass" },
  -- Xerox
  { path="/cgi-bin/dynamic/index.html",        vendor="Xerox",  method="GET",  auth_check=false,
    cve=nil, sev="INFO", cvss=0,
    desc="Xerox EWS dynamic page",
    xpl=nil },
  -- Generic
  { path="/firmware/update",                   vendor="Generic", method="GET", auth_check=true,
    cve=nil, sev="MEDIUM", cvss=5.0,
    desc="Generic firmware update endpoint",
    xpl="xpl/research/research-generic-fw-upload" },
  { path="/upgrade",                           vendor="Generic", method="GET", auth_check=true,
    cve=nil, sev="MEDIUM", cvss=5.0,
    desc="Generic upgrade endpoint",
    xpl=nil },
}

action = function(host, port)
  local out = stdnse.output_table()

  -- Quick root probe to confirm HTTP service
  local root = http.get(host, port.number, "/", { timeout = 4000 })
  if not root then return "HTTP not responding" end

  local exposed = {}
  local cves_found = {}
  local seen_cves = {}

  for _, ep in ipairs(FW_ENDPOINTS) do
    local resp = http.get(host, port.number, ep.path,
      { timeout = 4000, redirect_ok = false })
    if resp then
      local interesting = (resp.status == 200) or
                          (resp.status == 302) or
                          (resp.status == 401)  -- 401 = exists but needs auth
      if interesting then
        local status_str = tostring(resp.status)
        local needs_auth = (resp.status == 401 or resp.status == 403)

        if resp.status == 200 and ep.auth_check then
          -- Unprotected! High severity
          table.insert(exposed, string.format("%s (HTTP %s — no auth required) [%s]",
            ep.path, status_str, ep.vendor))
          if ep.cve and not seen_cves[ep.cve] then
            seen_cves[ep.cve] = true
            table.insert(cves_found, ep)
          end
        elseif resp.status == 200 then
          table.insert(exposed, string.format("%s (HTTP %s) [%s]",
            ep.path, status_str, ep.vendor))
        elseif needs_auth then
          table.insert(exposed, string.format("%s (HTTP %s — auth required, endpoint EXISTS) [%s]",
            ep.path, status_str, ep.vendor))
        elseif resp.status == 302 then
          local loc = resp.header and resp.header["location"] or "?"
          table.insert(exposed, string.format("%s → %s (HTTP %s) [%s]",
            ep.path, loc, status_str, ep.vendor))
        end
      end
    end
  end

  if #exposed == 0 then
    return "No firmware endpoints found — device may be patched or use non-standard paths"
  end

  out["Exposed-Endpoints"] = exposed

  -- Build CVE output
  if #cves_found > 0 then
    local cve_lines = {}
    for _, c in ipairs(cves_found) do
      if c.cve then
        table.insert(cve_lines, string.format("[%s] %s (CVSS %.1f) — %s",
          c.sev, c.cve, c.cvss, c.desc))
      end
    end
    out["CVEs"] = cve_lines
  end

  -- Verdict
  local unauth_count = 0
  for _, ep_str in ipairs(exposed) do
    if ep_str:match("no auth required") then unauth_count = unauth_count + 1 end
  end

  if unauth_count > 0 then
    out["Verdict"] = string.format(
      "VULNERABLE — %d unprotected firmware endpoint(s) found", unauth_count)
    if cves_found[1] and cves_found[1].xpl then
      out["Suggest"] = "printerxpl-forge run --module " .. cves_found[1].xpl .. " --target " .. host.ip
    end
  elseif #exposed > 0 then
    out["Verdict"] = string.format(
      "POSSIBLY VULNERABLE — %d firmware endpoint(s) detected (auth required)", #exposed)
    if cves_found[1] and cves_found[1].xpl then
      out["Suggest"] = "printerxpl-forge run --module " .. cves_found[1].xpl ..
                       " --dry-run --target " .. host.ip
    end
  else
    out["Verdict"] = "NOT VULNERABLE — no firmware endpoints accessible"
  end

  out["Full-Scan"] = "pip install printerxpl-forge  |  printerxpl-forge scan --target " .. host.ip

  return out
end
