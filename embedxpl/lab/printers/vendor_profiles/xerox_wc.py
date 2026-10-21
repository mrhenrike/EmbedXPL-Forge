#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PrinterLab — Xerox WorkCentre 7855 Profile
===========================================
Simulates a Xerox WorkCentre enterprise MFP.

Known vulnerabilities reproduced:
  - EDB-35151  : Xerox WorkCentre DLM remote code execution via firmware upload
  - CVE-2022-23968 : Xerox SSRF via IPP Print-URI
  - Default credentials: admin/1111
  - SNMP with full MIB (extensive printer info exposure)
"""
# Author    : Andre Henrique (@mrhenrike)
# GitHub    : https://github.com/mrhenrike
# LinkedIn  : https://linkedin.com/in/mrhenrike
# X/Twitter : https://x.com/mrhenrike

from simulators.base_printer import PrinterProfile

XEROX_WORKCENTER = PrinterProfile(
    make         = 'Xerox',
    model        = 'WorkCentre 7855',
    firmware     = '073.xxx.002.34100',
    serial       = 'XRX-C3A4B5C6',
    uuid         = 'urn:uuid:00000000-0000-0000-0000-xeroxwc7855',
    location     = 'Executive Suite — 10th Floor',
    contact      = 'sysadmin@corp.local',

    languages    = ['PJL', 'PCL', 'PostScript', 'TIFF'],
    doc_formats  = [
        'application/pdf',
        'application/postscript',
        'application/vnd.hp-PCL',
        'image/tiff',
        'application/octet-stream',
    ],

    admin_user   = 'admin',
    admin_pass   = '1111',      # Xerox default
    pjl_password = '',
    snmp_read    = 'public',
    snmp_write   = 'private',
    ftp_user     = 'admin',
    ftp_pass     = '1111',

    vuln = {
        'pjl_traversal':       True,
        'pjl_password_leak':   True,
        'anon_ipp_jobs':       False,   # Xerox requires auth for print
        'ipp_purge_anon':      False,
        'lpd_unauthenticated': True,
        'lpd_bof_probe':       False,
        'default_creds':       True,    # admin/1111
        'snmp_public_write':   True,    # Xerox enterprise MFPs often have write enabled
        'snmp_factory_reset':  True,
        'ftp_open':            True,
        'web_traversal':       False,
        'web_default_creds':   True,
        'wsd_enabled':         True,
        'ssrf_capable':        True,    # CVE-2022-23968
        'firmware_upload':     True,    # EDB-35151: DLM firmware upload RCE
        'nvram_rw':            True,
    },

    filesystem = {
        '0:/logs/security.log':   '2024-01-10 08:30:00 USER login admin SUCCESS\n2024-01-10 10:15:22 SCAN CEO scan.pdf\n',
        '0:/config/network.xml':  '<network><ip>10.0.0.50</ip><mask>255.255.0.0</mask><gw>10.0.0.1</gw></network>',
        '0:/config/auth.xml':     '<auth><admin_pass>1111</admin_pass><fax_forward>finance@corp.local</fax_forward></auth>',
        '0:/tmp/scan_fax001.pdf': '%PDF-1.4 1 0 obj<</Type/Catalog/Pages 2 0 R>>',
        '0:/tmp/scan_fax002.pdf': '%PDF-1.4 — Board agenda scan',
        '0:/dlm/firmware.dlm':    'XEROX DLM FIRMWARE PLACEHOLDER — replace with valid DLM for RCE',
    },

    snmp_mibs = {
        '1.3.6.1.2.1.1.1.0':          'Xerox WorkCentre 7855; ROM: 073.xxx.002.34100',
        '1.3.6.1.2.1.1.5.0':          'XRX-WC7855-EXEC',
        '1.3.6.1.2.1.1.6.0':          'Executive Suite — 10th Floor',
        '1.3.6.1.2.1.43.5.1.1.3.1':   '3',
        '1.3.6.1.2.1.43.5.1.1.1.1':   'Xerox WorkCentre 7855',
        '1.3.6.1.2.1.43.10.2.1.4.1.1':'98321',
        '1.3.6.1.4.1.253.8.62.1.8.1.1.1': 'admin',    # Xerox admin MIB
        '1.3.6.1.4.1.253.8.62.1.8.1.1.2': '1111',     # Xerox admin password exposed via SNMP!
    },

    port_raw  = 9100,
    port_ipp  = 631,
    port_lpd  = 515,
    port_http = 80,
    port_snmp = 161,
    port_ftp  = 21,
)
