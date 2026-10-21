#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PrinterLab — Lexmark CS720de Profile
=======================================
Simulates a Lexmark color laser printer.

BlackHat 2017 matrix: 10 vulnerabilities (highest count after HP)
  - PS infinite loop, showpage redefinition, offline mode, physical damage
  - SNMP factory reset, PML factory reset, PS factory restore
  - PS content overlay/replacement (print job manipulation)
  - PJL filesystem access + credential disclosure

Default credentials:
  - Web admin: admin / (blank password)
  - SNMP: public (read), private (write)
  - Lexmark Device Password: blank on most models
"""
# Author    : Andre Henrique (@mrhenrike)
# GitHub    : https://github.com/mrhenrike
# LinkedIn  : https://linkedin.com/in/mrhenrike
# X/Twitter : https://x.com/mrhenrike

from simulators.base_printer import PrinterProfile

LEXMARK_CS720 = PrinterProfile(
    make         = 'Lexmark',
    model        = 'CS720de',
    firmware     = 'CSPB.075.241',
    serial       = 'LXKB0003456',
    uuid         = 'urn:uuid:00000000-0000-0000-0000-lexmarkcs720de',
    location     = 'Print Center — Floor 4',
    contact      = 'helpdesk@corp.local',

    languages    = ['PJL', 'PCL', 'PostScript', 'PCL6', 'PDF'],
    doc_formats  = [
        'application/pdf',
        'application/postscript',
        'application/vnd.hp-PCL',
        'application/vnd.hp-PCLXL',
        'application/octet-stream',
    ],

    admin_user   = 'admin',
    admin_pass   = '',          # Lexmark default: blank
    pjl_password = '',
    snmp_read    = 'public',
    snmp_write   = 'private',
    ftp_user     = 'admin',
    ftp_pass     = '',

    vuln = {
        'pjl_traversal':       True,   # n/a per BHat but some models vulnerable
        'pjl_password_leak':   False,  # Lexmark: n/a for PS password
        'anon_ipp_jobs':       True,
        'ipp_purge_anon':      True,
        'lpd_unauthenticated': True,
        'lpd_bof_probe':       True,   # BHat 2017: physical damage confirmed
        'default_creds':       True,   # admin/blank
        'snmp_public_write':   False,
        'snmp_factory_reset':  True,   # PML + SNMP factory restore (BHat 2017)
        'ftp_open':            True,
        'web_traversal':       False,
        'web_default_creds':   True,
        'wsd_enabled':         True,
        'ssrf_capable':        True,
        'firmware_upload':     True,
        'nvram_rw':            True,
    },

    filesystem = {
        '0:/sys/lexmark/net.cfg':    'ip=192.168.1.70\nadmin=\nadmin_pass=\n',
        '0:/sys/lexmark/jobs.log':   '2024-01-22 09:00:01 PRINT ceo board-q4.pdf 12 pages\n',
        '0:/etc/passwd':             'root::0:0::/:/bin/sh\nlexmark::1000:1000::/home/lx:/bin/sh\n',
    },

    snmp_mibs = {
        '1.3.6.1.2.1.1.1.0':         'Lexmark CS720de; SW: CSPB.075.241',
        '1.3.6.1.2.1.1.5.0':         'LEXMARK-CS720-F4',
        '1.3.6.1.2.1.1.6.0':         'Print Center — Floor 4',
        '1.3.6.1.2.1.43.5.1.1.3.1':  '3',
        '1.3.6.1.2.1.43.5.1.1.1.1':  'Lexmark CS720de',
        '1.3.6.1.2.1.43.10.2.1.4.1.1': '45321',
        '1.3.6.1.4.1.641.2.1.2.1.2.0': 'CSPB.075.241',  # Lexmark firmware MIB
    },

    port_raw  = 9100,
    port_ipp  = 631,
    port_lpd  = 515,
    port_http = 80,
    port_snmp = 161,
    port_ftp  = 21,
)
