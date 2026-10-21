#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PrinterLab — Brother MFC-J5945DW Profile
==========================================
Simulates a Brother MFC inkjet/laser multifunction printer.

BlackHat 2017 matrix: 7 vulnerabilities
  - PS Infinite loop (DoS)
  - PS showpage redefinition
  - PJL physical damage (NVRAM)
  - PML factory reset (SNMP)
  - PS print job manipulation (content overlay / replacement)
  - Memory access via PJL
  - Credential disclosure via PJL INFO VARIABLES

Default credentials (from Brother manuals):
  - HTTP web: user = admin, password = access or initpass
  - FTP:      user = admin, password = access
  - SNMP:     community = public
  - Telnet:   no auth on some models
"""
# Author    : Andre Henrique (@mrhenrike)
# GitHub    : https://github.com/mrhenrike
# LinkedIn  : https://linkedin.com/in/mrhenrike
# X/Twitter : https://x.com/mrhenrike

from simulators.base_printer import PrinterProfile

BROTHER_MFC = PrinterProfile(
    make         = 'Brother',
    model        = 'MFC-J5945DW',
    firmware     = 'U1.28J',
    serial       = 'U63883A9N392543',
    uuid         = 'urn:uuid:00000000-0000-0000-0000-brothermfcj5945',
    location     = 'Conference Room A',
    contact      = 'it@corp.local',

    languages    = ['PJL', 'PCL', 'PostScript', 'BRScript3'],
    doc_formats  = [
        'application/pdf',
        'application/postscript',
        'application/vnd.hp-PCL',
        'image/jpeg',
        'image/png',
        'application/octet-stream',
    ],

    admin_user   = 'admin',
    admin_pass   = 'access',     # Brother default — or 'initpass'
    pjl_password = '',
    snmp_read    = 'public',
    snmp_write   = 'private',
    ftp_user     = 'admin',
    ftp_pass     = 'access',

    vuln = {
        'pjl_traversal':       True,   # PJL filesystem access
        'pjl_password_leak':   True,   # INFO VARIABLES leaks password
        'anon_ipp_jobs':       True,   # Anonymous print accepted
        'ipp_purge_anon':      True,
        'lpd_unauthenticated': True,
        'lpd_bof_probe':       True,   # BHat 2017: Brother physical damage via oversized ctrl
        'default_creds':       True,   # admin/access
        'snmp_public_write':   False,
        'snmp_factory_reset':  True,   # PML (SNMP-based) factory reset
        'ftp_open':            True,
        'web_traversal':       False,
        'web_default_creds':   True,
        'wsd_enabled':         True,
        'ssrf_capable':        True,
        'firmware_upload':     False,
        'nvram_rw':            True,   # PJL NVRAM damage (BHat 2017)
    },

    filesystem = {
        '0:/etc/passwd':             'root::0:0::/:/bin/sh\nadmin::1000:1000::/home/admin:/bin/sh\n',
        '0:/brother/config/net.cfg': 'ip=192.168.1.60\ngateway=192.168.1.1\nsnmp=public\n',
        '0:/brother/config/web.cfg': 'admin_user=admin\nadmin_pass=access\n',
        '0:/tmp/job001.prn':         '%!PS\n%%Title: Brother Confidential\n(access) show\nshowpage\n%%EOF',
    },

    snmp_mibs = {
        '1.3.6.1.2.1.1.1.0':         'Brother MFC-J5945DW; ROM: U1.28J',
        '1.3.6.1.2.1.1.5.0':         'BROTHER-MFCJ5945',
        '1.3.6.1.2.1.1.6.0':         'Conference Room A',
        '1.3.6.1.2.1.43.5.1.1.3.1':  '3',
        '1.3.6.1.2.1.43.5.1.1.1.1':  'Brother MFC-J5945DW',
        '1.3.6.1.2.1.43.10.2.1.4.1.1': '3421',
        '1.3.6.1.4.1.2435.2.3.9.4.2.1.1.5.0': 'U63883A9N392543',  # Brother serial MIB
    },

    port_raw  = 9100,
    port_ipp  = 631,
    port_lpd  = 515,
    port_http = 80,
    port_snmp = 161,
    port_ftp  = 21,
)
