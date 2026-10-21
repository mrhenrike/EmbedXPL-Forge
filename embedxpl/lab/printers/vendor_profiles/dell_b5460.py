#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PrinterLab — Dell B5460dn Profile
====================================
Simulates a Dell laser printer (OEM Lexmark).

BlackHat 2017 matrix: 11 vulnerabilities
  - PS infinite loop, showpage redefinition, offline mode, physical damage
  - SNMP factory reset, PS factory restore, PS content overlay/replacement
  - PJL memory access, file system access, credential disclosure

Default credentials:
  - Web: admin / (blank)
  - SNMP: public / private
  - Dell printers share Lexmark firmware base
"""
# Author    : Andre Henrique (@mrhenrike)
# GitHub    : https://github.com/mrhenrike
# LinkedIn  : https://linkedin.com/in/mrhenrike
# X/Twitter : https://x.com/mrhenrike

from simulators.base_printer import PrinterProfile

DELL_B5460 = PrinterProfile(
    make         = 'Dell',
    model        = 'B5460dn',
    firmware     = 'LD71.JN.P338',
    serial       = 'DLB5005892',
    uuid         = 'urn:uuid:00000000-0000-0000-0000-dellb5460dn',
    location     = 'Server Room — IT Dept',
    contact      = 'it@corp.local',

    languages    = ['PJL', 'PCL', 'PostScript', 'PCL6'],
    doc_formats  = [
        'application/pdf',
        'application/postscript',
        'application/vnd.hp-PCL',
        'application/vnd.hp-PCLXL',
        'application/octet-stream',
    ],

    admin_user   = 'admin',
    admin_pass   = '',
    pjl_password = '',
    snmp_read    = 'public',
    snmp_write   = 'private',
    ftp_user     = 'admin',
    ftp_pass     = '',

    vuln = {
        'pjl_traversal':       True,
        'pjl_password_leak':   True,
        'anon_ipp_jobs':       True,
        'ipp_purge_anon':      True,
        'lpd_unauthenticated': True,
        'lpd_bof_probe':       True,
        'default_creds':       True,
        'snmp_public_write':   True,   # Dell B-series: SNMP write often enabled
        'snmp_factory_reset':  True,
        'ftp_open':            True,
        'web_traversal':       True,
        'web_default_creds':   True,
        'wsd_enabled':         True,
        'ssrf_capable':        True,
        'firmware_upload':     True,
        'nvram_rw':            True,
    },

    filesystem = {
        '0:/etc/passwd':          'root::0:0::/:/bin/sh\nadmin::0:0::/:/bin/sh\n',
        '0:/dell/config/net.cfg': 'ip=192.168.1.80\ngateway=192.168.1.1\npassword=\n',
        '0:/tmp/spooled/job001.ps': '%!PS\n%%Title: Dell Confidential Job\n(IT dept) show\nshowpage\n%%EOF',
    },

    snmp_mibs = {
        '1.3.6.1.2.1.1.1.0':         'Dell B5460dn; ROM: LD71.JN.P338; Lexmark OEM',
        '1.3.6.1.2.1.1.5.0':         'DELL-B5460DN-ITDEPT',
        '1.3.6.1.2.1.1.6.0':         'Server Room',
        '1.3.6.1.2.1.43.5.1.1.3.1':  '3',
        '1.3.6.1.2.1.43.5.1.1.1.1':  'Dell B5460dn',
        '1.3.6.1.2.1.43.10.2.1.4.1.1': '89221',
    },

    port_raw  = 9100,
    port_ipp  = 631,
    port_lpd  = 515,
    port_http = 80,
    port_snmp = 161,
    port_ftp  = 21,
)
