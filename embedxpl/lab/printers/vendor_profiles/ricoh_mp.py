#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PrinterLab — Ricoh MP C3003 Profile
=====================================
Simulates a Ricoh multifunction printer.

Known vulnerabilities reproduced:
  - CVE-2019-14308 : LPD buffer overflow
  - EDB-47850      : Ricoh multiple MFP XSS via log viewer
  - Default admin password: blank (admin/)
  - SNMP public community with broad MIB access
  - FTP access with default credentials
"""
# Author    : Andre Henrique (@mrhenrike)
# GitHub    : https://github.com/mrhenrike
# LinkedIn  : https://linkedin.com/in/mrhenrike
# X/Twitter : https://x.com/mrhenrike

from simulators.base_printer import PrinterProfile

RICOH_MP_C3003 = PrinterProfile(
    make         = 'Ricoh',
    model        = 'MP C3003',
    firmware     = 'D088M4500',
    serial       = 'E4823001',
    uuid         = 'urn:uuid:00000000-0000-0000-0000-ricohc3003',
    location     = 'Print Room — B1',
    contact      = 'helpdesk@corp.local',

    languages    = ['PJL', 'PCL', 'PostScript'],
    doc_formats  = [
        'application/pdf',
        'application/postscript',
        'application/vnd.hp-PCL',
        'application/octet-stream',
    ],

    admin_user   = 'admin',
    admin_pass   = '',          # blank — common Ricoh default
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
        'lpd_bof_probe':       True,   # CVE-2019-14308
        'default_creds':       True,
        'snmp_public_write':   False,
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
        '0:/etc/passwd':          'root::0:0::/:/bin/sh\nadmin::0:0::/:/bin/sh\nricoh::1000:1000::/home/ricoh:/bin/sh\n',
        '0:/etc/shadow':          'root:$1$ricoh$abc123456:18000:0:99999:7:::\nadmin::18000:0:99999:7:::\n',
        '0:/usr/ricoh/conf/web.conf': 'admin_password=\nweb_port=80\nssl_port=443\nssl_enabled=1\n',
        '0:/tmp/jobs/job001.prn': '%!PS\n%%Title: HR Termination Letters\n(CONFIDENTIAL) show\nshowpage\n%%EOF',
        '0:/tmp/jobs/job002.prn': '%!PS\n%%Title: Merger Announcement\n(CONFIDENTIAL) show\nshowpage\n%%EOF',
        '0:/tmp/scan001.pdf':     '%PDF-1.4 1 0 obj<</Type/Catalog>>',
        '0:/ricoh/log/job.log':   '2024-01-15 09:23:01 PRINT jsmith 1 pages Q4-Report.pdf\n2024-01-15 09:45:12 SCAN CEO scan_personal.pdf\n',
        '0:/ricoh/conf/network.cfg': 'ip_address=192.168.1.50\ngateway=192.168.1.1\nsubnet=255.255.255.0\nsnmp_community=public\n',
    },

    snmp_mibs = {
        '1.3.6.1.2.1.1.1.0':          'Ricoh MP C3003; ROM: D088M4500; RAM: 512MB',
        '1.3.6.1.2.1.1.5.0':          'RICOH-MPC3003-B1',
        '1.3.6.1.2.1.1.6.0':          'Print Room — B1',
        '1.3.6.1.2.1.43.5.1.1.3.1':   '3',
        '1.3.6.1.2.1.43.5.1.1.1.1':   'Ricoh MP C3003',
        '1.3.6.1.2.1.43.10.2.1.4.1.1':'12438',  # pages printed (high usage)
        '1.3.6.1.4.1.367.3.2.1.2.19.5.1.5.1': 'admin',    # Ricoh admin user MIB
        '1.3.6.1.4.1.367.3.2.1.2.19.5.1.6.1': '',          # Ricoh admin password (blank!)
    },

    port_raw  = 9100,
    port_ipp  = 631,
    port_lpd  = 515,
    port_http = 80,
    port_snmp = 161,
    port_ftp  = 21,
)
