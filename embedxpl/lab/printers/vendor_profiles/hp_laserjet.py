#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PrinterLab — HP LaserJet Pro M404n Profile
============================================
Simulates an HP LaserJet Pro with JetDirect firmware.

Known vulnerabilities reproduced:
  - CVE-2010-4107 / EDB-15631 : PJL directory traversal (FSDIRLIST/FSUPLOAD)
  - CVE-2011-4786 : PJL password disclosure via INFO VARIABLES
  - CVE-2021-39237 : HP FutureSmart — information disclosure
  - EDB-45273     : HP PJL RCE via SNMP restart trigger
"""
# Author    : Andre Henrique (@mrhenrike)
# GitHub    : https://github.com/mrhenrike
# LinkedIn  : https://linkedin.com/in/mrhenrike
# X/Twitter : https://x.com/mrhenrike

from simulators.base_printer import PrinterProfile

HP_LASERJET_PRO = PrinterProfile(
    make         = 'HP',
    model        = 'LaserJet Pro M404n',
    firmware     = 'FutureSmart 4.11.2.1',
    serial       = 'VNB3K17493',
    uuid         = 'urn:uuid:1-2-3-4-hp-laserjet-m404n',
    location     = 'Office Floor 3',
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
    admin_pass   = '',          # blank — default credential
    pjl_password = '',          # no PJL password set
    snmp_read    = 'public',
    snmp_write   = 'private',
    ftp_user     = 'admin',
    ftp_pass     = '',

    vuln = {
        'pjl_traversal':       True,    # EDB-15631
        'pjl_password_leak':   True,    # INFO VARIABLES reveals PJL password
        'anon_ipp_jobs':       True,    # anonymous print allowed
        'ipp_purge_anon':      True,    # Purge-Jobs without auth
        'lpd_unauthenticated': True,
        'lpd_bof_probe':       False,   # HP LP not susceptible
        'default_creds':       True,
        'snmp_public_write':   False,
        'snmp_factory_reset':  True,    # EDB-45273 style
        'ftp_open':            True,
        'web_traversal':       True,
        'web_default_creds':   True,
        'wsd_enabled':         True,
        'ssrf_capable':        True,
        'firmware_upload':     True,    # CVE-2021-39237 style
        'nvram_rw':            True,
    },

    filesystem = {
        '0:/webServer/default.xml':        '<config><admin_pass></admin_pass><pjl_pass></pjl_pass></config>',
        '0:/webServer/cs/log/access.log':  '192.168.1.100 - admin [01/Jan/2024:09:00:00] GET /admin 200',
        '0:/etc/passwd':                   'root::0:0::/:/bin/dlsh\noperator::2:2::/:/bin/false\n',
        '0:/.profile':                     '# HP JetDirect .profile v4.11\nexport PATH=/hp/bin:$PATH\n',
        '0:/tmp/printjobs/job001.prn':     '%!PS\n%%Title: Q4 Financial Report\n(Confidential) show\nshowpage\n%%EOF',
        '0:/tmp/printjobs/job002.prn':     '%!PS\n%%Title: Board Meeting Minutes\nshowpage\n%%EOF',
        '0:/hpmnt/etc/passwd':             'root::0:0::/:/bin/dlsh\n',
        '0:/hpmnt/etc/shadow':             'root:$1$hp$abc123:18000:0:99999:7:::\n',
        '0:/hp/conf/nic.conf':             'ip=192.168.0.10\ngateway=192.168.0.1\nsubnet=255.255.255.0\n',
    },

    snmp_mibs = {
        '1.3.6.1.2.1.1.1.0':              'HP LaserJet Pro M404n; ROM: FutureSmart 4.11.2.1; RAM: 256MB',
        '1.3.6.1.2.1.1.3.0':              '1234567',
        '1.3.6.1.2.1.1.4.0':              'it@corp.local',
        '1.3.6.1.2.1.1.5.0':              'HP-LASERJET-FLOOR3',
        '1.3.6.1.2.1.1.6.0':              'Office Floor 3',
        '1.3.6.1.2.1.43.5.1.1.3.1':      '3',    # prtGeneralReset: notResetting
        '1.3.6.1.2.1.43.5.1.1.1.1':      'HP LaserJet Pro M404n',
        '1.3.6.1.2.1.43.10.2.1.4.1.1':   '450',  # pages printed
        '1.3.6.1.4.1.11.2.3.9.4.2.1.1.3.2': 'VNB3K17493',  # serial via HP MIB
    },

    port_raw  = 9100,
    port_ipp  = 631,
    port_lpd  = 515,
    port_http = 80,
    port_snmp = 161,
    port_ftp  = 21,
)
