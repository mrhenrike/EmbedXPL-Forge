#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PrinterLab — Kyocera ECOSYS P3055dn Profile
=============================================
Simulates a Kyocera ECOSYS laser printer.

Notable characteristics:
  - Default admin password: admin00
  - SNMP community: public / KYOCERA
  - Supports PJL, PCL, PostScript, KNX
  - KM-NET / KYOVPN management interface
"""
# Author    : Andre Henrique (@mrhenrike)
# GitHub    : https://github.com/mrhenrike
# LinkedIn  : https://linkedin.com/in/mrhenrike
# X/Twitter : https://x.com/mrhenrike

from simulators.base_printer import PrinterProfile

KYOCERA_ECOSYS = PrinterProfile(
    make         = 'Kyocera',
    model        = 'ECOSYS P3055dn',
    firmware     = '2NH_2200.006.527',
    serial       = 'VCM9301234',
    uuid         = 'urn:uuid:00000000-0000-0000-0000-kyocerap3055',
    location     = 'Accounting Dept — 2nd Floor',
    contact      = 'print@corp.local',

    languages    = ['PJL', 'PCL', 'PostScript', 'KNX'],
    doc_formats  = [
        'application/pdf',
        'application/postscript',
        'application/vnd.hp-PCL',
        'application/octet-stream',
    ],

    admin_user   = 'Admin',
    admin_pass   = 'admin00',   # Kyocera ECOSYS default
    pjl_password = '',
    snmp_read    = 'public',
    snmp_write   = 'KYOCERA',   # Kyocera-specific write community
    ftp_user     = 'anonymous',
    ftp_pass     = '',

    vuln = {
        'pjl_traversal':       True,
        'pjl_password_leak':   True,
        'anon_ipp_jobs':       True,
        'ipp_purge_anon':      True,
        'lpd_unauthenticated': True,
        'lpd_bof_probe':       True,
        'default_creds':       True,    # Admin/admin00
        'snmp_public_write':   False,
        'snmp_factory_reset':  True,
        'ftp_open':            True,    # anonymous FTP accepted
        'web_traversal':       False,
        'web_default_creds':   True,
        'wsd_enabled':         False,   # Kyocera uses KM-NET instead
        'ssrf_capable':        True,
        'firmware_upload':     True,
        'nvram_rw':            True,
    },

    filesystem = {
        '0:/etc/kyocera/network.conf':  'ip=192.168.1.100\ngw=192.168.1.1\nsnmp_community=public\n',
        '0:/etc/kyocera/user.conf':     'Admin:admin00:admin\nguest:guest:user\n',
        '0:/tmp/job001.pcl':            '\x1b%-12345X@PJL JOB NAME="Payroll Q4"\n\x1b(s1P',
        '0:/sys/kmnet.log':             '2024-01-20 08:00:00 KM-NET login Admin SUCCESS\n',
    },

    snmp_mibs = {
        '1.3.6.1.2.1.1.1.0':          'Kyocera ECOSYS P3055dn; ROM: 2NH_2200.006.527',
        '1.3.6.1.2.1.1.5.0':          'KYOCERA-P3055DN-ACCT',
        '1.3.6.1.2.1.1.6.0':          'Accounting Dept — 2nd Floor',
        '1.3.6.1.2.1.43.5.1.1.3.1':   '3',
        '1.3.6.1.2.1.43.5.1.1.1.1':   'Kyocera ECOSYS P3055dn',
        '1.3.6.1.2.1.43.10.2.1.4.1.1':'34782',
        '1.3.6.1.4.1.1347.43.5.1.1.1.1': '2NH_2200.006.527',  # firmware via Kyocera MIB
    },

    port_raw  = 9100,
    port_ipp  = 631,
    port_lpd  = 515,
    port_http = 80,
    port_snmp = 161,
    port_ftp  = 21,
)
