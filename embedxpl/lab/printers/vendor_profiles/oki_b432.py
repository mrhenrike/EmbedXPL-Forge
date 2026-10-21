#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PrinterLab — OKI B432dn Profile
=================================
Simulates an OKI B-series laser printer.

BlackHat 2017 matrix: 8 vulnerabilities
  - PS infinite loop, offline mode, PJL physical damage
  - SNMP factory reset, PS factory restore
  - PJL memory access, file system access
  - Credential disclosure (MAC address as default password)

Default credentials:
  - Web: admin / (MAC address as password, e.g. last 6 hex: aaaaaa)
  - SNMP: public
  - Some OKI models: password = MAC6 (last 6 chars of MAC without colons)
"""
# Author    : Andre Henrique (@mrhenrike)
# GitHub    : https://github.com/mrhenrike
# LinkedIn  : https://linkedin.com/in/mrhenrike
# X/Twitter : https://x.com/mrhenrike

from simulators.base_printer import PrinterProfile

OKI_B432 = PrinterProfile(
    make         = 'OKI',
    model        = 'B432dn',
    firmware     = '01.11',
    serial       = 'OKB432AB123456',
    uuid         = 'urn:uuid:00000000-0000-0000-0000-okib432dn',
    location     = 'Warehouse — Ground Floor',
    contact      = 'ops@corp.local',

    languages    = ['PJL', 'PCL', 'PostScript', 'PCLXL'],
    doc_formats  = [
        'application/pdf',
        'application/postscript',
        'application/vnd.hp-PCL',
        'application/vnd.hp-PCLXL',
        'application/octet-stream',
    ],

    admin_user   = 'admin',
    admin_pass   = 'aaaaaa',     # OKI default: last 6 of MAC, or 'aaaaaa' for lab
    pjl_password = '',
    snmp_read    = 'public',
    snmp_write   = 'private',
    ftp_user     = 'admin',
    ftp_pass     = 'aaaaaa',

    vuln = {
        'pjl_traversal':       True,
        'pjl_password_leak':   True,
        'anon_ipp_jobs':       True,
        'ipp_purge_anon':      True,
        'lpd_unauthenticated': True,
        'lpd_bof_probe':       False,
        'default_creds':       True,   # admin/aaaaaa (MAC6)
        'snmp_public_write':   False,
        'snmp_factory_reset':  True,
        'ftp_open':            True,
        'web_traversal':       False,
        'web_default_creds':   True,
        'wsd_enabled':         True,
        'ssrf_capable':        True,
        'firmware_upload':     False,
        'nvram_rw':            True,
    },

    filesystem = {
        '0:/oki/config/net.cfg':    'ip=192.168.1.110\ngateway=192.168.1.1\npass=aaaaaa\n',
        '0:/oki/log/print.log':     '2024-02-01 08:00:00 PRINT warehouse inventory-Q1.pdf\n',
        '0:/etc/passwd':            'root::0:0::/:/bin/sh\n',
    },

    snmp_mibs = {
        '1.3.6.1.2.1.1.1.0':         'OKI B432dn; ROM: 01.11',
        '1.3.6.1.2.1.1.5.0':         'OKI-B432DN-WAREHOUSE',
        '1.3.6.1.2.1.1.6.0':         'Warehouse Ground Floor',
        '1.3.6.1.2.1.43.5.1.1.3.1':  '3',
        '1.3.6.1.2.1.43.5.1.1.1.1':  'OKI B432dn',
        '1.3.6.1.2.1.43.10.2.1.4.1.1': '8901',
        '1.3.6.1.4.1.2001.1.1.1.1.11.1.1.20': 'aaaaaa',  # OKI admin password in SNMP!
    },

    port_raw  = 9100,
    port_ipp  = 631,
    port_lpd  = 515,
    port_http = 80,
    port_snmp = 161,
    port_ftp  = 21,
)
