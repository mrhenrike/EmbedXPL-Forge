#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PrinterLab — Konica Minolta bizhub C368 Profile
================================================
Simulates a Konica Minolta bizhub enterprise MFP.

BlackHat 2017 matrix: 7 vulnerabilities
  - PS infinite loop
  - PJL offline mode, physical damage (NVRAM)
  - SNMP/PML factory reset
  - PJL file system access, memory access
  - Credential disclosure via web (admin password in plain config)

Default credentials:
  - Web: Administrator / (blank) or admin / 12345678
  - SNMP: public
  - FTP: admin / 12345678 on some models
"""
# Author    : Andre Henrique (@mrhenrike)
# GitHub    : https://github.com/mrhenrike
# LinkedIn  : https://linkedin.com/in/mrhenrike
# X/Twitter : https://x.com/mrhenrike

from simulators.base_printer import PrinterProfile

KONICA_BIZHUB_C368 = PrinterProfile(
    make         = 'Konica Minolta',
    model        = 'bizhub C368',
    firmware     = 'A8AR50D0090G',
    serial       = 'A8AR0Y0040001',
    uuid         = 'urn:uuid:00000000-0000-0000-0000-konicabizhubc368',
    location     = 'Legal Department — 5th Floor',
    contact      = 'legal-it@corp.local',

    languages    = ['PJL', 'PCL', 'PostScript', 'PDF', 'XPS'],
    doc_formats  = [
        'application/pdf',
        'application/postscript',
        'application/vnd.hp-PCL',
        'application/vnd.ms-xpsdocument',
        'application/octet-stream',
    ],

    admin_user   = 'Administrator',
    admin_pass   = '',          # KM default: blank or 12345678
    pjl_password = '',
    snmp_read    = 'public',
    snmp_write   = 'private',
    ftp_user     = 'admin',
    ftp_pass     = '12345678',

    vuln = {
        'pjl_traversal':       True,
        'pjl_password_leak':   True,
        'anon_ipp_jobs':       True,
        'ipp_purge_anon':      True,
        'lpd_unauthenticated': True,
        'lpd_bof_probe':       True,   # BHat 2017: physical damage confirmed
        'default_creds':       True,
        'snmp_public_write':   False,
        'snmp_factory_reset':  True,
        'ftp_open':            True,
        'web_traversal':       False,
        'web_default_creds':   True,
        'wsd_enabled':         True,
        'ssrf_capable':        True,
        'firmware_upload':     True,
        'nvram_rw':            True,
    },

    filesystem = {
        '0:/etc/passwd':               'root::0:0::/:/bin/sh\nAdministrator::0:0::/:/bin/sh\n',
        '0:/km/config/network.cfg':    'ip=10.0.0.100\ngateway=10.0.0.1\nadmin_pass=\n',
        '0:/km/log/access.log':        '2024-01-25 14:30:00 SCAN CEO 15 pages LEGAL-CONTRACT.pdf\n',
        '0:/km/config/auth.cfg':       'Administrator=\nFTPPassword=12345678\n',
        '0:/tmp/scan001.pdf':          '%PDF-1.4 - Legal contract scan',
        '0:/tmp/scan002.pdf':          '%PDF-1.4 - HR termination document',
    },

    snmp_mibs = {
        '1.3.6.1.2.1.1.1.0':         'Konica Minolta bizhub C368; ROM: A8AR50D0090G',
        '1.3.6.1.2.1.1.5.0':         'KM-BIZHUB-C368-LEGAL',
        '1.3.6.1.2.1.1.6.0':         'Legal Department 5th Floor',
        '1.3.6.1.2.1.43.5.1.1.3.1':  '3',
        '1.3.6.1.2.1.43.5.1.1.1.1':  'Konica Minolta bizhub C368',
        '1.3.6.1.2.1.43.10.2.1.4.1.1': '234567',
        '1.3.6.1.4.1.18334.1.1.1.5.7.2.1.2.1.1': 'A8AR0Y0040001',  # KM serial MIB
    },

    port_raw  = 9100,
    port_ipp  = 631,
    port_lpd  = 515,
    port_http = 80,
    port_snmp = 161,
    port_ftp  = 21,
)
