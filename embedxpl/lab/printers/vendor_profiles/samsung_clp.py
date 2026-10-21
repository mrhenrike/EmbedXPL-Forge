#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PrinterLab — Samsung CLP-775ND Profile
=========================================
Simulates a Samsung color laser printer (now HP-acquired).

BlackHat 2017 matrix: 1 vulnerability confirmed (limited PS support on many models).
  - PS infinite loop confirmed on color models

Default credentials:
  - HTTP: admin / sec00000 (or root / root on some)
  - SNMP: public
  - No FTP by default

Note: Many Samsung printers have limited PS support (direct raster/SPL).
      Web interface often exposed with known default password: sec00000
"""
# Author    : Andre Henrique (@mrhenrike)
# GitHub    : https://github.com/mrhenrike
# LinkedIn  : https://linkedin.com/in/mrhenrike
# X/Twitter : https://x.com/mrhenrike

from simulators.base_printer import PrinterProfile

SAMSUNG_CLP775 = PrinterProfile(
    make         = 'Samsung',
    model        = 'CLP-775ND',
    firmware     = 'V4.00.01.32',
    serial       = 'ZH8BBAJ101234',
    uuid         = 'urn:uuid:00000000-0000-0000-0000-samsungclp775',
    location     = 'Reception — 1st Floor',
    contact      = 'it@corp.local',

    languages    = ['SPL', 'PostScript', 'PCL'],  # SPL = Samsung Print Language
    doc_formats  = [
        'application/pdf',
        'application/postscript',
        'application/vnd.hp-PCL',
        'image/jpeg',
        'application/octet-stream',
    ],

    admin_user   = 'admin',
    admin_pass   = 'sec00000',   # Samsung default
    pjl_password = '',
    snmp_read    = 'public',
    snmp_write   = 'private',
    ftp_user     = '',           # no FTP on Samsung
    ftp_pass     = '',

    vuln = {
        'pjl_traversal':       False,  # Limited PJL support
        'pjl_password_leak':   False,
        'anon_ipp_jobs':       True,   # IPP typically unauthenticated
        'ipp_purge_anon':      True,
        'lpd_unauthenticated': True,
        'lpd_bof_probe':       False,
        'default_creds':       True,   # admin/sec00000
        'snmp_public_write':   False,
        'snmp_factory_reset':  False,
        'ftp_open':            False,  # No FTP on Samsung
        'web_traversal':       False,
        'web_default_creds':   True,
        'wsd_enabled':         True,
        'ssrf_capable':        True,   # IPP Print-URI
        'firmware_upload':     False,
        'nvram_rw':            False,
    },

    filesystem = {
        '0:/samsung/config/net.cfg': 'ip=192.168.1.90\ngateway=192.168.1.1\n',
        '0:/samsung/config/web.cfg': 'admin=admin\npassword=sec00000\n',
    },

    snmp_mibs = {
        '1.3.6.1.2.1.1.1.0':         'Samsung CLP-775ND; ROM: V4.00.01.32',
        '1.3.6.1.2.1.1.5.0':         'SAMSUNG-CLP775-RECEPTION',
        '1.3.6.1.2.1.1.6.0':         'Reception 1st Floor',
        '1.3.6.1.2.1.43.5.1.1.3.1':  '3',
        '1.3.6.1.2.1.43.5.1.1.1.1':  'Samsung CLP-775ND',
        '1.3.6.1.2.1.43.10.2.1.4.1.1': '12431',
        '1.3.6.1.4.1.236.11.5.11.81.1.0': 'ZH8BBAJ101234',  # Samsung serial MIB
    },

    port_raw  = 9100,
    port_ipp  = 631,
    port_lpd  = 515,
    port_http = 80,
    port_snmp = 161,
    port_ftp  = 21,
)
