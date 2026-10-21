#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PrinterLab — Epson EcoTank L3250 Profile
=========================================
Simulates the lab's actual Epson L3250 printer (192.168.0.152).

Protocol stack:
  - IPP over HTTP/HTTPS (port 631)
  - WSD (port 3702 UDP, 5357 TCP)
  - ESC/P-R, PWG Raster (no PJL/PS/PCL)
  - HTTP web management (port 80)
  - No RAW/9100 or LPD/515
  - SNMP (port 161)

Vulnerabilities:
  - Anonymous IPP job submission accepted
  - IPP Purge-Jobs (DoS)
  - Default web credentials (admin / serial-number)
  - WSD enumeration
  - SNMP public community
"""
# Author    : Andre Henrique (@mrhenrike)
# GitHub    : https://github.com/mrhenrike
# LinkedIn  : https://linkedin.com/in/mrhenrike
# X/Twitter : https://x.com/mrhenrike

from simulators.base_printer import PrinterProfile

EPSON_L3250 = PrinterProfile(
    make         = 'Epson',
    model        = 'L3250 Series',
    firmware     = 'MA17I4-1221',
    serial       = 'EPSON3F9F9C',
    uuid         = 'urn:uuid:cfe92100-67c4-11d4-a4-epsonl3250',
    location     = 'Lab Room — 192.168.0.152',
    contact      = 'lab@safelabs.local',

    languages    = ['ESC/P-R', 'PWGRaster'],     # no PJL/PS/PCL
    doc_formats  = [
        'image/pwg-raster',
        'image/jpeg',
        'image/png',
        'application/octet-stream',
    ],

    admin_user   = 'admin',
    admin_pass   = 'EPSON3F9F9C',   # serial number as default password
    pjl_password = '',              # N/A — no PJL support
    snmp_read    = 'public',
    snmp_write   = 'private',
    ftp_user     = 'admin',
    ftp_pass     = '',

    vuln = {
        'pjl_traversal':       False,   # ESC/P only
        'pjl_password_leak':   False,
        'anon_ipp_jobs':       True,    # anonymous print accepted
        'ipp_purge_anon':      True,    # DoS via Purge-Jobs
        'lpd_unauthenticated': False,   # no LPD
        'lpd_bof_probe':       False,
        'default_creds':       True,    # serial = password
        'snmp_public_write':   False,
        'snmp_factory_reset':  False,
        'ftp_open':            False,   # no FTP
        'web_traversal':       False,
        'web_default_creds':   True,    # admin / serial-number
        'wsd_enabled':         True,    # WSD active
        'ssrf_capable':        True,    # IPP Print-URI SSRF possible
        'firmware_upload':     False,
        'nvram_rw':            False,
    },

    filesystem = {
        # No real filesystem access — only simulated web config
        '0:/config/network.xml': (
            '<network><ip>192.168.0.152</ip>'
            '<subnet>255.255.255.0</subnet>'
            '<gateway>192.168.0.1</gateway>'
            '<dns>8.8.8.8</dns></network>'
        ),
    },

    snmp_mibs = {
        '1.3.6.1.2.1.1.1.0':         'EPSON L3250 Series; ESC/P-R; Ink: CMYK',
        '1.3.6.1.2.1.1.3.0':         '9876543',
        '1.3.6.1.2.1.1.5.0':         'EPSON3F9F9C',
        '1.3.6.1.2.1.1.6.0':         'Lab Room',
        '1.3.6.1.2.1.43.5.1.1.1.1':  'EPSON L3250 Series',
        '1.3.6.1.2.1.43.10.2.1.4.1.1': '128',  # pages printed (ink saver mode)
    },

    port_raw  = 9100,   # not actually open — simulator binds anyway (rejected)
    port_ipp  = 631,
    port_lpd  = 515,    # not open on real device
    port_http = 80,
    port_snmp = 161,
    port_ftp  = 21,     # not open on real device
)
