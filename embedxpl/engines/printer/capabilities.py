#!/usr/bin/env python3
# -*- coding: utf-8 -*-


# Author    : Andre Henrique (@mrhenrike)
# GitHub    : https://github.com/mrhenrike
# LinkedIn  : https://linkedin.com/in/mrhenrike
# X/Twitter : https://x.com/mrhenrike

# python standard library
import re
import os
import sys  # , urllib.error, urllib.parse

import requests
import urllib3

# local pret classes
from utils.helper import output, item

# ── SNMP backend selection ───────────────────────────────────────────────────
# Priority: pysnmp-lextudio v5+ hlapi (sync) → pysnmp v4 oneliner (legacy)
# pysnmp v7 (community fork) ships an asyncio-only API; we detect and use
# the synchronous shim when available.
_SNMP_BACKEND = None

import warnings as _pysnmp_warn
_pysnmp_warn.filterwarnings("ignore", category=RuntimeWarning)

try:
    # pysnmp-lextudio ≥5 (hlapi synchronous, Python 3.8+) — primary backend
    from pysnmp.hlapi import (  # type: ignore
        getCmd, nextCmd, CommunityData, UdpTransportTarget,
        ContextData, ObjectType, ObjectIdentity, SnmpEngine,
    )
    _SNMP_BACKEND = 'hlapi-v5'
except ImportError:
    pass

if _SNMP_BACKEND is None:
    try:
        # pysnmp ≥7 community version exposes hlapi.asyncio; provide a sync shim
        from pysnmp.hlapi.asyncio import (  # type: ignore
            getCmd as _asyncGetCmd, CommunityData, UdpTransportTarget,
            ContextData, ObjectType, ObjectIdentity, SnmpEngine,
        )
        import asyncio as _asyncio

        def getCmd(*args, **kwargs):  # type: ignore[override]
            """Synchronous shim wrapping the asyncio getCmd."""
            return _asyncio.get_event_loop().run_until_complete(
                _asyncGetCmd(*args, **kwargs)
            )

        _SNMP_BACKEND = 'hlapi-v7'
    except ImportError:
        pass

if _SNMP_BACKEND is None:
    try:
        # pysnmp ≤4.x oneliner (legacy, deprecated in 3.12+)
        from pysnmp.entity.rfc3413.oneliner import cmdgen  # type: ignore
        _SNMP_BACKEND = 'oneliner'
    except ImportError:
        pass


class capabilities():
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    # set defaults
    support = False
    # default timeout - can be overridden in __init__
    timeout = 1.5
    # set pret.py directory
    rundir = os.path.dirname(os.path.realpath(__file__)) + os.path.sep
    '''
  ┌──────────────────────────────────────────────────────────┐
  │            how to get printer's capabilities?            │
  ├──────┬───────────────────────┬───────────────────────────┤
  │      │ model (for db lookup) │ lang (ps/pjl/pcl support) │
  ├──────┼───────────────────────┼───────────────────────────┤
  │ IPP  │ printer-description   │ printer-description       │
  │ SNMP │ hrDeviceDescr         │ prtInterpreterDescription │
  │ HTTP │ html-title            │ -                         │
  | HTTPS| html-title            | -                         |
  └──────┴───────────────────────┴───────────────────────────┘
  '''

    def __init__(self, args, timeout=None):
        # allow custom timeout to be passed
        if timeout is not None:
            self.timeout = timeout
        # skip this in unsafe mode
        if not args.safe:
            return
        # set printer language
        if args.mode == 'ps':
            lang = ["PS", "PostScript", "BR-Script", "KPDL"]
        if args.mode == 'pjl':
            lang = ["PJL"]
        if args.mode == 'pcl':
            lang = ["PCL"]
        # get list of PostScript/PJL/PCL capable printers
        self.models = self.get_models(args.mode + ".dat")
        # try to get printer capabilities via IPP/SNMP/HTTP
        if not self.support:
            self.ipp(args.target, lang)
        if not self.support:
            self.http(args.target)
        if not self.support:
            self.https(args.target)
        if not self.support:
            self.snmp(args.target, lang)
        # feedback on PostScript/PJL/PCL support
        self.feedback(self.support, lang[0])
        # in safe mode, exit if unsupported
        if args.safe and not self.support:
            print((os.linesep + "Quitting as we are in safe mode."))
            sys.exit()
        print("")

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    # get capabilities via IPP (HTTP or HTTPS fallback)
    def ipp(self, host, lang):
        try:
            sys.stdout.write("Checking for IPP support:         ")
            # IPP 1.1 GET-PRINTER-ATTRIBUTES request (binary)
            body = (
                b'\x01\x01\x00\x0b\x00\x01\xab\x10'
                b'\x01G\x00\x12attributes-charset\x00\x05utf-8'
                b'H\x00\x1battributes-natural-language\x00\x02en'
                b'E\x00\x0bprinter-uri\x00\x14ipp://localhost/ipp/'
                b'D\x00\x14requested-attributes\x00\x13printer-description\x03'
            )
            headers = {'Content-type': 'application/ipp'}
            response_bytes = None

            # IPP endpoints to probe (in priority order)
            ipp_candidates = [
                ('http',  host, 631, '/'),
                ('http',  host, 631, '/ipp/'),
                ('http',  host, 631, '/ipp/print'),
                ('https', host, 631, '/ipp/print'),
                ('https', host, 631, '/ipp/'),
                ('https', host, 631, '/'),
            ]
            for scheme, h, port, path in ipp_candidates:
                try:
                    url = f"{scheme}://{h}:{port}{path}"
                    r = requests.post(url, data=body, headers=headers,
                                      timeout=self.timeout * 2,
                                      verify=False)
                    # 200 = success; 426 means TLS required → continue loop
                    if r.status_code == 200 and len(r.content) > 8:
                        response_bytes = r.content
                        break
                except Exception:
                    continue

            if response_bytes is None:
                raise Exception("no IPP endpoint responded")

            # Decode as latin-1 so binary bytes are preserved 1:1
            response = response_bytes.decode('latin-1')

            # Extract printer-device-id field (contains MDL: and CMD:)
            # It appears as a length-prefixed string in IPP binary
            model = item(re.findall(r"MDL:(.+?);", response))
            langs = item(re.findall(r"CMD:(.+?);", response))

            # Also scan document-format-supported for ESC/P, PWGRaster etc.
            doc_fmts = re.findall(r"(application/vnd\.epson\.[^;\x00]+|"
                                  r"application/postscript|"
                                  r"application/pcl|"
                                  r"image/pwg-raster)", response, re.I)
            if doc_fmts:
                self.doc_formats = doc_fmts
                output().chitchat(f"  IPP document formats: {', '.join(doc_fmts)}")

            # Try to set language support from CMD: field
            self.support = [x for x in [re.findall(
                re.escape(pdl), langs, re.I) for pdl in lang] if x]
            self.set_support(model)
            output().green("found")
        except Exception as e:
            output().errmsg("not found", e)

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    # get capabilities via HTTP
    def http(self, host):
        try:
            sys.stdout.write("Checking for HTTP support:        ")
            # allow_redirects=False so an HTTP→HTTPS redirect doesn't cause SSL errors
            html = requests.get(
                "http://" + host, verify=False,
                allow_redirects=False, timeout=self.timeout,
            ).text
            title = re.findall("<title.*?>\n?(.+?)\n?</title>",
                               html, re.I | re.M | re.S)
            model = item(title)
            self.set_support(model)
            output().green("found")
        except Exception as e:
            output().errmsg("not found", e)

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    # get capabilities via HTTPS
    def https(self, host):
        try:
            # poor man's way get https title
            sys.stdout.write("Checking for HTTPS support:       ")
            html = requests.get("https://" + host, verify=False).text
            # cause we are to parsimonious to import BeautifulSoup ;)
            title = re.findall("<title.*?>\n?(.+?)\n?</title>",
                               html, re.I | re.M | re.S)
            # get name of device
            model = item(title)
            # get language support
            self.set_support(model)
            output().green("found")
        except Exception as e:
            output().errmsg("not found", e)

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    # get capabilities via SNMP
    def snmp(self, host, lang):
        try:
            sys.stdout.write("Checking for SNMP support:        ")
            if _SNMP_BACKEND is None:
                raise NameError("pysnmp not installed")

            # HOST-RESOURCES-MIB → hrDeviceDescr
            desc_oid = '1.3.6.1.2.1.25.3.2.1.3'
            # Printer-MIB → prtInterpreterDescription
            pdls_oid = '1.3.6.1.2.1.43.15.1.1.5.1'
            desc, pdls = [], []

            if _SNMP_BACKEND in ('hlapi-v5', 'hlapi-v7'):
                # pysnmp-lextudio v5 synchronous hlapi (also v7 via shim)
                engine    = SnmpEngine()
                community = CommunityData('public', mpModel=0)
                transport = UdpTransportTarget(
                    (host, 161), timeout=self.timeout, retries=0)
                context   = ContextData()

                for oid_str, bucket in [(desc_oid, desc), (pdls_oid, pdls)]:
                    for err_ind, err_stat, _, var_binds in nextCmd(
                        engine, community, transport, context,
                        ObjectType(ObjectIdentity(oid_str)),
                        lexicographicMode=False,
                    ):
                        if err_ind:
                            break
                        if err_stat:
                            break
                        for var_bind in var_binds:
                            bucket.append(str(var_bind[1]))

            elif _SNMP_BACKEND == 'oneliner':
                # Legacy oneliner API (pysnmp ≤ 4.x, Python 3.8–3.11)
                error, error_status, _idx, binds = cmdgen.CommandGenerator().nextCmd(  # type: ignore
                    cmdgen.CommunityData('public', mpModel=0),
                    cmdgen.UdpTransportTarget((host, 161), timeout=self.timeout, retries=0),
                    desc_oid, pdls_oid,
                )
                if error:
                    raise Exception(error)
                if error_status:
                    raise Exception(error_status.prettyPrint())
                for row in binds:
                    for key, val in row:
                        if desc_oid in str(key):
                            desc.append(str(val))
                        if pdls_oid in str(key):
                            pdls.append(str(val))

            # get name of device
            model = item(desc)
            # get language support
            langs = ','.join(pdls)
            self.support = [x for x in [re.findall(
                re.escape(pdl), langs, re.I) for pdl in lang] if x]
            output().green("found")
        except NameError:
            output().errmsg("not found", "pysnmp module not installed")
        except Exception as e:
            output().errmsg("not found", e)
    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    # feedback on language support

    def feedback(self, support, lang):
        sys.stdout.write("Checking for %-21s" % (lang + " support: "))
        if support:
            output().green("found")
        else:
            output().warning("not found")

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    # set language support
    def set_support(self, model):
        # model_stripped = re.sub(r'(\d|\s|-)[a-zA-Z]+$', '', model)
        '''
        ┌───────────────────────────────────────────────────────┐
        │ Experimental -- This might introduce false positives! │
        ├───────────────────────────────────────────────────────┤
        │ The stripped down version of the model string removes │
        │ endings like '-series', ' printer' (maybe localized), │
        │ 'd' (duplex), 't' (tray), 'c' (color), 'n' (network). │
        └───────────────────────────────────────────────────────┘
        '''
        self.support = [x for x in [re.findall(
            re.escape(m), model, re.I) for m in self.models] if x]

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    # open database of supported devices
    def get_models(self, file):
        try:
            with open(self.rundir + "db" + os.path.sep + file, 'r') as f:
                models = [line.strip() for line in f if line.strip()]
            return models
        except IOError as e:
            output().errmsg("Cannot open file", e)
            return []
