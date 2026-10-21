#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author    : Andre Henrique (@mrhenrike)
# LinkedIn  : https://linkedin.com/in/mrhenrike
# X/Twitter : https://x.com/mrhenrike
"""Printer profile registry for PrinterLab.

Printers mapped to BlackHat 2017 Vulnerability Matrix:
  HP      — 12 vulns (rows 1-7)
  Ricoh   — simulated as generic enterprise MFP
  Brother — 7 vulns  (rows 8-9)
  Lexmark — 10 vulns (rows 10-12)
  Dell    — 11 vulns (rows 14-15)
  Kyocera — 8 vulns  (row 16)
  Samsung — 1 vuln   (rows 17-18)
  Konica  — 7 vulns  (row 19)
  OKI     — 8 vulns  (row 20)
  Epson   — ESC/P lab printer (real device profile)
  Xerox   — enterprise MFP
"""

from printers.hp_laserjet     import HP_LASERJET_PRO
from printers.epson_l3250     import EPSON_L3250
from printers.ricoh_mp        import RICOH_MP_C3003
from printers.xerox_wc        import XEROX_WORKCENTER
from printers.kyocera_ecosys  import KYOCERA_ECOSYS
from printers.brother_mfc     import BROTHER_MFC
from printers.lexmark_cs      import LEXMARK_CS720
from printers.dell_b5460      import DELL_B5460
from printers.samsung_clp     import SAMSUNG_CLP775
from printers.konica_bizhub   import KONICA_BIZHUB_C368
from printers.oki_b432        import OKI_B432

ALL_PROFILES = {
    'hp':      HP_LASERJET_PRO,
    'epson':   EPSON_L3250,
    'ricoh':   RICOH_MP_C3003,
    'xerox':   XEROX_WORKCENTER,
    'kyocera': KYOCERA_ECOSYS,
    'brother': BROTHER_MFC,
    'lexmark': LEXMARK_CS720,
    'dell':    DELL_B5460,
    'samsung': SAMSUNG_CLP775,
    'konica':  KONICA_BIZHUB_C368,
    'oki':     OKI_B432,
}

__all__ = [
    'ALL_PROFILES',
    'HP_LASERJET_PRO', 'EPSON_L3250', 'RICOH_MP_C3003',
    'XEROX_WORKCENTER', 'KYOCERA_ECOSYS', 'BROTHER_MFC',
    'LEXMARK_CS720', 'DELL_B5460', 'SAMSUNG_CLP775',
    'KONICA_BIZHUB_C368', 'OKI_B432',
]
