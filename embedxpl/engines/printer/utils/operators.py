#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PostScript Operators Database
===============================
This module contains a comprehensive list of PostScript operators organized by category.

Contains 400+ PostScript operators including:
- Standard operators (file, exec, run, etc.)
- Proprietary operators (Brother, HP, etc.)
- Security-relevant operators for testing
- 16 categories covering all PS functionality

PLANNED USAGE:
=======================
from utils.operators import operators

class ps(printer):
    def __init__(self, args):
        super().__init__(args)
        self.ops = operators()
        
    def do_enumerate_operators(self, arg):
        '''Test which PostScript operators are available'''
        for category, ops in self.ops.oplist.items():
            print(f"\\n{category}")
            for op in ops:
                result = self.test_operator(op)
                # Display result

SECURITY TESTING:
=================
This module enables testing for:
- File system access (file, deletefile, renamefile)
- Code execution (exec, run, cvx)
- Information disclosure (product, version, serialnumber)
- Authentication bypass (setpassword, getpassword)
- Device control (devformat, devmount, devdismount)

DO NOT REMOVE: Required for upcoming PostScript security testing module
"""

# Author    : Andre Henrique (@mrhenrike)
# GitHub    : https://github.com/mrhenrike
# LinkedIn  : https://linkedin.com/in/mrhenrike
# X/Twitter : https://x.com/mrhenrike

class operators():
    '''
    ┌─────────────────────────────────────┐
    │ PostScript operators and categories │
    └─────────────────────────────────────┘
    '''
    oplist = {
        '01. Operand Stack Manipulation Operators':
        [
            'pop',
            'exch',
            'dup',
            'copy',
            'index',
            'roll',
            'clear',
            'count',
            'mark',
            'cleartomark',
            'counttomark'
        ],
        '02. Arithmetic and Math Operators':
        [
            'add',
            'div',
            'idiv',
            'mod',
            'mul',
            'sub',
            'abs',
            'neg',
            'ceiling',
            'floor',
            'round',
            'truncate',
            'sqrt',
            'atan',
            'cos',
            'sin',
            'exp',
            'ln',
            'log',
            'rand',
            'srand',
            'rrand'
        ],
        '03. Array Operators':
        [
            'array',
            'length',
            'get',
            'put',
            'getinterval',
            'putinterval',
            'astore',
            'aload',
            'forall'
        ],
        '04. Packed Array Operators':
        [
            'packedarray',
            'setpacking',
            'currentpacking'
        ],
        '05. Dictionary Operators':
        [
            'dict ',
            'maxlength',
            'begin',
            'end',
            'def',
            'load',
            'store',
            'undef',
            'known',
            'where',
            'currentdict',
            'errordict',
            '$error',
            'systemdict',
            'userdict',
            'globaldict',
            'statusdict',
            'countdictstack',
            'dictstack',
            'cleardictstack'
        ],
        '06. String Operators':
        [
            'string',
            'anchorsearch',
            'search'
        ],
        '07. Relational, Boolean, and Bitwise Operators':
        [
            'eq',
            'ne',
            'ge',
            'gt',
            'le',
            'lt',
            'and',
            'or',
            'xor',
            'true',
            'false',
            'bitshift'
        ],
        '08. Control Operators':
        [
            'exec',
            'if',
            'ifelse',
            'for',
            'repeat',
            'loop',
            'exit',
            'stop',
            'stopped',
            'countexecstack',
            'execstack',
            'quit',
            'start'
        ],
        '09. Type, Attribute, and Conversion Operators':
        [
            'type',
            'cvlit',
            'cvx',
            'xcheck',
            'executeonly',
            'noaccess',
            'readonly',
            'rcheck',
            'wcheck',
            'cvi',
            'cvn',
            'cvr',
            'cvrs',
            'cvs'
        ],
        '10. File Operators':
        [
            'file',
            'filter',
            'closefile',
            'read',
            'write',
            'readhexstring',
            'writehexstring',
            'readstring',
            'writestring',
            'readline',
            'token',
            'bytesavailable',
            'flush',
            'flushfile',
            'resetfile',
            'status',
            'run',
            'currentfile',
            'deletefile',
            'renamefile',
            'filenameforall',
            'setfileposition',
            'fileposition',
            'print',
            '=',
            '==',
            'stack',
            'pstack',
            'printobject',
            'writeobject',
            'setobjectformat',
            'currentobjectformat'
        ],
        '11. Resource Operators':
        [
            'defineresource',
            'undefineresource',
            'findresource',
            'findcolorrendering',
            'resourcestatus',
            'resourceforall'
        ],
        '12. Virtual Memory Operators':
        [
            'save',
            'restore',
            'setglobal',
            'currentglobal',
            'gcheck',
            'startjob',
            'defineuserobject',
            'execuserobject',
            'undefineuserobject'
        ],
        '13. Miscellaneous Operators':
        [
            'bind',
            'null',
            'version',
            'realtime',
            'usertime',
            'languagelevel',
            'product',
            'revision',
            'serialnumber',
            'executive',
            'echo',
            'prompt'
        ],
        '14. Device Setup and Output Operators':
        [
            'showpage',
            'copypage',
            'setpagedevice',
            'currentpagedevice',
            'nulldevice'
        ],
        '15. Error Operators':
        [
            'handleerror',
            '.error'
        ],
        '16. Supplement and Proprietary Operators':
        [
            'BiteMe',
            'brCIDCode',
            'brfindfont',
            'brGetCurrentColor',
            'brgetjpnfont',
            '_BRFileExec',
            '_brGetXPSPage',
            '_brGetXPSThumb',
            '_brpdfscan',
            'brlanguagelevel',
            'brPchk',
            'brPDFThumbPrint',
            'brPSDKey',
            'BrRegiChart',
            'brTpForm',
            'brTpPjlCheck',
            'brTpStroke',
            'buildfunction',
            'buildtime',
            'byteorder',
            'cache_memory',
            'callut',
            'cexec',
            'changeucrgcr',
            'chdir',
            'checksum',
            'cidcompat',
            'clearinterrupt',
            'command',
            'composefont',
            'cwd',
            'defaultduplexmode',
            'defaultpapertray',
            'defaultresolution',
            'defaulttimeouts',
            'defaulttrayswitch',
            'defaulttumble',
            'devcontrol',
            'devdismount',
            'devforall',
            'devformat',
            'devmount',
            'devstatus',
            'directimage',
            'disableinterrupt',
            'discardtransparencygroup',
            'diskonline',
            'diskstatus',
            'displayoperatormsg',
            'doautoformfeed',
            'doexecutive',
            'doffsuppress',
            'doinitfile',
            'dopanellock',
            'dopowersave',
            'doprinterrors',
            'doreprint',
            'dostartpage',
            'dosysstart',
            'duplexer',
            'enableinterrupt',
            'endjob',
            'endtransparencygroup',
            'endtransparencymask',
            'enginesync',
            'execdepth',
            'execn',
            'execpoolimgtable',
            'execvecttoimagetable',
            'findcolorrendering',
            'firstside',
            'fontnonzerowinding',
            'fontprivatedict',
            'gadget',
            'getedlut',
            'getenginedebug',
            'getentitydir',
            'getfinelut',
            'getjobstms',
            'getmydata',
            'getpassword',
            'getsuperfinelut',
            'gettrue1200',
            'getufstring',
            'hardwareiomode',
            'idle',
            'idlefonts',
            'ignoresize',
            'imagemasksw',
            'imagetiff',
            'initializedisk',
            'initlut',
            'inittransparencymask',
            'interrupts_clear',
            'interrupts_enabled',
            'interrupts_no',
            'interrupts_reset',
            'interrupts_yes',
            'ipdsjog',
            'jobtimeout',
            'kccreatepic',
            'kcdeletepic',
            'kcloadpic',
            'kcmakebarcode',
            'kcrevivepic',
            'kcsavepic',
            'lzwavailable',
            'malloc_verify',
            'MD5Encode',
            'newsheet',
            'pagecount',
            'pagesprinted',
            'panel',
            'paperdirectional',
            'papertray',
            'patternsearch',
            'pdfnewsheet',
            'peek',
            'poke',
            'powersavetime',
            'pragmatics',
            'printconfiguration',
            'printername',
            'printer_reset',
            'printer_status',
            'processcolors',
            'processipdserror',
            'pwd',
            'ramsize',
            'rdbytes',
            'readinputbuffer',
            'readpbstring',
            'readtotalramsize',
            'remain_memory',
            'removeall',
            'removeglyphs',
            'resolveicc',
            'sccbatch',
            'sccinteractive',
            'setbrFilename',
            'setbrTpBM',
            'setbrTpca',
            'setcoverpage',
            'setdefaultduplexmode',
            'setdefaultpapertray',
            'setdefaultresolution',
            'setdefaulttimeouts',
            'setdefaulttrayswitch',
            'setdefaulttumble',
            'setdoautoformfeed',
            'setdoffsuppress',
            'setdopanellock',
            'setdopowersave',
            'setdoprinterrors',
            'setdoreprint',
            'setdostartpage',
            'setdosysstart',
            'setedlut',
            'setenginesync',
            'setfilenameextend',
            'setfillalpha',
            'setfinelut',
            'sethardwareiomode',
            'setignoresize',
            'setipdsmode',
            'setjobname',
            'setjobtimeout',
            'setmanualduplexmode',
            'setmediatype',
            'setpantonescreen',
            'setpapertray',
            'setpassword',
            'setprintername',
            'setropmode',
            'setsccbatch',
            'setsccinteractive',
            'setsmoothness',
            'setsoftalpha',
            'setsoftwareiomode',
            'setstrokealpha',
            'setsuperfinelut',
            'setuniversalsize',
            'setusbbinary',
            'setuserdiskpercent',
            'smooth4',
            'softwareiomode',
            'statementnumber',
            'stretch',
            'tonersave',
            'train_memory',
            'transparencyshowpage',
            'ucrgcrforimage',
            'ucrgcrtable600',
            'ucrgcrtablecapt',
            'unlimit',
            'usepantonescreen',
            'userdiskpercent',
            'verify'
        ]  # TBD: reduce to the `interesting' ones (from a security point of view)
    }
