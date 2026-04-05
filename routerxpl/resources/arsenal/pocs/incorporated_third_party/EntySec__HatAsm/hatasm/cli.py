"""
MIT License

Copyright (c) 2020-2024 EntySec

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import os
import stat
import argparse

from badges import Tables

from .__main__ import HatAsm
from .console import Console


class HatAsmCLI(HatAsm, Tables):
    """ Subclass of hatasm module.

    This subclass of hatasm module is intended for providing
    command-line interface for HatAsm.
    """

    description = (
        "HatAsm is a powerful assembler and disassembler"
        " that provides support for all common architectures."
    )

    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('--arch', dest='arch', help='Architecture to assemble or disassemble for.')
    parser.add_argument('--mode', dest='mode', help='Architecture mode (for example - arm/thumb).')
    parser.add_argument('--syntax', dest='syntax', help='Assembler/Disassembler syntax (for example - intel/att).')
    parser.add_argument('-i', '--input', dest='input', help='Input file for assembler or disassembler.')
    parser.add_argument('-o', '--output', dest='output', help='Output file to write output.')
    parser.add_argument('-a', '--assemble', action='store_true', dest='asm', help='Launch HatAsm assembler.')
    parser.add_argument('-d', '--disassemble', action='store_true', dest='disasm',
                        help='Launch HatAsm disassembler.')
    parser.add_argument('-e', '--emulate', action='store_true', dest='emulate',
                        help='Emulate assembled code in CLI.')
    parser.add_argument('-f', '--format', dest='format', help='Output file format (e.g. elf, macho, pe).')
    parser.add_argument('--formats', dest='formats', action='store_true', help='Display all available formats.')
    args = parser.parse_args()

    def start(self) -> None:
        """ Main command-line arguments handler.

        :return None: None
        """

        if self.args.formats:
            data = []

            for format in self.get_format():
                data.append((
                    format.info['Format'], format.info['Name'],
                    format.info['Platform']
                ))

            self.print_table('Output Formats', ('Format', 'Name', 'Platform'), *data)
            return

        if not self.args.syntax:
            self.args.syntax = 'intel'

        if not self.args.arch:
            self.parser.print_help()
            return

        if not self.args.asm and not self.args.disasm:
            self.parser.print_help()
            return

        if self.args.asm and self.args.arch:
            if self.args.arch not in self.ks_arch:
                self.print_error("HatAsm: assembler failed: unsupported architecture")
                return
        else:
            if self.args.arch not in self.cs_arch:
                self.print_error("HatAsm: disassembler failed: unsupported architecture")
                return

        if self.args.asm and self.args.input:
            result = self.assemble_from(self.args.arch, self.args.input,
                                        self.args.mode, self.args.syntax)
            if not result:
                return

            if self.args.output:
                if self.args.format:
                    result = self.pack_exe(result, self.args.arch,
                                           self.args.format)

                with open(self.args.output, 'wb') as f:
                    f.write(result)

                st = os.stat(self.args.output)
                if self.args.format:
                    os.chmod(self.args.output, st.st_mode | stat.S_IEXEC)

                return

            for line in self.hexdump(result):
                self.print_empty(line)

            return

        elif self.args.disasm and self.args.input:
            result = self.disassemble_from(self.args.arch, self.args.input,
                                           self.args.mode, self.args.syntax)

            if not result:
                return

            if self.args.output:
                with open(self.args.output, 'w') as f:
                    for opcode in result:
                        f.write(f"{opcode.mnemonic}\t{opcode.op_str}\n")
                return

            for line in result:
                self.print_empty("0x%x:\t%s\t%s" % (line.address, line.mnemonic,
                                                    line.op_str))

            return

        Console(self.args.arch, self.args.mode, self.args.syntax,
                asm=self.args.asm, emulate=self.args.emulate).shell()


def main() -> None:
    """ HatAsm command-line interface.

    :return None: None
    """

    try:
        cli = HatAsmCLI()
        cli.start()
    except Exception as e:
        # Avoid catching BaseException (KeyboardInterrupt/SystemExit/etc.)
        print(e)
