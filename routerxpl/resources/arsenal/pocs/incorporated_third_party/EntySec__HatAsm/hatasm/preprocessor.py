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

from hatasm.syscall import Syscall


class Preprocessor(object):
    """ Subclass of hatasm module.

    This subclass of hatasm module is intended to provide
    a preprocessor for custom HatAsm mnemonics.
    """

    def __init__(self, arch: str) -> None:
        """ Initialize preprocessor.

        :param str arch: arch to initialize preprocessor for
        :return None: None
        """

        self.arch = arch
        self.mnemonics = {
            "hsm.trap": self.hatasm_trap,
            "hsm.trap.s": self.hatasm_trap,
            "hsm.trap.l": self.hatasm_trap
        }

    def hatasm_trap(self, call: str, args: list) -> list:
        """ Processing function for hatasm.trap mnemonic.

        :param str call: full mnemonic name
        :param list args: list of arguments for the mnemonic
        :return str: processed assembly code
        """

        if len(args) == 0:
            raise ValueError("hatasm.trap requires at least one argument (syscall).")

        use_stack = call.endswith('.s')
        use_lowest = call.endswith('.l')

        return Syscall().craft_syscall(self.arch, args[0], args[1:],
                                       stack=use_stack, lowest=use_lowest)

    def preprocess(self, code: str) -> str:
        """ Preprocess code.

        :param str code: code to preprocess
        :return str: preprocessed code
        """

        lines = code.splitlines()
        code = []

        for line in lines:
            line = line.strip()

            if not line:
                continue

            parts = line.split(maxsplit=1)
            mnemonic = parts[0]
            args = []
            if len(parts) > 1:
                args = [arg.strip() for arg in parts[1].split(',')]

            if mnemonic in self.mnemonics:
                code.append(self.mnemonics[mnemonic](mnemonic, args))
            else:
                code.append(line)

        return '\n'.join(code)
