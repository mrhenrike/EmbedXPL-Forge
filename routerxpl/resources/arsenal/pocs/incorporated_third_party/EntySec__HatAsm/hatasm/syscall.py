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

from hatasm.syscall_tables import SYSCALLS

from typing import Union


class Syscall(object):
    """ Subclass of pex.arch module.

    This subclass of pex.arch module is intended to provide an
    extensive toolkit for crafting and utilizing POSIX syscalls.
    """

    REGS = {
        'armle': ['r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r7'],
        'armbe': ['r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r7'],
        'aarch64': ['x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x8'],
        'x86': ['ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'eax'],
        'x64': ['rdi', 'rsi', 'rdx', 'r10', 'r8', 'r9', 'rax'],
        'mipsle': ['$a0', '$a1', '$a2', '$a3', '$a4', '$a5', '$v0'],
        'mipsbe': ['$a0', '$a1', '$a2', '$a3', '$a4', '$a5', '$v0']
    }

    def x86_register(self, arch: str, num: int, arg: int = 0) -> Union[str, None]:
        """ Decide which register to use to save integer for syscall.

        :param str arch: architecture
        :param int num: number
        :param int argument: argument position (-1 for NR)
        :return Union[str, None]: register or None if does not exist
        """

        regs = {
            'x86': {
                32: self.REGS['x86'],
                16: ["bx", "cx", "dx", "si", "di", "bp", "ax"],
                8: ["bl", "cl", "dl", None, None, None, "al"]
            },
            'x64': {
                64: self.REGS['x64'],
                32: ["edi", "esi", "edx", "r10d", "r8d", "r9d", "eax"],
                16: ["di", "si", "dx", "r10w", "r8w", "r9w", "ax"],
                8: ["dil", "sil", "dl", "r10b", "r8b", "r9b", "al"]
            }
        }

        if num < 0:
            raise ValueError("Number must be non-negative.")
        elif num <= 0xFF:
            size = 8
        elif num <= 0xFFFF:
            size = 16
        elif num <= 0xFFFFFFFF:
            size = 32
        elif num <= 0xFFFFFFFFFFFFFFFF:
            size = 64
        else:
            raise ValueError("Number is too large to fit in a register.")

        if arch not in regs:
            raise ValueError("Unsupported architecture.")

        aval_regs = regs[arch].get(size)
        if not aval_regs:
            raise ValueError(f"No registers available for {size}-bit numbers on {str(arch)}.")

        return aval_regs[arg]

    def x86_move(self, arch: str, num: int, arg: int = 0,
                 stack: bool = False, lowest: bool = False) -> str:
        """ Perform efficient move (register/stack).

        :param str arch: architecture
        :param int num: number
        :param int argument: argument position (-1 for NR)
        :param bool stack: use stack instead of standard mov
        :param bool lowest: use lowest register for number
        :return str: code
        """

        high_reg = self.REGS[arch][arg]

        """ If number is zero, then we perform XOR on highest register
        to override it with zeros.
        """

        if not num:
            return f"xor {high_reg}, {high_reg}\n"

        if lowest:
            low_reg = self.x86_register(arch, num, arg)
        else:
            low_reg = high_reg

        """ If no register is supported we use stack and highest
        register to move number to this register.
        """

        if not low_reg:
            low_reg = high_reg

        if not stack:
            return f"mov {low_reg}, {hex(num)}\n"

        """ If using stack select highest possible register because
        otherwise we'll stuck upon a CPU hardware feature is not implemented
        error.
        """

        code = f"push {hex(num)}\n"
        code += f"pop {high_reg}\n"

        return code

    def craft_syscall(self, arch: str, call: Union[str, int],
                      args: list = [], **kwargs) -> str:
        """ Craft syscall using syscall number.

        :param str arch: architecture to craft for
        :param Union[str, int] call: syscall number/name
        :param list args: arguments
        :raises RuntimeError: with trailing error message
        """

        if len(args) > 6:
            raise RuntimeError("Number of syscall arguments is bigger than 6!")

        if arch not in self.REGS:
            raise RuntimeError("Architecture provided is not supported!")

        code = ""
        regs = self.REGS[arch]
        syscalls = SYSCALLS[arch]

        if isinstance(call, str):
            call = syscalls[call]

        if arch in ['x64', 'x86']:
            for i in range(len(args)):
                code += self.x86_move(arch, int(args[i]), i, **kwargs)

            code += self.x86_move(arch, call, -1, **kwargs)

            if arch == 'x64':
                code += "syscall\n"
            else:
                code += "int 0x80\n"

        elif arch in ['armle', 'armbe', 'aarch64']:
            for i in range(len(args)):
                if not args[i]:
                    code += f"eor {regs[i]}, {regs[i]}, {regs[i]}\n"
                    continue

                code += f"mov {regs[i]}, {hex(args[i])}\n"

            code += f"mov {regs[-1]}, {hex(call)}\n"
            code += "svc 0\n"

        elif arch in ['mipsle', 'mipsbe']:
            for i in range(len(args)):
                if not args[i]:
                    code += f"xor {regs[i]}, {regs[i]}, {regs[i]}\n"
                    continue

                code += f"addiu {regs[i]}, $zero, {hex(args[i])}\n"

            code += f"addiu {regs[-1]}, $zero, {hex(call)}\n"
            code += "syscall 0x40404\n"

        return code
