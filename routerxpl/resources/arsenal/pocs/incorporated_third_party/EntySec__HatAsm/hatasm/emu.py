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

from unicorn import *
from unicorn.x86_const import *
from unicorn.arm_const import *
from unicorn.mips_const import *

from badges import Badges

CODE_SIZE = 0x20000000
STACK_ADDRESS = 0x10000000
STACK_POINTER = 0x13000000


class Emu(Badges):
    """ Subclass of hatasm module.

    This subclass of hatasm module is intended to provide
    an emulation interface.
    """

    uc_arch = {
        'x86': (UC_ARCH_X86, UC_MODE_32),
        'x64': (UC_ARCH_X86, UC_MODE_64),

        'ppc': (UC_ARCH_PPC, UC_MODE_32 + UC_MODE_BIG_ENDIAN),
        'ppc64': (UC_ARCH_PPC, UC_MODE_64),

        'aarch64': (UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN),
        'armle': (UC_ARCH_ARM, UC_MODE_ARM + UC_MODE_LITTLE_ENDIAN),
        'armbe': (UC_ARCH_ARM, UC_MODE_ARM + UC_MODE_BIG_ENDIAN),

        'sparc': (UC_ARCH_SPARC, UC_MODE_BIG_ENDIAN),
        'sparc64': (UC_ARCH_SPARC, UC_MODE_BIG_ENDIAN),

        'mips64le': (UC_ARCH_MIPS, UC_MODE_MIPS64 + UC_MODE_LITTLE_ENDIAN),
        'mips64be': (UC_ARCH_MIPS, UC_MODE_MIPS64 + UC_MODE_BIG_ENDIAN),
        'mipsle': (UC_ARCH_MIPS, UC_MODE_MIPS32 + UC_MODE_LITTLE_ENDIAN),
        'mipsbe': (UC_ARCH_MIPS, UC_MODE_MIPS32 + UC_MODE_BIG_ENDIAN)
    }

    def __init__(self, arch: str, size: int = CODE_SIZE,
                 stack: int = STACK_ADDRESS, sp: int = STACK_POINTER) -> None:
        """ Initialize emulator.

        :param str arch: architecture
        :param int size: memory size
        :param int stack: stack address
        :return None: None
        """

        if arch not in self.uc_arch:
            raise RuntimeError(f"Wrong architecture: {arch}!")

        self.arch = arch
        self.sp = sp

        self.vm = Uc(*self.uc_arch[arch])
        self.vm.mem_map(0, size)

        if arch == 'x64':
            self.vm.reg_write(UC_X86_REG_RSP, sp)
            self.vm.reg_write(UC_X86_REG_RBP, stack)

        elif arch == 'x86':
            self.vm.reg_write(UC_X86_REG_ESP, sp)
            self.vm.reg_write(UC_X86_REG_EBP, stack)

        elif arch in ['armle', 'armbe']:
            self.vm.reg_write(UC_ARM_REG_R13, sp)
            self.vm.reg_write(UC_ARM_REG_R11, stack)

        elif arch in ['mipsle', 'mipsbe']:
            self.vm.reg_write(UC_MIPS_REG_SP, sp)
            self.vm.reg_write(UC_MIPS_REG_FP, stack)

    def emulate(self, code: bytes) -> None:
        """ Emulate code.

        :param bytes code: code
        :return None: None
        """

        if self.arch == 'x64':
            return self.x64_emulate(code)

        elif self.arch == 'x86':
            return self.x86_emulate(code)

        elif self.arch in ['armle', 'armbe']:
            return self.arm_emulate(code)

        elif self.arch in ['mipsle', 'mipsbe']:
            return self.mips_emulate(code)

        raise RuntimeError("Unsupported architecture!")

    def print_stack(self, stack: int, sp: int, byte_size: int = 8, rows: int = 5) -> None:
        """ Print stack.

        :param int stack: stack start
        :param int sp: stack pointer
        :return None: None
        """

        self.print_empty("----------------- stack context -----------------")

        read_start_addr = stack - byte_size * 8
        read_offset = byte_size * 4 * rows
        stack_data = self.vm.mem_read(read_start_addr, read_offset)
        sp_val = sp

        for i in range(0, len(stack_data), byte_size):
            if i % (byte_size * 4) == 0:
                if i != 0:
                    self.print_empty(start='')

                self.print_empty(f"0x{read_start_addr + i:0{byte_size * 2}x} : ", start="", end="")

            reversed_bytes = stack_data[i:i + byte_size][::-1]
            current_addr = read_start_addr + i

            if sp_val == current_addr:
                self.print_empty(f"%red{int.from_bytes(reversed_bytes, 'big'):0{byte_size * 2}x}%end", start="", end=" ")
            else:
                self.print_empty(f"{int.from_bytes(reversed_bytes, 'big'):0{byte_size * 2}x}", start="", end=" ")

        self.print_empty('%newline', start='')

    def mips_emulate(self, code: bytes) -> None:
        """ Emulate MIPS code.

        :param bytes code: code
        :return None: None
        """

        self.vm.mem_write(0, code)

        initial_registers = {}
        registers = [
            ("zero", UC_MIPS_REG_ZERO), ("at", UC_MIPS_REG_AT), ("v0", UC_MIPS_REG_V0), ("v1", UC_MIPS_REG_V1),
            ("a0", UC_MIPS_REG_A0), ("a1", UC_MIPS_REG_A1), ("a2", UC_MIPS_REG_A2), ("a3", UC_MIPS_REG_A3),
            ("t0", UC_MIPS_REG_T0), ("t1", UC_MIPS_REG_T1), ("t2", UC_MIPS_REG_T2), ("t3", UC_MIPS_REG_T3),
            ("t4", UC_MIPS_REG_T4), ("t5", UC_MIPS_REG_T5), ("t6", UC_MIPS_REG_T6), ("t7", UC_MIPS_REG_T7),
            ("s0", UC_MIPS_REG_S0), ("s1", UC_MIPS_REG_S1), ("s2", UC_MIPS_REG_S2), ("s3", UC_MIPS_REG_S3),
            ("s4", UC_MIPS_REG_S4), ("s5", UC_MIPS_REG_S5), ("s6", UC_MIPS_REG_S6), ("s7", UC_MIPS_REG_S7),
            ("t8", UC_MIPS_REG_T8), ("t9", UC_MIPS_REG_T9), ("k0", UC_MIPS_REG_K0), ("k1", UC_MIPS_REG_K1),
            ("gp", UC_MIPS_REG_GP), ("sp", UC_MIPS_REG_SP), ("fp", UC_MIPS_REG_FP), ("ra", UC_MIPS_REG_RA),
        ]

        for name, reg in registers:
            initial_registers[name] = self.vm.reg_read(reg)

        try:
            self.vm.emu_start(0, len(code))
        except Exception as e:
            self.print_error(f"An error occurred during emulation: {str(e)}!")
            return

        self.print_empty("------ cpu context ------")

        def colorize_register_submethod(name, reg):
            if self.vm.reg_read(reg) != initial_registers[name]:
                return f"%yellow{name:<3}%end : %red0x{self.vm.reg_read(reg):08x}%end"
            return f"%yellow{name:<3}%end : 0x{self.vm.reg_read(reg):08x}"

        self.print_empty(" ".join(colorize_register_submethod(name, reg) for name, reg in registers[0:4]))
        self.print_empty(" ".join(colorize_register_submethod(name, reg) for name, reg in registers[4:8]))
        self.print_empty(" ".join(colorize_register_submethod(name, reg) for name, reg in registers[8:12]))
        self.print_empty(" ".join(colorize_register_submethod(name, reg) for name, reg in registers[12:16]))
        self.print_empty(" ".join(colorize_register_submethod(name, reg) for name, reg in registers[16:20]))
        self.print_empty(" ".join(colorize_register_submethod(name, reg) for name, reg in registers[20:24]))
        self.print_empty(" ".join(colorize_register_submethod(name, reg) for name, reg in registers[24:28]))
        self.print_empty(" ".join(colorize_register_submethod(name, reg) for name, reg in registers[28:]))

        self.print_stack(self.sp, self.vm.reg_read(UC_MIPS_REG_SP), byte_size=4)

    def arm_emulate(self, code: bytes) -> None:
        """ Emulate ARM(le/be) code.

        :param bytes code: code
        :return None: None
        """

        self.vm.mem_write(0, code)

        initial_registers = {}
        registers = [
            ("r0", UC_ARM_REG_R0), ("r1", UC_ARM_REG_R1), ("r2", UC_ARM_REG_R2), ("r3", UC_ARM_REG_R3),
            ("r4", UC_ARM_REG_R4), ("r5", UC_ARM_REG_R5), ("r6", UC_ARM_REG_R6), ("r7", UC_ARM_REG_R7),
            ("r8", UC_ARM_REG_R8), ("r9", UC_ARM_REG_R9), ("r10", UC_ARM_REG_R10),
            ("r11", UC_ARM_REG_R11), ("r12", UC_ARM_REG_R12), ("r13", UC_ARM_REG_R13), ("r14", UC_ARM_REG_R14),
            ("r15", UC_ARM_REG_R15),
        ]

        for name, reg in registers:
            initial_registers[name] = self.vm.reg_read(reg)

        try:
            self.vm.emu_start(0, len(code))
        except Exception as e:
            self.print_error(f"An error occured during emulation: {str(e)}!")
            return

        self.print_empty("------ cpu context ------")

        def colorize_register_submethod(name, reg):
            if self.vm.reg_read(reg) != initial_registers[name]:
                return f"%yellow{name:<3}%end : %red0x{self.vm.reg_read(reg):08x}%end"

            return f"%yellow{name:<3}%end : 0x{self.vm.reg_read(reg):08x}"

        self.print_empty(" ".join(colorize_register_submethod(name, reg) for name, reg in registers[0:4]))
        self.print_empty(" ".join(colorize_register_submethod(name, reg) for name, reg in registers[4:8]))
        self.print_empty(" ".join(colorize_register_submethod(name, reg) for name, reg in registers[8:11]))
        self.print_empty(" ".join(colorize_register_submethod(name, reg) for name, reg in registers[11:15]))
        self.print_empty(" ".join(colorize_register_submethod(name, reg) for name, reg in registers[15:]))

        flags = self.vm.reg_read(UC_ARM_REG_CPSR)
        flag_values = {
            "n": (flags >> 31) & 1,
            "z": (flags >> 30) & 1,
            "c": (flags >> 29) & 1,
            "v": (flags >> 28) & 1,
            "q": (flags >> 27) & 1,
        }

        self.print_empty("%yellowflags%end : 0x{:08x} (n:{} z:{} c:{} v:{} q:{})".format(
            flags,
            flag_values["n"], flag_values["z"], flag_values["c"],
            flag_values["v"], flag_values["q"]
        ))

        self.print_stack(self.sp, self.vm.reg_read(UC_ARM_REG_R13), byte_size=4)

    def x86_emulate(self, code: bytes) -> None:
        """ Emulate x86 code.

        :param bytes code: code
        :return None: None
        """

        self.vm.mem_write(0, code)
        self.vm.reg_write(UC_X86_REG_EIP, 0)

        initial_registers = {}
        registers = [
            ("eax", UC_X86_REG_RAX), ("ebx", UC_X86_REG_RBX), ("ecx", UC_X86_REG_RCX), ("edx", UC_X86_REG_RDX),
            ("esi", UC_X86_REG_RSI), ("edi", UC_X86_REG_RDI),
            ("eip", UC_X86_REG_RIP), ("ebp", UC_X86_REG_RBP), ("esp", UC_X86_REG_RSP),
            ("cs", UC_X86_REG_CS), ("ss", UC_X86_REG_SS), ("ds", UC_X86_REG_DS), ("es", UC_X86_REG_ES),
            ("fs", UC_X86_REG_FS), ("gs", UC_X86_REG_GS),
        ]

        for name, reg in registers:
            initial_registers[name] = self.vm.reg_read(reg)

        try:
            self.vm.emu_start(0, len(code))
        except Exception as e:
            self.print_error(f"An error occured during emulation: {str(e)}!")
            return

        self.print_empty("------ cpu context ------")

        def colorize_register_submethod(name, reg):
            if self.vm.reg_read(reg) != initial_registers[name]:
                return f"%yellow{name:<3}%end : %red0x{self.vm.reg_read(reg):08x}%end"

            return f"%yellow{name:<3}%end : 0x{self.vm.reg_read(reg):08x}"

        self.print_empty(" ".join(colorize_register_submethod(name, reg) for name, reg in registers[0:4]))
        self.print_empty(" ".join(colorize_register_submethod(name, reg) for name, reg in registers[4:6]))
        self.print_empty(" ".join(colorize_register_submethod(name, reg) for name, reg in registers[6:9]))
        self.print_empty(" ".join(colorize_register_submethod(name, reg) for name, reg in registers[9:14]))
        self.print_empty(" ".join(colorize_register_submethod(name, reg) for name, reg in registers[14:]))

        flags = self.vm.reg_read(UC_X86_REG_EFLAGS)
        flag_values = {
            "cf": (flags >> 0) & 1,
            "zf": (flags >> 6) & 1,
            "of": (flags >> 11) & 1,
            "sf": (flags >> 7) & 1,
            "pf": (flags >> 2) & 1,
            "af": (flags >> 4) & 1,
            "df": (flags >> 10) & 1,
        }

        self.print_empty("%yellowflags%end : 0x{:08x} (cf:{} zf:{} of:{} sf:{} pf:{} af:{} df:{})".format(
            flags,
            flag_values["cf"], flag_values["zf"], flag_values["of"],
            flag_values["sf"], flag_values["pf"], flag_values["af"],
            flag_values["df"],
        ))

        self.print_stack(self.sp, self.vm.reg_read(UC_X86_REG_ESP), byte_size=4)

    def x64_emulate(self, code: bytes) -> None:
        """ Emulate x64 code.

        :param bytes code: code
        :return None: None
        """

        self.vm.mem_write(0, code)
        self.vm.reg_write(UC_X86_REG_RIP, 0)

        initial_registers = {}
        registers = [
            ("rax", UC_X86_REG_RAX), ("rbx", UC_X86_REG_RBX), ("rcx", UC_X86_REG_RCX), ("rdx", UC_X86_REG_RDX),
            ("rsi", UC_X86_REG_RSI), ("rdi", UC_X86_REG_RDI), ("r8", UC_X86_REG_R8), ("r9", UC_X86_REG_R9),
            ("r10", UC_X86_REG_R10), ("r11", UC_X86_REG_R11), ("r12", UC_X86_REG_R12), ("r13", UC_X86_REG_R13),
            ("r14", UC_X86_REG_R14), ("r15", UC_X86_REG_R15),
            ("rip", UC_X86_REG_RIP), ("rbp", UC_X86_REG_RBP), ("rsp", UC_X86_REG_RSP),
            ("cs", UC_X86_REG_CS), ("ss", UC_X86_REG_SS), ("ds", UC_X86_REG_DS), ("es", UC_X86_REG_ES),
            ("fs", UC_X86_REG_FS), ("gs", UC_X86_REG_GS),
        ]

        for name, reg in registers:
            initial_registers[name] = self.vm.reg_read(reg)

        try:
            self.vm.emu_start(0, len(code))
        except Exception as e:
            self.print_error(f"An error occured during emulation: {str(e)}!")
            return

        self.print_empty("------ cpu context ------")

        def colorize_register_submethod(name, reg):
            if self.vm.reg_read(reg) != initial_registers[name]:
                return f"%yellow{name:<3}%end : %red0x{self.vm.reg_read(reg):016x}%end"

            return f"%yellow{name:<3}%end : 0x{self.vm.reg_read(reg):016x}"

        self.print_empty(" ".join(colorize_register_submethod(name, reg) for name, reg in registers[0:4]))
        self.print_empty(" ".join(colorize_register_submethod(name, reg) for name, reg in registers[4:8]))
        self.print_empty(" ".join(colorize_register_submethod(name, reg) for name, reg in registers[8:12]))
        self.print_empty(" ".join(colorize_register_submethod(name, reg) for name, reg in registers[12:14]))
        self.print_empty(" ".join(colorize_register_submethod(name, reg) for name, reg in registers[14:17]))
        self.print_empty(" ".join(colorize_register_submethod(name, reg) for name, reg in registers[17:21]))
        self.print_empty(" ".join(colorize_register_submethod(name, reg) for name, reg in registers[21:]))

        flags = self.vm.reg_read(UC_X86_REG_EFLAGS)
        flag_values = {
            "cf": (flags >> 0) & 1,
            "zf": (flags >> 6) & 1,
            "of": (flags >> 11) & 1,
            "sf": (flags >> 7) & 1,
            "pf": (flags >> 2) & 1,
            "af": (flags >> 4) & 1,
            "df": (flags >> 10) & 1,
        }

        self.print_empty("%yellowflags%end : 0x{:016x} (cf:{} zf:{} of:{} sf:{} pf:{} af:{} df:{})".format(
            flags,
            flag_values["cf"], flag_values["zf"], flag_values["of"],
            flag_values["sf"], flag_values["pf"], flag_values["af"],
            flag_values["df"],
        ))

        self.print_stack(self.sp, self.vm.reg_read(UC_X86_REG_RSP))
