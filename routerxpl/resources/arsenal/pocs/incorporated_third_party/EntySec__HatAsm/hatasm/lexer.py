import re
from typing import Dict, Set, Optional, List

from prompt_toolkit.lexers import Lexer
from prompt_toolkit.styles import Style
from prompt_toolkit.formatted_text import StyleAndTextTuples


def _word_boundary(pattern: str) -> str:
    # “word boundary” that also works for regs containing $ or %.
    return r"(?<![A-Za-z0-9_])" + pattern + r"(?![A-Za-z0-9_])"


def _compile_token_regex(tokens: Set[str]) -> Optional[re.Pattern]:
    if not tokens:
        return None
    # Sort longest-first so "r10" matches before "r1"
    items = sorted(tokens, key=len, reverse=True)
    pat = "|".join(re.escape(t) for t in items)
    return re.compile(_word_boundary(r"(?:%s)" % pat), re.IGNORECASE)


def _x86_x64_mnemonics() -> Set[str]:
    # “Lots” of common x86/x64 mnemonics (Intel/AT&T names are generally same token)
    base = {
        # data movement
        "mov", "movzx", "movsx", "movsxd", "lea", "xchg", "bswap",
        "push", "pop", "pusha", "popa", "pushf", "popf", "pushfd", "popfd", "pushfq", "popfq",
        "cmov", "cmova", "cmovae", "cmovb", "cmovbe", "cmovc", "cmove", "cmovg", "cmovge",
        "cmovl", "cmovle", "cmovna", "cmovnae", "cmovnb", "cmovnbe", "cmovne", "cmovng",
        "cmovnge", "cmovnl", "cmovnle", "cmovno", "cmovnp", "cmovns", "cmovnz", "cmovo",
        "cmovp", "cmovpe", "cmovpo", "cmovs", "cmovz",
        "cwd", "cdq", "cqo", "cbw", "cwde", "cdqe",
        # arithmetic/logic
        "add", "adc", "sub", "sbb", "imul", "mul", "idiv", "div",
        "inc", "dec", "neg", "not",
        "and", "or", "xor", "test", "cmp",
        "shl", "sal", "shr", "sar", "rol", "ror", "rcl", "rcr",
        # string ops
        "movsb", "movsw", "movsd", "movsq",
        "stosb", "stosw", "stosd", "stosq",
        "lodsb", "lodsw", "lodsd", "lodsq",
        "scasb", "scasw", "scasd", "scasq",
        "cmpsb", "cmpsw", "cmpsd", "cmpsq",
        "rep", "repe", "repne", "repnz", "repz",
        # control flow
        "jmp", "call", "ret", "retn", "retf", "iret", "iretd", "iretq",
        "jz", "jnz", "je", "jne", "ja", "jae", "jb", "jbe", "jc", "jnc",
        "jg", "jge", "jl", "jle", "jo", "jno", "js", "jns", "jp", "jnp", "jpe", "jpo",
        "loop", "loope", "loopne", "jecxz", "jrcxz",
        # flags/system
        "nop", "hlt", "int", "into", "int3",
        "syscall", "sysenter", "sysexit", "sysret",
        "clc", "stc", "cmc", "cli", "sti", "cld", "std",
        "lahf", "sahf",
        "cpuid", "rdtsc", "rdtscp", "rdrand", "rdseed",
        "in", "out",
        "enter", "leave",
    }
    # Include common setcc forms as explicit tokens
    setcc = {
        "seta", "setae", "setb", "setbe", "setc", "sete", "setg", "setge",
        "setl", "setle", "setna", "setnae", "setnb", "setnbe", "setnc", "setne",
        "setng", "setnge", "setnl", "setnle", "setno", "setnp", "setns", "setnz",
        "seto", "setp", "setpe", "setpo", "sets", "setz"
    }
    base |= setcc
    return base


def _x86_x64_registers() -> Set[str]:
    regs = set()

    # 8/16/32/64 GPRs
    regs |= {
        "al", "cl", "dl", "bl", "ah", "ch", "dh", "bh",
        "spl", "bpl", "sil", "dil",
        "ax", "cx", "dx", "bx", "sp", "bp", "si", "di",
        "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
        "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
        "rip", "eip", "ip",
    }
    # r8..r15 variants
    for i in range(8, 16):
        regs.add(f"r{i}")
        regs.add(f"r{i}d")
        regs.add(f"r{i}w")
        regs.add(f"r{i}b")

    # segments / flags
    regs |= {"cs", "ds", "es", "fs", "gs", "ss", "eflags", "rflags"}

    # mmx/xmm/ymm/zmm
    for i in range(0, 32):
        regs.add(f"xmm{i}")
        regs.add(f"ymm{i}")
        regs.add(f"zmm{i}")
    for i in range(0, 8):
        regs.add(f"mm{i}")

    # x87 stack
    for i in range(0, 8):
        regs.add(f"st({i})")
        regs.add(f"st{i}")

    # common control/debug (not exhaustive)
    for i in range(0, 9):
        regs.add(f"cr{i}")
        regs.add(f"dr{i}")

    return regs


def _arm_mnemonics() -> Set[str]:
    return {
        "mov", "mvn", "ldr", "str", "ldrb", "strb", "ldrh", "strh",
        "ldm", "stm", "push", "pop",
        "add", "adc", "sub", "sbc", "rsb", "rsc",
        "mul", "mla", "umull", "smull", "udiv", "sdiv",
        "and", "orr", "eor", "bic",
        "cmp", "cmn", "tst", "teq",
        "lsl", "lsr", "asr", "ror",
        "b", "bl", "bx", "blx",
        "beq", "bne", "bgt", "blt", "bge", "ble", "bhi", "bls", "bhs", "blo",
        "svc", "swi",
        "nop", "bkpt",
    }


def _arm_registers() -> Set[str]:
    regs = {f"r{i}" for i in range(0, 16)}
    regs |= {"sp", "lr", "pc", "cpsr", "spsr"}
    # SIMD-ish names (best-effort)
    regs |= {f"s{i}" for i in range(0, 32)}
    regs |= {f"d{i}" for i in range(0, 32)}
    regs |= {f"q{i}" for i in range(0, 16)}
    return regs


def _aarch64_mnemonics() -> Set[str]:
    return {
        "mov", "movi", "movz", "movk", "adr", "adrp",
        "ldr", "str", "ldrb", "strb", "ldrh", "strh", "ldrsw",
        "ldp", "stp",
        "add", "adds", "sub", "subs",
        "and", "ands", "orr", "eor", "bic",
        "cmp", "cmn", "tst",
        "b", "bl", "br", "blr", "ret",
        "cbz", "cbnz", "tbz", "tbnz",
        "beq", "bne", "bgt", "blt", "bge", "ble", "bhi", "bls", "bhs", "blo",
        "svc",
        "nop", "hlt", "brk",
    }


def _aarch64_registers() -> Set[str]:
    regs = set()
    # x0-x30 / w0-w30
    for i in range(0, 31):
        regs.add(f"x{i}")
        regs.add(f"w{i}")
    regs |= {"sp", "fp", "lr", "pc", "xzr", "wzr"}

    # vector registers: v0-v31, plus common typed aliases
    for i in range(0, 32):
        regs.add(f"v{i}")
        regs.add(f"q{i}")
        regs.add(f"d{i}")
        regs.add(f"s{i}")
        regs.add(f"h{i}")
        regs.add(f"b{i}")

    return regs


def _mips_mnemonics() -> Set[str]:
    return {
        "add", "addu", "addi", "addiu",
        "sub", "subu",
        "and", "andi", "or", "ori", "xor", "xori", "nor",
        "slt", "sltu", "slti", "sltiu",
        "lui",
        "lw", "sw", "lb", "sb", "lh", "sh", "lbu", "lhu",
        "ld", "sd",
        "beq", "bne", "bgez", "bltz", "bgtz", "blez",
        "j", "jal", "jr", "jalr",
        "syscall", "break",
        "nop",
    }


def _mips_registers() -> Set[str]:
    regs = set()
    # numeric $0-$31
    regs |= {f"${i}" for i in range(0, 32)}
    # conventional names (with $)
    regs |= {
        "$zero", "$at",
        "$v0", "$v1",
        "$a0", "$a1", "$a2", "$a3",
        "$t0", "$t1", "$t2", "$t3", "$t4", "$t5", "$t6", "$t7", "$t8", "$t9",
        "$s0", "$s1", "$s2", "$s3", "$s4", "$s5", "$s6", "$s7",
        "$k0", "$k1",
        "$gp", "$sp", "$fp", "$ra",
    }
    return regs


def _ppc_mnemonics() -> Set[str]:
    return {
        "add", "addi", "addis", "addc", "adde", "subf", "subfc", "subfe", "subfic",
        "and", "andi.", "andis.", "or", "ori", "oris", "xor", "xori", "xoris",
        "slw", "srw", "sraw", "rlwinm", "rlwimi",
        "li", "lis", "mr",
        "lwz", "stw", "lbz", "stb", "lhz", "sth",
        "ld", "std",
        "cmpw", "cmplw", "cmpd", "cmpld",
        "b", "bl", "bc", "bclr", "bctr",
        "beq", "bne", "bgt", "blt", "bge", "ble",
        "mflr", "mtlr", "mfctr", "mtctr",
        "sc",
        "nop",
    }


def _ppc_registers() -> Set[str]:
    regs = set()
    regs |= {f"r{i}" for i in range(0, 32)}
    regs |= {f"f{i}" for i in range(0, 32)}
    regs |= {f"v{i}" for i in range(0, 32)}
    regs |= {f"cr{i}" for i in range(0, 8)}
    regs |= {"lr", "ctr", "xer", "msr"}
    return regs


def _sparc_mnemonics() -> Set[str]:
    return {
        "sethi",
        "add", "addcc", "sub", "subcc",
        "and", "andcc", "or", "orcc", "xor", "xnor",
        "sll", "srl", "sra",
        "ld", "st", "ldub", "lduh", "lduw", "ldsb", "ldsh", "ldsw",
        "stb", "sth", "stw", "stx", "ldx",
        "ba", "bn", "be", "bne", "bg", "bl", "bge", "ble",
        "call", "jmpl",
        "ret", "retl",
        "save", "restore",
        "nop",
        "ta",
    }


def _sparc_registers() -> Set[str]:
    regs = set()
    regs |= {f"g{i}" for i in range(0, 8)}
    regs |= {f"o{i}" for i in range(0, 8)}
    regs |= {f"l{i}" for i in range(0, 8)}
    regs |= {f"i{i}" for i in range(0, 8)}
    regs |= {"sp", "fp", "psr", "wim", "tbr", "y"}
    return regs


ARCH_MNEMONICS: Dict[str, Set[str]] = {
    "x86": _x86_x64_mnemonics(),
    "x64": _x86_x64_mnemonics(),
    "ppc": _ppc_mnemonics(),
    "ppc64": _ppc_mnemonics(),
    "armle": _arm_mnemonics(),
    "armbe": _arm_mnemonics(),
    "aarch64": _aarch64_mnemonics(),
    "sparc": _sparc_mnemonics(),
    "sparc64": _sparc_mnemonics(),
    "mipsle": _mips_mnemonics(),
    "mipsbe": _mips_mnemonics(),
    "mips64le": _mips_mnemonics(),
    "mips64be": _mips_mnemonics(),
}

ARCH_REGS: Dict[str, Set[str]] = {
    "x86": _x86_x64_registers(),
    "x64": _x86_x64_registers(),
    "ppc": _ppc_registers(),
    "ppc64": _ppc_registers(),
    "armle": _arm_registers(),
    "armbe": _arm_registers(),
    "aarch64": _aarch64_registers(),
    "sparc": _sparc_registers(),
    "sparc64": _sparc_registers(),
    "mipsle": _mips_registers(),
    "mipsbe": _mips_registers(),
    "mips64le": _mips_registers(),
    "mips64be": _mips_registers(),
}


class HatAsmLiveLexer(Lexer):
    """
    Arch-aware lexer:
    - labels at start: foo:
    - directives: .asciz / .byte / db/dw/dd/dq/dt
    - known mnemonics: green
    - known registers: cyan
    - numbers: yellow
    - strings: light green
    - comments: dim
    """

    _label_re = re.compile(r"^\s*([A-Za-z_][\w\$\.]*)(:)")
    _directive_re = re.compile(r"^\s*(\.[A-Za-z_][\w\.]*|db|dw|dd|dq|dt)\b", re.IGNORECASE)
    _number_re = re.compile(r"(?:0x[0-9A-Fa-f]+|\b-?\d+\b)")
    _string_re = re.compile(r"('([^'\\]|\\.)*'|\"([^\"\\]|\\.)*\")")

    # Token-ish word: includes dot for directives/mnemonics, includes $ and % for some arches/syntaxes
    _token_re = re.compile(r"[%\$]?[A-Za-z_\.][A-Za-z0-9_\.\$]*")

    def __init__(self, arch: str = "x64"):
        self.arch = arch
        self._mnemonics = ARCH_MNEMONICS.get(arch, set())
        self._regs = ARCH_REGS.get(arch, set())
        self._reg_rx = _compile_token_regex(self._regs)

    def set_arch(self, arch: str) -> None:
        self.arch = arch
        self._mnemonics = ARCH_MNEMONICS.get(arch, set())
        self._regs = ARCH_REGS.get(arch, set())
        self._reg_rx = _compile_token_regex(self._regs)

    def lex_document(self, document):
        def get_line(lineno: int) -> StyleAndTextTuples:
            text = document.lines[lineno]
            if not text:
                return []

            # Split out comment
            comment_idx = None
            for ch in (';', '#'):
                i = text.find(ch)
                if i != -1 and (comment_idx is None or i < comment_idx):
                    comment_idx = i

            code_part = text if comment_idx is None else text[:comment_idx]
            comment_part = "" if comment_idx is None else text[comment_idx:]

            out: StyleAndTextTuples = []

            # Label at start
            m = self._label_re.match(code_part)
            if m:
                before = code_part[:m.start(1)]
                if before:
                    out.append(("class:text", before))
                out.append(("class:label", m.group(1)))
                out.append(("class:punct", m.group(2)))
                code_part = code_part[m.end():]

            # Directive line (after optional label)
            if self._directive_re.match(code_part):
                stripped = code_part.lstrip()
                leading_ws_len = len(code_part) - len(stripped)
                if leading_ws_len:
                    out.append(("class:text", code_part[:leading_ws_len]))
                token = stripped.split(None, 1)[0]
                out.append(("class:directive", token))
                remainder = stripped[len(token):]
                out.extend(self._style_rest(remainder))
            else:
                out.extend(self._style_mnemonic_then_rest(code_part))

            if comment_part:
                out.append(("class:comment", comment_part))

            return out

        return get_line

    def _style_mnemonic_then_rest(self, s: str) -> StyleAndTextTuples:
        out: StyleAndTextTuples = []

        stripped = s.lstrip()
        leading_ws_len = len(s) - len(stripped)
        if leading_ws_len:
            out.append(("class:text", s[:leading_ws_len]))

        if not stripped:
            return out

        # First token is candidate mnemonic
        first_match = self._token_re.match(stripped)
        if not first_match:
            out.append(("class:text", stripped))
            return out

        first = first_match.group(0)
        rest = stripped[first_match.end():]

        # highlight mnemonic only if known for current arch
        if first.lower() in self._mnemonics:
            out.append(("class:mnemonic", first))
        else:
            out.append(("class:text", first))

        out.extend(self._style_rest(rest))
        return out

    def _style_rest(self, s: str) -> StyleAndTextTuples:
        """
        Style remainder with registers, strings, numbers.
        We scan left-to-right; strings first, then numbers, then registers/tokens.
        """
        out: StyleAndTextTuples = []
        i = 0

        while i < len(s):
            sm = self._string_re.search(s, i)
            nm = self._number_re.search(s, i)

            # next special (string/number) match
            candidates = [m for m in (sm, nm) if m is not None]
            next_special = min(candidates, key=lambda x: x.start()) if candidates else None

            # If no special left, just style registers/tokens in the tail
            if next_special is None:
                out.extend(self._style_regs_in_text(s[i:]))
                break

            # Style text before special (with register highlighting)
            if next_special.start() > i:
                out.extend(self._style_regs_in_text(s[i:next_special.start()]))

            if next_special is sm:
                out.append(("class:string", next_special.group(0)))
            else:
                out.append(("class:number", next_special.group(0)))

            i = next_special.end()

        return out

    def _style_regs_in_text(self, chunk: str) -> StyleAndTextTuples:
        """
        Highlight registers within a chunk; everything else default.
        """
        if not chunk:
            return []
        if self._reg_rx is None:
            return [("class:text", chunk)]

        out: StyleAndTextTuples = []
        pos = 0
        for m in self._reg_rx.finditer(chunk):
            if m.start() > pos:
                out.append(("class:text", chunk[pos:m.start()]))
            out.append(("class:register", m.group(0)))
            pos = m.end()

        if pos < len(chunk):
            out.append(("class:text", chunk[pos:]))

        return out


HATASM_STYLE = Style.from_dict({
    "text": "",
    "mnemonic": "fg:#22c55e",       # green
    "register": "fg:#38bdf8",       # cyan
    "directive": "fg:#60a5fa",      # blue
    "label": "fg:#a78bfa",          # purple
    "punct": "fg:#94a3b8",               # gray
    "number": "fg:#fbbf24",              # yellow
    "string": "fg:#86efac",              # light green
    "comment": "fg:#64748b italic",      # dim gray
})
