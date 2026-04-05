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

import codecs
import re

from .asm import ASM
from .emu import Emu

from badges.cmd import Cmd
from colorscript import ColorScript

from .lexer import HatAsmLiveLexer, HATASM_STYLE


class Console(Cmd, ASM):
    """Interactive assembler/disassembler console."""

    # Directives/data pseudo-ops (architecture-agnostic)
    _DIRECTIVE_RE = re.compile(r"^\s*(\.[A-Za-z_][\w\.]*|db|dw|dd|dq|dt)\b", re.IGNORECASE)

    # Standalone label: "name:" with nothing after it
    _STANDALONE_LABEL_RE = re.compile(r"^\s*[A-Za-z_][\w\$\.]*:\s*$")

    def __init__(self, arch: str, mode: str = '',
                 syntax: str = 'intel',
                 prompt: str = '%dark%yellow[hatasm]>%end ',
                 asm: bool = True,
                 emulate: bool = True) -> None:
        super().__init__(prompt=prompt, builtins={'.': None})

        self.scheme = prompt
        self.arch = arch
        self.mode = mode
        self.syntax = syntax

        self.asm = asm
        self.cached = ""

        # Recording mode controlled by .start/.end
        self.recording = False
        self.rec_addr = 0  # byte counter in record mode
        self.rec_base = 0x10000000

        # True only when prompt is currently in "label multiline" dotted mode
        self.label_prompt = False

        # Arch-aware live lexer instance (switchable)
        self._lexer = HatAsmLiveLexer(arch=self.arch)
        self._prompt_raw = prompt
        self.configure_prompt(lexer=self._lexer, style=HATASM_STYLE)

        if emulate:
            self.emu = Emu(arch)
        else:
            self.emu = None

        # Ensure prompt matches initial state
        self._set_prompt_for_state()

    # -----------------------
    # Prompt helpers
    # -----------------------

    def _record_prompt(self) -> str:
        addr = self.rec_base + self.rec_addr
        return f"%dark%yellow[0x{addr:08x}]>%end "

    def _set_prompt_for_state(self) -> None:
        if self.label_prompt:
            return

        if self.recording:
            self._prompt_raw = self._record_prompt()
            self.set_prompt(self._prompt_raw)
        else:
            self._prompt_raw = self.scheme
            self.set_prompt(self._prompt_raw)

    def _cached_prompt_str(self) -> str:
        # Dots must match the prompt user will see (raw template, no ANSI yet)
        width = len(ColorScript().strip(self._prompt_raw))
        return '.' * width + ' ' * 4

    def _enter_label_prompt(self) -> None:
        self.set_prompt(self._cached_prompt_str())
        self.label_prompt = True

    def _exit_label_prompt(self) -> None:
        self.label_prompt = False
        self._set_prompt_for_state()

    # -----------------------
    # Detection helpers
    # -----------------------

    @staticmethod
    def _strip_comment(line: str) -> str:
        # Detection-only stripping (does not parse quotes)
        for token in (';', '#'):
            if token in line:
                line = line.split(token, 1)[0]
        return line.strip()

    def _is_standalone_label(self, code: str) -> bool:
        s = self._strip_comment(code)
        return bool(s) and bool(self._STANDALONE_LABEL_RE.match(s))

    def _is_directive(self, code: str) -> bool:
        s = self._strip_comment(code)
        return bool(s) and bool(self._DIRECTIVE_RE.match(s))

    # -----------------------
    # Record-mode address counting
    # -----------------------

    def _record_count_line_bytes(self, line: str) -> None:
        """
        Best-effort byte counting in record mode.
        We attempt to assemble the single line:
          - If it succeeds, advance rec_addr by len(bytes)
          - If it fails (labels/directives needing context), do nothing
        """
        try:
            b = self.assemble(self.arch, line, self.mode, self.syntax)
            if b:
                self.rec_addr += len(b)
        except Exception:
            pass

    # -----------------------
    # Assembly flush
    # -----------------------

    def _flush_cached_block(self) -> None:
        """Assemble cached buffer atomically and print result/errors."""
        if not self.cached:
            self._set_prompt_for_state()
            return

        code_block = self.cached
        self.cached = ""  # clear early to avoid stale buffer

        try:
            result = self.assemble(self.arch, code_block, self.mode, self.syntax)

            if self.emu:
                self.emu.emulate(result)

            for line in self.hexdump(result):
                self.print_empty(line)

        except (KeyboardInterrupt, EOFError):
            self.print_empty()

        except Exception as e:
            msg = str(e).split(' (', 1)[0]
            self.print_error(f"HatAsm: assembler failed: {msg}")

        finally:
            self._set_prompt_for_state()

    # -----------------------
    # Cmd hooks
    # -----------------------

    def emptyline(self) -> None:
        """
        Blank line behavior:

        - If we're currently in the dotted "label prompt":
            * If recording: exit dotted prompt, keep recording, do NOT flush
            * If not recording: exit dotted prompt and flush immediately

        - If recording (but not in label prompt):
            * do NOT flush/assemble
            * preserve the blank line in the cache

        - Otherwise (not recording):
            * if we have cached content (from label/directive), flush/assemble as usual
        """
        if not self.asm:
            return

        if self.label_prompt:
            # Always exit dotted prompt first
            self._exit_label_prompt()

            if self.recording:
                # Keep recording; don't assemble
                self.cached += "\n"
                self._set_prompt_for_state()
                return

            # Not recording: assemble immediately on the same Enter
            # (Optional) preserve a separator newline
            self.cached += "\n"
            self._flush_cached_block()
            return

        if self.recording:
            self.cached += "\n"
            self._set_prompt_for_state()
            return

        if not self.cached:
            return

        self._flush_cached_block()

    def default(self, args: list, raw_line: str = "", **kwargs) -> None:
        # IMPORTANT: raw_line preserves quotes for directives like: .asciz "sas"
        code = raw_line if raw_line else ' '.join(args)

        # Disassemble mode unchanged
        if not self.asm:
            code_bytes = codecs.escape_decode(code)[0]
            print(code_bytes)
            result = self.disassemble(self.arch, code_bytes, self.mode, self.syntax)

            if self.emu:
                self.emu.emulate(code_bytes)

            for line in result:
                self.print_empty("0x%x:\t%s\t%s" % (line.address, line.mnemonic, line.op_str))
            return

        cmd = self._strip_comment(code)

        # -----------------------
        # Meta commands
        # -----------------------

        # .arch <arch> switches assembler/disassembler arch + lexer highlighting
        if cmd.startswith(".arch"):
            parts = cmd.split()
            if len(parts) != 2:
                avail = ", ".join(sorted(self.ks_arch.keys()))
                self.print_error(f"Usage: .arch <arch> (available: {avail})")
                return

            new_arch = parts[1].strip()
            if new_arch not in self.ks_arch:
                avail = ", ".join(sorted(self.ks_arch.keys()))
                self.print_error(f"Unsupported arch: {new_arch} (available: {avail})")
                return

            self.arch = new_arch

            # keep emulator aligned too
            if self.emu:
                self.emu = Emu(new_arch)

            # update live lexer arch
            self._lexer.set_arch(new_arch)

            self.print_process(f"Architecture set to: {new_arch}%newline")
            return

        # .start / .end controls
        if cmd == ".start":
            self.recording = True
            self.rec_addr = 0
            self._set_prompt_for_state()
            return

        if cmd == ".end":
            # End recording and flush atomically
            self.recording = False
            self._exit_label_prompt()
            self._flush_cached_block()
            # Reset record counter after flush
            self.rec_addr = 0
            self._set_prompt_for_state()
            return

        # -----------------------
        # Recording mode
        # -----------------------
        if self.recording:
            # Dotted prompt only for standalone labels (even while recording)
            if self._is_standalone_label(code):
                self._enter_label_prompt()
            else:
                self._set_prompt_for_state()

            # Best-effort address advance for single-line instructions
            self._record_count_line_bytes(code)

            self.cached += code + "\n"
            return

        # -----------------------
        # Non-recording cached mode (labels/directives)
        # -----------------------

        # If we already have cached content (auto-cached), keep buffering.
        if self.cached:
            if self._is_standalone_label(code):
                self._enter_label_prompt()
            self.cached += code + "\n"
            return

        # Enter dotted prompt ONLY on standalone labels.
        if self._is_standalone_label(code):
            self._enter_label_prompt()
            self.cached += code + "\n"
            return

        # Directives/data often need context; cache them too,
        # BUT do NOT enter dotted prompt (labels only).
        if self._is_directive(code):
            self.cached += code + "\n"
            return

        # -----------------------
        # Single-line assemble
        # -----------------------
        try:
            result = self.assemble(self.arch, code, self.mode, self.syntax)

            if self.emu:
                self.emu.emulate(result)

            for line in self.hexdump(result):
                self.print_empty(line)

        except Exception as e:
            msg = str(e).split(' (', 1)[0]
            self.print_error(f"HatAsm: assembler failed: {msg}")

    def shell(self) -> None:
        self.loop()
