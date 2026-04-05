"""
This plugin requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from badges.cmd import Command

from pwny.api import *
from pwny.types import *

from hatsploit.lib.core.plugin import Plugin


UAC_INFO = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL)

TLV_TYPE_UAC_ELEVATED = tlv_custom_type(TLV_TYPE_INT, TAB_BASE, API_TYPE)
TLV_TYPE_UAC_INTEGRITY = tlv_custom_type(TLV_TYPE_INT, TAB_BASE, API_TYPE + 1)
TLV_TYPE_UAC_INTEGRITY_NAME = tlv_custom_type(TLV_TYPE_STRING, TAB_BASE, API_TYPE)

INTEGRITY_UNKNOWN = 0
INTEGRITY_LOW = 1
INTEGRITY_MEDIUM = 2
INTEGRITY_HIGH = 3
INTEGRITY_SYSTEM = 4


class HatSploitPlugin(Plugin):
    def __init__(self):
        super().__init__({
            'Name': "UAC Plugin",
            'Plugin': "uac",
            'Authors': [
                'EntySec - plugin developer',
            ],
            'Description': "Check UAC elevation status and integrity level.",
        })

        self.commands = [
            Command({
                'Category': "gather",
                'Name': "uac",
                'Description': "Check UAC elevation status and integrity level.",
                'MinArgs': 1,
                'Options': [
                    (
                        ('-i', '--info'),
                        {
                            'help': "Display UAC and token integrity information.",
                            'action': 'store_true',
                        }
                    ),
                ]
            })
        ]

    def uac(self, args):
        if args.info:
            result = self.session.send_command(
                tag=UAC_INFO, plugin=self.plugin
            )

            if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                self.print_error("Failed to retrieve UAC information!")
                return

            elevated = result.get_int(TLV_TYPE_UAC_ELEVATED)
            integrity = result.get_int(TLV_TYPE_UAC_INTEGRITY)
            integrity_name = result.get_string(TLV_TYPE_UAC_INTEGRITY_NAME)

            elevated_str = "Yes" if elevated else "No"

            if integrity >= INTEGRITY_HIGH:
                integrity_display = f"%green{integrity_name}%end"
            elif integrity == INTEGRITY_MEDIUM:
                integrity_display = f"%yellow{integrity_name}%end"
            else:
                integrity_display = f"%red{integrity_name}%end"

            self.print_information(f"Elevated: {elevated_str}")
            self.print_information(f"Integrity: {integrity_display}")

        else:
            self.print_usage()

    def load(self):
        pass
