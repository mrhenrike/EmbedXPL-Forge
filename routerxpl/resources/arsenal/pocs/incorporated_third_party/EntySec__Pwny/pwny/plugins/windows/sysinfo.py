"""
This plugin requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from badges.cmd import Command

from pwny.api import *
from pwny.types import *

from hatsploit.lib.core.plugin import Plugin

SYSINFO_APPS = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL)
SYSINFO_HOTFIX = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL + 1)

TLV_TYPE_APP_NAME = tlv_custom_type(TLV_TYPE_STRING, TAB_BASE, API_TYPE)
TLV_TYPE_APP_VERSION = tlv_custom_type(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 1)
TLV_TYPE_APP_VENDOR = tlv_custom_type(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 2)
TLV_TYPE_APP_DATE = tlv_custom_type(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 3)
TLV_TYPE_APP_GROUP = tlv_custom_type(TLV_TYPE_GROUP, TAB_BASE, API_TYPE)

TLV_TYPE_HF_KBID = tlv_custom_type(TLV_TYPE_STRING, TAB_BASE, API_TYPE)
TLV_TYPE_HF_DESC = tlv_custom_type(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 1)
TLV_TYPE_HF_DATE = tlv_custom_type(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 2)
TLV_TYPE_HF_GROUP = tlv_custom_type(TLV_TYPE_GROUP, TAB_BASE, API_TYPE)


class HatSploitPlugin(Plugin):
    def __init__(self):
        super().__init__({
            'Name': "System Info Plugin",
            'Plugin': "sysinfo",
            'Authors': [
                'EntySec - plugin developer',
            ],
            'Description': "Enumerate installed software and hotfixes.",
        })

        self.commands = [
            Command({
                'Category': "gather",
                'Name': "apps",
                'Description': "List installed applications.",
                'MinArgs': 1,
                'Options': [
                    (
                        ('-l', '--list'),
                        {
                            'help': "List all installed applications.",
                            'action': 'store_true',
                        }
                    ),
                    (
                        ('-f', '--filter'),
                        {
                            'help': "Filter by application name.",
                            'metavar': 'NAME',
                        }
                    ),
                    (
                        ('-v', '--vendor'),
                        {
                            'help': "Filter by vendor/publisher name.",
                            'metavar': 'VENDOR',
                        }
                    ),
                ]
            }),
            Command({
                'Category': "gather",
                'Name': "hotfix",
                'Description': "List installed hotfixes.",
                'MinArgs': 1,
                'Options': [
                    (
                        ('-l', '--list'),
                        {
                            'help': "List all installed hotfixes.",
                            'action': 'store_true',
                        }
                    ),
                    (
                        ('-f', '--filter'),
                        {
                            'help': "Filter by KB number.",
                            'metavar': 'KB',
                        }
                    ),
                ]
            }),
        ]

    def apps(self, args):
        if not args.list and not args.filter and not args.vendor:
            args.list = True

        self.print_process("Enumerating installed applications...")

        result = self.session.send_command(
            tag=SYSINFO_APPS, plugin=self.plugin
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error("Failed to enumerate installed applications!")
            return

        headers = ("Name", "Version", "Vendor", "Install Date")
        data = []
        seen = set()

        entry = result.get_tlv(TLV_TYPE_APP_GROUP)
        while entry:
            name = entry.get_string(TLV_TYPE_APP_NAME) or ''
            version = entry.get_string(TLV_TYPE_APP_VERSION) or ''
            vendor = entry.get_string(TLV_TYPE_APP_VENDOR) or ''
            date = entry.get_string(TLV_TYPE_APP_DATE) or ''

            if name and name not in seen:
                seen.add(name)

                if ((not args.filter or args.filter.lower() in name.lower()) and
                        (not args.vendor or args.vendor.lower() in vendor.lower())):
                    data.append((name, version or '-', vendor or '-', date or '-'))

            entry = result.get_tlv(TLV_TYPE_APP_GROUP)

        if not data:
            self.print_warning("No matching applications found.")
            return

        data.sort(key=lambda x: x[0].lower())
        self.print_table(
            f"Installed Applications ({len(data)})", headers, *data
        )

    def hotfix(self, args):
        if not args.list and not args.filter:
            args.list = True

        self.print_process("Enumerating installed hotfixes...")

        result = self.session.send_command(
            tag=SYSINFO_HOTFIX, plugin=self.plugin
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error("Failed to enumerate hotfixes!")
            return

        headers = ("KB ID", "Package")
        data = []
        seen = set()

        entry = result.get_tlv(TLV_TYPE_HF_GROUP)
        while entry:
            kb = entry.get_string(TLV_TYPE_HF_KBID) or ''
            desc = entry.get_string(TLV_TYPE_HF_DESC) or ''

            if kb and kb not in seen:
                seen.add(kb)

                if not args.filter or args.filter.upper() in kb.upper():
                    data.append((kb, desc or '-'))

            entry = result.get_tlv(TLV_TYPE_HF_GROUP)

        if not data:
            self.print_warning("No matching hotfixes found.")
            return

        data.sort(key=lambda x: x[0])
        self.print_table(
            f"Installed Hotfixes ({len(data)})", headers, *data
        )
