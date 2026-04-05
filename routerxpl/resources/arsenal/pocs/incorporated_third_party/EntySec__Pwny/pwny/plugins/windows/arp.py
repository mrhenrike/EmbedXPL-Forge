"""
This plugin requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from badges.cmd import Command

from pwny.api import *
from pwny.types import *

from hatsploit.lib.core.plugin import Plugin

ARP_LIST = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL)

TLV_TYPE_ARP_IP = tlv_custom_type(TLV_TYPE_STRING, TAB_BASE, API_TYPE)
TLV_TYPE_ARP_MAC = tlv_custom_type(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 1)
TLV_TYPE_ARP_TYPE = tlv_custom_type(TLV_TYPE_INT, TAB_BASE, API_TYPE)
TLV_TYPE_ARP_IFINDEX = tlv_custom_type(TLV_TYPE_INT, TAB_BASE, API_TYPE + 1)
TLV_TYPE_ARP_GROUP = tlv_custom_type(TLV_TYPE_GROUP, TAB_BASE, API_TYPE)

ARP_TYPE_NAMES = {
    1: 'Other',
    2: 'Invalid',
    3: 'Dynamic',
    4: 'Static',
}


class HatSploitPlugin(Plugin):
    def __init__(self):
        super().__init__({
            'Name': "ARP Plugin",
            'Plugin': "arp",
            'Authors': [
                'EntySec - plugin developer',
            ],
            'Description': "Enumerate the ARP table.",
        })

        self.commands = [
            Command({
                'Category': "gather",
                'Name': "arp",
                'Description': "Show the ARP table.",
                'MinArgs': 1,
                'Options': [
                    (
                        ('-l', '--list'),
                        {
                            'help': "List all ARP entries.",
                            'action': 'store_true',
                        }
                    ),
                    (
                        ('-f', '--filter'),
                        {
                            'help': "Filter by IP substring.",
                            'metavar': 'IP',
                        }
                    ),
                ]
            })
        ]

    def arp(self, args):
        if not args.list and not args.filter:
            args.list = True

        self.print_process("Querying ARP table...")

        result = self.session.send_command(
            tag=ARP_LIST, plugin=self.plugin
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error("Failed to query ARP table!")
            return

        headers = ("IP Address", "MAC Address", "Type", "Interface")
        data = []

        entry = result.get_tlv(TLV_TYPE_ARP_GROUP)
        while entry:
            ip = entry.get_string(TLV_TYPE_ARP_IP) or ''
            mac = entry.get_string(TLV_TYPE_ARP_MAC) or ''
            arp_type = entry.get_int(TLV_TYPE_ARP_TYPE) or 0
            ifindex = entry.get_int(TLV_TYPE_ARP_IFINDEX) or 0

            if not args.filter or args.filter in ip:
                type_name = ARP_TYPE_NAMES.get(arp_type, str(arp_type))
                data.append((ip, mac, type_name, str(ifindex)))

            entry = result.get_tlv(TLV_TYPE_ARP_GROUP)

        if not data:
            self.print_warning("No matching entries found.")
            return

        self.print_table("ARP Table", headers, *data)
