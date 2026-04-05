"""
This plugin requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from badges.cmd import Command

from pwny.api import *
from pwny.types import *

from hatsploit.lib.core.plugin import Plugin


NETSHARE_ENUM = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL)
NETSESSION_ENUM = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL + 1)

TLV_TYPE_SHARE_NAME = tlv_custom_type(TLV_TYPE_STRING, TAB_BASE, API_TYPE)
TLV_TYPE_SHARE_PATH = tlv_custom_type(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 1)
TLV_TYPE_SHARE_REMARK = tlv_custom_type(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 2)
TLV_TYPE_SHARE_TYPE = tlv_custom_type(TLV_TYPE_INT, TAB_BASE, API_TYPE)
TLV_TYPE_SHARE_GROUP = tlv_custom_type(TLV_TYPE_GROUP, TAB_BASE, API_TYPE)

TLV_TYPE_SESSION_CLIENT = tlv_custom_type(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 3)
TLV_TYPE_SESSION_USER = tlv_custom_type(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 4)
TLV_TYPE_SESSION_TIME = tlv_custom_type(TLV_TYPE_INT, TAB_BASE, API_TYPE + 1)
TLV_TYPE_SESSION_IDLE = tlv_custom_type(TLV_TYPE_INT, TAB_BASE, API_TYPE + 2)
TLV_TYPE_SESSION_GROUP = tlv_custom_type(TLV_TYPE_GROUP, TAB_BASE, API_TYPE + 1)

SHARE_TYPES = {
    0x00000000: "Disk",
    0x00000001: "Printer",
    0x00000002: "Device",
    0x00000003: "IPC",
    0x80000000: "Special",
}


def format_seconds(seconds):
    if seconds < 60:
        return f"{seconds}s"
    elif seconds < 3600:
        return f"{seconds // 60}m {seconds % 60}s"
    else:
        h = seconds // 3600
        m = (seconds % 3600) // 60
        return f"{h}h {m}m"


class HatSploitPlugin(Plugin):
    def __init__(self):
        super().__init__({
            'Name': "Net Share Plugin",
            'Plugin': "netshare",
            'Authors': [
                'EntySec - plugin developer',
            ],
            'Description': "Enumerate network shares and sessions.",
        })

        self.commands = [
            Command({
                'Category': "gather",
                'Name': "net_enum",
                'Description': "Enumerate network shares and sessions.",
                'MinArgs': 1,
                'Options': [
                    (
                        ('-s', '--shares'),
                        {
                            'help': "List SMB/network shares.",
                            'action': 'store_true',
                        }
                    ),
                    (
                        ('-S', '--sessions'),
                        {
                            'help': "List active network sessions.",
                            'action': 'store_true',
                        }
                    ),
                ]
            })
        ]

    def net_enum(self, args):
        if args.shares:
            result = self.session.send_command(
                tag=NETSHARE_ENUM, plugin=self.plugin
            )

            if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                self.print_error("Failed to enumerate shares!")
                return

            data = []
            entry = result.get_tlv(TLV_TYPE_SHARE_GROUP)

            while entry:
                name_raw = entry.get_raw(TLV_TYPE_SHARE_NAME)
                path_raw = entry.get_raw(TLV_TYPE_SHARE_PATH)
                remark_raw = entry.get_raw(TLV_TYPE_SHARE_REMARK)

                name = name_raw.decode('utf-8', errors='replace') if name_raw else ''
                path = path_raw.decode('utf-8', errors='replace') if path_raw else ''
                remark = remark_raw.decode('utf-8', errors='replace') if remark_raw else ''

                share_type = entry.get_int(TLV_TYPE_SHARE_TYPE) or 0
                type_base = share_type & 0x0FFFFFFF
                type_name = SHARE_TYPES.get(type_base, "Unknown")
                if share_type & 0x80000000:
                    type_name += " (Hidden)"

                data.append((name, type_name, path, remark))
                entry = result.get_tlv(TLV_TYPE_SHARE_GROUP)

            if not data:
                self.print_warning("No shares found.")
                return

            self.print_table("Network Shares",
                             ('Name', 'Type', 'Path', 'Remark'), *data)

        elif args.sessions:
            result = self.session.send_command(
                tag=NETSESSION_ENUM, plugin=self.plugin
            )

            if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                self.print_error("Failed to enumerate sessions!")
                return

            data = []
            entry = result.get_tlv(TLV_TYPE_SESSION_GROUP)

            while entry:
                client_raw = entry.get_raw(TLV_TYPE_SESSION_CLIENT)
                user_raw = entry.get_raw(TLV_TYPE_SESSION_USER)

                client = client_raw.decode('utf-8', errors='replace') if client_raw else ''
                user = user_raw.decode('utf-8', errors='replace') if user_raw else ''

                time_val = entry.get_int(TLV_TYPE_SESSION_TIME) or 0
                idle_val = entry.get_int(TLV_TYPE_SESSION_IDLE) or 0

                data.append((
                    client, user,
                    format_seconds(time_val),
                    format_seconds(idle_val)
                ))
                entry = result.get_tlv(TLV_TYPE_SESSION_GROUP)

            if not data:
                self.print_warning("No active sessions found.")
                return

            self.print_table("Network Sessions",
                             ('Client', 'User', 'Active', 'Idle'), *data)

        else:
            self.print_usage()

    def load(self):
        pass
