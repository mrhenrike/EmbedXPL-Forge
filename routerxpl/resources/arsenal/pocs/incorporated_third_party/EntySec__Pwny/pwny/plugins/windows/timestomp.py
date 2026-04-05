"""
This plugin requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

import datetime

from badges.cmd import Command

from pwny.api import *
from pwny.types import *

from hatsploit.lib.core.plugin import Plugin


TIMESTOMP_SET = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL)
TIMESTOMP_GET = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL + 1)

TLV_TYPE_TS_PATH = tlv_custom_type(TLV_TYPE_STRING, TAB_BASE, API_TYPE)
TLV_TYPE_TS_MTIME = tlv_custom_type(TLV_TYPE_INT, TAB_BASE, API_TYPE)
TLV_TYPE_TS_ATIME = tlv_custom_type(TLV_TYPE_INT, TAB_BASE, API_TYPE + 1)
TLV_TYPE_TS_CTIME = tlv_custom_type(TLV_TYPE_INT, TAB_BASE, API_TYPE + 2)


class HatSploitPlugin(Plugin):
    def __init__(self):
        super().__init__({
            'Name': "Timestomp Plugin",
            'Plugin': "timestomp",
            'Authors': [
                'EntySec - plugin developer',
            ],
            'Description': "View or modify file timestamps.",
        })

        self.commands = [
            Command({
                'Category': "manage",
                'Name': "timestomp",
                'Description': "View or modify file timestamps.",
                'MinArgs': 1,
                'Options': [
                    (
                        ('-g', '--get'),
                        {
                            'help': "Get timestamps of a file.",
                            'metavar': 'PATH',
                        }
                    ),
                    (
                        ('-s', '--set'),
                        {
                            'help': "Set timestamps on a file.",
                            'metavar': 'PATH',
                        }
                    ),
                    (
                        ('-m', '--mtime'),
                        {
                            'help': "Modified time (YYYY-MM-DD HH:MM:SS).",
                            'metavar': 'TIME',
                        }
                    ),
                    (
                        ('-a', '--atime'),
                        {
                            'help': "Access time (YYYY-MM-DD HH:MM:SS).",
                            'metavar': 'TIME',
                        }
                    ),
                    (
                        ('-c', '--ctime'),
                        {
                            'help': "Creation time (YYYY-MM-DD HH:MM:SS).",
                            'metavar': 'TIME',
                        }
                    ),
                    (
                        ('-r', '--ref'),
                        {
                            'help': "Copy timestamps from reference file.",
                            'metavar': 'PATH',
                        }
                    ),
                ]
            })
        ]

    def parse_time(self, time_str):
        try:
            dt = datetime.datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S")
            return int(dt.timestamp())
        except ValueError:
            self.print_error(f"Invalid time format: {time_str}")
            self.print_information("Expected: YYYY-MM-DD HH:MM:SS")
            return None

    def format_time(self, unix_time):
        if unix_time == 0:
            return "(not set)"
        return datetime.datetime.fromtimestamp(unix_time).strftime(
            "%Y-%m-%d %H:%M:%S"
        )

    def get_timestamps(self, path):
        result = self.session.send_command(
            tag=TIMESTOMP_GET,
            plugin=self.plugin,
            args={
                TLV_TYPE_TS_PATH: path,
            }
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error(f"Failed to get timestamps for: {path}")
            return None

        return {
            'mtime': result.get_int(TLV_TYPE_TS_MTIME),
            'atime': result.get_int(TLV_TYPE_TS_ATIME),
            'ctime': result.get_int(TLV_TYPE_TS_CTIME),
        }

    def timestomp(self, args):
        if args.get:
            ts = self.get_timestamps(args.get)
            if ts is None:
                return

            self.print_information(f"Timestamps for: {args.get}")
            self.print_information(f"  Modified : {self.format_time(ts['mtime'])}")
            self.print_information(f"  Accessed : {self.format_time(ts['atime'])}")
            self.print_information(f"  Created  : {self.format_time(ts['ctime'])}")

        elif args.set:
            cmd_args = {
                TLV_TYPE_TS_PATH: args.set,
            }

            if args.ref:
                ref_ts = self.get_timestamps(args.ref)
                if ref_ts is None:
                    return

                cmd_args[TLV_TYPE_TS_MTIME] = ref_ts['mtime']
                cmd_args[TLV_TYPE_TS_ATIME] = ref_ts['atime']
                cmd_args[TLV_TYPE_TS_CTIME] = ref_ts['ctime']

                self.print_process(
                    f"Copying timestamps from {args.ref} to {args.set}..."
                )
            else:
                if not args.mtime and not args.atime and not args.ctime:
                    self.print_error(
                        "Specify at least one of: -m/--mtime, -a/--atime, "
                        "-c/--ctime, or -r/--ref"
                    )
                    return

                if args.mtime:
                    ts = self.parse_time(args.mtime)
                    if ts is None:
                        return
                    cmd_args[TLV_TYPE_TS_MTIME] = ts

                if args.atime:
                    ts = self.parse_time(args.atime)
                    if ts is None:
                        return
                    cmd_args[TLV_TYPE_TS_ATIME] = ts

                if args.ctime:
                    ts = self.parse_time(args.ctime)
                    if ts is None:
                        return
                    cmd_args[TLV_TYPE_TS_CTIME] = ts

                self.print_process(f"Modifying timestamps on {args.set}...")

            result = self.session.send_command(
                tag=TIMESTOMP_SET,
                plugin=self.plugin,
                args=cmd_args,
            )

            if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                self.print_error("Failed to modify timestamps!")
                return

            self.print_success("Timestamps modified successfully.")

        else:
            self.print_usage()

    def load(self):
        pass
