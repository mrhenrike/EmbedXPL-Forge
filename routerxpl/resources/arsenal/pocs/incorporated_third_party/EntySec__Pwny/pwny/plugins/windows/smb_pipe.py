"""
This plugin requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from badges.cmd import Command

from pwny.api import *
from pwny.types import *

from hatsploit.lib.core.plugin import Plugin

SMBPIPE_CREATE = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL)
SMBPIPE_CONNECT = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL + 1)
SMBPIPE_READ = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL + 2)
SMBPIPE_WRITE = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL + 3)
SMBPIPE_CLOSE = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL + 4)

TLV_TYPE_PIPE_NAME = tlv_custom_type(TLV_TYPE_STRING, TAB_BASE, API_TYPE)
TLV_TYPE_PIPE_HOST = tlv_custom_type(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 1)
TLV_TYPE_PIPE_DATA = tlv_custom_type(TLV_TYPE_BYTES, TAB_BASE, API_TYPE)
TLV_TYPE_PIPE_LEN = tlv_custom_type(TLV_TYPE_INT, TAB_BASE, API_TYPE)
TLV_TYPE_PIPE_ID = tlv_custom_type(TLV_TYPE_INT, TAB_BASE, API_TYPE + 1)


class HatSploitPlugin(Plugin):
    def __init__(self):
        super().__init__({
            'Name': "SMB Pipe Plugin",
            'Plugin': "smb_pipe",
            'Authors': [
                'EntySec - plugin developer',
            ],
            'Description': (
                "Named pipe communication for lateral movement. "
                "Create or connect to named pipes over SMB."
            ),
        })

        self.pipes = {}

        self.commands = [
            Command({
                'Category': "pivot",
                'Name': "pipe",
                'Description': "Named pipe operations.",
                'MinArgs': 1,
                'Options': [
                    (
                        ('action',),
                        {
                            'help': "Action to perform.",
                            'choices': [
                                'create', 'connect', 'read',
                                'write', 'close', 'list',
                            ],
                        }
                    ),
                    (
                        ('-n', '--name'),
                        {
                            'help': "Pipe name (e.g. pwny_comms).",
                            'metavar': 'NAME',
                        }
                    ),
                    (
                        ('-H', '--host'),
                        {
                            'help': (
                                "Remote host for connect "
                                "(e.g. 192.168.1.10 or HOSTNAME)."
                            ),
                            'metavar': 'HOST',
                        }
                    ),
                    (
                        ('-i', '--id'),
                        {
                            'help': "Pipe ID for read/write/close.",
                            'type': int,
                            'metavar': 'ID',
                        }
                    ),
                    (
                        ('-d', '--data'),
                        {
                            'help': "Data to write (string).",
                            'metavar': 'DATA',
                        }
                    ),
                    (
                        ('-l', '--length'),
                        {
                            'help': "Bytes to read (default: 4096).",
                            'type': int,
                            'default': 4096,
                            'metavar': 'LEN',
                        }
                    ),
                ]
            })
        ]

    def pipe(self, args):
        action = args.action

        if action == 'create':
            self._create(args)
        elif action == 'connect':
            self._connect(args)
        elif action == 'read':
            self._read(args)
        elif action == 'write':
            self._write(args)
        elif action == 'close':
            self._close(args)
        elif action == 'list':
            self._list()

    def _create(self, args):
        if not args.name:
            self.print_error("Specify pipe name with -n/--name")
            return

        self.print_process(
            f"Creating named pipe \\\\.\\pipe\\{args.name} "
            f"and waiting for connection..."
        )

        result = self.session.send_command(
            tag=SMBPIPE_CREATE,
            plugin=self.plugin,
            args={TLV_TYPE_PIPE_NAME: args.name},
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error("Failed to create pipe!")
            return

        pipe_id = result.get_int(TLV_TYPE_PIPE_ID)
        self.pipes[pipe_id] = f"\\\\.\\pipe\\{args.name}"
        self.print_success(
            f"Pipe created and client connected (ID: {pipe_id})"
        )

    def _connect(self, args):
        if not args.name or not args.host:
            self.print_error(
                "Specify pipe name (-n) and host (-H)"
            )
            return

        self.print_process(
            f"Connecting to \\\\{args.host}\\pipe\\{args.name}..."
        )

        result = self.session.send_command(
            tag=SMBPIPE_CONNECT,
            plugin=self.plugin,
            args={
                TLV_TYPE_PIPE_NAME: args.name,
                TLV_TYPE_PIPE_HOST: args.host,
            },
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error("Failed to connect to pipe!")
            return

        pipe_id = result.get_int(TLV_TYPE_PIPE_ID)
        self.pipes[pipe_id] = f"\\\\{args.host}\\pipe\\{args.name}"
        self.print_success(f"Connected (ID: {pipe_id})")

    def _read(self, args):
        if args.id is None:
            self.print_error("Specify pipe ID with -i/--id")
            return

        result = self.session.send_command(
            tag=SMBPIPE_READ,
            plugin=self.plugin,
            args={
                TLV_TYPE_PIPE_ID: args.id,
                TLV_TYPE_PIPE_LEN: args.length,
            },
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error("Failed to read from pipe!")
            return

        data = result.get_raw(TLV_TYPE_PIPE_DATA)
        nbytes = result.get_int(TLV_TYPE_PIPE_LEN)

        if data:
            self.print_success(f"Read {nbytes} bytes:")
            try:
                self.print_empty(data.decode('utf-8', errors='replace'))
            except Exception:
                self.print_hexdump(data)
        else:
            self.print_warning("No data available.")

    def _write(self, args):
        if args.id is None:
            self.print_error("Specify pipe ID with -i/--id")
            return
        if not args.data:
            self.print_error("Specify data with -d/--data")
            return

        data = args.data.encode('utf-8')

        result = self.session.send_command(
            tag=SMBPIPE_WRITE,
            plugin=self.plugin,
            args={
                TLV_TYPE_PIPE_ID: args.id,
                TLV_TYPE_PIPE_DATA: data,
            },
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error("Failed to write to pipe!")
            return

        nbytes = result.get_int(TLV_TYPE_PIPE_LEN)
        self.print_success(f"Wrote {nbytes} bytes.")

    def _close(self, args):
        if args.id is None:
            self.print_error("Specify pipe ID with -i/--id")
            return

        result = self.session.send_command(
            tag=SMBPIPE_CLOSE,
            plugin=self.plugin,
            args={TLV_TYPE_PIPE_ID: args.id},
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error("Failed to close pipe!")
            return

        self.pipes.pop(args.id, None)
        self.print_success(f"Pipe {args.id} closed.")

    def _list(self):
        if not self.pipes:
            self.print_warning("No active pipes.")
            return

        headers = ("ID", "Path")
        data = [
            (str(pid), path)
            for pid, path in sorted(self.pipes.items())
        ]
        self.print_table("Active Pipes", headers, *data)

    def unload(self):
        for pid in list(self.pipes.keys()):
            try:
                self.session.send_command(
                    tag=SMBPIPE_CLOSE,
                    plugin=self.plugin,
                    args={TLV_TYPE_PIPE_ID: pid},
                )
            except Exception:
                pass
        self.pipes.clear()
