"""
This plugin requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

import struct
import threading
import time
import io

from badges.cmd import Command

from pwny.api import *
from pwny.types import *

from hatsploit.lib.core.plugin import Plugin

SNIFFER_LIST = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL)
SNIFFER_STATS = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL + 1)

SNIFFER_PIPE = tlv_custom_pipe(PIPE_STATIC, TAB_BASE, PIPE_TYPE)

TLV_TYPE_IFACE_IP = tlv_custom_type(TLV_TYPE_STRING, TAB_BASE, API_TYPE)
TLV_TYPE_IFACE_NAME = tlv_custom_type(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 1)
TLV_TYPE_IFACE_MASK = tlv_custom_type(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 2)
TLV_TYPE_IFACE_GROUP = tlv_custom_type(TLV_TYPE_GROUP, TAB_BASE, API_TYPE)
TLV_TYPE_IFACE_INDEX = tlv_custom_type(TLV_TYPE_INT, TAB_BASE, API_TYPE)

TLV_TYPE_SNIFF_PKTS = tlv_custom_type(TLV_TYPE_INT, TAB_BASE, API_TYPE + 1)
TLV_TYPE_SNIFF_BYTES = tlv_custom_type(TLV_TYPE_INT, TAB_BASE, API_TYPE + 2)
TLV_TYPE_SNIFF_DROPS = tlv_custom_type(TLV_TYPE_INT, TAB_BASE, API_TYPE + 3)


# Fake Ethernet header (DLT_RAW → Raw IP) constants for PCAP
PCAP_MAGIC = 0xA1B2C3D4
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4
PCAP_LINKTYPE_RAW = 101  # DLT_RAW — raw IP, no link-layer header


def write_pcap_header(f):
    """Write a PCAP global header (DLT_RAW)."""
    f.write(struct.pack(
        '<IHHiIII',
        PCAP_MAGIC,
        PCAP_VERSION_MAJOR,
        PCAP_VERSION_MINOR,
        0,          # thiszone
        0,          # sigfigs
        65535,      # snaplen
        PCAP_LINKTYPE_RAW,
    ))


def write_pcap_packet(f, ts, data):
    """Write a single PCAP packet record."""
    sec = int(ts)
    usec = int((ts - sec) * 1_000_000)
    caplen = len(data)
    f.write(struct.pack('<IIII', sec, usec, caplen, caplen))
    f.write(data)


class HatSploitPlugin(Plugin):
    def __init__(self):
        super().__init__({
            'Name': "Sniffer Plugin",
            'Plugin': "sniffer",
            'Authors': [
                'EntySec - plugin developer',
            ],
            'Description': (
                "Capture network packets via raw sockets (SIO_RCVALL). "
                "Requires administrator privileges."
            ),
        })

        self.captures = {}

        self.commands = [
            Command({
                'Category': "gather",
                'Name': "sniffer",
                'Description': "Network packet sniffer.",
                'MinArgs': 1,
                'Options': [
                    (
                        ('-l', '--list'),
                        {
                            'help': "List available network interfaces.",
                            'action': 'store_true',
                        }
                    ),
                    (
                        ('-s', '--start'),
                        {
                            'help': "Start capture on interface IP.",
                            'metavar': 'IP',
                        }
                    ),
                    (
                        ('-c', '--close'),
                        {
                            'help': "Stop capture by interface IP.",
                            'metavar': 'IP',
                        }
                    ),
                    (
                        ('-L',),
                        {
                            'help': "List active captures.",
                            'dest': 'active',
                            'action': 'store_true',
                        }
                    ),
                    (
                        ('-d', '--dump'),
                        {
                            'help': "Dump captured packets to PCAP file.",
                            'metavar': 'IP',
                        }
                    ),
                    (
                        ('-o', '--output'),
                        {
                            'help': "Output file path for dump.",
                            'metavar': 'FILE',
                        }
                    ),
                    (
                        ('-n', '--count'),
                        {
                            'help': "Number of packets to capture (0 = continuous, default: 0).",
                            'type': int,
                            'default': 0,
                            'metavar': 'N',
                        }
                    ),
                ]
            })
        ]

    def _capture_thread(self, iface_ip):
        """Background thread: reads pipe and buffers raw IP packets."""

        while iface_ip in self.captures:
            cap = self.captures.get(iface_ip)
            if not cap:
                break

            try:
                data = self.session.pipes.read_pipe(
                    pipe_type=SNIFFER_PIPE,
                    pipe_id=cap['ID'],
                    size=65535,
                    plugin=self.plugin,
                )
            except Exception:
                break

            if not data or len(data) == 0:
                continue

            ts = time.time()

            # Parse length-prefixed packets: [4-byte BE length][raw IP]
            offset = 0
            while offset + 4 <= len(data):
                pktlen = struct.unpack_from('>I', data, offset)[0]
                offset += 4

                if pktlen == 0 or offset + pktlen > len(data):
                    break

                pkt = data[offset:offset + pktlen]
                offset += pktlen

                cap['Packets'].append((ts, pkt))
                cap['ByteCount'] += pktlen

                limit = cap.get('Limit', 0)
                if limit > 0 and len(cap['Packets']) >= limit:
                    return

    def sniffer(self, args):
        if args.list:
            self._list_interfaces()

        elif args.active:
            self._list_active()

        elif args.start:
            self._start_capture(args.start, args.count)

        elif args.close:
            self._stop_capture(args.close)

        elif args.dump:
            self._dump_capture(args.dump, args.output)

        else:
            self.print_usage()

    def _list_interfaces(self):
        self.print_process("Querying network interfaces...")

        result = self.session.send_command(
            tag=SNIFFER_LIST,
            plugin=self.plugin,
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error("Failed to query interfaces!")
            return

        headers = ("Index", "IP Address", "Netmask")
        data = []

        entry = result.get_tlv(TLV_TYPE_IFACE_GROUP)
        while entry:
            ip = entry.get_string(TLV_TYPE_IFACE_IP) or ''
            mask = entry.get_string(TLV_TYPE_IFACE_MASK) or ''
            idx = entry.get_int(TLV_TYPE_IFACE_INDEX) or 0

            data.append((str(idx), ip, mask))
            entry = result.get_tlv(TLV_TYPE_IFACE_GROUP)

        if not data:
            self.print_warning("No interfaces found.")
            return

        self.print_table("Network Interfaces", headers, *data)

    def _list_active(self):
        if not self.captures:
            self.print_warning("No active captures.")
            return

        headers = ("Interface", "Packets", "Bytes")
        data = []

        for ip, cap in self.captures.items():
            data.append((ip, str(len(cap['Packets'])), str(cap['ByteCount'])))

        self.print_table("Active Captures", headers, *data)

    def _start_capture(self, iface_ip, count):
        if iface_ip in self.captures:
            self.print_warning(f"Already capturing on {iface_ip}.")
            return

        self.print_process(f"Starting capture on {iface_ip}...")

        try:
            pipe_id = self.session.pipes.create_pipe(
                pipe_type=SNIFFER_PIPE,
                args={
                    TLV_TYPE_IFACE_IP: iface_ip,
                },
                plugin=self.plugin,
            )
        except RuntimeError:
            self.print_error(
                f"Failed to start capture on {iface_ip}! "
                "Ensure you have administrator privileges."
            )
            return

        cap = {
            'ID': pipe_id,
            'Packets': [],
            'ByteCount': 0,
            'Limit': count,
        }
        self.captures[iface_ip] = cap

        thread = threading.Thread(
            target=self._capture_thread,
            args=(iface_ip,),
        )
        thread.daemon = True
        thread.start()
        cap['Thread'] = thread

        if count > 0:
            self.print_success(
                f"Capturing up to {count} packets on {iface_ip}."
            )
        else:
            self.print_success(f"Capturing on {iface_ip}.")

    def _stop_capture(self, iface_ip):
        cap = self.captures.get(iface_ip)
        if not cap:
            self.print_error(f"No active capture on {iface_ip}.")
            return

        self.print_process(f"Stopping capture on {iface_ip}...")

        pkt_count = len(cap['Packets'])

        # Remove first so the thread exits its loop
        self.captures.pop(iface_ip, None)

        try:
            self.session.pipes.destroy_pipe(
                SNIFFER_PIPE, cap['ID'], plugin=self.plugin
            )
        except RuntimeError:
            pass

        self.print_success(
            f"Stopped. {pkt_count} packets captured ({cap['ByteCount']} bytes)."
        )

    def _dump_capture(self, iface_ip, output):
        cap = self.captures.get(iface_ip)
        if not cap:
            self.print_error(f"No active capture on {iface_ip}.")
            return

        packets = list(cap['Packets'])
        if not packets:
            self.print_warning("No packets captured yet.")
            return

        output = output or self.session.loot.random_loot('pcap')

        try:
            with open(output, 'wb') as f:
                write_pcap_header(f)
                for ts, pkt in packets:
                    write_pcap_packet(f, ts, pkt)

            self.print_success(
                f"Dumped {len(packets)} packets to {output}"
            )
        except Exception as e:
            self.print_error(f"Failed to write PCAP: {e}")

    def load(self):
        pass
