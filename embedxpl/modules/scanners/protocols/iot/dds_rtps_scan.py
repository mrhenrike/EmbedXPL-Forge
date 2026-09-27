# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""DDS RTPS Participant Discovery and Topic Enumeration Scanner.

Discovers DDS (Data Distribution Service) participants via RTPS
(Real-Time Publish-Subscribe) Simple Participant Discovery Protocol
(SPDP) on multicast, and enumerates published/subscribed topics.

References:
  - OMG DDS v1.4 Specification
  - OMG RTPS v2.3 Wire Protocol

Version: 1.0.0
"""

import socket
import struct
import time

from embedxpl.core.exploit import *


_RTPS_MAGIC = b"RTPS"
_RTPS_VERSION_23 = (2, 3)
_RTPS_VERSION_22 = (2, 2)

_SPDP_MULTICAST_ADDR = "239.255.0.1"
_SPDP_BASE_PORT = 7400
_PB = 7400
_DG = 250
_PG = 2
_D0 = 0
_D1 = 10

_SUBMSG_DATA = 0x15
_SUBMSG_INFO_TS = 0x09
_SUBMSG_HEARTBEAT = 0x07

_PID_PARTICIPANT_NAME = 0x0034
_PID_DEFAULT_UNICAST_LOCATOR = 0x0031
_PID_METATRAFFIC_UNICAST_LOCATOR = 0x0032
_PID_TOPIC_NAME = 0x0005
_PID_TYPE_NAME = 0x0007
_PID_ENDPOINT_GUID = 0x005A
_PID_VENDOR_ID = 0x0016
_PID_PROTOCOL_VERSION = 0x0015
_PID_SENTINEL = 0x0001

_VENDOR_IDS = {
    (0x01, 0x01): "RTI Connext DDS",
    (0x01, 0x02): "OpenDDS (OCI)",
    (0x01, 0x03): "OpenSplice (ADLINK)",
    (0x01, 0x0F): "eProsima Fast DDS",
    (0x01, 0x10): "Eclipse Cyclone DDS",
    (0x01, 0x12): "GurumNetworks GurumDDS",
}


class Exploit(Exploit):
    """DDS RTPS Participant Discovery and Topic Enumeration Scanner.

    Joins SPDP multicast to discover DDS participants and enumerate
    topics, types, and vendor information from RTPS wire protocol.

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "DDS RTPS Participant Discovery Scanner",
        "description": (
            "Discovers DDS participants via RTPS SPDP multicast on 239.255.0.1, "
            "enumerates published/subscribed topics, type names, and identifies "
            "DDS vendor implementations (RTI, FastDDS, CycloneDDS, etc.)."
        ),
        "authors": ("Andre Henrique (@mrhenrike)",),
        "references": (
            "https://www.omg.org/spec/DDSI-RTPS/2.3/",
            "https://www.omg.org/spec/DDS/1.4/",
        ),
        "devices": ("DDS Participants", "Industrial DDS Nodes", "ROS2 Nodes"),
        "severity": "info",
        "mitre": ["T0846"],
        "status": "confirmed",
    }

    target = OptIP("", "Target IP (for unicast probe, empty for multicast discovery)")
    port = OptPort(7400, "RTPS discovery base port")
    timeout = OptInteger(10, "Discovery listen duration in seconds")
    domain_id = OptInteger(0, "DDS Domain ID")

    def _discovery_port(self) -> int:
        """Calculate SPDP discovery multicast port for the given domain."""
        return _PB + _DG * int(self.domain_id) + _D0

    def _build_spdp_request(self) -> bytes:
        """Build minimal RTPS SPDP participant announcement probe."""
        guid_prefix = struct.pack(">III", 0xE0F00001, 0x00000000, int(time.time()) & 0xFFFFFFFF)
        header = _RTPS_MAGIC + struct.pack(">BB", 2, 3)
        header += struct.pack(">HH", 0x010F, 0x0000)
        header += guid_prefix
        submsg_flags = 0x05
        inline_qos_flag = 0x02
        data_flag = 0x04
        submsg = struct.pack(
            "<BBH", _SUBMSG_DATA, submsg_flags | inline_qos_flag | data_flag, 0
        )
        entity_id_reader = struct.pack(">I", 0x000001C1)
        entity_id_writer = struct.pack(">I", 0x000100C2)
        submsg += struct.pack(">HH", 0, 0)
        submsg += entity_id_reader + entity_id_writer
        sn = struct.pack(">II", 0, 1)
        submsg += sn
        submsg_len = len(submsg) - 4
        submsg = submsg[:2] + struct.pack("<H", submsg_len) + submsg[4:]
        return header + submsg

    def _join_multicast(self) -> socket.socket:
        """Join SPDP multicast group for discovery."""
        disc_port = self._discovery_port()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", disc_port))
        mreq = socket.inet_aton(_SPDP_MULTICAST_ADDR) + socket.inet_aton("0.0.0.0")
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        sock.settimeout(2.0)
        return sock

    def _parse_rtps_header(self, data: bytes) -> dict:
        """Parse RTPS message header."""
        if len(data) < 20 or data[:4] != _RTPS_MAGIC:
            return {}
        version = (data[4], data[5])
        vendor = (data[6], data[7])
        guid_prefix = data[8:20]
        return {
            "version": "{}.{}".format(version[0], version[1]),
            "vendor": _VENDOR_IDS.get(vendor, "Unknown ({},{})".format(vendor[0], vendor[1])),
            "vendor_raw": vendor,
            "guid_prefix": guid_prefix.hex(),
        }

    def _parse_parameter_list(self, data: bytes) -> dict:
        """Parse RTPS serialized parameter list (PID/length/value)."""
        params = {}
        offset = 0
        while offset + 4 <= len(data):
            pid = struct.unpack("<H", data[offset:offset + 2])[0]
            length = struct.unpack("<H", data[offset + 2:offset + 4])[0]
            if pid == _PID_SENTINEL:
                break
            if offset + 4 + length > len(data):
                break
            value = data[offset + 4:offset + 4 + length]

            if pid == _PID_PARTICIPANT_NAME:
                str_len = struct.unpack("<I", value[:4])[0] if len(value) >= 4 else 0
                if str_len > 0 and 4 + str_len <= len(value):
                    params["participant_name"] = value[4:4 + str_len - 1].decode(
                        "utf-8", errors="replace"
                    )
            elif pid == _PID_TOPIC_NAME:
                str_len = struct.unpack("<I", value[:4])[0] if len(value) >= 4 else 0
                if str_len > 0 and 4 + str_len <= len(value):
                    topic = value[4:4 + str_len - 1].decode("utf-8", errors="replace")
                    params.setdefault("topics", []).append(topic)
            elif pid == _PID_TYPE_NAME:
                str_len = struct.unpack("<I", value[:4])[0] if len(value) >= 4 else 0
                if str_len > 0 and 4 + str_len <= len(value):
                    tname = value[4:4 + str_len - 1].decode("utf-8", errors="replace")
                    params.setdefault("types", []).append(tname)
            elif pid == _PID_DEFAULT_UNICAST_LOCATOR:
                if len(value) >= 24:
                    kind = struct.unpack("<I", value[0:4])[0]
                    loc_port = struct.unpack("<I", value[4:8])[0]
                    if kind == 1:
                        ip_bytes = value[20:24]
                        ip_str = ".".join(str(b) for b in ip_bytes)
                        params["unicast_locator"] = "{}:{}".format(ip_str, loc_port)

            offset += 4 + length
            if length % 4 != 0:
                offset += 4 - (length % 4)
        return params

    def _parse_data_submessage(self, data: bytes, offset: int) -> dict:
        """Parse a DATA submessage to extract inline QoS and serialized data."""
        if offset + 24 > len(data):
            return {}
        extra_flags = struct.unpack("<H", data[offset:offset + 2])[0]
        octets_to_inline = struct.unpack("<H", data[offset + 2:offset + 4])[0]
        reader_id = data[offset + 4:offset + 8]
        writer_id = data[offset + 8:offset + 12]
        payload_offset = offset + 20 + octets_to_inline
        if payload_offset + 4 > len(data):
            return {}
        encaps = data[payload_offset:payload_offset + 4]
        param_data = data[payload_offset + 4:]
        return self._parse_parameter_list(param_data)

    def _collect_participants(self, sock: socket.socket, duration: float) -> list:
        """Collect SPDP announcements for the given duration."""
        participants = {}
        deadline = time.time() + duration
        while time.time() < deadline:
            try:
                data, addr = sock.recvfrom(65535)
                header = self._parse_rtps_header(data)
                if not header:
                    continue
                guid = header["guid_prefix"]
                if guid in participants:
                    continue

                entry = {
                    "source_ip": addr[0],
                    "source_port": addr[1],
                    "version": header["version"],
                    "vendor": header["vendor"],
                    "guid_prefix": guid,
                    "participant_name": "",
                    "topics": [],
                    "types": [],
                }

                offset = 20
                while offset + 4 <= len(data):
                    submsg_id = data[offset]
                    submsg_flags = data[offset + 1]
                    submsg_len = struct.unpack("<H", data[offset + 2:offset + 4])[0]
                    if submsg_id == _SUBMSG_DATA:
                        params = self._parse_data_submessage(data, offset + 4)
                        if params.get("participant_name"):
                            entry["participant_name"] = params["participant_name"]
                        if params.get("topics"):
                            entry["topics"].extend(params["topics"])
                        if params.get("types"):
                            entry["types"].extend(params["types"])
                        if params.get("unicast_locator"):
                            entry["unicast_locator"] = params["unicast_locator"]
                    offset += 4 + submsg_len
                    if submsg_len == 0:
                        break

                participants[guid] = entry
            except socket.timeout:
                continue
            except (socket.error, OSError):
                break
        return list(participants.values())

    @mute
    def check(self) -> bool:
        """Verify multicast discovery port is bindable."""
        try:
            sock = self._join_multicast()
            sock.close()
            return True
        except (socket.error, OSError):
            return False

    @multi
    def run(self) -> None:
        """Execute DDS RTPS participant discovery."""
        disc_port = self._discovery_port()
        print_status("Scanning DDS Domain {} (multicast {}:{}, {} seconds)".format(
            self.domain_id, _SPDP_MULTICAST_ADDR, disc_port, self.timeout
        ))

        try:
            sock = self._join_multicast()
        except (socket.error, OSError) as exc:
            print_error("Cannot join multicast: {}".format(exc))
            return

        try:
            participants = self._collect_participants(sock, float(self.timeout))
        finally:
            sock.close()

        if not participants:
            print_warning("No DDS participants discovered")
            return

        print_success("Discovered {} DDS participant(s)".format(len(participants)))
        for p in participants:
            name = p["participant_name"] or "(unnamed)"
            print_info("Participant: {} [{}]".format(name, p["vendor"]))
            print_info("  Source: {}:{}".format(p["source_ip"], p["source_port"]))
            print_info("  GUID prefix: {}".format(p["guid_prefix"]))
            print_info("  RTPS version: {}".format(p["version"]))
            if p.get("unicast_locator"):
                print_info("  Unicast locator: {}".format(p["unicast_locator"]))
            if p["topics"]:
                print_info("  Topics ({}):".format(len(p["topics"])))
                for i, topic in enumerate(p["topics"]):
                    ttype = p["types"][i] if i < len(p["types"]) else ""
                    suffix = " [{}]".format(ttype) if ttype else ""
                    print_info("    {}{}".format(topic, suffix))
