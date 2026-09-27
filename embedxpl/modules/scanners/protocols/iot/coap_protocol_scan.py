# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""CoAP Protocol Scanner - Resource Discovery, DTLS Check, Observe Support.

Probes Constrained Application Protocol (CoAP) endpoints for available
resources via /.well-known/core, checks DTLS support, and tests the
Observe option for subscription-based monitoring.

References:
  - RFC 7252 (CoAP)
  - RFC 6690 (CoRE Link Format)
  - RFC 7641 (Observe)

Version: 1.0.0
"""

import socket
import struct
import time

from embedxpl.core.exploit import *


_COAP_VERSION = 1
_TYPE_CON = 0
_TYPE_ACK = 2
_CODE_GET = (0, 1)
_OPT_URI_PATH = 11
_OPT_CONTENT_FORMAT = 12
_OPT_OBSERVE = 6
_CONTENT_LINK_FORMAT = 40


class Exploit(Exploit):
    """CoAP Protocol Scanner.

    Discovers CoAP resources via /.well-known/core, checks DTLS
    availability on port 5684, and tests Observe subscription support.

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "CoAP Protocol Scanner",
        "description": (
            "Probes CoAP endpoints using UDP/5683 to discover resources via "
            "/.well-known/core (RFC 6690), test DTLS on port 5684, and verify "
            "Observe option (RFC 7641) support for event subscriptions."
        ),
        "authors": ("Andre Henrique (@mrhenrike)",),
        "references": (
            "https://www.rfc-editor.org/rfc/rfc7252",
            "https://www.rfc-editor.org/rfc/rfc6690",
            "https://www.rfc-editor.org/rfc/rfc7641",
        ),
        "devices": ("CoAP Servers", "Eclipse Californium", "libcoap", "Zephyr CoAP"),
        "severity": "info",
        "mitre": ["T0846"],
        "status": "confirmed",
    }

    target = OptIP("", "Target CoAP server IP")
    port = OptPort(5683, "CoAP UDP port")
    dtls_port = OptPort(5684, "CoAP DTLS port")
    timeout = OptInteger(5, "Socket timeout in seconds")

    _msg_id = 0

    def _next_msg_id(self) -> int:
        self._msg_id = (self._msg_id + 1) & 0xFFFF
        return self._msg_id

    def _build_header(self, msg_type: int, code_class: int, code_detail: int,
                      msg_id: int, token: bytes = b"") -> bytes:
        """Build CoAP message header (4 bytes + token)."""
        tkl = len(token)
        byte0 = (_COAP_VERSION << 6) | (msg_type << 4) | (tkl & 0x0F)
        byte1 = ((code_class & 0x07) << 5) | (code_detail & 0x1F)
        header = struct.pack(">BBH", byte0, byte1, msg_id) + token
        return header

    def _encode_option(self, delta: int, value: bytes) -> bytes:
        """Encode a single CoAP option."""
        ext_delta = b""
        if delta < 13:
            d = delta
        elif delta < 269:
            d = 13
            ext_delta = struct.pack(">B", delta - 13)
        else:
            d = 14
            ext_delta = struct.pack(">H", delta - 269)

        length = len(value)
        ext_len = b""
        if length < 13:
            l_field = length
        elif length < 269:
            l_field = 13
            ext_len = struct.pack(">B", length - 13)
        else:
            l_field = 14
            ext_len = struct.pack(">H", length - 269)

        return struct.pack(">B", (d << 4) | l_field) + ext_delta + ext_len + value

    def _build_get(self, uri_path_segments: list, observe: bool = False) -> bytes:
        """Build a CoAP GET request with URI-Path options."""
        token = struct.pack(">H", self._next_msg_id())
        header = self._build_header(_TYPE_CON, _CODE_GET[0], _CODE_GET[1],
                                    self._next_msg_id(), token)
        options = b""
        prev_opt = 0
        if observe:
            options += self._encode_option(_OPT_OBSERVE - prev_opt, b"\x00")
            prev_opt = _OPT_OBSERVE

        for seg in uri_path_segments:
            delta = _OPT_URI_PATH - prev_opt
            options += self._encode_option(delta, seg.encode("utf-8"))
            prev_opt = _OPT_URI_PATH

        return header + options

    def _send_coap(self, packet: bytes) -> bytes:
        """Send CoAP request via UDP and wait for response."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(float(self.timeout))
            sock.sendto(packet, (self.target, int(self.port)))
            data, _ = sock.recvfrom(4096)
            sock.close()
            return data
        except (socket.error, OSError):
            return b""

    def _parse_response_code(self, data: bytes) -> tuple:
        """Extract response code class and detail."""
        if len(data) < 4:
            return (0, 0)
        code_byte = data[1]
        return ((code_byte >> 5) & 0x07, code_byte & 0x1F)

    def _parse_payload(self, data: bytes) -> str:
        """Extract payload after the 0xFF marker."""
        if len(data) < 4:
            return ""
        tkl = data[0] & 0x0F
        offset = 4 + tkl
        while offset < len(data):
            if data[offset] == 0xFF:
                return data[offset + 1:].decode("utf-8", errors="replace")
            opt_delta = (data[offset] >> 4) & 0x0F
            opt_len = data[offset] & 0x0F
            offset += 1
            if opt_delta == 13:
                offset += 1
            elif opt_delta == 14:
                offset += 2
            if opt_len == 13:
                opt_len = data[offset] + 13 if offset < len(data) else 0
                offset += 1
            elif opt_len == 14:
                opt_len = struct.unpack(">H", data[offset:offset + 2])[0] + 269 if offset + 2 <= len(data) else 0
                offset += 2
            offset += opt_len
        return ""

    def _parse_link_format(self, payload: str) -> list:
        """Parse CoRE Link Format into list of resource dicts."""
        resources = []
        for entry in payload.split(","):
            entry = entry.strip()
            if not entry:
                continue
            parts = entry.split(";")
            uri = parts[0].strip("<>")
            attrs = {}
            for attr in parts[1:]:
                if "=" in attr:
                    k, v = attr.split("=", 1)
                    attrs[k.strip()] = v.strip('"')
            resources.append({"uri": uri, "attrs": attrs})
        return resources

    def _discover_resources(self) -> list:
        """Discover resources via /.well-known/core."""
        pkt = self._build_get([".well-known", "core"])
        resp = self._send_coap(pkt)
        if not resp:
            return []
        code_class, code_detail = self._parse_response_code(resp)
        if code_class != 2:
            return []
        payload = self._parse_payload(resp)
        return self._parse_link_format(payload)

    def _check_dtls(self) -> bool:
        """Check if DTLS port responds to a ClientHello-like probe."""
        probe = b"\x16\x01\x00\x00\x00\x00\x00\x00\x00\x00"
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(float(self.timeout))
            sock.sendto(probe, (self.target, int(self.dtls_port)))
            data, _ = sock.recvfrom(1024)
            sock.close()
            return len(data) > 0
        except (socket.error, OSError):
            return False

    def _check_observe(self, resource_uri: str) -> bool:
        """Test Observe option on a resource."""
        segments = [s for s in resource_uri.split("/") if s]
        pkt = self._build_get(segments, observe=True)
        resp = self._send_coap(pkt)
        if not resp or len(resp) < 4:
            return False
        code_class, _ = self._parse_response_code(resp)
        return code_class == 2

    @mute
    def check(self) -> bool:
        """Verify CoAP port is reachable via empty GET."""
        pkt = self._build_get([".well-known", "core"])
        resp = self._send_coap(pkt)
        return len(resp) > 0

    @multi
    def run(self) -> None:
        """Execute CoAP protocol scan."""
        print_status("Scanning CoAP endpoint at {}:{}".format(self.target, self.port))

        if not self.check():
            print_error("CoAP port {} not reachable".format(self.port))
            return

        print_success("CoAP port {} responsive".format(self.port))

        resources = self._discover_resources()
        if resources:
            print_success("Discovered {} resource(s):".format(len(resources)))
            for r in resources:
                rt = r["attrs"].get("rt", "")
                ct = r["attrs"].get("ct", "")
                extra = ""
                if rt:
                    extra += " rt={}".format(rt)
                if ct:
                    extra += " ct={}".format(ct)
                print_info("  {}{}".format(r["uri"], extra))
        else:
            print_warning("No resources discovered via /.well-known/core")

        dtls_ok = self._check_dtls()
        if dtls_ok:
            print_success("DTLS port {} responsive".format(self.dtls_port))
        else:
            print_warning("DTLS port {} not reachable".format(self.dtls_port))

        if resources:
            test_uri = resources[0]["uri"]
            observe_ok = self._check_observe(test_uri)
            if observe_ok:
                print_success("Observe option supported on {}".format(test_uri))
            else:
                print_info("Observe option not supported or denied on {}".format(test_uri))
