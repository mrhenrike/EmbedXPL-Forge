# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""OPC UA GetEndpoints Scanner.

Discovers OPC UA server endpoints using the binary Hello + OpenSecureChannel
+ GetEndpoints sequence. Lists available endpoints, security policies,
authentication modes, and server application descriptions. Port 4840.

Constructs OPC UA binary-encoded messages via struct.pack.

References:
  - OPC UA Specification Part 4: Services
  - OPC UA Specification Part 6: Mappings

Version: 1.0.0
"""

import socket
import struct
import time

from embedxpl.core.exploit import *


class Exploit(Exploit):
    """OPC UA GetEndpoints Scanner.

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "OPC UA GetEndpoints Scanner",
        "description": (
            "Discovers OPC UA endpoints via binary Hello + OpenSecureChannel "
            "+ GetEndpoints sequence. Lists security policies, message security "
            "modes, and user token types. Identifies anonymous access, "
            "certificate-based, and username/password authentication options."
        ),
        "authors": ("Andre Henrique (@mrhenrike)",),
        "references": (
            "https://opcfoundation.org/developer-tools/specifications-unified-architecture",
        ),
        "devices": (
            "Siemens S7-1500 OPC UA",
            "Beckhoff TwinCAT",
            "Kepware KEPServerEX",
            "Unified Automation servers",
            "Prosys OPC UA",
            "Ignition OPC UA",
        ),
        "severity": "info",
        "mitre": ["T0846"],
        "status": "confirmed",
    }

    target = OptIP("", "Target OPC UA server IP")
    port = OptPort(4840, "OPC UA binary protocol port")
    timeout = OptInteger(8, "Socket timeout in seconds")

    # OPC UA message types
    _HEL = b"HEL"
    _ACK = b"ACK"
    _OPN = b"OPN"
    _MSG = b"MSG"
    _ERR = b"ERR"

    # Security policies
    _SECURITY_POLICIES = {
        "http://opcfoundation.org/UA/SecurityPolicy#None": "None",
        "http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15": "Basic128Rsa15 (deprecated)",
        "http://opcfoundation.org/UA/SecurityPolicy#Basic256": "Basic256 (deprecated)",
        "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256": "Basic256Sha256",
        "http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep": "Aes128-Sha256-RsaOaep",
        "http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss": "Aes256-Sha256-RsaPss",
    }

    _MSG_SECURITY_MODES = {
        1: "None",
        2: "Sign",
        3: "SignAndEncrypt",
    }

    _TOKEN_TYPES = {
        0: "Anonymous",
        1: "UserName",
        2: "Certificate",
        3: "IssuedToken",
    }

    def _encode_string(self, s: str) -> bytes:
        """Encode OPC UA String (int32 length prefix + UTF-8)."""
        if not s:
            return struct.pack("<i", -1)
        encoded = s.encode("utf-8")
        return struct.pack("<i", len(encoded)) + encoded

    def _build_hello(self) -> bytes:
        """Build OPC UA Hello message."""
        url = "opc.tcp://{}:{}".format(self.target, self.port)
        url_bytes = url.encode("utf-8")

        body = struct.pack("<IIIII",
            0, 65535, 65535, 0, 0,
        )
        body += struct.pack("<I", len(url_bytes)) + url_bytes

        return self._HEL + b"F" + struct.pack("<I", 8 + len(body)) + body

    def _build_open_channel(self) -> bytes:
        """Build OpenSecureChannel with SecurityPolicy None."""
        policy = "http://opcfoundation.org/UA/SecurityPolicy#None"
        policy_bytes = policy.encode("utf-8")

        sec_header = struct.pack("<I", len(policy_bytes)) + policy_bytes
        sec_header += struct.pack("<i", -1)  # no sender cert
        sec_header += struct.pack("<i", -1)  # no receiver thumbprint

        seq = struct.pack("<II", 1, 1)

        # OpenSecureChannelRequest NodeId: ns=0, id=446
        node_id = struct.pack("<BHH", 0x01, 0x00, 446)

        # Request header
        req = struct.pack("<BB", 0x00, 0x00)  # null auth token
        req += struct.pack("<q", int(time.time() * 10000000) + 116444736000000000)
        req += struct.pack("<I", 1)  # request handle
        req += struct.pack("<I", 0)  # diagnostics
        req += self._encode_string("")  # audit
        req += struct.pack("<I", 10000)  # timeout
        req += struct.pack("<BBB", 0x00, 0x00, 0x00)  # null ext obj

        body = struct.pack("<I", 0)  # client proto version
        body += struct.pack("<I", 0)  # issue request
        body += struct.pack("<I", 1)  # msg security mode: None
        body += struct.pack("<i", 32) + (b"\x00" * 32)  # nonce
        body += struct.pack("<I", 3600000)  # lifetime

        payload = sec_header + seq + node_id + req + body
        header = self._OPN + b"F" + struct.pack("<II", 8 + len(payload) + 4, 0)
        return header + payload

    def _build_get_endpoints(self, channel_id: int, token_id: int) -> bytes:
        """Build GetEndpoints request."""
        sec_header = struct.pack("<I", token_id)
        seq = struct.pack("<II", 2, 2)

        # GetEndpoints NodeId: ns=0, id=428
        node_id = struct.pack("<BHH", 0x01, 0x00, 428)

        req = struct.pack("<BB", 0x00, 0x00)
        req += struct.pack("<q", int(time.time() * 10000000) + 116444736000000000)
        req += struct.pack("<I", 2)
        req += struct.pack("<I", 0)
        req += self._encode_string("")
        req += struct.pack("<I", 10000)
        req += struct.pack("<BBB", 0x00, 0x00, 0x00)

        url = "opc.tcp://{}:{}".format(self.target, self.port)
        body = self._encode_string(url)
        body += struct.pack("<i", -1)  # locale IDs (null array)
        body += struct.pack("<i", -1)  # profile URIs (null array)

        payload = sec_header + seq + node_id + req + body
        header = self._MSG + b"F" + struct.pack("<II", 8 + len(payload) + 4, channel_id)
        return header + payload

    def _recv_msg(self, sock: socket.socket) -> bytes:
        """Receive complete OPC UA message."""
        buf = b""
        while len(buf) < 8:
            chunk = sock.recv(8 - len(buf))
            if not chunk:
                return b""
            buf += chunk

        msg_size = struct.unpack_from("<I", buf, 4)[0]
        while len(buf) < msg_size:
            chunk = sock.recv(min(msg_size - len(buf), 8192))
            if not chunk:
                break
            buf += chunk
        return buf

    def _parse_endpoints(self, data: bytes) -> list:
        """Parse GetEndpoints response to extract endpoint descriptions."""
        endpoints = []

        # Decode readable strings from the binary response
        raw = data[24:] if len(data) > 24 else data
        text = raw.decode("utf-8", errors="replace")

        # Extract security policy URIs
        for uri, name in self._SECURITY_POLICIES.items():
            if uri in text:
                ep = {"security_policy": name, "policy_uri": uri}

                # Find associated message security mode near this policy
                idx = text.find(uri)
                region = raw[max(0, idx - 50):idx + len(uri) + 100]
                for off in range(len(region) - 4):
                    val = struct.unpack_from("<I", region, off)[0]
                    if val in self._MSG_SECURITY_MODES:
                        ep["msg_security_mode"] = self._MSG_SECURITY_MODES[val]
                        break

                # Look for token types
                tokens = []
                for t_val, t_name in self._TOKEN_TYPES.items():
                    # Token type encoded as int32 near policy data
                    check = struct.pack("<I", t_val)
                    if check in region:
                        tokens.append(t_name)
                if tokens:
                    ep["user_tokens"] = tokens

                endpoints.append(ep)

        # Deduplicate
        seen = set()
        unique = []
        for ep in endpoints:
            key = ep.get("security_policy", "") + ep.get("msg_security_mode", "")
            if key not in seen:
                seen.add(key)
                unique.append(ep)

        return unique

    @mute
    def check(self) -> bool:
        """Verify OPC UA server responds to Hello."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(float(self.timeout))
            sock.connect((self.target, self.port))
            sock.sendall(self._build_hello())
            resp = self._recv_msg(sock)
            sock.close()
            return bool(resp and resp[:3] == self._ACK)
        except (socket.error, OSError):
            return False

    def run(self) -> None:
        """Discover OPC UA endpoints and security configuration."""
        print_status(
            "OPC UA endpoint scan on {}:{}".format(self.target, self.port)
        )

        if not self.check():
            print_error("OPC UA server not responding")
            return

        print_success("OPC UA server acknowledged Hello")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(float(self.timeout))
            sock.connect((self.target, self.port))

            # Hello
            sock.sendall(self._build_hello())
            ack = self._recv_msg(sock)
            if not ack or ack[:3] != self._ACK:
                print_error("No ACK")
                sock.close()
                return

            # Server capabilities from ACK
            if len(ack) >= 28:
                print_info("Server buffer: recv={}, send={}".format(
                    struct.unpack_from("<I", ack, 12)[0],
                    struct.unpack_from("<I", ack, 16)[0],
                ))

            # OpenSecureChannel
            print_info("Opening channel (SecurityPolicy#None)...")
            sock.sendall(self._build_open_channel())
            osc = self._recv_msg(sock)

            if not osc or osc[:3] != self._OPN:
                if osc and osc[:3] == self._ERR:
                    err_code = struct.unpack_from("<I", osc, 8)[0] if len(osc) > 12 else 0
                    print_error("Server error: 0x{:08X}".format(err_code))
                else:
                    print_error("OpenSecureChannel failed")
                sock.close()
                return

            channel_id = struct.unpack_from("<I", osc, 8)[0]
            token_id = 1
            if len(osc) > 60:
                token_id = struct.unpack_from("<I", osc, 56)[0]
            print_success("Channel opened (ID: {})".format(channel_id))

            # GetEndpoints
            print_info("Requesting endpoint descriptions...")
            sock.sendall(self._build_get_endpoints(channel_id, token_id))
            ep_resp = self._recv_msg(sock)

            if ep_resp and len(ep_resp) > 24:
                print_success(
                    "GetEndpoints response: {} bytes".format(len(ep_resp))
                )
                endpoints = self._parse_endpoints(ep_resp)

                if endpoints:
                    print_success("{} endpoint(s) discovered:".format(len(endpoints)))
                    for i, ep in enumerate(endpoints):
                        print_info("  Endpoint {}:".format(i + 1))
                        print_info("    Security Policy: {}".format(
                            ep.get("security_policy", "unknown")
                        ))
                        print_info("    Message Mode: {}".format(
                            ep.get("msg_security_mode", "unknown")
                        ))
                        tokens = ep.get("user_tokens", [])
                        if tokens:
                            print_info("    Auth Tokens: {}".format(", ".join(tokens)))
                        if "Anonymous" in tokens:
                            print_success("    [!] Anonymous access available")
                else:
                    print_info("Could not parse endpoint details from response")
            else:
                print_error("No GetEndpoints response")

            sock.close()

        except socket.error as exc:
            print_error("Connection error: {}".format(exc))
