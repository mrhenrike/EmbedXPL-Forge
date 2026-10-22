# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""SIP endpoint scanner via OPTIONS/INVITE probes.

Discovers SIP-enabled devices on a target network by sending SIP OPTIONS
requests and analyzing responses. Identifies device type, firmware version,
supported methods, and potential misconfigurations.

References:
  - RFC 3261: SIP: Session Initiation Protocol
  - OWASP VoIP Security Testing Guide

Version: 1.0.0
"""

import random
import socket
import string

from embedxpl.core.exploit import (
    OptIP, OptPort, OptBool, OptString,
    print_success, print_error, print_status, print_info,
)


class Exploit:
    """SIP endpoint scanner.

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "SIP Endpoint Scanner",
        "description": (
            "Discovers SIP endpoints by sending OPTIONS requests and "
            "parsing responses. Identifies device type, firmware, supported "
            "SIP methods and potential misconfigurations."
        ),
        "authors": ("Andre Henrique (@mrhenrike) | Uniao Geek",),
        "references": (
            "https://www.rfc-editor.org/rfc/rfc3261",
        ),
        "devices": ("SIP-enabled VoIP devices",),
    }

    target = OptIP("", "Target IP")
    port = OptPort(5060, "SIP port")
    ssl = OptBool(False, "Use TLS (port 5061)")
    transport = OptString("udp", "Transport protocol (udp/tcp)")

    def _generate_call_id(self) -> str:
        chars = string.ascii_lowercase + string.digits
        return "".join(random.choices(chars, k=32))

    def _generate_branch(self) -> str:
        chars = string.ascii_lowercase + string.digits
        return "z9hG4bK" + "".join(random.choices(chars, k=16))

    def _build_options_request(self, local_ip: str) -> str:
        call_id = self._generate_call_id()
        branch = self._generate_branch()
        tag = "".join(random.choices(string.digits, k=8))

        return (
            "OPTIONS sip:100@{target}:{port} SIP/2.0\r\n"
            "Via: SIP/2.0/{transport} {local}:5060;branch={branch};rport\r\n"
            "Max-Forwards: 70\r\n"
            "From: <sip:scanner@{local}>;tag={tag}\r\n"
            "To: <sip:100@{target}>\r\n"
            "Call-ID: {callid}@{local}\r\n"
            "CSeq: 1 OPTIONS\r\n"
            "Contact: <sip:scanner@{local}:5060>\r\n"
            "Accept: application/sdp\r\n"
            "Content-Length: 0\r\n"
            "\r\n"
        ).format(
            target=self.target,
            port=self.port,
            transport=self.transport.upper(),
            local=local_ip,
            branch=branch,
            tag=tag,
            callid=call_id,
        )

    def _get_local_ip(self) -> str:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect((str(self.target), int(self.port)))
            ip = sock.getsockname()[0]
            sock.close()
            return ip
        except OSError:
            return "127.0.0.1"

    def _parse_sip_response(self, data: str) -> dict[str, str]:
        result: dict[str, str] = {}
        lines = data.split("\r\n")
        if lines:
            result["status_line"] = lines[0]
            parts = lines[0].split(" ", 2)
            if len(parts) >= 2:
                result["status_code"] = parts[1]
            if len(parts) >= 3:
                result["reason"] = parts[2]

        for line in lines[1:]:
            if ":" in line:
                key, _, value = line.partition(":")
                key = key.strip().lower()
                value = value.strip()
                if key == "user-agent":
                    result["user_agent"] = value
                elif key == "server":
                    result["server"] = value
                elif key == "allow":
                    result["allow"] = value
                elif key == "supported":
                    result["supported"] = value
                elif key == "www-authenticate":
                    result["www_authenticate"] = value

        return result

    def run(self) -> None:
        port = 5061 if self.ssl else int(self.port)
        proto = str(self.transport).lower()

        print_status(
            "Scanning SIP endpoint at {}:{} ({})".format(self.target, port, proto)
        )

        local_ip = self._get_local_ip()
        request = self._build_options_request(local_ip)

        try:
            if proto == "udp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            sock.settimeout(5)

            if proto == "tcp":
                sock.connect((str(self.target), port))
                sock.sendall(request.encode())
            else:
                sock.sendto(request.encode(), (str(self.target), port))

            data, _ = sock.recvfrom(4096) if proto == "udp" else (sock.recv(4096), None)
            sock.close()

        except socket.timeout:
            print_error("No SIP response (timeout)")
            return
        except OSError as e:
            print_error("Connection error: {}".format(e))
            return

        response = data.decode("utf-8", errors="replace")
        parsed = self._parse_sip_response(response)

        status = parsed.get("status_code", "?")
        print_success("SIP response received: {} {}".format(
            status, parsed.get("reason", "")
        ))

        if "user_agent" in parsed:
            print_info("User-Agent: {}".format(parsed["user_agent"]))
        if "server" in parsed:
            print_info("Server: {}".format(parsed["server"]))
        if "allow" in parsed:
            print_info("Allowed methods: {}".format(parsed["allow"]))
            methods = parsed["allow"].upper()
            if "REGISTER" in methods:
                print_success("REGISTER method allowed (registration attacks possible)")
            if "INVITE" in methods:
                print_info("INVITE method allowed (call initiation possible)")
        if "supported" in parsed:
            print_info("Supported: {}".format(parsed["supported"]))
        if "www_authenticate" in parsed:
            print_info("Authentication required: {}".format(parsed["www_authenticate"]))
            if "digest" in parsed["www_authenticate"].lower():
                print_info("Digest authentication in use")

        if status == "200":
            print_success("Endpoint is reachable and responsive")
        elif status == "401":
            print_info("Endpoint requires authentication (401)")
        elif status == "403":
            print_info("Endpoint rejected request (403 Forbidden)")
        elif status == "404":
            print_info("Extension not found (404)")
