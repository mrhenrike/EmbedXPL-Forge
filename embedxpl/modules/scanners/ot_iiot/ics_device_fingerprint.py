# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""Multi-Protocol ICS Device Fingerprint Scanner.

Probes ICS/SCADA devices using multiple OT protocols in sequence:
Modbus TCP, BACnet/IP, DNP3, S7comm, and PROFINET DCP. Identifies
device type, firmware, vendor, and supported protocol stack from
combined probe responses.

Constructs all protocol frames manually via struct.pack.

References:
  - ICS-CERT: Industrial Control Systems Assessment
  - NIST SP 800-82 Rev 3: Guide to OT Security

Version: 1.0.0
"""

import socket
import struct
import time

from embedxpl.core.exploit import *


class Exploit(Exploit):
    """Multi-Protocol ICS Device Fingerprint Scanner.

    Author: Andre Henrique (LinkedIn/X: @mrhenrike)
    Version: 1.0.0
    """

    __info__ = {
        "name": "Multi-Protocol ICS Device Fingerprint Scanner",
        "description": (
            "Probes ICS devices using Modbus TCP (FC 43/14), BACnet Who-Is, "
            "DNP3 Link Status, S7comm COTP/SZL, and PROFINET DCP Identify "
            "in sequence. Builds a composite device fingerprint from all "
            "responding protocols to identify device type and capabilities."
        ),
        "authors": ("Andre Henrique (@mrhenrike)",),
        "references": (
            "https://www.cisa.gov/uscert/ics",
            "https://csrc.nist.gov/pubs/sp/800/82/r3/final",
        ),
        "devices": (
            "Siemens S7-1200/S7-1500",
            "Schneider Electric Modicon",
            "Allen-Bradley ControlLogix/CompactLogix",
            "ABB AC500/AC800M",
            "GE/Emerson PAC/PLC",
            "Honeywell Experion",
            "Any multi-protocol ICS device",
        ),
        "severity": "info",
        "mitre": ["T0846", "T0888"],
        "status": "confirmed",
    }

    target = OptIP("", "Target ICS device IP")
    timeout = OptInteger(3, "Per-probe socket timeout in seconds")
    probe_modbus = OptBool(True, "Probe Modbus TCP/502")
    probe_bacnet = OptBool(True, "Probe BACnet UDP/47808")
    probe_dnp3 = OptBool(True, "Probe DNP3 TCP/20000")
    probe_s7comm = OptBool(True, "Probe S7comm TCP/102")
    probe_profinet = OptBool(False, "Probe PROFINET DCP (requires raw socket)")
    profinet_iface = OptString("eth0", "Interface for PROFINET DCP probe")

    def _tcp_probe(self, port: int, data: bytes) -> bytes:
        """Send TCP probe and return response."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(float(self.timeout))
            sock.connect((self.target, port))
            sock.sendall(data)
            resp = sock.recv(512)
            sock.close()
            return resp
        except (socket.error, OSError):
            return b""

    def _udp_probe(self, port: int, data: bytes) -> bytes:
        """Send UDP probe and return response."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(float(self.timeout))
            sock.sendto(data, (self.target, port))
            resp, _ = sock.recvfrom(1500)
            sock.close()
            return resp
        except (socket.timeout, socket.error):
            return b""

    def _probe_modbus_id(self) -> dict:
        """Probe Modbus TCP FC 43/14 Read Device Identification."""
        result = {"protocol": "Modbus TCP", "port": 502}
        pdu = struct.pack(">BBBB", 0x2B, 0x0E, 0x01, 0x00)
        mbap = struct.pack(">HHHB", 1, 0x0000, len(pdu) + 1, 1)
        resp = self._tcp_probe(502, mbap + pdu)

        if not resp or len(resp) < 14:
            result["status"] = "no_response"
            return result

        fc = resp[7]
        if fc == 0x2B and len(resp) > 14:
            num_obj = resp[14]
            offset = 15
            for _ in range(num_obj):
                if offset + 2 > len(resp):
                    break
                obj_id = resp[offset]
                obj_len = resp[offset + 1]
                offset += 2
                if offset + obj_len > len(resp):
                    break
                val = resp[offset:offset + obj_len].decode("ascii", errors="replace")
                if obj_id == 0x00:
                    result["vendor"] = val
                elif obj_id == 0x01:
                    result["product"] = val
                elif obj_id == 0x02:
                    result["revision"] = val
                offset += obj_len
            result["status"] = "identified"
        elif fc == (0x2B | 0x80):
            # FC 43 not supported, try FC 17
            pdu17 = struct.pack(">B", 0x11)
            mbap17 = struct.pack(">HHHB", 2, 0x0000, 2, 1)
            resp17 = self._tcp_probe(502, mbap17 + pdu17)
            if resp17 and len(resp17) > 9 and resp17[7] == 0x11:
                byte_count = resp17[8]
                server_id = resp17[9:9 + byte_count].decode("ascii", errors="replace")
                result["server_id"] = server_id.rstrip("\x00")
                result["status"] = "partial"
            else:
                result["status"] = "modbus_active"
        else:
            result["status"] = "modbus_active"
        return result

    def _probe_bacnet_whois(self) -> dict:
        """Probe BACnet/IP with Who-Is."""
        result = {"protocol": "BACnet/IP", "port": 47808}
        who_is = struct.pack(">BBH", 0x81, 0x0A, 12)
        who_is += b"\x01\x20\xff\xff\x00\xff\x10\x08"

        resp = self._udp_probe(47808, who_is)
        if not resp or len(resp) < 12:
            result["status"] = "no_response"
            return result

        result["status"] = "active"
        # Parse I-Am: look for object ID and vendor ID
        for i in range(4, len(resp) - 5):
            if resp[i] == 0xC4:  # Object Identifier tag
                oid = struct.unpack_from(">I", resp, i + 1)[0]
                instance = oid & 0x3FFFFF
                result["device_instance"] = instance
                break

        # Find vendor ID
        for i in range(4, len(resp) - 2):
            if resp[i] == 0x21:
                result["vendor_id"] = resp[i + 1]
                break
            elif resp[i] == 0x22:
                result["vendor_id"] = struct.unpack_from(">H", resp, i + 1)[0]
                break

        return result

    def _probe_dnp3_link(self) -> dict:
        """Probe DNP3 with Link Status Request."""
        result = {"protocol": "DNP3", "port": 20000}

        # Build minimal link status request
        header = struct.pack("<H", 0x0564)  # start
        header += struct.pack("<B", 5)  # length
        header += struct.pack("<B", 0xC9)  # DIR|PRM|FC=LinkStatus
        header += struct.pack("<H", 10)  # dst=10
        header += struct.pack("<H", 1)  # src=1

        # CRC
        crc = 0x0000
        crc_table = []
        for i in range(256):
            c = i
            for _ in range(8):
                c = (c >> 1) ^ 0xA6BC if c & 1 else c >> 1
            crc_table.append(c & 0xFFFF)
        for b in header:
            crc = (crc >> 8) ^ crc_table[(crc ^ b) & 0xFF]
        crc = (~crc) & 0xFFFF

        frame = header + struct.pack("<H", crc)
        resp = self._tcp_probe(20000, frame)

        if not resp or len(resp) < 10:
            result["status"] = "no_response"
            return result

        start = struct.unpack_from("<H", resp, 0)[0]
        if start == 0x0564:
            src_addr = struct.unpack_from("<H", resp, 6)[0]
            result["outstation_addr"] = src_addr
            result["status"] = "active"
        else:
            result["status"] = "invalid_response"
        return result

    def _probe_s7comm(self) -> dict:
        """Probe S7comm via COTP connection and SZL read."""
        result = {"protocol": "S7comm", "port": 102}

        # COTP Connection Request (ISO-on-TCP)
        cotp_cr = b"\x03\x00\x00\x16"  # TPKT header
        cotp_cr += b"\x11\xe0\x00\x00\x00\x01\x00"
        cotp_cr += b"\xc0\x01\x0a"  # src-tsap
        cotp_cr += b"\xc1\x02\x01\x00"  # dst-tsap (rack 0, slot 1)
        cotp_cr += b"\xc2\x02\x01\x02"  # tpdu-size

        resp = self._tcp_probe(102, cotp_cr)
        if not resp or len(resp) < 7:
            result["status"] = "no_response"
            return result

        if resp[5] != 0xD0:  # COTP CC (Connection Confirm)
            result["status"] = "cotp_rejected"
            return result

        result["status"] = "active"

        # S7comm Setup Communication
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(float(self.timeout))
            sock.connect((self.target, 102))
            sock.sendall(cotp_cr)
            sock.recv(512)

            # S7 Setup Communication
            s7_setup = (
                b"\x03\x00\x00\x19"  # TPKT
                b"\x02\xf0\x80"  # COTP DT
                b"\x32\x01\x00\x00"  # S7: Job
                b"\x00\x00\x00\x08\x00\x00"
                b"\xf0\x00\x00\x01\x00\x01\x01\xe0"
            )
            sock.sendall(s7_setup)
            setup_resp = sock.recv(512)

            if setup_resp and len(setup_resp) > 12:
                # SZL Read (Module Identification): SZL-ID 0x0011
                szl_read = (
                    b"\x03\x00\x00\x21"  # TPKT
                    b"\x02\xf0\x80"  # COTP DT
                    b"\x32\x07\x00\x00"  # S7: UserData
                    b"\x00\x00\x00\x08\x00\x08"
                    b"\x00\x01\x12\x04\x11\x44\x01\x00"
                    b"\xff\x09\x00\x04"
                    b"\x00\x11\x00\x00"  # SZL-ID 0x0011, index 0
                )
                sock.sendall(szl_read)
                szl_resp = sock.recv(1024)

                if szl_resp and len(szl_resp) > 40:
                    # Extract module info from SZL response
                    payload = szl_resp[27:] if len(szl_resp) > 27 else b""
                    text = payload.decode("ascii", errors="replace")
                    import re
                    parts = re.findall(r"[\x20-\x7E]{3,}", text)
                    if parts:
                        result["module_info"] = parts[:3]

            sock.close()
        except (socket.error, OSError):
            pass

        return result

    def _probe_profinet_dcp(self) -> dict:
        """Probe PROFINET DCP Identify (requires AF_PACKET)."""
        result = {"protocol": "PROFINET DCP", "port": "L2/0x8892"}
        try:
            sock = socket.socket(
                socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x8892)
            )
            sock.bind((self.profinet_iface, 0))
            sock.settimeout(float(self.timeout))

            # Get MAC
            try:
                import fcntl
                info = fcntl.ioctl(
                    sock.fileno(), 0x8927,
                    struct.pack("256s", self.profinet_iface.encode()[:15])
                )
                src_mac = info[18:24]
            except (ImportError, OSError):
                src_mac = b"\x02\x00\x00\x00\x00\x01"

            dst = b"\x01\x0e\xcf\x00\x00\x00"
            eth = dst + src_mac + struct.pack(">H", 0x8892)

            xid = int(time.time()) & 0xFFFFFFFF
            dcp = struct.pack(">HBBI HH", 0xFEFE, 0x05, 0x00, xid, 0x0080, 4)
            block = struct.pack(">BBH", 0xFF, 0xFF, 0x0000)

            frame = eth + dcp + block
            frame += b"\x00" * max(0, 60 - len(frame))

            sock.send(frame)
            deadline = time.time() + float(self.timeout)
            while time.time() < deadline:
                try:
                    data = sock.recv(1518)
                    if len(data) >= 28:
                        fid = struct.unpack_from(">H", data, 14)[0]
                        if fid == 0xFEFF:
                            result["status"] = "active"
                            result["device_mac"] = ":".join(
                                "{:02x}".format(b) for b in data[6:12]
                            )
                            sock.close()
                            return result
                except socket.timeout:
                    break

            sock.close()
            result["status"] = "no_response"
        except (OSError, AttributeError):
            result["status"] = "raw_socket_unavailable"
        return result

    @mute
    def check(self) -> bool:
        """Verify at least one ICS protocol port is open."""
        ports = []
        if self.probe_modbus:
            ports.append(502)
        if self.probe_s7comm:
            ports.append(102)
        if self.probe_dnp3:
            ports.append(20000)

        for p in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                sock.connect((self.target, p))
                sock.close()
                return True
            except (socket.error, OSError):
                continue

        if self.probe_bacnet:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(1)
                probe = struct.pack(">BBH", 0x81, 0x0A, 12)
                probe += b"\x01\x20\xff\xff\x00\xff\x10\x08"
                sock.sendto(probe, (self.target, 47808))
                sock.recvfrom(64)
                sock.close()
                return True
            except (socket.timeout, socket.error):
                pass
        return False

    @multi
    def run(self) -> None:
        """Execute multi-protocol ICS fingerprint scan."""
        print_status(
            "ICS fingerprint scan on {} (Modbus={}, BACnet={}, DNP3={}, "
            "S7={}, PROFINET={})".format(
                self.target, self.probe_modbus, self.probe_bacnet,
                self.probe_dnp3, self.probe_s7comm, self.probe_profinet,
            )
        )

        results = []

        if self.probe_modbus:
            print_info("Probing Modbus TCP/502...")
            r = self._probe_modbus_id()
            results.append(r)
            if r.get("status") not in ("no_response",):
                print_success("Modbus: {} | {} {} {}".format(
                    r.get("status"),
                    r.get("vendor", ""),
                    r.get("product", ""),
                    r.get("revision", ""),
                ))
            else:
                print_info("Modbus: no response")

        if self.probe_bacnet:
            print_info("Probing BACnet UDP/47808...")
            r = self._probe_bacnet_whois()
            results.append(r)
            if r.get("status") == "active":
                print_success("BACnet: device #{}, vendor={}".format(
                    r.get("device_instance", "?"),
                    r.get("vendor_id", "?"),
                ))
            else:
                print_info("BACnet: no response")

        if self.probe_dnp3:
            print_info("Probing DNP3 TCP/20000...")
            r = self._probe_dnp3_link()
            results.append(r)
            if r.get("status") == "active":
                print_success("DNP3: outstation addr={}".format(
                    r.get("outstation_addr", "?")
                ))
            else:
                print_info("DNP3: no response")

        if self.probe_s7comm:
            print_info("Probing S7comm TCP/102...")
            r = self._probe_s7comm()
            results.append(r)
            if r.get("status") == "active":
                info = r.get("module_info", [])
                print_success("S7comm: active{}".format(
                    " | " + " / ".join(info) if info else ""
                ))
            else:
                print_info("S7comm: {}".format(r.get("status", "no response")))

        if self.probe_profinet:
            print_info("Probing PROFINET DCP (L2)...")
            r = self._probe_profinet_dcp()
            results.append(r)
            if r.get("status") == "active":
                print_success("PROFINET: MAC={}".format(r.get("device_mac", "?")))
            else:
                print_info("PROFINET: {}".format(r.get("status", "no response")))

        # Summary
        active = [r for r in results if r.get("status") not in ("no_response", "raw_socket_unavailable")]
        protocols = [r["protocol"] for r in active]

        print_info("Fingerprint summary for {}:".format(self.target))
        print_info("  Active protocols: {}".format(
            ", ".join(protocols) if protocols else "none detected"
        ))

        if "S7comm" in protocols and "PROFINET DCP" in protocols:
            print_success("  Likely: Siemens S7 PLC (S7comm + PROFINET)")
        elif "S7comm" in protocols:
            print_success("  Likely: Siemens S7 PLC or compatible")
        elif "Modbus TCP" in protocols and "BACnet/IP" in protocols:
            print_success("  Likely: BMS/HVAC controller (multi-protocol)")
        elif "BACnet/IP" in protocols:
            print_success("  Likely: Building automation controller")
        elif "DNP3" in protocols:
            print_success("  Likely: Utility/power protective relay or RTU")
        elif "Modbus TCP" in protocols:
            modbus_r = next((r for r in results if r["protocol"] == "Modbus TCP"), {})
            vendor = modbus_r.get("vendor", "Unknown")
            print_success("  Likely: PLC/RTU ({})".format(vendor))
        else:
            print_info("  Device type: inconclusive")
