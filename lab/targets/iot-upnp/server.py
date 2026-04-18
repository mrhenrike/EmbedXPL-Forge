# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""Simulated UPnP/SSDP IoT device for EmbedXPL-Forge local lab.

Exposes a minimal UPnP device description (rootDesc.xml) and
SSDP advertisement via HTTP on port 49152, allowing EmbedXPL
UPnP scanner modules to fingerprint and test against it.

Version: 1.0.0
"""

from __future__ import annotations

import logging
import socket
import threading

from flask import Flask, Response

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("lab.upnp")

app = Flask(__name__)

_ROOT_DESC_XML = """\
<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <specVersion><major>1</major><minor>0</minor></specVersion>
  <device>
    <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
    <friendlyName>EmbedXPL-Lab UPnP Device</friendlyName>
    <manufacturer>TP-Link Technologies Co., Ltd.</manufacturer>
    <manufacturerURL>http://www.tp-link.com</manufacturerURL>
    <modelDescription>TP-Link SOHO Router WR940N</modelDescription>
    <modelName>TL-WR940N</modelName>
    <modelNumber>v4</modelNumber>
    <modelURL>http://www.tp-link.com</modelURL>
    <serialNumber>00000000000000</serialNumber>
    <UDN>uuid:embedxpl-lab-wr940n-upnp-00000001</UDN>
    <serviceList>
      <service>
        <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
        <serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId>
        <controlURL>/ctl/IPConn</controlURL>
        <eventSubURL>/evt/IPConn</eventSubURL>
        <SCPDURL>/WANIPCn.xml</SCPDURL>
      </service>
    </serviceList>
    <presentationURL>http://192.168.0.1/</presentationURL>
  </device>
</root>
"""

_SSDP_NOTIFY = (
    "NOTIFY * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    "CACHE-CONTROL: max-age=1800\r\n"
    "LOCATION: http://172.20.0.30:49152/rootDesc.xml\r\n"
    "NT: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
    "NTS: ssdp:alive\r\n"
    "SERVER: EmbedXPL-Lab/1.0 UPnP/1.0 TL-WR940N/1.0\r\n"
    "USN: uuid:embedxpl-lab-wr940n-upnp-00000001::"
    "urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
    "\r\n"
)


@app.route("/rootDesc.xml")
def root_desc():
    """Return UPnP device description XML."""
    return Response(_ROOT_DESC_XML, mimetype="text/xml")


@app.route("/WANIPCn.xml")
def wan_ip_conn():
    """Minimal WANIPConnection service description."""
    xml = (
        '<?xml version="1.0"?>'
        '<scpd xmlns="urn:schemas-upnp-org:service-1-0">'
        "<specVersion><major>1</major><minor>0</minor></specVersion>"
        "<actionList></actionList><serviceStateTable></serviceStateTable>"
        "</scpd>"
    )
    return Response(xml, mimetype="text/xml")


def _ssdp_listener() -> None:
    """Listen for SSDP M-SEARCH queries and reply with device info."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", 1900))
        import struct
        mreq = struct.pack("4sL", socket.inet_aton("239.255.255.250"), socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        logger.info("SSDP listener active on UDP 1900")
        while True:
            data, addr = sock.recvfrom(1024)
            if b"M-SEARCH" in data:
                logger.info("SSDP M-SEARCH from %s", addr)
                response = (
                    "HTTP/1.1 200 OK\r\n"
                    "CACHE-CONTROL: max-age=1800\r\n"
                    "DATE: Mon, 01 Jan 2024 00:00:00 GMT\r\n"
                    "EXT:\r\n"
                    "LOCATION: http://172.20.0.30:49152/rootDesc.xml\r\n"
                    "SERVER: EmbedXPL-Lab/1.0 UPnP/1.0 TL-WR940N/1.0\r\n"
                    "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
                    "USN: uuid:embedxpl-lab-wr940n-upnp-00000001::"
                    "urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
                    "\r\n"
                )
                sock.sendto(response.encode(), addr)
    except Exception as exc:
        logger.error("SSDP listener error: %s", exc)
    finally:
        sock.close()


if __name__ == "__main__":
    ssdp_thread = threading.Thread(target=_ssdp_listener, daemon=True)
    ssdp_thread.start()
    logger.info("Starting UPnP/SSDP lab target on 0.0.0.0:49152")
    app.run(host="0.0.0.0", port=49152, debug=False)
