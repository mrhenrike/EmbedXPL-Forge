#!/usr/bin/env python3
"""Check current transport state and active URI on the TV."""
import requests

TARGET = "192.168.18.6"
UPNP = 2870
AVT = "urn:schemas-upnp-org:service:AVTransport:1"


def soap(action, inner_xml, path):
    body = (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
        's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
        "<s:Body>"
        f'<u:{action} xmlns:u="{AVT}">{inner_xml}</u:{action}>'
        "</s:Body></s:Envelope>"
    )
    headers = {
        "Content-Type": 'text/xml; charset="utf-8"',
        "SOAPACTION": f'"{AVT}#{action}"',
    }
    return requests.post(
        f"http://{TARGET}:{UPNP}/{path}", data=body.encode(), headers=headers, timeout=8
    )


r = soap("GetTransportInfo", "<InstanceID>0</InstanceID>", "control/AVTransport")
print("=== GetTransportInfo ===")
print(r.text)

r2 = soap("GetPositionInfo", "<InstanceID>0</InstanceID>", "control/AVTransport")
print("\n=== GetPositionInfo ===")
print(r2.text)

r3 = soap("GetMediaInfo", "<InstanceID>0</InstanceID>", "control/AVTransport")
print("\n=== GetMediaInfo ===")
print(r3.text)
