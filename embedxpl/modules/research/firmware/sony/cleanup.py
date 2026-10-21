#!/usr/bin/env python3
"""Restore TV to original state after PoC."""
import requests

TARGET = "192.168.18.6"
UPNP = 2870
DIAL = 56789
AVT = "urn:schemas-upnp-org:service:AVTransport:1"
RC = "urn:schemas-upnp-org:service:RenderingControl:1"


def soap(svc, action, inner, path):
    body = (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
        's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
        f"<s:Body><u:{action} xmlns:u=\"{svc}\">{inner}</u:{action}></s:Body>"
        "</s:Envelope>"
    )
    headers = {
        "Content-Type": 'text/xml; charset="utf-8"',
        "SOAPACTION": f'"{svc}#{action}"',
    }
    return requests.post(f"http://{TARGET}:{UPNP}/{path}", data=body.encode(),
                         headers=headers, timeout=8)


# Stop any running app
for app in ["Netflix", "YouTube"]:
    try:
        r = requests.delete(f"http://{TARGET}:{DIAL}/apps/{app}/run", timeout=3)
        print(f"Stop {app}: {r.status_code}")
    except Exception:
        pass

# Stop transport
try:
    r = soap(AVT, "Stop", "<InstanceID>0</InstanceID>", "control/AVTransport")
    print(f"Stop transport: {r.status_code}")
except Exception:
    pass

# Restore volume to 5
try:
    r = soap(RC, "SetVolume",
             "<InstanceID>0</InstanceID><Channel>Master</Channel><DesiredVolume>5</DesiredVolume>",
             "control/RenderingControl")
    print(f"Restore volume=5: {r.status_code}")
except Exception:
    pass

print("Cleanup done.")
