# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""UART Console Scanner: baud rate brute-force, bootloader/shell/login
detection. Refs: TIA/EIA-232, OWASP IoT Testing Guide. Version: 1.0.0
"""

from __future__ import annotations

import re
import time

from embedxpl.core.exploit import *

_DEFAULT_BAUDS: list[int] = [9600, 19200, 38400, 57600, 115200]

_BOOTLOADER_PATTERNS: list[tuple[str, str]] = [
    (r"U-Boot\s+\d", "U-Boot"), (r"CFE\s+version", "Broadcom CFE"),
    (r"RedBoot", "RedBoot (eCos)"), (r"Barebox\s+\d", "Barebox"),
    (r"Das\s+U-Boot", "U-Boot"), (r"OpenWrt\s+BOOT", "OpenWrt Boot"),
    (r"BootROM", "BootROM"), (r"AP\s*Boot", "AP Boot"),
]
_SHELL_PATTERNS: list[tuple[str, str]] = [
    (r"#\s*$", "root shell"), (r"\$\s*$", "user shell"),
    (r"BusyBox\s+v", "BusyBox shell"), (r"ash\s*$", "ash shell"),
]
_LOGIN_PATTERNS: list[tuple[str, str]] = [
    (r"[Ll]ogin\s*:", "login prompt"), (r"[Uu]sername\s*:", "username prompt"),
    (r"[Pp]assword\s*:", "password prompt"),
]
_FIRMWARE_PATTERNS: list[tuple[str, str]] = [
    (r"Linux\s+version\s+\d", "Linux kernel boot"), (r"Starting\s+kernel", "kernel handoff"),
    (r"VxWorks", "VxWorks RTOS"), (r"FreeRTOS", "FreeRTOS"),
    (r"Zephyr", "Zephyr RTOS"), (r"ThreadX", "ThreadX RTOS"),
]


class Exploit(Exploit):
    """UART Console Scanner: baud rate brute-force with pattern classification."""

    __info__ = {
        "name": "UART Console Scanner",
        "description": (
            "Scans for exposed UART consoles on embedded devices by brute-forcing "
            "baud rates (9600 to 115200). Detects boot loaders (U-Boot, CFE, "
            "RedBoot), login prompts, and direct shell access."
        ),
        "authors": ("Andre Henrique (@mrhenrike)",),
        "references": (
            "https://owasp.org/www-project-iot-testing-guide/",
        ),
        "devices": ("Routers", "IoT devices", "Embedded systems"),
        "severity": "high",
        "required_hardware": ["usb_serial_adapter"],
    }

    target = OptString("", "Serial port (e.g. /dev/ttyUSB0, COM3)")
    timeout = OptInteger(3, "Read timeout per baud rate in seconds")
    bauds = OptString(
        "9600,19200,38400,57600,115200",
        "Comma-separated baud rates to try",
    )
    send_newline = OptBool(True, "Send newlines to provoke output")

    def _parse_bauds(self) -> list[int]:
        """Parse baud rate list from the option string."""
        raw = str(self.bauds).strip()
        if not raw:
            return list(_DEFAULT_BAUDS)
        result: list[int] = []
        for token in raw.split(","):
            token = token.strip()
            if token.isdigit():
                result.append(int(token))
        return result or list(_DEFAULT_BAUDS)

    def _classify_output(self, text: str) -> list[dict[str, str]]:
        """Match captured text against known patterns."""
        findings: list[dict[str, str]] = []
        all_patterns = (
            [("bootloader", p, n) for p, n in _BOOTLOADER_PATTERNS]
            + [("shell", p, n) for p, n in _SHELL_PATTERNS]
            + [("login", p, n) for p, n in _LOGIN_PATTERNS]
            + [("firmware", p, n) for p, n in _FIRMWARE_PATTERNS]
        )
        for category, pattern, name in all_patterns:
            if re.search(pattern, text):
                findings.append({"category": category, "name": name})
        return findings

    def _try_baud(self, baud: int) -> dict[str, object]:
        """Attempt to read data at a specific baud rate."""
        try:
            import serial  # type: ignore[import-untyped]
        except ImportError:
            print_error("pyserial not installed; cannot open serial port")
            return {}

        result: dict[str, object] = {"baud": baud, "readable": False, "raw": b""}
        try:
            port = serial.Serial(
                port=str(self.target),
                baudrate=baud,
                timeout=float(self.timeout),
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
            )
        except (serial.SerialException, OSError, ValueError) as exc:
            print_error("Cannot open {} at {}: {}".format(self.target, baud, exc))
            return result

        try:
            port.reset_input_buffer()
            if self.send_newline:
                for _ in range(3):
                    port.write(b"\r\n")
                    time.sleep(0.15)

            time.sleep(0.5)
            raw = port.read(4096)
            result["raw"] = raw

            if not raw:
                return result

            # Check for printable ASCII ratio to detect valid baud.
            printable = sum(1 for b in raw if 0x20 <= b <= 0x7E or b in (0x0A, 0x0D, 0x09))
            ratio = printable / len(raw) if raw else 0.0
            result["readable"] = ratio >= 0.6
            result["printable_ratio"] = round(ratio, 2)

            if result["readable"]:
                text = raw.decode("ascii", errors="replace")
                result["text"] = text
                result["findings"] = self._classify_output(text)
        except (serial.SerialException, OSError) as exc:
            print_error("Read error at baud {}: {}".format(baud, exc))
        finally:
            port.close()

        return result

    @mute
    def check(self) -> bool:
        """Verify the serial port is accessible."""
        if not self.target:
            return False
        try:
            import serial  # type: ignore[import-untyped]
            p = serial.Serial(str(self.target), baudrate=9600, timeout=0.5)
            p.close()
            return True
        except Exception:
            return False

    def run(self) -> None:
        """Execute UART console scan across configured baud rates."""
        if not self.target:
            print_error("No serial port specified in 'target'")
            return

        bauds = self._parse_bauds()
        print_status("UART Console Scanner on {}, testing {} baud rate(s)".format(
            self.target, len(bauds),
        ))

        best: dict[str, object] = {}
        for baud in bauds:
            print_status("Trying {} baud...".format(baud))
            result = self._try_baud(baud)
            if not result:
                break
            if result.get("readable"):
                print_success("Readable output at {} baud (printable ratio: {})".format(
                    baud, result.get("printable_ratio", "?"),
                ))
                if not best or len(result.get("raw", b"")) > len(best.get("raw", b"")):  # type: ignore[arg-type]
                    best = result

        if not best:
            print_warning("No readable UART output detected on {}".format(self.target))
            return

        findings: list[dict[str, str]] = best.get("findings", [])  # type: ignore[assignment]
        if findings:
            print_success("Identified {} pattern(s) at {} baud:".format(
                len(findings), best["baud"],
            ))
            for f in findings:
                print_info("  [{}] {}".format(f["category"], f["name"]))
        else:
            print_info("Readable data at {} baud but no known patterns matched".format(
                best["baud"],
            ))

        text = best.get("text", "")
        if text:
            preview = str(text)[:200].replace("\r", "").replace("\n", " | ")
            print_info("Preview: {}".format(preview))
