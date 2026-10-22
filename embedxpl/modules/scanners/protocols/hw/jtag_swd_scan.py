# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""JTAG/SWD Debug Port Scanner: ARM CoreSight DAP, IDCODE extraction,
JTAG chain enumeration. Refs: IEEE 1149.1, ARM IHI 0031. Version: 1.0.0
"""
from __future__ import annotations

import struct
import time

from embedxpl.core.exploit import *

_JTAG_MANUFACTURERS: dict[int, str] = {
    0x00E: "STMicroelectronics", 0x020: "NXP (Freescale)", 0x03B: "ARM Ltd.",
    0x049: "Xilinx", 0x06D: "Microchip (Atmel)", 0x093: "Texas Instruments",
    0x0B3: "Espressif", 0x0E5: "Intel (Altera)", 0x170: "Cypress / Infineon",
}
_CORESIGHT_DAP_IDCODES: dict[int, str] = {
    0x0BA00477: "ARM Cortex DAP (JTAG)", 0x0BA01477: "ARM Cortex DAP (SWD)",
    0x0BA02477: "ARM Cortex-M0 DAP", 0x0BA04477: "ARM Cortex-M33 DAP",
    0x0BA80477: "ARM Cortex-M7 DAP", 0x6BA00477: "ARM Cortex-A DAP",
}
_DEBUG_ADAPTER_USB: list[tuple[int, int, str]] = [
    (0x1366, 0x0101, "SEGGER J-Link"), (0x1366, 0x0105, "SEGGER J-Link Plus"),
    (0x0403, 0x6010, "FTDI FT2232 (JTAG)"), (0x0403, 0x6014, "FTDI FT232H"),
    (0x0483, 0x3748, "ST-Link V2"), (0x0483, 0x374B, "ST-Link V2-1"),
    (0x0483, 0x374E, "ST-Link V3"), (0x1CBE, 0x00FD, "TI XDS110"),
    (0x15BA, 0x002A, "Olimex ARM-USB-OCD"), (0x1209, 0x2488, "Black Magic Probe"),
    (0x2E8A, 0x000C, "Raspberry Pi Debug Probe"),
]


class Exploit(Exploit):
    """JTAG/SWD Debug Port Scanner: IDCODE chain, CoreSight DAP, USB adapters."""

    __info__ = {
        "name": "JTAG/SWD Debug Port Scanner",
        "description": (
            "Scans for exposed JTAG/SWD debug interfaces on embedded targets. "
            "Enumerates JTAG chain IDCODEs, identifies ARM CoreSight DAP, and "
            "detects USB debug adapters (J-Link, ST-Link, FTDI)."
        ),
        "authors": ("Andre Henrique (@mrhenrike)",),
        "references": (
            "https://standards.ieee.org/standard/1149_1-2013.html",
            "https://developer.arm.com/documentation/ihi0031/latest",
        ),
        "devices": ("ARM Cortex MCUs", "FPGA dev boards", "Embedded SoCs"),
        "severity": "high",
        "required_hardware": ["jtag_swd_adapter"],
    }

    target = OptString("", "Serial port for JTAG adapter (e.g. /dev/ttyUSB0)")
    timeout = OptInteger(3, "Serial read timeout in seconds")
    baudrate = OptInteger(115200, "Serial baud rate for adapter communication")
    usb_scan = OptBool(True, "Scan USB bus for known debug adapters")

    def _scan_usb_adapters(self) -> list[dict[str, str]]:
        """Detect known JTAG/SWD USB adapters on the host."""
        found: list[dict[str, str]] = []
        try:
            import usb.core  # type: ignore[import-untyped]
        except ImportError:
            print_warning("pyusb not installed; skipping USB adapter scan")
            return found

        for vid, pid, label in _DEBUG_ADAPTER_USB:
            devices = list(usb.core.find(find_all=True, idVendor=vid, idProduct=pid))
            for dev in devices:
                serial = ""
                try:
                    serial = dev.serial_number or ""
                except Exception:
                    pass
                found.append({
                    "adapter": label,
                    "vid_pid": "{:04X}:{:04X}".format(vid, pid),
                    "serial": serial,
                    "bus": "{}.{}".format(dev.bus, dev.address),
                })
        return found

    @staticmethod
    def _parse_idcode(raw: bytes) -> int | None:
        """Extract a 32-bit IDCODE from raw bytes (little-endian)."""
        if len(raw) < 4:
            return None
        val = struct.unpack("<I", raw[:4])[0]
        if val == 0x00000000 or val == 0xFFFFFFFF:
            return None
        return val

    @staticmethod
    def _decode_idcode(idcode: int) -> dict[str, str]:
        """Decode JTAG IDCODE fields per IEEE 1149.1."""
        version = (idcode >> 28) & 0x0F
        part = (idcode >> 12) & 0xFFFF
        mfr_id = (idcode >> 1) & 0x7FF
        mfr_name = _JTAG_MANUFACTURERS.get(mfr_id, "Unknown (0x{:03X})".format(mfr_id))
        coresight = _CORESIGHT_DAP_IDCODES.get(idcode, "")
        return {
            "idcode_hex": "0x{:08X}".format(idcode),
            "version": str(version),
            "part_number": "0x{:04X}".format(part),
            "manufacturer": mfr_name,
            "coresight": coresight,
        }

    def _serial_read_idcodes(self) -> list[int]:
        """Read JTAG IDCODE chain from a serial debug adapter."""
        try:
            import serial  # type: ignore[import-untyped]
        except ImportError:
            print_error("pyserial not installed; cannot communicate with adapter")
            return []

        idcodes: list[int] = []
        try:
            port = serial.Serial(
                port=str(self.target),
                baudrate=int(self.baudrate),
                timeout=float(self.timeout),
            )
        except (serial.SerialException, OSError, ValueError) as exc:
            print_error("Cannot open {}: {}".format(self.target, exc))
            return idcodes

        try:
            port.reset_input_buffer()
            # Send JTAG-to-IDCODE shift sequence: 5x TMS=1 (Test-Logic-Reset),
            # then TMS=0 (Run-Test/Idle), TMS=1,0,0 (Shift-DR).
            port.write(b"\xFF\xFF\x01\x04")
            time.sleep(0.2)
            raw = port.read(256)
            offset = 0
            while offset + 4 <= len(raw):
                idcode = self._parse_idcode(raw[offset:offset + 4])
                if idcode is None:
                    break
                idcodes.append(idcode)
                offset += 4
        except (serial.SerialException, OSError) as exc:
            print_error("Serial read error: {}".format(exc))
        finally:
            port.close()

        return idcodes

    @mute
    def check(self) -> bool:
        """Verify that the serial port or USB adapters are accessible."""
        if self.usb_scan:
            adapters = self._scan_usb_adapters()
            if adapters:
                return True
        if self.target:
            try:
                import serial  # type: ignore[import-untyped]
                p = serial.Serial(str(self.target), timeout=0.5)
                p.close()
                return True
            except Exception:
                return False
        return False

    def run(self) -> None:
        """Execute JTAG/SWD debug port scan."""
        print_status("JTAG/SWD Debug Port Scanner starting...")

        if self.usb_scan:
            print_status("Scanning USB bus for debug adapters...")
            adapters = self._scan_usb_adapters()
            if adapters:
                print_success("Found {} USB debug adapter(s)".format(len(adapters)))
                for a in adapters:
                    sn = " SN={}".format(a["serial"]) if a["serial"] else ""
                    print_info("  {} [{}] bus {}{}".format(
                        a["adapter"], a["vid_pid"], a["bus"], sn,
                    ))
            else:
                print_info("No known USB debug adapters detected")

        if not self.target:
            if not self.usb_scan:
                print_warning("No serial target and USB scan disabled; nothing to do")
            return

        print_status("Reading JTAG IDCODE chain from {}...".format(self.target))
        idcodes = self._serial_read_idcodes()

        if not idcodes:
            print_warning("No JTAG IDCODEs extracted from {}".format(self.target))
            return

        print_success("Extracted {} IDCODE(s) from JTAG chain".format(len(idcodes)))
        for idx, idcode in enumerate(idcodes):
            info = self._decode_idcode(idcode)
            label = info["coresight"] or info["manufacturer"]
            print_info("  TAP {}: {} - {} (part {}, ver {})".format(
                idx, info["idcode_hex"], label, info["part_number"], info["version"],
            ))
