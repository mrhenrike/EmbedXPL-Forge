# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""I2C/SPI Bus Probe Scanner: I2C address scan (0x03-0x77), SPI flash
JEDEC ID extraction. Refs: NXP UM10204, JEDEC JESD216. Version: 1.0.0
"""

from __future__ import annotations

import struct

from embedxpl.core.exploit import *

_I2C_KNOWN_ADDRESSES: dict[int, str] = {
    0x20: "PCF8574/MCP23017 GPIO", 0x27: "PCF8574A LCD/GPIO",
    0x3C: "SSD1306 OLED", 0x3D: "SSD1306 OLED (alt)",
    0x48: "TMP102/ADS1115 Temp/ADC",
    0x50: "AT24C EEPROM", 0x51: "AT24C EEPROM (A0=1)",
    0x52: "AT24C EEPROM (A1=1)", 0x53: "AT24C EEPROM (A0=A1=1)",
    0x54: "AT24C EEPROM (A2=1)", 0x55: "AT24C EEPROM (A0=A2=1)",
    0x56: "AT24C EEPROM (A1=A2=1)", 0x57: "AT24C EEPROM (all set)",
    0x68: "DS3231 RTC / MPU-6050", 0x69: "MPU-6050 (alt)",
    0x76: "BME280/BMP280", 0x77: "BME280/BMP280 (alt)",
}
_JEDEC_MANUFACTURERS: dict[int, str] = {
    0x01: "Spansion/Cypress/Infineon", 0x1F: "Adesto (Atmel)",
    0x20: "Micron/Numonyx/ST", 0x37: "AMIC", 0x68: "Macronix (alt)",
    0x7F: "ISSI/PMC", 0x9D: "ISSI", 0xBF: "Microchip (SST)",
    0xC2: "Macronix (MXIC)", 0xC8: "GigaDevice", 0xEF: "Winbond",
}
_SPI_JEDEC_CMD = bytes([0x9F])


class Exploit(Exploit):
    """I2C/SPI Bus Probe: address enumeration, JEDEC flash identification."""

    __info__ = {
        "name": "I2C/SPI Bus Probe Scanner",
        "description": (
            "Scans I2C bus for active slave addresses (0x03-0x77) and probes "
            "SPI flash chips for JEDEC manufacturer/device IDs. Identifies "
            "EEPROMs, sensors, RTCs, and flash memory components."
        ),
        "authors": ("Andre Henrique (@mrhenrike)",),
        "references": (
            "https://www.nxp.com/docs/en/user-guide/UM10204.pdf",
            "https://www.jedec.org/standards-documents/docs/jesd216",
        ),
        "devices": ("I2C/SPI peripherals", "EEPROM", "SPI Flash", "Sensors"),
        "severity": "medium",
        "required_hardware": ["i2c_adapter", "spi_adapter"],
    }

    target = OptString("/dev/spidev0.0", "SPI device path for flash probe")
    i2c_bus = OptInteger(1, "I2C bus number (e.g. 1 for /dev/i2c-1)")
    i2c_scan = OptBool(True, "Scan I2C bus for slave addresses")
    spi_scan = OptBool(True, "Probe SPI flash JEDEC ID")
    timeout = OptInteger(2, "Timeout for bus operations in seconds")

    def _scan_i2c(self) -> list[dict[str, str]]:
        """Enumerate I2C slave addresses on the configured bus."""
        found: list[dict[str, str]] = []
        bus_path = "/dev/i2c-{}".format(int(self.i2c_bus))

        try:
            import fcntl
        except ImportError:
            print_error("fcntl not available (Linux required for I2C scanning)")
            return found

        _I2C_SLAVE = 0x0703

        try:
            fd = open(bus_path, "rb", buffering=0)
        except (OSError, PermissionError) as exc:
            print_error("Cannot open {}: {}".format(bus_path, exc))
            return found

        try:
            for addr in range(0x03, 0x78):
                try:
                    fcntl.ioctl(fd, _I2C_SLAVE, addr)
                    fd.read(1)
                    device_type = _I2C_KNOWN_ADDRESSES.get(addr, "Unknown")
                    found.append({
                        "address": "0x{:02X}".format(addr),
                        "device": device_type,
                    })
                except (OSError, IOError):
                    continue
        finally:
            fd.close()

        return found

    @staticmethod
    def _decode_jedec(raw: bytes) -> dict[str, str] | None:
        """Decode a 3-byte JEDEC ID response."""
        if len(raw) < 3:
            return None
        mfr_id, mem_type, capacity = struct.unpack("BBB", raw[:3])
        if mfr_id in (0x00, 0xFF):
            return None
        mfr_name = _JEDEC_MANUFACTURERS.get(mfr_id, "Unknown (0x{:02X})".format(mfr_id))
        size_kb = (1 << capacity) // 1024 if capacity > 0 else 0
        return {
            "manufacturer": mfr_name,
            "manufacturer_id": "0x{:02X}".format(mfr_id),
            "memory_type": "0x{:02X}".format(mem_type),
            "capacity_id": "0x{:02X}".format(capacity),
            "estimated_size": "{}KB".format(size_kb) if size_kb else "unknown",
        }

    def _probe_spi_jedec(self) -> dict[str, str] | None:
        """Send JEDEC Read ID (0x9F) command to SPI device."""
        try:
            import spidev  # type: ignore[import-untyped]
        except ImportError:
            print_warning("spidev not installed; attempting raw device access")
            return self._probe_spi_raw()

        try:
            spi = spidev.SpiDev()
            parts = str(self.target).replace("/dev/spidev", "").split(".")
            bus_n = int(parts[0]) if len(parts) >= 1 else 0
            dev_n = int(parts[1]) if len(parts) >= 2 else 0
            spi.open(bus_n, dev_n)
            spi.max_speed_hz = 1000000
            spi.mode = 0
            resp = spi.xfer2([0x9F, 0x00, 0x00, 0x00])
            spi.close()
            return self._decode_jedec(bytes(resp[1:4]))
        except (OSError, ValueError, IndexError) as exc:
            print_error("SPI probe failed: {}".format(exc))
            return None

    def _probe_spi_raw(self) -> dict[str, str] | None:
        """Fallback: send JEDEC command via raw device file."""
        try:
            with open(str(self.target), "r+b", buffering=0) as fd:
                fd.write(_SPI_JEDEC_CMD + b"\x00\x00\x00")
                resp = fd.read(4)
                if len(resp) >= 3:
                    return self._decode_jedec(resp[:3])
        except (OSError, PermissionError) as exc:
            print_error("Raw SPI access failed on {}: {}".format(self.target, exc))
        return None

    @mute
    def check(self) -> bool:
        """Verify that at least one configured bus is accessible."""
        if self.i2c_scan:
            bus_path = "/dev/i2c-{}".format(int(self.i2c_bus))
            try:
                fd = open(bus_path, "rb", buffering=0)
                fd.close()
                return True
            except (OSError, PermissionError):
                pass
        if self.spi_scan:
            try:
                fd = open(str(self.target), "rb", buffering=0)
                fd.close()
                return True
            except (OSError, PermissionError):
                pass
        return False

    def run(self) -> None:
        """Execute I2C and SPI bus probe."""
        print_status("I2C/SPI Bus Probe starting...")

        if self.i2c_scan:
            print_status("Scanning I2C bus {}...".format(self.i2c_bus))
            devices = self._scan_i2c()
            if devices:
                print_success("Found {} I2C device(s):".format(len(devices)))
                for d in devices:
                    print_info("  {} - {}".format(d["address"], d["device"]))
            else:
                print_info("No I2C devices found on bus {}".format(self.i2c_bus))

        if self.spi_scan:
            print_status("Probing SPI flash JEDEC ID on {}...".format(self.target))
            jedec = self._probe_spi_jedec()
            if jedec:
                print_success("SPI Flash detected:")
                print_info("  Manufacturer: {} [{}]".format(
                    jedec["manufacturer"], jedec["manufacturer_id"],
                ))
                print_info("  Memory type: {}, Capacity: {} [{}]".format(
                    jedec["memory_type"], jedec["estimated_size"], jedec["capacity_id"],
                ))
            else:
                print_info("No SPI flash JEDEC ID detected on {}".format(self.target))
