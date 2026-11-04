"""Bluetooth Low Energy client using bleak (cross-platform, no root required)."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Optional

from embedxpl.core.exploit.exploit import Exploit
from embedxpl.core.exploit.option import OptInteger, OptString
from embedxpl.core.exploit.printer import (
    print_error,
    print_status,
    print_success,
    print_table,
)


@dataclass
class BTLEService:
    uuid: str
    description: str
    characteristics: list[dict] = field(default_factory=list)


@dataclass
class BTLEDevice:
    address: str
    name: str
    rssi: int
    manufacturer_data: bytes = b""
    service_uuids: list[str] = field(default_factory=list)

    def print_info(self) -> None:
        print_success(f"Device: {self.address}  RSSI: {self.rssi} dBm")
        headers = ("Field", "Value")
        rows = [
            ("Address", self.address),
            ("Name", self.name or "(unknown)"),
            ("RSSI", f"{self.rssi} dBm"),
            ("Services", ", ".join(self.service_uuids) or "none"),
        ]
        print_table(headers, *rows)

    def print_services(self, services: list[BTLEService]) -> None:
        if not services:
            print_status("No services found or device not connectable")
            return
        for svc in services:
            print_status(f"Service: {svc.uuid} ({svc.description})")
            for ch in svc.characteristics:
                print_status(
                    f"  Char {ch['uuid']}  props={ch['properties']}  "
                    f"value={ch.get('value', b'').hex() or '(none)'}"
                )


async def _do_scan(timeout: float, mac: Optional[str]) -> list[BTLEDevice]:
    try:
        from bleak import BleakScanner
    except ImportError:
        print_error("bleak not installed — run: pip install bleak")
        return []

    results: list[BTLEDevice] = []
    devices = await BleakScanner.discover(timeout=timeout, return_adv=True)
    for addr, (dev, adv) in devices.items():
        if mac and addr.upper() != mac.upper():
            continue
        results.append(
            BTLEDevice(
                address=addr,
                name=dev.name or "",
                rssi=adv.rssi,
                manufacturer_data=next(iter(adv.manufacturer_data.values()), b""),
                service_uuids=[str(u) for u in adv.service_uuids],
            )
        )
    return results


async def _do_enumerate(mac: str) -> list[BTLEService]:
    try:
        from bleak import BleakClient
    except ImportError:
        print_error("bleak not installed — run: pip install bleak")
        return []

    services: list[BTLEService] = []
    try:
        async with BleakClient(mac) as client:
            for svc in client.services:
                chars = []
                for ch in svc.characteristics:
                    value = b""
                    if "read" in ch.properties:
                        try:
                            value = bytes(await client.read_gatt_char(ch.uuid))
                        except Exception:
                            pass
                    chars.append(
                        {
                            "uuid": str(ch.uuid),
                            "properties": ", ".join(ch.properties),
                            "value": value,
                        }
                    )
                services.append(
                    BTLEService(
                        uuid=str(svc.uuid),
                        description=svc.description,
                        characteristics=chars,
                    )
                )
    except Exception as err:
        print_error(f"Connection failed: {err}")
    return services


async def _do_write(mac: str, char_uuid: str, data: bytes) -> bool:
    try:
        from bleak import BleakClient
    except ImportError:
        print_error("bleak not installed — run: pip install bleak")
        return False

    try:
        async with BleakClient(mac) as client:
            await client.write_gatt_char(char_uuid, data)
            return True
    except Exception as err:
        print_error(f"Write failed: {err}")
        return False


class BTLEClient(Exploit):
    """Base class for Bluetooth LE exploit/scanner modules."""

    scan_time = OptInteger(10, "Seconds to scan for BLE devices")

    def btle_scan(self, mac: Optional[str] = None) -> list[BTLEDevice]:
        return asyncio.run(_do_scan(float(self.scan_time), mac))

    def btle_enumerate(self, mac: str) -> list[BTLEService]:
        return asyncio.run(_do_enumerate(mac))

    def btle_write(self, mac: str, char_uuid: str, data: bytes) -> bool:
        return asyncio.run(_do_write(mac, char_uuid, data))
