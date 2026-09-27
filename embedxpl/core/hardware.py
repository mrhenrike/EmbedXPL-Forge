# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""Hardware Requirements Gate for EmbedXPL-Forge.

Defines canonical hardware identifiers, human-readable descriptions,
purchasing examples with product names, chipsets, pricing, and driver
references. Provides a pre-run gate function that inspects a module's
__info__["required_hardware"] list and warns the operator before
execution when physical adapters (UART, BLE, SDR, etc.) are needed.

The gate can operate in interactive mode (prompt s/N) or strict mode
(raise RuntimeError), making it suitable for both manual pentesting
sessions and automated pipeline scans.

References:
  - Internal framework convention for hardware-dependent modules
  - OWASP IoT Attack Surface Areas: hardware interfaces

Version: 1.0.0
"""

import sys
import textwrap
from enum import Enum, unique


@unique
class HWReq(str, Enum):
    """Canonical hardware requirement identifiers.

    Each member maps to a physical adapter or interface that a module
    may require. Values are lowercase snake_case strings used inside
    __info__["required_hardware"] lists across all exploit and scanner
    modules.

    Attributes:
        WIFI_MONITOR: Wi-Fi adapter with monitor mode and injection.
        BLE_ADAPTER: Bluetooth Low Energy USB dongle with HCI access.
        SDR_TXRX: Software-Defined Radio with TX/RX capability.
        RFID_PROXMARK: Proxmark3 or compatible RFID research platform.
        CAN_INTERFACE: USB-to-CAN or SocketCAN-compatible adapter.
        UART_ADAPTER: USB-to-UART TTL serial adapter (3.3V/5V).
        ULTRASONIC_SPEAKER: Ultrasonic transducer for inaudible commands.
        THREAD_BORDER_USB: Thread/802.15.4 USB border router dongle.
    """

    WIFI_MONITOR = "wifi_monitor_mode"
    BLE_ADAPTER = "ble_adapter"
    SDR_TXRX = "sdr_txrx"
    RFID_PROXMARK = "rfid_proxmark"
    CAN_INTERFACE = "can_interface"
    UART_ADAPTER = "uart_ttl_adapter"
    ULTRASONIC_SPEAKER = "ultrasonic_speaker"
    THREAD_BORDER_USB = "thread_border_usb"


HARDWARE_DESCRIPTIONS = {
    HWReq.WIFI_MONITOR: (
        "Wi-Fi adapter capable of monitor mode and packet injection. "
        "Required for passive sniffing, deauthentication frames, and "
        "raw 802.11 frame crafting on 2.4/5 GHz bands."
    ),
    HWReq.BLE_ADAPTER: (
        "Bluetooth Low Energy USB adapter with raw HCI access. Needed "
        "for BLE advertisement scanning, GATT service enumeration, "
        "device spoofing, pairing hijack, and connection manipulation."
    ),
    HWReq.SDR_TXRX: (
        "Software-Defined Radio with transmit and receive capability. "
        "Used for ISM-band signal capture, replay attacks, and RF "
        "protocol analysis on sub-GHz (315/433/868/915 MHz) and "
        "2.4 GHz frequencies."
    ),
    HWReq.RFID_PROXMARK: (
        "Proxmark3 or compatible RFID/NFC research tool. Required for "
        "125 kHz LF and 13.56 MHz HF card cloning, reader emulation, "
        "protocol sniffing, key recovery, and credential extraction."
    ),
    HWReq.CAN_INTERFACE: (
        "CAN bus adapter (USB-to-CAN or SocketCAN-compatible). Required "
        "for automotive and industrial CAN 2.0 / CAN FD frame injection, "
        "passive sniffing, UDS diagnostics, and bus fuzzing."
    ),
    HWReq.UART_ADAPTER: (
        "USB-to-UART TTL serial adapter (3.3V or 5V logic levels). "
        "Required for serial console access, U-Boot bootloader "
        "interaction, firmware dump over console, and root shell "
        "access on embedded devices with exposed debug pads."
    ),
    HWReq.ULTRASONIC_SPEAKER: (
        "Ultrasonic transducer or parametric speaker array capable of "
        "emitting modulated audio above 20 kHz. Required for inaudible "
        "voice command injection (DolphinAttack, SurfingAttack) against "
        "MEMS microphones in smart assistants."
    ),
    HWReq.THREAD_BORDER_USB: (
        "Thread/OpenThread USB border router dongle (802.15.4 radio). "
        "Required for Thread mesh network packet capture, commissioning "
        "protocol attacks, and IEEE 802.15.4 frame injection."
    ),
}


HARDWARE_EXAMPLES = {
    HWReq.WIFI_MONITOR: {
        "product_name": "Alfa AWUS036ACH",
        "chipset": "Realtek RTL8812AU",
        "price_usd": 65.00,
        "buy_url": "https://www.alfa.com.tw/products/awus036ach",
        "driver_tools": ["aircrack-ng", "rtl8812au-dkms", "hostapd"],
        "os_support": ["Linux", "Windows (limited)", "macOS (limited)"],
    },
    HWReq.BLE_ADAPTER: {
        "product_name": "Sena UD100 / CSR 4.0 USB Dongle",
        "chipset": "CSR8510 / TI CC2540",
        "price_usd": 15.00,
        "buy_url": "https://www.senanetworks.com/ud100.html",
        "driver_tools": ["bluez", "hcitool", "gatttool", "bettercap"],
        "os_support": ["Linux", "Windows", "macOS"],
    },
    HWReq.SDR_TXRX: {
        "product_name": "HackRF One",
        "chipset": "MAX2837 / MAX5864 / CPLD",
        "price_usd": 350.00,
        "buy_url": "https://greatscottgadgets.com/hackrf/one/",
        "driver_tools": ["gnuradio", "gqrx", "inspectrum", "URH"],
        "os_support": ["Linux", "Windows", "macOS"],
    },
    HWReq.RFID_PROXMARK: {
        "product_name": "Proxmark3 RDV4",
        "chipset": "AT91SAM7S512 + Xilinx FPGA",
        "price_usd": 300.00,
        "buy_url": "https://proxmark.com/",
        "driver_tools": ["proxmark3 client", "iceman firmware", "libnfc"],
        "os_support": ["Linux", "Windows", "macOS"],
    },
    HWReq.CAN_INTERFACE: {
        "product_name": "CANable 2.0 (USB-C)",
        "chipset": "STM32G0B1",
        "price_usd": 40.00,
        "buy_url": "https://canable.io/",
        "driver_tools": ["can-utils", "socketcan", "python-can"],
        "os_support": ["Linux", "Windows"],
    },
    HWReq.UART_ADAPTER: {
        "product_name": "FTDI FT232RL USB-to-UART",
        "chipset": "FTDI FT232RL",
        "price_usd": 12.00,
        "buy_url": "https://ftdichip.com/products/ft232rl/",
        "driver_tools": ["minicom", "picocom", "screen", "PuTTY"],
        "os_support": ["Linux", "Windows", "macOS"],
    },
    HWReq.ULTRASONIC_SPEAKER: {
        "product_name": "Murata MA40S4S (40 kHz piezo array)",
        "chipset": "Custom amplifier + DAC board",
        "price_usd": 85.00,
        "buy_url": "https://www.murata.com/products/sensor/ultrasonic",
        "driver_tools": ["audacity (mod carrier)", "custom MCU firmware"],
        "os_support": ["Linux", "Windows", "macOS"],
    },
    HWReq.THREAD_BORDER_USB: {
        "product_name": "Nordic nRF52840 Dongle",
        "chipset": "nRF52840 (ARM Cortex-M4F)",
        "price_usd": 10.00,
        "buy_url": "https://www.nordicsemi.com/Products/Development-hardware/nRF52840-Dongle",
        "driver_tools": ["wpantund", "ot-commissioner", "wireshark (802.15.4)"],
        "os_support": ["Linux", "Windows", "macOS"],
    },
}


_COL_WIDTHS = {
    "id": 22,
    "product": 36,
    "chipset": 28,
    "price": 10,
}


def _resolve_hw_enum(identifier):
    """Resolve a string identifier to its HWReq enum member.

    Args:
        identifier: String matching a HWReq value (e.g., "ble_adapter").

    Returns:
        HWReq member if found, None otherwise.
    """
    for member in HWReq:
        if member.value == identifier:
            return member
    return None


def _build_separator():
    """Build a horizontal separator line for the hardware table.

    Returns:
        String with '+---+---+...' formatting.
    """
    parts = []
    for key in ("id", "product", "chipset", "price"):
        parts.append("-" * (_COL_WIDTHS[key] + 2))
    return "+" + "+".join(parts) + "+"


def _format_hardware_table(requirements):
    """Build an ASCII table summarizing required hardware adapters.

    Args:
        requirements: List of resolved HWReq enum members.

    Returns:
        Multi-line string with aligned columns for ID, product,
        chipset, and approximate USD price.
    """
    sep = _build_separator()
    header = "| {:<{}} | {:<{}} | {:<{}} | {:<{}} |".format(
        "Hardware ID", _COL_WIDTHS["id"],
        "Recommended Product", _COL_WIDTHS["product"],
        "Chipset", _COL_WIDTHS["chipset"],
        "Price USD", _COL_WIDTHS["price"],
    )

    lines = [sep, header, sep]
    for hw in requirements:
        ex = HARDWARE_EXAMPLES.get(hw, {})
        product = ex.get("product_name", "N/A")
        if len(product) > _COL_WIDTHS["product"]:
            product = product[:_COL_WIDTHS["product"] - 3] + "..."
        chipset = ex.get("chipset", "N/A")
        if len(chipset) > _COL_WIDTHS["chipset"]:
            chipset = chipset[:_COL_WIDTHS["chipset"] - 3] + "..."
        price_str = "${:.0f}".format(ex.get("price_usd", 0))

        lines.append("| {:<{}} | {:<{}} | {:<{}} | {:<{}} |".format(
            hw.value, _COL_WIDTHS["id"],
            product, _COL_WIDTHS["product"],
            chipset, _COL_WIDTHS["chipset"],
            price_str, _COL_WIDTHS["price"],
        ))
    lines.append(sep)
    return "\n".join(lines)


def _format_hardware_detail(hw_member):
    """Format detailed info block for a single hardware requirement.

    Args:
        hw_member: HWReq enum member.

    Returns:
        Multi-line string with description, product recommendation,
        chipset, price, purchase URL, driver tools, and OS support.
    """
    desc = HARDWARE_DESCRIPTIONS.get(hw_member, "No description available.")
    ex = HARDWARE_EXAMPLES.get(hw_member, {})
    wrapped_desc = textwrap.fill(desc, width=72, initial_indent="    ",
                                 subsequent_indent="    ")
    lines = [
        "  [{id}]".format(id=hw_member.value),
        wrapped_desc,
        "    Product     : {v}".format(v=ex.get("product_name", "N/A")),
        "    Chipset     : {v}".format(v=ex.get("chipset", "N/A")),
        "    Price       : ${p:.2f} USD".format(p=ex.get("price_usd", 0)),
        "    Purchase    : {v}".format(v=ex.get("buy_url", "N/A")),
        "    Drivers     : {v}".format(v=", ".join(ex.get("driver_tools", ["-"]))),
        "    OS Support  : {v}".format(v=", ".join(ex.get("os_support", ["-"]))),
    ]
    return "\n".join(lines)


def list_all_hardware():
    """Return a sorted list of all canonical hardware identifiers.

    Returns:
        List of (HWReq member, description string) tuples, sorted by
        enum value.
    """
    items = []
    for member in sorted(HWReq, key=lambda m: m.value):
        desc = HARDWARE_DESCRIPTIONS.get(member, "")
        items.append((member, desc))
    return items


def get_hardware_summary(identifier):
    """Retrieve complete metadata for a single hardware identifier.

    Args:
        identifier: String matching a HWReq value, or HWReq member.

    Returns:
        Dict with keys: id, description, product_name, chipset,
        price_usd, buy_url, driver_tools, os_support.
        Returns None if the identifier is not recognized.
    """
    if isinstance(identifier, str):
        hw = _resolve_hw_enum(identifier)
    elif isinstance(identifier, HWReq):
        hw = identifier
    else:
        return None

    if hw is None:
        return None

    ex = HARDWARE_EXAMPLES.get(hw, {})
    return {
        "id": hw.value,
        "description": HARDWARE_DESCRIPTIONS.get(hw, ""),
        "product_name": ex.get("product_name", ""),
        "chipset": ex.get("chipset", ""),
        "price_usd": ex.get("price_usd", 0.0),
        "buy_url": ex.get("buy_url", ""),
        "driver_tools": list(ex.get("driver_tools", [])),
        "os_support": list(ex.get("os_support", [])),
    }


def estimate_total_cost(identifiers):
    """Calculate estimated total hardware cost for a list of identifiers.

    Args:
        identifiers: Iterable of string hardware identifiers.

    Returns:
        Float with total estimated USD cost. Unknown identifiers
        contribute zero.
    """
    total = 0.0
    for item in identifiers:
        hw = _resolve_hw_enum(item) if isinstance(item, str) else item
        if hw is not None:
            ex = HARDWARE_EXAMPLES.get(hw, {})
            total += ex.get("price_usd", 0.0)
    return total


def check_hardware_requirements(module_info, interactive=True):
    """Gate-check hardware requirements before module execution.

    Reads the "required_hardware" key from a module __info__ dict,
    resolves each identifier to its HWReq canonical form, and presents
    a detailed warning with product recommendations, pricing, driver
    information, and OS compatibility.

    In interactive mode, prompts the operator for confirmation (s/N).
    In non-interactive mode, raises RuntimeError when hardware is
    required, allowing pipeline orchestrators to skip modules that
    need physical adapters.

    Args:
        module_info: Dict containing module metadata (the __info__ dict).
        interactive: If True, prompt user for confirmation via stdin.
            If False, raise RuntimeError when hardware is required.

    Returns:
        True if no hardware is required or the operator confirmed
        availability. False if the operator declined execution.

    Raises:
        RuntimeError: In non-interactive mode when the module declares
            hardware requirements that cannot be auto-verified.
    """
    raw_requirements = module_info.get("required_hardware", [])
    if not raw_requirements:
        return True

    resolved = []
    unrecognized = []
    for item in raw_requirements:
        hw = _resolve_hw_enum(item)
        if hw is not None:
            resolved.append(hw)
        else:
            unrecognized.append(str(item))

    module_name = module_info.get("name", "Unknown Module")
    total_cost = estimate_total_cost(resolved)

    print("\n" + "=" * 78)
    print("  HARDWARE REQUIREMENTS - {name}".format(name=module_name))
    print("=" * 78)
    print()
    print("  This module requires {n} physical hardware adapter(s):".format(
        n=len(resolved) + len(unrecognized)
    ))
    print()

    if resolved:
        print(_format_hardware_table(resolved))
        print()
        for hw in resolved:
            print(_format_hardware_detail(hw))
            print()

    if unrecognized:
        print("  Unrecognized hardware identifiers (not in HWReq catalog):")
        for item in unrecognized:
            print("    - {v}".format(v=item))
        print()

    print("  Estimated total hardware cost: ${t:.2f} USD".format(t=total_cost))
    print()
    print("-" * 78)
    print(
        "  WARNING: Running this module without the listed hardware will\n"
        "  produce connection errors, timeouts, or incomplete results.\n"
        "  Ensure all adapters are physically connected and drivers are\n"
        "  loaded before proceeding."
    )
    print("-" * 78)

    if not interactive:
        hw_list = ", ".join(r.value for r in resolved)
        if unrecognized:
            hw_list += ", " + ", ".join(unrecognized)
        raise RuntimeError(
            "Module '{name}' requires hardware: {hw}. "
            "Cannot proceed in non-interactive mode.".format(
                name=module_name, hw=hw_list,
            )
        )

    try:
        answer = input("\n  Proceed with execution? (s/N): ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False

    return answer in ("s", "sim", "y", "yes")


# Integration: add to embedxpl/core/exploit/exploit.py Exploit class:
# def _pre_run(self):
#     from embedxpl.core.hardware import check_hardware_requirements
#     if not check_hardware_requirements(self.__info__, interactive=True):
#         raise SystemExit(0)
#     super()._pre_run()
