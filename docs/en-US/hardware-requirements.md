# Hardware Requirements

This document lists all physical hardware adapters that EmbedXPL-Forge
modules may require. Each entry includes a recommended product,
chipset information, approximate pricing, purchase links, required
drivers/tools, and OS compatibility.

Modules declare their requirements via the `required_hardware` key in
the `__info__` dict. The framework's hardware gate
(`embedxpl.core.hardware`) warns the operator before execution when
physical adapters are needed.

For a machine-generated version of this file (reflecting the latest
module data), run:

```bash
python -m embedxpl.tools.docgen --lang en-US --output docs/en-US/
```


## Wi-Fi Monitor (`wifi_monitor_mode`)

Wi-Fi adapter capable of monitor mode and packet injection. Required
for passive sniffing, deauthentication frames, and raw 802.11 frame
crafting on 2.4/5 GHz bands.

| Field | Value |
|-------|-------|
| **Product** | Alfa AWUS036ACH |
| **Chipset** | Realtek RTL8812AU |
| **Price (USD)** | $65.00 |
| **Purchase** | <https://www.alfa.com.tw/products/awus036ach> |
| **Drivers/Tools** | aircrack-ng, rtl8812au-dkms, hostapd |
| **OS Support** | Linux, Windows (limited), macOS (limited) |

### Usage Notes

- Best performance on Linux with patched rtl8812au drivers.
- Monitor mode must be enabled via `airmon-ng start wlan0`.
- Some chipset revisions require specific firmware versions.
- Modules using this adapter: Wi-Fi deauth, WPA handshake capture,
  evil twin AP, PMKID extraction.


## BLE Adapter (`ble_adapter`)

Bluetooth Low Energy USB adapter with raw HCI access. Needed for BLE
advertisement scanning, GATT service enumeration, device spoofing,
pairing hijack, and connection manipulation.

| Field | Value |
|-------|-------|
| **Product** | Sena UD100 / CSR 4.0 USB Dongle |
| **Chipset** | CSR8510 / TI CC2540 |
| **Price (USD)** | $15.00 |
| **Purchase** | <https://www.senanetworks.com/ud100.html> |
| **Drivers/Tools** | bluez, hcitool, gatttool, bettercap |
| **OS Support** | Linux, Windows, macOS |

### Usage Notes

- Requires BlueZ 5.50+ for full BLE scanning support.
- TI CC2540 variant offers better raw HCI access for sniffer mode.
- Some modules also support the Ubertooth One for link-layer sniffing.
- Modules using this adapter: BLE enumeration, GATT fuzzing,
  BLE pairing hijack, beacon spoofing.


## SDR TX/RX (`sdr_txrx`)

Software-Defined Radio with transmit and receive capability. Used for
ISM-band signal capture, replay attacks, and RF protocol analysis on
sub-GHz (315/433/868/915 MHz) and 2.4 GHz frequencies.

| Field | Value |
|-------|-------|
| **Product** | HackRF One |
| **Chipset** | MAX2837 / MAX5864 / CPLD |
| **Price (USD)** | $350.00 |
| **Purchase** | <https://greatscottgadgets.com/hackrf/one/> |
| **Drivers/Tools** | gnuradio, gqrx, inspectrum, URH |
| **OS Support** | Linux, Windows, macOS |

### Usage Notes

- Covers 1 MHz to 6 GHz with 20 MHz bandwidth.
- Half-duplex: cannot transmit and receive simultaneously.
- For full-duplex operations, consider USRP B200/B210.
- Modules using this adapter: sub-GHz replay, ISM-band analysis,
  garage door signal capture, RF jamming detection.


## RFID Proxmark (`rfid_proxmark`)

Proxmark3 or compatible RFID/NFC research tool. Required for
125 kHz LF and 13.56 MHz HF card cloning, reader emulation,
protocol sniffing, key recovery, and credential extraction.

| Field | Value |
|-------|-------|
| **Product** | Proxmark3 RDV4 |
| **Chipset** | AT91SAM7S512 + Xilinx FPGA |
| **Price (USD)** | $300.00 |
| **Purchase** | <https://proxmark.com/> |
| **Drivers/Tools** | proxmark3 client, iceman firmware, libnfc |
| **OS Support** | Linux, Windows, macOS |

### Usage Notes

- Flash the Iceman community firmware for extended card support.
- RDV4 includes a built-in battery for standalone operations.
- Supports: HID, EM4100, T55xx, Mifare Classic, DESFire, iCLASS.
- Modules using this adapter: RFID clone, Mifare key recovery,
  access badge emulation, NFC relay attack.


## CAN Interface (`can_interface`)

CAN bus adapter (USB-to-CAN or SocketCAN-compatible). Required for
automotive and industrial CAN 2.0 / CAN FD frame injection, passive
sniffing, UDS diagnostics, and bus fuzzing.

| Field | Value |
|-------|-------|
| **Product** | CANable 2.0 (USB-C) |
| **Chipset** | STM32G0B1 |
| **Price (USD)** | $40.00 |
| **Purchase** | <https://canable.io/> |
| **Drivers/Tools** | can-utils, socketcan, python-can |
| **OS Support** | Linux, Windows |

### Usage Notes

- CANable 2.0 supports both CAN 2.0B and CAN FD.
- On Linux, use `slcand` or `candleLight` firmware for SocketCAN.
- For automotive ECU testing, pair with an OBD-II to DB9 adapter.
- Modules using this adapter: CAN bus sniffing, UDS scanning,
  CAN frame injection, ECU fuzzing.


## UART Adapter (`uart_ttl_adapter`)

USB-to-UART TTL serial adapter (3.3V or 5V logic levels). Required
for serial console access, U-Boot bootloader interaction, firmware
dump over console, and root shell access on embedded devices with
exposed debug pads.

| Field | Value |
|-------|-------|
| **Product** | FTDI FT232RL USB-to-UART |
| **Chipset** | FTDI FT232RL |
| **Price (USD)** | $12.00 |
| **Purchase** | <https://ftdichip.com/products/ft232rl/> |
| **Drivers/Tools** | minicom, picocom, screen, PuTTY |
| **OS Support** | Linux, Windows, macOS |

### Usage Notes

- Verify target logic level before connecting (3.3V vs 5V).
- Cross-connect TX/RX: adapter TX to device RX and vice versa.
- Common baud rates: 9600, 19200, 38400, 57600, 115200.
- Modules using this adapter: UART root shell, U-Boot interrupt,
  firmware serial dump, bootloader modification.


## Ultrasonic Speaker (`ultrasonic_speaker`)

Ultrasonic transducer or parametric speaker array capable of emitting
modulated audio above 20 kHz. Required for inaudible voice command
injection (DolphinAttack, SurfingAttack) against MEMS microphones
in smart assistants.

| Field | Value |
|-------|-------|
| **Product** | Murata MA40S4S (40 kHz piezo array) |
| **Chipset** | Custom amplifier + DAC board |
| **Price (USD)** | $85.00 |
| **Purchase** | <https://www.murata.com/products/sensor/ultrasonic> |
| **Drivers/Tools** | audacity (mod carrier), custom MCU firmware |
| **OS Support** | Linux, Windows, macOS |

### Usage Notes

- Effective range: 1-3 meters depending on transducer power.
- Requires an ultrasonic carrier signal modulated with voice commands.
- Works against Google Home, Amazon Echo, Apple Siri devices.
- Modules using this adapter: DolphinAttack voice injection,
  ultrasonic command replay.


## Thread Border USB (`thread_border_usb`)

Thread/OpenThread USB border router dongle (802.15.4 radio). Required
for Thread mesh network packet capture, commissioning protocol
attacks, and IEEE 802.15.4 frame injection.

| Field | Value |
|-------|-------|
| **Product** | Nordic nRF52840 Dongle |
| **Chipset** | nRF52840 (ARM Cortex-M4F) |
| **Price (USD)** | $10.00 |
| **Purchase** | <https://www.nordicsemi.com/Products/Development-hardware/nRF52840-Dongle> |
| **Drivers/Tools** | wpantund, ot-commissioner, wireshark (802.15.4) |
| **OS Support** | Linux, Windows, macOS |

### Usage Notes

- Flash with the OpenThread sniffer firmware for Wireshark integration.
- Supports IEEE 802.15.4 channels 11-26 (2.4 GHz band).
- Can act as a Thread border router for network commissioning attacks.
- Modules using this adapter: Thread network sniffing, 802.15.4 frame
  injection, Thread commissioning exploit.


## Cost Summary

| Adapter | Price (USD) |
|---------|-------------|
| Wi-Fi Monitor (Alfa AWUS036ACH) | $65.00 |
| BLE Adapter (CSR 4.0) | $15.00 |
| SDR TX/RX (HackRF One) | $350.00 |
| RFID Proxmark (RDV4) | $300.00 |
| CAN Interface (CANable 2.0) | $40.00 |
| UART Adapter (FT232RL) | $12.00 |
| Ultrasonic Speaker (MA40S4S) | $85.00 |
| Thread Border USB (nRF52840) | $10.00 |
| **Total (all adapters)** | **$877.00** |

Most modules require only network connectivity (no special hardware).
Physical adapters are needed primarily for RF, serial console, and
bus-level attack modules.
