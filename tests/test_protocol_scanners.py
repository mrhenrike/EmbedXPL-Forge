"""Tests for IoT and HW protocol scanner modules: structural and info validation."""

import pytest

from embedxpl.core.exploit.exploit import Exploit


def _get_info(cls):
    """Retrieve __info__ dict handling metaclass name mangling."""
    for attr in dir(cls):
        if attr.endswith("__info__") and attr.startswith("_"):
            return getattr(cls, attr)
    return getattr(cls, "__info__", {})


SCANNER_MODULES = [
    ("embedxpl.modules.scanners.protocols.iot.ble_scan", "BLE GATT"),
    ("embedxpl.modules.scanners.protocols.iot.mqtt_protocol_scan", "MQTT Protocol"),
    ("embedxpl.modules.scanners.protocols.iot.upnp_ssdp_scan", "UPnP/SSDP"),
    ("embedxpl.modules.scanners.protocols.iot.coap_protocol_scan", "CoAP Protocol"),
    ("embedxpl.modules.scanners.protocols.iot.zigbee_scan", "Zigbee PAN"),
    ("embedxpl.modules.scanners.protocols.iot.zwave_scan", "Z-Wave"),
    ("embedxpl.modules.scanners.protocols.iot.lorawan_scan", "LoRaWAN"),
    ("embedxpl.modules.scanners.protocols.iot.wifi_scan", "WiFi"),
    ("embedxpl.modules.scanners.protocols.iot.dds_rtps_scan", "DDS/RTPS"),
    ("embedxpl.modules.scanners.protocols.hw.jtag_swd_scan", "JTAG/SWD"),
    ("embedxpl.modules.scanners.protocols.hw.uart_console_scan", "UART Console"),
    ("embedxpl.modules.scanners.protocols.hw.i2c_spi_probe", "I2C/SPI"),
]


@pytest.fixture(params=SCANNER_MODULES, ids=[m[1] for m in SCANNER_MODULES])
def scanner_cls(request):
    import importlib
    mod_path, _label = request.param
    mod = importlib.import_module(mod_path)
    return mod.Exploit


class TestScannerInheritance:
    def test_inherits_exploit(self, scanner_cls):
        assert issubclass(scanner_cls, Exploit)


class TestScannerInfo:
    def test_has_info(self, scanner_cls):
        info = _get_info(scanner_cls)
        assert isinstance(info, dict)
        assert "name" in info
        assert "description" in info

    def test_has_run(self, scanner_cls):
        assert callable(getattr(scanner_cls, "run", None))

    def test_has_check(self, scanner_cls):
        assert callable(getattr(scanner_cls, "check", None))


class TestScannerInstantiation:
    def test_instantiate(self, scanner_cls):
        instance = scanner_cls()
        assert instance is not None

    def test_options_property(self, scanner_cls):
        instance = scanner_cls()
        opts = instance.options
        assert isinstance(opts, (dict, list))
        assert len(opts) > 0

    def test_not_destructive_by_default(self, scanner_cls):
        instance = scanner_cls()
        if hasattr(instance, "destructive"):
            assert instance.destructive is False or instance.destructive is not True


# ── Specific scanner features ──

class TestBLEScanner:
    def test_hci_device_option(self):
        from embedxpl.modules.scanners.protocols.iot.ble_scan import Exploit
        e = Exploit()
        assert hasattr(e, "hci_device")


class TestMQTTScanner:
    def test_port_option(self):
        from embedxpl.modules.scanners.protocols.iot.mqtt_protocol_scan import Exploit
        e = Exploit()
        assert hasattr(e, "port")


class TestUPnPScanner:
    def test_fetch_desc_option(self):
        from embedxpl.modules.scanners.protocols.iot.upnp_ssdp_scan import Exploit
        e = Exploit()
        assert hasattr(e, "fetch_desc")


class TestCoAPScanner:
    def test_dtls_port(self):
        from embedxpl.modules.scanners.protocols.iot.coap_protocol_scan import Exploit
        e = Exploit()
        assert hasattr(e, "dtls_port")


class TestZigbeeScanner:
    def test_channel_option(self):
        from embedxpl.modules.scanners.protocols.iot.zigbee_scan import Exploit
        e = Exploit()
        assert hasattr(e, "channel")

    def test_baud_rate(self):
        from embedxpl.modules.scanners.protocols.iot.zigbee_scan import Exploit
        e = Exploit()
        assert hasattr(e, "baud_rate")


class TestZWaveScanner:
    def test_frequency(self):
        from embedxpl.modules.scanners.protocols.iot.zwave_scan import Exploit
        e = Exploit()
        assert hasattr(e, "frequency")


class TestLoRaWANScanner:
    def test_region(self):
        from embedxpl.modules.scanners.protocols.iot.lorawan_scan import Exploit
        e = Exploit()
        assert hasattr(e, "region")


class TestJTAGScanner:
    def test_baudrate(self):
        from embedxpl.modules.scanners.protocols.hw.jtag_swd_scan import Exploit
        e = Exploit()
        assert hasattr(e, "baudrate")


class TestUARTScanner:
    def test_bauds(self):
        from embedxpl.modules.scanners.protocols.hw.uart_console_scan import Exploit
        e = Exploit()
        assert hasattr(e, "bauds")


class TestI2CSPIScanner:
    def test_i2c_bus(self):
        from embedxpl.modules.scanners.protocols.hw.i2c_spi_probe import Exploit
        e = Exploit()
        assert hasattr(e, "i2c_bus")
