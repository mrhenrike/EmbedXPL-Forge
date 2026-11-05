"""SNMP compatibility tests using a local UDP agent and the installed PySNMP API."""

import socketserver
import threading
from unittest.mock import AsyncMock, Mock

import pytest
from pyasn1.codec.ber import decoder, encoder
from pysnmp.proto import api
from pysnmp.proto.rfc1905 import EndOfMibView

from embedxpl.core.snmp import snmp_client as backend
from embedxpl.core.snmp.session import SNMPSession

SYS_DESCR = "1.3.6.1.2.1.1.1.0"
SYS_CONTACT = "1.3.6.1.2.1.1.4.0"


@pytest.fixture
def snmp_agent():
    protocol = api.PROTOCOL_MODULES[1]
    values = {
        tuple(map(int, SYS_DESCR.split("."))): protocol.OctetString("Fixture router"),
        tuple(map(int, SYS_CONTACT.split("."))): protocol.OctetString("original"),
        (1, 3, 6, 1, 2, 1, 2, 1, 0): protocol.Integer(3),
    }
    requests = []

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            packet, transport = self.request
            message, _ = decoder.decode(packet, asn1Spec=protocol.Message())
            version = int(message["version"])
            p = api.PROTOCOL_MODULES[version]
            message, _ = decoder.decode(packet, asn1Spec=p.Message())
            pdu = p.apiMessage.get_pdu(message)
            response = p.apiMessage.get_response(message)
            response_pdu = p.apiMessage.get_pdu(response)
            bindings = []
            for name, value in p.apiPDU.get_varbinds(pdu):
                oid = tuple(name)
                requests.append((version, str(p.apiMessage.get_community(message)), oid))
                if pdu.tagSet == p.SetRequestPDU.tagSet:
                    values[oid] = value
                elif pdu.tagSet == p.GetNextRequestPDU.tagSet:
                    oid = next((key for key in sorted(values) if key > oid), oid)
                bindings.append((oid, values.get(oid, EndOfMibView())))
            p.apiPDU.set_varbinds(response_pdu, bindings)
            transport.sendto(encoder.encode(response), self.client_address)

    server = socketserver.UDPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    try:
        yield server.server_address, requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.mark.parametrize("version", [0, 1])
def test_get_set_and_walk_with_real_pysnmp(snmp_agent, version):
    (host, port), requests = snmp_agent
    with SNMPSession(host, port, "fixture", version=version, timeout=0.5) as session:
        error, status, _, bindings = session.get(SYS_DESCR)
        assert not error and not status
        assert str(bindings[0][1]) == "Fixture router"
        error, status, _, _ = session.set(SYS_CONTACT, "updated")
        assert not error and not status
        assert str(session.get(SYS_CONTACT)[3][0][1]) == "updated"
        rows = list(session.walk("1.3.6.1.2.1.1"))
        assert [str(row[3][0][0]) for row in rows] == [SYS_DESCR, SYS_CONTACT]
        assert len(list(session.walk("1.3.6.1.2.1.1", max_rows=1))) == 1
    assert requests and all(v == version and community == "fixture" for v, community, _ in requests)
    assert session._runner is None


def test_session_closes_when_transport_initialization_fails(monkeypatch):
    engine = Mock()
    monkeypatch.setattr(backend, "SnmpEngine", lambda: engine)
    monkeypatch.setattr(backend.UdpTransportTarget, "create", AsyncMock(side_effect=OSError("DNS failed")))
    with pytest.raises(OSError, match="DNS failed"):
        with SNMPSession("invalid"):
            pytest.fail("session should not open")
    engine.close_dispatcher.assert_called_once()


def test_session_closes_when_request_raises(monkeypatch):
    engine = Mock()
    monkeypatch.setattr(backend, "SnmpEngine", lambda: engine)
    monkeypatch.setattr(backend.UdpTransportTarget, "create", AsyncMock(return_value=Mock()))
    monkeypatch.setattr(backend, "get_cmd", AsyncMock(side_effect=RuntimeError("request failed")))
    with pytest.raises(RuntimeError, match="request failed"):
        with SNMPSession("127.0.0.1") as session:
            session.get(SYS_DESCR)
    engine.close_dispatcher.assert_called_once()


@pytest.mark.parametrize("v3", [False, True])
def test_core_client_closes_when_transport_fails(monkeypatch, v3):
    engine = Mock()
    monkeypatch.setattr(backend, "SnmpEngine", lambda: engine)
    monkeypatch.setattr(backend, "_build_transport_target", AsyncMock(side_effect=OSError("DNS failed")))
    client = backend.SNMPCli("invalid", 161)
    if v3:
        assert client.get_v3("fixture", SYS_DESCR) is None
    else:
        with pytest.raises(OSError, match="DNS failed"):
            client.get("public", SYS_DESCR)
    engine.close_dispatcher.assert_called_once()
