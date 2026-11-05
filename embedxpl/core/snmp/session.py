"""Blocking SNMP operations over the PySNMP asyncio API."""

import asyncio
from types import TracebackType
from typing import Iterator

from embedxpl.core.snmp import snmp_client as backend


class SNMPSession:
    """Keep transport, engine and event loop together for a sequence of requests."""

    def __init__(self, host: str, port: int = 161, community: str = "public",
                 version: int = 1, timeout: float = 3, retries: int = 0) -> None:
        if backend.SNMP_IMPORT_ERROR is not None:
            raise ImportError(f"PySNMP unavailable: {backend.SNMP_IMPORT_ERROR}")
        self.host, self.port = host, int(port)
        self.community, self.version = community, version
        self.timeout, self.retries = float(timeout), retries
        self._runner = None
        self._engine = None

    def __enter__(self) -> "SNMPSession":
        self._runner = asyncio.Runner()
        try:
            self._runner.run(self._open())
        except BaseException:
            self.__exit__(None, None, None)
            raise
        return self

    async def _open(self) -> None:
        self._engine = backend.SnmpEngine()
        self._transport = await backend._build_transport_target(
            self.host, self.port, self.retries, timeout=self.timeout,
        )
        self._auth = backend.CommunityData(self.community, mpModel=self.version)
        self._context = backend.ContextData()

    async def _close(self) -> None:
        if self._engine is not None:
            backend._close_engine(self._engine)

    def __exit__(self, exc_type: type | None, exc: BaseException | None,
                 traceback: TracebackType | None) -> None:
        if self._runner is not None:
            try:
                self._runner.run(self._close())
            finally:
                self._runner.close()
                self._runner = None
                self._engine = None

    def get(self, *oids: str) -> tuple:
        """Return (error indication, error status, error index, variable bindings)."""
        objects = [backend.ObjectType(backend.ObjectIdentity(oid)) for oid in oids]
        return self._runner.run(backend.get_cmd(
            self._engine, self._auth, self._transport, self._context, *objects,
        ))

    def set(self, oid: str, value: str) -> tuple:
        """Set an OCTET STRING value, preserving the PySNMP response tuple."""
        try:
            from pysnmp.hlapi.v3arch.asyncio import OctetString, set_cmd
        except ImportError:
            from pysnmp.hlapi.asyncio import OctetString, setCmd as set_cmd
        obj = backend.ObjectType(backend.ObjectIdentity(oid), OctetString(value))
        return self._runner.run(set_cmd(
            self._engine, self._auth, self._transport, self._context, obj,
        ))

    def walk(self, oid: str, max_rows: int = 2000) -> Iterator[tuple]:
        """Walk one subtree, stopping at its boundary or the requested row limit."""
        try:
            from pysnmp.hlapi.v3arch.asyncio import next_cmd
        except ImportError:
            from pysnmp.hlapi.asyncio import nextCmd as next_cmd
        from pysnmp.proto.rfc1905 import EndOfMibView, NoSuchInstance, NoSuchObject

        prefix = tuple(int(part) for part in oid.strip(".").split("."))
        previous = prefix
        for _ in range(max_rows):
            obj = backend.ObjectType(backend.ObjectIdentity(previous))
            result = self._runner.run(next_cmd(
                self._engine, self._auth, self._transport, self._context, obj,
            ))
            error, status, _, bindings = result
            if error or status:
                yield result
                return
            if not bindings:
                return
            name, value = bindings[0]
            current = tuple(name)
            if (current[:len(prefix)] != prefix or current <= previous
                    or isinstance(value, (EndOfMibView, NoSuchInstance, NoSuchObject))):
                return
            yield result
            previous = current
