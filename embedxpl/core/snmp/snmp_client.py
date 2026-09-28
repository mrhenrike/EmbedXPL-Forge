import asyncio
SNMP_IMPORT_ERROR = None
try:
    from pysnmp.hlapi.v3arch.asyncio import (
        SnmpEngine,
        CommunityData,
        UsmUserData,
        UdpTransportTarget,
        ContextData,
        ObjectType,
        ObjectIdentity,
        usmNoAuthProtocol,
        usmHMACSHAAuthProtocol,
        usmHMACMD5AuthProtocol,
        usmNoPrivProtocol,
        usmAesCfb128Protocol,
        usmDESPrivProtocol,
        get_cmd,
    )
except ImportError:
    try:
        from pysnmp.hlapi.asyncio import (
            SnmpEngine,
            CommunityData,
            UsmUserData,
            UdpTransportTarget,
            ContextData,
            ObjectType,
            ObjectIdentity,
            usmNoAuthProtocol,
            usmHMACSHAAuthProtocol,
            usmHMACMD5AuthProtocol,
            usmNoPrivProtocol,
            usmAesCfb128Protocol,
            usmDESPrivProtocol,
            getCmd as get_cmd,
        )
    except ImportError as err:
        SNMP_IMPORT_ERROR = err
        SnmpEngine = None
        CommunityData = None
        UsmUserData = None
        UdpTransportTarget = None
        ContextData = None
        ObjectType = None
        ObjectIdentity = None
        usmNoAuthProtocol = None
        usmHMACSHAAuthProtocol = None
        usmHMACMD5AuthProtocol = None
        usmNoPrivProtocol = None
        usmAesCfb128Protocol = None
        usmDESPrivProtocol = None
        get_cmd = None

from embedxpl.core.exploit.exploit import Exploit
from embedxpl.core.exploit.exploit import Protocol
from embedxpl.core.exploit.option import OptBool
from embedxpl.core.exploit.printer import print_success
from embedxpl.core.exploit.printer import print_error


SNMP_TIMEOUT = 15.0


async def _build_transport_target(snmp_target: str, snmp_port: int, retries: int):
    """Build SNMP transport target across pysnmp API variants."""
    if UdpTransportTarget is None:
        raise RuntimeError("SNMP backend unavailable: {}".format(SNMP_IMPORT_ERROR))
    if hasattr(UdpTransportTarget, "create"):
        return await UdpTransportTarget.create((snmp_target, snmp_port), timeout=SNMP_TIMEOUT, retries=retries)

    return UdpTransportTarget((snmp_target, snmp_port), timeout=SNMP_TIMEOUT, retries=retries)


class SNMPCli:
    """ SNMP Client provides methods to handle communication with SNMP server """

    def __init__(self, snmp_target: str, snmp_port: int, verbosity: bool = False) -> None:
        """ SNMP client constructor

        :param str snmp_target: target SNMP server ip address
        :param port snmp_port: target SNMP server port
        :param bool verbosity: display verbose output
        :return None:
        """

        if SnmpEngine is None or get_cmd is None:
            raise RuntimeError("SNMP backend unavailable: {}".format(SNMP_IMPORT_ERROR))

        self.snmp_target = snmp_target
        self.snmp_port = snmp_port
        self.verbosity = verbosity

        self.peer = "{}:{}".format(self.snmp_target, snmp_port)

    def get(self, community_string: str, oid: str, version: int = 1, retries: int = 0) -> bytes:
        """ Get OID from SNMP server

        :param str community_string: SNMP server community string
        :param str oid: SNMP server oid
        :param int version: SNMP protocol version
        :param int retries: number of retries
        :return bytes: SNMP server response
        """

        return asyncio.run(self.get_cmd(
            community_string,
            oid,
            version,
            retries
        ))

    async def get_cmd(self, community_string: str, oid: str, version: int, retries: int):
        """ Retrieves OID from SNMP server

        :param str community_string: SNMP server community string
        :param str oid: SNMP server oid
        :param int version: SNMP protocol version
        :param int retries: number of retries
        :return bytes: SNMP server response
        """

        snmpEngine = SnmpEngine()
        transport_target = await _build_transport_target(self.snmp_target, self.snmp_port, retries)

        iterator = get_cmd(
            snmpEngine,
            CommunityData(community_string, mpModel=version),
            transport_target,
            ContextData(),
            ObjectType(ObjectIdentity(oid))
        )

        errorIndication, errorStatus, errorIndex, varBinds = await iterator
        snmpEngine.close_dispatcher()

        if errorIndication:
            print_error(
                self.peer,
                "SNMP request error for community '{}': {}".format(community_string, errorIndication),
                verbose=self.verbosity,
            )
        elif errorStatus:
            print_error(
                self.peer,
                "SNMP response error for community '{}': {}".format(community_string, errorStatus.prettyPrint()),
                verbose=self.verbosity,
            )
        else:
            print_success(self.peer, "SNMP valid community string found: '{}'".format(community_string), verbose=self.verbosity)
            return varBinds

        return None

    @staticmethod
    def _resolve_auth_protocol(name: str):
        normalized = str(name or "NONE").strip().upper()
        mapping = {
            "NONE": usmNoAuthProtocol,
            "SHA": usmHMACSHAAuthProtocol,
            "MD5": usmHMACMD5AuthProtocol,
        }
        return mapping.get(normalized)

    @staticmethod
    def _resolve_priv_protocol(name: str):
        normalized = str(name or "NONE").strip().upper()
        mapping = {
            "NONE": usmNoPrivProtocol,
            "AES": usmAesCfb128Protocol,
            "DES": usmDESPrivProtocol,
        }
        return mapping.get(normalized)

    async def get_cmd_v3(
        self,
        username: str,
        oid: str,
        security_level: str = "authPriv",
        auth_protocol: str = "SHA",
        auth_key: str = "",
        priv_protocol: str = "AES",
        priv_key: str = "",
        retries: int = 0,
    ):
        snmpEngine = SnmpEngine()
        transport_target = await _build_transport_target(self.snmp_target, self.snmp_port, retries)

        auth_proto = self._resolve_auth_protocol(auth_protocol)
        priv_proto = self._resolve_priv_protocol(priv_protocol)
        level = str(security_level or "authPriv").strip()

        if auth_proto is None or priv_proto is None:
            print_error(self.peer, "SNMPv3 invalid protocol selection", verbose=self.verbosity)
            return None

        try:
            if level == "noAuthNoPriv":
                user_data = UsmUserData(
                    userName=username,
                    authProtocol=usmNoAuthProtocol,
                    privProtocol=usmNoPrivProtocol,
                )
            elif level == "authNoPriv":
                user_data = UsmUserData(
                    userName=username,
                    authKey=auth_key,
                    authProtocol=auth_proto,
                    privProtocol=usmNoPrivProtocol,
                )
            else:
                user_data = UsmUserData(
                    userName=username,
                    authKey=auth_key,
                    privKey=priv_key,
                    authProtocol=auth_proto,
                    privProtocol=priv_proto,
                )

            iterator = get_cmd(
                snmpEngine,
                user_data,
                transport_target,
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
            )

            errorIndication, errorStatus, _, varBinds = await iterator
            snmpEngine.close_dispatcher()

            if errorIndication:
                print_error(
                    self.peer,
                    "SNMPv3 request error for user '{}': {}".format(username, errorIndication),
                    verbose=self.verbosity,
                )
            elif errorStatus:
                print_error(
                    self.peer,
                    "SNMPv3 response error for user '{}': {}".format(username, errorStatus.prettyPrint()),
                    verbose=self.verbosity,
                )
            else:
                print_success(self.peer, "SNMPv3 valid credentials found for user '{}'".format(username), verbose=self.verbosity)
                return varBinds
        except Exception as err:
            print_error(self.peer, "SNMPv3 authentication error", err, verbose=self.verbosity)
        return None

    def get_v3(
        self,
        username: str,
        oid: str,
        security_level: str = "authPriv",
        auth_protocol: str = "SHA",
        auth_key: str = "",
        priv_protocol: str = "AES",
        priv_key: str = "",
        retries: int = 0,
    ) -> bytes:
        return asyncio.run(
            self.get_cmd_v3(
                username=username,
                oid=oid,
                security_level=security_level,
                auth_protocol=auth_protocol,
                auth_key=auth_key,
                priv_protocol=priv_protocol,
                priv_key=priv_key,
                retries=retries,
            )
        )


# pylint: disable=no-member
class SNMPClient(Exploit):
    """ SNMP Client exploit """

    target_protocol = Protocol.SNMP

    verbosity = OptBool(True, "Enable verbose output: true/false")

    def snmp_create(self, target: str = None, port: int = None) -> SNMPCli:
        """ Create SNMP client

        :param str target: target SNMP server ip address
        :param int port: target SNMP server port
        :return SNMPCli: SNMP client object
        """

        snmp_target = target if target else self.target
        snmp_port = port if port else self.port

        snmp_client = SNMPCli(snmp_target, snmp_port, verbosity=self.verbosity)
        return snmp_client
