import paramiko

from embedxpl.core.exploit.exploit import Exploit
from embedxpl.core.exploit.exploit import Protocol
from embedxpl.core.exploit.option import OptBool
from embedxpl.core.exploit.printer import print_error
from embedxpl.core.exploit.printer import print_success


SFTP_TIMEOUT = 8.0


class SFTPCli:
    """SFTP client for authentication checks and file operations."""

    def __init__(self, sftp_target: str, sftp_port: int, verbosity: bool = False) -> None:
        self.sftp_target = sftp_target
        self.sftp_port = sftp_port
        self.verbosity = verbosity
        self.peer = "{}:{}".format(self.sftp_target, self.sftp_port)

        self.transport = None
        self.sftp_client = None

    def connect(self, retries: int = 1) -> bool:
        for _ in range(retries):
            try:
                self.transport = paramiko.Transport((self.sftp_target, self.sftp_port))
                self.transport.banner_timeout = SFTP_TIMEOUT
                self.transport.connect_timeout = SFTP_TIMEOUT
                self.transport.start_client(timeout=SFTP_TIMEOUT)
                return True
            except Exception as err:
                print_error(self.peer, "SFTP Error while connecting to the server", err, verbose=self.verbosity)
                self.close()
        return False

    def login(self, username: str, password: str, retries: int = 1) -> bool:
        for _ in range(retries):
            try:
                if not self.connect():
                    continue
                self.transport.auth_password(username=username, password=password, timeout=SFTP_TIMEOUT)
                self.sftp_client = paramiko.SFTPClient.from_transport(self.transport)
                print_success(
                    self.peer,
                    "SFTP Authentication Successful - Username: '{}' Password: '{}'".format(username, password),
                    verbose=self.verbosity,
                )
                return True
            except paramiko.AuthenticationException:
                print_error(
                    self.peer,
                    "SFTP Authentication Failed - Username: '{}' Password: '{}'".format(username, password),
                    verbose=self.verbosity,
                )
                self.close()
                break
            except Exception as err:
                print_error(self.peer, "SFTP Error while authenticating", err, verbose=self.verbosity)
                self.close()
        return False

    def test_connect(self) -> bool:
        if self.connect():
            self.close()
            return True
        return False

    def close(self) -> bool:
        try:
            if self.sftp_client is not None:
                self.sftp_client.close()
                self.sftp_client = None
            if self.transport is not None:
                self.transport.close()
                self.transport = None
            return True
        except Exception as err:
            print_error(self.peer, "SFTP Error while closing connection", err, verbose=self.verbosity)
        return False


# pylint: disable=no-member
class SFTPClient(Exploit):
    target_protocol = Protocol.SFTP

    verbosity = OptBool(True, "Enable verbose output: true/false")

    def sftp_create(self, target: str = None, port: int = None) -> SFTPCli:
        sftp_target = target if target else self.target
        sftp_port = port if port else self.port
        return SFTPCli(sftp_target, sftp_port, verbosity=self.verbosity)
