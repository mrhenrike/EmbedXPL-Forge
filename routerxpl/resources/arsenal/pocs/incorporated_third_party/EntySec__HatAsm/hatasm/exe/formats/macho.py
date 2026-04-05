"""
This format requires HatAsm: https://github.com/EntySec/HatAsm
Current source: https://github.com/EntySec/HatAsm
"""

import os
import struct

from hatasm.lib.format import Format


class HatAsmFormat(Format):
    macho_magic = [
        b"\xca\xfe\xba\xbe",
        b"\xfe\xed\xfa\xce",
        b"\xfe\xed\xfa\xcf",
        b"\xce\xfa\xed\xfe",
        b"\xcf\xfa\xed\xfe"
    ]

    def __init__(self) -> None:
        super().__init__({
            'Format': 'macho',
            'Name': 'Mach-O iOS/macOS Executable Format',
            'Description': (
                'Pack machine code into a Mach-O file.'
            ),
            'Arch': ['x64', 'aarch64'],
            'Platform': 'macos'
        })

        self.macho_headers = {
            'x64': self.templates + 'macho/macho_x64.macho',
            'aarch64': self.templates + 'macho/macho_aarch64.macho',
        }

    def run(self, arch, data):
        if data[:4] in self.macho_magic:
            return data

        for header_arch in self.macho_headers:
            if arch != header_arch:
                continue

            if not os.path.exists(self.macho_headers[header_arch]):
                raise RuntimeError("Macho header corrupted!")

            data_size = len(data)

            pointer = b'payload:'.upper()
            pointer_size = len(pointer)

            with open(self.macho_headers[header_arch], 'rb') as f:
                macho = f.read()
                pointer_index = macho.index(pointer)

                if data_size >= pointer_size:
                    return macho[:pointer_index] + data + macho[pointer_index + data_size:]
                return macho[:pointer_index] + data + macho[pointer_index + pointer_size:]

        raise RuntimeError("Failed to find compatible macho header!")
