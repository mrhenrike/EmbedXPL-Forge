"""
This format requires HatAsm: https://github.com/EntySec/HatAsm
Current source: https://github.com/EntySec/HatAsm
"""

import os
import struct

from hatasm.lib.format import Format


class HatAsmFormat(Format):
    dylib_magic = [
        b"\xca\xfe\xba\xbe",
        b"\xfe\xed\xfa\xce",
        b"\xfe\xed\xfa\xcf",
        b"\xce\xfa\xed\xfe",
        b"\xcf\xfa\xed\xfe"
    ]

    def __init__(self) -> None:
        super().__init__({
            'Format': 'dylib',
            'Name': 'Mach-O iOS/macOS Dynamic Library Format',
            'Description': (
                'Pack machine code into a dylib file.'
            ),
            'Arch': ['x64'],
            'Platform': 'macos'
        })

        self.dylib_headers = {
            'x64': self.templates + 'dylib/dylib_x64.dylib',
        }

    def run(self, arch, data):
        if data[:4] in self.dylib_magic:
            return data

        for header_arch in self.dylib_headers:
            if arch != header_arch:
                continue

            if not os.path.exists(self.dylib_headers[header_arch]):
                raise RuntimeError("Dylib header corrupted!")

            data_size = len(data)

            pointer = b'payload:'.upper()
            pointer_size = len(pointer)

            with open(self.dylib_headers[header_arch], 'rb') as f:
                dylib = f.read()
                pointer_index = dylib.index(pointer)

                if data_size >= pointer_size:
                    return dylib[:pointer_index] + data + dylib[pointer_index + data_size:]
                return dylib[:pointer_index] + data + dylib[pointer_index + pointer_size:]

        raise RuntimeError("Failed to find compatible dylib header!")
