"""
MIT License

Copyright (c) 2020-2024 EntySec

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

from hatasm.lib.formats import Formats


class EXE(Formats):
    """ Main class of pex.exe module.

    This main class of pex.exe module is intended for providing
    some implementations of executable file manipulation methods.
    """

    def pack_exe(self, data: bytes, arch: str, format: str,
                 *args, **kwargs) -> bytes:
        """ Pack executable.

        :param bytes data: data to check
        :param str arch: architecture to pack for
        :param str format: executable format
        :return bytes: packed data
        :raises RuntimeError: with trailing error message
        """

        return self.get_format(format, arch).run(
            arch, data, *args, **kwargs)
