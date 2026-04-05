"""
This plugin requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

import struct

from badges.cmd import Command

from pwny.api import *
from pwny.types import *

from hatsploit.lib.core.plugin import Plugin


FORGE_CALL = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL)
FORGE_MEMREAD = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL + 1)
FORGE_MEMWRITE = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL + 2)
FORGE_RESOLVE = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL + 3)

FORGE_DLL = tlv_custom_type(TLV_TYPE_STRING, TAB_BASE, API_TYPE)
FORGE_FUNC = tlv_custom_type(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 1)

FORGE_ARGS = tlv_custom_type(TLV_TYPE_BYTES, TAB_BASE, API_TYPE)
FORGE_RETVAL = tlv_custom_type(TLV_TYPE_BYTES, TAB_BASE, API_TYPE + 1)
FORGE_OUTPUT = tlv_custom_type(TLV_TYPE_BYTES, TAB_BASE, API_TYPE + 2)

FORGE_LASTERR = tlv_custom_type(TLV_TYPE_INT, TAB_BASE, API_TYPE)
FORGE_ADDR = tlv_custom_type(TLV_TYPE_BYTES, TAB_BASE, API_TYPE + 3)
FORGE_LENGTH = tlv_custom_type(TLV_TYPE_INT, TAB_BASE, API_TYPE + 1)
FORGE_DATA = tlv_custom_type(TLV_TYPE_BYTES, TAB_BASE, API_TYPE + 4)

# Argument type tags (must match C side)
ARG_DWORD = 0
ARG_QWORD = 1
ARG_BOOL = 2
ARG_LPCSTR = 3
ARG_LPCWSTR = 4
ARG_BUF_IN = 5
ARG_BUF_OUT = 6
ARG_BUF_INOUT = 7
ARG_PTR = 8


class ForgeResult(dict):
    """Result of a forge call.

    Attributes:
        return_value (int): raw 64-bit return value
        last_error (int): GetLastError() after the call
        output (dict): {arg_index: bytes} for output buffers

    Also accessible as dict keys for backward compat.
    """

    def __init__(self, return_value, last_error, output):
        super().__init__(
            return_value=return_value,
            last_error=last_error,
            output=output,
        )
        self.return_value = return_value
        self.last_error = last_error
        self.output = output

    def __repr__(self):
        out_desc = {k: f'{len(v)} bytes' for k, v in self.output.items()}
        return (
            f"ForgeResult(return_value=0x{self.return_value:x}, "
            f"last_error={self.last_error}, output={out_desc})"
        )


class ForgeHandle:
    """Context manager that auto-closes a Win32 HANDLE.

    Usage::

        with ForgeHandle(forge, handle_value) as h:
            forge.kernel32.WriteFile(int(h), ...)
        # CloseHandle called automatically

        # Or via the convenience method:
        with forge.handle(forge.kernel32.CreateFileA(...)) as h:
            forge.kernel32.ReadFile(int(h), ("out", 4096), 4096, ("out", 4), None)
    """

    def __init__(self, forge, handle_or_result, close_func=None):
        if isinstance(handle_or_result, ForgeResult):
            self._value = handle_or_result.return_value
        else:
            self._value = int(handle_or_result)
        self._forge = forge
        self._close_func = close_func

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._value and self._value != 0xFFFFFFFFFFFFFFFF:
            if self._close_func:
                self._close_func(self._value)
            else:
                self._forge.kernel32.CloseHandle(self._value)
        return False

    def __int__(self):
        return self._value

    def __index__(self):
        return self._value

    def __repr__(self):
        return f"ForgeHandle(0x{self._value:x})"

    @property
    def value(self):
        return self._value


class ForgeFunction:
    """Callable proxy for a single Win32 function.

    Type inference rules for arguments:
        int              -> DWORD (if <= 0xFFFFFFFF) or QWORD
        bool             -> BOOL
        str              -> LPCSTR (UTF-8)
        bytes            -> BUF_IN
        None             -> DWORD 0 (NULL pointer)
        ("out", N)       -> BUF_OUT of size N
        ("inout", bytes) -> BUF_INOUT
        ("wstr", str)    -> LPCWSTR (UTF-16LE)
        ("qword", int)   -> force QWORD
        ("dword", int)   -> force DWORD
        ("ptr", int)     -> raw 64-bit pointer
    """

    def __init__(self, forge, dll_name, func_name):
        self._forge = forge
        self._dll = dll_name
        self._func = func_name

    def __call__(self, *args):
        packer = ForgePacker()

        for arg in args:
            if arg is None:
                packer.add_dword(0)
            elif isinstance(arg, bool):
                packer.add_bool(arg)
            elif isinstance(arg, int):
                if -0x80000000 <= arg <= 0xFFFFFFFF:
                    packer.add_dword(arg & 0xFFFFFFFF)
                else:
                    packer.add_qword(arg)
            elif isinstance(arg, str):
                packer.add_str(arg)
            elif isinstance(arg, bytes):
                packer.add_buf_in(arg)
            elif isinstance(arg, (tuple, list)) and len(arg) == 2:
                tag, val = arg
                tag = tag.lower() if isinstance(tag, str) else tag
                if tag == 'out':
                    packer.add_buf_out(int(val))
                elif tag == 'inout':
                    packer.add_buf_inout(
                        val if isinstance(val, bytes) else val.encode()
                    )
                elif tag == 'wstr':
                    packer.add_wstr(val)
                elif tag == 'qword':
                    packer.add_qword(int(val))
                elif tag == 'dword':
                    packer.add_dword(int(val) & 0xFFFFFFFF)
                elif tag == 'ptr':
                    packer.add_ptr(int(val))
                else:
                    raise TypeError(f"Unknown tuple tag: {tag!r}")
            else:
                raise TypeError(
                    f"Unsupported argument type: {type(arg).__name__}"
                )

        packed = packer.get()
        tlv_args = {
            FORGE_DLL: self._dll,
            FORGE_FUNC: self._func,
        }
        if packed:
            tlv_args[FORGE_ARGS] = packed

        result = self._forge._session.send_command(
            tag=FORGE_CALL,
            plugin=self._forge._plugin_id,
            args=tlv_args,
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            raise RuntimeError(
                f"{self._dll}!{self._func} call failed "
                f"(status={result.get_int(TLV_TYPE_STATUS)})"
            )

        retval_raw = result.get_raw(FORGE_RETVAL)
        if retval_raw and len(retval_raw) >= 8:
            retval = struct.unpack('<Q', retval_raw[:8])[0]
        else:
            retval = 0

        last_error = result.get_int(FORGE_LASTERR)

        output = {}
        output_raw = result.get_raw(FORGE_OUTPUT)
        if output_raw:
            output = parse_output_buffers(output_raw)

        return ForgeResult(retval, last_error, output)

    def __repr__(self):
        return f"<ForgeFunction {self._dll}!{self._func}>"


class ForgeDll:
    """Proxy for a single DLL — attribute access returns a callable function."""

    def __init__(self, forge, dll_name):
        self._forge = forge
        self._dll = dll_name

    def __getattr__(self, name):
        if name.startswith('_'):
            raise AttributeError(name)
        return ForgeFunction(self._forge, self._dll, name)

    def __repr__(self):
        return f"<ForgeDll {self._dll}>"


class Forge:
    """Programmatic API for calling arbitrary Win32 functions.

    Usage::

        rg = session.forge              # attached by the plugin
        rg.user32.MessageBoxA(0, "hello", "title", 0)
        rg.kernel32.GetCurrentProcessId()

        # Explicit types via tuples:
        rg.kernel32.ReadFile(handle, ("out", 4096), 4096, ("out", 4), None)
        rg.user32.MessageBoxW(0, ("wstr", "hello"), ("wstr", "title"), 0)
        rg.kernel32.VirtualAllocEx(proc, ("qword", 0), 4096, 0x3000, 0x40)

    Memory access::

        rg.memread(0x7ff700001000, 64)    # returns bytes
        rg.memwrite(0x7ff700001000, b'\\x90\\x90')

    Type inference:
        int    -> DWORD (32-bit) or QWORD (>32-bit)
        bool   -> BOOL
        str    -> LPCSTR
        bytes  -> BUF_IN
        None   -> DWORD 0 (NULL)
        ("out", N)       -> output buffer of N bytes
        ("inout", bytes) -> in+out buffer
        ("wstr", str)    -> LPCWSTR
        ("qword", int)   -> force QWORD
        ("dword", int)   -> force DWORD
    """

    def __init__(self, session, plugin_id):
        self._session = session
        self._plugin_id = plugin_id

    def __getattr__(self, name):
        if name.startswith('_'):
            raise AttributeError(name)

        # Assume it's a DLL name. Auto-append .dll if missing.
        dll = name if '.' in name else name + '.dll'
        return ForgeDll(self, dll)

    def memread(self, address, length):
        """Read raw bytes from a remote process address.

        :param int address: 64-bit virtual address
        :param int length: number of bytes to read
        :return bytes: memory contents
        """
        result = self._session.send_command(
            tag=FORGE_MEMREAD,
            plugin=self._plugin_id,
            args={
                FORGE_ADDR: struct.pack('<Q', address),
                FORGE_LENGTH: length,
            },
        )
        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            raise RuntimeError("memread failed")
        return result.get_raw(FORGE_DATA)

    def memwrite(self, address, data):
        """Write raw bytes to a remote process address.

        :param int address: 64-bit virtual address
        :param bytes data: bytes to write
        """
        result = self._session.send_command(
            tag=FORGE_MEMWRITE,
            plugin=self._plugin_id,
            args={
                FORGE_ADDR: struct.pack('<Q', address),
                FORGE_DATA: data,
            },
        )
        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            raise RuntimeError("memwrite failed")

    def resolve(self, dll, func):
        """Resolve a function address without calling it.

        :param str dll: DLL name (e.g. 'kernel32.dll')
        :param str func: function name (e.g. 'VirtualAlloc')
        :return int: 64-bit address of the function
        :raises RuntimeError: if the function cannot be resolved
        """
        dll = dll if '.' in dll else dll + '.dll'
        result = self._session.send_command(
            tag=FORGE_RESOLVE,
            plugin=self._plugin_id,
            args={
                FORGE_DLL: dll,
                FORGE_FUNC: func,
            },
        )
        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            raise RuntimeError(
                f"Cannot resolve {dll}!{func}"
            )
        addr_raw = result.get_raw(FORGE_ADDR)
        if addr_raw and len(addr_raw) >= 8:
            return struct.unpack('<Q', addr_raw[:8])[0]
        return 0

    def call(self, dll, func, *args):
        """Call a Win32 function by explicit DLL and function name.

        Alternative to the attribute-proxy pattern.  Useful when DLL or
        function names contain characters that are not valid Python
        identifiers.

        :param str dll: DLL name (e.g. 'user32.dll')
        :param str func: function name
        :param args: arguments (same type rules as attribute proxy)
        :return ForgeResult:
        """
        dll = dll if '.' in dll else dll + '.dll'
        return ForgeFunction(self, dll, func)(*args)

    def handle(self, handle_or_result, close_func=None):
        """Wrap a Win32 HANDLE in a context manager.

        The handle is closed automatically via CloseHandle (or a custom
        *close_func*) when the ``with`` block exits.

        Usage::

            with forge.handle(forge.kernel32.CreateFileA(...)) as h:
                forge.kernel32.ReadFile(int(h), ...)
            # CloseHandle called here

        :param handle_or_result: int or ForgeResult
        :param close_func: optional callable(int) for non-CloseHandle cleanup
        :return ForgeHandle:
        """
        return ForgeHandle(self, handle_or_result, close_func)

    def __repr__(self):
        return "<Forge proxy>"


class ForgePacker:
    """Pack arguments for forge calls.

    Wire format for each argument:
        uint8_t  type
        uint32_t data_len
        uint8_t  data[data_len]
    """

    def __init__(self):
        self.buffer = b''

    def add_dword(self, value):
        self.buffer += struct.pack('<BI', ARG_DWORD, 4)
        self.buffer += struct.pack('<I', value & 0xFFFFFFFF)

    def add_qword(self, value):
        self.buffer += struct.pack('<BI', ARG_QWORD, 8)
        self.buffer += struct.pack('<Q', value & 0xFFFFFFFFFFFFFFFF)

    def add_bool(self, value):
        self.buffer += struct.pack('<BI', ARG_BOOL, 4)
        self.buffer += struct.pack('<I', 1 if value else 0)

    def add_str(self, value):
        if isinstance(value, str):
            value = value.encode('utf-8')
        self.buffer += struct.pack('<BI', ARG_LPCSTR, len(value))
        self.buffer += value

    def add_wstr(self, value):
        if isinstance(value, str):
            value = value.encode('utf-16-le')
        self.buffer += struct.pack('<BI', ARG_LPCWSTR, len(value))
        self.buffer += value

    def add_buf_in(self, value):
        self.buffer += struct.pack('<BI', ARG_BUF_IN, len(value))
        self.buffer += value

    def add_buf_out(self, size):
        self.buffer += struct.pack('<BI', ARG_BUF_OUT, size)
        self.buffer += b'\x00' * size

    def add_buf_inout(self, value):
        self.buffer += struct.pack('<BI', ARG_BUF_INOUT, len(value))
        self.buffer += value

    def add_ptr(self, value):
        self.buffer += struct.pack('<BI', ARG_PTR, 8)
        self.buffer += struct.pack('<Q', value & 0xFFFFFFFFFFFFFFFF)

    def get(self):
        return self.buffer


def parse_output_buffers(data):
    """Parse the packed output buffer blob into a dict of {arg_index: bytes}."""
    result = {}
    offset = 0
    while offset + 8 <= len(data):
        idx = struct.unpack_from('<I', data, offset)[0]
        length = struct.unpack_from('<I', data, offset + 4)[0]
        offset += 8
        if offset + length > len(data):
            break
        result[idx] = data[offset:offset + length]
        offset += length
    return result


TYPE_NAMES = {
    'd': 'DWORD',
    'q': 'QWORD',
    'b': 'BOOL',
    's': 'LPCSTR',
    'ws': 'LPCWSTR',
    'bi': 'buffer_in',
    'bo': 'buffer_out',
    'bio': 'buffer_inout',
    'p': 'pointer',
}


def parse_arg_spec(spec):
    """Parse a CLI argument spec like 'd:42', 's:hello', 'bo:256'.

    Returns (type_tag, data_bytes) or raises ValueError.
    """
    if ':' not in spec:
        raise ValueError(f"Invalid arg spec (missing ':'): {spec}")

    prefix, _, value = spec.partition(':')
    prefix = prefix.lower()

    if prefix == 'd':
        return ARG_DWORD, struct.pack('<I', int(value, 0) & 0xFFFFFFFF)
    elif prefix == 'q':
        return ARG_QWORD, struct.pack('<Q', int(value, 0) & 0xFFFFFFFFFFFFFFFF)
    elif prefix == 'b':
        return ARG_BOOL, struct.pack('<I', 1 if value.lower() in ('1', 'true') else 0)
    elif prefix == 's':
        data = value.encode('utf-8')
        return ARG_LPCSTR, data
    elif prefix == 'ws':
        data = value.encode('utf-16-le')
        return ARG_LPCWSTR, data
    elif prefix == 'bi':
        data = bytes.fromhex(value)
        return ARG_BUF_IN, data
    elif prefix == 'bo':
        size = int(value, 0)
        return ARG_BUF_OUT, b'\x00' * size
    elif prefix == 'bio':
        data = bytes.fromhex(value)
        return ARG_BUF_INOUT, data
    elif prefix == 'p':
        return ARG_PTR, struct.pack('<Q', int(value, 0) & 0xFFFFFFFFFFFFFFFF)
    else:
        raise ValueError(f"Unknown type prefix: {prefix}")


class HatSploitPlugin(Plugin):
    def __init__(self):
        super().__init__({
            'Name': "Forge Plugin",
            'Plugin': "forge",
            'Authors': [
                'EntySec - plugin developer',
            ],
            'Description': (
                "Call arbitrary Win32 API functions, "
                "read/write process memory."
            ),
        })

        self.commands = [
            Command({
                'Category': "manage",
                'Name': "forge",
                'Description': "Call arbitrary Win32 API functions.",
                'MinArgs': 1,
                'Options': [
                    (
                        ('action',),
                        {
                            'help': "Action to perform.",
                            'choices': ['call', 'memread', 'memwrite', 'resolve'],
                        }
                    ),
                    (
                        ('positional',),
                        {
                            'help': (
                                "For 'call': <dll> <func> [arg ...]\n"
                                "  Arg format: <type>:<value>\n"
                                "  Types: d (DWORD), q (QWORD), b (BOOL),\n"
                                "         s (LPCSTR), ws (LPCWSTR),\n"
                                "         bi (buffer_in hex), bo (buffer_out size),\n"
                                "         bio (buffer_inout hex)\n"
                                "  Examples: d:0x80000002 s:SOFTWARE\\\\Test bo:256\n"
                                "\n"
                                "For 'memread': <hex_address> <length>\n"
                                "For 'memwrite': <hex_address> <hex_data>\n"
                                "For 'resolve': <dll> <func>"
                            ),
                            'nargs': '*',
                        }
                    ),
                ]
            })
        ]

    def _do_call(self, positional):
        if len(positional) < 2:
            self.print_error("Usage: forge call <dll> <func> [args...]")
            return

        dll_name = positional[0]
        func_name = positional[1]
        arg_specs = positional[2:]

        # Pack arguments
        packed = b''
        for spec in arg_specs:
            try:
                tag, data = parse_arg_spec(spec)
            except ValueError as e:
                self.print_error(str(e))
                return
            packed += struct.pack('<BI', tag, len(data)) + data

        tlv_args = {
            FORGE_DLL: dll_name,
            FORGE_FUNC: func_name,
        }

        if packed:
            tlv_args[FORGE_ARGS] = packed

        self.print_process(
            f"Calling {dll_name}!{func_name} "
            f"({len(arg_specs)} args)..."
        )

        result = self.session.send_command(
            tag=FORGE_CALL,
            plugin=self.plugin,
            args=tlv_args,
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error("Call failed!")
            return

        # Parse return value (8-byte LE)
        retval_raw = result.get_raw(FORGE_RETVAL)
        if retval_raw and len(retval_raw) >= 8:
            retval = struct.unpack('<Q', retval_raw[:8])[0]
        else:
            retval = 0

        last_error = result.get_int(FORGE_LASTERR)

        self.print_success(
            f"Return value: 0x{retval:016x} ({retval})"
        )
        self.print_information(
            f"GetLastError: {last_error}"
        )

        # Parse output buffers
        output_raw = result.get_raw(FORGE_OUTPUT)
        if output_raw:
            buffers = parse_output_buffers(output_raw)
            for idx, data in sorted(buffers.items()):
                self.print_information(
                    f"  Output buffer [arg {idx}] "
                    f"({len(data)} bytes):"
                )
                # Print hex dump (first 256 bytes)
                self._hexdump(data[:256])
                if len(data) > 256:
                    self.print_information(
                        f"  ... ({len(data) - 256} more bytes)"
                    )

    def _do_memread(self, positional):
        if len(positional) < 2:
            self.print_error(
                "Usage: forge memread <hex_address> <length>"
            )
            return

        try:
            addr = int(positional[0], 16)
            length = int(positional[1], 0)
        except ValueError:
            self.print_error("Invalid address or length!")
            return

        result = self.session.send_command(
            tag=FORGE_MEMREAD,
            plugin=self.plugin,
            args={
                FORGE_ADDR: struct.pack('<Q', addr),
                FORGE_LENGTH: length,
            },
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error("Memory read failed!")
            return

        data = result.get_raw(FORGE_DATA)
        if data:
            self.print_success(
                f"Read {len(data)} bytes from 0x{addr:016x}:"
            )
            self._hexdump(data)
        else:
            self.print_error("No data returned!")

    def _do_memwrite(self, positional):
        if len(positional) < 2:
            self.print_error(
                "Usage: forge memwrite <hex_address> <hex_data>"
            )
            return

        try:
            addr = int(positional[0], 16)
            data = bytes.fromhex(positional[1])
        except ValueError:
            self.print_error("Invalid address or hex data!")
            return

        result = self.session.send_command(
            tag=FORGE_MEMWRITE,
            plugin=self.plugin,
            args={
                FORGE_ADDR: struct.pack('<Q', addr),
                FORGE_DATA: data,
            },
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error("Memory write failed!")
            return

        self.print_success(
            f"Wrote {len(data)} bytes to 0x{addr:016x}."
        )

    def _do_resolve(self, positional):
        if len(positional) < 2:
            self.print_error(
                "Usage: forge resolve <dll> <func>"
            )
            return

        dll_name = positional[0]
        func_name = positional[1]

        if '.' not in dll_name:
            dll_name += '.dll'

        result = self.session.send_command(
            tag=FORGE_RESOLVE,
            plugin=self.plugin,
            args={
                FORGE_DLL: dll_name,
                FORGE_FUNC: func_name,
            },
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error(
                f"Cannot resolve {dll_name}!{func_name}"
            )
            return

        addr_raw = result.get_raw(FORGE_ADDR)
        if addr_raw and len(addr_raw) >= 8:
            addr = struct.unpack('<Q', addr_raw[:8])[0]
        else:
            addr = 0

        self.print_success(
            f"{dll_name}!{func_name} = 0x{addr:016x}"
        )

    def _hexdump(self, data, width=16):
        for i in range(0, len(data), width):
            chunk = data[i:i + width]
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            ascii_part = ''.join(
                chr(b) if 0x20 <= b < 0x7f else '.'
                for b in chunk
            )
            self.print_information(
                f"  {i:08x}  {hex_part:<{width * 3}}  {ascii_part}"
            )

    def forge(self, args):
        action = args.action
        positional = args.positional or []

        if action == 'call':
            self._do_call(positional)
        elif action == 'memread':
            self._do_memread(positional)
        elif action == 'memwrite':
            self._do_memwrite(positional)
        elif action == 'resolve':
            self._do_resolve(positional)

    def load(self):
        self.session.forge = Forge(self.session, self.plugin)

    def unload(self):
        self.session.forge = None
