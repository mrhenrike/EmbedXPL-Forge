"""
This plugin requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

import struct

from badges.cmd import Command

from pwny.api import *
from pwny.types import *

from hatsploit.lib.core.plugin import Plugin


REGISTRY_READ = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL)
REGISTRY_WRITE = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL + 1)
REGISTRY_DELETE = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL + 2)

TLV_TYPE_REG_HIVE = tlv_custom_type(TLV_TYPE_INT, TAB_BASE, API_TYPE)
TLV_TYPE_REG_PATH = tlv_custom_type(TLV_TYPE_STRING, TAB_BASE, API_TYPE)
TLV_TYPE_REG_KEY = tlv_custom_type(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 1)
TLV_TYPE_REG_TYPE = tlv_custom_type(TLV_TYPE_INT, TAB_BASE, API_TYPE + 1)
TLV_TYPE_REG_VALUE = tlv_custom_type(TLV_TYPE_BYTES, TAB_BASE, API_TYPE)

REG_HIVE_HKCR = 0
REG_HIVE_HKCU = 1
REG_HIVE_HKLM = 2
REG_HIVE_HKU = 3
REG_HIVE_HKCC = 4

HIVE_MAP = {
    'HKCR': REG_HIVE_HKCR,
    'HKEY_CLASSES_ROOT': REG_HIVE_HKCR,
    'HKCU': REG_HIVE_HKCU,
    'HKEY_CURRENT_USER': REG_HIVE_HKCU,
    'HKLM': REG_HIVE_HKLM,
    'HKEY_LOCAL_MACHINE': REG_HIVE_HKLM,
    'HKU': REG_HIVE_HKU,
    'HKEY_USERS': REG_HIVE_HKU,
    'HKCC': REG_HIVE_HKCC,
    'HKEY_CURRENT_CONFIG': REG_HIVE_HKCC,
}

# Windows registry type constants
REG_NONE = 0
REG_SZ = 1
REG_EXPAND_SZ = 2
REG_BINARY = 3
REG_DWORD = 4
REG_DWORD_BIG_ENDIAN = 5
REG_LINK = 6
REG_MULTI_SZ = 7
REG_QWORD = 11

REG_TYPE_NAMES = {
    REG_NONE: 'REG_NONE',
    REG_SZ: 'REG_SZ',
    REG_EXPAND_SZ: 'REG_EXPAND_SZ',
    REG_BINARY: 'REG_BINARY',
    REG_DWORD: 'REG_DWORD',
    REG_DWORD_BIG_ENDIAN: 'REG_DWORD_BIG_ENDIAN',
    REG_LINK: 'REG_LINK',
    REG_MULTI_SZ: 'REG_MULTI_SZ',
    REG_QWORD: 'REG_QWORD',
}


def parse_hive_path(full_path):
    """ Parse a registry path like HKLM\\Software\\Microsoft into hive + subpath.

    :param str full_path: full registry path
    :return tuple: (hive_id, subpath)
    """

    parts = full_path.replace('/', '\\').split('\\', 1)
    hive_name = parts[0].upper()
    subpath = parts[1] if len(parts) > 1 else ''

    hive_id = HIVE_MAP.get(hive_name)
    if hive_id is None:
        raise ValueError(f"Unknown registry hive: {hive_name}")

    return hive_id, subpath


def format_reg_value(data, reg_type):
    """ Format registry value bytes for display.

    :param bytes data: raw value data
    :param int reg_type: registry value type
    :return str: formatted value string
    """

    if reg_type in (REG_SZ, REG_EXPAND_SZ, REG_LINK):
        try:
            return data.decode('utf-8').rstrip('\x00')
        except UnicodeDecodeError:
            try:
                return data.decode('utf-16-le').rstrip('\x00')
            except UnicodeDecodeError:
                return data.hex()

    elif reg_type == REG_DWORD:
        if len(data) >= 4:
            return str(struct.unpack('<I', data[:4])[0])
        return data.hex()

    elif reg_type == REG_DWORD_BIG_ENDIAN:
        if len(data) >= 4:
            return str(struct.unpack('>I', data[:4])[0])
        return data.hex()

    elif reg_type == REG_QWORD:
        if len(data) >= 8:
            return str(struct.unpack('<Q', data[:8])[0])
        return data.hex()

    elif reg_type == REG_MULTI_SZ:
        try:
            text = data.decode('utf-16-le').rstrip('\x00')
            return ', '.join(text.split('\x00'))
        except UnicodeDecodeError:
            return data.hex()

    else:
        return data.hex()


class HatSploitPlugin(Plugin):
    def __init__(self):
        super().__init__({
            'Name': "Registry Plugin",
            'Plugin': "registry",
            'Authors': [
                'EntySec - plugin developer',
            ],
            'Description': "Read, write, and delete Windows registry values.",
        })

        self.commands = [
            Command({
                'Category': "manage",
                'Name': "registry",
                'Description': "Read, write, and delete Windows registry values.",
                'MinArgs': 1,
                'Options': [
                    (
                        ('-r', '--read'),
                        {
                            'help': "Read a registry value (HIVE\\Path value_name).",
                            'metavar': 'PATH',
                        }
                    ),
                    (
                        ('-w', '--write'),
                        {
                            'help': "Write a registry value (HIVE\\Path).",
                            'metavar': 'PATH',
                        }
                    ),
                    (
                        ('-d', '--delete'),
                        {
                            'help': "Delete a registry value (HIVE\\Path).",
                            'metavar': 'PATH',
                        }
                    ),
                    (
                        ('-k', '--key'),
                        {
                            'help': "Registry value name.",
                            'metavar': 'NAME',
                        }
                    ),
                    (
                        ('-v', '--value'),
                        {
                            'help': "Data to write (for --write).",
                            'metavar': 'DATA',
                        }
                    ),
                    (
                        ('-t', '--type'),
                        {
                            'help': "Registry type: REG_SZ (default), REG_DWORD, REG_BINARY, REG_QWORD.",
                            'metavar': 'TYPE',
                            'default': 'REG_SZ'
                        }
                    ),
                ]
            })
        ]

    def parse_reg_type(self, type_str):
        type_map = {
            'REG_NONE': REG_NONE,
            'REG_SZ': REG_SZ,
            'REG_EXPAND_SZ': REG_EXPAND_SZ,
            'REG_BINARY': REG_BINARY,
            'REG_DWORD': REG_DWORD,
            'REG_QWORD': REG_QWORD,
            'REG_MULTI_SZ': REG_MULTI_SZ,
        }
        return type_map.get(type_str.upper(), REG_SZ)

    def encode_value(self, value_str, reg_type):
        if reg_type == REG_DWORD:
            return struct.pack('<I', int(value_str, 0))
        elif reg_type == REG_QWORD:
            return struct.pack('<Q', int(value_str, 0))
        elif reg_type in (REG_SZ, REG_EXPAND_SZ):
            return (value_str + '\x00').encode('utf-8')
        elif reg_type == REG_BINARY:
            return bytes.fromhex(value_str.replace(' ', ''))
        else:
            return value_str.encode('utf-8')

    def registry(self, args):
        if args.read:
            if not args.key:
                self.print_error("Specify value name with --key!")
                return

            try:
                hive, path = parse_hive_path(args.read)
            except ValueError as e:
                self.print_error(str(e))
                return

            result = self.session.send_command(
                tag=REGISTRY_READ,
                plugin=self.plugin,
                args={
                    TLV_TYPE_REG_HIVE: hive,
                    TLV_TYPE_REG_PATH: path,
                    TLV_TYPE_REG_KEY: args.key,
                }
            )

            if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                self.print_error("Failed to read registry value!")
                return

            reg_type = result.get_int(TLV_TYPE_REG_TYPE)
            data = result.get_raw(TLV_TYPE_REG_VALUE)

            type_name = REG_TYPE_NAMES.get(reg_type, f"Unknown({reg_type})")
            formatted = format_reg_value(data, reg_type)

            self.print_information(f"Type: {type_name}")
            self.print_information(f"Data: {formatted}")

        elif args.write:
            if not args.key:
                self.print_error("Specify value name with --key!")
                return

            if args.value is None:
                self.print_error("Specify data with --value!")
                return

            try:
                hive, path = parse_hive_path(args.write)
            except ValueError as e:
                self.print_error(str(e))
                return

            reg_type = self.parse_reg_type(args.type)

            try:
                encoded = self.encode_value(args.value, reg_type)
            except Exception as e:
                self.print_error(f"Failed to encode value: {e}")
                return

            result = self.session.send_command(
                tag=REGISTRY_WRITE,
                plugin=self.plugin,
                args={
                    TLV_TYPE_REG_HIVE: hive,
                    TLV_TYPE_REG_PATH: path,
                    TLV_TYPE_REG_KEY: args.key,
                    TLV_TYPE_REG_TYPE: reg_type,
                    TLV_TYPE_REG_VALUE: encoded,
                }
            )

            if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                self.print_error("Failed to write registry value!")
                return

            self.print_success("Registry value written successfully!")

        elif args.delete:
            try:
                hive, path = parse_hive_path(args.delete)
            except ValueError as e:
                self.print_error(str(e))
                return

            cmd_args = {
                TLV_TYPE_REG_HIVE: hive,
                TLV_TYPE_REG_PATH: path,
            }

            if args.key:
                cmd_args[TLV_TYPE_REG_KEY] = args.key

            result = self.session.send_command(
                tag=REGISTRY_DELETE,
                plugin=self.plugin,
                args=cmd_args
            )

            if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
                self.print_error("Failed to delete registry value!")
                return

            if args.key:
                self.print_success(f"Registry value '{args.key}' deleted!")
            else:
                self.print_success("Registry key deleted!")

        else:
            self.print_usage()

    def load(self):
        pass
