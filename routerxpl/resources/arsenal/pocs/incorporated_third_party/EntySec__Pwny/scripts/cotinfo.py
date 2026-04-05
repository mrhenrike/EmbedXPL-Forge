#!/usr/bin/env python3
"""
cotinfo.py — Display information about COT (Code-Only Tab) blob files.

Usage:
    python3 cotinfo.py <file.cot> [file2.cot ...]
    python3 cotinfo.py -d <directory>       # scan all COT files in a directory
    python3 cotinfo.py --hex <file.cot>     # also show hex dump of entry point region

Parses the cot_header_t (24 bytes for v1, 40 bytes for v2) and prints
layout details including base relocation info for v2 blobs.
Zero external dependencies — uses Python stdlib only.
"""

import argparse
import os
import struct
import sys

COT_MAGIC = 0x00544F43  # "COT\0" little-endian
COT_HEADER_V1_SIZE = 24
COT_HEADER_V2_SIZE = 40

# Memory page size used by the stomp loader (PE header preserved here)
STOMP_PAGE = 0x1000


def read_header(data):
    """Parse a cot_header_t from raw bytes.

    Supports v1 (24-byte) and v2 (40-byte) headers.
    Returns a dict with header fields, or None on invalid magic.
    """
    if len(data) < COT_HEADER_V1_SIZE:
        return None

    magic, version, entry_offset, code_size, rw_offset, rw_size = \
        struct.unpack_from('<IIIIII', data, 0)

    if magic != COT_MAGIC:
        return None

    hdr = {
        'magic': magic,
        'version': version,
        'entry_offset': entry_offset,
        'code_size': code_size,
        'rw_offset': rw_offset,
        'rw_size': rw_size,
        'original_base': 0,
        'reloc_count': 0,
        'header_size': COT_HEADER_V1_SIZE,
    }

    if version >= 2 and len(data) >= COT_HEADER_V2_SIZE:
        original_base, reloc_count, _pad = \
            struct.unpack_from('<QII', data, 24)
        hdr['original_base'] = original_base
        hdr['reloc_count'] = reloc_count
        hdr['header_size'] = COT_HEADER_V2_SIZE

    return hdr


def hexdump(data, base_offset=0, width=16):
    """Return a hex dump string."""
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        ascii_part = ''.join(
            chr(b) if 0x20 <= b < 0x7f else '.' for b in chunk
        )
        lines.append(f'  {base_offset + i:08x}  {hex_part:<{width * 3}}  {ascii_part}')
    return '\n'.join(lines)


def entropy(data):
    """Calculate Shannon entropy of a byte sequence (0.0 – 8.0)."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    length = len(data)
    import math
    ent = 0.0
    for count in freq:
        if count:
            p = count / length
            ent -= p * math.log2(p)
    return ent


def analyze_cot(path, show_hex=False):
    """Analyze a single COT file and print results."""
    file_size = os.path.getsize(path)

    with open(path, 'rb') as f:
        data = f.read()

    hdr = read_header(data)
    if hdr is None:
        print(f'[-] {path}: not a valid COT file (bad magic or too small)')
        return False

    hdr_size = hdr['header_size']
    blob = data[hdr_size:]
    name = os.path.basename(path)

    # Derived values
    rx_size = hdr['rw_offset'] if hdr['rw_offset'] > 0 else hdr['code_size']
    rw_end = hdr['rw_offset'] + hdr['rw_size'] if hdr['rw_size'] > 0 else 0
    trailing = hdr['code_size'] - rw_end if rw_end > 0 else 0

    # Stomp VA offsets (relative to sacrifice DLL base)
    stomp_entry = STOMP_PAGE + hdr['entry_offset']

    blob_entropy = entropy(blob) if blob else 0.0

    # Validate
    warnings = []
    if hdr['version'] not in (1, 2):
        warnings.append(f'unexpected version {hdr["version"]} (expected 1 or 2)')
    actual_blob = hdr['code_size']
    if hdr['version'] >= 2:
        actual_blob += hdr['reloc_count'] * 4
    if actual_blob > len(blob):
        warnings.append(
            f'header says {actual_blob} bytes after header, '
            f'but only {len(blob)} available'
        )
    if hdr['entry_offset'] >= hdr['code_size']:
        warnings.append('entry_offset is outside code blob')
    if hdr['rw_offset'] > 0 and hdr['rw_offset'] + hdr['rw_size'] > hdr['code_size']:
        warnings.append('RW region extends past end of code blob')

    print(f'[*] File:          {path}')
    print(f'[*] Plugin:        {name}')
    print(f'[*] File size:     {file_size} bytes ({file_size / 1024:.1f} KB)')
    print(f'[*] Magic:         0x{hdr["magic"]:08X} ("COT\\0")')
    print(f'[*] Version:       {hdr["version"]}')
    print(f'[*] Code size:     {hdr["code_size"]} bytes ({hdr["code_size"] / 1024:.1f} KB)')
    print(f'[*] Entry offset:  0x{hdr["entry_offset"]:X} (stomp VA: 0x{stomp_entry:X})')

    if hdr['rw_size'] > 0:
        print(f'[*] RW region:     offset 0x{hdr["rw_offset"]:X}, '
              f'size {hdr["rw_size"]} bytes ({hdr["rw_size"] / 1024:.1f} KB)')
        print(f'[*] RX region:     offset 0x0, size {rx_size} bytes ({rx_size / 1024:.1f} KB)')
        if trailing > 0:
            print(f'[*] Trailing RX:   offset 0x{rw_end:X}, '
                  f'size {trailing} bytes ({trailing / 1024:.1f} KB)')
    else:
        print(f'[*] RW region:     none (code-only, no writable data)')
        print(f'[*] RX region:     0x0 – 0x{hdr["code_size"]:X} '
              f'({hdr["code_size"]} bytes)')

    print(f'[*] Entropy:       {blob_entropy:.2f} / 8.00')
    print(f'[*] Header:        {hdr_size} bytes (v{hdr["version"]})')

    # Relocation info (v2+)
    if hdr['version'] >= 2:
        print(f'[*] Original base: 0x{hdr["original_base"]:016X}')
        print(f'[*] Relocations:   {hdr["reloc_count"]} DIR64 fixups')
        if show_hex and hdr['reloc_count'] > 0:
            reloc_off = hdr['code_size']
            for i in range(hdr['reloc_count']):
                off = reloc_off + i * 4
                if off + 4 <= len(blob):
                    roff = struct.unpack_from('<I', blob, off)[0]
                    print(f'             [{i:3d}] blob+0x{roff:06X}')
                else:
                    print(f'             [{i:3d}] (truncated)')

    # Memory layout diagram
    print(f'[*] Memory layout after stomp:')
    print(f'     hStomp + 0x0000  PE header (sacrifice, untouched)')
    print(f'     hStomp + 0x{STOMP_PAGE:04X}  .text + .rdata  [RX]  '
          f'({rx_size} bytes)')
    if hdr['rw_size'] > 0:
        rw_stomp = STOMP_PAGE + hdr['rw_offset']
        print(f'     hStomp + 0x{rw_stomp:04X}  .data + .bss    [RW]  '
              f'({hdr["rw_size"]} bytes)')
        if trailing > 0:
            trail_stomp = STOMP_PAGE + rw_end
            print(f'     hStomp + 0x{trail_stomp:04X}  trailing        [RX]  '
                  f'({trailing} bytes)')

    if warnings:
        for w in warnings:
            print(f'[!] WARNING: {w}')

    if show_hex and blob:
        ep = hdr['entry_offset']
        ctx = min(64, len(blob) - ep)
        if ctx > 0:
            print(f'[*] Entry point bytes (first {ctx} at offset 0x{ep:X}):')
            print(hexdump(blob[ep:ep + ctx], base_offset=ep))

        print(f'[*] Blob header bytes (first 64):')
        print(hexdump(blob[:min(64, len(blob))]))

    return True


def find_cot_files(directory):
    """Recursively find files that look like COT blobs in a directory."""
    cot_files = []
    for root, dirs, files in os.walk(directory):
        for name in sorted(files):
            path = os.path.join(root, name)
            try:
                with open(path, 'rb') as f:
                    magic = f.read(4)
                if len(magic) == 4 and struct.unpack('<I', magic)[0] == COT_MAGIC:
                    cot_files.append(path)
            except (OSError, IOError):
                pass
    return cot_files


def main():
    parser = argparse.ArgumentParser(
        description='Display information about COT (Code-Only Tab) blob files.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            'Examples:\n'
            '  %(prog)s pwny/tabs/windows/x64/forge\n'
            '  %(prog)s -d pwny/tabs/windows/x64/\n'
            '  %(prog)s --hex pwny/tabs/windows/x64/evasion\n'
        ),
    )
    parser.add_argument('files', nargs='*', help='COT file(s) to analyze')
    parser.add_argument('-d', '--dir', help='Scan directory for COT files')
    parser.add_argument('--hex', action='store_true',
                        help='Show hex dump of entry point and blob header')
    args = parser.parse_args()

    paths = list(args.files) if args.files else []

    if args.dir:
        found = find_cot_files(args.dir)
        if not found:
            print(f'[-] No COT files found in {args.dir}', file=sys.stderr)
            sys.exit(1)
        paths.extend(found)

    if not paths:
        parser.print_help()
        sys.exit(1)

    ok = 0
    for i, path in enumerate(paths):
        if not os.path.isfile(path):
            print(f'[-] {path}: not found', file=sys.stderr)
            continue
        if i > 0:
            print()
        if analyze_cot(path, show_hex=args.hex):
            ok += 1

    if len(paths) > 1:
        print(f'\n[*] Analyzed {ok}/{len(paths)} COT files.')


if __name__ == '__main__':
    main()
