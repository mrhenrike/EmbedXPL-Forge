#!/usr/bin/env python3
"""
pe2cot.py — Convert a PE DLL into a COT (Code-Only Tab) blob.

Usage:
    python3 pe2cot.py <input.dll> <output.cot>

Extracts the virtual image of all code/data sections (skipping .reloc),
locates the TabInitCOT export, parses base relocations, and writes a
v2 .cot file:

    [cot_header_t  40 bytes]   magic | version | entry_offset | code_size
                                rw_offset | rw_size | original_base
                                reloc_count | _pad
    [flat code blob]           virtual-layout of .text + .rdata + .data + ...
    [reloc table]              reloc_count * uint32 (blob-relative offsets)

The loader applies delta = (runtime_base - original_base) to each
DIR64 fixup entry at load time, so plugin code can freely use static
pointer arrays, function pointer tables, etc.

Zero external dependencies — uses Python stdlib only.
"""

import struct
import sys
import os

COT_MAGIC = 0x00544F43  # "COT\0" little-endian
COT_VERSION = 2
COT_HEADER_FMT = '<IIIIIIQI I'  # 6*u32 + u64 + u32 + u32 = 40 bytes
COT_HEADER_SIZE = struct.calcsize(COT_HEADER_FMT)

# Sections to omit from the code blob — .reloc is parsed separately
SKIP_SECTIONS = {b'.reloc'}


def _u16(data, off):
    return struct.unpack_from('<H', data, off)[0]


def _u32(data, off):
    return struct.unpack_from('<I', data, off)[0]


def _u64(data, off):
    return struct.unpack_from('<Q', data, off)[0]


def _rva_to_offset(sections, rva):
    """Translate an RVA to a raw file offset."""
    for s in sections:
        if s['va'] <= rva < s['va'] + max(s['vsize'], s['raw_size']):
            return rva - s['va'] + s['raw_offset']
    return None


def _parse_pe(data):
    if data[:2] != b'MZ':
        raise ValueError('Not a PE file (missing MZ)')

    e_lfanew = _u32(data, 0x3C)
    if data[e_lfanew:e_lfanew + 4] != b'PE\x00\x00':
        raise ValueError('Not a PE file (missing PE\\0\\0)')

    coff = e_lfanew + 4
    num_sections = _u16(data, coff + 2)
    opt_hdr_size = _u16(data, coff + 16)

    opt = coff + 20
    magic = _u16(data, opt)
    if magic == 0x20B:        # PE32+
        image_base = _u64(data, opt + 24)
        export_dd = opt + 112
        reloc_dd = opt + 152   # IMAGE_DIRECTORY_ENTRY_BASERELOC = 5
    elif magic == 0x10B:      # PE32
        image_base = _u32(data, opt + 28)
        export_dd = opt + 96
        reloc_dd = opt + 128
    else:
        raise ValueError(f'Unknown optional header magic 0x{magic:04X}')

    export_rva = _u32(data, export_dd)
    export_size = _u32(data, export_dd + 4)

    reloc_rva = _u32(data, reloc_dd)
    reloc_size = _u32(data, reloc_dd + 4)

    sec_off = opt + opt_hdr_size
    sections = []
    for i in range(num_sections):
        o = sec_off + i * 40
        sections.append({
            'name':       data[o:o + 8].rstrip(b'\x00'),
            'vsize':      _u32(data, o + 8),
            'va':         _u32(data, o + 12),
            'raw_size':   _u32(data, o + 16),
            'raw_offset': _u32(data, o + 20),
            'chars':      _u32(data, o + 36),
        })

    return sections, export_rva, export_size, reloc_rva, reloc_size, image_base


def _find_export_rva(data, sections, export_rva, target):
    """Return the RVA of an export by name, or None."""
    if export_rva == 0:
        return None

    base = _rva_to_offset(sections, export_rva)
    if base is None:
        return None

    num_names      = _u32(data, base + 24)
    funcs_rva      = _u32(data, base + 28)
    names_rva      = _u32(data, base + 32)
    ordinals_rva   = _u32(data, base + 36)

    funcs_off    = _rva_to_offset(sections, funcs_rva)
    names_off    = _rva_to_offset(sections, names_rva)
    ordinals_off = _rva_to_offset(sections, ordinals_rva)

    for i in range(num_names):
        name_rva  = _u32(data, names_off + i * 4)
        name_off  = _rva_to_offset(sections, name_rva)
        end       = data.index(b'\x00', name_off)
        name      = data[name_off:end]

        if name == target:
            ordinal  = _u16(data, ordinals_off + i * 2)
            func_rva = _u32(data, funcs_off + ordinal * 4)
            return func_rva

    return None


def _parse_relocs(data, sections, reloc_rva, reloc_size,
                  base_va, total_size):
    """Parse the PE .reloc section and return blob-relative fixup offsets.

    Only DIR64 (type 10 / 0xA) entries within the kept section range
    [base_va, base_va + total_size) are included.

    Returns a sorted list of uint32 blob-relative offsets.
    """
    if reloc_rva == 0 or reloc_size == 0:
        return []

    file_off = _rva_to_offset(sections, reloc_rva)
    if file_off is None:
        return []

    offsets = []
    pos = 0

    while pos < reloc_size:
        if pos + 8 > reloc_size:
            break

        block_rva = _u32(data, file_off + pos)
        block_size = _u32(data, file_off + pos + 4)

        if block_size < 8:
            break

        num_entries = (block_size - 8) // 2

        for i in range(num_entries):
            entry = _u16(data, file_off + pos + 8 + i * 2)
            rtype = (entry >> 12) & 0xF
            roff = entry & 0xFFF

            if rtype == 0:  # IMAGE_REL_BASED_ABSOLUTE (padding)
                continue
            if rtype != 10:  # IMAGE_REL_BASED_DIR64
                continue

            rva = block_rva + roff

            # Filter: only keep entries within the blob range
            if base_va <= rva < base_va + total_size:
                offsets.append(rva - base_va)

        pos += block_size

    offsets.sort()
    return offsets


def main():
    if len(sys.argv) != 3:
        print(f'Usage: {sys.argv[0]} <input.dll> <output.cot>', file=sys.stderr)
        sys.exit(1)

    dll_path, cot_path = sys.argv[1], sys.argv[2]

    with open(dll_path, 'rb') as f:
        data = f.read()

    sections, exp_rva, exp_size, reloc_rva, reloc_size, image_base = \
        _parse_pe(data)

    # ---- Find TabInitCOT export -----------------------------------------
    entry_rva = _find_export_rva(data, sections, exp_rva, b'TabInitCOT')
    if entry_rva is None:
        print('ERROR: TabInitCOT export not found in DLL', file=sys.stderr)
        sys.exit(1)

    # ---- Select sections to keep ----------------------------------------
    keep = [s for s in sections if s['name'] not in SKIP_SECTIONS]
    if not keep:
        print('ERROR: no sections to extract', file=sys.stderr)
        sys.exit(1)

    keep.sort(key=lambda s: s['va'])

    base_va    = keep[0]['va']
    last       = keep[-1]
    total_size = (last['va'] + last['vsize']) - base_va

    # ---- Build virtual-layout blob --------------------------------------
    blob = bytearray(total_size)
    for sec in keep:
        dst = sec['va'] - base_va
        n   = min(sec['raw_size'], sec['vsize'])
        blob[dst:dst + n] = data[sec['raw_offset']:sec['raw_offset'] + n]

    # ---- Compute writable region (.data, .bss) offset/size --------
    # IMAGE_SCN_MEM_WRITE = 0x80000000
    rw_offset = 0
    rw_size = 0
    rw_secs = [s for s in keep if s['chars'] & 0x80000000]
    if rw_secs:
        rw_secs.sort(key=lambda s: s['va'])
        rw_start = rw_secs[0]['va'] - base_va
        rw_last  = rw_secs[-1]
        rw_end   = (rw_last['va'] + rw_last['vsize']) - base_va
        rw_offset = rw_start
        rw_size   = rw_end - rw_start

    # ---- Compute entry offset -------------------------------------------
    entry_offset = entry_rva - base_va
    if not (0 <= entry_offset < total_size):
        print(f'ERROR: TabInitCOT RVA 0x{entry_rva:X} outside extracted '
              f'sections (base VA 0x{base_va:X})', file=sys.stderr)
        sys.exit(1)

    # ---- Parse base relocations -----------------------------------------
    original_base = image_base + base_va
    relocs = _parse_relocs(data, sections, reloc_rva, reloc_size,
                           base_va, total_size)

    # ---- Write .cot file (v2: 40-byte header + blob + reloc table) ------
    header = struct.pack(COT_HEADER_FMT,
                         COT_MAGIC, COT_VERSION,
                         entry_offset, total_size,
                         rw_offset, rw_size,
                         original_base,
                         len(relocs), 0)

    reloc_table = struct.pack(f'<{len(relocs)}I', *relocs) if relocs else b''

    with open(cot_path, 'wb') as f:
        f.write(header)
        f.write(blob)
        f.write(reloc_table)

    # ---- Summary --------------------------------------------------------
    sec_names = ', '.join(s['name'].decode(errors='replace') for s in keep)
    out_size  = os.path.getsize(cot_path)
    print(f'[*] Input:        {dll_path}')
    print(f'[*] Sections:     {sec_names}')
    print(f'[*] Base VA:      0x{base_va:X}')
    print(f'[*] TabInitCOT:   RVA 0x{entry_rva:X}  (blob offset 0x{entry_offset:X})')
    print(f'[*] Code blob:    {total_size} bytes ({total_size / 1024:.1f} KB)')
    if rw_size > 0:
        print(f'[*] RW region:    offset 0x{rw_offset:X}, size {rw_size} bytes')
    else:
        print(f'[*] RW region:    none')
    print(f'[*] Relocations:  {len(relocs)} DIR64 fixups '
          f'(original base 0x{original_base:X})')
    print(f'[*] Output:       {cot_path} ({out_size} bytes)')


if __name__ == '__main__':
    main()
