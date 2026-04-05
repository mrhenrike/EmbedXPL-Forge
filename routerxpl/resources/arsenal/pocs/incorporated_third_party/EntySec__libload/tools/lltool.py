#!/usr/bin/env python3
#
# lltool — Mach-O/ELF → llbin packer, ELF → flat binary converter (Python3)
#
# Reads a Mach-O executable (or fat binary) or ELF executable,
# flattens all segments into a contiguous image, extracts
# relocations and import references, and writes an llbin file
# that can be loaded trivially at runtime.
#
# Also converts static-pie ELF executables to flat binary images
# suitable for direct stager loading (mmap + jump).
#
# Usage: lltool pack    <input> <output.llbin>
#        lltool info    <file.llbin|file.macho|file.elf>
#        lltool elf2bin <input.elf> <output.bin>
#        lltool elf2bin -e <input.elf>

import argparse
import struct
import sys
from dataclasses import dataclass, field

# ─── Constants ────────────────────────────────────────────────────

LLBIN_MAGIC   = 0x4E424C4C   # "LLBN" little-endian
LLBIN_VERSION = 1

LLBIN_FIXUP_REBASE = 0
LLBIN_FIXUP_IMPORT = 1

MH_MAGIC_64    = 0xFEEDFACF
FAT_MAGIC      = 0xCAFEBABE
FAT_CIGAM      = 0xBEBAFECA
MH_EXECUTE     = 2
CPU_TYPE_X86_64 = 0x01000007
CPU_TYPE_ARM64  = 0x0100000C

LC_SEGMENT_64           = 0x19
LC_MAIN                 = 0x80000028
LC_DYLD_INFO            = 0x22
LC_DYLD_INFO_ONLY       = 0x80000022
LC_DYLD_CHAINED_FIXUPS  = 0x80000034

REBASE_OPCODE_MASK          = 0xF0
REBASE_IMMEDIATE_MASK       = 0x0F
REBASE_OPCODE_DONE          = 0x00
REBASE_OPCODE_SET_TYPE_IMM  = 0x10
REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB = 0x20
REBASE_OPCODE_ADD_ADDR_ULEB              = 0x30
REBASE_OPCODE_ADD_ADDR_IMM_SCALED        = 0x40
REBASE_OPCODE_DO_REBASE_IMM_TIMES        = 0x50
REBASE_OPCODE_DO_REBASE_ULEB_TIMES       = 0x60
REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB    = 0x70
REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB = 0x80

BIND_OPCODE_MASK          = 0xF0
BIND_IMMEDIATE_MASK       = 0x0F
BIND_OPCODE_DONE          = 0x00
BIND_OPCODE_SET_DYLIB_ORDINAL_IMM         = 0x10
BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB        = 0x20
BIND_OPCODE_SET_DYLIB_SPECIAL_IMM          = 0x30
BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM  = 0x40
BIND_OPCODE_SET_TYPE_IMM                   = 0x50
BIND_OPCODE_SET_ADDEND_SLEB               = 0x60
BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB   = 0x70
BIND_OPCODE_ADD_ADDR_ULEB                 = 0x80
BIND_OPCODE_DO_BIND                        = 0x90
BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB         = 0xA0
BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED   = 0xB0
BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB = 0xC0

DYLD_CHAINED_PTR_ARM64E             = 1
DYLD_CHAINED_PTR_64                 = 2
DYLD_CHAINED_PTR_64_OFFSET          = 6
DYLD_CHAINED_PTR_ARM64E_USERLAND    = 12
DYLD_CHAINED_PTR_ARM64E_USERLAND24  = 13

DYLD_CHAINED_IMPORT        = 1
DYLD_CHAINED_IMPORT_ADDEND = 2

DYLD_CHAINED_PTR_START_NONE = 0xFFFF

PAGE_ALIGN = 0x3FFF  # 16K - 1

# ─── ELF Constants ───────────────────────────────────────────────

ELF_MAGIC = b'\x7fELF'
ELFCLASS32 = 1
ELFCLASS64 = 2
ELFDATA2LSB = 1
ELFDATA2MSB = 2
ET_EXEC = 2
ET_DYN  = 3
EM_SPARC   = 2
EM_386     = 3
EM_MIPS    = 8
EM_ARM     = 40
EM_X86_64  = 62
EM_AARCH64 = 183

PT_LOAD    = 1
PT_DYNAMIC = 2

PF_X = 1
PF_W = 2
PF_R = 4

# ── elf2bin constants ────────────────────────────────────────────

BIN_MAGIC = b'\x7fBIN'

EI_CLASS_OFF = 4
EI_DATA_OFF  = 5

SHT_NULL    = 0
SHT_SYMTAB  = 2
SHT_STRTAB  = 3
SHT_NOTE    = 7
SHT_NOBITS  = 8
SHF_ALLOC   = 0x2

_DEAD_SHTYPES = {SHT_SYMTAB, SHT_NOTE}
_DEAD_NAMES = {b'.comment', b'.symtab', b'.strtab', b'.shstrtab'}

DT_NULL    = 0
DT_NEEDED  = 1
DT_PLTRELSZ = 2
DT_STRTAB  = 5
DT_SYMTAB  = 6
DT_RELA    = 7
DT_RELASZ  = 8
DT_RELAENT = 9
DT_REL     = 17
DT_RELSZ   = 18
DT_RELENT  = 19
DT_PLTREL  = 20
DT_JMPREL  = 23

SHN_UNDEF = 0

# x86_64 relocation types
R_X86_64_NONE      = 0
R_X86_64_64        = 1
R_X86_64_GLOB_DAT  = 6
R_X86_64_JUMP_SLOT = 7
R_X86_64_RELATIVE  = 8

# aarch64 relocation types
R_AARCH64_NONE      = 0
R_AARCH64_ABS64     = 257
R_AARCH64_GLOB_DAT  = 1025
R_AARCH64_JUMP_SLOT = 1026
R_AARCH64_RELATIVE  = 1027

# i386 relocation types
R_386_32       = 1
R_386_GLOB_DAT = 6
R_386_JMP_SLOT = 7
R_386_RELATIVE = 8

# ARM relocation types
R_ARM_ABS32     = 2
R_ARM_GLOB_DAT  = 21
R_ARM_JUMP_SLOT = 22
R_ARM_RELATIVE  = 23

# MIPS relocation types
R_MIPS_32       = 2
R_MIPS_REL32    = 3
R_MIPS_GLOB_DAT = 51
R_MIPS_JUMP_SLOT = 127

# SPARC relocation types
R_SPARC_32       = 3
R_SPARC_GLOB_DAT = 20
R_SPARC_JMP_SLOT = 21
R_SPARC_RELATIVE = 22

# ─── Data structures ─────────────────────────────────────────────

@dataclass
class Segment:
    name: str
    vmaddr: int
    vmsize: int
    fileoff: int
    filesize: int
    initprot: int = 0


@dataclass
class Fixup:
    offset: int
    type: int
    import_idx: int = 0
    addend: int = 0


@dataclass
class Import:
    name: str


@dataclass
class PackerState:
    segs: list = field(default_factory=list)
    base_vmaddr: int = 0
    total_size: int = 0
    image: bytearray = field(default_factory=bytearray)
    fixups: list = field(default_factory=list)
    imports: list = field(default_factory=list)
    entry_off: int = 0
    has_entry: bool = False

    def find_or_add_import(self, name: str) -> int:
        # Strip leading underscore (Mach-O convention)
        n = name[1:] if name.startswith('_') else name
        for i, imp in enumerate(self.imports):
            if imp.name == n:
                return i
        idx = len(self.imports)
        self.imports.append(Import(name=n))
        return idx

    def find_or_add_import_raw(self, name: str) -> int:
        """Add import without stripping underscore (for ELF)."""
        for i, imp in enumerate(self.imports):
            if imp.name == name:
                return i
        idx = len(self.imports)
        self.imports.append(Import(name=name))
        return idx

    def add_fixup(self, offset: int, ftype: int,
                  import_idx: int = 0, addend: int = 0):
        self.fixups.append(Fixup(offset=offset, type=ftype,
                                 import_idx=import_idx, addend=addend))

    def seg_image_addr(self, idx: int) -> int:
        """Return offset into image for segment idx, or -1."""
        if idx >= len(self.segs):
            return -1
        s = self.segs[idx]
        if s.vmaddr < self.base_vmaddr:
            return -1
        return s.vmaddr - self.base_vmaddr


# ─── LEB128 helpers ──────────────────────────────────────────────

def read_uleb128(data: bytes, pos: int) -> tuple:
    val = 0
    shift = 0
    while pos < len(data):
        b = data[pos]
        pos += 1
        val |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
        if shift >= 64:
            break
    return val, pos


def read_sleb128(data: bytes, pos: int) -> tuple:
    val = 0
    shift = 0
    b = 0
    while pos < len(data):
        b = data[pos]
        pos += 1
        val |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            break
        if shift >= 64:
            break
    if shift < 64 and (b & 0x40):
        val |= -(1 << shift)
    return val, pos


# ─── Fat binary extraction ───────────────────────────────────────

def extract_arch(data: bytes, cpu_type: int = None) -> bytes:
    """Extract matching architecture from a fat binary, or return as-is."""
    if len(data) < 4:
        raise ValueError("file too small")

    magic = struct.unpack_from('<I', data, 0)[0]

    if magic == FAT_MAGIC or magic == FAT_CIGAM:
        narch = struct.unpack_from('>I', data, 4)[0]
        offset = 8
        for _ in range(narch):
            ct, _, off, sz, _ = struct.unpack_from('>IIIII', data, offset)
            offset += 20
            if cpu_type and ct == cpu_type:
                return data[off:off + sz]
            # Auto-detect: prefer ARM64 then x86_64
            if ct == CPU_TYPE_ARM64 or ct == CPU_TYPE_X86_64:
                if cpu_type is None:
                    return data[off:off + sz]
        raise ValueError("no matching architecture in fat binary")

    return data


# ─── Build flat image from Mach-O ────────────────────────────────

def build_image(st: PackerState, data: bytes):
    """Parse Mach-O, collect segments, build flat image."""
    if len(data) < 32:
        raise ValueError("too small for Mach-O header")

    magic, _, _, filetype, ncmds, sizeofcmds = struct.unpack_from(
        '<IIIIII', data, 0)

    if magic != MH_MAGIC_64:
        raise ValueError(f"not a 64-bit Mach-O (magic=0x{magic:08x})")
    if filetype != MH_EXECUTE:
        raise ValueError("input must be MH_EXECUTE")

    # Parse load commands
    lc_off = 32  # sizeof(mach_header_64)
    lo, hi = 2**64, 0

    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from('<II', data, lc_off)

        if cmd == LC_SEGMENT_64:
            segname = data[lc_off + 8:lc_off + 24].split(b'\x00')[0].decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from(
                '<QQQQ', data, lc_off + 24)
            # initprot is at offset 24+32+4+4 = 64 within the LC
            _maxprot, initprot = struct.unpack_from('<II', data, lc_off + 56)

            st.segs.append(Segment(
                name=segname, vmaddr=vmaddr, vmsize=vmsize,
                fileoff=fileoff, filesize=filesize, initprot=initprot))

            if segname == "__PAGEZERO" or vmsize == 0:
                lc_off += cmdsize
                continue

            lo = min(lo, vmaddr)
            hi = max(hi, vmaddr + vmsize)

        elif cmd == LC_MAIN:
            st.entry_off = struct.unpack_from('<Q', data, lc_off + 8)[0]
            st.has_entry = True

        lc_off += cmdsize

    if lo >= hi:
        raise ValueError("no loadable segments")

    st.base_vmaddr = lo
    st.total_size = (hi - lo + PAGE_ALIGN) & ~PAGE_ALIGN
    st.image = bytearray(st.total_size)

    # Copy segment data
    for s in st.segs:
        if s.filesize == 0 or s.name == "__PAGEZERO":
            continue
        if s.vmaddr < st.base_vmaddr:
            continue
        if s.fileoff + s.filesize > len(data):
            raise ValueError(f"segment {s.name} extends past EOF")
        dest = s.vmaddr - st.base_vmaddr
        st.image[dest:dest + s.filesize] = data[s.fileoff:s.fileoff + s.filesize]

    if not st.has_entry:
        raise ValueError("no LC_MAIN found")


# ─── Chained fixup processing ────────────────────────────────────

def process_chained(st: PackerState, data: bytes,
                    dataoff: int, datasize: int):
    base = dataoff

    # dyld_chained_fixups_header
    (fixups_version, starts_offset, imports_offset, symbols_offset,
     imports_count, imports_format, _) = struct.unpack_from(
        '<IIIIIII', data, base)

    starts_base = base + starts_offset
    seg_count = struct.unpack_from('<I', data, starts_base)[0]

    imp_base = base + imports_offset
    sym_base = base + symbols_offset

    for seg_i in range(seg_count):
        seg_info_off = struct.unpack_from(
            '<I', data, starts_base + 4 + seg_i * 4)[0]
        if seg_info_off == 0:
            continue

        ss_base = starts_base + seg_info_off

        # dyld_chained_starts_in_segment
        (ss_size, page_size, pointer_format) = struct.unpack_from(
            '<IHH', data, ss_base)
        segment_offset = struct.unpack_from('<Q', data, ss_base + 8)[0]
        max_valid_ptr = struct.unpack_from('<I', data, ss_base + 16)[0]
        page_count = struct.unpack_from('<H', data, ss_base + 20)[0]

        if seg_i >= len(st.segs):
            continue
        if st.segs[seg_i].vmaddr < st.base_vmaddr:
            continue

        ptr_fmt = pointer_format

        if ptr_fmt in (DYLD_CHAINED_PTR_64, DYLD_CHAINED_PTR_64_OFFSET):
            stride = 4
        elif ptr_fmt in (DYLD_CHAINED_PTR_ARM64E,
                         DYLD_CHAINED_PTR_ARM64E_USERLAND,
                         DYLD_CHAINED_PTR_ARM64E_USERLAND24):
            stride = 8
        else:
            stride = 4

        for page_i in range(page_count):
            page_start = struct.unpack_from(
                '<H', data, ss_base + 22 + page_i * 2)[0]
            if page_start == DYLD_CHAINED_PTR_START_NONE:
                continue

            page_off = page_i * page_size
            chain_off = segment_offset + page_off + page_start

            while True:
                raw = struct.unpack_from('<Q', st.image, chain_off)[0]
                is_bind = (raw >> 63) & 1
                nxt = 0
                img_off = chain_off

                if ptr_fmt in (DYLD_CHAINED_PTR_64,
                               DYLD_CHAINED_PTR_64_OFFSET):
                    nxt = (raw >> 51) & 0xFFF

                    if is_bind:
                        ordinal = raw & 0xFFFFFF
                        add = (raw >> 24) & 0xFF
                        if add & 0x80:
                            add = add - 256  # sign-extend 8-bit

                        sym, imp_addend = _resolve_chained_import(
                            data, imp_base, sym_base,
                            imports_format, ordinal)

                        idx = st.find_or_add_import(sym)
                        struct.pack_into('<Q', st.image, img_off, 0)
                        st.add_fixup(img_off, LLBIN_FIXUP_IMPORT,
                                     idx, add + imp_addend)
                    else:
                        target = raw & 0xFFFFFFFFF
                        high8 = (raw >> 36) & 0xFF

                        if ptr_fmt == DYLD_CHAINED_PTR_64_OFFSET:
                            value = st.base_vmaddr + target
                        else:
                            value = target
                        value |= high8 << 56

                        struct.pack_into('<Q', st.image, img_off, value)
                        st.add_fixup(img_off, LLBIN_FIXUP_REBASE)

                elif ptr_fmt in (DYLD_CHAINED_PTR_ARM64E,
                                 DYLD_CHAINED_PTR_ARM64E_USERLAND,
                                 DYLD_CHAINED_PTR_ARM64E_USERLAND24):
                    is_auth = (raw >> 63) & 1
                    is_bind = (raw >> 62) & 1
                    nxt = (raw >> 52) & 0x7FF

                    if is_bind:
                        if ptr_fmt == DYLD_CHAINED_PTR_ARM64E_USERLAND24:
                            ordinal = raw & 0xFFFFFF
                        else:
                            ordinal = raw & 0xFFFF

                        sym, imp_addend = _resolve_chained_import(
                            data, imp_base, sym_base,
                            imports_format, ordinal)

                        idx = st.find_or_add_import(sym)
                        struct.pack_into('<Q', st.image, img_off, 0)
                        st.add_fixup(img_off, LLBIN_FIXUP_IMPORT,
                                     idx, imp_addend)
                    else:
                        high8 = 0
                        if is_auth:
                            target = raw & 0xFFFFFFFF
                        else:
                            target = raw & 0x7FFFFFFFF
                            high8 = (raw >> 43) & 0xFF

                        if ptr_fmt == DYLD_CHAINED_PTR_ARM64E:
                            value = target
                        else:
                            value = st.base_vmaddr + target

                        if not is_auth:
                            value |= high8 << 56

                        struct.pack_into('<Q', st.image, img_off, value)
                        st.add_fixup(img_off, LLBIN_FIXUP_REBASE)

                if nxt == 0:
                    break
                chain_off += nxt * stride


def _resolve_chained_import(data, imp_base, sym_base,
                            imports_format, ordinal):
    """Resolve a chained import ordinal to (symbol_name, addend)."""
    imp_addend = 0

    if imports_format == DYLD_CHAINED_IMPORT:
        raw32 = struct.unpack_from('<I', data, imp_base + ordinal * 4)[0]
        name_offset = (raw32 >> 9) & 0x7FFFFF
    elif imports_format == DYLD_CHAINED_IMPORT_ADDEND:
        raw32 = struct.unpack_from('<I', data, imp_base + ordinal * 8)[0]
        name_offset = (raw32 >> 9) & 0x7FFFFF
        imp_addend = struct.unpack_from('<i', data,
                                        imp_base + ordinal * 8 + 4)[0]
    else:
        raise ValueError(f"unsupported chained import format {imports_format}")

    # Read NUL-terminated string
    end = data.index(b'\x00', sym_base + name_offset)
    sym = data[sym_base + name_offset:end].decode('ascii')
    return sym, imp_addend


# ─── Legacy rebase (LC_DYLD_INFO) ────────────────────────────────

def process_rebase(st: PackerState, opcodes: bytes):
    pos = 0
    seg_idx = 0
    seg_off = 0

    while pos < len(opcodes):
        byte = opcodes[pos]
        pos += 1
        opcode = byte & REBASE_OPCODE_MASK
        imm = byte & REBASE_IMMEDIATE_MASK

        if opcode == REBASE_OPCODE_DONE:
            return
        elif opcode == REBASE_OPCODE_SET_TYPE_IMM:
            pass
        elif opcode == REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
            seg_idx = imm
            seg_off, pos = read_uleb128(opcodes, pos)
        elif opcode == REBASE_OPCODE_ADD_ADDR_ULEB:
            v, pos = read_uleb128(opcodes, pos)
            seg_off += v
        elif opcode == REBASE_OPCODE_ADD_ADDR_IMM_SCALED:
            seg_off += imm * 8
        elif opcode == REBASE_OPCODE_DO_REBASE_IMM_TIMES:
            base = st.seg_image_addr(seg_idx)
            if base < 0:
                raise ValueError("bad segment in rebase")
            for _ in range(imm):
                st.add_fixup(base + seg_off, LLBIN_FIXUP_REBASE)
                seg_off += 8
        elif opcode == REBASE_OPCODE_DO_REBASE_ULEB_TIMES:
            count, pos = read_uleb128(opcodes, pos)
            base = st.seg_image_addr(seg_idx)
            if base < 0:
                raise ValueError("bad segment in rebase")
            for _ in range(count):
                st.add_fixup(base + seg_off, LLBIN_FIXUP_REBASE)
                seg_off += 8
        elif opcode == REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB:
            skip, pos = read_uleb128(opcodes, pos)
            base = st.seg_image_addr(seg_idx)
            if base < 0:
                raise ValueError("bad segment in rebase")
            st.add_fixup(base + seg_off, LLBIN_FIXUP_REBASE)
            seg_off += 8 + skip
        elif opcode == REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB:
            count, pos = read_uleb128(opcodes, pos)
            skip, pos = read_uleb128(opcodes, pos)
            base = st.seg_image_addr(seg_idx)
            if base < 0:
                raise ValueError("bad segment in rebase")
            for _ in range(count):
                st.add_fixup(base + seg_off, LLBIN_FIXUP_REBASE)
                seg_off += 8 + skip
        else:
            raise ValueError(f"unknown rebase opcode 0x{opcode:02x}")


# ─── Legacy bind (LC_DYLD_INFO) ──────────────────────────────────

def process_bind(st: PackerState, opcodes: bytes, is_lazy: bool = False):
    pos = 0
    sym_name = None
    seg_idx = 0
    seg_off = 0
    addend = 0

    while pos < len(opcodes):
        byte = opcodes[pos]
        pos += 1
        opcode = byte & BIND_OPCODE_MASK
        imm = byte & BIND_IMMEDIATE_MASK

        if opcode == BIND_OPCODE_DONE:
            if not is_lazy:
                return
        elif opcode in (BIND_OPCODE_SET_DYLIB_ORDINAL_IMM,
                        BIND_OPCODE_SET_DYLIB_SPECIAL_IMM,
                        BIND_OPCODE_SET_TYPE_IMM):
            pass
        elif opcode == BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
            _, pos = read_uleb128(opcodes, pos)
        elif opcode == BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
            end = opcodes.index(b'\x00', pos)
            sym_name = opcodes[pos:end].decode('ascii')
            pos = end + 1
        elif opcode == BIND_OPCODE_SET_ADDEND_SLEB:
            addend, pos = read_sleb128(opcodes, pos)
        elif opcode == BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
            seg_idx = imm
            seg_off, pos = read_uleb128(opcodes, pos)
        elif opcode == BIND_OPCODE_ADD_ADDR_ULEB:
            v, pos = read_uleb128(opcodes, pos)
            seg_off += v
        elif opcode == BIND_OPCODE_DO_BIND:
            if not sym_name:
                raise ValueError("bind without symbol")
            idx = st.find_or_add_import(sym_name)
            base = st.seg_image_addr(seg_idx)
            if base < 0:
                raise ValueError("bad segment in bind")
            off = base + seg_off
            struct.pack_into('<Q', st.image, off, 0)
            st.add_fixup(off, LLBIN_FIXUP_IMPORT, idx, addend)
            seg_off += 8
        elif opcode == BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
            if not sym_name:
                raise ValueError("bind without symbol")
            idx = st.find_or_add_import(sym_name)
            base = st.seg_image_addr(seg_idx)
            if base < 0:
                raise ValueError("bad segment in bind")
            off = base + seg_off
            struct.pack_into('<Q', st.image, off, 0)
            st.add_fixup(off, LLBIN_FIXUP_IMPORT, idx, addend)
            skip, pos = read_uleb128(opcodes, pos)
            seg_off += 8 + skip
        elif opcode == BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
            if not sym_name:
                raise ValueError("bind without symbol")
            idx = st.find_or_add_import(sym_name)
            base = st.seg_image_addr(seg_idx)
            if base < 0:
                raise ValueError("bad segment in bind")
            off = base + seg_off
            struct.pack_into('<Q', st.image, off, 0)
            st.add_fixup(off, LLBIN_FIXUP_IMPORT, idx, addend)
            seg_off += 8 + imm * 8
        elif opcode == BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
            count, pos = read_uleb128(opcodes, pos)
            skip, pos = read_uleb128(opcodes, pos)
            if not sym_name:
                raise ValueError("bind without symbol")
            idx = st.find_or_add_import(sym_name)
            base = st.seg_image_addr(seg_idx)
            if base < 0:
                raise ValueError("bad segment in bind")
            for _ in range(count):
                off = base + seg_off
                struct.pack_into('<Q', st.image, off, 0)
                st.add_fixup(off, LLBIN_FIXUP_IMPORT, idx, addend)
                seg_off += 8 + skip
        else:
            if is_lazy:
                pass  # ignore unknown in lazy bind
            else:
                raise ValueError(f"unknown bind opcode 0x{opcode:02x}")


# ─── Walk load commands for fixups ────────────────────────────────

def process_fixups(st: PackerState, data: bytes):
    ncmds = struct.unpack_from('<I', data, 16)[0]
    lc_off = 32

    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from('<II', data, lc_off)

        if cmd == LC_DYLD_CHAINED_FIXUPS:
            dataoff, datasize = struct.unpack_from('<II', data, lc_off + 8)
            print(f"  processing chained fixups (off={dataoff} size={datasize})")
            process_chained(st, data, dataoff, datasize)

        elif cmd in (LC_DYLD_INFO, LC_DYLD_INFO_ONLY):
            (rebase_off, rebase_size, bind_off, bind_size,
             _, _, lazy_off, lazy_size, _, _) = struct.unpack_from(
                '<IIIIIIIIII', data, lc_off + 8)

            if rebase_size > 0:
                print(f"  processing rebase opcodes ({rebase_size} bytes)")
                process_rebase(st, data[rebase_off:rebase_off + rebase_size])
            if bind_size > 0:
                print(f"  processing bind opcodes ({bind_size} bytes)")
                process_bind(st, data[bind_off:bind_off + bind_size])
            if lazy_size > 0:
                print(f"  processing lazy bind opcodes ({lazy_size} bytes)")
                process_bind(st, data[lazy_off:lazy_off + lazy_size],
                             is_lazy=True)

        lc_off += cmdsize


# ─── ELF loading ─────────────────────────────────────────────────

def is_elf(data: bytes) -> bool:
    return len(data) >= 4 and data[:4] == ELF_MAGIC


def build_image_elf(st: PackerState, data: bytes):
    """Parse ELF (32 or 64-bit), collect PT_LOAD segments, build flat image."""
    if len(data) < 16:
        raise ValueError("too small for ELF header")

    if data[:4] != ELF_MAGIC:
        raise ValueError("not an ELF file")

    ei_class = data[4]
    is_64 = (ei_class == ELFCLASS64)

    if is_64:
        if len(data) < 64:
            raise ValueError("too small for ELF64 header")
        (e_type, e_machine, _, e_entry, e_phoff, _, _, _,
         e_phentsize, e_phnum) = struct.unpack_from('<HHIQQQIHHH', data, 16)
    else:
        if len(data) < 52:
            raise ValueError("too small for ELF32 header")
        (e_type, e_machine, _, e_entry, e_phoff, _, _, _,
         e_phentsize, e_phnum) = struct.unpack_from('<HHIIIIIHHHH', data, 16)

    if e_type not in (ET_EXEC, ET_DYN):
        raise ValueError(f"unsupported ELF type {e_type}")

    # Parse program headers
    lo, hi = 2**64, 0
    phdrs = []

    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize

        if is_64:
            (p_type, p_flags, p_offset, p_vaddr, _, p_filesz,
             p_memsz, _) = struct.unpack_from('<IIQQQQQQ', data, off)
        else:
            # ELF32 Phdr: p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align
            (p_type, p_offset, p_vaddr, _, p_filesz,
             p_memsz, p_flags, _) = struct.unpack_from('<IIIIIIII', data, off)

        phdrs.append((p_type, p_flags, p_offset, p_vaddr, p_filesz, p_memsz))

        if p_type == PT_LOAD and p_memsz > 0:
            seg_lo = p_vaddr
            seg_hi = p_vaddr + p_memsz
            lo = min(lo, seg_lo)
            hi = max(hi, seg_hi)

    if lo >= hi:
        raise ValueError("no loadable segments")

    lo &= ~PAGE_ALIGN
    hi = (hi + PAGE_ALIGN) & ~PAGE_ALIGN

    st.base_vmaddr = lo
    st.total_size = hi - lo
    st.image = bytearray(st.total_size)
    st.entry_off = e_entry - lo
    st.has_entry = True

    # Copy segment data & build segment list
    for (p_type, p_flags, p_offset, p_vaddr, p_filesz, p_memsz) in phdrs:
        if p_type != PT_LOAD or p_memsz == 0:
            continue

        dest = p_vaddr - lo
        if p_filesz > 0:
            if p_offset + p_filesz > len(data):
                raise ValueError(f"segment at 0x{p_vaddr:x} extends past EOF")
            st.image[dest:dest + p_filesz] = data[p_offset:p_offset + p_filesz]

        # Map ELF p_flags to VM_PROT
        prot = 0
        if p_flags & PF_R: prot |= 1  # VM_PROT_READ
        if p_flags & PF_W: prot |= 2  # VM_PROT_WRITE
        if p_flags & PF_X: prot |= 4  # VM_PROT_EXECUTE

        st.segs.append(Segment(
            name=f"LOAD@0x{p_vaddr:x}",
            vmaddr=p_vaddr,
            vmsize=p_memsz,
            fileoff=p_offset,
            filesize=p_filesz,
            initprot=prot))


def process_elf_relocations(st: PackerState, data: bytes):
    """Process ELF dynamic relocations (32 and 64-bit, all arches)."""
    if len(data) < 16:
        return

    ei_class = data[4]
    is_64 = (ei_class == ELFCLASS64)

    if is_64:
        (_, _, _, _, e_phoff, _, _, _,
         e_phentsize, e_phnum) = struct.unpack_from('<HHIQQQIHHH', data, 16)
    else:
        (_, _, _, _, e_phoff, _, _, _,
         e_phentsize, e_phnum) = struct.unpack_from('<HHIIIIIHHHH', data, 16)

    e_machine = struct.unpack_from('<H', data, 18)[0]

    # Find PT_DYNAMIC
    dyn_off = 0
    dyn_size = 0
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize

        if is_64:
            p_type = struct.unpack_from('<I', data, off)[0]
            if p_type == PT_DYNAMIC:
                _, _, p_offset, p_vaddr, _, p_filesz, _, _ = struct.unpack_from(
                    '<IIQQQQQQ', data, off)
                dyn_off = p_vaddr - st.base_vmaddr
                dyn_size = p_filesz
                break
        else:
            p_type = struct.unpack_from('<I', data, off)[0]
            if p_type == PT_DYNAMIC:
                _, p_offset, p_vaddr, _, p_filesz, _, _, _ = struct.unpack_from(
                    '<IIIIIIII', data, off)
                dyn_off = p_vaddr - st.base_vmaddr
                dyn_size = p_filesz
                break

    if dyn_off == 0:
        return

    # Struct sizes for this ELF class
    if is_64:
        dyn_entry_sz = 16    # Elf64_Dyn = qQ
        dyn_fmt = '<qQ'
        sym_entry_sz = 24    # Elf64_Sym
        rela_entry_sz = 24   # Elf64_Rela = QQq
        rela_fmt = '<QQq'
        rel_entry_sz = 16    # Elf64_Rel = QQ
        rel_fmt = '<QQ'
        slot_fmt = '<Q'
        slot_sz = 8
        def r_sym(info): return info >> 32
        def r_type(info): return info & 0xffffffff
        def sym_name_from_entry(off):
            return struct.unpack_from('<I', st.image, off)[0]
    else:
        dyn_entry_sz = 8     # Elf32_Dyn = iI
        dyn_fmt = '<iI'
        sym_entry_sz = 16    # Elf32_Sym
        rela_entry_sz = 12   # Elf32_Rela = IIi
        rela_fmt = '<IIi'
        rel_entry_sz = 8     # Elf32_Rel = II
        rel_fmt = '<II'
        slot_fmt = '<I'
        slot_sz = 4
        def r_sym(info): return info >> 8
        def r_type(info): return info & 0xff
        def sym_name_from_entry(off):
            return struct.unpack_from('<I', st.image, off)[0]

    # Parse dynamic entries from the image
    rela_off = 0
    rela_sz = 0
    rel_off = 0
    rel_sz = 0
    jmprel_off = 0
    jmprel_sz = 0
    pltrel_type = DT_RELA
    symtab_off = 0
    strtab_off = 0

    pos = dyn_off
    while pos < dyn_off + dyn_size:
        d_tag, d_val = struct.unpack_from(dyn_fmt, st.image, pos)
        pos += dyn_entry_sz
        if d_tag == DT_NULL:
            break
        elif d_tag == DT_RELA:
            rela_off = d_val - st.base_vmaddr
        elif d_tag == DT_RELASZ:
            rela_sz = d_val
        elif d_tag == DT_REL:
            rel_off = d_val - st.base_vmaddr
        elif d_tag == DT_RELSZ:
            rel_sz = d_val
        elif d_tag == DT_JMPREL:
            jmprel_off = d_val - st.base_vmaddr
        elif d_tag == DT_PLTRELSZ:
            jmprel_sz = d_val
        elif d_tag == DT_PLTREL:
            pltrel_type = d_val
        elif d_tag == DT_SYMTAB:
            symtab_off = d_val - st.base_vmaddr
        elif d_tag == DT_STRTAB:
            strtab_off = d_val - st.base_vmaddr

    # Relocation type classification
    def is_relative(machine, rtype, rsym):
        if machine == EM_X86_64:  return rtype == R_X86_64_RELATIVE
        if machine == EM_AARCH64: return rtype == R_AARCH64_RELATIVE
        if machine == EM_386:     return rtype == R_386_RELATIVE
        if machine == EM_ARM:     return rtype == R_ARM_RELATIVE
        if machine == EM_MIPS:    return rtype == R_MIPS_REL32 and rsym == 0
        if machine == EM_SPARC:   return rtype == R_SPARC_RELATIVE
        return False

    def is_import(machine, rtype, rsym):
        if machine == EM_X86_64:
            return rtype in (R_X86_64_GLOB_DAT, R_X86_64_JUMP_SLOT, R_X86_64_64)
        if machine == EM_AARCH64:
            return rtype in (R_AARCH64_GLOB_DAT, R_AARCH64_JUMP_SLOT, R_AARCH64_ABS64)
        if machine == EM_386:
            return rtype in (R_386_GLOB_DAT, R_386_JMP_SLOT, R_386_32)
        if machine == EM_ARM:
            return rtype in (R_ARM_GLOB_DAT, R_ARM_JUMP_SLOT, R_ARM_ABS32)
        if machine == EM_MIPS:
            return rtype in (R_MIPS_32, R_MIPS_GLOB_DAT, R_MIPS_JUMP_SLOT) or \
                   (rtype == R_MIPS_REL32 and rsym > 0)
        if machine == EM_SPARC:
            return rtype in (R_SPARC_GLOB_DAT, R_SPARC_JMP_SLOT, R_SPARC_32)
        return False

    def read_sym_name(sym_idx):
        if symtab_off <= 0 or strtab_off <= 0 or sym_idx == 0:
            return None
        sym_entry = symtab_off + sym_idx * sym_entry_sz
        st_name = sym_name_from_entry(sym_entry)
        name_start = strtab_off + st_name
        try:
            name_end = st.image.index(0, name_start)
        except ValueError:
            return None
        name = st.image[name_start:name_end].decode('ascii')
        return name if name else None

    def process_rela_table(table_off, table_sz):
        if table_off == 0 or table_sz == 0:
            return
        count = table_sz // rela_entry_sz
        for i in range(count):
            off = table_off + i * rela_entry_sz
            r_offset, r_info, r_addend = struct.unpack_from(rela_fmt, st.image, off)
            rt = r_type(r_info)
            rs = r_sym(r_info)
            img_off = r_offset - st.base_vmaddr

            if is_relative(e_machine, rt, rs):
                val = st.base_vmaddr + r_addend
                struct.pack_into(slot_fmt, st.image, img_off,
                                 val & ((1 << (slot_sz * 8)) - 1))
                st.add_fixup(img_off, LLBIN_FIXUP_REBASE)
            elif is_import(e_machine, rt, rs):
                name = read_sym_name(rs)
                if name:
                    idx = st.find_or_add_import_raw(name)
                    struct.pack_into(slot_fmt, st.image, img_off, 0)
                    st.add_fixup(img_off, LLBIN_FIXUP_IMPORT, idx, r_addend)

    def process_rel_table(table_off, table_sz):
        if table_off == 0 or table_sz == 0:
            return
        count = table_sz // rel_entry_sz
        for i in range(count):
            off = table_off + i * rel_entry_sz
            r_offset, r_info = struct.unpack_from(rel_fmt, st.image, off)
            rt = r_type(r_info)
            rs = r_sym(r_info)
            img_off = r_offset - st.base_vmaddr

            if is_relative(e_machine, rt, rs):
                # Implicit addend in slot — just mark for rebase
                st.add_fixup(img_off, LLBIN_FIXUP_REBASE)
            elif is_import(e_machine, rt, rs):
                # Implicit addend from slot value
                addend = struct.unpack_from(slot_fmt, st.image, img_off)[0]
                name = read_sym_name(rs)
                if name:
                    idx = st.find_or_add_import_raw(name)
                    struct.pack_into(slot_fmt, st.image, img_off, 0)
                    st.add_fixup(img_off, LLBIN_FIXUP_IMPORT, idx, addend)

    # Process RELA table
    process_rela_table(rela_off, rela_sz)

    # Process REL table (i386, ARM, MIPS)
    process_rel_table(rel_off, rel_sz)

    # Process JMPREL table (REL or RELA per DT_PLTREL)
    if jmprel_off and jmprel_sz:
        if pltrel_type == DT_RELA:
            process_rela_table(jmprel_off, jmprel_sz)
        else:
            process_rel_table(jmprel_off, jmprel_sz)


# ─── Write llbin output ──────────────────────────────────────────

def write_llbin(st: PackerState, path: str, arch: int):
    # Build string table
    strtab = bytearray()
    import_entries = []
    for imp in st.imports:
        name_off = len(strtab)
        strtab.extend(imp.name.encode('ascii') + b'\x00')
        import_entries.append((name_off, 0))

    # Struct sizes (matching llbin.h)
    hdr_size = 72         # sizeof(llbin_header)
    fixup_size = 16       # sizeof(llbin_fixup): I BB H q
    import_size = 8       # sizeof(llbin_import): II

    image_off   = hdr_size
    fixup_off   = image_off + st.total_size
    import_off  = fixup_off + len(st.fixups) * fixup_size
    strings_off = import_off + len(st.imports) * import_size

    # Pack header: 4×uint32 + 3×uint64 + 3×uint32 + 2×uint32 + 3×uint32
    # Build segment table (skip __PAGEZERO and zero-vmsize segments)
    seg_entries = []
    for s in st.segs:
        if s.vmsize == 0 or s.vmaddr < st.base_vmaddr:
            continue
        seg_entries.append((s.vmaddr - st.base_vmaddr, s.vmsize, s.initprot))

    hdr = struct.pack('<IIII QQQ III II III',
                      LLBIN_MAGIC, LLBIN_VERSION, arch, 0,
                      st.entry_off, st.total_size, st.base_vmaddr,
                      image_off, fixup_off, len(st.fixups),
                      import_off, len(st.imports),
                      strings_off, len(strtab), len(seg_entries))

    with open(path, 'wb') as f:
        f.write(hdr)
        f.write(st.image)

        for fx in st.fixups:
            f.write(struct.pack('<IBBHq',
                                fx.offset, fx.type, 0,
                                fx.import_idx, fx.addend))

        for name_off, flags in import_entries:
            f.write(struct.pack('<II', name_off, flags))

        f.write(strtab)

        for offset, size, prot in seg_entries:
            f.write(struct.pack('<IIII', offset, size, prot, 0))

    total = strings_off + len(strtab) + len(seg_entries) * 16
    return total


# ─── Info command ─────────────────────────────────────────────────

def cmd_info(path: str):
    with open(path, 'rb') as f:
        data = f.read()

    if len(data) < 4:
        print("File too small")
        return

    magic = struct.unpack_from('<I', data, 0)[0]

    if magic == LLBIN_MAGIC:
        print_llbin_info(data)
    elif is_elf(data):
        print_elf_info(data)
    elif magic == MH_MAGIC_64:
        print_macho_info(data)
    elif magic in (FAT_MAGIC, FAT_CIGAM):
        print(f"Fat binary ({len(data)} bytes)")
        try:
            slice_data = extract_arch(data)
            print_macho_info(slice_data)
        except ValueError as e:
            print(f"  Error: {e}")
    else:
        print(f"Unknown format (magic=0x{magic:08x})")


def print_llbin_info(data: bytes):
    if len(data) < 72:
        print("Truncated llbin")
        return

    (magic, version, arch, flags,
     entry_off, image_size, preferred_base,
     image_off, fixup_off, fixup_count,
     import_off, import_count,
     strings_off, strings_size, _) = struct.unpack_from(
        '<IIII QQQ III II III', data, 0)

    arch_name = {
        CPU_TYPE_ARM64: "arm64", CPU_TYPE_X86_64: "x86_64",
        0x00000007: "i386", 0x0000000C: "arm",
        0x00000008: "mips", 0x00000002: "sparc",
    }.get(arch, f"0x{arch:x}")

    print(f"llbin v{version} ({arch_name})")
    print(f"  image_size:     0x{image_size:x} ({image_size} bytes)")
    print(f"  preferred_base: 0x{preferred_base:x}")
    print(f"  entry_off:      0x{entry_off:x}")
    print(f"  fixups:         {fixup_count}")
    print(f"  imports:        {import_count}")

    if import_count > 0 and strings_off + strings_size <= len(data):
        strtab = data[strings_off:strings_off + strings_size]
        print("  imported symbols:")
        for i in range(import_count):
            off = import_off + i * 8
            name_off = struct.unpack_from('<I', data, off)[0]
            if name_off < len(strtab):
                end = strtab.index(b'\x00', name_off)
                name = strtab[name_off:end].decode('ascii')
                print(f"    [{i}] {name}")


def print_macho_info(data: bytes):
    if len(data) < 32:
        print("Truncated Mach-O")
        return

    magic, cputype, _, filetype, ncmds, _ = struct.unpack_from(
        '<IIIIII', data, 0)

    arch_name = {CPU_TYPE_ARM64: "arm64", CPU_TYPE_X86_64: "x86_64"}.get(
        cputype, f"0x{cputype:x}")
    ftype = {2: "MH_EXECUTE", 6: "MH_DYLIB", 8: "MH_BUNDLE"}.get(
        filetype, str(filetype))

    print(f"Mach-O 64-bit {ftype} ({arch_name}), {len(data)} bytes")

    lc_off = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from('<II', data, lc_off)

        if cmd == LC_SEGMENT_64:
            segname = data[lc_off + 8:lc_off + 24].split(b'\x00')[0].decode()
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from(
                '<QQQQ', data, lc_off + 24)
            print(f"  {segname:16s}  vmaddr=0x{vmaddr:x}  "
                  f"vmsize=0x{vmsize:x}  filesize=0x{filesize:x}")
        elif cmd == LC_MAIN:
            entry = struct.unpack_from('<Q', data, lc_off + 8)[0]
            print(f"  LC_MAIN           entry=0x{entry:x}")
        elif cmd == LC_DYLD_CHAINED_FIXUPS:
            doff, dsz = struct.unpack_from('<II', data, lc_off + 8)
            print(f"  LC_DYLD_CHAINED_FIXUPS  off={doff} size={dsz}")
        elif cmd in (LC_DYLD_INFO, LC_DYLD_INFO_ONLY):
            print("  LC_DYLD_INFO")

        lc_off += cmdsize


def print_elf_info(data: bytes):
    if len(data) < 16:
        print("Truncated ELF")
        return

    ei_class = data[4]
    is_64 = (ei_class == ELFCLASS64)

    if is_64:
        if len(data) < 64:
            print("Truncated ELF64")
            return
        e_type, e_machine = struct.unpack_from('<HH', data, 16)
        e_entry = struct.unpack_from('<Q', data, 24)[0]
        e_phoff = struct.unpack_from('<Q', data, 32)[0]
        e_phentsize, e_phnum = struct.unpack_from('<HH', data, 54)
    else:
        if len(data) < 52:
            print("Truncated ELF32")
            return
        e_type, e_machine = struct.unpack_from('<HH', data, 16)
        e_entry = struct.unpack_from('<I', data, 24)[0]
        e_phoff = struct.unpack_from('<I', data, 28)[0]
        e_phentsize, e_phnum = struct.unpack_from('<HH', data, 42)

    arch_map = {
        EM_X86_64: "x86_64", EM_AARCH64: "aarch64",
        EM_386: "i386", EM_ARM: "arm", EM_MIPS: "mips", EM_SPARC: "sparc",
    }
    arch_name = arch_map.get(e_machine, f"0x{e_machine:x}")
    etype = {ET_EXEC: "ET_EXEC", ET_DYN: "ET_DYN"}.get(e_type, str(e_type))
    elf_bits = "ELF64" if is_64 else "ELF32"

    print(f"{elf_bits} {etype} ({arch_name}), {len(data)} bytes")
    print(f"  entry: 0x{e_entry:x}")

    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize

        if is_64:
            p_type, p_flags, p_offset, p_vaddr = struct.unpack_from('<IIqq', data, off)
            p_filesz, p_memsz = struct.unpack_from('<QQ', data, off + 32)
        else:
            p_type, p_offset, p_vaddr, _ = struct.unpack_from('<IIII', data, off)
            p_filesz, p_memsz, p_flags, _ = struct.unpack_from('<IIII', data, off + 16)

        if p_type == PT_LOAD:
            flags_str = ''
            if p_flags & PF_R: flags_str += 'R'
            if p_flags & PF_W: flags_str += 'W'
            if p_flags & PF_X: flags_str += 'X'
            print(f"  PT_LOAD  vaddr=0x{p_vaddr:x}  memsz=0x{p_memsz:x}  "
                  f"filesz=0x{p_filesz:x}  {flags_str}")
        elif p_type == PT_DYNAMIC:
            print(f"  PT_DYNAMIC  vaddr=0x{p_vaddr:x}")


# ─── Pack command ─────────────────────────────────────────────────

def cmd_pack(input_path: str, output_path: str):
    with open(input_path, 'rb') as f:
        raw = f.read()

    print(f"lltool: {input_path} ({len(raw)} bytes)")

    st = PackerState()

    if is_elf(raw):
        # ELF path
        e_machine = struct.unpack_from('<H', raw, 18)[0]
        ei_class = raw[4]
        is_64 = (ei_class == ELFCLASS64)

        arch_map = {
            EM_AARCH64: (CPU_TYPE_ARM64, "aarch64"),
            EM_X86_64:  (CPU_TYPE_X86_64, "x86_64"),
            EM_386:     (0x00000007, "i386"),
            EM_ARM:     (0x0000000C, "arm"),
            EM_MIPS:    (0x00000008, "mips"),
            EM_SPARC:   (0x00000002, "sparc"),
        }
        if e_machine not in arch_map:
            raise ValueError(f"unsupported ELF machine 0x{e_machine:x}")

        arch, arch_name = arch_map[e_machine]
        elf_bits = "ELF64" if is_64 else "ELF32"
        print(f"  {elf_bits} ({arch_name}): {len(raw)} bytes")

        build_image_elf(st, raw)

        print(f"  base=0x{st.base_vmaddr:x}  size=0x{st.total_size:x}  "
              f"entry=0x{st.entry_off:x}")
        print(f"  segments: {len(st.segs)}")
        for i, s in enumerate(st.segs):
            print(f"    [{i}] {s.name:20s}  vmaddr=0x{s.vmaddr:x}  "
                  f"size=0x{s.vmsize:x}")

        process_elf_relocations(st, raw)
    else:
        # Mach-O path
        data = extract_arch(raw)
        print(f"  Mach-O slice: {len(data)} bytes")

        arch = struct.unpack_from('<I', data, 4)[0]

        build_image(st, data)

        print(f"  base=0x{st.base_vmaddr:x}  size=0x{st.total_size:x}  "
              f"entry=0x{st.entry_off:x}")
        print(f"  segments: {len(st.segs)}")
        for i, s in enumerate(st.segs):
            print(f"    [{i}] {s.name:16s}  vmaddr=0x{s.vmaddr:x}  "
                  f"size=0x{s.vmsize:x}")

        process_fixups(st, data)

    nrebase = sum(1 for f in st.fixups if f.type == LLBIN_FIXUP_REBASE)
    nimport = sum(1 for f in st.fixups if f.type == LLBIN_FIXUP_IMPORT)
    print(f"  fixups:  {len(st.fixups)} ({nrebase} rebase, {nimport} import)")
    print(f"  imports: {len(st.imports)}")

    for i, imp in enumerate(st.imports):
        print(f"    [{i}] {imp.name}")

    total = write_llbin(st, output_path, arch)
    print(f"  wrote {output_path} ({total} bytes)")


# ─── elf2bin — ELF to flat binary ────────────────────────────────

def _parse_elf_bin(data):
    """Parse an ELF file for elf2bin conversion.

    Returns dict with keys:
        bits, endian, entry, segments, dynamic,
        e_shoff, e_shnum, e_shentsize, sections.
    """
    if len(data) < 16:
        raise ValueError('file too small to be ELF')
    if data[:4] != ELF_MAGIC:
        raise ValueError('not an ELF file (bad magic)')

    bits = {ELFCLASS32: 32, ELFCLASS64: 64}.get(data[EI_CLASS_OFF])
    if bits is None:
        raise ValueError(f'unsupported ELF class {data[EI_CLASS_OFF]}')

    endian = {ELFDATA2LSB: '<', ELFDATA2MSB: '>'}.get(data[EI_DATA_OFF])
    if endian is None:
        raise ValueError(f'unsupported ELF data encoding {data[EI_DATA_OFF]}')

    if bits == 64:
        ehdr_fmt = f'{endian}HHI QQQ I HHHHHH'
        ehdr_size = 64
    else:
        ehdr_fmt = f'{endian}HHI III I HHHHHH'
        ehdr_size = 52

    if len(data) < ehdr_size:
        raise ValueError('truncated ELF header')

    fields = struct.unpack_from(ehdr_fmt, data, 16)
    (e_type, _e_machine, _e_version, e_entry,
     e_phoff, e_shoff, _e_flags, _e_ehsize,
     e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = fields

    if e_type not in (ET_EXEC, ET_DYN):
        raise ValueError(f'unsupported ELF type {e_type} (need ET_EXEC or ET_DYN)')

    segments = []
    dynamic_vaddr = 0
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        if off + e_phentsize > len(data):
            raise ValueError(f'program header {i} extends past EOF')
        if bits == 64:
            (p_type, _p_flags, p_offset, p_vaddr, _p_paddr,
             p_filesz, p_memsz, _p_align) = struct.unpack_from(
                f'{endian}II QQQQQQ', data, off)
        else:
            (p_type, p_offset, p_vaddr, _p_paddr,
             p_filesz, p_memsz, _p_flags, _p_align) = struct.unpack_from(
                f'{endian}I IIIIII', data, off)

        if p_type == PT_LOAD:
            segments.append((p_type, p_offset, p_vaddr, p_filesz, p_memsz))
        elif p_type == PT_DYNAMIC:
            dynamic_vaddr = p_vaddr

    if not segments:
        raise ValueError('no PT_LOAD segments')

    sections = []
    shstrtab_data = b''

    if e_shoff and e_shnum and e_shentsize:
        if e_shstrndx < e_shnum:
            shstr_hdr_off = e_shoff + e_shstrndx * e_shentsize
            if shstr_hdr_off + e_shentsize <= len(data):
                if bits == 64:
                    shstr_f = struct.unpack_from(
                        f'{endian}II QQQQII QQ', data, shstr_hdr_off)
                else:
                    shstr_f = struct.unpack_from(
                        f'{endian}IIIIIIIIII', data, shstr_hdr_off)
                shstrtab_off = shstr_f[4]
                shstrtab_sz = shstr_f[5]
                if shstrtab_off + shstrtab_sz <= len(data):
                    shstrtab_data = data[shstrtab_off:shstrtab_off + shstrtab_sz]

        for i in range(e_shnum):
            sh_off = e_shoff + i * e_shentsize
            if sh_off + e_shentsize > len(data):
                break
            if bits == 64:
                (sh_name, sh_type, sh_flags, sh_addr, sh_offset,
                 sh_size, sh_link, _sh_info,
                 _sh_addralign, sh_entsize) = struct.unpack_from(
                    f'{endian}II QQQQII QQ', data, sh_off)
            else:
                (sh_name, sh_type, sh_flags, sh_addr, sh_offset,
                 sh_size, sh_link, _sh_info,
                 _sh_addralign, sh_entsize) = struct.unpack_from(
                    f'{endian}IIIIIIIIII', data, sh_off)

            name = b''
            if sh_name < len(shstrtab_data):
                nul = shstrtab_data.find(b'\0', sh_name)
                if nul >= 0:
                    name = shstrtab_data[sh_name:nul]

            sections.append({
                'sh_type': sh_type, 'sh_flags': sh_flags,
                'sh_offset': sh_offset, 'sh_size': sh_size,
                'sh_addr': sh_addr, 'sh_link': sh_link,
                'sh_entsize': sh_entsize, 'name': name,
            })

    return {
        'bits': bits, 'endian': endian, 'entry': e_entry,
        'e_shoff': e_shoff, 'e_shnum': e_shnum,
        'e_shentsize': e_shentsize,
        'segments': segments, 'dynamic': dynamic_vaddr,
        'sections': sections,
    }


def _elf2bin_image(data, trailer=False, strip_meta=True):
    """Convert ELF bytes to a flat binary image."""
    info = _parse_elf_bin(data)
    segs = info['segments']

    lo = min(seg[2] for seg in segs)
    lo = lo & ~0xfff

    if strip_meta:
        file_hi = max(seg[2] + seg[3] for seg in segs)
    else:
        file_hi = max(seg[2] + seg[4] for seg in segs)

    image_size = file_hi - lo
    image = bytearray(image_size)

    for (_ptype, p_offset, p_vaddr, p_filesz, _p_memsz) in segs:
        if p_filesz == 0:
            continue
        src_end = p_offset + p_filesz
        if src_end > len(data):
            raise ValueError(
                f'PT_LOAD at vaddr 0x{p_vaddr:x}: file data '
                f'(offset 0x{p_offset:x} + 0x{p_filesz:x}) extends past EOF')
        dest = p_vaddr - lo
        image[dest:dest + p_filesz] = data[p_offset:src_end]

    if strip_meta:
        _zero_dead_metadata(image, info, lo)

    if trailer:
        endian = info['endian']
        start_func = _find_start_c(data, info) or info['entry']
        if info['bits'] == 64:
            trl = struct.pack(f'{endian}qq', start_func, info['dynamic'])
        else:
            trl = struct.pack(f'{endian}ii', start_func, info['dynamic'])
        trl += BIN_MAGIC
        image.extend(trl)

    return bytes(image)


def _zero_dead_metadata(image, info, lo):
    """Zero out runtime-dead sections within the flat image."""
    for sect in info['sections']:
        if sect['sh_size'] == 0 or sect['sh_type'] == SHT_NOBITS:
            continue
        if not (sect['sh_flags'] & SHF_ALLOC):
            continue

        is_dead = (sect['sh_type'] in _DEAD_SHTYPES or
                   sect['name'] in _DEAD_NAMES)
        if not is_dead:
            continue

        img_off = sect['sh_addr'] - lo
        if img_off < 0 or img_off + sect['sh_size'] > len(image):
            continue

        if sect['sh_type'] == SHT_STRTAB and sect['name'] not in _DEAD_NAMES:
            continue

        image[img_off:img_off + sect['sh_size']] = b'\0' * sect['sh_size']

    sh_off = info['e_shoff']
    sh_size = info['e_shnum'] * info['e_shentsize']
    if sh_off and sh_size and sh_off + sh_size <= len(image):
        image[sh_off:sh_off + sh_size] = b'\0' * sh_size

    endian = info['endian']
    if info['bits'] == 64:
        struct.pack_into(f'{endian}Q', image, 40, 0)
        struct.pack_into(f'{endian}HHH', image, 58, 0, 0, 0)
    else:
        struct.pack_into(f'{endian}I', image, 32, 0)
        struct.pack_into(f'{endian}HHH', image, 46, 0, 0, 0)


def _find_start_c(data, info):
    """Find _start_c symbol vaddr (for legacy trailer only)."""
    for sect in info['sections']:
        if sect['sh_type'] != SHT_SYMTAB or sect['sh_entsize'] == 0:
            continue
        sh_link = sect['sh_link']
        if sh_link >= len(info['sections']):
            return 0
        strtab = info['sections'][sh_link]
        strtab_off = strtab['sh_offset']

        nsyms = sect['sh_size'] // sect['sh_entsize']
        for j in range(nsyms):
            sym_off = sect['sh_offset'] + j * sect['sh_entsize']
            if sym_off + sect['sh_entsize'] > len(data):
                break
            if info['bits'] == 64:
                (st_name, _, _, _, st_value, _) = struct.unpack_from(
                    f'{info["endian"]}I BBH QQ', data, sym_off)
            else:
                (st_name, st_value, _, _, _, _) = struct.unpack_from(
                    f'{info["endian"]}III BBH', data, sym_off)
            name_off = strtab_off + st_name
            if name_off >= len(data):
                continue
            nul = data.find(b'\0', name_off, name_off + 256)
            if nul < 0:
                continue
            if data[name_off:nul] == b'_start_c':
                return st_value
        break
    return 0


def _elf2bin_entry(data):
    """Return the e_entry offset suitable for the stager."""
    info = _parse_elf_bin(data)
    lo = min(seg[2] for seg in info['segments'])
    lo = lo & ~0xfff
    return info['entry'] - lo


def cmd_elf2bin(input_path, output_path=None, entry_only=False,
                trailer=False, no_strip=False):
    """Convert a static-pie ELF to a flat binary image."""
    with open(input_path, 'rb') as f:
        data = f.read()

    if entry_only:
        print(f'0x{_elf2bin_entry(data):x}')
        return

    if not output_path:
        print('error: output file is required (unless using -e)',
              file=sys.stderr)
        sys.exit(1)

    info = _parse_elf_bin(data)
    strip = not no_strip
    image = _elf2bin_image(data, trailer=trailer, strip_meta=strip)

    lo = min(seg[2] for seg in info['segments'])
    lo = lo & ~0xfff
    file_hi = max(seg[2] + seg[3] for seg in info['segments'])
    mem_hi = max(seg[2] + seg[4] for seg in info['segments'])

    print(f'elf2bin: {input_path} ({len(data)} bytes)')
    print(f'  class:    ELF{info["bits"]} {"LE" if info["endian"] == "<" else "BE"}')
    print(f'  entry:    0x{info["entry"]:x} (offset 0x{info["entry"] - lo:x})')
    print(f'  base:     0x{lo:x}')
    print(f'  segments: {len(info["segments"])}')
    for i, (_, p_off, p_va, p_fsz, p_msz) in enumerate(info['segments']):
        print(f'    [{i}] vaddr=0x{p_va:x}  filesz=0x{p_fsz:x}  memsz=0x{p_msz:x}')
    if info['dynamic']:
        print(f'  dynamic:  0x{info["dynamic"]:x}')

    saved = (mem_hi - lo) - len(image)
    if strip and saved > 0:
        print(f'  trimmed:  {saved} bytes (BSS + metadata)')

    with open(output_path, 'wb') as f:
        f.write(image)

    print(f'  output:   {output_path} ({len(image)} bytes)')


# ─── Main ─────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="lltool — Mach-O/ELF/llbin packer, inspector, and converter")
    sub = parser.add_subparsers(dest='command')

    p_pack = sub.add_parser('pack', help='Pack Mach-O or ELF into llbin format')
    p_pack.add_argument('input', help='Input Mach-O or ELF executable')
    p_pack.add_argument('output', help='Output llbin file')

    p_info = sub.add_parser('info', help='Show info about a Mach-O, ELF, or llbin')
    p_info.add_argument('file', help='Input file (.macho, ELF, or .llbin)')

    p_e2b = sub.add_parser('elf2bin',
                           help='Convert static-pie ELF to flat binary image')
    p_e2b.add_argument('input', help='Input ELF file')
    p_e2b.add_argument('output', nargs='?', help='Output binary file')
    p_e2b.add_argument('-e', '--entry-only', action='store_true',
                       help='Print entry offset and exit')
    p_e2b.add_argument('--no-trailer', action='store_true',
                       help='Omit bin_info trailer (image will lack entry metadata)')
    p_e2b.add_argument('--no-strip', action='store_true',
                       help='Keep dead metadata and trailing BSS')

    args = parser.parse_args()

    if args.command == 'pack':
        cmd_pack(args.input, args.output)
    elif args.command == 'info':
        cmd_info(args.file)
    elif args.command == 'elf2bin':
        cmd_elf2bin(args.input, args.output, args.entry_only,
                    not args.no_trailer, args.no_strip)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == '__main__':
    main()
