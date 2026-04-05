/*
 * llpack — Mach-O/ELF → llbin packer
 *
 * Reads a Mach-O executable (or fat binary) or an ELF shared object,
 * flattens all segments into a contiguous image, extracts relocations
 * and import references, and writes an llbin file that can be loaded
 * trivially at runtime.
 *
 * Usage: llpack <input> <output.llbin>
 */

#include "llbin.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifdef __APPLE__
#include <libkern/OSByteOrder.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach/machine.h>
#endif

#ifdef __linux__
#include <elf.h>

/* ELF type bridge — select 32-bit or 64-bit types at compile time */
#if __SIZEOF_POINTER__ == 8
#define Elf_Ehdr    Elf64_Ehdr
#define Elf_Phdr    Elf64_Phdr
#define Elf_Dyn     Elf64_Dyn
#define Elf_Sym     Elf64_Sym
#define Elf_Rela    Elf64_Rela
#define Elf_Rel     Elf64_Rel
#define Elf_Addr    Elf64_Addr
#define ELF_R_TYPE  ELF64_R_TYPE
#define ELF_R_SYM   ELF64_R_SYM
#define ELFCLASS_NATIVE ELFCLASS64
#else
#define Elf_Ehdr    Elf32_Ehdr
#define Elf_Phdr    Elf32_Phdr
#define Elf_Dyn     Elf32_Dyn
#define Elf_Sym     Elf32_Sym
#define Elf_Rela    Elf32_Rela
#define Elf_Rel     Elf32_Rel
#define Elf_Addr    Elf32_Addr
#define ELF_R_TYPE  ELF32_R_TYPE
#define ELF_R_SYM   ELF32_R_SYM
#define ELFCLASS_NATIVE ELFCLASS32
#endif

#if defined(__mips__)
#ifndef R_MIPS_GLOB_DAT
#define R_MIPS_GLOB_DAT 51
#endif
#ifndef R_MIPS_JUMP_SLOT
#define R_MIPS_JUMP_SLOT 127
#endif
#endif

#endif

/* Arch constants for llbin header (portable) */
#ifndef CPU_TYPE_X86_64
#define CPU_TYPE_X86_64  0x01000007
#endif
#ifndef CPU_TYPE_ARM64
#define CPU_TYPE_ARM64   0x0100000C
#endif

/* ------------------------------------------------------------------ */
/*  Chained-fixup structs (may not be in older SDK headers)           */
/*  Mach-O specific — only needed on Apple platforms                  */
/* ------------------------------------------------------------------ */

#ifdef __APPLE__

#ifndef DYLD_CHAINED_PTR_64

struct dyld_chained_fixups_header {
    uint32_t fixups_version;
    uint32_t starts_offset;
    uint32_t imports_offset;
    uint32_t symbols_offset;
    uint32_t imports_count;
    uint32_t imports_format;
    uint32_t symbols_format;
};

struct dyld_chained_starts_in_image {
    uint32_t seg_count;
    uint32_t seg_info_offset[];
};

struct dyld_chained_starts_in_segment {
    uint32_t size;
    uint16_t page_size;
    uint16_t pointer_format;
    uint64_t segment_offset;
    uint32_t max_valid_pointer;
    uint16_t page_count;
    uint16_t page_start[];
};

struct dyld_chained_import {
    uint32_t lib_ordinal : 8;
    uint32_t weak_import : 1;
    uint32_t name_offset : 23;
};

struct dyld_chained_import_addend {
    uint32_t lib_ordinal : 8;
    uint32_t weak_import : 1;
    uint32_t name_offset : 23;
    int32_t  addend;
};

#define DYLD_CHAINED_PTR_ARM64E             1
#define DYLD_CHAINED_PTR_64                 2
#define DYLD_CHAINED_PTR_64_OFFSET          6
#define DYLD_CHAINED_PTR_ARM64E_USERLAND    12
#define DYLD_CHAINED_PTR_ARM64E_USERLAND24  13

#define DYLD_CHAINED_IMPORT                 1
#define DYLD_CHAINED_IMPORT_ADDEND          2

#endif /* DYLD_CHAINED_PTR_64 */

#ifndef DYLD_CHAINED_PTR_START_NONE
#define DYLD_CHAINED_PTR_START_NONE  0xFFFF
#endif

#endif /* __APPLE__ */

/* ------------------------------------------------------------------ */
/*  Limits                                                            */
/* ------------------------------------------------------------------ */

#define MAX_SEGS    32
#define MAX_FIXUPS  131072
#define MAX_IMPORTS 4096
#define MAX_STRINGS 131072

/* ------------------------------------------------------------------ */
/*  State                                                             */
/* ------------------------------------------------------------------ */

struct seg_info {
    char     name[16];
    uint64_t vmaddr;
    uint64_t vmsize;
    uint64_t fileoff;
    uint64_t filesize;
    uint32_t initprot;
};

static struct seg_info     segs[MAX_SEGS];
static uint32_t            nsegs;
static uint64_t            base_vmaddr;
static uint64_t            total_size;       /* page-aligned   */

static uint8_t            *image;            /* flat image buf  */

static struct llbin_fixup  fixups[MAX_FIXUPS];
static uint32_t            nfixups;

static struct llbin_import imports[MAX_IMPORTS];
static uint32_t            nimports;

static char                strtab[MAX_STRINGS];
static uint32_t            strtab_len;

static uint64_t            entry_off;
static int                 has_entry;

/* ------------------------------------------------------------------ */
/*  Helpers                                                           */
/* ------------------------------------------------------------------ */

static void die(const char *msg)
{
    fprintf(stderr, "llpack: %s\n", msg);
    exit(1);
}

static uint32_t add_string(const char *s)
{
    size_t len = strlen(s) + 1;
    if (strtab_len + len > MAX_STRINGS)
        die("string table overflow");
    uint32_t off = strtab_len;
    memcpy(strtab + off, s, len);
    strtab_len += (uint32_t)len;
    return off;
}

#ifdef __APPLE__
static uint16_t find_or_add_import(const char *name)
{
    /* Strip leading underscore (Mach-O convention) */
    const char *n = name;
    if (n[0] == '_') n++;

    for (uint32_t i = 0; i < nimports; i++) {
        if (strcmp(strtab + imports[i].name_off, n) == 0)
            return (uint16_t)i;
    }

    if (nimports >= MAX_IMPORTS)
        die("import table overflow");

    uint16_t idx = (uint16_t)nimports;
    imports[nimports].name_off = add_string(n);
    imports[nimports].flags    = 0;
    nimports++;
    return idx;
}
#endif /* __APPLE__ */

static void add_fixup(uint32_t offset, uint8_t type,
                       uint16_t import_idx, int64_t addend)
{
    if (nfixups >= MAX_FIXUPS)
        die("fixup table overflow");

    fixups[nfixups].offset     = offset;
    fixups[nfixups].type       = type;
    fixups[nfixups].reserved   = 0;
    fixups[nfixups].import_idx = import_idx;
    fixups[nfixups].addend     = addend;
    nfixups++;
}

/* ================================================================== */
/*  Mach-O specific code                                              */
/* ================================================================== */

#ifdef __APPLE__

static uint64_t read_uleb128(const uint8_t **p, const uint8_t *end)
{
    uint64_t val = 0;
    unsigned shift = 0;
    while (*p < end) {
        uint8_t b = **p; (*p)++;
        val |= (uint64_t)(b & 0x7F) << shift;
        if (!(b & 0x80)) break;
        shift += 7;
        if (shift >= 64) break;
    }
    return val;
}

static int64_t read_sleb128(const uint8_t **p, const uint8_t *end)
{
    int64_t  val   = 0;
    unsigned shift = 0;
    uint8_t  b     = 0;
    while (*p < end) {
        b = **p; (*p)++;
        val |= (int64_t)(b & 0x7F) << shift;
        shift += 7;
        if (!(b & 0x80)) break;
        if (shift >= 64) break;
    }
    if (shift < 64 && (b & 0x40))
        val |= -(1LL << shift);
    return val;
}

/* ------------------------------------------------------------------ */
/*  Fat binary extraction                                             */
/* ------------------------------------------------------------------ */

static const uint8_t *extract_arch(const uint8_t *buf, size_t len,
                                   size_t *out_len)
{
    uint32_t magic;
    if (len < 4) return NULL;
    memcpy(&magic, buf, 4);

    if (magic == FAT_MAGIC || magic == FAT_CIGAM) {
        struct fat_header fh;
        memcpy(&fh, buf, sizeof(fh));
        uint32_t narch = OSSwapBigToHostInt32(fh.nfat_arch);

        if (len < sizeof(fh) + narch * sizeof(struct fat_arch))
            return NULL;

        for (uint32_t i = 0; i < narch; i++) {
            struct fat_arch fa;
            memcpy(&fa, buf + sizeof(fh) + i * sizeof(fa), sizeof(fa));
            cpu_type_t ct = (cpu_type_t)OSSwapBigToHostInt32(fa.cputype);

#if defined(__arm64__) || defined(__aarch64__)
            if (ct == CPU_TYPE_ARM64)
#elif defined(__x86_64__)
            if (ct == CPU_TYPE_X86_64)
#else
            if (0)
#endif
            {
                uint32_t o = OSSwapBigToHostInt32(fa.offset);
                uint32_t s = OSSwapBigToHostInt32(fa.size);
                if ((uint64_t)o + s > len) return NULL;
                *out_len = s;
                return buf + o;
            }
        }
        return NULL;
    }

    *out_len = len;
    return buf;
}

/* ------------------------------------------------------------------ */
/*  Build flat image from Mach-O segments                             */
/* ------------------------------------------------------------------ */

static int build_image(const uint8_t *buf, size_t len)
{
    const struct mach_header_64 *hdr = (const struct mach_header_64 *)buf;

    if (len < sizeof(*hdr) || hdr->magic != MH_MAGIC_64)
        return -1;

    if (hdr->filetype != MH_EXECUTE)
        die("input must be a Mach-O executable (MH_EXECUTE)");

    const uint8_t *lc = buf + sizeof(*hdr);
    uint64_t lo = UINT64_MAX, hi = 0;

    /* Collect segments */
    nsegs = 0;
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        const struct load_command *cmd = (const struct load_command *)lc;

        if (cmd->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg =
                (const struct segment_command_64 *)lc;

            if (nsegs >= MAX_SEGS) die("too many segments");

            memcpy(segs[nsegs].name, seg->segname, 16);
            segs[nsegs].vmaddr   = seg->vmaddr;
            segs[nsegs].vmsize   = seg->vmsize;
            segs[nsegs].fileoff  = seg->fileoff;
            segs[nsegs].filesize = seg->filesize;
            segs[nsegs].initprot = seg->initprot;
            nsegs++;

            if (strcmp(seg->segname, "__PAGEZERO") == 0 ||
                seg->vmsize == 0) {
                lc += cmd->cmdsize;
                continue;
            }

            if (seg->vmaddr < lo)                   lo = seg->vmaddr;
            if (seg->vmaddr + seg->vmsize > hi)     hi = seg->vmaddr + seg->vmsize;
        }

        lc += cmd->cmdsize;
    }

    if (lo >= hi) die("no loadable segments");

    base_vmaddr = lo;
    total_size  = ((hi - lo) + 0x3FFFULL) & ~0x3FFFULL; /* 16 KB align */

    image = calloc(1, (size_t)total_size);
    if (!image) die("out of memory");

    /* Copy segment data into flat image */
    for (uint32_t i = 0; i < nsegs; i++) {
        if (segs[i].filesize == 0)                     continue;
        if (strcmp(segs[i].name, "__PAGEZERO") == 0)   continue;
        if (segs[i].vmaddr < base_vmaddr)              continue;

        if (segs[i].fileoff + segs[i].filesize > len)
            die("segment extends past end of file");

        uint64_t dest = segs[i].vmaddr - base_vmaddr;
        memcpy(image + dest, buf + segs[i].fileoff, (size_t)segs[i].filesize);
    }

    /* Find entry point */
    has_entry = 0;
    lc = buf + sizeof(*hdr);
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        const struct load_command *cmd = (const struct load_command *)lc;
        if (cmd->cmd == LC_MAIN) {
            const struct entry_point_command *ep =
                (const struct entry_point_command *)lc;
            entry_off = ep->entryoff;
            has_entry = 1;
        }
        lc += cmd->cmdsize;
    }

    if (!has_entry) die("no LC_MAIN found");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Chained fixup processing                                          */
/* ------------------------------------------------------------------ */

static int process_chained(const uint8_t *buf,
                           uint32_t dataoff, uint32_t datasize)
{
    (void)datasize;

    const uint8_t *base = buf + dataoff;
    const struct dyld_chained_fixups_header *hdr =
        (const struct dyld_chained_fixups_header *)base;

    const struct dyld_chained_starts_in_image *starts =
        (const struct dyld_chained_starts_in_image *)
        (base + hdr->starts_offset);

    const uint8_t *imp_base = base + hdr->imports_offset;
    const char    *sym_base = (const char *)base + hdr->symbols_offset;

    for (uint32_t seg_i = 0; seg_i < starts->seg_count; seg_i++) {
        if (starts->seg_info_offset[seg_i] == 0) continue;

        const struct dyld_chained_starts_in_segment *ss =
            (const struct dyld_chained_starts_in_segment *)
            ((const uint8_t *)starts + starts->seg_info_offset[seg_i]);

        if (seg_i >= nsegs) continue;
        if (segs[seg_i].vmaddr < base_vmaddr) continue;

        uint16_t ptr_fmt = ss->pointer_format;
        uint32_t stride;

        switch (ptr_fmt) {
        case DYLD_CHAINED_PTR_64:
        case DYLD_CHAINED_PTR_64_OFFSET:
            stride = 4; break;
        case DYLD_CHAINED_PTR_ARM64E:
        case DYLD_CHAINED_PTR_ARM64E_USERLAND:
        case DYLD_CHAINED_PTR_ARM64E_USERLAND24:
            stride = 8; break;
        default:
            stride = 4; break;
        }

        for (uint32_t page_i = 0; page_i < ss->page_count; page_i++) {
            uint16_t page_start = ss->page_start[page_i];
            if (page_start == DYLD_CHAINED_PTR_START_NONE) continue;

            uint64_t page_off = (uint64_t)page_i * ss->page_size;
            uint8_t *chain = image +
                             (uint64_t)ss->segment_offset +
                             page_off + page_start;

            while (1) {
                uint64_t raw;
                memcpy(&raw, chain, sizeof(raw));

                int      is_bind = (raw >> 63) & 1;
                uint32_t next    = 0;
                uint32_t img_off = (uint32_t)(chain - image);

                if (ptr_fmt == DYLD_CHAINED_PTR_64 ||
                    ptr_fmt == DYLD_CHAINED_PTR_64_OFFSET) {

                    next = (uint32_t)((raw >> 51) & 0xFFF);

                    if (is_bind) {
                        uint32_t ordinal = (uint32_t)(raw & 0xFFFFFF);
                        int32_t  add     = (int32_t)((raw >> 24) & 0xFF);
                        if (add & 0x80) add |= (int32_t)0xFFFFFF00;

                        const char *sym    = NULL;
                        int32_t imp_addend = 0;

                        if (hdr->imports_format == DYLD_CHAINED_IMPORT) {
                            const struct dyld_chained_import *imp =
                                (const struct dyld_chained_import *)imp_base
                                + ordinal;
                            sym = sym_base + imp->name_offset;
                        } else if (hdr->imports_format == DYLD_CHAINED_IMPORT_ADDEND) {
                            const struct dyld_chained_import_addend *imp =
                                (const struct dyld_chained_import_addend *)
                                imp_base + ordinal;
                            sym = sym_base + imp->name_offset;
                            imp_addend = imp->addend;
                        }
                        if (!sym) die("unsupported chained import format");

                        uint16_t idx = find_or_add_import(sym);
                        uint64_t zero = 0;
                        memcpy(chain, &zero, sizeof(zero));
                        add_fixup(img_off, LLBIN_FIXUP_IMPORT, idx,
                                  (int64_t)add + imp_addend);
                    } else {
                        /* Rebase: write preferred-base value */
                        uint64_t target = raw & 0xFFFFFFFFFULL;
                        uint8_t  high8  = (raw >> 36) & 0xFF;
                        uint64_t value;

                        if (ptr_fmt == DYLD_CHAINED_PTR_64_OFFSET)
                            value = base_vmaddr + target;
                        else
                            value = target;

                        value |= (uint64_t)high8 << 56;
                        memcpy(chain, &value, sizeof(value));
                        add_fixup(img_off, LLBIN_FIXUP_REBASE, 0, 0);
                    }

                } else if (ptr_fmt == DYLD_CHAINED_PTR_ARM64E ||
                           ptr_fmt == DYLD_CHAINED_PTR_ARM64E_USERLAND ||
                           ptr_fmt == DYLD_CHAINED_PTR_ARM64E_USERLAND24) {

                    int is_auth = (raw >> 63) & 1;
                    is_bind = (raw >> 62) & 1;
                    next = (uint32_t)((raw >> 52) & 0x7FF);

                    if (is_bind) {
                        uint32_t ordinal;
                        if (ptr_fmt == DYLD_CHAINED_PTR_ARM64E_USERLAND24)
                            ordinal = (uint32_t)(raw & 0xFFFFFF);
                        else
                            ordinal = (uint32_t)(raw & 0xFFFF);

                        const char *sym    = NULL;
                        int32_t imp_addend = 0;

                        if (hdr->imports_format == DYLD_CHAINED_IMPORT) {
                            const struct dyld_chained_import *imp =
                                (const struct dyld_chained_import *)imp_base
                                + ordinal;
                            sym = sym_base + imp->name_offset;
                        } else if (hdr->imports_format == DYLD_CHAINED_IMPORT_ADDEND) {
                            const struct dyld_chained_import_addend *imp =
                                (const struct dyld_chained_import_addend *)
                                imp_base + ordinal;
                            sym = sym_base + imp->name_offset;
                            imp_addend = imp->addend;
                        }
                        if (!sym) die("unsupported chained import format");

                        uint16_t idx = find_or_add_import(sym);
                        uint64_t zero = 0;
                        memcpy(chain, &zero, sizeof(zero));
                        add_fixup(img_off, LLBIN_FIXUP_IMPORT, idx,
                                  imp_addend);
                    } else {
                        uint64_t target;
                        uint8_t  high8 = 0;

                        if (is_auth) {
                            target = raw & 0xFFFFFFFF;
                        } else {
                            target = raw & 0x7FFFFFFFFULL;
                            high8  = (raw >> 43) & 0xFF;
                        }

                        uint64_t value;
                        if (ptr_fmt == DYLD_CHAINED_PTR_ARM64E)
                            value = target;
                        else
                            value = base_vmaddr + target;

                        if (!is_auth)
                            value |= (uint64_t)high8 << 56;

                        memcpy(chain, &value, sizeof(value));
                        add_fixup(img_off, LLBIN_FIXUP_REBASE, 0, 0);
                    }
                }

                if (next == 0) break;
                chain += next * stride;
            }
        }
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/*  Legacy rebase (LC_DYLD_INFO / LC_DYLD_INFO_ONLY)                  */
/* ------------------------------------------------------------------ */

static uint8_t *seg_addr(uint32_t idx)
{
    if (idx >= nsegs || segs[idx].vmaddr < base_vmaddr)
        return NULL;
    return image + (segs[idx].vmaddr - base_vmaddr);
}

static int process_rebase(const uint8_t *opcodes, size_t size)
{
    const uint8_t *p = opcodes, *end = opcodes + size;
    uint32_t seg_idx = 0;
    uint64_t seg_off = 0;

    while (p < end) {
        uint8_t byte   = *p++;
        uint8_t opcode = byte & REBASE_OPCODE_MASK;
        uint8_t imm    = byte & REBASE_IMMEDIATE_MASK;

        switch (opcode) {
        case REBASE_OPCODE_DONE:
            return 0;
        case REBASE_OPCODE_SET_TYPE_IMM:
            break;
        case REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
            seg_idx = imm;
            seg_off = read_uleb128(&p, end);
            break;
        case REBASE_OPCODE_ADD_ADDR_ULEB:
            seg_off += read_uleb128(&p, end);
            break;
        case REBASE_OPCODE_ADD_ADDR_IMM_SCALED:
            seg_off += (uint64_t)imm * 8;
            break;
        case REBASE_OPCODE_DO_REBASE_IMM_TIMES: {
            uint8_t *b = seg_addr(seg_idx);
            if (!b) return -1;
            for (uint8_t j = 0; j < imm; j++) {
                add_fixup((uint32_t)(b + seg_off - image),
                          LLBIN_FIXUP_REBASE, 0, 0);
                seg_off += 8;
            }
            break;
        }
        case REBASE_OPCODE_DO_REBASE_ULEB_TIMES: {
            uint64_t count = read_uleb128(&p, end);
            uint8_t *b = seg_addr(seg_idx);
            if (!b) return -1;
            for (uint64_t j = 0; j < count; j++) {
                add_fixup((uint32_t)(b + seg_off - image),
                          LLBIN_FIXUP_REBASE, 0, 0);
                seg_off += 8;
            }
            break;
        }
        case REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB: {
            uint64_t skip = read_uleb128(&p, end);
            uint8_t *b = seg_addr(seg_idx);
            if (!b) return -1;
            add_fixup((uint32_t)(b + seg_off - image),
                      LLBIN_FIXUP_REBASE, 0, 0);
            seg_off += 8 + skip;
            break;
        }
        case REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB: {
            uint64_t count = read_uleb128(&p, end);
            uint64_t skip  = read_uleb128(&p, end);
            uint8_t *b = seg_addr(seg_idx);
            if (!b) return -1;
            for (uint64_t j = 0; j < count; j++) {
                add_fixup((uint32_t)(b + seg_off - image),
                          LLBIN_FIXUP_REBASE, 0, 0);
                seg_off += 8 + skip;
            }
            break;
        }
        default:
            return -1;
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Legacy bind (LC_DYLD_INFO / LC_DYLD_INFO_ONLY)                    */
/* ------------------------------------------------------------------ */

static int process_bind(const uint8_t *opcodes, size_t size, int is_lazy)
{
    const uint8_t *p = opcodes, *end = opcodes + size;
    const char *sym_name = NULL;
    uint32_t seg_idx = 0;
    uint64_t seg_off = 0;
    int64_t  addend  = 0;

    while (p < end) {
        uint8_t byte   = *p++;
        uint8_t opcode = byte & BIND_OPCODE_MASK;
        uint8_t imm    = byte & BIND_IMMEDIATE_MASK;

        switch (opcode) {
        case BIND_OPCODE_DONE:
            if (!is_lazy) return 0;
            break;
        case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
        case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
        case BIND_OPCODE_SET_TYPE_IMM:
            (void)imm; break;
        case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
            read_uleb128(&p, end); break;
        case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
            sym_name = (const char *)p;
            while (p < end && *p) p++;
            if (p < end) p++;
            break;
        case BIND_OPCODE_SET_ADDEND_SLEB:
            addend = read_sleb128(&p, end);
            break;
        case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
            seg_idx = imm;
            seg_off = read_uleb128(&p, end);
            break;
        case BIND_OPCODE_ADD_ADDR_ULEB:
            seg_off += read_uleb128(&p, end);
            break;
        case BIND_OPCODE_DO_BIND: {
            if (!sym_name) return -1;
            uint16_t idx = find_or_add_import(sym_name);
            uint8_t *b = seg_addr(seg_idx);
            if (!b) return -1;
            uint32_t off = (uint32_t)(b + seg_off - image);
            uint64_t zero = 0;
            memcpy(b + seg_off, &zero, 8);
            add_fixup(off, LLBIN_FIXUP_IMPORT, idx, addend);
            seg_off += 8;
            break;
        }
        case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB: {
            if (!sym_name) return -1;
            uint16_t idx = find_or_add_import(sym_name);
            uint8_t *b = seg_addr(seg_idx);
            if (!b) return -1;
            uint32_t off = (uint32_t)(b + seg_off - image);
            uint64_t zero = 0;
            memcpy(b + seg_off, &zero, 8);
            add_fixup(off, LLBIN_FIXUP_IMPORT, idx, addend);
            seg_off += 8 + read_uleb128(&p, end);
            break;
        }
        case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED: {
            if (!sym_name) return -1;
            uint16_t idx = find_or_add_import(sym_name);
            uint8_t *b = seg_addr(seg_idx);
            if (!b) return -1;
            uint32_t off = (uint32_t)(b + seg_off - image);
            uint64_t zero = 0;
            memcpy(b + seg_off, &zero, 8);
            add_fixup(off, LLBIN_FIXUP_IMPORT, idx, addend);
            seg_off += 8 + (uint64_t)imm * 8;
            break;
        }
        case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB: {
            uint64_t count = read_uleb128(&p, end);
            uint64_t skip  = read_uleb128(&p, end);
            if (!sym_name) return -1;
            uint16_t idx = find_or_add_import(sym_name);
            uint8_t *b = seg_addr(seg_idx);
            if (!b) return -1;
            for (uint64_t j = 0; j < count; j++) {
                uint32_t off = (uint32_t)(b + seg_off - image);
                uint64_t zero = 0;
                memcpy(b + seg_off, &zero, 8);
                add_fixup(off, LLBIN_FIXUP_IMPORT, idx, addend);
                seg_off += 8 + skip;
            }
            break;
        }
        default:
            if (is_lazy) break;
            return -1;
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Walk all load commands to process fixups                           */
/* ------------------------------------------------------------------ */

static int process_fixups(const uint8_t *buf, size_t len)
{
    const struct mach_header_64 *hdr = (const struct mach_header_64 *)buf;
    const uint8_t *lc = buf + sizeof(*hdr);
    (void)len;

    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        const struct load_command *cmd = (const struct load_command *)lc;

        switch (cmd->cmd) {
        case LC_DYLD_CHAINED_FIXUPS: {
            const struct linkedit_data_command *ldc =
                (const struct linkedit_data_command *)lc;
            printf("  processing chained fixups (off=%u size=%u)\n",
                   ldc->dataoff, ldc->datasize);
            if (process_chained(buf, ldc->dataoff, ldc->datasize) < 0)
                die("chained fixup processing failed");
            break;
        }
        case LC_DYLD_INFO:
        case LC_DYLD_INFO_ONLY: {
            const struct dyld_info_command *di =
                (const struct dyld_info_command *)lc;
            if (di->rebase_size > 0) {
                printf("  processing rebase opcodes (%u bytes)\n",
                       di->rebase_size);
                if (process_rebase(buf + di->rebase_off,
                                   di->rebase_size) < 0)
                    die("rebase processing failed");
            }
            if (di->bind_size > 0) {
                printf("  processing bind opcodes (%u bytes)\n",
                       di->bind_size);
                if (process_bind(buf + di->bind_off,
                                 di->bind_size, 0) < 0)
                    die("bind processing failed");
            }
            if (di->lazy_bind_size > 0) {
                printf("  processing lazy bind opcodes (%u bytes)\n",
                       di->lazy_bind_size);
                if (process_bind(buf + di->lazy_bind_off,
                                 di->lazy_bind_size, 1) < 0)
                    die("lazy bind processing failed");
            }
            break;
        }
        default:
            break;
        }

        lc += cmd->cmdsize;
    }
    return 0;
}

#endif /* __APPLE__ */

/* ================================================================== */
/*  ELF specific code                                                 */
/* ================================================================== */

#ifdef __linux__

static uint16_t find_or_add_import_raw(const char *name)
{
    /* No underscore stripping — ELF symbols don't have leading _ */
    for (uint32_t i = 0; i < nimports; i++) {
        if (strcmp(strtab + imports[i].name_off, name) == 0)
            return (uint16_t)i;
    }

    if (nimports >= MAX_IMPORTS)
        die("import table overflow");

    uint16_t idx = (uint16_t)nimports;
    imports[nimports].name_off = add_string(name);
    imports[nimports].flags    = 0;
    nimports++;
    return idx;
}

static int build_image_elf(const uint8_t *buf, size_t len)
{
    if (len < sizeof(Elf_Ehdr))
        return -1;

    const Elf_Ehdr *ehdr = (const Elf_Ehdr *)buf;

    /* Validate ELF */
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0)
        return -1;
    if (ehdr->e_ident[EI_CLASS] != ELFCLASS_NATIVE)
        die("ELF class does not match native pointer size");
    if (ehdr->e_type != ET_DYN && ehdr->e_type != ET_EXEC)
        die("input must be ET_DYN or ET_EXEC");

    /* Scan PT_LOAD segments for address range */
    uint64_t lo = UINT64_MAX, hi = 0;
    nsegs = 0;

    for (uint16_t i = 0; i < ehdr->e_phnum; i++) {
        if ((uint64_t)ehdr->e_phoff + (i + 1) * ehdr->e_phentsize > len)
            die("program header extends past EOF");

        const Elf_Phdr *phdr =
            (const Elf_Phdr *)(buf + ehdr->e_phoff + i * ehdr->e_phentsize);

        if (phdr->p_type != PT_LOAD)
            continue;

        if (nsegs >= MAX_SEGS) die("too many segments");

        segs[nsegs].vmaddr   = phdr->p_vaddr;
        segs[nsegs].vmsize   = phdr->p_memsz;
        segs[nsegs].fileoff  = phdr->p_offset;
        segs[nsegs].filesize = phdr->p_filesz;
        segs[nsegs].initprot = 0;
        if (phdr->p_flags & PF_R) segs[nsegs].initprot |= 1; /* VM_PROT_READ */
        if (phdr->p_flags & PF_W) segs[nsegs].initprot |= 2; /* VM_PROT_WRITE */
        if (phdr->p_flags & PF_X) segs[nsegs].initprot |= 4; /* VM_PROT_EXECUTE */
        snprintf(segs[nsegs].name, 16, "LOAD%u", nsegs);
        nsegs++;

        if (phdr->p_vaddr < lo)
            lo = phdr->p_vaddr;
        if (phdr->p_vaddr + phdr->p_memsz > hi)
            hi = phdr->p_vaddr + phdr->p_memsz;
    }

    if (lo >= hi) die("no PT_LOAD segments");

    base_vmaddr = lo;
    total_size  = ((hi - lo) + 0xFFFULL) & ~0xFFFULL; /* 4KB align */

    image = calloc(1, (size_t)total_size);
    if (!image) die("out of memory");

    /* Copy segment data */
    for (uint32_t i = 0; i < nsegs; i++) {
        if (segs[i].filesize == 0) continue;
        if (segs[i].fileoff + segs[i].filesize > len)
            die("segment extends past end of file");

        uint64_t dest = segs[i].vmaddr - base_vmaddr;
        memcpy(image + dest, buf + segs[i].fileoff, (size_t)segs[i].filesize);
    }

    /* Entry point */
    entry_off = ehdr->e_entry - base_vmaddr;
    has_entry = 1;

    return 0;
}

static int process_fixups_elf(const uint8_t *buf, size_t len)
{
    const Elf_Ehdr *ehdr = (const Elf_Ehdr *)buf;

    /* Find PT_DYNAMIC */
    const Elf_Phdr *dyn_phdr = NULL;
    for (uint16_t i = 0; i < ehdr->e_phnum; i++) {
        const Elf_Phdr *phdr =
            (const Elf_Phdr *)(buf + ehdr->e_phoff + i * ehdr->e_phentsize);
        if (phdr->p_type == PT_DYNAMIC) {
            dyn_phdr = phdr;
            break;
        }
    }

    if (!dyn_phdr) {
        printf("  no PT_DYNAMIC — static binary, no fixups\n");
        return 0;
    }

    /* Parse dynamic entries from the flat image */
    uint64_t dyn_off = dyn_phdr->p_vaddr - base_vmaddr;
    const Elf_Dyn *dyn = (const Elf_Dyn *)(image + dyn_off);

    uint64_t rela_addr = 0, rela_sz = 0, rela_ent = 0;
    uint64_t rel_addr = 0, rel_sz = 0, rel_ent = 0;
    uint64_t jmprel_addr = 0, pltrelsz = 0;
    int      pltrel_type = DT_RELA;
    uint64_t symtab_addr = 0, strtab_addr = 0;

    for (const Elf_Dyn *d = dyn; d->d_tag != DT_NULL; d++) {
        switch (d->d_tag) {
        case DT_RELA:     rela_addr   = d->d_un.d_ptr; break;
        case DT_RELASZ:   rela_sz     = d->d_un.d_val; break;
        case DT_RELAENT:  rela_ent    = d->d_un.d_val; break;
        case DT_REL:      rel_addr    = d->d_un.d_ptr; break;
        case DT_RELSZ:    rel_sz      = d->d_un.d_val; break;
        case DT_RELENT:   rel_ent     = d->d_un.d_val; break;
        case DT_JMPREL:   jmprel_addr = d->d_un.d_ptr; break;
        case DT_PLTRELSZ: pltrelsz    = d->d_un.d_val; break;
        case DT_PLTREL:   pltrel_type = (int)d->d_un.d_val; break;
        case DT_SYMTAB:   symtab_addr = d->d_un.d_ptr; break;
        case DT_STRTAB:   strtab_addr = d->d_un.d_ptr; break;
        }
    }

    (void)len;

    const Elf_Sym *symtab = symtab_addr ?
        (const Elf_Sym *)(image + symtab_addr - base_vmaddr) : NULL;
    const char *dynstr = strtab_addr ?
        (const char *)(image + strtab_addr - base_vmaddr) : NULL;

    uint16_t machine = ehdr->e_machine;

    /* Helper: classify relocation type */
    #define IS_RELATIVE(m, t, s) ( \
        ((m) == EM_X86_64  && (t) == R_X86_64_RELATIVE) || \
        ((m) == EM_AARCH64 && (t) == R_AARCH64_RELATIVE) || \
        ((m) == EM_386     && (t) == R_386_RELATIVE) || \
        ((m) == EM_ARM     && (t) == R_ARM_RELATIVE) || \
        ((m) == EM_MIPS    && (t) == R_MIPS_REL32 && (s) == 0) || \
        ((m) == EM_SPARC   && (t) == R_SPARC_RELATIVE) )

    #define IS_IMPORT(m, t, s) ( \
        ((m) == EM_X86_64  && ((t) == R_X86_64_GLOB_DAT || \
                               (t) == R_X86_64_JUMP_SLOT || \
                               (t) == R_X86_64_64)) || \
        ((m) == EM_AARCH64 && ((t) == R_AARCH64_GLOB_DAT || \
                               (t) == R_AARCH64_JUMP_SLOT || \
                               (t) == R_AARCH64_ABS64)) || \
        ((m) == EM_386     && ((t) == R_386_GLOB_DAT || \
                               (t) == R_386_JMP_SLOT || \
                               (t) == R_386_32)) || \
        ((m) == EM_ARM     && ((t) == R_ARM_GLOB_DAT || \
                               (t) == R_ARM_JUMP_SLOT || \
                               (t) == R_ARM_ABS32)) || \
        ((m) == EM_MIPS    && ((t) == R_MIPS_32 || \
                               (t) == R_MIPS_GLOB_DAT || \
                               (t) == R_MIPS_JUMP_SLOT || \
                               ((t) == R_MIPS_REL32 && (s) > 0))) || \
        ((m) == EM_SPARC   && ((t) == R_SPARC_GLOB_DAT || \
                               (t) == R_SPARC_JMP_SLOT || \
                               (t) == R_SPARC_32)) )

    size_t slot_sz = sizeof(Elf_Addr);

    /* Process DT_RELA table */
    if (rela_addr && rela_sz && rela_ent) {
        uint64_t count = rela_sz / rela_ent;
        const Elf_Rela *tbl =
            (const Elf_Rela *)(image + rela_addr - base_vmaddr);

        printf("  processing DT_RELA (%llu entries)\n",
               (unsigned long long)count);

        for (uint64_t i = 0; i < count; i++) {
            uint32_t type = ELF_R_TYPE(tbl[i].r_info);
            uint32_t sym  = ELF_R_SYM(tbl[i].r_info);
            uint64_t off  = tbl[i].r_offset - base_vmaddr;

            if (IS_RELATIVE(machine, type, sym)) {
                Elf_Addr val = (Elf_Addr)tbl[i].r_addend;
                memcpy(image + off, &val, slot_sz);
                add_fixup((uint32_t)off, LLBIN_FIXUP_REBASE, 0, 0);
            } else if (IS_IMPORT(machine, type, sym) &&
                       symtab && dynstr && sym > 0) {
                const char *name = dynstr + symtab[sym].st_name;
                uint16_t idx = find_or_add_import_raw(name);
                Elf_Addr zero = 0;
                memcpy(image + off, &zero, slot_sz);
                add_fixup((uint32_t)off, LLBIN_FIXUP_IMPORT, idx,
                          tbl[i].r_addend);
            }
        }
    }

    /* Process DT_REL table (used by i386, ARM, MIPS) */
    if (rel_addr && rel_sz && rel_ent) {
        uint64_t count = rel_sz / rel_ent;
        const Elf_Rel *tbl =
            (const Elf_Rel *)(image + rel_addr - base_vmaddr);

        printf("  processing DT_REL (%llu entries)\n",
               (unsigned long long)count);

        for (uint64_t i = 0; i < count; i++) {
            uint32_t type = ELF_R_TYPE(tbl[i].r_info);
            uint32_t sym  = ELF_R_SYM(tbl[i].r_info);
            uint64_t off  = tbl[i].r_offset - base_vmaddr;

            if (IS_RELATIVE(machine, type, sym)) {
                /* Implicit addend already in slot — keep it as-is */
                add_fixup((uint32_t)off, LLBIN_FIXUP_REBASE, 0, 0);
            } else if (IS_IMPORT(machine, type, sym) &&
                       symtab && dynstr && sym > 0) {
                /* REL: implicit addend in slot */
                Elf_Addr addend;
                memcpy(&addend, image + off, slot_sz);
                const char *name = dynstr + symtab[sym].st_name;
                uint16_t idx = find_or_add_import_raw(name);
                Elf_Addr zero = 0;
                memcpy(image + off, &zero, slot_sz);
                add_fixup((uint32_t)off, LLBIN_FIXUP_IMPORT, idx,
                          (int64_t)addend);
            }
        }
    }

    /* Process DT_JMPREL table (may be RELA or REL per DT_PLTREL) */
    if (jmprel_addr && pltrelsz) {
        if (pltrel_type == DT_RELA) {
            uint64_t count = pltrelsz / sizeof(Elf_Rela);
            const Elf_Rela *tbl =
                (const Elf_Rela *)(image + jmprel_addr - base_vmaddr);

            printf("  processing DT_JMPREL/RELA (%llu entries)\n",
                   (unsigned long long)count);

            for (uint64_t i = 0; i < count; i++) {
                uint32_t sym_idx = ELF_R_SYM(tbl[i].r_info);
                uint64_t off = tbl[i].r_offset - base_vmaddr;

                if (symtab && dynstr && sym_idx > 0) {
                    const char *name = dynstr + symtab[sym_idx].st_name;
                    uint16_t idx = find_or_add_import_raw(name);
                    Elf_Addr zero = 0;
                    memcpy(image + off, &zero, slot_sz);
                    add_fixup((uint32_t)off, LLBIN_FIXUP_IMPORT, idx,
                              tbl[i].r_addend);
                }
            }
        } else {
            uint64_t count = pltrelsz / sizeof(Elf_Rel);
            const Elf_Rel *tbl =
                (const Elf_Rel *)(image + jmprel_addr - base_vmaddr);

            printf("  processing DT_JMPREL/REL (%llu entries)\n",
                   (unsigned long long)count);

            for (uint64_t i = 0; i < count; i++) {
                uint32_t sym_idx = ELF_R_SYM(tbl[i].r_info);
                uint64_t off = tbl[i].r_offset - base_vmaddr;

                if (symtab && dynstr && sym_idx > 0) {
                    const char *name = dynstr + symtab[sym_idx].st_name;
                    uint16_t idx = find_or_add_import_raw(name);
                    Elf_Addr addend;
                    memcpy(&addend, image + off, slot_sz);
                    Elf_Addr zero = 0;
                    memcpy(image + off, &zero, slot_sz);
                    add_fixup((uint32_t)off, LLBIN_FIXUP_IMPORT, idx,
                              (int64_t)addend);
                }
            }
        }
    }

    #undef IS_RELATIVE
    #undef IS_IMPORT

    return 0;
}

#endif /* __linux__ */

/* ------------------------------------------------------------------ */
/*  Write llbin output                                                */
/* ------------------------------------------------------------------ */

static int write_llbin(const char *path)
{
    struct llbin_header hdr;
    memset(&hdr, 0, sizeof(hdr));

    hdr.magic          = LLBIN_MAGIC;
    hdr.version        = LLBIN_VERSION;
#if defined(__arm64__) || defined(__aarch64__)
    hdr.arch           = CPU_TYPE_ARM64;
#elif defined(__x86_64__)
    hdr.arch           = CPU_TYPE_X86_64;
#elif defined(__i386__)
    hdr.arch           = 0x00000007; /* CPU_TYPE_I386 */
#elif defined(__arm__)
    hdr.arch           = 0x0000000C; /* CPU_TYPE_ARM */
#elif defined(__mips__)
    hdr.arch           = 0x00000008; /* EM_MIPS */
#elif defined(__sparc__)
    hdr.arch           = 0x00000002; /* EM_SPARC */
#else
    hdr.arch           = 0;
#endif
    hdr.entry_off      = entry_off;
    hdr.image_size     = total_size;
    hdr.preferred_base = base_vmaddr;

    hdr.image_off    = (uint32_t)sizeof(hdr);
    hdr.fixup_off    = hdr.image_off + (uint32_t)total_size;
    hdr.fixup_count  = nfixups;
    hdr.import_off   = hdr.fixup_off +
                       nfixups * (uint32_t)sizeof(struct llbin_fixup);
    hdr.import_count = nimports;
    hdr.strings_off  = hdr.import_off +
                       nimports * (uint32_t)sizeof(struct llbin_import);
    hdr.strings_size = strtab_len;

    /* Build segment table (skip __PAGEZERO and zero-vmsize segments) */
    struct llbin_segment llsegs[MAX_SEGS];
    uint32_t llseg_count = 0;
    for (uint32_t i = 0; i < nsegs; i++) {
        if (segs[i].vmsize == 0 || segs[i].vmaddr < base_vmaddr)
            continue;
        llsegs[llseg_count].offset = (uint32_t)(segs[i].vmaddr - base_vmaddr);
        llsegs[llseg_count].size   = (uint32_t)segs[i].vmsize;
        llsegs[llseg_count].prot   = segs[i].initprot;
        llsegs[llseg_count].pad    = 0;
        llseg_count++;
    }
    hdr.seg_count = llseg_count;

    FILE *f = fopen(path, "wb");
    if (!f) { perror(path); return -1; }

    fwrite(&hdr,    sizeof(hdr),                   1,        f);
    fwrite(image,   1,                             (size_t)total_size, f);
    fwrite(fixups,  sizeof(struct llbin_fixup),     nfixups,  f);
    fwrite(imports, sizeof(struct llbin_import),    nimports, f);
    fwrite(strtab,  1,                             strtab_len, f);
    if (llseg_count > 0)
        fwrite(llsegs, sizeof(struct llbin_segment), llseg_count, f);

    fclose(f);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  main                                                              */
/* ------------------------------------------------------------------ */

int main(int argc, char *argv[])
{
    if (argc != 3) {
        fprintf(stderr, "Usage: llpack <input> <output.llbin>\n");
        return 1;
    }

    /* Read input file */
    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror(argv[1]); return 1; }

    fseek(f, 0, SEEK_END);
    long flen = ftell(f);
    if (flen <= 0) die("empty or unreadable input");
    size_t len = (size_t)flen;
    fseek(f, 0, SEEK_SET);

    uint8_t *buf = malloc(len);
    if (!buf) die("out of memory");
    if (fread(buf, 1, len, f) != len) die("short read");
    fclose(f);

    printf("llpack: %s (%zu bytes)\n", argv[1], len);

#ifdef __APPLE__
    /* Extract matching architecture from fat binaries */
    size_t macho_len;
    const uint8_t *macho = extract_arch(buf, len, &macho_len);
    if (!macho) die("cannot extract matching architecture");

    printf("  Mach-O slice: %zu bytes\n", macho_len);

    /* Build flat image from segments */
    if (build_image(macho, macho_len) < 0)
        die("build_image failed");
#endif

#ifdef __linux__
    /* Build flat image from ELF */
    if (build_image_elf(buf, len) < 0)
        die("build_image_elf failed");
#endif

    printf("  base=0x%llx  size=0x%llx  entry=0x%llx\n",
           (unsigned long long)base_vmaddr,
           (unsigned long long)total_size,
           (unsigned long long)entry_off);
    printf("  segments: %u\n", nsegs);
    for (uint32_t i = 0; i < nsegs; i++)
        printf("    [%u] %-16.16s  vmaddr=0x%llx  size=0x%llx\n",
               i, segs[i].name,
               (unsigned long long)segs[i].vmaddr,
               (unsigned long long)segs[i].vmsize);

    /* Extract fixups */
#ifdef __APPLE__
    if (process_fixups(macho, macho_len) < 0)
        die("process_fixups failed");
#endif

#ifdef __linux__
    if (process_fixups_elf(buf, len) < 0)
        die("process_fixups_elf failed");
#endif

    printf("  fixups:  %u (%u rebase, %u import)\n", nfixups,
           nfixups - nimports, nimports);
    printf("  imports: %u\n", nimports);
    for (uint32_t i = 0; i < nimports; i++)
        printf("    [%u] %s\n", i, strtab + imports[i].name_off);

    /* Write output */
    if (write_llbin(argv[2]) < 0)
        die("write_llbin failed");

    uint64_t out_size = (uint64_t)sizeof(struct llbin_header) +
                        total_size +
                        nfixups  * sizeof(struct llbin_fixup) +
                        nimports * sizeof(struct llbin_import) +
                        strtab_len;
    printf("  output: %s (%llu bytes)\n", argv[2], (unsigned long long)out_size);

    free(buf);
    free(image);
    return 0;
}
