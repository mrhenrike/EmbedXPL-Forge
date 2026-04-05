/*
 * macho.c — macOS Mach-O reflective loader
 *
 * Reflective Mach-O loader: parses and loads Mach-O binaries (and the
 * pre-packed llbin format) entirely from memory without writing to disk.
 * Supports both legacy LC_DYLD_INFO_ONLY rebase/bind and the newer
 * LC_DYLD_CHAINED_FIXUPS format.
 *
 * Code execution strategy (in order of preference):
 *   1. Dual-map via mach_vm_remap — two views of the same physical
 *      pages (RW for writing, RX for execution). No entitlements.
 *   2. MAP_JIT + pthread_jit_write_protect_np (arm64).
 *   3. Plain mmap + mprotect (x86_64 / fallback).
 */

#include "libload.h"
#include "llbin.h"

#include <dlfcn.h>
#include <stdio.h>

#ifdef LIBLOAD_DEBUG
  #define LL_DBG(...) fprintf(stderr, __VA_ARGS__)
#else
  #define LL_DBG(...) ((void)0)
#endif
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <crt_externs.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <pthread.h>
#include <libkern/OSCacheControl.h>
#include <sys/mman.h>

/* ------------------------------------------------------------------ */
/*  Chained-fixup structs (may not exist in older SDKs)               */
/* ------------------------------------------------------------------ */

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
#define DYLD_CHAINED_PTR_ARM64E_KERNEL      7
#define DYLD_CHAINED_PTR_ARM64E_USERLAND    12
#define DYLD_CHAINED_PTR_ARM64E_USERLAND24  13

#define DYLD_CHAINED_IMPORT                 1
#define DYLD_CHAINED_IMPORT_ADDEND          2
#define DYLD_CHAINED_IMPORT_ADDEND64        3

#endif /* DYLD_CHAINED_PTR_64 */

#ifndef DYLD_CHAINED_PTR_START_NONE
#define DYLD_CHAINED_PTR_START_NONE  0xFFFF
#endif

/* ------------------------------------------------------------------ */
/*  Constants                                                         */
/* ------------------------------------------------------------------ */

#define LL_MAX_SEGMENTS 32

/* Forward declaration */
struct libload_ctx;
static int ll_dualmap_alloc(struct libload_ctx *ctx, size_t size);

/* ------------------------------------------------------------------ */
/*  Internal types                                                    */
/* ------------------------------------------------------------------ */

struct ll_segment {
    char      name[16];
    uint64_t  vmaddr;
    uint64_t  vmsize;
    uint64_t  fileoff;
    uint64_t  filesize;
    int       initprot;
    int       maxprot;
    uint32_t  nsects;
    /* Offset to first section_64 within the original buffer */
    uint64_t  sect_buf_off;
};

struct libload_ctx {
    void     *base;           /* executable mapping (RX or JIT)     */
    void     *rw_base;        /* writable mapping for double-map    */
    size_t    total_size;     /* size of mapping                    */
    uint64_t  slide;          /* actual - preferred load address    */
    uint64_t  base_vmaddr;    /* lowest vmaddr (excl. __PAGEZERO)   */

    struct ll_segment segs[LL_MAX_SEGMENTS];
    uint32_t  nsegs;

    /* Export trie (points into mapped __LINKEDIT) */
    const uint8_t *exports;
    uint32_t       exports_size;

    /* Entry point (offset from start of __TEXT / image base) */
    uint64_t  entry_off;
    int       has_entry;
    int       use_jit;        /* MAP_JIT was used for allocation    */
    int       use_dualmap;    /* dual-mapped RW+RX                  */
    int       tlv_info_idx;   /* TLV metadata table index, -1=none  */
};

/* ------------------------------------------------------------------ */
/*  LEB128 helpers                                                    */
/* ------------------------------------------------------------------ */

static uint64_t read_uleb128(const uint8_t **p, const uint8_t *end)
{
    uint64_t val = 0;
    unsigned shift = 0;

    while (*p < end)
    {
        uint8_t byte = **p;
        (*p)++;
        val |= (uint64_t)(byte & 0x7F) << shift;

        if ((byte & 0x80) == 0)
            break;

        shift += 7;

        if (shift >= 64)
            break;
    }

    return val;
}

static int64_t read_sleb128(const uint8_t **p, const uint8_t *end)
{
    int64_t val = 0;
    unsigned shift = 0;
    uint8_t byte = 0;

    while (*p < end)
    {
        byte = **p;
        (*p)++;
        val |= (int64_t)(byte & 0x7F) << shift;
        shift += 7;

        if ((byte & 0x80) == 0)
            break;

        if (shift >= 64)
            break;
    }

    if (shift < 64 && (byte & 0x40))
        val |= -(1LL << shift);

    return val;
}

/* ------------------------------------------------------------------ */
/*  Fat binary extraction                                             */
/* ------------------------------------------------------------------ */

static const uint8_t *ll_extract_arch(const uint8_t *buf, size_t len,
                                      size_t *out_len)
{
    uint32_t magic;

    if (len < sizeof(uint32_t))
        return NULL;

    memcpy(&magic, buf, sizeof(magic));

    if (magic == FAT_MAGIC || magic == FAT_CIGAM)
    {
        struct fat_header fh;
        uint32_t narch, i;

        if (len < sizeof(fh))
            return NULL;

        memcpy(&fh, buf, sizeof(fh));
        narch = OSSwapBigToHostInt32(fh.nfat_arch);

        if (len < sizeof(fh) + narch * sizeof(struct fat_arch))
            return NULL;

        for (i = 0; i < narch; i++)
        {
            struct fat_arch fa;
            memcpy(&fa, buf + sizeof(fh) + i * sizeof(fa), sizeof(fa));

            cpu_type_t cputype = (cpu_type_t)OSSwapBigToHostInt32(fa.cputype);

#if defined(__x86_64__)
            if (cputype == CPU_TYPE_X86_64)
#elif defined(__arm64__) || defined(__aarch64__)
            if (cputype == CPU_TYPE_ARM64)
#else
            if (0)
#endif
            {
                uint32_t offset = OSSwapBigToHostInt32(fa.offset);
                uint32_t size   = OSSwapBigToHostInt32(fa.size);

                if ((uint64_t)offset + size > len)
                    return NULL;

                *out_len = size;
                return buf + offset;
            }
        }

        return NULL; /* no matching architecture */
    }

    /* Not a fat binary — return as-is */
    *out_len = len;
    return buf;
}

/* ------------------------------------------------------------------ */
/*  Mach-O validation                                                 */
/* ------------------------------------------------------------------ */

static int ll_validate(const uint8_t *buf, size_t len)
{
    if (len < sizeof(struct mach_header_64))
        return -1;

    const struct mach_header_64 *hdr = (const struct mach_header_64 *)buf;

    if (hdr->magic != MH_MAGIC_64)
        return -1;

    if (hdr->filetype != MH_DYLIB &&
        hdr->filetype != MH_BUNDLE &&
        hdr->filetype != MH_EXECUTE)
        return -1;

    return 0;
}

/* ------------------------------------------------------------------ */
/*  Segment mapping                                                   */
/* ------------------------------------------------------------------ */

static int ll_map_segments(struct libload_ctx *ctx,
                           const uint8_t *buf, size_t len)
{
    const struct mach_header_64 *hdr = (const struct mach_header_64 *)buf;
    const uint8_t *lc = buf + sizeof(struct mach_header_64);
    uint64_t lo = UINT64_MAX, hi = 0;
    uint32_t i;

    LL_DBG("[libload] map_segments: buf=%p len=%zu magic=0x%x ncmds=%u sizeofcmds=%u\n",
           (void *)buf, len, hdr->magic, hdr->ncmds, hdr->sizeofcmds);

    /* First pass: collect segments, find address range */
    ctx->nsegs = 0;

    for (i = 0; i < hdr->ncmds; i++)
    {
        const struct load_command *cmd = (const struct load_command *)lc;

        LL_DBG("[libload]   lc[%u] cmd=0x%x cmdsize=%u\n",
               i, cmd->cmd, cmd->cmdsize);

        if (cmd->cmd == LC_SEGMENT_64)
        {
            const struct segment_command_64 *seg =
                (const struct segment_command_64 *)lc;

            if (ctx->nsegs >= LL_MAX_SEGMENTS)
                return -1;

            struct ll_segment *s = &ctx->segs[ctx->nsegs];
            memcpy(s->name, seg->segname, 16);
            s->vmaddr   = seg->vmaddr;
            s->vmsize   = seg->vmsize;
            s->fileoff  = seg->fileoff;
            s->filesize = seg->filesize;
            s->initprot = seg->initprot;
            s->maxprot  = seg->maxprot;
            s->nsects   = seg->nsects;
            s->sect_buf_off = (uint64_t)(lc - buf) +
                              sizeof(struct segment_command_64);

            ctx->nsegs++;

            /* Skip __PAGEZERO */
            if (seg->vmsize == 0 || seg->filesize == 0)
            {
                if (strcmp(seg->segname, "__PAGEZERO") == 0)
                {
                    lc += cmd->cmdsize;
                    continue;
                }
            }

            if (seg->vmaddr < lo)
                lo = seg->vmaddr;
            if (seg->vmaddr + seg->vmsize > hi)
                hi = seg->vmaddr + seg->vmsize;
        }

        lc += cmd->cmdsize;
    }

    if (lo >= hi)
    {
        LL_DBG("[libload] lo >= hi: lo=0x%llx hi=0x%llx\n",
               (unsigned long long)lo, (unsigned long long)hi);
        return -1;
    }

    ctx->base_vmaddr = lo;
    ctx->total_size  = (size_t)(hi - lo);

    LL_DBG("[libload] base_vmaddr=0x%llx total_size=0x%zx (%zu)\n",
           (unsigned long long)lo, ctx->total_size, ctx->total_size);

    /*
     * Allocation strategy (same as llbin path):
     *  1. Dual-map: RW + RX views of same physical pages
     *  2. MAP_JIT: single mapping with W^X toggling (arm64)
     *  3. Plain mmap + mprotect (x86_64 / fallback)
     */
    int allocated = 0;

    if (!allocated && ll_dualmap_alloc(ctx, ctx->total_size) == 0)
        allocated = 1;

#if defined(__arm64__) || defined(__aarch64__)
    if (!allocated) {
        ctx->base = mmap(NULL, ctx->total_size,
                         PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_ANON | MAP_PRIVATE | MAP_JIT, -1, 0);
        if (ctx->base != MAP_FAILED) {
            ctx->use_jit = 1;
            pthread_jit_write_protect_np(0);
            allocated = 1;
        }
    }
#endif

    if (!allocated) {
        ctx->base = mmap(NULL, ctx->total_size,
                         PROT_READ | PROT_WRITE,
                         MAP_ANON | MAP_PRIVATE, -1, 0);
        if (ctx->base != MAP_FAILED)
            allocated = 1;
    }

    if (!allocated)
    {
        ctx->base = NULL;
        return -1;
    }

    ctx->slide = (uint64_t)ctx->base - lo;

    /* Write through the writable view */
    void *write_base = ctx->use_dualmap ? ctx->rw_base : ctx->base;

    /* Copy segment data */
    for (i = 0; i < ctx->nsegs; i++)
    {
        struct ll_segment *s = &ctx->segs[i];

        if (s->filesize == 0)
        {
            LL_DBG("[libload]   seg[%u] %.16s: skip (filesize=0)\n", i, s->name);
            continue;
        }

        if (s->vmaddr < ctx->base_vmaddr)
        {
            LL_DBG("[libload]   seg[%u] %.16s: skip (vmaddr=0x%llx < base=0x%llx)\n",
                   i, s->name, (unsigned long long)s->vmaddr,
                   (unsigned long long)ctx->base_vmaddr);
            continue; /* __PAGEZERO or invalid */
        }

        if (s->fileoff + s->filesize > len)
        {
            LL_DBG("[libload]   seg[%u] %.16s: FAIL fileoff=0x%llx + filesize=0x%llx = 0x%llx > len=0x%zx\n",
                   i, s->name,
                   (unsigned long long)s->fileoff,
                   (unsigned long long)s->filesize,
                   (unsigned long long)(s->fileoff + s->filesize), len);
            return -1;
        }

        uint64_t dest_off = s->vmaddr - ctx->base_vmaddr;
        LL_DBG("[libload]   seg[%u] %.16s: copy 0x%llx bytes to base+0x%llx\n",
               i, s->name, (unsigned long long)s->filesize,
               (unsigned long long)dest_off);
        memcpy((uint8_t *)write_base + dest_off,
               buf + s->fileoff, (size_t)s->filesize);
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/*  LINKEDIT helpers                                                   */
/* ------------------------------------------------------------------ */

/*
 * Translate a file offset within __LINKEDIT to a pointer in the
 * mapped image.  linkedit_fileoff / linkedit_vmaddr come from the
 * LC_SEGMENT_64(__LINKEDIT) command.
 */
/* Return the writable base address: rw_base for dual-map, base otherwise */
static inline void *ll_write_base(struct libload_ctx *ctx)
{
    return ctx->use_dualmap ? ctx->rw_base : ctx->base;
}

static const uint8_t *ll_linkedit_ptr(struct libload_ctx *ctx,
                                      uint64_t linkedit_vmaddr,
                                      uint64_t linkedit_fileoff,
                                      uint64_t file_offset)
{
    uint64_t delta = file_offset - linkedit_fileoff;
    return (const uint8_t *)ll_write_base(ctx) +
           (linkedit_vmaddr - ctx->base_vmaddr) + delta;
}

static int ll_find_linkedit(struct libload_ctx *ctx,
                            uint64_t *vmaddr, uint64_t *fileoff)
{
    uint32_t i;

    for (i = 0; i < ctx->nsegs; i++)
    {
        if (strncmp(ctx->segs[i].name, "__LINKEDIT", 16) == 0)
        {
            *vmaddr  = ctx->segs[i].vmaddr;
            *fileoff = ctx->segs[i].fileoff;
            return 0;
        }
    }

    return -1;
}

/* ------------------------------------------------------------------ */
/*  Segment index -> address helper for rebase/bind                   */
/* ------------------------------------------------------------------ */

static uint8_t *ll_seg_addr(struct libload_ctx *ctx, uint32_t seg_idx)
{
    if (seg_idx >= ctx->nsegs)
        return NULL;

    return (uint8_t *)ll_write_base(ctx) +
           (ctx->segs[seg_idx].vmaddr - ctx->base_vmaddr);
}

/* ------------------------------------------------------------------ */
/*  Rebase processing (LC_DYLD_INFO_ONLY)                             */
/* ------------------------------------------------------------------ */

static int ll_rebase(struct libload_ctx *ctx,
                     const uint8_t *opcodes, size_t size)
{
    const uint8_t *p = opcodes;
    const uint8_t *end = opcodes + size;
    uint32_t seg_idx = 0;
    uint64_t seg_off = 0;
    int done = 0;

    while (p < end && !done)
    {
        uint8_t byte = *p++;
        uint8_t opcode = byte & REBASE_OPCODE_MASK;
        uint8_t imm    = byte & REBASE_IMMEDIATE_MASK;

        switch (opcode)
        {
        case REBASE_OPCODE_DONE:
            done = 1;
            break;

        case REBASE_OPCODE_SET_TYPE_IMM:
            /* type = imm; we don't need the type */
            (void)imm;
            break;

        case REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
            seg_idx = imm;
            seg_off = read_uleb128(&p, end);
            break;

        case REBASE_OPCODE_ADD_ADDR_ULEB:
            seg_off += read_uleb128(&p, end);
            break;

        case REBASE_OPCODE_ADD_ADDR_IMM_SCALED:
            seg_off += (uint64_t)imm * sizeof(uint64_t);
            break;

        case REBASE_OPCODE_DO_REBASE_IMM_TIMES:
        {
            uint8_t *base = ll_seg_addr(ctx, seg_idx);
            if (!base) return -1;

            for (uint8_t j = 0; j < imm; j++)
            {
                uint64_t *slot = (uint64_t *)(base + seg_off);
                *slot += ctx->slide;
                seg_off += sizeof(uint64_t);
            }
            break;
        }

        case REBASE_OPCODE_DO_REBASE_ULEB_TIMES:
        {
            uint64_t count = read_uleb128(&p, end);
            uint8_t *base = ll_seg_addr(ctx, seg_idx);
            if (!base) return -1;

            for (uint64_t j = 0; j < count; j++)
            {
                uint64_t *slot = (uint64_t *)(base + seg_off);
                *slot += ctx->slide;
                seg_off += sizeof(uint64_t);
            }
            break;
        }

        case REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB:
        {
            uint64_t skip = read_uleb128(&p, end);
            uint8_t *base = ll_seg_addr(ctx, seg_idx);
            if (!base) return -1;

            uint64_t *slot = (uint64_t *)(base + seg_off);
            *slot += ctx->slide;
            seg_off += sizeof(uint64_t) + skip;
            break;
        }

        case REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB:
        {
            uint64_t count = read_uleb128(&p, end);
            uint64_t skip  = read_uleb128(&p, end);
            uint8_t *base = ll_seg_addr(ctx, seg_idx);
            if (!base) return -1;

            for (uint64_t j = 0; j < count; j++)
            {
                uint64_t *slot = (uint64_t *)(base + seg_off);
                *slot += ctx->slide;
                seg_off += sizeof(uint64_t) + skip;
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
/*  Bind processing (LC_DYLD_INFO_ONLY) — shared by bind & lazy bind  */
/* ------------------------------------------------------------------ */

static int ll_bind_opcodes(struct libload_ctx *ctx,
                           const uint8_t *opcodes, size_t size)
{
    const uint8_t *p = opcodes;
    const uint8_t *end = opcodes + size;
    const char *sym_name = NULL;
    uint32_t seg_idx = 0;
    uint64_t seg_off = 0;
    int64_t  addend  = 0;
    int done = 0;

    while (p < end && !done)
    {
        uint8_t byte = *p++;
        uint8_t opcode = byte & BIND_OPCODE_MASK;
        uint8_t imm    = byte & BIND_IMMEDIATE_MASK;

        switch (opcode)
        {
        case BIND_OPCODE_DONE:
            done = 1;
            break;

        case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
            (void)imm;
            break;

        case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
            read_uleb128(&p, end);
            break;

        case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
            break;

        case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
            sym_name = (const char *)p;
            while (p < end && *p) p++;
            if (p < end) p++; /* skip NUL */
            break;

        case BIND_OPCODE_SET_TYPE_IMM:
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

        case BIND_OPCODE_DO_BIND:
        {
            if (!sym_name) return -1;

            /* Skip leading underscore for dlsym lookup */
            const char *lookup = sym_name;
            if (lookup[0] == '_') lookup++;

            void *addr = dlsym(RTLD_DEFAULT, lookup);
            uint8_t *base = ll_seg_addr(ctx, seg_idx);
            if (!base) return -1;

            uint64_t *slot = (uint64_t *)(base + seg_off);
            *slot = (uint64_t)addr + addend;
            seg_off += sizeof(uint64_t);
            break;
        }

        case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
        {
            if (!sym_name) return -1;
            const char *lookup = sym_name;
            if (lookup[0] == '_') lookup++;

            void *addr = dlsym(RTLD_DEFAULT, lookup);
            uint8_t *base = ll_seg_addr(ctx, seg_idx);
            if (!base) return -1;

            uint64_t *slot = (uint64_t *)(base + seg_off);
            *slot = (uint64_t)addr + addend;
            seg_off += sizeof(uint64_t) + read_uleb128(&p, end);
            break;
        }

        case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
        {
            if (!sym_name) return -1;
            const char *lookup = sym_name;
            if (lookup[0] == '_') lookup++;

            void *addr = dlsym(RTLD_DEFAULT, lookup);
            uint8_t *base = ll_seg_addr(ctx, seg_idx);
            if (!base) return -1;

            uint64_t *slot = (uint64_t *)(base + seg_off);
            *slot = (uint64_t)addr + addend;
            seg_off += sizeof(uint64_t) + (uint64_t)imm * sizeof(uint64_t);
            break;
        }

        case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
        {
            uint64_t count = read_uleb128(&p, end);
            uint64_t skip  = read_uleb128(&p, end);
            if (!sym_name) return -1;
            const char *lookup = sym_name;
            if (lookup[0] == '_') lookup++;

            void *addr = dlsym(RTLD_DEFAULT, lookup);
            uint8_t *base = ll_seg_addr(ctx, seg_idx);
            if (!base) return -1;

            for (uint64_t j = 0; j < count; j++)
            {
                uint64_t *slot = (uint64_t *)(base + seg_off);
                *slot = (uint64_t)addr + addend;
                seg_off += sizeof(uint64_t) + skip;
            }
            break;
        }

        default:
            return -1;
        }
    }

    return 0;
}

/* Lazy bind stream uses BIND_OPCODE_DONE to separate entries */
static int ll_lazy_bind(struct libload_ctx *ctx,
                        const uint8_t *opcodes, size_t size)
{
    const uint8_t *p = opcodes;
    const uint8_t *end = opcodes + size;
    const char *sym_name = NULL;
    uint32_t seg_idx = 0;
    uint64_t seg_off = 0;
    int64_t  addend  = 0;

    while (p < end)
    {
        uint8_t byte = *p++;
        uint8_t opcode = byte & BIND_OPCODE_MASK;
        uint8_t imm    = byte & BIND_IMMEDIATE_MASK;

        switch (opcode)
        {
        case BIND_OPCODE_DONE:
            /* In lazy bind, DONE separates entries, not ends stream */
            break;

        case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
        case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
        case BIND_OPCODE_SET_TYPE_IMM:
            (void)imm;
            break;

        case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
            read_uleb128(&p, end);
            break;

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

        case BIND_OPCODE_DO_BIND:
        {
            if (!sym_name) return -1;
            const char *lookup = sym_name;
            if (lookup[0] == '_') lookup++;

            void *addr = dlsym(RTLD_DEFAULT, lookup);
            uint8_t *base = ll_seg_addr(ctx, seg_idx);
            if (!base) return -1;

            uint64_t *slot = (uint64_t *)(base + seg_off);
            *slot = (uint64_t)addr + addend;
            seg_off += sizeof(uint64_t);
            break;
        }

        default:
            break; /* ignore unknown in lazy bind */
        }
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/*  Chained fixups (LC_DYLD_CHAINED_FIXUPS)                           */
/* ------------------------------------------------------------------ */

static int ll_chained_fixups(struct libload_ctx *ctx,
                             const uint8_t *buf,
                             uint64_t linkedit_vmaddr,
                             uint64_t linkedit_fileoff,
                             uint32_t dataoff, uint32_t datasize)
{
    const uint8_t *fixup_base = ll_linkedit_ptr(ctx, linkedit_vmaddr,
                                                linkedit_fileoff, dataoff);
    (void)datasize;

    const struct dyld_chained_fixups_header *hdr =
        (const struct dyld_chained_fixups_header *)fixup_base;

    const struct dyld_chained_starts_in_image *starts =
        (const struct dyld_chained_starts_in_image *)
        (fixup_base + hdr->starts_offset);

    /* Build imports table */
    const uint8_t *imports_base = fixup_base + hdr->imports_offset;
    const char *symbols_base = (const char *)fixup_base + hdr->symbols_offset;

    (void)buf;

    LL_DBG("[libload] chained: seg_count=%u imports_count=%u imports_format=%u\n",
           starts->seg_count, hdr->imports_count, hdr->imports_format);

    for (uint32_t seg_i = 0; seg_i < starts->seg_count; seg_i++)
    {
        LL_DBG("[libload] chained seg[%u] offset=%u\n",
               seg_i, starts->seg_info_offset[seg_i]);

        if (starts->seg_info_offset[seg_i] == 0)
            continue;

        const struct dyld_chained_starts_in_segment *seg_starts =
            (const struct dyld_chained_starts_in_segment *)
            ((const uint8_t *)starts + starts->seg_info_offset[seg_i]);

        if (seg_i >= ctx->nsegs)
            continue;

        LL_DBG("[libload]   seg %.16s vmaddr=0x%llx base_vmaddr=0x%llx\n",
               ctx->segs[seg_i].name,
               (unsigned long long)ctx->segs[seg_i].vmaddr,
               (unsigned long long)ctx->base_vmaddr);

        if (ctx->segs[seg_i].vmaddr < ctx->base_vmaddr)
        {
            LL_DBG("[libload]   skipping (vmaddr < base)\n");
            continue;
        }

        LL_DBG("[libload]   ptr_fmt=%u page_size=%u seg_off=0x%llx page_count=%u\n",
               seg_starts->pointer_format, seg_starts->page_size,
               (unsigned long long)seg_starts->segment_offset,
               seg_starts->page_count);

        uint16_t ptr_fmt = seg_starts->pointer_format;
        uint32_t stride;

        switch (ptr_fmt)
        {
        case DYLD_CHAINED_PTR_64:
        case DYLD_CHAINED_PTR_64_OFFSET:
            stride = 4;
            break;
        case DYLD_CHAINED_PTR_ARM64E:
        case DYLD_CHAINED_PTR_ARM64E_USERLAND:
        case DYLD_CHAINED_PTR_ARM64E_USERLAND24:
            stride = 8;
            break;
        default:
            stride = 4;
            break;
        }

        for (uint32_t page_i = 0; page_i < seg_starts->page_count; page_i++)
        {
            uint16_t page_start = seg_starts->page_start[page_i];

            if (page_start == DYLD_CHAINED_PTR_START_NONE)
                continue;

            uint64_t page_off = (uint64_t)page_i * seg_starts->page_size;
            uint8_t *chain = (uint8_t *)ll_write_base(ctx) +
                             (uint64_t)seg_starts->segment_offset +
                             page_off + page_start;

            while (1)
            {
                uint64_t raw;
                memcpy(&raw, chain, sizeof(raw));

                int is_bind = (raw >> 63) & 1;
                uint32_t next = 0;

                if (ptr_fmt == DYLD_CHAINED_PTR_64 ||
                    ptr_fmt == DYLD_CHAINED_PTR_64_OFFSET)
                {
                    next = (uint32_t)((raw >> 51) & 0xFFF);

                    if (is_bind)
                    {
                        uint32_t ordinal = (uint32_t)(raw & 0xFFFFFF);
                        int32_t  add     = (int32_t)((raw >> 24) & 0xFF);

                        /* Sign-extend 8-bit addend */
                        if (add & 0x80)
                            add |= (int32_t)0xFFFFFF00;

                        const char *sym = NULL;
                        int32_t import_addend = 0;

                        if (hdr->imports_format == DYLD_CHAINED_IMPORT)
                        {
                            const struct dyld_chained_import *imp =
                                (const struct dyld_chained_import *)imports_base
                                + ordinal;
                            sym = symbols_base + imp->name_offset;
                        }
                        else if (hdr->imports_format == DYLD_CHAINED_IMPORT_ADDEND)
                        {
                            const struct dyld_chained_import_addend *imp =
                                (const struct dyld_chained_import_addend *)
                                imports_base + ordinal;
                            sym = symbols_base + imp->name_offset;
                            import_addend = imp->addend;
                        }

                        if (sym)
                        {
                            const char *lookup = sym;
                            if (lookup[0] == '_') lookup++;

                            void *resolved = dlsym(RTLD_DEFAULT, lookup);
                            uint64_t value = (uint64_t)resolved +
                                             add + import_addend;
                            memcpy(chain, &value, sizeof(value));
                        }
                    }
                    else
                    {
                        /* Rebase */
                        uint64_t target = raw & 0xFFFFFFFFFULL;  /* 36 bits */
                        uint8_t  high8  = (raw >> 36) & 0xFF;
                        uint64_t value;

                        if (ptr_fmt == DYLD_CHAINED_PTR_64_OFFSET)
                            value = (uint64_t)ctx->base + target;
                        else
                            value = target + ctx->slide;

                        value |= (uint64_t)high8 << 56;
                        memcpy(chain, &value, sizeof(value));
                    }
                }
                else if (ptr_fmt == DYLD_CHAINED_PTR_ARM64E ||
                         ptr_fmt == DYLD_CHAINED_PTR_ARM64E_USERLAND ||
                         ptr_fmt == DYLD_CHAINED_PTR_ARM64E_USERLAND24)
                {
                    int is_auth = (raw >> 63) & 1;

                    /* For non-auth pointers: combine bind bit check */
                    if (!is_auth)
                        is_bind = (raw >> 62) & 1;
                    else
                        is_bind = (raw >> 62) & 1;

                    if (ptr_fmt == DYLD_CHAINED_PTR_ARM64E)
                        next = (uint32_t)((raw >> 52) & 0x7FF);
                    else
                        next = (uint32_t)((raw >> 52) & 0x7FF);

                    if (is_bind)
                    {
                        uint32_t ordinal;

                        if (ptr_fmt == DYLD_CHAINED_PTR_ARM64E_USERLAND24)
                            ordinal = (uint32_t)(raw & 0xFFFFFF);
                        else
                            ordinal = (uint32_t)(raw & 0xFFFF);

                        const char *sym = NULL;

                        if (hdr->imports_format == DYLD_CHAINED_IMPORT)
                        {
                            const struct dyld_chained_import *imp =
                                (const struct dyld_chained_import *)imports_base
                                + ordinal;
                            sym = symbols_base + imp->name_offset;
                        }
                        else if (hdr->imports_format == DYLD_CHAINED_IMPORT_ADDEND)
                        {
                            const struct dyld_chained_import_addend *imp =
                                (const struct dyld_chained_import_addend *)
                                imports_base + ordinal;
                            sym = symbols_base + imp->name_offset;
                        }

                        if (sym)
                        {
                            const char *lookup = sym;
                            if (lookup[0] == '_') lookup++;
                            void *resolved = dlsym(RTLD_DEFAULT, lookup);
                            uint64_t value = (uint64_t)resolved;
                            memcpy(chain, &value, sizeof(value));
                        }
                    }
                    else
                    {
                        uint64_t target;
                        uint8_t  high8 = 0;

                        if (is_auth)
                        {
                            target = raw & 0xFFFFFFFF; /* 32-bit target */
                        }
                        else
                        {
                            target = raw & 0x7FFFFFFFFULL; /* 43 bits */
                            high8  = (raw >> 43) & 0xFF;
                        }

                        uint64_t value;
                        if (ptr_fmt == DYLD_CHAINED_PTR_ARM64E)
                            value = target + ctx->slide;
                        else
                            value = (uint64_t)ctx->base + target;

                        if (!is_auth)
                            value |= (uint64_t)high8 << 56;

                        memcpy(chain, &value, sizeof(value));
                    }
                }

                if (next == 0)
                    break;

                chain += next * stride;
            }
        }
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/*  Memory protection                                                  */
/* ------------------------------------------------------------------ */

static int ll_protect(struct libload_ctx *ctx)
{
    if (ctx->use_dualmap)
    {
        /*
         * The entire base view was initially set to RX.
         * Now apply per-segment protections so that writable
         * segments (__DATA, __DATA_CONST) are accessible at runtime.
         */
        for (uint32_t i = 0; i < ctx->nsegs; i++)
        {
            struct ll_segment *s = &ctx->segs[i];
            if (s->vmsize == 0 || s->vmaddr < ctx->base_vmaddr)
                continue;

            int prot = 0;
            if (s->initprot & VM_PROT_READ)    prot |= PROT_READ;
            if (s->initprot & VM_PROT_WRITE)   prot |= PROT_WRITE;
            if (s->initprot & VM_PROT_EXECUTE) prot |= PROT_EXEC;

            uint64_t off = s->vmaddr - ctx->base_vmaddr;
            void *addr   = (uint8_t *)ctx->base + off;
            size_t sz    = (s->vmsize + getpagesize() - 1) & ~(getpagesize() - 1);

            int rc = mprotect(addr, sz, prot);
            LL_DBG("[libload] protect seg[%u] %.16s: addr=%p sz=0x%zx prot=%d rc=%d\n",
                   i, s->name, addr, sz, prot, rc);
            (void)rc;
        }
        sys_icache_invalidate(ctx->base, ctx->total_size);
        return 0;
    }

#if defined(__arm64__) || defined(__aarch64__)
    if (ctx->use_jit)
    {
        /* Switch all MAP_JIT pages from W to X */
        pthread_jit_write_protect_np(1);
        sys_icache_invalidate(ctx->base, ctx->total_size);
        return 0;
    }
#endif

    for (uint32_t i = 0; i < ctx->nsegs; i++)
    {
        struct ll_segment *s = &ctx->segs[i];

        if (s->vmsize == 0 || s->vmaddr < ctx->base_vmaddr)
            continue;

        uint64_t off = s->vmaddr - ctx->base_vmaddr;
        void *addr   = (uint8_t *)ctx->base + off;

        size_t page_size = (size_t)getpagesize();
        size_t size = (s->vmsize + page_size - 1) & ~(page_size - 1);
        if (size == 0)
            continue;

        int prot = 0;
        if (s->initprot & VM_PROT_READ)    prot |= PROT_READ;
        if (s->initprot & VM_PROT_WRITE)   prot |= PROT_WRITE;
        if (s->initprot & VM_PROT_EXECUTE) prot |= PROT_EXEC;

        mprotect(addr, size, prot);
    }

    /* Flush instruction cache */
    sys_icache_invalidate(ctx->base, ctx->total_size);

    return 0;
}

/* ------------------------------------------------------------------ */
/*  Thread-Local Variables (TLV)                                       */
/* ------------------------------------------------------------------ */

struct ll_tlv_descriptor {
    void *(*thunk)(struct ll_tlv_descriptor *);
    unsigned long key;
    unsigned long offset;
};

struct ll_tlv_info {
    pthread_key_t key;
    void         *template_data;
    size_t        template_size;
    size_t        total_size;
    int           in_use;
};

#define LL_MAX_TLV_IMAGES 16
static struct ll_tlv_info ll_tlv_table[LL_MAX_TLV_IMAGES];
static pthread_mutex_t ll_tlv_lock = PTHREAD_MUTEX_INITIALIZER;

static void ll_tlv_destroy(void *data)
{
    free(data);
}

static void *ll_tlv_get_addr(struct ll_tlv_descriptor *desc)
{
    void *data = pthread_getspecific((pthread_key_t)desc->key);

    if (__builtin_expect(data != NULL, 1))
        return (char *)data + desc->offset;

    /* First access on this thread — find metadata and allocate */
    struct ll_tlv_info *info = NULL;

    pthread_mutex_lock(&ll_tlv_lock);
    for (int i = 0; i < LL_MAX_TLV_IMAGES; i++)
    {
        if (ll_tlv_table[i].in_use &&
            ll_tlv_table[i].key == (pthread_key_t)desc->key)
        {
            info = &ll_tlv_table[i];
            break;
        }
    }
    pthread_mutex_unlock(&ll_tlv_lock);

    if (!info || info->total_size == 0)
        return NULL;

    data = calloc(1, info->total_size);
    if (!data)
        return NULL;

    if (info->template_data && info->template_size > 0)
        memcpy(data, info->template_data, info->template_size);

    pthread_setspecific((pthread_key_t)desc->key, data);
    return (char *)data + desc->offset;
}

static void ll_setup_tlv(struct libload_ctx *ctx)
{
    const struct mach_header_64 *hdr =
        (const struct mach_header_64 *)ctx->base;

    if (hdr->magic != MH_MAGIC_64)
        return;

    const uint8_t *lc = (const uint8_t *)ctx->base + sizeof(*hdr);

    /* Find TLV-related sections */
    const struct section_64 *thread_vars_sect = NULL;
    const struct section_64 *thread_data_sect = NULL;
    const struct section_64 *thread_bss_sect  = NULL;

    for (uint32_t i = 0; i < hdr->ncmds; i++)
    {
        const struct load_command *cmd = (const struct load_command *)lc;

        if (cmd->cmd == LC_SEGMENT_64)
        {
            const struct segment_command_64 *seg =
                (const struct segment_command_64 *)lc;
            const struct section_64 *sects =
                (const struct section_64 *)(lc + sizeof(*seg));

            for (uint32_t j = 0; j < seg->nsects; j++)
            {
                if (strncmp(sects[j].sectname, "__thread_vars", 16) == 0)
                    thread_vars_sect = &sects[j];
                else if (strncmp(sects[j].sectname, "__thread_data", 16) == 0)
                    thread_data_sect = &sects[j];
                else if (strncmp(sects[j].sectname, "__thread_bss", 16) == 0)
                    thread_bss_sect = &sects[j];
            }
        }

        lc += cmd->cmdsize;
    }

    if (!thread_vars_sect)
        return;

    size_t template_size = thread_data_sect ? thread_data_sect->size : 0;
    size_t bss_size      = thread_bss_sect  ? thread_bss_sect->size  : 0;
    size_t total_size    = template_size + bss_size;

    if (total_size == 0)
        return;

    /* Allocate a pthread key for this image */
    pthread_key_t key;
    if (pthread_key_create(&key, ll_tlv_destroy) != 0)
        return;

    /* Copy template data (already rebased) */
    void *template_copy = NULL;
    if (template_size > 0)
    {
        template_copy = malloc(template_size);
        if (!template_copy)
        {
            pthread_key_delete(key);
            return;
        }
        uintptr_t tdata_addr = thread_data_sect->addr + ctx->slide;
        memcpy(template_copy, (void *)tdata_addr, template_size);
    }

    /* Register metadata in the global table */
    int idx = -1;
    pthread_mutex_lock(&ll_tlv_lock);
    for (int i = 0; i < LL_MAX_TLV_IMAGES; i++)
    {
        if (!ll_tlv_table[i].in_use)
        {
            ll_tlv_table[i].key           = key;
            ll_tlv_table[i].template_data = template_copy;
            ll_tlv_table[i].template_size = template_size;
            ll_tlv_table[i].total_size    = total_size;
            ll_tlv_table[i].in_use        = 1;
            idx = i;
            break;
        }
    }
    pthread_mutex_unlock(&ll_tlv_lock);

    if (idx < 0)
    {
        free(template_copy);
        pthread_key_delete(key);
        return;
    }

    ctx->tlv_info_idx = idx;

    LL_DBG("[libload] TLV setup: key=%lu template=%zu bss=%zu total=%zu\n",
           (unsigned long)key, template_size, bss_size, total_size);

    /* Patch descriptors: need write access to __DATA */
    if (ctx->use_jit)
        pthread_jit_write_protect_np(0);

    size_t nvars = thread_vars_sect->size / sizeof(struct ll_tlv_descriptor);
    uintptr_t vars_addr = thread_vars_sect->addr + ctx->slide;
    struct ll_tlv_descriptor *descs = (struct ll_tlv_descriptor *)vars_addr;

    for (size_t i = 0; i < nvars; i++)
    {
        descs[i].thunk = ll_tlv_get_addr;
        descs[i].key   = (unsigned long)key;
        /* offset is already set correctly by the linker */
    }

    if (ctx->use_jit)
    {
        pthread_jit_write_protect_np(1);
        sys_icache_invalidate(ctx->base, ctx->total_size);
    }

    LL_DBG("[libload] TLV: patched %zu descriptors\n", nvars);
}

static void ll_cleanup_tlv(struct libload_ctx *ctx)
{
    if (ctx->tlv_info_idx < 0)
        return;

    pthread_mutex_lock(&ll_tlv_lock);
    struct ll_tlv_info *info = &ll_tlv_table[ctx->tlv_info_idx];
    if (info->in_use)
    {
        pthread_key_delete(info->key);
        free(info->template_data);
        info->template_data = NULL;
        info->in_use = 0;
    }
    pthread_mutex_unlock(&ll_tlv_lock);

    ctx->tlv_info_idx = -1;
}

/* ------------------------------------------------------------------ */
/*  ObjC runtime registration                                         */
/* ------------------------------------------------------------------ */

/*
 * Notify the Objective-C runtime about a reflectively loaded image.
 *
 * When dyld loads a Mach-O, it calls _objc_map_images() so the runtime
 * scans __objc_classlist, __objc_selrefs, __objc_catlist, etc. and
 * registers every class, selector, category and protocol.  Without this
 * call, classes defined in the loaded binary are invisible to the
 * runtime (@interface / @implementation won't work, message dispatch
 * can't find them, +load never runs).
 *
 * After map_images, _objc_load_image() triggers +load methods.
 *
 * Both symbols are private but exported from libobjc.A.dylib.
 * If they're not present (hypothetical stripped environment), the
 * loader silently continues — ObjC just won't work in that image.
 */

typedef void (*ll_objc_map_images_fn)(unsigned count,
                                      const char * const paths[],
                                      const struct mach_header * const mhdrs[]);

static void ll_register_objc(struct libload_ctx *ctx)
{
    /*
     * Quick check: does this image contain ObjC metadata?
     * Look for any section in __DATA/__DATA_CONST that starts with
     * "__objc_".  Skip the dlsym + runtime calls for pure-C images.
     */
    const struct mach_header_64 *hdr =
        (const struct mach_header_64 *)ctx->base;

    if (hdr->magic != MH_MAGIC_64)
        return;

    const uint8_t *lc = (const uint8_t *)ctx->base + sizeof(*hdr);
    int has_objc = 0;

    for (uint32_t i = 0; i < hdr->ncmds && !has_objc; i++) {
        const struct load_command *cmd = (const struct load_command *)lc;

        if (cmd->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg =
                (const struct segment_command_64 *)lc;
            const struct section_64 *sects =
                (const struct section_64 *)(lc + sizeof(*seg));

            for (uint32_t j = 0; j < seg->nsects; j++) {
                if (strncmp(sects[j].sectname, "__objc_", 7) == 0) {
                    has_objc = 1;
                    break;
                }
            }
        }

        lc += cmd->cmdsize;
    }

    if (!has_objc)
        return;

    ll_objc_map_images_fn map_fn =
        (ll_objc_map_images_fn)dlsym(RTLD_DEFAULT, "_objc_map_images");

    if (!map_fn) {
        LL_DBG("[libload] _objc_map_images not found, skipping ObjC registration\n");
        return;
    }

    LL_DBG("[libload] registering ObjC metadata with runtime...\n");

    /*
     * MAP_JIT mode: the entire allocation is RX after protect.
     * _objc_map_images needs to write __DATA sections (isa fixup,
     * selector uniquing, etc.), so temporarily flip to writable.
     */
    if (ctx->use_jit)
        pthread_jit_write_protect_np(0);

    const char *path = "libload-reflective";
    const struct mach_header *mh = (const struct mach_header *)ctx->base;
    map_fn(1, &path, &mh);

    LL_DBG("[libload] _objc_map_images returned OK\n");

    /*
     * _objc_load_image() would trigger +load methods, but on modern
     * macOS it calls _dyld_lookup_section_info() which requires the
     * image to be registered with dyld.  Since our image was loaded
     * reflectively, dyld doesn't know about it and the call crashes.
     *
     * Instead, manually invoke +load on classes listed in the
     * __objc_nlclslist section (non-lazy class list).
     */

    typedef void *(*sel_reg_fn)(const char *);
    typedef void *(*class_get_method_fn)(void *, void *);
    typedef void (*imp_fn)(void *, void *);
    typedef imp_fn (*method_get_imp_fn)(void *);

    sel_reg_fn     sel_reg   = (sel_reg_fn)dlsym(RTLD_DEFAULT, "sel_registerName");
    class_get_method_fn get_m = (class_get_method_fn)dlsym(RTLD_DEFAULT, "class_getClassMethod");
    method_get_imp_fn   get_i = (method_get_imp_fn)dlsym(RTLD_DEFAULT, "method_getImplementation");

    if (sel_reg && get_m && get_i) {
        void *sel_load = sel_reg("load");

        /* Scan for __objc_nlclslist section */
        lc = (const uint8_t *)ctx->base + sizeof(*hdr);
        for (uint32_t i = 0; i < hdr->ncmds; i++) {
            const struct load_command *cmd = (const struct load_command *)lc;

            if (cmd->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *seg =
                    (const struct segment_command_64 *)lc;
                const struct section_64 *sects =
                    (const struct section_64 *)(lc + sizeof(*seg));

                for (uint32_t j = 0; j < seg->nsects; j++) {
                    if (strncmp(sects[j].sectname, "__objc_nlclslist", 16) == 0) {
                        uintptr_t addr = sects[j].addr + ctx->slide;
                        size_t count = sects[j].size / sizeof(void *);

                        LL_DBG("[libload] calling +load on %zu non-lazy classes\n", count);

                        void **classes = (void **)addr;
                        for (size_t k = 0; k < count; k++) {
                            void *cls = classes[k];
                            if (!cls) continue;
                            void *method = get_m(cls, sel_load);
                            if (method) {
                                imp_fn imp = get_i(method);
                                if (imp)
                                    imp(cls, sel_load);
                            }
                        }
                    }
                }
            }

            lc += cmd->cmdsize;
        }
    }

    if (ctx->use_jit) {
        pthread_jit_write_protect_np(1);
        sys_icache_invalidate(ctx->base, ctx->total_size);
    }

    LL_DBG("[libload] ObjC registration complete\n");
}

/* ------------------------------------------------------------------ */
/*  Initializers                                                       */
/* ------------------------------------------------------------------ */

static int ll_run_initializers(struct libload_ctx *ctx,
                               const uint8_t *buf)
{
    typedef void (*init_fn)(void);

    for (uint32_t i = 0; i < ctx->nsegs; i++)
    {
        struct ll_segment *s = &ctx->segs[i];

        if (s->nsects == 0 || s->vmaddr < ctx->base_vmaddr)
            continue;

        const struct section_64 *sections =
            (const struct section_64 *)(buf + s->sect_buf_off);

        for (uint32_t j = 0; j < s->nsects; j++)
        {
            if ((sections[j].flags & SECTION_TYPE) != S_MOD_INIT_FUNC_POINTERS)
                continue;

            uint64_t addr = sections[j].addr + ctx->slide;
            size_t count  = sections[j].size / sizeof(uint64_t);

            init_fn *fns = (init_fn *)addr;

            for (size_t k = 0; k < count; k++)
            {
                if (fns[k])
                    fns[k]();
            }
        }
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/*  Export trie lookup                                                  */
/* ------------------------------------------------------------------ */

static void *ll_export_find(struct libload_ctx *ctx, const char *name)
{
    if (!ctx->exports || ctx->exports_size == 0 || !name)
        return NULL;

    const uint8_t *trie = ctx->exports;
    const uint8_t *end  = trie + ctx->exports_size;
    const uint8_t *node = trie;
    const char    *sym  = name;

    while (node < end)
    {
        const uint8_t *p = node;
        uint64_t term_size = read_uleb128(&p, end);

        if (term_size > 0 && *sym == '\0')
        {
            /* Terminal node and we've consumed the whole symbol name */
            uint64_t flags = read_uleb128(&p, end);

            if (flags & EXPORT_SYMBOL_FLAGS_REEXPORT)
            {
                /* Re-exported from another dylib — resolve via dlsym */
                read_uleb128(&p, end); /* ordinal */
                const char *reexport_name = (const char *)p;
                if (*reexport_name == '\0')
                    reexport_name = name;
                const char *lookup = reexport_name;
                if (lookup[0] == '_') lookup++;
                return dlsym(RTLD_DEFAULT, lookup);
            }
            else if (flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER)
            {
                uint64_t stub_off = read_uleb128(&p, end);
                (void)stub_off;
                uint64_t resolver_off = read_uleb128(&p, end);
                /* Call resolver to get actual address */
                typedef void *(*resolver_fn)(void);
                resolver_fn resolver = (resolver_fn)
                    ((uint8_t *)ctx->base + resolver_off);
                return resolver();
            }
            else
            {
                uint64_t sym_off = read_uleb128(&p, end);
                return (uint8_t *)ctx->base + sym_off;
            }
        }

        /* Skip terminal info */
        if (term_size > 0)
            p = node + 1 + (size_t)term_size;
        else
            p = node + 1; /* term_size was 0, encoded as single byte */

        if (p >= end)
            return NULL;

        /* Read children */
        uint8_t child_count = *p++;
        const uint8_t *found_child = NULL;

        for (uint8_t c = 0; c < child_count; c++)
        {
            /* Edge label (NUL-terminated string) */
            const char *edge = (const char *)p;
            size_t edge_len = strlen(edge);

            p += edge_len + 1; /* skip string + NUL */

            uint64_t child_off = read_uleb128(&p, end);

            if (!found_child && strncmp(sym, edge, edge_len) == 0)
            {
                sym += edge_len;
                found_child = trie + child_off;
            }
        }

        if (!found_child)
            return NULL;

        node = found_child;
    }

    return NULL;
}

/* ------------------------------------------------------------------ */
/*  Dual-map helper: two views of the same physical pages             */
/*  One RW (for writing), one RX (for execution). No entitlements.    */
/* ------------------------------------------------------------------ */

static int ll_dualmap_alloc(struct libload_ctx *ctx, size_t size)
{
    mach_vm_address_t rw_addr = 0;
    kern_return_t kr;

    /* Allocate backing memory (RW) */
    kr = mach_vm_allocate(mach_task_self(), &rw_addr, size,
                          VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS)
        return -1;

    /* Create a second mapping of the same physical pages via remap */
    mach_vm_address_t rx_addr = 0;
    vm_prot_t cur_prot, max_prot;

    kr = mach_vm_remap(mach_task_self(), &rx_addr, size, 0,
                       VM_FLAGS_ANYWHERE,
                       mach_task_self(), rw_addr, FALSE,
                       &cur_prot, &max_prot,
                       VM_INHERIT_NONE);
    if (kr != KERN_SUCCESS) {
        mach_vm_deallocate(mach_task_self(), rw_addr, size);
        return -1;
    }

    /* Make the second mapping executable */
    kr = mach_vm_protect(mach_task_self(), rx_addr, size, FALSE,
                         VM_PROT_READ | VM_PROT_EXECUTE);
    if (kr != KERN_SUCCESS) {
        mach_vm_deallocate(mach_task_self(), rx_addr, size);
        mach_vm_deallocate(mach_task_self(), rw_addr, size);
        return -1;
    }

    ctx->rw_base     = (void *)rw_addr;
    ctx->base        = (void *)rx_addr;
    ctx->total_size  = size;
    ctx->use_dualmap = 1;
    ctx->use_jit     = 0;
    return 0;
}

/* ------------------------------------------------------------------ */
/*  llbin initializer runner                                           */
/* ------------------------------------------------------------------ */

static void ll_llbin_run_initializers(struct libload_ctx *ctx)
{
    typedef void (*init_fn)(void);

    const struct mach_header_64 *hdr =
        (const struct mach_header_64 *)ctx->base;

    if (hdr->magic != MH_MAGIC_64)
        return;

    const uint8_t *lc = (const uint8_t *)ctx->base + sizeof(*hdr);

    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        const struct load_command *cmd = (const struct load_command *)lc;

        if (cmd->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg =
                (const struct segment_command_64 *)lc;
            const struct section_64 *sects =
                (const struct section_64 *)(lc + sizeof(*seg));

            for (uint32_t j = 0; j < seg->nsects; j++) {
                if ((sects[j].flags & SECTION_TYPE) != S_MOD_INIT_FUNC_POINTERS)
                    continue;

                uint64_t addr = sects[j].addr + ctx->slide;
                size_t count  = sects[j].size / sizeof(uint64_t);

                LL_DBG("[libload] llbin: running %zu initializers from %s,%s\n",
                       count, seg->segname, sects[j].sectname);

                for (size_t k = 0; k < count; k++) {
                    uint64_t fn_addr;
                    memcpy(&fn_addr, (uint8_t *)addr + k * sizeof(uint64_t),
                           sizeof(fn_addr));
                    if (fn_addr)
                        ((init_fn)(uintptr_t)fn_addr)();
                }
            }
        }

        lc += cmd->cmdsize;
    }
}

/* ------------------------------------------------------------------ */
/*  llbin loader (pre-packed flat binary)                              */
/* ------------------------------------------------------------------ */

static struct libload_ctx *ll_load_llbin(const uint8_t *buf, size_t len)
{
    if (len < sizeof(struct llbin_header))
        return NULL;

    const struct llbin_header *hdr = (const struct llbin_header *)buf;

    if (hdr->magic != LLBIN_MAGIC || hdr->version != LLBIN_VERSION)
        return NULL;

    /* Bounds-check all sections */
    if ((uint64_t)hdr->image_off + hdr->image_size > len)
        return NULL;
    if ((uint64_t)hdr->fixup_off +
        (uint64_t)hdr->fixup_count * sizeof(struct llbin_fixup) > len)
        return NULL;
    if ((uint64_t)hdr->import_off +
        (uint64_t)hdr->import_count * sizeof(struct llbin_import) > len)
        return NULL;
    if ((uint64_t)hdr->strings_off + hdr->strings_size > len)
        return NULL;

    struct libload_ctx *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;

    ctx->tlv_info_idx = -1;
    ctx->total_size = (size_t)hdr->image_size;

    /*
     * Allocation strategy (in order of preference):
     *  1. Dual-map: RW + RX views of same physical pages (no entitlements)
     *  2. MAP_JIT: single mapping with W^X toggling (arm64)
     *  3. Plain mmap + mprotect (x86_64 / SIP-disabled)
     */
    int allocated = 0;

    /* Strategy 1: dual-map */
    if (!allocated && ll_dualmap_alloc(ctx, ctx->total_size) == 0)
        allocated = 1;

#if defined(__arm64__) || defined(__aarch64__)
    /* Strategy 2: MAP_JIT */
    if (!allocated) {
        ctx->base = mmap(NULL, ctx->total_size,
                         PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_ANON | MAP_PRIVATE | MAP_JIT, -1, 0);
        if (ctx->base != MAP_FAILED) {
            ctx->use_jit = 1;
            pthread_jit_write_protect_np(0);
            allocated = 1;
        }
    }
#endif

    /* Strategy 3: plain mmap */
    if (!allocated) {
        ctx->base = mmap(NULL, ctx->total_size,
                         PROT_READ | PROT_WRITE,
                         MAP_ANON | MAP_PRIVATE, -1, 0);
        if (ctx->base != MAP_FAILED)
            allocated = 1;
    }

    if (!allocated) {
        free(ctx);
        return NULL;
    }

    /* Write through the writable view */
    void *write_base = ctx->use_dualmap ? ctx->rw_base : ctx->base;
    memcpy(write_base, buf + hdr->image_off, (size_t)hdr->image_size);

    /* Apply fixups (through writable view) */
    const struct llbin_fixup  *fixups  =
        (const struct llbin_fixup *)(buf + hdr->fixup_off);
    const struct llbin_import *imps    =
        (const struct llbin_import *)(buf + hdr->import_off);
    const char                *strings =
        (const char *)(buf + hdr->strings_off);

    int64_t slide = (int64_t)((uint64_t)ctx->base - hdr->preferred_base);

    for (uint32_t i = 0; i < hdr->fixup_count; i++) {
        if (fixups[i].offset + sizeof(uint64_t) > hdr->image_size)
            continue;

        uint8_t *ptr = (uint8_t *)write_base + fixups[i].offset;

        switch (fixups[i].type) {
        case LLBIN_FIXUP_REBASE: {
            uint64_t val;
            memcpy(&val, ptr, sizeof(val));
            val = (uint64_t)((int64_t)val + slide);
            memcpy(ptr, &val, sizeof(val));
            break;
        }
        case LLBIN_FIXUP_IMPORT: {
            if (fixups[i].import_idx >= hdr->import_count)
                break;
            uint32_t name_off = imps[fixups[i].import_idx].name_off;
            if (name_off >= hdr->strings_size)
                break;
            const char *name = strings + name_off;
            void *sym = dlsym(RTLD_DEFAULT, name);
            uint64_t val = (uint64_t)sym + fixups[i].addend;
            memcpy(ptr, &val, sizeof(val));
            break;
        }
        }
    }

    /* Finalize: apply per-segment protections */
    int did_seg_protect = 0;

    if (hdr->seg_count > 0) {
        uint32_t seg_table_off = hdr->strings_off + hdr->strings_size;
        if ((uint64_t)seg_table_off +
            (uint64_t)hdr->seg_count * sizeof(struct llbin_segment) <= len) {
            const struct llbin_segment *lsegs =
                (const struct llbin_segment *)(buf + seg_table_off);

            if (ctx->use_jit)
                pthread_jit_write_protect_np(0);

            for (uint32_t i = 0; i < hdr->seg_count; i++) {
                if (lsegs[i].size == 0)
                    continue;
                int prot = 0;
                if (lsegs[i].prot & VM_PROT_READ)    prot |= PROT_READ;
                if (lsegs[i].prot & VM_PROT_WRITE)   prot |= PROT_WRITE;
                if (lsegs[i].prot & VM_PROT_EXECUTE) prot |= PROT_EXEC;
                void *addr = (uint8_t *)ctx->base + lsegs[i].offset;
                size_t sz  = (lsegs[i].size + getpagesize() - 1) &
                             ~(getpagesize() - 1);
                mprotect(addr, sz, prot);
            }
            did_seg_protect = 1;
        }
    }

    if (!did_seg_protect) {
        if (ctx->use_jit)
            pthread_jit_write_protect_np(1);
        else if (!ctx->use_dualmap)
            mprotect(ctx->base, ctx->total_size, PROT_READ | PROT_EXEC);
    }

    sys_icache_invalidate(ctx->base, ctx->total_size);

    ctx->entry_off   = hdr->entry_off;
    ctx->has_entry   = 1;
    ctx->slide       = (uint64_t)slide;
    ctx->base_vmaddr = hdr->preferred_base;

    /* Register ObjC classes and run initializers from in-memory header */
    ll_register_objc(ctx);
    ll_setup_tlv(ctx);
    ll_llbin_run_initializers(ctx);

    return ctx;
}

/* ------------------------------------------------------------------ */
/*  Public API                                                         */
/* ------------------------------------------------------------------ */

libload_t libload_open(const unsigned char *buf, size_t len)
{
    const uint8_t *macho;
    size_t macho_len;
    struct libload_ctx *ctx = NULL;

    if (!buf || len == 0)
        return NULL;

    /* Detect llbin format */
    if (len >= sizeof(uint32_t)) {
        uint32_t magic;
        memcpy(&magic, buf, sizeof(magic));
        if (magic == LLBIN_MAGIC)
            return ll_load_llbin(buf, len);
    }

    /* Extract matching architecture from fat binaries */
    macho = ll_extract_arch(buf, len, &macho_len);

    if (!macho || ll_validate(macho, macho_len) < 0)
    {
        LL_DBG("[libload] validate failed: macho=%p\n", (void *)macho);
        return NULL;
    }

    ctx = calloc(1, sizeof(*ctx));

    if (!ctx)
        return NULL;

    ctx->tlv_info_idx = -1;

    /* Map segments into memory */
    if (ll_map_segments(ctx, macho, macho_len) < 0)
    {
        LL_DBG("[libload] ll_map_segments failed\n");
        goto fail;
    }
    LL_DBG("[libload] map_segments OK: base=%p total=0x%zx slide=0x%llx base_vmaddr=0x%llx nsegs=%u\n",
           ctx->base, ctx->total_size, (unsigned long long)ctx->slide,
           (unsigned long long)ctx->base_vmaddr, ctx->nsegs);

    /* Walk load commands for dyld info, chained fixups, entry point */
    const struct mach_header_64 *hdr =
        (const struct mach_header_64 *)macho;
    const uint8_t *lc = macho + sizeof(struct mach_header_64);

    uint64_t le_vmaddr = 0, le_fileoff = 0;
    ll_find_linkedit(ctx, &le_vmaddr, &le_fileoff);

    int has_dyld_info = 0;
    int has_chained   = 0;

    for (uint32_t i = 0; i < hdr->ncmds; i++)
    {
        const struct load_command *cmd = (const struct load_command *)lc;

        switch (cmd->cmd)
        {
        case LC_DYLD_INFO:
        case LC_DYLD_INFO_ONLY:
        {
            const struct dyld_info_command *di =
                (const struct dyld_info_command *)lc;

            if (di->rebase_size > 0)
            {
                const uint8_t *rebase = ll_linkedit_ptr(ctx, le_vmaddr,
                    le_fileoff, di->rebase_off);
                ll_rebase(ctx, rebase, di->rebase_size);
            }

            if (di->bind_size > 0)
            {
                const uint8_t *bind = ll_linkedit_ptr(ctx, le_vmaddr,
                    le_fileoff, di->bind_off);
                ll_bind_opcodes(ctx, bind, di->bind_size);
            }

            if (di->lazy_bind_size > 0)
            {
                const uint8_t *lazy = ll_linkedit_ptr(ctx, le_vmaddr,
                    le_fileoff, di->lazy_bind_off);
                ll_lazy_bind(ctx, lazy, di->lazy_bind_size);
            }

            if (di->export_size > 0)
            {
                ctx->exports = ll_linkedit_ptr(ctx, le_vmaddr,
                    le_fileoff, di->export_off);
                ctx->exports_size = di->export_size;
            }

            has_dyld_info = 1;
            break;
        }

        case LC_DYLD_CHAINED_FIXUPS:
        {
            const struct linkedit_data_command *ldc =
                (const struct linkedit_data_command *)lc;

            LL_DBG("[libload] chained fixups: dataoff=%u datasize=%u le_vmaddr=0x%llx le_fileoff=0x%llx\n",
                   ldc->dataoff, ldc->datasize,
                   (unsigned long long)le_vmaddr, (unsigned long long)le_fileoff);

            if (ll_chained_fixups(ctx, macho, le_vmaddr, le_fileoff,
                              ldc->dataoff, ldc->datasize) < 0)
            {
                LL_DBG("[libload] ll_chained_fixups FAILED\n");
                goto fail;
            }
            LL_DBG("[libload] chained fixups OK\n");

            has_chained = 1;
            break;
        }

        case LC_DYLD_EXPORTS_TRIE:
        {
            const struct linkedit_data_command *ldc =
                (const struct linkedit_data_command *)lc;

            if (ldc->datasize > 0)
            {
                ctx->exports = ll_linkedit_ptr(ctx, le_vmaddr,
                    le_fileoff, ldc->dataoff);
                ctx->exports_size = ldc->datasize;
            }
            break;
        }

        case LC_MAIN:
        {
            const struct entry_point_command *ep =
                (const struct entry_point_command *)lc;
            ctx->entry_off = ep->entryoff;
            ctx->has_entry = 1;
            break;
        }

        default:
            break;
        }

        lc += cmd->cmdsize;
    }

    (void)has_dyld_info;
    (void)has_chained;

    /* Set memory protections */
    LL_DBG("[libload] setting protections...\n");
    ll_protect(ctx);

    /* Register ObjC classes/selectors/categories with the runtime */
    ll_register_objc(ctx);

    /* Set up Thread-Local Variables */
    ll_setup_tlv(ctx);

    /* Run static initializers */
    LL_DBG("[libload] running initializers...\n");
    ll_run_initializers(ctx, macho);
    LL_DBG("[libload] done, returning ctx\n");

    return ctx;

fail:
    if (ctx)
    {
        if (ctx->base)
            munmap(ctx->base, ctx->total_size);
        free(ctx);
    }
    return NULL;
}

void *libload_sym(libload_t ctx, const char *name)
{
    if (!ctx || !name)
        return NULL;

    return ll_export_find(ctx, name);
}

int libload_close(libload_t ctx)
{
    if (!ctx)
        return -1;

    ll_cleanup_tlv(ctx);

    if (ctx->base)
        munmap(ctx->base, ctx->total_size);
    if (ctx->rw_base && ctx->rw_base != ctx->base)
        munmap(ctx->rw_base, ctx->total_size);

    free(ctx);
    return 0;
}

pid_t libload_exec(const unsigned char *buf, size_t len,
                   char *const argv[], char *const envp[])
{
    pid_t pid;

    if (!buf || len == 0 || !argv)
        return -1;

    pid = fork();

    if (pid < 0)
        return -1;

    if (pid > 0)
        return pid; /* parent */

    /* Child process */
    libload_t ctx = libload_open(buf, len);

    if (!ctx || !ctx->has_entry)
    {
        LL_DBG("[libload] exec: open failed or no entry (ctx=%p has_entry=%d)\n",
               (void *)ctx, ctx ? ctx->has_entry : -1);
        _exit(127);
    }

    typedef int (*main_fn)(int, char **, char **, char **);
    main_fn entry = (main_fn)((uint8_t *)ctx->base + ctx->entry_off);

    LL_DBG("[libload] exec: base=%p entry_off=0x%llx entry=%p dualmap=%d jit=%d\n",
           ctx->base, (unsigned long long)ctx->entry_off, (void *)entry,
           ctx->use_dualmap, ctx->use_jit);

#ifdef LIBLOAD_DEBUG
    /* Dump first 16 bytes at the entry point */
    uint8_t *ep = (uint8_t *)entry;
    LL_DBG("[libload] exec: bytes at entry: %02x %02x %02x %02x %02x %02x %02x %02x\n",
           ep[0], ep[1], ep[2], ep[3], ep[4], ep[5], ep[6], ep[7]);
#endif

    /* Count argc */
    int argc = 0;
    while (argv[argc]) argc++;

    char **env = envp ? (char **)envp : *_NSGetEnviron();
    char *apple[] = { NULL };

    LL_DBG("[libload] exec: jumping to entry (argc=%d)...\n", argc);
    int ret = entry(argc, (char **)argv, env, apple);

    libload_close(ctx);
    _exit(ret);
}

int libload_run(const unsigned char *buf, size_t len,
                char *const argv[], char *const envp[])
{
    if (!buf || len == 0 || !argv)
        return -1;

    libload_t ctx = libload_open(buf, len);

    if (!ctx || !ctx->has_entry)
    {
        LL_DBG("[libload] run: open failed or no entry (ctx=%p has_entry=%d)\n",
               (void *)ctx, ctx ? ctx->has_entry : -1);
        if (ctx) libload_close(ctx);
        return -1;
    }

    typedef int (*main_fn)(int, char **, char **, char **);
    main_fn entry = (main_fn)((uint8_t *)ctx->base + ctx->entry_off);

    LL_DBG("[libload] run: base=%p entry_off=0x%llx entry=%p dualmap=%d jit=%d\n",
           ctx->base, (unsigned long long)ctx->entry_off, (void *)entry,
           ctx->use_dualmap, ctx->use_jit);

    int argc = 0;
    while (argv[argc]) argc++;

    char **env = envp ? (char **)envp : *_NSGetEnviron();
    char *apple[] = { NULL };

    LL_DBG("[libload] run: jumping to entry (argc=%d)...\n", argc);
    int ret = entry(argc, (char **)argv, env, apple);

    libload_close(ctx);
    _exit(ret);
}
