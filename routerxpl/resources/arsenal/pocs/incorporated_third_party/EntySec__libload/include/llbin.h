/*
 * llbin — Pre-linked flat binary format
 *
 * A Mach-O executable is "packed" offline into this format by llpack.
 * All complex Mach-O parsing (chained fixups, rebase/bind opcodes,
 * segment mapping) is done once at pack time.  The runtime loader
 * simply:
 *
 *   1. mmap a single contiguous region (MAP_JIT on Apple Silicon)
 *   2. Copy the flat image
 *   3. Walk a trivial fixup table (rebases + imports)
 *   4. Toggle W→X, flush icache, jump to entry
 *
 * File layout:
 *   [ llbin_header ]
 *   [ flat image   ]  (image_size bytes, page-aligned)
 *   [ fixup table  ]  (fixup_count × sizeof(llbin_fixup))
 *   [ import table ]  (import_count × sizeof(llbin_import))
 *   [ string table ]  (strings_size bytes, NUL-terminated names)
 */

#ifndef LLBIN_H
#define LLBIN_H

#include <stdint.h>

#define LLBIN_MAGIC     0x4E424C4C  /* "LLBN" little-endian */
#define LLBIN_VERSION   1

/* Fixup types */
#define LLBIN_FIXUP_REBASE  0   /* *(uint64_t*) += slide               */
#define LLBIN_FIXUP_IMPORT  1   /* *(uint64_t*)  = dlsym(name) + addend */

struct llbin_header {
    uint32_t magic;
    uint32_t version;
    uint32_t arch;           /* CPU_TYPE_ARM64, CPU_TYPE_X86_64, etc.  */
    uint32_t flags;
    uint64_t entry_off;      /* entry point offset within flat image   */
    uint64_t image_size;     /* runtime allocation size (page-aligned) */
    uint64_t preferred_base; /* preferred load address for slide calc  */
    uint32_t image_off;      /* file offset of flat image data         */
    uint32_t fixup_off;      /* file offset of fixup table             */
    uint32_t fixup_count;    /* number of fixup entries                */
    uint32_t import_off;     /* file offset of import table            */
    uint32_t import_count;   /* number of import entries               */
    uint32_t strings_off;    /* file offset of string table            */
    uint32_t strings_size;   /* size of string table in bytes          */
    uint32_t seg_count;      /* number of segment entries (0 = none)   */
};

/*
 * Segment table follows the string table in the file.
 * Only present when seg_count > 0.
 */
struct llbin_segment {
    uint32_t offset;         /* offset within flat image               */
    uint32_t size;           /* size in bytes (page-aligned)           */
    uint32_t prot;           /* VM_PROT_* flags (initprot)             */
    uint32_t pad;
};

struct llbin_fixup {
    uint32_t offset;         /* offset within flat image to patch      */
    uint8_t  type;           /* LLBIN_FIXUP_REBASE or _IMPORT          */
    uint8_t  reserved;
    uint16_t import_idx;     /* index into import table (for _IMPORT)  */
    int64_t  addend;         /* addend for _IMPORT                     */
};

struct llbin_import {
    uint32_t name_off;       /* offset into string table               */
    uint32_t flags;          /* reserved                               */
};

#endif /* LLBIN_H */
