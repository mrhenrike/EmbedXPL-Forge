/*
 * elf.c — Reflective ELF loader and userland exec
 *
 * Loads ELF shared objects and executables entirely from memory.
 * No memfd_create, no /proc/self/fd, no temporary files.
 *
 *   1. Parse ELF header and program headers
 *   2. Map contiguous region and copy PT_LOAD segments
 *   3. Process relocations (RELA, REL, JMPREL) via dlsym
 *   4. Set per-segment protections with mprotect
 *   5. Run DT_INIT / DT_INIT_ARRAY constructors
 *
 * Also supports pre-packed llbin format for fast loading.
 *
 * Supported architectures:
 *   x86_64, aarch64, i386, arm (LE/BE), mips (LE/BE), sparc
 */

#define _GNU_SOURCE

#include "libload.h"
#include "llbin.h"

#include <dlfcn.h>
#include <elf.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/auxv.h>
#include <sys/mman.h>

extern char **environ;

/* ------------------------------------------------------------------ */
/*  ELF type bridge — select 32-bit or 64-bit types at compile time   */
/* ------------------------------------------------------------------ */

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

#else /* 32-bit */

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

/* ------------------------------------------------------------------ */
/*  MIPS relocation fallbacks (may be missing in older elf.h)         */
/* ------------------------------------------------------------------ */

#if defined(__mips__)
#ifndef R_MIPS_GLOB_DAT
#define R_MIPS_GLOB_DAT  51
#endif
#ifndef R_MIPS_JUMP_SLOT
#define R_MIPS_JUMP_SLOT 127
#endif
#endif

/* ------------------------------------------------------------------ */
/*  Icache flush (needed on non-x86 arches)                           */
/* ------------------------------------------------------------------ */

#if defined(__aarch64__) || defined(__arm__) || defined(__mips__) || defined(__sparc__)
#define LL_FLUSH_ICACHE(base, sz) \
    __builtin___clear_cache((char *)(base), (char *)(base) + (sz))
#else
#define LL_FLUSH_ICACHE(base, sz) ((void)0)
#endif

/* Defined in the per-arch entry_*.S files */
extern void ll_entry_trampoline(void *sp, void *entry)
    __attribute__((noreturn));

#define LL_MAX_SEGMENTS 32

struct ll_segment {
    uint64_t vaddr;
    uint64_t memsz;
    uint64_t filesz;
    uint64_t offset;
    uint32_t flags;
};

struct libload_ctx {
    uint8_t   *base;
    size_t     size;
    Elf_Sym   *dynsym;
    const char *dynstr;
    uint32_t  *gnu_hash;
    uint32_t  *sysv_hash;
    struct ll_segment segs[LL_MAX_SEGMENTS];
    int seg_count;
    uint64_t preferred_base;
};

/* ------------------------------------------------------------------ */
/*  Helpers                                                           */
/* ------------------------------------------------------------------ */

static uint32_t elf_gnu_hash(const char *name)
{
    uint32_t h = 5381;
    for (const unsigned char *p = (const unsigned char *)name; *p; p++)
        h = (h << 5) + h + *p;
    return h;
}

static uint32_t elf_sysv_hash(const char *name)
{
    uint32_t h = 0, g;
    for (const unsigned char *p = (const unsigned char *)name; *p; p++) {
        h = (h << 4) + *p;
        g = h & 0xf0000000;
        if (g) h ^= g >> 24;
        h &= ~g;
    }
    return h;
}

static int prot_from_flags(uint32_t p_flags)
{
    int prot = 0;
    if (p_flags & PF_R) prot |= PROT_READ;
    if (p_flags & PF_W) prot |= PROT_WRITE;
    if (p_flags & PF_X) prot |= PROT_EXEC;
    return prot;
}

static void mprotect_page_aligned(uint8_t *base, uint64_t offset,
                                  uint64_t memsz, int prot)
{
    uintptr_t start = (uintptr_t)(base + offset) & ~(uintptr_t)0xfff;
    uintptr_t end   = ((uintptr_t)(base + offset + memsz) + 0xfff)
                      & ~(uintptr_t)0xfff;
    mprotect((void *)start, end - start, prot);
}

/* ------------------------------------------------------------------ */
/*  Relocation type classification                                    */
/* ------------------------------------------------------------------ */

static inline int is_relative_reloc(uint32_t type, uint32_t sym)
{
#if defined(__x86_64__)
    (void)sym;
    return type == R_X86_64_RELATIVE;
#elif defined(__aarch64__)
    (void)sym;
    return type == R_AARCH64_RELATIVE;
#elif defined(__i386__)
    (void)sym;
    return type == R_386_RELATIVE;
#elif defined(__arm__)
    (void)sym;
    return type == R_ARM_RELATIVE;
#elif defined(__mips__)
    return type == R_MIPS_REL32 && sym == 0;
#elif defined(__sparc__)
    (void)sym;
    return type == R_SPARC_RELATIVE;
#else
    (void)type; (void)sym;
    return 0;
#endif
}

static inline int is_import_reloc(uint32_t type, uint32_t sym)
{
#if defined(__x86_64__)
    (void)sym;
    return type == R_X86_64_GLOB_DAT ||
           type == R_X86_64_JUMP_SLOT ||
           type == R_X86_64_64;
#elif defined(__aarch64__)
    (void)sym;
    return type == R_AARCH64_GLOB_DAT ||
           type == R_AARCH64_JUMP_SLOT ||
           type == R_AARCH64_ABS64;
#elif defined(__i386__)
    (void)sym;
    return type == R_386_GLOB_DAT ||
           type == R_386_JMP_SLOT ||
           type == R_386_32;
#elif defined(__arm__)
    (void)sym;
    return type == R_ARM_GLOB_DAT ||
           type == R_ARM_JUMP_SLOT ||
           type == R_ARM_ABS32;
#elif defined(__mips__)
    return type == R_MIPS_32 ||
           type == R_MIPS_GLOB_DAT ||
           type == R_MIPS_JUMP_SLOT ||
           (type == R_MIPS_REL32 && sym > 0);
#elif defined(__sparc__)
    (void)sym;
    return type == R_SPARC_GLOB_DAT ||
           type == R_SPARC_JMP_SLOT ||
           type == R_SPARC_32;
#else
    (void)type; (void)sym;
    return 0;
#endif
}

/* ------------------------------------------------------------------ */
/*  Relocation processing                                             */
/* ------------------------------------------------------------------ */

static void apply_rela(uint8_t *base, Elf_Addr lo, Elf_Rela *rela,
                       size_t count, Elf_Sym *symtab, const char *strtab)
{
    for (size_t i = 0; i < count; i++) {
        Elf_Addr *slot = (Elf_Addr *)(base + (rela[i].r_offset - lo));
        uint32_t type = ELF_R_TYPE(rela[i].r_info);
        uint32_t si   = ELF_R_SYM(rela[i].r_info);

        if (is_relative_reloc(type, si)) {
            *slot = (Elf_Addr)(uintptr_t)base +
                    (Elf_Addr)rela[i].r_addend - lo;
        } else if (is_import_reloc(type, si) && symtab && strtab) {
            const char *name = strtab + symtab[si].st_name;
            void *sym = NULL;
            if (symtab[si].st_shndx != SHN_UNDEF)
                sym = (void *)(base + (symtab[si].st_value - lo));
            else
                sym = dlsym(RTLD_DEFAULT, name);
            if (sym)
                *slot = (Elf_Addr)(uintptr_t)sym +
                        (Elf_Addr)rela[i].r_addend;
        }
    }
}

static void apply_rel(uint8_t *base, Elf_Addr lo, Elf_Rel *rel,
                      size_t count, Elf_Sym *symtab, const char *strtab)
{
    Elf_Addr slide = (Elf_Addr)((uintptr_t)base - (uintptr_t)lo);

    for (size_t i = 0; i < count; i++) {
        Elf_Addr *slot = (Elf_Addr *)(base + (rel[i].r_offset - lo));
        uint32_t type = ELF_R_TYPE(rel[i].r_info);
        uint32_t si   = ELF_R_SYM(rel[i].r_info);

        if (is_relative_reloc(type, si)) {
            *slot += slide;
        } else if (is_import_reloc(type, si) && symtab && strtab) {
            Elf_Addr addend = *slot;
            const char *name = strtab + symtab[si].st_name;
            void *sym = NULL;
            if (symtab[si].st_shndx != SHN_UNDEF)
                sym = (void *)(base + (symtab[si].st_value - lo));
            else
                sym = dlsym(RTLD_DEFAULT, name);
            if (sym)
                *slot = (Elf_Addr)(uintptr_t)sym + addend;
        }
    }
}

/* ------------------------------------------------------------------ */
/*  llbin loader                                                      */
/* ------------------------------------------------------------------ */

static struct libload_ctx *ll_load_llbin(const unsigned char *buf, size_t len)
{
    const struct llbin_header *hdr = (const struct llbin_header *)buf;

    if (len < sizeof(*hdr))
        return NULL;
    if (hdr->magic != LLBIN_MAGIC || hdr->version != LLBIN_VERSION)
        return NULL;
    if ((uint64_t)hdr->image_off + hdr->image_size > len)
        return NULL;
    if ((uint64_t)hdr->fixup_off +
        hdr->fixup_count * sizeof(struct llbin_fixup) > len)
        return NULL;

    size_t alloc = (size_t)hdr->image_size;
    uint8_t *base = mmap(NULL, alloc, PROT_READ | PROT_WRITE,
                         MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (base == MAP_FAILED)
        return NULL;

    memcpy(base, buf + hdr->image_off, hdr->image_size);

    intptr_t slide = (intptr_t)((uintptr_t)base -
                                (uintptr_t)hdr->preferred_base);
    const struct llbin_fixup *fixups =
        (const struct llbin_fixup *)(buf + hdr->fixup_off);
    const struct llbin_import *imports =
        (const struct llbin_import *)(buf + hdr->import_off);
    const char *strings = (const char *)(buf + hdr->strings_off);

    for (uint32_t i = 0; i < hdr->fixup_count; i++) {
        const struct llbin_fixup *f = &fixups[i];
        uintptr_t *slot = (uintptr_t *)(base + f->offset);

        if (f->type == LLBIN_FIXUP_REBASE) {
            *slot += (uintptr_t)slide;
        } else if (f->type == LLBIN_FIXUP_IMPORT) {
            if (f->import_idx >= hdr->import_count)
                continue;
            const char *name = strings + imports[f->import_idx].name_off;
            void *sym = dlsym(RTLD_DEFAULT, name);
            if (sym)
                *slot = (uintptr_t)sym + (uintptr_t)f->addend;
        }
    }

    LL_FLUSH_ICACHE(base, alloc);

    if (hdr->seg_count > 0) {
        const struct llbin_segment *segs =
            (const struct llbin_segment *)(buf + hdr->strings_off +
                                           hdr->strings_size);
        for (uint32_t i = 0; i < hdr->seg_count; i++) {
            if (segs[i].prot && segs[i].size > 0)
                mprotect_page_aligned(base, segs[i].offset, segs[i].size,
                                      (int)segs[i].prot);
        }
    } else {
        mprotect(base, alloc, PROT_READ | PROT_EXEC);
    }

    struct libload_ctx *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        munmap(base, alloc);
        return NULL;
    }

    ctx->base = base;
    ctx->size = alloc;
    ctx->preferred_base = hdr->preferred_base;
    return ctx;
}

/* ------------------------------------------------------------------ */
/*  Reflective ELF loader                                             */
/* ------------------------------------------------------------------ */

static struct libload_ctx *ll_load_elf(const unsigned char *buf, size_t len)
{
    if (len < sizeof(Elf_Ehdr))
        return NULL;

    const Elf_Ehdr *ehdr = (const Elf_Ehdr *)buf;

    if (ehdr->e_ident[EI_MAG0] != ELFMAG0 ||
        ehdr->e_ident[EI_MAG1] != ELFMAG1 ||
        ehdr->e_ident[EI_MAG2] != ELFMAG2 ||
        ehdr->e_ident[EI_MAG3] != ELFMAG3)
        return NULL;

    if (ehdr->e_ident[EI_CLASS] != ELFCLASS_NATIVE)
        return NULL;
    if (ehdr->e_type != ET_DYN && ehdr->e_type != ET_EXEC)
        return NULL;
    if (ehdr->e_phoff == 0 || ehdr->e_phnum == 0)
        return NULL;
    if (ehdr->e_phoff + (uint64_t)ehdr->e_phnum * sizeof(Elf_Phdr) > len)
        return NULL;

    const Elf_Phdr *phdrs = (const Elf_Phdr *)(buf + ehdr->e_phoff);

    uint64_t lo = UINT64_MAX, hi = 0;
    int load_count = 0;

    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdrs[i].p_type != PT_LOAD)
            continue;
        uint64_t seg_lo = phdrs[i].p_vaddr;
        uint64_t seg_hi = phdrs[i].p_vaddr + phdrs[i].p_memsz;
        if (seg_lo < lo) lo = seg_lo;
        if (seg_hi > hi) hi = seg_hi;
        load_count++;
    }

    if (load_count == 0 || lo >= hi)
        return NULL;

    lo &= ~(uint64_t)0xfff;
    hi = (hi + 0xfff) & ~(uint64_t)0xfff;
    size_t total_size = (size_t)(hi - lo);

    uint8_t *base = mmap(NULL, total_size, PROT_READ | PROT_WRITE,
                         MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (base == MAP_FAILED)
        return NULL;

    struct ll_segment segs[LL_MAX_SEGMENTS];
    int seg_count = 0;
    Elf_Addr elf_lo = (Elf_Addr)lo;

    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdrs[i].p_type != PT_LOAD)
            continue;
        if (seg_count >= LL_MAX_SEGMENTS)
            break;

        uint64_t seg_off = phdrs[i].p_vaddr - lo;
        if (phdrs[i].p_filesz > 0) {
            if (phdrs[i].p_offset + phdrs[i].p_filesz > len) {
                munmap(base, total_size);
                return NULL;
            }
            memcpy(base + seg_off, buf + phdrs[i].p_offset,
                   phdrs[i].p_filesz);
        }

        segs[seg_count].vaddr  = phdrs[i].p_vaddr;
        segs[seg_count].memsz  = phdrs[i].p_memsz;
        segs[seg_count].filesz = phdrs[i].p_filesz;
        segs[seg_count].offset = phdrs[i].p_offset;
        segs[seg_count].flags  = phdrs[i].p_flags;
        seg_count++;
    }

    /* Parse PT_DYNAMIC */
    Elf_Rela *rela = NULL;       size_t rela_sz = 0;
    Elf_Rel  *rel = NULL;        size_t rel_sz = 0;
    void     *jmprel = NULL;     size_t jmprel_sz = 0;
    int       pltrel_type = DT_RELA;
    Elf_Sym  *symtab = NULL;
    const char *strtab = NULL;
    uint32_t *gnu_hash = NULL;
    uint32_t *sysv_hash = NULL;
    void     (*init_func)(void) = NULL;
    void     (**init_array)(void) = NULL;
    size_t    init_array_sz = 0;

    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdrs[i].p_type != PT_DYNAMIC)
            continue;

        Elf_Dyn *dyn = (Elf_Dyn *)(base + (phdrs[i].p_vaddr - elf_lo));
        int count = phdrs[i].p_memsz / sizeof(Elf_Dyn);

        for (int d = 0; d < count && dyn[d].d_tag != DT_NULL; d++) {
            Elf_Addr ptr = dyn[d].d_un.d_ptr;
            Elf_Addr val = dyn[d].d_un.d_val;
            switch (dyn[d].d_tag) {
            case DT_RELA:       rela = (Elf_Rela *)(base + (ptr - elf_lo)); break;
            case DT_RELASZ:     rela_sz = val; break;
            case DT_REL:        rel = (Elf_Rel *)(base + (ptr - elf_lo)); break;
            case DT_RELSZ:      rel_sz = val; break;
            case DT_JMPREL:     jmprel = (void *)(base + (ptr - elf_lo)); break;
            case DT_PLTRELSZ:   jmprel_sz = val; break;
            case DT_PLTREL:     pltrel_type = (int)val; break;
            case DT_SYMTAB:     symtab = (Elf_Sym *)(base + (ptr - elf_lo)); break;
            case DT_STRTAB:     strtab = (const char *)(base + (ptr - elf_lo)); break;
            case DT_GNU_HASH:   gnu_hash = (uint32_t *)(base + (ptr - elf_lo)); break;
            case DT_HASH:       sysv_hash = (uint32_t *)(base + (ptr - elf_lo)); break;
            case DT_INIT:       init_func = (void (*)(void))(base + (ptr - elf_lo)); break;
            case DT_INIT_ARRAY: init_array = (void (**)(void))(base + (ptr - elf_lo)); break;
            case DT_INIT_ARRAYSZ: init_array_sz = val; break;
            }
        }
        break;
    }

    if (rela && rela_sz > 0 && symtab && strtab)
        apply_rela(base, elf_lo, rela,
                   rela_sz / sizeof(Elf_Rela), symtab, strtab);

    if (rel && rel_sz > 0)
        apply_rel(base, elf_lo, rel,
                  rel_sz / sizeof(Elf_Rel), symtab, strtab);

    if (jmprel && jmprel_sz > 0 && symtab && strtab) {
        if (pltrel_type == DT_RELA)
            apply_rela(base, elf_lo, (Elf_Rela *)jmprel,
                       jmprel_sz / sizeof(Elf_Rela), symtab, strtab);
        else
            apply_rel(base, elf_lo, (Elf_Rel *)jmprel,
                      jmprel_sz / sizeof(Elf_Rel), symtab, strtab);
    }

    LL_FLUSH_ICACHE(base, total_size);

    for (int i = 0; i < seg_count; i++)
        mprotect_page_aligned(base, segs[i].vaddr - lo, segs[i].memsz,
                              prot_from_flags(segs[i].flags));

    if (init_func)
        init_func();
    if (init_array && init_array_sz > 0) {
        size_t count = init_array_sz / sizeof(void *);
        for (size_t i = 0; i < count; i++)
            if (init_array[i])
                init_array[i]();
    }

    struct libload_ctx *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        munmap(base, total_size);
        return NULL;
    }

    ctx->base = base;
    ctx->size = total_size;
    ctx->dynsym = symtab;
    ctx->dynstr = strtab;
    ctx->gnu_hash = gnu_hash;
    ctx->sysv_hash = sysv_hash;
    ctx->preferred_base = lo;
    memcpy(ctx->segs, segs, seg_count * sizeof(struct ll_segment));
    ctx->seg_count = seg_count;
    return ctx;
}

/* ------------------------------------------------------------------ */
/*  Symbol resolution                                                 */
/* ------------------------------------------------------------------ */

static void *ll_sym_gnu(struct libload_ctx *ctx, const char *name)
{
    uint32_t *ht = ctx->gnu_hash;
    uint32_t nbuckets  = ht[0];
    uint32_t symoffset = ht[1];
    uint32_t bloom_sz  = ht[2];
    uint32_t *buckets =
        &ht[4 + bloom_sz * (sizeof(Elf_Addr) / sizeof(uint32_t))];
    uint32_t *chain = &buckets[nbuckets];

    uint32_t h = elf_gnu_hash(name);
    uint32_t idx = buckets[h % nbuckets];
    if (idx == 0)
        return NULL;

    for (;;) {
        uint32_t cv = chain[idx - symoffset];
        if ((cv | 1) == (h | 1)) {
            Elf_Sym *sym = &ctx->dynsym[idx];
            if (sym->st_shndx != SHN_UNDEF &&
                strcmp(ctx->dynstr + sym->st_name, name) == 0)
                return (void *)(ctx->base +
                       (sym->st_value - (Elf_Addr)ctx->preferred_base));
        }
        if (cv & 1)
            break;
        idx++;
    }
    return NULL;
}

static void *ll_sym_sysv(struct libload_ctx *ctx, const char *name)
{
    uint32_t nbuckets = ctx->sysv_hash[0];
    uint32_t *buckets = &ctx->sysv_hash[2];
    uint32_t *chain   = &buckets[nbuckets];

    uint32_t h = elf_sysv_hash(name);
    uint32_t idx = buckets[h % nbuckets];

    while (idx != STN_UNDEF) {
        Elf_Sym *sym = &ctx->dynsym[idx];
        if (sym->st_shndx != SHN_UNDEF &&
            strcmp(ctx->dynstr + sym->st_name, name) == 0)
            return (void *)(ctx->base +
                   (sym->st_value - (Elf_Addr)ctx->preferred_base));
        idx = chain[idx];
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/*  Public API — library loading                                      */
/* ------------------------------------------------------------------ */

libload_t libload_open(const unsigned char *buf, size_t len)
{
    if (!buf || len < 4)
        return NULL;

    uint32_t magic;
    memcpy(&magic, buf, 4);
    if (magic == LLBIN_MAGIC)
        return ll_load_llbin(buf, len);

    return ll_load_elf(buf, len);
}

void *libload_sym(libload_t ctx, const char *name)
{
    if (!ctx || !name)
        return NULL;
    if (ctx->gnu_hash && ctx->dynsym && ctx->dynstr)
        return ll_sym_gnu(ctx, name);
    if (ctx->sysv_hash && ctx->dynsym && ctx->dynstr)
        return ll_sym_sysv(ctx, name);
    return NULL;
}

int libload_close(libload_t ctx)
{
    if (!ctx)
        return -1;
    if (ctx->base && ctx->size > 0)
        munmap(ctx->base, ctx->size);
    free(ctx);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Userland exec                                                     */
/* ------------------------------------------------------------------ */

struct ll_exec_info {
    uint8_t  *base;
    uintptr_t entry;
    uintptr_t phdr;
    uint16_t  phent;
    uint16_t  phnum;
    size_t    size;
    uint64_t  preferred_base;
};

static int ll_parse_exec(const unsigned char *buf, size_t len,
                         struct ll_exec_info *info)
{
    if (len < 4)
        return -1;

    uint32_t magic;
    memcpy(&magic, buf, 4);
    if (magic == LLBIN_MAGIC) {
        struct libload_ctx *ctx = ll_load_llbin(buf, len);
        if (!ctx)
            return -1;
        const struct llbin_header *hdr = (const struct llbin_header *)buf;
        info->base = ctx->base;
        info->size = ctx->size;
        info->entry = (uintptr_t)ctx->base + (uintptr_t)hdr->entry_off;
        info->preferred_base = ctx->preferred_base;
        info->phdr = 0;
        info->phent = 0;
        info->phnum = 0;
        free(ctx);
        return 0;
    }

    if (len < sizeof(Elf_Ehdr))
        return -1;

    const Elf_Ehdr *ehdr = (const Elf_Ehdr *)buf;

    if (ehdr->e_ident[EI_MAG0] != ELFMAG0 ||
        ehdr->e_ident[EI_MAG1] != ELFMAG1 ||
        ehdr->e_ident[EI_MAG2] != ELFMAG2 ||
        ehdr->e_ident[EI_MAG3] != ELFMAG3)
        return -1;
    if (ehdr->e_ident[EI_CLASS] != ELFCLASS_NATIVE)
        return -1;

    const Elf_Phdr *phdrs = (const Elf_Phdr *)(buf + ehdr->e_phoff);

    uint64_t lo = UINT64_MAX, hi = 0;
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdrs[i].p_type != PT_LOAD) continue;
        uint64_t seg_lo = phdrs[i].p_vaddr;
        uint64_t seg_hi = seg_lo + phdrs[i].p_memsz;
        if (seg_lo < lo) lo = seg_lo;
        if (seg_hi > hi) hi = seg_hi;
    }
    if (lo >= hi) return -1;

    lo &= ~(uint64_t)0xfff;
    hi = (hi + 0xfff) & ~(uint64_t)0xfff;
    size_t total = (size_t)(hi - lo);

    uint8_t *base = mmap(NULL, total, PROT_READ | PROT_WRITE,
                         MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (base == MAP_FAILED) return -1;

    Elf_Addr elf_lo = (Elf_Addr)lo;

    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdrs[i].p_type != PT_LOAD) continue;
        if (phdrs[i].p_filesz > 0)
            memcpy(base + (phdrs[i].p_vaddr - elf_lo),
                   buf + phdrs[i].p_offset, phdrs[i].p_filesz);
    }

    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdrs[i].p_type != PT_DYNAMIC) continue;

        Elf_Dyn *dyn = (Elf_Dyn *)(base + (phdrs[i].p_vaddr - elf_lo));
        int dcount = phdrs[i].p_memsz / sizeof(Elf_Dyn);

        Elf_Rela *r = NULL;   size_t rsz = 0;
        Elf_Rel  *rl = NULL;  size_t rlsz = 0;
        void     *jr = NULL;  size_t jrsz = 0;
        int       plt = DT_RELA;
        Elf_Sym  *st = NULL;
        const char *str = NULL;

        for (int d = 0; d < dcount && dyn[d].d_tag != DT_NULL; d++) {
            Elf_Addr ptr = dyn[d].d_un.d_ptr;
            Elf_Addr val = dyn[d].d_un.d_val;
            switch (dyn[d].d_tag) {
            case DT_RELA:     r   = (Elf_Rela *)(base + (ptr - elf_lo)); break;
            case DT_RELASZ:   rsz = val; break;
            case DT_REL:      rl  = (Elf_Rel *)(base + (ptr - elf_lo)); break;
            case DT_RELSZ:    rlsz = val; break;
            case DT_JMPREL:   jr  = (void *)(base + (ptr - elf_lo)); break;
            case DT_PLTRELSZ: jrsz = val; break;
            case DT_PLTREL:   plt = (int)val; break;
            case DT_SYMTAB:   st  = (Elf_Sym *)(base + (ptr - elf_lo)); break;
            case DT_STRTAB:   str = (const char *)(base + (ptr - elf_lo)); break;
            }
        }

        if (r && rsz && st && str)
            apply_rela(base, elf_lo, r, rsz / sizeof(Elf_Rela), st, str);
        if (rl && rlsz)
            apply_rel(base, elf_lo, rl, rlsz / sizeof(Elf_Rel), st, str);
        if (jr && jrsz && st && str) {
            if (plt == DT_RELA)
                apply_rela(base, elf_lo, (Elf_Rela *)jr,
                           jrsz / sizeof(Elf_Rela), st, str);
            else
                apply_rel(base, elf_lo, (Elf_Rel *)jr,
                          jrsz / sizeof(Elf_Rel), st, str);
        }
        break;
    }

    LL_FLUSH_ICACHE(base, total);

    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdrs[i].p_type != PT_LOAD) continue;
        mprotect_page_aligned(base, phdrs[i].p_vaddr - elf_lo,
                              phdrs[i].p_memsz,
                              prot_from_flags(phdrs[i].p_flags));
    }

    info->base = base;
    info->size = total;
    info->entry = (uintptr_t)base + (ehdr->e_entry - elf_lo);
    info->phdr = (uintptr_t)base + ehdr->e_phoff;
    info->phent = ehdr->e_phentsize;
    info->phnum = ehdr->e_phnum;
    info->preferred_base = lo;
    return 0;
}

static void __attribute__((noreturn))
ll_jump_entry(struct ll_exec_info *info,
              char *const argv[], char *const envp[])
{
    int argc = 0;
    while (argv && argv[argc]) argc++;
    int envc = 0;
    while (envp && envp[envc]) envc++;

    size_t stack_size = 1024 * 1024;
    void *stack_base = mmap(NULL, stack_size, PROT_READ | PROT_WRITE,
                            MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (stack_base == MAP_FAILED)
        _exit(127);

    uintptr_t *sp = (uintptr_t *)((uint8_t *)stack_base + stack_size);

    /* Place 16 random bytes at the top of the stack for AT_RANDOM.
     * glibc uses these for stack canary / pointer guard init. */
    sp -= 2; /* 16 bytes */
    uintptr_t at_random_ptr = (uintptr_t)sp;
    unsigned long host_random = getauxval(AT_RANDOM);
    if (host_random)
        memcpy((void *)sp, (void *)host_random, 16);
    else
        memset((void *)sp, 0x41, 16);

    int auxc = 9 * 2 + 2;
    int total_slots = 1 + argc + 1 + envc + 1 + auxc;
    if (total_slots & 1)
        total_slots++;

    sp -= total_slots;

    uintptr_t *p = sp;
    *p++ = (uintptr_t)argc;

    for (int i = 0; i < argc; i++)
        *p++ = (uintptr_t)argv[i];
    *p++ = 0;

    for (int i = 0; i < envc; i++)
        *p++ = (uintptr_t)envp[i];
    *p++ = 0;

    *p++ = AT_BASE;   *p++ = (uintptr_t)info->base;
    *p++ = AT_ENTRY;  *p++ = info->entry;
    *p++ = AT_PHNUM;  *p++ = info->phnum;
    *p++ = AT_PHENT;  *p++ = info->phent;
    *p++ = AT_PHDR;   *p++ = info->phdr;
    *p++ = AT_PAGESZ; *p++ = (uintptr_t)getpagesize();
    *p++ = AT_RANDOM; *p++ = at_random_ptr;
    *p++ = AT_UID;    *p++ = (uintptr_t)getuid();
    *p++ = AT_EUID;   *p++ = (uintptr_t)geteuid();
    *p++ = 0; *p++ = 0;

    ll_entry_trampoline((void *)sp, (void *)info->entry);
}

pid_t libload_exec(const unsigned char *buf, size_t len,
                   char *const argv[], char *const envp[])
{
    if (!buf || len == 0 || !argv)
        return -1;

    pid_t pid = fork();
    if (pid < 0)
        return -1;

    if (pid == 0) {
        struct ll_exec_info info;
        if (ll_parse_exec(buf, len, &info) < 0)
            _exit(127);
        ll_jump_entry(&info, argv, envp ? envp : environ);
    }

    return pid;
}

int libload_run(const unsigned char *buf, size_t len,
                char *const argv[], char *const envp[])
{
    if (!buf || len == 0 || !argv)
        return -1;

    struct ll_exec_info info;
    if (ll_parse_exec(buf, len, &info) < 0)
        return -1;

    ll_jump_entry(&info, argv, envp ? envp : environ);
}

/* ------------------------------------------------------------------ */
/*  Flat binary (elf2bin) execution                                   */
/* ------------------------------------------------------------------ */

/*
 * bin_info trailer appended by elf2bin (--trailer).
 * Sits at image + image_len - sizeof(struct bin_info).
 */
struct bin_info {
#if __SIZEOF_POINTER__ == 8
    int64_t start_function;
    int64_t dynamic_linker_info;
#else
    int32_t start_function;
    int32_t dynamic_linker_info;
#endif
    char    magic_number[4];
} __attribute__((packed));

#define BIN_MAGIC "\x7f" "BIN"

static void __attribute__((noreturn))
ll_exec_bin(char *image, size_t image_len)
{
    void (*e_entry)(long *, long *);
    long stack[9] = {0};
    long *dynv;

    struct bin_info *image_info =
        (struct bin_info *)(image + image_len - sizeof(*image_info));
    e_entry = (void *)(image + image_info->start_function);

    stack[0] = 1;
    stack[1] = (intptr_t)"libc.so";
    stack[2] = 0;
    stack[3] = 0; /* empty envp */
    stack[4] = AT_BASE; stack[5] = (intptr_t)image;
    stack[6] = AT_NULL; stack[7] = 0;

    dynv = (void *)(image + image_info->dynamic_linker_info);

    e_entry(stack, dynv);
    __builtin_unreachable();
}

pid_t libload_exec_bin(const unsigned char *buf, size_t len,
                       char *const argv[], char *const envp[])
{
    (void)argv; (void)envp;

    if (!buf || len < sizeof(struct bin_info))
        return -1;

    /* Verify trailer magic */
    const struct bin_info *trl =
        (const struct bin_info *)(buf + len - sizeof(struct bin_info));
    if (memcmp(trl->magic_number, BIN_MAGIC, 4) != 0)
        return -1;

    pid_t pid = fork();
    if (pid < 0)
        return -1;

    if (pid == 0) {
        char *image = mmap(NULL, len,
                           PROT_READ | PROT_WRITE | PROT_EXEC,
                           MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        if (image == MAP_FAILED)
            _exit(127);
        memcpy(image, buf, len);
        LL_FLUSH_ICACHE(image, len);
        ll_exec_bin(image, len);
    }

    return pid;
}

int libload_run_bin(const unsigned char *buf, size_t len,
                    char *const argv[], char *const envp[])
{
    (void)argv; (void)envp;

    if (!buf || len < sizeof(struct bin_info))
        return -1;

    const struct bin_info *trl =
        (const struct bin_info *)(buf + len - sizeof(struct bin_info));
    if (memcmp(trl->magic_number, BIN_MAGIC, 4) != 0)
        return -1;

    char *image = mmap(NULL, len,
                       PROT_READ | PROT_WRITE | PROT_EXEC,
                       MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (image == MAP_FAILED)
        return -1;
    memcpy(image, buf, len);
    LL_FLUSH_ICACHE(image, len);
    ll_exec_bin(image, len);
}
