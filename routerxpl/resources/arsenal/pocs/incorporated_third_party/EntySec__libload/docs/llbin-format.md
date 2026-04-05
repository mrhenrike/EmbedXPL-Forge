# llbin Format Specification

The llbin format is a pre-packed flat binary produced offline from ELF or Mach-O executables. All complex binary parsing is done once at pack time. The runtime loader simply allocates memory, copies the image, applies fixups, and jumps to the entry point.

## Motivation

Reflective loading of ELF and Mach-O binaries requires substantial parsing: segment mapping, relocation processing, symbol resolution, chained fixup decoding, opcode stream interpretation, etc. The llbin format moves all of this complexity offline, producing a simple flat image with a trivial fixup table that can be applied in a tight loop.

Benefits:
- **Smaller runtime code** — the llbin loader is ~100 lines vs. thousands for the full ELF/Mach-O loaders
- **Faster loading** — single memcpy + linear fixup walk
- **Cross-platform** — same format works on Linux and macOS
- **Deterministic** — the C and Python packers produce byte-identical output

## Magic and Detection

```
Offset  Size  Value
0       4     0x4E424C4C ("LLBN" in little-endian)
```

`libload_open` and `libload_exec` check for this magic and use the llbin fast path when detected.

## File Layout

```
┌─────────────────────────────┐  offset 0
│        llbin_header         │  (68 bytes)
├─────────────────────────────┤  header.image_off
│        Flat Image           │  (header.image_size bytes, page-aligned)
├─────────────────────────────┤  header.fixup_off
│        Fixup Table          │  (header.fixup_count × 16 bytes)
├─────────────────────────────┤  header.import_off
│        Import Table         │  (header.import_count × 8 bytes)
├─────────────────────────────┤  header.strings_off
│        String Table         │  (header.strings_size bytes)
├─────────────────────────────┤  (optional, if seg_count > 0)
│        Segment Table        │  (header.seg_count × 16 bytes)
└─────────────────────────────┘
```

## Header

```c
struct llbin_header {
    uint32_t magic;           /* 0x4E424C4C ("LLBN")                    */
    uint32_t version;         /* Format version (currently 1)            */
    uint32_t arch;            /* CPU type (e.g. CPU_TYPE_ARM64, EM_X86_64) */
    uint32_t flags;           /* Reserved (0)                            */
    uint64_t entry_off;       /* Entry point offset within flat image    */
    uint64_t image_size;      /* Runtime allocation size (page-aligned)  */
    uint64_t preferred_base;  /* Preferred load address for slide calc   */
    uint32_t image_off;       /* File offset of flat image data          */
    uint32_t fixup_off;       /* File offset of fixup table              */
    uint32_t fixup_count;     /* Number of fixup entries                 */
    uint32_t import_off;      /* File offset of import table             */
    uint32_t import_count;    /* Number of import entries                */
    uint32_t strings_off;     /* File offset of string table             */
    uint32_t strings_size;    /* Size of string table in bytes           */
    uint32_t seg_count;       /* Number of segment entries (0 = none)    */
};
```

Total: 68 bytes.

### `arch` Field

For Mach-O sources, this is the Mach-O CPU type constant:
- `CPU_TYPE_ARM64` (0x0100000C)
- `CPU_TYPE_X86_64` (0x01000007)

For ELF sources, this is the ELF machine type:
- `EM_X86_64` (62)
- `EM_AARCH64` (183)
- `EM_386` (3)
- `EM_ARM` (40)
- `EM_MIPS` (8)
- `EM_SPARC` (2) / `EM_SPARC32PLUS` (18)

### `preferred_base`

The virtual address where the original binary expected to be loaded. The runtime slide is computed as:

```
slide = actual_load_address - preferred_base
```

All `LLBIN_FIXUP_REBASE` entries add this slide to the slot value.

## Fixup Table

```c
struct llbin_fixup {
    uint32_t offset;       /* Offset within flat image to patch          */
    uint8_t  type;         /* LLBIN_FIXUP_REBASE (0) or _IMPORT (1)     */
    uint8_t  reserved;
    uint16_t import_idx;   /* Index into import table (for _IMPORT)      */
    int64_t  addend;       /* Addend for _IMPORT fixups                  */
};
```

Size: 16 bytes per entry.

### Fixup Types

**`LLBIN_FIXUP_REBASE` (0):**

Adjusts an internal pointer by the load slide.

```
slot = image + fixup.offset
*slot += slide
```

On ELF32 targets, the slot is 4 bytes (`uint32_t *`); on ELF64 and Mach-O, it's 8 bytes (`uint64_t *`).

**`LLBIN_FIXUP_IMPORT` (1):**

Resolves an external symbol and writes its address (plus addend) to the slot.

```
slot = image + fixup.offset
name = strings + imports[fixup.import_idx].name_off
*slot = dlsym(RTLD_DEFAULT, name) + fixup.addend
```

## Import Table

```c
struct llbin_import {
    uint32_t name_off;     /* Offset into string table                   */
    uint32_t flags;        /* Reserved (0)                               */
};
```

Size: 8 bytes per entry.

Each entry references a NUL-terminated symbol name in the string table.

## Segment Table (Optional)

```c
struct llbin_segment {
    uint32_t offset;       /* Offset within flat image                   */
    uint32_t size;         /* Size in bytes (page-aligned)               */
    uint32_t prot;         /* VM protection flags                        */
    uint32_t pad;          /* Padding                                    */
};
```

Size: 16 bytes per entry. Present only when `seg_count > 0`.

Protection flags use the standard VM_PROT constants:
- `VM_PROT_READ` (1)
- `VM_PROT_WRITE` (2)
- `VM_PROT_EXECUTE` (4)

## String Table

A blob of NUL-terminated C strings. Import entries reference strings by their byte offset within this table.

## Runtime Loading Algorithm

```
1. Verify magic == LLBN, version == 1
2. Allocate image_size bytes (mmap, MAP_JIT if available)
3. Copy flat image from file offset image_off
4. Compute slide = load_address - preferred_base
5. For each fixup:
     if type == REBASE:
       *(slot_t*)(image + offset) += slide
     if type == IMPORT:
       name = strings + imports[import_idx].name_off
       *(slot_t*)(image + offset) = dlsym(RTLD_DEFAULT, name) + addend
6. If seg_count > 0, apply per-segment protections via mprotect
   Otherwise, set entire region to RX
7. Flush instruction cache (architecture-dependent)
8. Entry point = image + entry_off
```

## Packing Tools

Two tools produce llbin files:

- **llpack** (C) — `build/llpack input output.llbin`
- **lltool** (Python3) — `python3 tools/lltool.py pack input output.llbin`

Both produce byte-identical output. See [tools.md](tools.md) for detailed usage.

## Inspecting llbin Files

```sh
python3 tools/lltool.py info output.llbin
```

Prints header fields, fixup counts, import names, and segment layout.
