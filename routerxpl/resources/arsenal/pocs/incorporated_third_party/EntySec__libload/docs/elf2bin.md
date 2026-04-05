# elf2bin — Flat Binary Format

The elf2bin converter produces flat binary images from static-pie ELF executables. The output is designed for minimal stager loading — no relocation processing, no symbol resolution, just `mmap` + `memcpy` + `jump`.

## Overview

A static-pie ELF built with musl is fully self-relocating: its `_dlstart_c` entry point walks its own `PT_DYNAMIC` and applies relocations internally. This means the loader (stager) doesn't need to understand relocations at all — it just needs to:

1. Map enough memory (file data + BSS)
2. Copy the image
3. Build a minimal stack (argc, argv, envp, auxv)
4. Jump to the entry point

## Format

The output is a contiguous flat memory image indexed by virtual address. The ELF header is preserved at offset 0 so the loader can read:

- `e_entry` — entry point offset from base
- `e_phoff`, `e_phentsize`, `e_phnum` — program headers (for auxv)

### BSS Trimming

By default, elf2bin trims trailing BSS (zero-initialized data) from the output. The image only extends to the last byte of actual file data (`p_filesz`), not the full memory size (`p_memsz`). The loader's `mmap(MAP_ANONYMOUS)` zero-fills beyond, providing the BSS region automatically.

This significantly reduces wire size — a typical musl static-pie binary has 20-100KB of BSS that becomes zero bytes on the wire.

### Dead Metadata Stripping

Runtime-dead sections are zeroed for better compressibility:

- `.symtab`, `.strtab`, `.shstrtab`, `.comment` — not needed at runtime
- `.note.*` sections — not needed at runtime
- Section header table — zeroed and e_shoff/e_shnum cleared in ELF header

The `.dynstr` section is preserved (needed by the self-relocator via `DT_STRTAB`).

## Converting

```sh
# Convert with default optimizations (BSS trim + metadata strip)
python3 tools/lltool.py elf2bin input.elf output.bin

# Print entry offset only
python3 tools/lltool.py elf2bin -e input.elf

# Keep dead metadata and trailing BSS (larger output, for debugging)
python3 tools/lltool.py elf2bin --no-strip input.elf output.bin

# Append legacy bin_info trailer
python3 tools/lltool.py elf2bin --trailer input.elf output.bin
```

## Loading

### Stager Pattern

The minimal loading sequence:

```
mmap(NULL, page_align(memsz), PROT_READ|PROT_WRITE|PROT_EXEC,
     MAP_ANONYMOUS|MAP_PRIVATE, -1, 0)
recv(socket, base, file_len)        // or read from any source
jump(base + e_entry, stack)
```

Where `memsz` is computed from LOAD segments:

```
for each PT_LOAD segment:
    memsz = max(memsz, p_vaddr + p_memsz)
memsz = page_align(memsz)
```

### Auxiliary Vector

The entry point expects a System V initial stack:

```
[sp + 0]   argc
[sp + 8]   argv[0] ... argv[argc-1]
           NULL
           envp[0] ... envp[n-1]
           NULL
           AT_BASE    base_address
           AT_PHDR    base + e_phoff
           AT_PHENT   e_phentsize
           AT_PHNUM   e_phnum
           AT_PAGESZ  0x1000
           AT_RANDOM  base (or any 16 random bytes)
           AT_NULL    0
```

`AT_BASE` is required — musl's `_dlstart_c` uses it as the relocation base.

## C API

libload provides two functions for loading flat binary images directly:

```c
pid_t libload_exec_bin(const unsigned char *buf, size_t len,
                       char *const argv[], char *const envp[]);

int libload_run_bin(const unsigned char *buf, size_t len,
                    char *const argv[], char *const envp[]);
```

These work identically to `libload_exec` / `libload_run` but for flat binary images instead of full ELF executables. The image must start with a valid ELF header (preserved by elf2bin).

### Example

```c
#include <libload.h>
#include <sys/wait.h>

/* buf contains the flat binary produced by lltool elf2bin */
char *argv[] = { "program", NULL };
pid_t pid = libload_exec_bin(buf, len, argv, NULL);
if (pid > 0) {
    int status;
    waitpid(pid, &status, 0);
}
```

## Building Static-Pie Input

The input ELF must be a static-pie executable. With musl:

```sh
musl-gcc -static-pie -o program program.c
```

Or with a musl cross-compiler:

```sh
aarch64-linux-musl-gcc -static-pie -o program program.c
```

The musl runtime handles all self-relocation internally via `_dlstart_c`, making the resulting binary fully position-independent with no external dependencies.
