# Tools

libload includes two packing tools that convert ELF and Mach-O executables into the llbin pre-packed format. Both tools produce byte-identical output.

## llpack (C)

A C tool built as part of the standard CMake build.

### Usage

```sh
llpack <input> <output.llbin>
```

### Arguments

| Argument | Description |
|----------|-------------|
| `input` | Path to a Mach-O or ELF executable |
| `output.llbin` | Path for the output llbin file |

### Example

```sh
# Build
cmake -B build && cmake --build build

# Pack an executable
build/llpack ./myprogram myprogram.llbin

# Verify it loads
build/test_llbin myprogram.llbin
```

### Supported Input Formats

| Format | Details |
|--------|---------|
| Mach-O 64-bit | `MH_EXECUTE`, `MH_DYLIB`, `MH_BUNDLE` |
| Fat/Universal | Extracts the native architecture slice |
| ELF64 | x86_64, aarch64 |
| ELF32 | i386, ARM, MIPS, SPARC |

### What It Does

1. Parses the input binary's headers and load commands
2. Computes the flat image layout (all segments contiguous)
3. Extracts and classifies all relocations/fixups:
   - Internal pointer adjustments → `LLBIN_FIXUP_REBASE`
   - External symbol references → `LLBIN_FIXUP_IMPORT`
4. Builds the import and string tables
5. Writes the llbin file (header + image + fixup table + import table + strings + segments)

For Mach-O inputs, it processes:
- `LC_DYLD_INFO_ONLY` rebase/bind/lazy-bind opcode streams
- `LC_DYLD_CHAINED_FIXUPS` chained pointer fixups

For ELF inputs, it processes:
- `DT_RELA` / `DT_REL` relocation tables
- `DT_JMPREL` + `DT_PLTREL` PLT relocations
- Per-architecture relocation type classification

---

## lltool (Python 3)

A Python 3 tool with no external dependencies (stdlib only).

### Usage

```sh
# Pack a binary into llbin
python3 tools/lltool.py pack <input> <output.llbin>

# Inspect a binary (Mach-O, ELF, or llbin)
python3 tools/lltool.py info <file>
```

### Commands

#### `pack`

Converts a Mach-O or ELF executable into llbin format.

```sh
python3 tools/lltool.py pack ./myprogram myprogram.llbin
```

| Argument | Description |
|----------|-------------|
| `input` | Path to a Mach-O or ELF executable |
| `output` | Path for the output llbin file |

#### `info`

Displays detailed information about a binary file. Supports Mach-O, ELF, and llbin formats.

```sh
python3 tools/lltool.py info myprogram.llbin
```

#### `elf2bin`

Converts a static-pie ELF executable into a flat binary image suitable for stager loading. The output preserves the ELF header at offset 0 (for entry point and program headers) but is otherwise a flat memory dump with BSS trimmed and dead metadata zeroed.

```sh
# Convert ELF to flat binary
python3 tools/lltool.py elf2bin input.elf output.bin

# Print entry offset only
python3 tools/lltool.py elf2bin -e input.elf
```

| Argument | Description |
|----------|-------------|
| `input` | Path to a static-pie ELF executable |
| `output` | Path for the output flat binary (optional with `-e`) |
| `-e`, `--entry-only` | Print the entry point offset and exit |
| `--trailer` | Append legacy bin_info trailer |
| `--no-strip` | Keep dead metadata and trailing BSS |

The output can be loaded at runtime by:
1. `mmap(RWX, page_align(memsz))` — memsz computed from LOAD segments
2. `read(len)` into the mapping — MAP_ANONYMOUS zero-fills BSS beyond
3. Jump to `base + e_entry`

See [elf2bin.md](elf2bin.md) for format details.

### Advantage Over llpack

lltool requires only Python 3 (no compilation needed), making it useful for:
- Quickly inspecting binaries on any system with Python
- Packing in build scripts or CI pipelines
- Cross-platform use without a cross-compiler

### Verifying Equivalence

Both tools produce byte-identical output:

```sh
build/llpack ./program a.llbin
python3 tools/lltool.py pack ./program b.llbin
diff a.llbin b.llbin   # no output (identical)
```
