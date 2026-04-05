# Linux Platform

The Linux implementation provides a reflective ELF loader and ptrace-based process injection, supporting six architectures.

## Supported Architectures

| Architecture | ELF Class | Pointer Size | Relocation Style | Entry Trampoline |
|--------------|-----------|-------------|------------------|------------------|
| x86_64 | ELF64 | 8 bytes | RELA | `entry_x86_64.S` |
| aarch64 | ELF64 | 8 bytes | RELA | `entry_aarch64.S` |
| i386 | ELF32 | 4 bytes | REL | `entry_x86.S` |
| ARM (LE/BE) | ELF32 | 4 bytes | REL | `entry_arm.S` |
| MIPS (LE/BE) | ELF32 | 4 bytes | REL | `entry_mips.S` |
| SPARC | ELF32 | 4 bytes | RELA | `entry_sparc.S` |

Architecture is selected at compile time via the compiler's predefined macros. A single build targets exactly one architecture.

## ELF Loader Internals

### ELF32/64 Type Bridge

The loader uses a compile-time type bridge to handle both ELF32 and ELF64 transparently:

```c
#if __SIZEOF_POINTER__ == 8
  typedef Elf64_Ehdr   Elf_Ehdr;
  typedef Elf64_Phdr   Elf_Phdr;
  typedef Elf64_Dyn    Elf_Dyn;
  typedef Elf64_Sym    Elf_Sym;
  typedef Elf64_Rela   Elf_Rela;
  typedef Elf64_Rel    Elf_Rel;
  typedef Elf64_Addr   Elf_Addr;
  // ...
#else
  typedef Elf32_Ehdr   Elf_Ehdr;
  // ... (32-bit equivalents)
#endif
```

This means `Elf_Addr` is `uint32_t` on 32-bit targets and `uint64_t` on 64-bit, and all pointer-sized slots in relocations are handled correctly.

### Loading Flow

1. **Parse ELF header** — verify magic, class (32/64), machine type
2. **Map LOAD segments** — `mmap` each `PT_LOAD` segment at the correct virtual offset. For `ET_DYN` (shared objects), the base address is chosen by the kernel. For `ET_EXEC`, segments are mapped at their specified virtual addresses.
3. **Process DYNAMIC section** — walk `PT_DYNAMIC` to find:
   - `DT_SYMTAB`, `DT_STRTAB`, `DT_SYMENT` — symbol table
   - `DT_GNU_HASH` or `DT_HASH` — hash table for symbol lookup
   - `DT_RELA` / `DT_REL` — relocation tables
   - `DT_JMPREL` + `DT_PLTREL` — PLT relocations (may be REL or RELA)
   - `DT_INIT`, `DT_INIT_ARRAY` — constructors
4. **Apply relocations** — for each relocation entry:
   - Classify as relative or import using per-architecture functions
   - Relative: `*slot += base` (adjusts internal pointers)
   - Import: `*slot = dlsym(RTLD_DEFAULT, name) + addend`
5. **Flush instruction cache** — on architectures with non-coherent I/D caches (ARM, MIPS, SPARC), issue `__builtin___clear_cache`
6. **Run constructors** — call `DT_INIT`, then each function in `DT_INIT_ARRAY`
7. **Return handle** — the context stores the load base, segment map, and dynamic tables for later `libload_sym` calls

### Relocation Types by Architecture

| Architecture | Relative | Global Data | Jump Slot | Absolute |
|-------------|----------|-------------|-----------|----------|
| x86_64 | `R_X86_64_RELATIVE` (8) | `R_X86_64_GLOB_DAT` (6) | `R_X86_64_JUMP_SLOT` (7) | `R_X86_64_64` (1) |
| aarch64 | `R_AARCH64_RELATIVE` (1027) | `R_AARCH64_GLOB_DAT` (1025) | `R_AARCH64_JUMP_SLOT` (1026) | `R_AARCH64_ABS64` (257) |
| i386 | `R_386_RELATIVE` (8) | `R_386_GLOB_DAT` (6) | `R_386_JMP_SLOT` (7) | `R_386_32` (1) |
| ARM | `R_ARM_RELATIVE` (23) | `R_ARM_GLOB_DAT` (21) | `R_ARM_JUMP_SLOT` (22) | `R_ARM_ABS32` (2) |
| MIPS | `R_MIPS_REL32` (3)¹ | `R_MIPS_GLOB_DAT` (51) | `R_MIPS_JUMP_SLOT` (127) | `R_MIPS_32` (2) |
| SPARC | `R_SPARC_RELATIVE` (22) | `R_SPARC_GLOB_DAT` (20) | `R_SPARC_JMP_SLOT` (21) | `R_SPARC_32` (3) |

¹ MIPS uses `R_MIPS_REL32` for both relative and import relocations. When `sym == 0`, it's treated as relative; when `sym > 0`, it's an import.

### REL vs RELA

- **RELA** (used by x86_64, aarch64, SPARC): addend is stored in the relocation entry itself (`r_addend` field)
- **REL** (used by i386, ARM, MIPS): addend is implicit — read from the slot before applying the relocation

The `DT_PLTREL` tag specifies whether the PLT relocation table (`DT_JMPREL`) uses REL or RELA format, which is dispatched at runtime.

## Entry Trampolines

When executing a complete ELF binary via `libload_exec` or `libload_run`, the loader must set up the initial process stack exactly as the kernel would. Each architecture has a `.S` file that:

1. Receives the stack pointer and entry point as function arguments
2. Switches to the prepared stack
3. Jumps to the entry point

The initial stack layout follows the System V ABI:

```
[top of stack]
  NULL                  (end of auxv)
  auxv entries...       (AT_PAGESZ, AT_PHDR, etc.)
  NULL                  (end of envp)
  envp[n-1]
  ...
  envp[0]
  NULL                  (end of argv)
  argv[argc-1]
  ...
  argv[0]
  argc                  (integer)
[stack pointer →]
```

### Architecture-Specific Details

**x86_64**: Arguments in `rdi` (stack) and `rsi` (entry). SysV ABI.

**aarch64**: Arguments in `x0` (stack) and `x1` (entry). AAPCS.

**i386**: Arguments on the stack (cdecl). The trampoline pops them before switching.

**ARM**: Arguments in `r0` (stack) and `r1` (entry). Uses `BX` for Thumb interwork compatibility.

**MIPS**: Arguments in `$a0` (stack) and `$a1` (entry). Sets `$t9 = entry` for PIC convention (MIPS uses `$t9` as the static chain register). Includes delay slot handling.

**SPARC**: Arguments in `%o0` (stack) and `%o1` (entry). Includes delay slot handling.

## Symbol Resolution

`libload_sym` looks up exported symbols in the loaded ELF's dynamic symbol table:

1. If `DT_GNU_HASH` is present, use the GNU hash algorithm (bloom filter + bucket chains)
2. Otherwise fall back to `DT_HASH` (SysV hash)
3. Match the name in `DT_STRTAB`
4. Return `base + sym.st_value`

## Instruction Cache Flushing

On architectures with separate instruction and data caches (ARM, MIPS, SPARC), the loader issues `__builtin___clear_cache()` after writing code. On x86/x86_64, this is a no-op since the caches are coherent.

The `LL_FLUSH_ICACHE` macro handles this:

```c
#if defined(__arm__) || defined(__mips__) || defined(__sparc__)
  #define LL_FLUSH_ICACHE(start, end) __builtin___clear_cache((char*)(start), (char*)(end))
#else
  #define LL_FLUSH_ICACHE(start, end) ((void)0)
#endif
```

## Limitations

- Only dynamic executables (those with a `PT_DYNAMIC` segment) are supported for `libload_open`. Statically-linked executables can be executed via `libload_exec`/`libload_run` or converted to flat binaries via `lltool elf2bin` and executed with `libload_exec_bin`/`libload_run_bin`.
- `libload_open` requires the ELF to be a shared object (`ET_DYN`) or position-independent executable
- Thread-local storage (`PT_TLS`) is not handled
- MIPS `R_MIPS_REL32` with non-zero symbol is treated as absolute import; more exotic MIPS relocation types are not supported

## Process Injection

Three injection methods are available on Linux, all based on ptrace.

### Privilege Requirements

| Method | Requirement |
|--------|-------------|
| `libload_inject` | ptrace access (Yama scope 0, `CAP_SYS_PTRACE`, or target is direct child) |
| `libload_inject_dylib` | Same |
| `libload_inject_spawn` | **None** |

### `libload_inject` — PIC Code Injection

Uses ptrace to proxy syscalls in the target: `mmap` (allocate RW), `process_vm_writev` (copy code), `mprotect` (RW→RX), `clone` (new thread at entry). The injector scans the target's executable memory for the architecture-specific syscall instruction to use as a gadget.

| Architecture | Syscall Instruction |
|-------------|---------------------|
| x86_64 | `syscall` (`0F 05`) |
| aarch64 | `svc #0` (`01 00 00 D4`) |
| i386 | `int 0x80` (`CD 80`) |
| ARM | `svc #0` (`00 00 00 EF` / `00 DF` Thumb) |
| MIPS | `syscall` (`0C 00 00 00`) |
| SPARC | `ta 0x10` (`91 D0 20 10`) |

### `libload_inject_dylib` — Remote dlopen

Attaches via ptrace, hijacks thread registers to call `dlopen(path, RTLD_NOW)` in the target, catches the trap on return, restores registers. Resolves `dlopen` address by parsing `/proc/<pid>/maps` + libc symbol tables.

### `libload_inject_spawn` — LD_PRELOAD

Forks, sets the `LD_PRELOAD` environment variable to the `.so` path, then `execve`s the target. The dynamic linker loads the library before `main()`.

**Limitations:** Does not work on statically-linked or setuid binaries.

## Flat Binary Execution

`libload_exec_bin` and `libload_run_bin` execute flat binary images produced by `lltool elf2bin`. These are static-pie ELF executables flattened to a contiguous image with BSS trimmed. The loader reads the preserved ELF header for entry point and program header info, computes total memsz from LOAD segments, maps RWX memory, copies the image, builds the initial stack with auxv, and jumps to the entry point.

See [elf2bin.md](elf2bin.md) for format details and the C API.
