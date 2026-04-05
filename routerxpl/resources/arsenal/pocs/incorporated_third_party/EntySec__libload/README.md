# libload

A minimal C library for loading executables and shared libraries from memory — **without writing anything to disk**. Supports reflective loading, in-memory execution, and process injection on Linux and macOS.

## Features

- **Reflective loading** — load ELF/Mach-O shared libraries directly from a memory buffer
- **In-memory execution** — fork+exec or replace the current process from a buffer
- **Process injection** — inject code or libraries into running processes (ptrace on Linux, Mach ports on macOS)
- **Zero disk artifacts** — no temp files, no `memfd_create`, no `/proc/self/fd`
- **llbin format** — pre-packed flat binary for fast runtime loading
- **Multi-architecture** — see platform table below

## Supported Platforms

| Platform | Architectures | Loader |
|----------|---------------|--------|
| **Linux** | x86_64, aarch64, i386, arm (LE/BE), mips (LE/BE), sparc | Reflective ELF loader |
| **macOS** | arm64, x86_64 | Reflective Mach-O loader (dual-map, chained fixups, export trie) |

## Quick Start

### Build

```sh
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

Enable debug logging (segment mapping, fixup details, injection steps):

```sh
cmake -B build -DLIBLOAD_DEBUG=ON
cmake --build build
```

Cross-compile for a different Linux architecture by pointing CMake at the appropriate toolchain:

```sh
cmake -B build -DCMAKE_C_COMPILER=mipsel-linux-gnu-gcc \
               -DCMAKE_ASM_COMPILER=mipsel-linux-gnu-gcc
cmake --build build
```

### Load a shared library from memory

```c
#include <libload.h>

/* Read .so / .dylib into buf... */
libload_t lib = libload_open(buf, len);
void (*func)(void) = libload_sym(lib, "my_function");
func();
libload_close(lib);
```

### Execute a binary from memory

```c
#include <libload.h>

/* Read executable into buf... */
char *argv[] = { "program", NULL };

/* Fork + exec (returns child PID) */
pid_t pid = libload_exec(buf, len, argv, NULL);
waitpid(pid, &status, 0);

/* Or replace current process (does not return on success) */
libload_run(buf, len, argv, NULL);
```

### Inject a library into a running process

```c
#include <libload.h>

/* Linux: ptrace + remote dlopen (requires CAP_SYS_PTRACE or yama scope 0) */
/* macOS: Mach task ports + thread hijack (requires task_for_pid access) */
libload_inject_dylib(target_pid, "/path/to/payload.so");
```

### Inject at spawn time (no privileges)

```c
#include <libload.h>

/* Linux: LD_PRELOAD    macOS: exception port inheritance */
char *argv[] = { "target", NULL };
pid_t pid = libload_inject_spawn("/path/to/target", "/path/to/payload.so",
                                  argv, NULL);
```

## API Overview

```c
/* Loading */
libload_t libload_open(const unsigned char *buf, size_t len);
void     *libload_sym(libload_t ctx, const char *name);
int       libload_close(libload_t ctx);

/* Execution */
pid_t     libload_exec(const unsigned char *buf, size_t len,
                       char *const argv[], char *const envp[]);
int       libload_run(const unsigned char *buf, size_t len,
                      char *const argv[], char *const envp[]);

/* Flat binary execution (Linux, for elf2bin images) */
pid_t     libload_exec_bin(const unsigned char *buf, size_t len,
                           char *const argv[], char *const envp[]);
int       libload_run_bin(const unsigned char *buf, size_t len,
                          char *const argv[], char *const envp[]);

/* Injection (platform-specific) */
int       libload_inject(pid_t pid, const void *code, size_t len,
                         size_t entry_offset, uint64_t arg);
int       libload_inject_dylib(pid_t pid, const char *lib_path);
pid_t     libload_inject_spawn(const char *target, const char *lib_path,
                               char *const argv[], char *const envp[]);
```

## llbin Pre-Packed Format

Pack executables offline into a flat binary that loads instantly at runtime:

```sh
# C packer
build/llpack input_executable output.llbin

# Python packer (byte-identical output)
python3 tools/lltool.py pack input_executable output.llbin
python3 tools/lltool.py info output.llbin
```

`libload_open` and `libload_exec` auto-detect llbin magic and use the fast path.

## elf2bin — Flat Binary Images

Convert static-pie ELF executables into minimal flat binary images for stager loading:

```sh
python3 tools/lltool.py elf2bin input.elf output.bin
```

Load with `libload_exec_bin` / `libload_run_bin`, or directly from a stager via `mmap` + `memcpy` + `jump`.

## Documentation

Detailed documentation is available in the [docs/](docs/) directory:

- [Building](docs/building.md) — build instructions and cross-compilation
- [API Reference](docs/api-reference.md) — complete function reference
- [Linux Platform](docs/linux.md) — ELF loader, injection, architecture support
- [macOS Platform](docs/macos.md) — Mach-O loader, injection, dual-map technique
- [llbin Format](docs/llbin-format.md) — binary format specification
- [elf2bin Format](docs/elf2bin.md) — flat binary format and C API
- [Tools](docs/tools.md) — llpack and lltool usage

## Limitations

- macOS: Swift metadata registration is not handled
- macOS: Only 64-bit Mach-O binaries are supported

## License

See [LICENSE](LICENSE) for details.
