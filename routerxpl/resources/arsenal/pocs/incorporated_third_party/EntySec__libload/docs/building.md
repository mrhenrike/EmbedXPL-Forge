# Building libload

## Requirements

- C11 compiler (GCC or Clang)
- CMake 3.15+
- System headers (no external dependencies)
- On macOS: Xcode Command Line Tools (for Objective-C support)

## Native Build

```sh
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

This produces:

| Output | Path |
|--------|------|
| Shared library | `build/libload.so` (Linux) or `build/libload.dylib` (macOS) |
| Static library | `build/libload.a` |
| llpack tool | `build/llpack` |
| Test binaries | `build/test_exec`, `build/testexec`, etc. |

## Build Options

| CMake Variable | Default | Description |
|----------------|---------|-------------|
| `CMAKE_BUILD_TYPE` | — | `Release`, `Debug`, `RelWithDebInfo` |
| `CMAKE_C_COMPILER` | system default | C compiler path |
| `CMAKE_ASM_COMPILER` | system default | Assembler path (Linux only) |
| `CMAKE_INSTALL_PREFIX` | `/usr/local` | Installation prefix |
| `LIBLOAD_DEBUG` | `OFF` | Enable verbose debug logging to stderr |

### Debug Logging

To enable internal debug output (segment mapping, fixup details, injection steps):

```sh
cmake -B build -DLIBLOAD_DEBUG=ON
cmake --build build
```

## Cross-Compilation (Linux)

Architecture is selected at compile time. Point CMake at the appropriate cross-compiler toolchain:

### x86_64

```sh
cmake -B build -DCMAKE_C_COMPILER=x86_64-linux-gnu-gcc \
               -DCMAKE_ASM_COMPILER=x86_64-linux-gnu-gcc
cmake --build build
```

### aarch64 (ARM 64-bit)

```sh
cmake -B build -DCMAKE_C_COMPILER=aarch64-linux-gnu-gcc \
               -DCMAKE_ASM_COMPILER=aarch64-linux-gnu-gcc
cmake --build build
```

### i386 (x86 32-bit)

```sh
cmake -B build -DCMAKE_C_COMPILER=i686-linux-gnu-gcc \
               -DCMAKE_ASM_COMPILER=i686-linux-gnu-gcc
cmake --build build
```

### ARM 32-bit (little-endian)

```sh
cmake -B build -DCMAKE_C_COMPILER=arm-linux-gnueabi-gcc \
               -DCMAKE_ASM_COMPILER=arm-linux-gnueabi-gcc
cmake --build build
```

### ARM 32-bit (big-endian)

```sh
cmake -B build -DCMAKE_C_COMPILER=armeb-linux-gnueabi-gcc \
               -DCMAKE_ASM_COMPILER=armeb-linux-gnueabi-gcc
cmake --build build
```

### MIPS (little-endian)

```sh
cmake -B build -DCMAKE_C_COMPILER=mipsel-linux-gnu-gcc \
               -DCMAKE_ASM_COMPILER=mipsel-linux-gnu-gcc
cmake --build build
```

### MIPS (big-endian)

```sh
cmake -B build -DCMAKE_C_COMPILER=mips-linux-gnu-gcc \
               -DCMAKE_ASM_COMPILER=mips-linux-gnu-gcc
cmake --build build
```

### SPARC

```sh
cmake -B build -DCMAKE_C_COMPILER=sparc-linux-gnu-gcc \
               -DCMAKE_ASM_COMPILER=sparc-linux-gnu-gcc
cmake --build build
```

## Installing Cross-Compilers

On Debian/Ubuntu:

```sh
# ARM
sudo apt install gcc-arm-linux-gnueabi gcc-aarch64-linux-gnu

# MIPS
sudo apt install gcc-mipsel-linux-gnu gcc-mips-linux-gnu

# SPARC
sudo apt install gcc-sparc64-linux-gnu

# i386
sudo apt install gcc-i686-linux-gnu
```

## Installation

```sh
cmake --install build
```

Installs:
- Headers to `${prefix}/include/`
- Libraries to `${prefix}/lib/`
- `llpack` to `${prefix}/bin/`

## Linking

### pkg-config / CMake

After installation, link against `-lload`:

```sh
gcc -o myapp myapp.c -lload -ldl   # Linux
clang -o myapp myapp.c -lload      # macOS
```

### Static linking

```sh
gcc -o myapp myapp.c -Lbuild -lload -ldl -static  # Linux
```

### CMake integration

```cmake
find_library(LIBLOAD load)
target_link_libraries(myapp PRIVATE ${LIBLOAD})
```

Or link directly from the build tree:

```cmake
add_subdirectory(libload)
target_link_libraries(myapp PRIVATE libload_static)
```

## Platform-Specific Notes

### Linux

- The build uses `enable_language(ASM)` to compile entry trampolines (`.S` files)
- All six `.S` files are always included in the source list; the assembler only compiles the one matching the target architecture via `#ifdef` guards
- Links against `-ldl` for `dlsym` / `dlopen`

### macOS

- Uses `enable_language(OBJC)` for Objective-C test files
- No assembly files — macOS uses inline assembly for the entry trampoline
- No `-ldl` needed (symbols are in libSystem)

## Docker Testing

For testing on Linux from a macOS host:

```sh
# Build container
docker run --rm -it \
  --platform linux/arm64 \
  --cap-add=SYS_PTRACE \
  --security-opt seccomp=unconfined \
  -v $(pwd):/src \
  ubuntu:22.04

# Inside container
apt update && apt install -y cmake gcc
cd /src && cmake -B /tmp/build && cmake --build /tmp/build
cd /tmp/build && ./test_exec /src/examples/testexec
```

`--cap-add=SYS_PTRACE` is required for injection tests. Use `--security-opt seccomp=unconfined` to allow `process_vm_writev` and other syscalls used by the injection code.
