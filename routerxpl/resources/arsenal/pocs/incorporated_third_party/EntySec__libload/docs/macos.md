# macOS Platform

The macOS implementation provides a reflective Mach-O loader and three process injection methods using Mach ports.

## Supported Architectures

| Architecture | Binary Format | Notes |
|--------------|---------------|-------|
| arm64 (Apple Silicon) | Mach-O 64-bit, fat/universal | Primary target |
| x86_64 (Intel) | Mach-O 64-bit, fat/universal | Supported |

Only 64-bit Mach-O binaries are supported. 32-bit Mach-O is not handled.

## Mach-O Loader Internals

### Supported Binary Types

- `MH_DYLIB` — dynamic libraries (`.dylib`)
- `MH_BUNDLE` — loadable bundles (`.bundle`)
- `MH_EXECUTE` — executables

Fat/universal binaries are handled by extracting the native architecture slice.

### Loading Flow

1. **Parse headers** — handle fat headers (extract native slice), verify Mach-O magic and CPU type
2. **Allocate memory** — three strategies, tried in order:
   - **Dual-map** via `mach_vm_remap` (preferred): allocate a RW region, remap it to a second RX region pointing to the same physical pages. W^X is maintained at all times — no page is ever simultaneously writable and executable.
   - **MAP_JIT** + `pthread_jit_write_protect_np` (arm64 fallback): allocate with `MAP_JIT`, toggle between write and execute modes
   - **Plain mmap** + `mprotect` (x86_64 fallback): allocate RW, copy, then `mprotect` to RX
3. **Copy segments** — copy each `LC_SEGMENT_64` into the allocated region at its virtual offset
4. **Process fixups** — two code paths depending on the load commands present:

   **`LC_DYLD_INFO_ONLY` (legacy, pre-macOS 12):**
   - Walk the **rebase opcode stream** to adjust internal pointers by the slide
   - Walk the **bind opcode stream** to resolve external symbol references via `dlsym(RTLD_DEFAULT, name)`
   - Walk the **lazy bind opcode stream** to patch PLT-style stubs

   **`LC_DYLD_CHAINED_FIXUPS` (modern, macOS 12+):**
   - Parse the chained fixup header to find page starts
   - Walk each fixup chain: rebases add the slide, binds resolve via `dlsym`
   - Supports DYLD_CHAINED_PTR_64 and DYLD_CHAINED_PTR_ARM64E formats

5. **Resolve external symbols** — all imports are resolved via `dlsym(RTLD_DEFAULT, name)`, which searches all loaded images
6. **Run initializers** — call functions in `__mod_init_func` section (Mach-O equivalent of `.init_array`)
7. **Set protections** — apply per-segment VM protections (`VM_PROT_READ`, `VM_PROT_WRITE`, `VM_PROT_EXECUTE`)

### Dual-Map Technique

The dual-map technique is the key innovation for maintaining W^X compliance without entitlements:

```
Physical pages:  [page A] [page B] [page C] ...

Virtual mapping 1 (RW):     0x1000 → page A (writable, for fixups)
Virtual mapping 2 (RX):     0x5000 → page A (executable, for code)
```

Both mappings point to the same physical pages via `mach_vm_remap`. The loader writes through the RW mapping and the code executes from the RX mapping. No single virtual page is ever both writable and executable simultaneously.

After all fixups are applied, the RW mapping is deallocated. Only the RX mapping remains.

### Export Trie

`libload_sym` resolves symbols by walking the Mach-O export trie, a compact prefix-tree structure stored in `LC_DYLD_INFO_ONLY` or `LC_DYLD_EXPORTS_TRIE`.

The trie encodes exported symbol names with shared prefixes. Each terminal node contains the symbol's offset from the image base. The walker follows edges byte-by-byte, matching the requested symbol name.

## Process Injection

macOS provides three injection methods, all using Mach ports:

### `libload_inject` — PIC Code Injection

Injects raw position-independent code into a remote process.

**Mechanism:**
1. Obtain the target's task port via `task_for_pid`
2. `mach_vm_allocate` a region in the target
3. `mach_vm_write` the code into the region
4. `mach_vm_protect` to mark it RX
5. `thread_create_running` to start a new thread at the entry point

**Requirements:** `task_for_pid` access (root, or target built with `get-task-allow`)

**Limitation:** Fails on Hardened Runtime targets — AMFI kills the target when unsigned executable pages are created.

### `libload_inject_dylib` — Remote dlopen

Injects a signed dylib by hijacking a thread to call `dlopen`.

**Mechanism:**
1. Obtain the target's task port
2. Suspend the target, save thread state
3. Allocate memory in the target for the dylib path string
4. Set thread registers: PC → `dlopen`, x0 → path, x1 → `RTLD_NOW`, LR → BRK trap
5. Resume the thread
6. Catch the `EXC_BREAKPOINT` when `dlopen` returns (via LR → BRK)
7. Restore original thread state and resume

**Requirements:** `task_for_pid` access

**Advantage:** No new executable pages are created — only existing signed code runs. Works on Hardened Runtime targets.

### `libload_inject_spawn` — Exception Port Inheritance

Spawns a process with a dylib pre-injected using a novel zero-privilege technique.

**Mechanism:**
1. For HR targets: copy the binary, patch entry point with `BRK #1`, ad-hoc re-sign
2. For non-HR targets: prepare a trigger dylib with `__attribute__((constructor))` that executes `BRK #1`
3. Set Mach exception ports on self via `task_swap_exception_ports`
4. `fork()` — child inherits exception port registrations
5. Child exec's into the target (exception ports survive exec)
6. Target hits `BRK` → kernel delivers `EXC_BREAKPOINT` to parent with **full task control port**
7. Parent hijacks thread to `dlopen` the payload dylib
8. Catch second exception when dlopen returns, skip past the BRK, resume normally

**Requirements:** None — no root, no entitlements, no `get-task-allow`

**Limitation:** Does not work on Apple platform binaries (`/usr/bin/*`, `/System/*`) — setting exception ports on these causes SIGKILL from the kernel.

See [EXCEPTION_PORT_INJECTION.md](../EXCEPTION_PORT_INJECTION.md) for the complete technical writeup.

## Injection Method Comparison

| Method | Privileges | HR Targets | Running Process | Disk Artifacts |
|--------|-----------|------------|-----------------|----------------|
| `libload_inject` | root / get-task-allow | No (AMFI blocks) | Yes | None |
| `libload_inject_dylib` | root / get-task-allow | Yes | Yes | None |
| `libload_inject_spawn` | None | Yes (non-platform) | No (spawn only) | Temp binary copy (HR only) |

## Limitations

- **No Objective-C class registration** — ObjC metadata and class lists are not registered with the runtime. Pure ObjC method dispatch works if the class is already registered.
- **No Swift metadata** — Swift type metadata, protocol conformances, and associated type witnesses are not registered.
- **No thread-local variables (TLV)** — `__thread` / `_Thread_local` variables require dyld cooperation that is not replicated.
- **No `LC_CODE_SIGNATURE` validation** — the loader does not verify code signatures. The loaded code runs with the host process's signing identity.
- **64-bit only** — 32-bit Mach-O is not supported.
- **No `@rpath` resolution** — import lookups use `dlsym(RTLD_DEFAULT, ...)` only; `@rpath`, `@loader_path`, and `@executable_path` references in imports are not resolved.
