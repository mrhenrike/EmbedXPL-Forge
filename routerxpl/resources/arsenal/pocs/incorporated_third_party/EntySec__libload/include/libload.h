/*
 * libload — Load executables from memory without touching disk
 *
 * Linux:  Reflective ELF loader (no memfd, no /proc, no temp files)
 * macOS:  Reflective Mach-O loader (no NSBundle, no temp files)
 */

#ifndef LIBLOAD_H
#define LIBLOAD_H

#include <stddef.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct libload_ctx *libload_t;

/*
 * Load a shared library from a memory buffer.
 * Returns a handle on success, NULL on failure.
 *
 * Linux:  Reflective ELF loading — parse, map, relocate in-process.
 * macOS:  Reflective Mach-O loading into process memory.
 */
libload_t libload_open(const unsigned char *buf, size_t len);

/*
 * Resolve a symbol from a loaded library.
 * Returns the symbol address, or NULL if not found.
 */
void *libload_sym(libload_t ctx, const char *name);

/*
 * Unload a previously loaded library.
 * Returns 0 on success, -1 on failure.
 */
int libload_close(libload_t ctx);

/*
 * Execute an executable from a memory buffer in a child process.
 * Returns child PID on success, -1 on failure.
 *
 * Linux:  Fork + reflective ELF load + jump to entry point.
 * macOS:  Fork + reflective Mach-O load + jump to entry point.
 */
pid_t libload_exec(const unsigned char *buf, size_t len,
                   char *const argv[], char *const envp[]);

/*
 * Execute an executable from a memory buffer, replacing the current
 * process. Does NOT fork — this function does not return on success.
 * Returns -1 on failure.
 *
 * Linux:  Reflective ELF load + jump to entry point in-place.
 * macOS:  Reflective Mach-O load + jump to entry point in-place.
 */
int libload_run(const unsigned char *buf, size_t len,
                char *const argv[], char *const envp[]);

/*
 * Execute a flat binary image (produced by lltool elf2bin --trailer)
 * in a child process. The image must have a bin_info trailer with
 * start_function, dynamic_linker_info offsets, and \x7fBIN magic.
 *
 * Returns child PID on success, -1 on failure.
 */
pid_t libload_exec_bin(const unsigned char *buf, size_t len,
                       char *const argv[], char *const envp[]);

/*
 * Execute a flat binary image, replacing the current process.
 * Does NOT fork — this function does not return on success.
 * Returns -1 on failure.
 */
int libload_run_bin(const unsigned char *buf, size_t len,
                    char *const argv[], char *const envp[]);

#ifdef __APPLE__

#include <stdint.h>

/*
 * Inject position-independent code into a remote process and execute it.
 *
 * Allocates memory in the target, writes the code, marks it RX, and
 * creates a new thread at entry_offset. arg is passed in x0.
 *
 * Requires task_for_pid access (root, or target has get-task-allow).
 * Fails on Hardened Runtime targets (AMFI kills on unsigned RX pages).
 *
 * Returns 0 on success, -1 on failure.
 */
int libload_inject(pid_t pid, const void *code, size_t len,
                   size_t entry_offset, uint64_t arg);

/*
 * Inject a dylib into a remote process by triggering dlopen().
 *
 * Creates a thread in the target that calls dlopen(path, RTLD_NOW).
 * No new executable pages are created — only existing signed code runs.
 * Works on Hardened Runtime / AMFI-protected processes.
 *
 * Requires task_for_pid access (root, or target has get-task-allow).
 *
 * Returns 0 on success, -1 on failure.
 */
int libload_inject_dylib(pid_t pid, const char *dylib_path);

/*
 * Spawn a process with a dylib injected via Mach exception ports.
 *
 * Novel zero-privilege injection vector:
 *   1. Copies target binary, patches entry point with BRK trap
 *   2. Spawns with posix_spawnattr_setexceptionports_np (private API)
 *   3. Catches exception → receives full task + thread Mach ports
 *   4. Thread-hijacks to call dlopen(dylib_path, RTLD_NOW)
 *   5. Resumes target normally via trampoline
 *
 * Requires: NO root, NO entitlements, NO get-task-allow.
 * Works on: Hardened Runtime binaries (non-platform).
 * Does NOT work on: Apple-signed platform binaries (/usr/bin etc.)
 *
 * Returns spawned PID on success, -1 on failure.
 */
pid_t libload_inject_spawn(const char *target_path,
                           const char *dylib_path,
                           char *const argv[],
                           char *const envp[]);

#endif /* __APPLE__ */

#ifdef __linux__

#include <stdint.h>

/*
 * Inject position-independent code into a remote process via ptrace.
 *
 * Uses syscall proxying: attaches via ptrace, executes mmap/mprotect
 * in the target via its own syscall instruction, writes code via
 * process_vm_writev, creates a new thread via remote clone().
 *
 * Requires: ptrace access (Yama scope 0 for non-child, or CAP_SYS_PTRACE).
 *
 * Returns 0 on success, -1 on failure.
 */
int libload_inject(pid_t pid, const void *code, size_t len,
                   size_t entry_offset, uint64_t arg);

/*
 * Inject a shared library into a remote process by triggering dlopen().
 *
 * Attaches via ptrace, hijacks a thread to call dlopen(path, RTLD_NOW),
 * catches the return, and restores original state.
 *
 * Requires: ptrace access (Yama scope 0 for non-child, or CAP_SYS_PTRACE).
 *
 * Returns 0 on success, -1 on failure.
 */
int libload_inject_dylib(pid_t pid, const char *so_path);

/*
 * Spawn a process with a shared library injected via LD_PRELOAD.
 *
 * Simple fork + execve with LD_PRELOAD environment variable set.
 * The dynamic linker loads the .so before main(), running constructors.
 *
 * Requires: NO privileges.
 * Limitation: Does not work on statically-linked or setuid binaries.
 *
 * Returns spawned PID on success, -1 on failure.
 */
pid_t libload_inject_spawn(const char *target_path,
                           const char *so_path,
                           char *const argv[],
                           char *const envp[]);

#endif /* __linux__ */

#ifdef __cplusplus
}
#endif

#endif /* LIBLOAD_H */
