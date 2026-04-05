/*
 * inject.c — macOS arm64 process injection via Mach task ports
 *
 * Three injection methods:
 *
 *   1. libload_inject()       — Direct PIC code injection.
 *      Allocates RW in target, writes code, promotes to RX, creates thread.
 *      Works on non-HR targets (SIP ok, AMFI kills HR targets).
 *
 *   2. libload_inject_dylib() — Thread-hijack remote dlopen().
 *      Hijacks an existing thread in the target, redirects it to call
 *      dlopen(path, RTLD_NOW), waits, then restores original state.
 *      NO new executable pages — only calls existing signed code.
 *      Works on HR/AMFI-protected targets.
 *
 *   3. libload_inject_spawn() — Spawn-time injection via exception ports.
 *      Uses public APIs only (task_swap_exception_ports + fork + exec).
 *      Exception ports survive fork+exec, delivering task+thread ports.
 *      Non-HR targets: DYLD_INSERT trigger dylib (no binary patching).
 *      HR targets: binary copy + entry BRK patch + ad-hoc re-sign.
 *      Thread-hijack to call dlopen, resume via trampoline/skip.
 *      NO root, NO entitlements, NO private APIs. Works on HR binaries.
 *
 * Methods 1-2 require task_for_pid access:
 *   - Root can access non-platform binaries (SIP-ok)
 *   - Target with com.apple.security.get-task-allow: any same-user caller
 *   - Platform binaries (Apple-signed): off-limits even to root w/ SIP
 *
 * Method 3 requires NO privileges — spawns a new instance with dylib.
 */

#ifdef __APPLE__

#include "libload.h"

#include <stdio.h>

#ifdef LIBLOAD_DEBUG
  #define LL_DBG(...) fprintf(stderr, __VA_ARGS__)
#else
  #define LL_DBG(...) ((void)0)
#endif
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <dlfcn.h>
#include <sys/wait.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/thread_act.h>
#include <mach/thread_status.h>

extern char **environ;

#define PAGE_SZ 16384
#define STACK_SZ (64 * 1024)

#define ALIGN_UP(x, a) (((x) + (a) - 1) & ~((a) - 1))

/* ------------------------------------------------------------------ */
/* libload_inject — Direct code injection                             */
/*                                                                    */
/* Allocates RW in target, writes PIC code, protects RX, creates      */
/* thread at entry. Works for non-HR targets on SIP-enabled systems.  */
/* ------------------------------------------------------------------ */
int libload_inject(pid_t pid, const void *code, size_t len,
                   size_t entry_offset, uint64_t arg)
{
    if (!code || len == 0 || entry_offset >= len)
        return -1;

    mach_port_t task = MACH_PORT_NULL;
    kern_return_t kr;

    /* 1. Get target task port */
    kr = task_for_pid(mach_task_self(), pid, &task);
    if (kr != KERN_SUCCESS) {
        LL_DBG("inject: task_for_pid(%d) failed: kr=%d (%s)\n",
               pid, kr, mach_error_string(kr));
        return -1;
    }

    /* 2. Allocate code + stack in target */
    size_t code_sz = ALIGN_UP(len, PAGE_SZ);
    size_t total = code_sz + STACK_SZ;

    mach_vm_address_t remote = 0;
    kr = mach_vm_allocate(task, &remote, total, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        LL_DBG("inject: mach_vm_allocate failed: kr=%d\n", kr);
        mach_port_deallocate(mach_task_self(), task);
        return -1;
    }

    /* 3. Write code to target */
    kr = mach_vm_write(task, remote, (vm_offset_t)code, (mach_msg_type_number_t)len);
    if (kr != KERN_SUCCESS) {
        LL_DBG("inject: mach_vm_write failed: kr=%d\n", kr);
        mach_vm_deallocate(task, remote, total);
        mach_port_deallocate(mach_task_self(), task);
        return -1;
    }

    /* 4. Protect code region as RX */
    kr = mach_vm_protect(task, remote, code_sz, FALSE,
                         VM_PROT_READ | VM_PROT_EXECUTE);
    if (kr != KERN_SUCCESS) {
        LL_DBG("inject: mach_vm_protect RX failed: kr=%d\n", kr);
        mach_vm_deallocate(task, remote, total);
        mach_port_deallocate(mach_task_self(), task);
        return -1;
    }

    /* Stack is at remote + code_sz, already RW.
     * Stack grows downward — SP points to top. */
    mach_vm_address_t stack_top = remote + total;

    /* 5. Create remote thread */
    arm_thread_state64_t state;
    memset(&state, 0, sizeof(state));

    arm_thread_state64_set_pc_fptr(state,
        (void *)(uintptr_t)(remote + entry_offset));
    arm_thread_state64_set_sp(state,
        (void *)(uintptr_t)stack_top);
    arm_thread_state64_set_lr_fptr(state, (void *)(uintptr_t)0);
    state.__x[0] = arg;

    thread_act_t thread = MACH_PORT_NULL;
    kr = thread_create_running(task, ARM_THREAD_STATE64,
                               (thread_state_t)&state,
                               ARM_THREAD_STATE64_COUNT, &thread);
    if (kr != KERN_SUCCESS) {
        LL_DBG("inject: thread_create_running failed: kr=%d\n", kr);
        mach_vm_deallocate(task, remote, total);
        mach_port_deallocate(mach_task_self(), task);
        return -1;
    }

    mach_port_deallocate(mach_task_self(), thread);
    mach_port_deallocate(mach_task_self(), task);
    return 0;
}

/* ------------------------------------------------------------------ */
/* libload_inject_dylib — Thread-hijack remote dlopen() injection     */
/*                                                                    */
/* Hijacks an existing thread in the target process:                  */
/*   1. Suspend target's main thread                                  */
/*   2. Save its full register state                                  */
/*   3. Redirect PC to dlopen(path, RTLD_NOW), LR to pause()         */
/*   4. Resume — dlopen loads the dylib, constructor runs             */
/*   5. Re-suspend, restore original state, resume                   */
/*                                                                    */
/* No new executable pages. Only calls existing signed functions in   */
/* the shared cache. Works on HR/AMFI-protected targets.              */
/*                                                                    */
/* The shared cache has a per-boot ASLR slide that's identical across */
/* all processes, so function addresses from our process are valid    */
/* in the target.                                                     */
/* ------------------------------------------------------------------ */
int libload_inject_dylib(pid_t pid, const char *dylib_path)
{
    if (!dylib_path || !dylib_path[0])
        return -1;

    mach_port_t task = MACH_PORT_NULL;
    kern_return_t kr;

    /* Resolve shared cache addresses — valid in all processes */
    void *dlopen_addr = dlsym(RTLD_DEFAULT, "dlopen");
    if (!dlopen_addr) {
        LL_DBG("inject_dylib: cannot resolve dlopen\n");
        return -1;
    }

    /* 1. Get target task port */
    kr = task_for_pid(mach_task_self(), pid, &task);
    if (kr != KERN_SUCCESS) {
        LL_DBG("inject_dylib: task_for_pid(%d) failed: kr=%d (%s)\n",
               pid, kr, mach_error_string(kr));
        return -1;
    }

    /* 2. Allocate RW memory in target for the path string */
    size_t path_len = strlen(dylib_path) + 1;
    size_t alloc_sz = ALIGN_UP(path_len, PAGE_SZ);

    mach_vm_address_t remote_path = 0;
    kr = mach_vm_allocate(task, &remote_path, alloc_sz, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        LL_DBG("inject_dylib: mach_vm_allocate failed: kr=%d\n", kr);
        mach_port_deallocate(mach_task_self(), task);
        return -1;
    }

    kr = mach_vm_write(task, remote_path, (vm_offset_t)dylib_path,
                       (mach_msg_type_number_t)path_len);
    if (kr != KERN_SUCCESS) {
        LL_DBG("inject_dylib: mach_vm_write failed: kr=%d\n", kr);
        mach_vm_deallocate(task, remote_path, alloc_sz);
        mach_port_deallocate(mach_task_self(), task);
        return -1;
    }

    /* 3. Get target's threads and pick the first one */
    thread_act_array_t threads = NULL;
    mach_msg_type_number_t thread_count = 0;
    kr = task_threads(task, &threads, &thread_count);
    if (kr != KERN_SUCCESS || thread_count == 0) {
        LL_DBG("inject_dylib: task_threads failed: kr=%d count=%d\n",
               kr, thread_count);
        mach_vm_deallocate(task, remote_path, alloc_sz);
        mach_port_deallocate(mach_task_self(), task);
        return -1;
    }

    thread_act_t target_thread = threads[0];

    /* Free the thread list (keep target_thread port) */
    for (mach_msg_type_number_t i = 1; i < thread_count; i++)
        mach_port_deallocate(mach_task_self(), threads[i]);
    vm_deallocate(mach_task_self(), (vm_address_t)threads,
                  thread_count * sizeof(thread_act_t));

    /* 4. Suspend the thread */
    kr = thread_suspend(target_thread);
    if (kr != KERN_SUCCESS) {
        LL_DBG("inject_dylib: thread_suspend failed: kr=%d\n", kr);
        mach_vm_deallocate(task, remote_path, alloc_sz);
        mach_port_deallocate(mach_task_self(), target_thread);
        mach_port_deallocate(mach_task_self(), task);
        return -1;
    }

    /* 5. Save original thread state */
    arm_thread_state64_t orig_state;
    mach_msg_type_number_t state_count = ARM_THREAD_STATE64_COUNT;
    kr = thread_get_state(target_thread, ARM_THREAD_STATE64,
                          (thread_state_t)&orig_state, &state_count);
    if (kr != KERN_SUCCESS) {
        LL_DBG("inject_dylib: thread_get_state failed: kr=%d\n", kr);
        thread_resume(target_thread);
        mach_vm_deallocate(task, remote_path, alloc_sz);
        mach_port_deallocate(mach_task_self(), target_thread);
        mach_port_deallocate(mach_task_self(), task);
        return -1;
    }

    /* 6. Build new state: call dlopen(path, RTLD_NOW)
     *
     * CRITICAL: Start from orig_state to preserve the thread's TLS pointer,
     * CPSR, and other implicit state. Only modify PC, LR, and args.
     * We keep the original SP — the thread was in a sleep call, so there's
     * plenty of stack space available for dlopen's call chain. */

    arm_thread_state64_t new_state = orig_state;

    arm_thread_state64_set_pc_fptr(new_state, dlopen_addr);
    arm_thread_state64_set_lr_fptr(new_state, (void *)(uintptr_t)0);

    new_state.__x[0] = (uint64_t)remote_path;  /* path */
    new_state.__x[1] = 0x2;                    /* RTLD_NOW */

    /* 7. Set new state and resume */
    kr = thread_set_state(target_thread, ARM_THREAD_STATE64,
                          (thread_state_t)&new_state,
                          ARM_THREAD_STATE64_COUNT);
    if (kr != KERN_SUCCESS) {
        LL_DBG("inject_dylib: thread_set_state failed: kr=%d\n", kr);
        thread_resume(target_thread);
        mach_vm_deallocate(task, remote_path, alloc_sz);
        mach_port_deallocate(mach_task_self(), target_thread);
        mach_port_deallocate(mach_task_self(), task);
        return -1;
    }

    kr = thread_resume(target_thread);
    if (kr != KERN_SUCCESS) {
        LL_DBG("inject_dylib: thread_resume failed: kr=%d\n", kr);
        mach_vm_deallocate(task, remote_path, alloc_sz);
        mach_port_deallocate(mach_task_self(), target_thread);
        mach_port_deallocate(mach_task_self(), task);
        return -1;
    }

    /* 8. Wait for dlopen to complete.
     *
     * Poll the thread's PC. When dlopen is done, it returns via BLR
     * to LR (which we set to 0). The thread will be at PC ≈ 0 or
     * will have crashed. We re-suspend ASAP.
     *
     * Alternatively, just sleep a reasonable time and re-suspend.
     * For a production implementation, you'd use Mach exception ports. */
    usleep(500000); /* 500ms — plenty for dlopen */

    /* 9. Re-suspend the thread */
    kr = thread_suspend(target_thread);
    if (kr != KERN_SUCCESS) {
        /* Thread may have died — check if process is still alive */
        LL_DBG("inject_dylib: re-suspend failed: kr=%d "
               "(target may have crashed)\n", kr);
        /* Still try to clean up */
    }

    /* 10. Restore original thread state */
    state_count = ARM_THREAD_STATE64_COUNT;
    kr = thread_set_state(target_thread, ARM_THREAD_STATE64,
                          (thread_state_t)&orig_state, state_count);
    if (kr != KERN_SUCCESS) {
        LL_DBG("inject_dylib: state restore failed: kr=%d\n", kr);
    }

    /* 11. Resume — thread continues from where it was before hijack */
    thread_resume(target_thread);

    /* Path memory stays allocated — dyld may reference it */
    mach_port_deallocate(mach_task_self(), target_thread);
    mach_port_deallocate(mach_task_self(), task);
    return 0;
}

/* ------------------------------------------------------------------ */
/* libload_inject_spawn — Zero-privilege spawn-time injection via      */
/*                        exception port inheritance across fork+exec  */
/*                                                                    */
/* Uses only PUBLIC macOS APIs — NO external tools (clang, codesign). */
/*                                                                    */
/* Two strategies based on target type:                               */
/*   Non-HR: DYLD_INSERT_LIBRARIES loads the payload dylib directly   */
/*           → no binary patching, no exception ports needed          */
/*   HR:     Copy binary, patch entry with BRK #1, native ad-hoc     */
/*           re-sign with SHA-256 page hashes, catch exception,       */
/*           thread-hijack to dlopen payload, trampoline resume       */
/*                                                                    */
/* No root, no entitlements, no private APIs. Works on HR binaries.   */
/* ------------------------------------------------------------------ */

#include <spawn.h>
#include <fcntl.h>
#include <copyfile.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <CommonCrypto/CommonDigest.h>
#include <libkern/OSByteOrder.h>

#define BRK_1_INSN 0xD4200020

/* Code signing constants */
#define CS_MAGIC_EMBEDDED_SIGNATURE  0xfade0cc0u
#define CS_MAGIC_CODEDIRECTORY       0xfade0c02u
#define CS_MAGIC_REQUIREMENTS        0xfade0c01u
#define CS_SLOT_CODEDIRECTORY        0u
#define CS_SLOT_REQUIREMENTS         2u
#define CS_SLOT_CMS_SIGNATURE        0x10000u
#define CS_MAGIC_BLOBWRAPPER         0xfade0b01u
#define CS_HASHTYPE_SHA256           2
#define CS_ADHOC                     0x00000002u
#define CS_LINKER_SIGNED             0x00020000u
#define CS_RUNTIME                   0x00010000u
#define CS_EXECSEG_MAIN_BINARY      0x1
#define CS_PAGE_SHIFT_4K             12
#define CS_PAGE_SIZE_4K              4096

/* Code signing blob structures (big-endian on disk) */
#pragma pack(1)
typedef struct {
    uint32_t magic;
    uint32_t length;
    uint32_t count;
} cs_super_blob_t;

typedef struct {
    uint32_t type;
    uint32_t offset;
} cs_blob_index_t;

typedef struct {
    uint32_t magic;            /* +0  */
    uint32_t length;           /* +4  */
    uint32_t version;          /* +8  */
    uint32_t flags;            /* +12 */
    uint32_t hashOffset;       /* +16 */
    uint32_t identOffset;      /* +20 */
    uint32_t nSpecialSlots;    /* +24 */
    uint32_t nCodeSlots;       /* +28 */
    uint32_t codeLimit;        /* +32 */
    uint8_t  hashSize;         /* +36 */
    uint8_t  hashType;         /* +37 */
    uint8_t  platform;         /* +38 */
    uint8_t  pageSize;         /* +39 */
    uint32_t spare2;           /* +40 */
    uint32_t scatterOffset;    /* +44 (v0x20100) */
    uint32_t teamOffset;       /* +48 (v0x20200) */
    uint32_t spare3;           /* +52 (v0x20300) */
    uint64_t codeLimit64;      /* +56 */
    uint64_t execSegBase;      /* +64 (v0x20400) */
    uint64_t execSegLimit;     /* +72 */
    uint64_t execSegFlags;     /* +80 */
                               /* =88 bytes total */
} cs_code_directory_t;
#pragma pack()

#define CS_CD_V20400_SIZE 88

/* Exception message structures */
#pragma pack(4)
typedef struct {
    mach_msg_header_t Head;
    mach_msg_body_t msgh_body;
    mach_msg_port_descriptor_t thread;
    mach_msg_port_descriptor_t task;
    NDR_record_t NDR;
    exception_type_t exception;
    mach_msg_type_number_t codeCnt;
    int64_t code[2];
} libload_exc_msg_t;

typedef struct {
    mach_msg_header_t Head;
    NDR_record_t NDR;
    kern_return_t RetCode;
} libload_exc_reply_t;
#pragma pack()

/* Find the entry point offset and FAT slice offset for an arm64 Mach-O */
static int exc_find_entry(const char *path, uint64_t *entry_off,
                          uint64_t *fat_offset)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;

    uint8_t buf[64 * 1024];
    ssize_t n = read(fd, buf, sizeof(buf));
    close(fd);
    if (n < (ssize_t)sizeof(struct mach_header_64))
        return -1;

    *fat_offset = 0;
    struct mach_header_64 *mh = (struct mach_header_64 *)buf;

    if (mh->magic == FAT_CIGAM || mh->magic == FAT_MAGIC) {
        struct fat_header *fh = (struct fat_header *)buf;
        uint32_t narch = OSSwapBigToHostInt32(fh->nfat_arch);
        struct fat_arch *archs = (struct fat_arch *)(buf + sizeof(*fh));
        int found = 0;
        for (uint32_t i = 0; i < narch; i++) {
            if (OSSwapBigToHostInt32(archs[i].cputype) == CPU_TYPE_ARM64) {
                *fat_offset = OSSwapBigToHostInt32(archs[i].offset);
                fd = open(path, O_RDONLY);
                if (fd < 0) return -1;
                lseek(fd, *fat_offset, SEEK_SET);
                n = read(fd, buf, sizeof(buf));
                close(fd);
                mh = (struct mach_header_64 *)buf;
                found = 1;
                break;
            }
        }
        if (!found) return -1;
    }

    if (mh->magic != MH_MAGIC_64) return -1;

    uint8_t *cmd = buf + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        struct load_command *lc = (struct load_command *)cmd;
        if (lc->cmd == LC_MAIN) {
            *entry_off = ((struct entry_point_command *)cmd)->entryoff;
            return 0;
        }
        cmd += lc->cmdsize;
    }
    return -1;
}

/* Check if binary has Hardened Runtime by parsing the CodeDirectory flags.
 * Returns 1 if CS_RUNTIME is set (DYLD_INSERT_LIBRARIES blocked), 0 otherwise.
 * Entirely native — no external tools. */
static int exc_is_hardened_runtime(const char *path)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;

    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); return 0; }

    size_t map_sz = (size_t)st.st_size;
    uint8_t *map = mmap(NULL, map_sz, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (map == MAP_FAILED) return 0;

    struct mach_header_64 *mh = (struct mach_header_64 *)map;
    uint64_t macho_off = 0;

    /* Handle FAT binaries */
    if (mh->magic == FAT_CIGAM || mh->magic == FAT_MAGIC) {
        struct fat_header *fh = (struct fat_header *)map;
        uint32_t narch = OSSwapBigToHostInt32(fh->nfat_arch);
        struct fat_arch *archs = (struct fat_arch *)(map + sizeof(*fh));
        for (uint32_t i = 0; i < narch; i++) {
            if (OSSwapBigToHostInt32(archs[i].cputype) == CPU_TYPE_ARM64) {
                macho_off = OSSwapBigToHostInt32(archs[i].offset);
                mh = (struct mach_header_64 *)(map + macho_off);
                break;
            }
        }
    }

    if (mh->magic != MH_MAGIC_64) { munmap(map, map_sz); return 0; }

    /* Find LC_CODE_SIGNATURE */
    uint8_t *cmd = (uint8_t *)mh + sizeof(struct mach_header_64);
    struct linkedit_data_command *cs_cmd = NULL;
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        struct load_command *lc = (struct load_command *)cmd;
        if (lc->cmd == LC_CODE_SIGNATURE)
            cs_cmd = (struct linkedit_data_command *)cmd;
        cmd += lc->cmdsize;
    }

    if (!cs_cmd) { munmap(map, map_sz); return 0; }

    /* Parse the SuperBlob to find the CodeDirectory */
    uint8_t *sig = map + macho_off + cs_cmd->dataoff;
    if (sig + sizeof(cs_super_blob_t) > map + map_sz) {
        munmap(map, map_sz);
        return 0;
    }

    cs_super_blob_t *sb = (cs_super_blob_t *)sig;
    if (OSSwapBigToHostInt32(sb->magic) != CS_MAGIC_EMBEDDED_SIGNATURE) {
        munmap(map, map_sz);
        return 0;
    }

    uint32_t nblobs = OSSwapBigToHostInt32(sb->count);
    cs_blob_index_t *indices = (cs_blob_index_t *)(sig + sizeof(cs_super_blob_t));

    for (uint32_t i = 0; i < nblobs; i++) {
        if (OSSwapBigToHostInt32(indices[i].type) == CS_SLOT_CODEDIRECTORY) {
            uint32_t boff = OSSwapBigToHostInt32(indices[i].offset);
            cs_code_directory_t *cd = (cs_code_directory_t *)(sig + boff);
            if (OSSwapBigToHostInt32(cd->magic) == CS_MAGIC_CODEDIRECTORY) {
                uint32_t flags = OSSwapBigToHostInt32(cd->flags);
                munmap(map, map_sz);
                return (flags & CS_RUNTIME) ? 1 : 0;
            }
        }
    }

    munmap(map, map_sz);
    return 0;
}

/* Native ad-hoc code signing: recompute SHA-256 page hashes and write
 * a minimal CodeDirectory + empty Requirements into the existing
 * LC_CODE_SIGNATURE space. No external tools needed.
 *
 * Uses read()/pwrite() instead of mmap() to avoid marking file pages
 * as write-mapped (wpmapped), which AMFI considers tainted at exec time.
 *
 * fat_offset: byte offset of the arm64 Mach-O slice (0 for thin). */
static int exc_adhoc_sign(const char *path, uint64_t fat_offset)
{
    int fd = open(path, O_RDWR);
    if (fd < 0) return -1;

    /* Read Mach-O header + load commands */
    uint8_t hdr[64 * 1024];
    if (pread(fd, hdr, sizeof(hdr), fat_offset) < (ssize_t)sizeof(struct mach_header_64)) {
        close(fd);
        return -1;
    }

    struct mach_header_64 *mh = (struct mach_header_64 *)hdr;
    if (mh->magic != MH_MAGIC_64) { close(fd); return -1; }

    /* Walk load commands for LC_CODE_SIGNATURE and __TEXT segment */
    uint8_t *cmd = hdr + sizeof(struct mach_header_64);
    uint32_t cs_off = 0, cs_space = 0;
    uint64_t text_fileoff = 0, text_filesize = 0;
    int found_cs = 0;

    for (uint32_t i = 0; i < mh->ncmds; i++) {
        struct load_command *lc = (struct load_command *)cmd;
        if (lc->cmd == LC_CODE_SIGNATURE) {
            struct linkedit_data_command *csc = (struct linkedit_data_command *)cmd;
            cs_off = csc->dataoff;
            cs_space = csc->datasize;
            found_cs = 1;
        } else if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *sc = (struct segment_command_64 *)cmd;
            if (strcmp(sc->segname, "__TEXT") == 0) {
                text_fileoff = sc->fileoff;
                text_filesize = sc->filesize;
            }
        }
        cmd += lc->cmdsize;
    }

    if (!found_cs) { close(fd); return -1; }

    uint32_t code_limit = cs_off;
    uint32_t n_code_slots =
        (code_limit + CS_PAGE_SIZE_4K - 1) / CS_PAGE_SIZE_4K;

    /* Identifier */
    const char *ident = "-";
    uint32_t ident_len = (uint32_t)strlen(ident) + 1;

    /* Layout: SuperBlob { CD, Req, CMS } + CodeDirectory + Req + CMS */
    uint32_t n_blobs = 3;
    uint32_t sb_hdr = (uint32_t)(sizeof(cs_super_blob_t) +
                                  n_blobs * sizeof(cs_blob_index_t));  /* 36 */

    /* Special slots: -1 (info/unused), -2 (requirements) */
    uint32_t n_special_slots = 2;

    uint32_t cd_ident_off = CS_CD_V20400_SIZE;
    uint32_t cd_hash_off = cd_ident_off + ident_len;
    cd_hash_off = (cd_hash_off + 3) & ~3u;  /* align to 4 */
    /* Special slot hashes are stored before code hashes at negative offsets.
     * hashOffset points to code slot 0; special slots are at
     * hashOffset - (slot * hashSize). We need space for n_special_slots
     * hashes before the code hashes. */
    uint32_t special_hash_sz = n_special_slots * CC_SHA256_DIGEST_LENGTH;
    uint32_t cd_length = cd_hash_off + special_hash_sz +
                         n_code_slots * CC_SHA256_DIGEST_LENGTH;

    /* Empty requirements blob: magic + length + count=0 */
    uint32_t req_length = 12;

    /* Empty CMS blob wrapper: magic + length */
    uint32_t cms_length = 8;

    uint32_t total = sb_hdr + cd_length + req_length + cms_length;
    if (total > cs_space) { close(fd); return -1; }

    /* Build signature in a heap buffer (not mmap) */
    uint8_t *sig = calloc(1, cs_space);
    if (!sig) { close(fd); return -1; }

    /* SuperBlob */
    cs_super_blob_t *sb = (cs_super_blob_t *)sig;
    sb->magic  = OSSwapHostToBigInt32(CS_MAGIC_EMBEDDED_SIGNATURE);
    sb->length = OSSwapHostToBigInt32(total);
    sb->count  = OSSwapHostToBigInt32(n_blobs);

    cs_blob_index_t *bi = (cs_blob_index_t *)(sig + sizeof(cs_super_blob_t));
    bi[0].type   = OSSwapHostToBigInt32(CS_SLOT_CODEDIRECTORY);
    bi[0].offset = OSSwapHostToBigInt32(sb_hdr);
    bi[1].type   = OSSwapHostToBigInt32(CS_SLOT_REQUIREMENTS);
    bi[1].offset = OSSwapHostToBigInt32(sb_hdr + cd_length);
    bi[2].type   = OSSwapHostToBigInt32(CS_SLOT_CMS_SIGNATURE);
    bi[2].offset = OSSwapHostToBigInt32(sb_hdr + cd_length + req_length);

    /* CodeDirectory */
    uint8_t *cd_ptr = sig + sb_hdr;
    cs_code_directory_t *cd = (cs_code_directory_t *)cd_ptr;
    /* hashOffset points to the first CODE slot hash, which is after
     * the special slot hashes in the blob. */
    uint32_t real_hash_off = cd_hash_off + special_hash_sz;
    cd->magic         = OSSwapHostToBigInt32(CS_MAGIC_CODEDIRECTORY);
    cd->length        = OSSwapHostToBigInt32(cd_length);
    cd->version       = OSSwapHostToBigInt32(0x20400);
    cd->flags         = OSSwapHostToBigInt32(CS_ADHOC);
    cd->hashOffset    = OSSwapHostToBigInt32(real_hash_off);
    cd->identOffset   = OSSwapHostToBigInt32(cd_ident_off);
    cd->nSpecialSlots = OSSwapHostToBigInt32(n_special_slots);
    cd->nCodeSlots    = OSSwapHostToBigInt32(n_code_slots);
    cd->codeLimit     = OSSwapHostToBigInt32(code_limit);
    cd->hashSize      = CC_SHA256_DIGEST_LENGTH;
    cd->hashType      = CS_HASHTYPE_SHA256;
    cd->platform      = 0;
    cd->pageSize      = CS_PAGE_SHIFT_4K;
    cd->spare2        = 0;
    cd->scatterOffset = 0;
    cd->teamOffset    = 0;
    cd->spare3        = 0;
    cd->codeLimit64   = 0;
    cd->execSegBase   = OSSwapHostToBigInt64(text_fileoff);
    cd->execSegLimit  = OSSwapHostToBigInt64(text_filesize);
    cd->execSegFlags  = OSSwapHostToBigInt64(CS_EXECSEG_MAIN_BINARY);

    memcpy(cd_ptr + cd_ident_off, ident, ident_len);

    /* Compute SHA-256 page hashes by reading file in pages (no mmap) */
    uint8_t *code_hashes = cd_ptr + real_hash_off;
    uint8_t page_buf[CS_PAGE_SIZE_4K];
    for (uint32_t i = 0; i < n_code_slots; i++) {
        uint32_t poff = i * CS_PAGE_SIZE_4K;
        uint32_t psz  = CS_PAGE_SIZE_4K;
        if (poff + psz > code_limit)
            psz = code_limit - poff;
        memset(page_buf, 0, sizeof(page_buf));
        pread(fd, page_buf, psz, fat_offset + poff);
        CC_SHA256(page_buf, psz, code_hashes + i * CC_SHA256_DIGEST_LENGTH);
    }

    /* Empty requirements SuperBlob */
    uint8_t *req = sig + sb_hdr + cd_length;
    uint32_t req_magic_val = OSSwapHostToBigInt32(CS_MAGIC_REQUIREMENTS);
    uint32_t req_len_val   = OSSwapHostToBigInt32(req_length);
    uint32_t req_count = 0;
    memcpy(req + 0, &req_magic_val, 4);
    memcpy(req + 4, &req_len_val, 4);
    memcpy(req + 8, &req_count, 4);

    /* Special slot -2: hash of the requirements blob */
    uint8_t *special_hashes = cd_ptr + cd_hash_off;
    CC_SHA256(req, req_length,
              special_hashes + 0);  /* slot -2 (requirements) */
    /* slot -1 (info plist): leave as zeros (no info plist) */

    /* Empty CMS blob wrapper (required by AMFI) */
    uint8_t *cms = sig + sb_hdr + cd_length + req_length;
    uint32_t cms_magic_val = OSSwapHostToBigInt32(CS_MAGIC_BLOBWRAPPER);
    uint32_t cms_len_val   = OSSwapHostToBigInt32(cms_length);
    memcpy(cms + 0, &cms_magic_val, 4);
    memcpy(cms + 4, &cms_len_val, 4);

    /* Write signature to file using pwrite (avoids wpmapped taint) */
    ssize_t written = pwrite(fd, sig, cs_space, fat_offset + cs_off);
    free(sig);
    close(fd);
    return (written == (ssize_t)cs_space) ? 0 : -1;
}

static kern_return_t exc_recv(mach_port_t port, libload_exc_msg_t *msg,
                              int timeout_ms)
{
    union {
        libload_exc_msg_t exc;
        char buf[4096];
    } u;
    memset(&u, 0, sizeof(u));

    kern_return_t kr = mach_msg(&u.exc.Head,
        MACH_RCV_MSG | MACH_RCV_TIMEOUT | MACH_RCV_LARGE,
        0, sizeof(u), port, timeout_ms, MACH_PORT_NULL);
    if (kr == KERN_SUCCESS)
        *msg = u.exc;
    return kr;
}

static kern_return_t exc_reply(libload_exc_msg_t *msg)
{
    libload_exc_reply_t reply;
    memset(&reply, 0, sizeof(reply));
    reply.Head.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
    reply.Head.msgh_size = sizeof(reply);
    reply.Head.msgh_remote_port = msg->Head.msgh_remote_port;
    reply.Head.msgh_local_port = MACH_PORT_NULL;
    reply.Head.msgh_id = msg->Head.msgh_id + 100;
    reply.NDR = NDR_record;
    reply.RetCode = KERN_SUCCESS;
    return mach_msg(&reply.Head, MACH_SEND_MSG, sizeof(reply),
                    0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
}

pid_t libload_inject_spawn(const char *target_path,
                           const char *dylib_path,
                           char *const argv[],
                           char *const envp[])
{
    if (!target_path || !dylib_path)
        return -1;

    int is_hr = exc_is_hardened_runtime(target_path);

    /* ── Non-HR path: load payload directly via DYLD_INSERT_LIBRARIES ── */
    if (!is_hr) {
        pid_t child = fork();
        if (child == 0) {
            /* Build exec argv: [target_path, argv[0], argv[1], ..., NULL] */
            int argc = 0;
            if (argv) while (argv[argc]) argc++;
            char **exec_argv = calloc(argc + 2, sizeof(char *));
            if (!exec_argv) _exit(127);
            exec_argv[0] = (char *)target_path;
            for (int i = 0; i < argc; i++)
                exec_argv[i + 1] = argv[i];

            /* Build environment with DYLD_INSERT_LIBRARIES */
            char *const *base_env = envp ? envp : environ;
            int env_count = 0;
            while (base_env[env_count]) env_count++;

            char **exec_envp = calloc(env_count + 2, sizeof(char *));
            if (!exec_envp) _exit(127);

            int j = 0;
            for (int i = 0; i < env_count; i++) {
                if (strncmp(base_env[i], "DYLD_INSERT_LIBRARIES=", 22) != 0)
                    exec_envp[j++] = (char *)base_env[i];
            }
            char dyld_env[1024];
            snprintf(dyld_env, sizeof(dyld_env),
                     "DYLD_INSERT_LIBRARIES=%s", dylib_path);
            exec_envp[j++] = dyld_env;
            exec_envp[j] = NULL;

            execve(target_path, exec_argv, exec_envp);
            _exit(127);
        }
        return child;
    }

    /* ── HR path: patch entry, native re-sign, exception port injection ── */

    void *dlopen_addr = dlsym(RTLD_DEFAULT, "dlopen");
    if (!dlopen_addr) return -1;

    uint64_t entry_off = 0, fat_off = 0;
    if (exc_find_entry(target_path, &entry_off, &fat_off) != 0)
        return -1;

    /* Copy binary and patch entry with BRK #1 */
    char tmp[256];
    snprintf(tmp, sizeof(tmp), "/tmp/.libload_%d", getpid());
    if (copyfile(target_path, tmp, NULL, COPYFILE_ALL) != 0)
        return -1;
    chmod(tmp, 0755);

    uint64_t file_off = fat_off + entry_off;
    uint32_t orig_insn = 0;
    int fd = open(tmp, O_RDWR);
    if (fd < 0) { unlink(tmp); return -1; }
    lseek(fd, file_off, SEEK_SET);
    if (read(fd, &orig_insn, 4) != 4) { close(fd); unlink(tmp); return -1; }
    uint32_t brk = BRK_1_INSN;
    lseek(fd, file_off, SEEK_SET);
    if (write(fd, &brk, 4) != 4) { close(fd); unlink(tmp); return -1; }
    close(fd);

    /* Native ad-hoc re-sign (SHA-256 page hashes) */
    if (exc_adhoc_sign(tmp, fat_off) != 0) { unlink(tmp); return -1; }

    /* Create exception receive port */
    mach_port_t exc_port = MACH_PORT_NULL;
    kern_return_t kr;
    kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &exc_port);
    if (kr) { unlink(tmp); return -1; }
    mach_port_insert_right(mach_task_self(), exc_port, exc_port,
                           MACH_MSG_TYPE_MAKE_SEND);

    /* Set exception ports on self — child inherits via fork */
    exception_mask_t exc_mask = EXC_MASK_BREAKPOINT | EXC_MASK_BAD_ACCESS |
                                EXC_MASK_SOFTWARE;
    exception_mask_t old_masks[EXC_TYPES_COUNT];
    mach_port_t old_ports[EXC_TYPES_COUNT];
    exception_behavior_t old_behaviors[EXC_TYPES_COUNT];
    thread_state_flavor_t old_flavors[EXC_TYPES_COUNT];
    mach_msg_type_number_t old_count = EXC_TYPES_COUNT;

    kr = task_swap_exception_ports(mach_task_self(), exc_mask,
                                   exc_port,
                                   EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES,
                                   ARM_THREAD_STATE64,
                                   old_masks, &old_count, old_ports,
                                   old_behaviors, old_flavors);
    if (kr != KERN_SUCCESS) {
        mach_port_deallocate(mach_task_self(), exc_port);
        unlink(tmp);
        return -1;
    }

    /* fork + exec patched binary */
    pid_t pid = fork();

    if (pid == 0) {
        int argc = 0;
        if (argv) while (argv[argc]) argc++;
        char **exec_argv = calloc(argc + 2, sizeof(char *));
        if (!exec_argv) _exit(127);
        exec_argv[0] = (char *)target_path;  /* show original name */
        for (int i = 0; i < argc; i++)
            exec_argv[i + 1] = argv[i];
        execve(tmp, exec_argv, envp ? (char *const *)envp : environ);
        _exit(127);
    }

    /* Immediately restore our own exception ports */
    for (mach_msg_type_number_t i = 0; i < old_count; i++) {
        task_set_exception_ports(mach_task_self(), old_masks[i],
                                 old_ports[i], old_behaviors[i],
                                 old_flavors[i]);
    }

    if (pid < 0) {
        mach_port_deallocate(mach_task_self(), exc_port);
        unlink(tmp);
        return -1;
    }

    /* --- Exception 1: BRK at patched entry point --- */
    libload_exc_msg_t msg;
    kr = exc_recv(exc_port, &msg, 10000);
    if (kr != KERN_SUCCESS) goto fail;

    mach_port_t task_port = msg.task.name;
    mach_port_t thread_port = msg.thread.name;

    /* Save thread state at BRK */
    arm_thread_state64_t saved;
    mach_msg_type_number_t scnt = ARM_THREAD_STATE64_COUNT;
    kr = thread_get_state(thread_port, ARM_THREAD_STATE64,
                          (thread_state_t)&saved, &scnt);
    if (kr != KERN_SUCCESS) goto fail;

    /* Write dylib path into target's address space */
    {
        size_t path_len = strlen(dylib_path) + 1;
        mach_vm_address_t remote_path = 0;
        kr = mach_vm_allocate(task_port, &remote_path, PAGE_SZ, VM_FLAGS_ANYWHERE);
        if (kr != KERN_SUCCESS) goto fail;
        kr = mach_vm_write(task_port, remote_path, (vm_offset_t)dylib_path,
                           (mach_msg_type_number_t)path_len);
        if (kr != KERN_SUCCESS) goto fail;

        /* Thread-hijack: call dlopen(path, RTLD_NOW)
         * LR → BRK at entry, so dlopen returns to our trap */
        arm_thread_state64_t inject = saved;
        uint64_t raw_dlopen = (uint64_t)dlopen_addr;
#ifdef __arm64e__
        raw_dlopen = (uint64_t)__builtin_ptrauth_strip(dlopen_addr,
                                                       ptrauth_key_function_pointer);
#endif
        inject.__pc = raw_dlopen;
        inject.__lr = saved.__pc;           /* return to BRK */
        inject.__x[0] = (uint64_t)remote_path;
        inject.__x[1] = 0x2;               /* RTLD_NOW */

        kr = thread_set_state(thread_port, ARM_THREAD_STATE64,
                              (thread_state_t)&inject,
                              ARM_THREAD_STATE64_COUNT);
        if (kr != KERN_SUCCESS) goto fail;
    }

    exc_reply(&msg);

    /* --- Exception 2: dlopen returned to BRK --- */
    kr = exc_recv(exc_port, &msg, 30000);
    if (kr != KERN_SUCCESS) goto fail;

    /* Build trampoline: execute original instruction, branch to entry+4.
     *
     * Layout (20 bytes):
     *   +0:  <original instruction>
     *   +4:  ldr x16, .+8
     *   +8:  br x16
     *  +12:  <entry_addr + 4>  (8-byte literal) */
    {
        mach_vm_address_t tramp = 0;
        kr = mach_vm_allocate(task_port, &tramp, PAGE_SZ, VM_FLAGS_ANYWHERE);
        if (kr != KERN_SUCCESS) goto fail;

        uint64_t return_addr = (uint64_t)saved.__pc + 4;
        uint8_t code[20];
        memcpy(code + 0, &orig_insn, 4);
        uint32_t ldr = 0x58000050; memcpy(code + 4, &ldr, 4);
        uint32_t br  = 0xD61F0200; memcpy(code + 8, &br, 4);
        memcpy(code + 12, &return_addr, 8);

        mach_vm_write(task_port, tramp, (vm_offset_t)code, 20);
        mach_vm_protect(task_port, tramp, PAGE_SZ, FALSE,
                        VM_PROT_READ | VM_PROT_EXECUTE);

        arm_thread_state64_t resume = saved;
        resume.__pc = tramp;
        thread_set_state(msg.thread.name, ARM_THREAD_STATE64,
                         (thread_state_t)&resume, ARM_THREAD_STATE64_COUNT);
    }

    exc_reply(&msg);
    unlink(tmp);
    mach_port_deallocate(mach_task_self(), exc_port);
    return pid;

fail:
    kill(pid, SIGKILL);
    waitpid(pid, NULL, WNOHANG);
    unlink(tmp);
    mach_port_deallocate(mach_task_self(), exc_port);
    return -1;
}

#endif /* __APPLE__ */
