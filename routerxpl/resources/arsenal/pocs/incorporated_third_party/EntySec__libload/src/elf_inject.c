/*
 * elf_inject.c — Linux process injection via ptrace
 *
 * Three injection methods:
 *
 *   1. libload_inject()       — PIC code injection via syscall proxy.
 *      Attaches via ptrace, uses target's own syscall instruction to
 *      mmap RW memory, writes code via process_vm_writev, mprotects RX,
 *      creates new thread via remote clone().
 *
 *   2. libload_inject_dylib() — Thread-hijack remote dlopen().
 *      Attaches via ptrace, finds dlopen in target's libc mapping,
 *      hijacks thread to call dlopen(path, RTLD_NOW), catches return
 *      via INT3/BRK trap, restores original state.
 *
 *   3. libload_inject_spawn() — LD_PRELOAD spawn.
 *      Simple fork + execve with LD_PRELOAD. Zero-privilege, always works
 *      on dynamically-linked non-setuid binaries.
 *
 * Methods 1-2 require ptrace access:
 *   - Yama ptrace_scope 0: any same-UID process
 *   - Yama ptrace_scope 1 (Ubuntu default): only child processes
 *   - CAP_SYS_PTRACE: overrides Yama restrictions
 *
 * Method 3 requires NO privileges.
 */

#ifdef __linux__

#define _GNU_SOURCE

#include "libload.h"

#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>

extern char **environ;

#define ALIGN_UP(x, a) (((x) + (a) - 1) & ~((a) - 1))

/* ------------------------------------------------------------------ */
/*  ptrace helpers                                                    */
/* ------------------------------------------------------------------ */

static int pt_attach(pid_t pid)
{
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0)
        return -1;

    int status;
    if (waitpid(pid, &status, 0) < 0) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }

    if (!WIFSTOPPED(status)) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }

    return 0;
}

static int pt_getregs(pid_t pid, struct iovec *iov)
{
    return ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, iov);
}

static int pt_setregs(pid_t pid, struct iovec *iov)
{
    return ptrace(PTRACE_SETREGSET, pid, (void *)NT_PRSTATUS, iov);
}

/* ------------------------------------------------------------------ */
/*  Find a syscall gadget in target's memory                          */
/* ------------------------------------------------------------------ */

static uint64_t pt_find_syscall(pid_t pid)
{
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE *maps = fopen(maps_path, "r");
    if (!maps)
        return 0;

    char line[512];
    uint64_t result = 0;

    while (fgets(line, sizeof(line), maps)) {
        /* Find executable regions (r-xp) in libc or vdso */
        unsigned long start, end;
        char perms[5];
        if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) != 3)
            continue;
        if (perms[2] != 'x')
            continue;
        if (!strstr(line, "libc") && !strstr(line, "vdso"))
            continue;

        /* Read this region from target memory */
        size_t region_sz = (size_t)(end - start);
        if (region_sz > 0x100000)
            region_sz = 0x100000; /* cap search at 1MB */

        uint8_t *buf = malloc(region_sz);
        if (!buf)
            continue;

        struct iovec local = { buf, region_sz };
        struct iovec remote = { (void *)start, region_sz };
        ssize_t n = process_vm_readv(pid, &local, 1, &remote, 1, 0);
        if (n <= 0) {
            free(buf);
            continue;
        }

#if defined(__x86_64__)
        /* Look for: syscall (0x0f 0x05) followed by ret or nop */
        for (ssize_t i = 0; i < n - 1; i++) {
            if (buf[i] == 0x0f && buf[i + 1] == 0x05) {
                result = start + i;
                free(buf);
                goto done;
            }
        }
#elif defined(__aarch64__)
        /* Look for: svc #0 (0xd4000001) */
        for (ssize_t i = 0; i <= n - 4; i += 4) {
            uint32_t insn;
            memcpy(&insn, buf + i, 4);
            if (insn == 0xd4000001) {
                result = start + i;
                free(buf);
                goto done;
            }
        }
#elif defined(__i386__)
        /* Look for: int 0x80 (0xcd 0x80) */
        for (ssize_t i = 0; i < n - 1; i++) {
            if (buf[i] == 0xcd && buf[i + 1] == 0x80) {
                result = start + i;
                free(buf);
                goto done;
            }
        }
#elif defined(__arm__)
        /* ARM mode: svc #0 = 0xef000000 */
        for (ssize_t i = 0; i <= n - 4; i += 4) {
            uint32_t insn;
            memcpy(&insn, buf + i, 4);
            if (insn == 0xef000000) {
                result = start + i;
                free(buf);
                goto done;
            }
        }
        /* Thumb mode: svc 0 = 0xdf00 */
        for (ssize_t i = 0; i <= n - 2; i += 2) {
            uint16_t insn;
            memcpy(&insn, buf + i, 2);
            if (insn == 0xdf00) {
                result = start + i;
                free(buf);
                goto done;
            }
        }
#elif defined(__mips__)
        /* MIPS: syscall = 0x0000000c */
        for (ssize_t i = 0; i <= n - 4; i += 4) {
            uint32_t insn;
            memcpy(&insn, buf + i, 4);
            if (insn == 0x0000000c) {
                result = start + i;
                free(buf);
                goto done;
            }
        }
#elif defined(__sparc__)
        /* SPARC: ta 0x10 = 0x91d02010 */
        for (ssize_t i = 0; i <= n - 4; i += 4) {
            uint32_t insn;
            memcpy(&insn, buf + i, 4);
            if (insn == 0x91d02010) {
                result = start + i;
                free(buf);
                goto done;
            }
        }
#endif
        free(buf);
    }

done:
    fclose(maps);
    return result;
}

/* ------------------------------------------------------------------ */
/*  Execute a syscall in the target process                           */
/* ------------------------------------------------------------------ */

static int64_t pt_remote_syscall(pid_t pid, uint64_t gadget,
                                 uint64_t nr,
                                 uint64_t a1, uint64_t a2,
                                 uint64_t a3, uint64_t a4,
                                 uint64_t a5, uint64_t a6)
{
#if defined(__x86_64__)
    struct user_regs_struct regs, saved;
    struct iovec iov = { &regs, sizeof(regs) };
    struct iovec siov = { &saved, sizeof(saved) };

    if (pt_getregs(pid, &siov) < 0)
        return -1;
    memcpy(&regs, &saved, sizeof(regs));

    regs.rax = nr;
    regs.rdi = a1;
    regs.rsi = a2;
    regs.rdx = a3;
    regs.r10 = a4;
    regs.r8  = a5;
    regs.r9  = a6;
    regs.rip = gadget;

    if (pt_setregs(pid, &iov) < 0)
        return -1;

    if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) < 0)
        return -1;

    int status;
    waitpid(pid, &status, 0);

    iov.iov_base = &regs;
    if (pt_getregs(pid, &iov) < 0)
        return -1;
    int64_t ret = (int64_t)regs.rax;

    siov.iov_base = &saved;
    pt_setregs(pid, &siov);

    return ret;

#elif defined(__aarch64__)
    struct {
        uint64_t regs[31];
        uint64_t sp;
        uint64_t pc;
        uint64_t pstate;
    } regs, saved;
    struct iovec iov = { &regs, sizeof(regs) };
    struct iovec siov = { &saved, sizeof(saved) };

    if (pt_getregs(pid, &siov) < 0)
        return -1;
    memcpy(&regs, &saved, sizeof(regs));

    regs.regs[8] = nr;
    regs.regs[0] = a1;
    regs.regs[1] = a2;
    regs.regs[2] = a3;
    regs.regs[3] = a4;
    regs.regs[4] = a5;
    regs.regs[5] = a6;
    regs.pc = gadget;

    if (pt_setregs(pid, &iov) < 0)
        return -1;

    if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) < 0)
        return -1;

    int status;
    waitpid(pid, &status, 0);

    iov.iov_base = &regs;
    if (pt_getregs(pid, &iov) < 0)
        return -1;
    int64_t ret = (int64_t)regs.regs[0];

    siov.iov_base = &saved;
    pt_setregs(pid, &siov);

    return ret;

#elif defined(__i386__)
    struct user_regs_struct regs, saved;
    struct iovec iov = { &regs, sizeof(regs) };
    struct iovec siov = { &saved, sizeof(saved) };

    if (pt_getregs(pid, &siov) < 0)
        return -1;
    memcpy(&regs, &saved, sizeof(regs));

    regs.eax = (unsigned long)nr;
    regs.ebx = (unsigned long)a1;
    regs.ecx = (unsigned long)a2;
    regs.edx = (unsigned long)a3;
    regs.esi = (unsigned long)a4;
    regs.edi = (unsigned long)a5;
    regs.ebp = (unsigned long)a6;
    regs.eip = (unsigned long)gadget;

    if (pt_setregs(pid, &iov) < 0)
        return -1;

    if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) < 0)
        return -1;

    int status;
    waitpid(pid, &status, 0);

    iov.iov_base = &regs;
    if (pt_getregs(pid, &iov) < 0)
        return -1;
    int64_t ret = (int64_t)(int32_t)regs.eax; /* sign-extend 32-bit */

    siov.iov_base = &saved;
    pt_setregs(pid, &siov);

    return ret;

#elif defined(__arm__)
    struct {
        uint32_t uregs[18]; /* r0..r15, cpsr, ORIG_r0 */
    } regs, saved;
    struct iovec iov = { &regs, sizeof(regs) };
    struct iovec siov = { &saved, sizeof(saved) };

    if (pt_getregs(pid, &siov) < 0)
        return -1;
    memcpy(&regs, &saved, sizeof(regs));

    regs.uregs[7]  = (uint32_t)nr;   /* r7 = syscall number */
    regs.uregs[0]  = (uint32_t)a1;
    regs.uregs[1]  = (uint32_t)a2;
    regs.uregs[2]  = (uint32_t)a3;
    regs.uregs[3]  = (uint32_t)a4;
    regs.uregs[4]  = (uint32_t)a5;
    regs.uregs[5]  = (uint32_t)a6;
    regs.uregs[15] = (uint32_t)gadget; /* pc */

    if (pt_setregs(pid, &iov) < 0)
        return -1;

    if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) < 0)
        return -1;

    int status;
    waitpid(pid, &status, 0);

    iov.iov_base = &regs;
    if (pt_getregs(pid, &iov) < 0)
        return -1;
    int64_t ret = (int64_t)(int32_t)regs.uregs[0]; /* sign-extend r0 */

    siov.iov_base = &saved;
    pt_setregs(pid, &siov);

    return ret;

#elif defined(__mips__) && !defined(__mips64)
    /*
     * MIPS o32 ptrace register layout (NT_PRSTATUS):
     *   [0..5]  padding (6 words)
     *   [6..37] r0..r31
     *   [38]    lo
     *   [39]    hi
     *   [40]    cp0_epc (PC)
     *   [41]    cp0_badvaddr
     *   [42]    cp0_status
     *   [43]    cp0_cause
     *   [44]    unused
     * Total: 45 * 4 = 180 bytes
     *
     * Syscall ABI: v0($2)=nr, a0-a3($4-$7)=args1-4
     * Args 5-6 go on stack at sp+16 and sp+20
     * Return: a3($7)=error flag, v0($2)=result/errno
     */
    uint32_t mregs[45], msaved[45];
    struct iovec iov = { mregs, sizeof(mregs) };
    struct iovec siov = { msaved, sizeof(msaved) };

    if (pt_getregs(pid, &siov) < 0)
        return -1;
    memcpy(mregs, msaved, sizeof(mregs));

    mregs[6 + 2]  = (uint32_t)nr;   /* v0 = syscall number */
    mregs[6 + 4]  = (uint32_t)a1;   /* a0 */
    mregs[6 + 5]  = (uint32_t)a2;   /* a1 */
    mregs[6 + 6]  = (uint32_t)a3;   /* a2 */
    mregs[6 + 7]  = (uint32_t)a4;   /* a3 */
    mregs[40]      = (uint32_t)gadget; /* cp0_epc = PC */

    /* Write args 5-6 to stack: sp+16 and sp+20 */
    uint32_t sp = mregs[6 + 29]; /* $sp */
    uint32_t stkargs[2] = { (uint32_t)a5, (uint32_t)a6 };
    struct iovec sl = { stkargs, 8 };
    struct iovec sr = { (void *)(uintptr_t)(sp + 16), 8 };
    process_vm_writev(pid, &sl, 1, &sr, 1, 0);

    if (pt_setregs(pid, &iov) < 0)
        return -1;

    if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) < 0)
        return -1;

    int status;
    waitpid(pid, &status, 0);

    iov.iov_base = mregs;
    if (pt_getregs(pid, &iov) < 0)
        return -1;

    int64_t ret;
    if (mregs[6 + 7]) /* a3 set = error */
        ret = -(int64_t)mregs[6 + 2]; /* negate errno */
    else
        ret = (int64_t)(uint32_t)mregs[6 + 2];

    siov.iov_base = msaved;
    pt_setregs(pid, &siov);

    return ret;

#elif defined(__sparc__)
    /*
     * SPARC32 ptrace register layout (NT_PRSTATUS):
     *   psr, pc, npc, y, u_regs[16]
     * u_regs: g0-g7 (globals), o0-o7 (outputs)
     *
     * Syscall ABI: g1=nr, o0-o5=args1-6
     * Return: carry in PSR = error, o0 = result/errno
     */
    struct {
        uint32_t psr;
        uint32_t pc;
        uint32_t npc;
        uint32_t y;
        uint32_t u_regs[16]; /* g0-g7, o0-o7 */
    } regs, saved;
    struct iovec iov = { &regs, sizeof(regs) };
    struct iovec siov = { &saved, sizeof(saved) };

    if (pt_getregs(pid, &siov) < 0)
        return -1;
    memcpy(&regs, &saved, sizeof(regs));

    regs.u_regs[1]  = (uint32_t)nr;  /* g1 = syscall number */
    regs.u_regs[8]  = (uint32_t)a1;  /* o0 */
    regs.u_regs[9]  = (uint32_t)a2;  /* o1 */
    regs.u_regs[10] = (uint32_t)a3;  /* o2 */
    regs.u_regs[11] = (uint32_t)a4;  /* o3 */
    regs.u_regs[12] = (uint32_t)a5;  /* o4 */
    regs.u_regs[13] = (uint32_t)a6;  /* o5 */
    regs.pc  = (uint32_t)gadget;
    regs.npc = (uint32_t)gadget + 4;

    if (pt_setregs(pid, &iov) < 0)
        return -1;

    if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) < 0)
        return -1;

    int status;
    waitpid(pid, &status, 0);

    iov.iov_base = &regs;
    if (pt_getregs(pid, &iov) < 0)
        return -1;

    int64_t ret;
    if (regs.psr & 0x00100000) /* PSR carry bit = error */
        ret = -(int64_t)regs.u_regs[8]; /* negate errno */
    else
        ret = (int64_t)(uint32_t)regs.u_regs[8];

    siov.iov_base = &saved;
    pt_setregs(pid, &siov);

    return ret;
#else
    (void)pid; (void)gadget; (void)nr;
    (void)a1; (void)a2; (void)a3; (void)a4; (void)a5; (void)a6;
    return -1;
#endif
}

/* ------------------------------------------------------------------ */
/*  libload_inject — PIC code injection via syscall proxy             */
/* ------------------------------------------------------------------ */

int libload_inject(pid_t pid, const void *code, size_t len,
                   size_t entry_offset, uint64_t arg)
{
    if (!code || len == 0 || entry_offset >= len)
        return -1;

    if (pt_attach(pid) < 0)
        return -1;

    int ret = -1;
    size_t alloc_sz = ALIGN_UP(len, 4096);

    /* Find syscall gadget */
    uint64_t gadget = pt_find_syscall(pid);
    if (!gadget)
        goto detach;

    /* Remote mmap: allocate RW memory */
    int64_t remote = pt_remote_syscall(pid, gadget, __NR_mmap,
                                       0, alloc_sz,
                                       PROT_READ | PROT_WRITE,
                                       MAP_ANONYMOUS | MAP_PRIVATE,
                                       (uint64_t)-1, 0);
    if (remote < 0 || remote == (int64_t)MAP_FAILED)
        goto detach;

    /* Write code via process_vm_writev */
    struct iovec local = { (void *)code, len };
    struct iovec remv  = { (void *)remote, len };
    if (process_vm_writev(pid, &local, 1, &remv, 1, 0) != (ssize_t)len)
        goto detach;

    /* Remote mprotect: RW → RX */
    int64_t mret = pt_remote_syscall(pid, gadget, __NR_mprotect,
                                     remote, alloc_sz,
                                     PROT_READ | PROT_EXEC,
                                     0, 0, 0);
    if (mret < 0)
        goto detach;

    /* Remote clone: create new thread at entry point */
    /* Allocate stack for the new thread */
    int64_t stack = pt_remote_syscall(pid, gadget, __NR_mmap,
                                      0, 65536,
                                      PROT_READ | PROT_WRITE,
                                      MAP_ANONYMOUS | MAP_PRIVATE,
                                      (uint64_t)-1, 0);
    if (stack < 0 || stack == (int64_t)MAP_FAILED)
        goto detach;

    /*
     * Instead of clone(), just hijack the stopped thread briefly
     * to jump to our code, then restore. Simpler and avoids
     * clone() complexity with different arch ABIs.
     */
#if defined(__x86_64__)
    {
        struct user_regs_struct regs, saved;
        struct iovec iov = { &regs, sizeof(regs) };
        struct iovec siov = { &saved, sizeof(saved) };

        pt_getregs(pid, &siov);
        memcpy(&regs, &saved, sizeof(regs));

        /* Set up: rdi = arg, rsp = new stack top, rip = entry */
        regs.rip = remote + entry_offset;
        regs.rdi = arg;
        regs.rsp = stack + 65536 - 8; /* leave room for alignment */

        /* Write INT3 as return address target */
        uint8_t trap = 0xcc; /* INT3 */
        int64_t trap_page = pt_remote_syscall(pid, gadget, __NR_mmap,
                                              0, 4096,
                                              PROT_READ | PROT_WRITE | PROT_EXEC,
                                              MAP_ANONYMOUS | MAP_PRIVATE,
                                              (uint64_t)-1, 0);
        if (trap_page > 0) {
            struct iovec tl2 = { &trap, 1 };
            struct iovec tr2 = { (void *)trap_page, 1 };
            process_vm_writev(pid, &tl2, 1, &tr2, 1, 0);
            /* Write trap_page address as return address on stack */
            uint64_t trap_addr = trap_page;
            struct iovec rl = { &trap_addr, 8 };
            struct iovec rr = { (void *)(stack + 65536 - 8), 8 };
            process_vm_writev(pid, &rl, 1, &rr, 1, 0);
        }

        pt_setregs(pid, &iov);
        ptrace(PTRACE_CONT, pid, NULL, NULL);

        /* Wait for our code to hit INT3 or complete */
        int status;
        waitpid(pid, &status, 0);

        /* Restore original state */
        pt_setregs(pid, &siov);
        ret = 0;
    }
#elif defined(__aarch64__)
    {
        struct {
            uint64_t regs[31];
            uint64_t sp;
            uint64_t pc;
            uint64_t pstate;
        } regs, saved;
        struct iovec iov = { &regs, sizeof(regs) };
        struct iovec siov = { &saved, sizeof(saved) };

        pt_getregs(pid, &siov);
        memcpy(&regs, &saved, sizeof(regs));

        regs.pc = remote + entry_offset;
        regs.regs[0] = arg;
        regs.sp = stack + 65536;

        /* Write BRK #0 as return trap */
        int64_t trap_page = pt_remote_syscall(pid, gadget, __NR_mmap,
                                              0, 4096,
                                              PROT_READ | PROT_WRITE | PROT_EXEC,
                                              MAP_ANONYMOUS | MAP_PRIVATE,
                                              (uint64_t)-1, 0);
        if (trap_page > 0) {
            uint32_t brk = 0xd4200000;
            struct iovec tl = { &brk, 4 };
            struct iovec tr = { (void *)trap_page, 4 };
            process_vm_writev(pid, &tl, 1, &tr, 1, 0);
            regs.regs[30] = trap_page; /* LR = trap */
        }

        pt_setregs(pid, &iov);
        ptrace(PTRACE_CONT, pid, NULL, NULL);

        int status;
        waitpid(pid, &status, 0);

        pt_setregs(pid, &siov);
        ret = 0;
    }
#elif defined(__i386__)
    {
        struct user_regs_struct regs, saved;
        struct iovec iov = { &regs, sizeof(regs) };
        struct iovec siov = { &saved, sizeof(saved) };

        pt_getregs(pid, &siov);
        memcpy(&regs, &saved, sizeof(regs));

        regs.eip = (unsigned long)(remote + entry_offset);
        regs.ecx = (unsigned long)arg; /* arg in ecx (cdecl stack push) */
        regs.esp = (unsigned long)(stack + 65536 - 16);

        /* Write INT3 trap page */
        int64_t trap_page = pt_remote_syscall(pid, gadget, __NR_mmap,
                                              0, 4096,
                                              PROT_READ | PROT_WRITE | PROT_EXEC,
                                              MAP_ANONYMOUS | MAP_PRIVATE,
                                              (uint64_t)-1, 0);
        if (trap_page > 0) {
            uint8_t trap = 0xcc;
            struct iovec tl = { &trap, 1 };
            struct iovec tr = { (void *)(uintptr_t)trap_page, 1 };
            process_vm_writev(pid, &tl, 1, &tr, 1, 0);
            /* Push arg and return address on stack */
            uint32_t stk[2] = { (uint32_t)trap_page, (uint32_t)arg };
            struct iovec sl = { stk, 8 };
            struct iovec sr = { (void *)(uintptr_t)(stack + 65536 - 16 + 4), 8 };
            process_vm_writev(pid, &sl, 1, &sr, 1, 0);
            /* Stack: [esp]=ret_addr [esp+4]=arg */
            uint32_t ret_addr = (uint32_t)trap_page;
            struct iovec rl = { &ret_addr, 4 };
            struct iovec rr = { (void *)(uintptr_t)(stack + 65536 - 16), 4 };
            process_vm_writev(pid, &rl, 1, &rr, 1, 0);
        }

        pt_setregs(pid, &iov);
        ptrace(PTRACE_CONT, pid, NULL, NULL);

        int status;
        waitpid(pid, &status, 0);

        pt_setregs(pid, &siov);
        ret = 0;
    }
#elif defined(__arm__)
    {
        struct {
            uint32_t uregs[18];
        } regs, saved;
        struct iovec iov = { &regs, sizeof(regs) };
        struct iovec siov = { &saved, sizeof(saved) };

        pt_getregs(pid, &siov);
        memcpy(&regs, &saved, sizeof(regs));

        regs.uregs[15] = (uint32_t)(remote + entry_offset); /* pc */
        regs.uregs[0]  = (uint32_t)arg;
        regs.uregs[13] = (uint32_t)(stack + 65536); /* sp */

        /* Write trap instruction */
        int64_t trap_page = pt_remote_syscall(pid, gadget, __NR_mmap,
                                              0, 4096,
                                              PROT_READ | PROT_WRITE | PROT_EXEC,
                                              MAP_ANONYMOUS | MAP_PRIVATE,
                                              (uint64_t)-1, 0);
        if (trap_page > 0) {
            /* UDF #0 (undefined instruction) to cause SIGILL as trap */
            uint32_t udf = 0xe7f001f0;
            struct iovec tl = { &udf, 4 };
            struct iovec tr = { (void *)(uintptr_t)trap_page, 4 };
            process_vm_writev(pid, &tl, 1, &tr, 1, 0);
            regs.uregs[14] = (uint32_t)trap_page; /* lr = trap */
        }

        pt_setregs(pid, &iov);
        ptrace(PTRACE_CONT, pid, NULL, NULL);

        int status;
        waitpid(pid, &status, 0);

        pt_setregs(pid, &siov);
        ret = 0;
    }
#elif defined(__mips__) && !defined(__mips64)
    {
        uint32_t mregs[45], msaved[45];
        struct iovec iov = { mregs, sizeof(mregs) };
        struct iovec siov = { msaved, sizeof(msaved) };

        pt_getregs(pid, &siov);
        memcpy(mregs, msaved, sizeof(mregs));

        mregs[40]     = (uint32_t)(remote + entry_offset); /* cp0_epc = PC */
        mregs[6 + 4]  = (uint32_t)arg;                     /* a0 */
        mregs[6 + 25] = (uint32_t)(remote + entry_offset); /* t9 for PIC */
        mregs[6 + 29] = (uint32_t)(stack + 65536);         /* sp */
        mregs[6 + 31] = 0;                                 /* ra = 0 (no return) */

        pt_setregs(pid, &iov);
        ptrace(PTRACE_CONT, pid, NULL, NULL);

        int status;
        waitpid(pid, &status, 0);

        pt_setregs(pid, &siov);
        ret = 0;
    }
#elif defined(__sparc__)
    {
        struct {
            uint32_t psr;
            uint32_t pc;
            uint32_t npc;
            uint32_t y;
            uint32_t u_regs[16];
        } regs, saved;
        struct iovec iov = { &regs, sizeof(regs) };
        struct iovec siov = { &saved, sizeof(saved) };

        pt_getregs(pid, &siov);
        memcpy(&regs, &saved, sizeof(regs));

        regs.pc  = (uint32_t)(remote + entry_offset);
        regs.npc = (uint32_t)(remote + entry_offset + 4);
        regs.u_regs[8]  = (uint32_t)arg;                   /* o0 */
        regs.u_regs[14] = (uint32_t)(stack + 65536 - 96);  /* sp (with frame) */

        pt_setregs(pid, &iov);
        ptrace(PTRACE_CONT, pid, NULL, NULL);

        int status;
        waitpid(pid, &status, 0);

        pt_setregs(pid, &siov);
        ret = 0;
    }
#endif

detach:
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return ret;
}

/* ------------------------------------------------------------------ */
/*  Find dlopen address in target process                             */
/* ------------------------------------------------------------------ */

static uint64_t find_remote_symbol(pid_t pid, const char *sym_name)
{
    /*
     * Strategy: find libc base in both our process and target,
     * compute offset of the symbol in ours, apply to target's base.
     */
    void *local_sym = dlsym(RTLD_DEFAULT, sym_name);
    if (!local_sym)
        return 0;

    /* Find our own libc base */
    Dl_info info;
    if (!dladdr(local_sym, &info) || !info.dli_fbase)
        return 0;
    uint64_t local_base = (uint64_t)(uintptr_t)info.dli_fbase;
    uint64_t sym_offset = (uint64_t)(uintptr_t)local_sym - local_base;

    /* Find the same library's base in target */
    const char *lib_name = info.dli_fname;
    /* Extract just the filename for matching */
    const char *base_name = strrchr(lib_name, '/');
    base_name = base_name ? base_name + 1 : lib_name;

    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE *maps = fopen(maps_path, "r");
    if (!maps)
        return 0;

    char line[512];
    uint64_t remote_base = 0;

    while (fgets(line, sizeof(line), maps)) {
        if (!strstr(line, base_name))
            continue;
        unsigned long start, end;
        char perms[5];
        if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) == 3) {
            /* Use the first (lowest) mapping — matches dladdr dli_fbase */
            remote_base = start;
            break;
        }
    }

    fclose(maps);

    if (!remote_base)
        return 0;

    return remote_base + sym_offset;
}

/* ------------------------------------------------------------------ */
/*  libload_inject_dylib — Thread-hijack remote dlopen()              */
/* ------------------------------------------------------------------ */

int libload_inject_dylib(pid_t pid, const char *so_path)
{
    if (!so_path)
        return -1;

    /* Find dlopen in target before attaching */
    uint64_t remote_dlopen = find_remote_symbol(pid, "dlopen");
    if (!remote_dlopen)
        return -1;

    if (pt_attach(pid) < 0)
        return -1;

    int ret = -1;
    uint64_t gadget = pt_find_syscall(pid);
    if (!gadget)
        goto detach;

    /* Allocate memory for path string */
    size_t path_len = strlen(so_path) + 1;
    size_t alloc_sz = ALIGN_UP(path_len, 4096);

    int64_t remote_path = pt_remote_syscall(pid, gadget, __NR_mmap,
                                            0, alloc_sz,
                                            PROT_READ | PROT_WRITE,
                                            MAP_ANONYMOUS | MAP_PRIVATE,
                                            (uint64_t)-1, 0);
    if (remote_path < 0 || remote_path == (int64_t)MAP_FAILED)
        goto detach;

    /* Write path string */
    struct iovec local = { (void *)so_path, path_len };
    struct iovec remv  = { (void *)remote_path, path_len };
    if (process_vm_writev(pid, &local, 1, &remv, 1, 0) != (ssize_t)path_len)
        goto detach;

    /* Allocate trap page for catching dlopen return */
    int64_t trap_page = pt_remote_syscall(pid, gadget, __NR_mmap,
                                          0, 4096,
                                          PROT_READ | PROT_WRITE | PROT_EXEC,
                                          MAP_ANONYMOUS | MAP_PRIVATE,
                                          (uint64_t)-1, 0);
    if (trap_page < 0)
        goto detach;

    /* Write trap instruction */
#if defined(__x86_64__)
    {
        uint8_t trap = 0xcc; /* INT3 */
        struct iovec tl = { &trap, 1 };
        struct iovec tr = { (void *)trap_page, 1 };
        process_vm_writev(pid, &tl, 1, &tr, 1, 0);
    }
#elif defined(__aarch64__)
    {
        uint32_t brk = 0xd4200000; /* BRK #0 */
        struct iovec tl = { &brk, 4 };
        struct iovec tr = { (void *)trap_page, 4 };
        process_vm_writev(pid, &tl, 1, &tr, 1, 0);
    }
#elif defined(__i386__)
    {
        uint8_t trap = 0xcc; /* INT3 */
        struct iovec tl = { &trap, 1 };
        struct iovec tr = { (void *)(uintptr_t)trap_page, 1 };
        process_vm_writev(pid, &tl, 1, &tr, 1, 0);
    }
#elif defined(__arm__)
    {
        uint32_t udf = 0xe7f001f0; /* UDF #0 (undefined instruction trap) */
        struct iovec tl = { &udf, 4 };
        struct iovec tr = { (void *)(uintptr_t)trap_page, 4 };
        process_vm_writev(pid, &tl, 1, &tr, 1, 0);
    }
#elif defined(__mips__)
    {
        uint32_t brk = 0x0000000d; /* BREAK */
        struct iovec tl = { &brk, 4 };
        struct iovec tr = { (void *)(uintptr_t)trap_page, 4 };
        process_vm_writev(pid, &tl, 1, &tr, 1, 0);
    }
#elif defined(__sparc__)
    {
        uint32_t illtrap = 0x00000000; /* ILLTRAP 0 */
        struct iovec tl = { &illtrap, 4 };
        struct iovec tr = { (void *)(uintptr_t)trap_page, 4 };
        process_vm_writev(pid, &tl, 1, &tr, 1, 0);
    }
#endif

    /* Hijack thread to call dlopen */
#if defined(__x86_64__)
    {
        struct user_regs_struct regs, saved;
        struct iovec iov = { &regs, sizeof(regs) };
        struct iovec siov = { &saved, sizeof(saved) };

        pt_getregs(pid, &siov);
        memcpy(&regs, &saved, sizeof(regs));

        /* dlopen(path, RTLD_NOW) — x86_64 ABI: rdi=arg1, rsi=arg2 */
        regs.rip = remote_dlopen;
        regs.rdi = remote_path;
        regs.rsi = RTLD_NOW;
        /* Align stack and push trap return address */
        regs.rsp = (saved.rsp & ~0xfULL) - 8;
        /* Write return address on stack */
        uint64_t trap_addr = trap_page;
        struct iovec rl = { &trap_addr, 8 };
        struct iovec rr = { (void *)regs.rsp, 8 };
        process_vm_writev(pid, &rl, 1, &rr, 1, 0);

        pt_setregs(pid, &iov);
        ptrace(PTRACE_CONT, pid, NULL, NULL);

        /* Wait for INT3 (dlopen returned) */
        int status;
        waitpid(pid, &status, 0);

        if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
            /* dlopen succeeded if rax != 0 */
            iov.iov_base = &regs;
            pt_getregs(pid, &iov);
            if (regs.rax != 0)
                ret = 0;
        }

        /* Restore original state */
        pt_setregs(pid, &siov);
    }
#elif defined(__aarch64__)
    {
        struct {
            uint64_t regs[31];
            uint64_t sp;
            uint64_t pc;
            uint64_t pstate;
        } regs, saved;
        struct iovec iov = { &regs, sizeof(regs) };
        struct iovec siov = { &saved, sizeof(saved) };

        pt_getregs(pid, &siov);
        memcpy(&regs, &saved, sizeof(regs));

        /* dlopen(path, RTLD_NOW) — aarch64 ABI: x0=arg1, x1=arg2 */
        regs.pc = remote_dlopen;
        regs.regs[0] = remote_path;
        regs.regs[1] = RTLD_NOW;
        regs.regs[30] = trap_page; /* LR = trap */

        pt_setregs(pid, &iov);
        ptrace(PTRACE_CONT, pid, NULL, NULL);

        int status;
        waitpid(pid, &status, 0);

        if (WIFSTOPPED(status)) {
            iov.iov_base = &regs;
            pt_getregs(pid, &iov);
            if (regs.regs[0] != 0)
                ret = 0;
        }

        pt_setregs(pid, &siov);
    }
#elif defined(__i386__)
    {
        struct user_regs_struct regs, saved;
        struct iovec iov = { &regs, sizeof(regs) };
        struct iovec siov = { &saved, sizeof(saved) };

        pt_getregs(pid, &siov);
        memcpy(&regs, &saved, sizeof(regs));

        /* dlopen(path, RTLD_NOW) — cdecl: args on stack */
        regs.eip = (unsigned long)remote_dlopen;
        regs.esp = (unsigned long)((saved.esp & ~0xfUL) - 16);
        /* Stack: [esp]=return_addr [esp+4]=path [esp+8]=flags */
        uint32_t frame[3] = {
            (uint32_t)trap_page,
            (uint32_t)remote_path,
            (uint32_t)RTLD_NOW
        };
        struct iovec fl = { frame, 12 };
        struct iovec fr = { (void *)(uintptr_t)regs.esp, 12 };
        process_vm_writev(pid, &fl, 1, &fr, 1, 0);

        pt_setregs(pid, &iov);
        ptrace(PTRACE_CONT, pid, NULL, NULL);

        int status;
        waitpid(pid, &status, 0);

        if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
            iov.iov_base = &regs;
            pt_getregs(pid, &iov);
            if (regs.eax != 0)
                ret = 0;
        }

        pt_setregs(pid, &siov);
    }
#elif defined(__arm__)
    {
        struct {
            uint32_t uregs[18];
        } regs, saved;
        struct iovec iov = { &regs, sizeof(regs) };
        struct iovec siov = { &saved, sizeof(saved) };

        pt_getregs(pid, &siov);
        memcpy(&regs, &saved, sizeof(regs));

        /* dlopen(path, RTLD_NOW) — AAPCS: r0=path, r1=flags */
        regs.uregs[15] = (uint32_t)remote_dlopen; /* pc */
        regs.uregs[0]  = (uint32_t)remote_path;
        regs.uregs[1]  = RTLD_NOW;
        regs.uregs[14] = (uint32_t)trap_page; /* lr = trap */

        pt_setregs(pid, &iov);
        ptrace(PTRACE_CONT, pid, NULL, NULL);

        int status;
        waitpid(pid, &status, 0);

        if (WIFSTOPPED(status)) {
            iov.iov_base = &regs;
            pt_getregs(pid, &iov);
            if (regs.uregs[0] != 0)
                ret = 0;
        }

        pt_setregs(pid, &siov);
    }
#elif defined(__mips__) && !defined(__mips64)
    {
        uint32_t mregs[45], msaved[45];
        struct iovec iov = { mregs, sizeof(mregs) };
        struct iovec siov = { msaved, sizeof(msaved) };

        pt_getregs(pid, &siov);
        memcpy(mregs, msaved, sizeof(mregs));

        /* dlopen(path, RTLD_NOW) — MIPS o32: a0=path, a1=flags */
        mregs[40]     = (uint32_t)remote_dlopen; /* cp0_epc = PC */
        mregs[6 + 25] = (uint32_t)remote_dlopen; /* t9 for PIC */
        mregs[6 + 4]  = (uint32_t)remote_path;   /* a0 */
        mregs[6 + 5]  = RTLD_NOW;                /* a1 */
        mregs[6 + 31] = (uint32_t)trap_page;     /* ra = trap */

        pt_setregs(pid, &iov);
        ptrace(PTRACE_CONT, pid, NULL, NULL);

        int status;
        waitpid(pid, &status, 0);

        if (WIFSTOPPED(status)) {
            iov.iov_base = mregs;
            pt_getregs(pid, &iov);
            if (mregs[6 + 2] != 0) /* v0 = return value */
                ret = 0;
        }

        pt_setregs(pid, &siov);
    }
#elif defined(__sparc__)
    {
        struct {
            uint32_t psr;
            uint32_t pc;
            uint32_t npc;
            uint32_t y;
            uint32_t u_regs[16];
        } regs, saved;
        struct iovec iov = { &regs, sizeof(regs) };
        struct iovec siov = { &saved, sizeof(saved) };

        pt_getregs(pid, &siov);
        memcpy(&regs, &saved, sizeof(regs));

        /* dlopen(path, RTLD_NOW) — SPARC: o0=path, o1=flags */
        regs.pc  = (uint32_t)remote_dlopen;
        regs.npc = (uint32_t)remote_dlopen + 4;
        regs.u_regs[8]  = (uint32_t)remote_path;  /* o0 */
        regs.u_regs[9]  = RTLD_NOW;               /* o1 */
        regs.u_regs[15] = (uint32_t)trap_page;    /* o7 = return addr */

        pt_setregs(pid, &iov);
        ptrace(PTRACE_CONT, pid, NULL, NULL);

        int status;
        waitpid(pid, &status, 0);

        if (WIFSTOPPED(status)) {
            iov.iov_base = &regs;
            pt_getregs(pid, &iov);
            if (regs.u_regs[8] != 0) /* o0 = return value */
                ret = 0;
        }

        pt_setregs(pid, &siov);
    }
#endif

detach:
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return ret;
}

/* ------------------------------------------------------------------ */
/*  libload_inject_spawn — LD_PRELOAD spawn                           */
/* ------------------------------------------------------------------ */

pid_t libload_inject_spawn(const char *target_path,
                           const char *so_path,
                           char *const argv[],
                           char *const envp[])
{
    if (!target_path || !so_path)
        return -1;

    pid_t pid = fork();
    if (pid < 0)
        return -1;

    if (pid == 0) {
        /* Child: set LD_PRELOAD and exec */

        /* Count existing envp */
        char *const *src_envp = envp ? envp : environ;
        int envc = 0;
        while (src_envp[envc]) envc++;

        /*
         * Build new envp: copy existing vars (skip any existing LD_PRELOAD),
         * add our LD_PRELOAD entry.
         */
        char **new_envp = calloc(envc + 2, sizeof(char *));
        if (!new_envp)
            _exit(127);

        /* Build LD_PRELOAD=<path> string */
        size_t plen = strlen("LD_PRELOAD=") + strlen(so_path) + 1;
        char *preload = malloc(plen);
        if (!preload)
            _exit(127);
        snprintf(preload, plen, "LD_PRELOAD=%s", so_path);

        int j = 0;
        new_envp[j++] = preload;
        for (int i = 0; i < envc; i++) {
            if (strncmp(src_envp[i], "LD_PRELOAD=", 11) != 0)
                new_envp[j++] = (char *)src_envp[i];
        }
        new_envp[j] = NULL;

        /* Build argv if not provided */
        char *default_argv[] = { (char *)target_path, NULL };
        char *const *exec_argv = argv ? argv : default_argv;

        execve(target_path, exec_argv, new_envp);
        _exit(127);
    }

    return pid;
}

#endif /* __linux__ */
