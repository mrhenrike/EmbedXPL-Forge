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
 * syscall.h — Direct syscall infrastructure.
 *
 * Own implementation replacing the third-party DirectSyscall.h.
 * Uses DJB2 hashing (same as PEB walking) instead of signatured ROR13.
 * Struct names, field names and function names are all unique.
 */

#ifndef _PWNY_SYSCALL_H_
#define _PWNY_SYSCALL_H_

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <intrin.h>

#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif

/* ---- DJB2 hash (compile-time usable, runtime only) ---- */

static inline __attribute__((always_inline)) DWORD sc_djb2(const char *s)
{
    DWORD h = 5381;

    while (*s)
    {
        h = ((h << 5) + h) + (BYTE)*s;
        s++;
    }

    return h;
}

/* ---- Syscall descriptor ---- */

typedef struct
{
    DWORD  hash;       /* DJB2 hash of the Zw* function name */
    DWORD  nargs;      /* number of arguments for stack fixup */
    DWORD  number;     /* resolved syscall number */
    PVOID  trampoline; /* address inside ntdll past the preamble */
} sc_entry_t;

/* ---- Pre-computed DJB2 hashes for Zw* names ---- */
/*
 * python3 -c "
 * def djb2(s):
 *     h = 5381
 *     for c in s:
 *         h = ((h << 5) + h + ord(c)) & 0xFFFFFFFF
 *     return h
 * for n in ['ZwAllocateVirtualMemory','ZwProtectVirtualMemory',
 *           'ZwFlushInstructionCache','ZwLockVirtualMemory']:
 *     print(f'#define SC_{n[2:].upper()}_HASH  0x{djb2(n):08X}')
 * "
 */
#define SC_ALLOCATEVIRTUALMEMORY_HASH  0x58B1E78D
#define SC_PROTECTVIRTUALMEMORY_HASH   0xE0772819
#define SC_FLUSHINSTRUCTIONCACHE_HASH  0xFD83B578
#define SC_LOCKVIRTUALMEMORY_HASH      0xAE1A38D3

/* Max number of Zw* exports we'll enumerate */
#define SC_MAX_ENTRIES 600

/* ---- Internal sort entry ---- */

typedef struct
{
    DWORD hash;
    PVOID addr;
} sc_sort_entry_t;

typedef struct
{
    DWORD            count;
    sc_sort_entry_t  entries[SC_MAX_ENTRIES];
} sc_sort_list_t;

/* ---- Function prototypes ---- */

BOOL sc_resolve(PVOID ntdll_base, sc_entry_t *entries[], DWORD count);

/* Assembly trampoline (gate_x64.S) */
extern NTSTATUS sc_gate(VOID);

/* Per-syscall wrappers (syscall.c) */
NTSTATUS sc_NtAllocateVirtualMemory(sc_entry_t *e, HANDLE proc,
                                    PVOID *base, ULONG_PTR zero_bits,
                                    PSIZE_T size, ULONG alloc_type,
                                    ULONG protect);

NTSTATUS sc_NtProtectVirtualMemory(sc_entry_t *e, HANDLE proc,
                                   PVOID *base, PSIZE_T size,
                                   ULONG new_prot, PULONG old_prot);

NTSTATUS sc_NtFlushInstructionCache(sc_entry_t *e, HANDLE proc,
                                    PVOID *base, SIZE_T size);

NTSTATUS sc_NtLockVirtualMemory(sc_entry_t *e, HANDLE proc,
                                PVOID *base, PSIZE_T size, ULONG type);

#endif /* _PWNY_SYSCALL_H_ */
