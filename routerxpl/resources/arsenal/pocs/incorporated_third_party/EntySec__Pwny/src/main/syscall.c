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
 * syscall.c — Direct syscall resolution and wrappers.
 *
 * Replaces DirectSyscall.c with DJB2-hashed, uniquely-named code.
 */

#include "syscall.h"

/* ---- Disable optimizations for the stub + wrappers ---- */
#ifdef __MINGW32__
#pragma GCC push_options
#pragma GCC optimize ("O0")
#endif

/*
 * sc_stub — called by every wrapper; the actual work is done
 * by the assembly trampoline (sc_gate in gate_x64.S) which
 * picks up the sc_entry_t pointer from the shadow space and
 * shifts arguments before returning into the ntdll stub.
 */

static NTSTATUS sc_stub(sc_entry_t *entry, ...)
{
    return sc_gate();
}

/* ---- Per-syscall wrappers (argument count matters for gate) ---- */

NTSTATUS sc_NtAllocateVirtualMemory(sc_entry_t *e, HANDLE proc,
                                    PVOID *base, ULONG_PTR zero_bits,
                                    PSIZE_T size, ULONG alloc_type,
                                    ULONG protect)
{
    return sc_stub(e, proc, base, zero_bits, size, alloc_type, protect);
}

NTSTATUS sc_NtProtectVirtualMemory(sc_entry_t *e, HANDLE proc,
                                   PVOID *base, PSIZE_T size,
                                   ULONG new_prot, PULONG old_prot)
{
    return sc_stub(e, proc, base, size, new_prot, old_prot);
}

NTSTATUS sc_NtFlushInstructionCache(sc_entry_t *e, HANDLE proc,
                                    PVOID *base, SIZE_T size)
{
    return sc_stub(e, proc, base, size);
}

NTSTATUS sc_NtLockVirtualMemory(sc_entry_t *e, HANDLE proc,
                                PVOID *base, PSIZE_T size, ULONG type)
{
    return sc_stub(e, proc, base, size, type);
}

#ifdef __MINGW32__
#pragma GCC pop_options
#endif

/* ---- Trampoline address extraction ---- */

static BOOL sc_extract_trampoline(PVOID stub, sc_entry_t *entry)
{
    if (stub == NULL || entry == NULL)
        return FALSE;

#ifdef _WIN64
    /*
     * Normal x64 ntdll stub:
     *   4C 8B D1          mov r10, rcx
     *   B8 XX XX 00 00    mov eax, <syscall_nr>
     *   <-- we want to land here (offset +8) -->
     *   0F 05             syscall
     *   C3                ret
     *
     * Hooked stub starts with E9 (jmp), same offset works.
     */
    if ((*(PUINT32)stub == 0xb8d18b4c &&
         *(PUSHORT)((PBYTE)stub + 4) == (USHORT)entry->number) ||
        *(PBYTE)stub == 0xe9)
    {
        entry->trampoline = (PVOID)((PBYTE)stub + 8);
        return TRUE;
    }
#else
    /*
     * x86 ntdll stub:
     *   B8 XX XX 00 00    mov eax, <syscall_nr>
     */
    if ((*(PBYTE)stub == 0xb8 &&
         *(PUSHORT)((PBYTE)stub + 1) == (USHORT)entry->number) ||
        *(PBYTE)stub == 0xe9)
    {
        entry->trampoline = (PVOID)((PBYTE)stub + 5);
        return TRUE;
    }
#endif

    return FALSE;
}

/* ---- Resolve syscall numbers by DJB2 hash ---- */

BOOL sc_resolve(PVOID ntdll_base, sc_entry_t *entries[], DWORD count)
{
    PIMAGE_DOS_HEADER dos;
    PIMAGE_NT_HEADERS nt;
    PIMAGE_EXPORT_DIRECTORY exp;
    PDWORD names, funcs;
    PWORD  ords;
    DWORD  i, j;
    sc_sort_list_t list;

    dos   = (PIMAGE_DOS_HEADER)ntdll_base;
    nt    = (PIMAGE_NT_HEADERS)((PBYTE)ntdll_base + dos->e_lfanew);
    exp   = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)ntdll_base +
                nt->OptionalHeader.DataDirectory[0].VirtualAddress);
    names = (PDWORD)((PBYTE)ntdll_base + exp->AddressOfNames);
    funcs = (PDWORD)((PBYTE)ntdll_base + exp->AddressOfFunctions);
    ords  = (PWORD)((PBYTE)ntdll_base + exp->AddressOfNameOrdinals);

    /* Collect all Zw* exports */
    list.count = 0;

    for (i = 0; i < exp->NumberOfNames; i++)
    {
        char *name = (char *)((PBYTE)ntdll_base + names[i]);

        if (name[0] == 'Z' && name[1] == 'w')
        {
            list.entries[list.count].hash = sc_djb2(name);
            list.entries[list.count].addr =
                (PVOID)((PBYTE)ntdll_base + funcs[ords[i]]);

            if (++list.count == SC_MAX_ENTRIES)
                break;
        }
    }

    /* Sort by address — index = syscall number */
    for (i = 0; i < list.count - 1; i++)
    {
        for (j = 0; j < list.count - i - 1; j++)
        {
            if (list.entries[j].addr > list.entries[j + 1].addr)
            {
                sc_sort_entry_t tmp = list.entries[j];
                list.entries[j]     = list.entries[j + 1];
                list.entries[j + 1] = tmp;
            }
        }
    }

    /* Match requested entries */
    for (i = 0; i < count; i++)
    {
        for (j = 0; j < list.count; j++)
        {
            if (list.entries[j].hash == entries[i]->hash)
            {
                entries[i]->number = j;

                if (!sc_extract_trampoline(list.entries[j].addr, entries[i]))
                    return FALSE;

                break;
            }
        }
    }

    /* Verify all resolved */
    for (i = 0; i < count; i++)
    {
        if (entries[i]->trampoline == NULL)
            return FALSE;
    }

    return TRUE;
}
