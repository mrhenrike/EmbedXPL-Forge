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
 * self_loader.h — Custom in-memory self-loader header.
 *
 * Uses own syscall infrastructure (syscall.h) with DJB2 hashing.
 * No third-party ReflectiveDLLInjection code remains.
 */

#ifndef _SELF_LOADER_H_
#define _SELF_LOADER_H_

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <intrin.h>

/*
 * Common definitions shared with dll.c
 */

#define DLL_HATSPLOIT_ATTACH    4
#define DLL_HATSPLOIT_DETACH    5
#define DLL_QUERY_HMODULE       6

#define DEREF(name)       (*(UINT_PTR *)(name))
#define DEREF_64(name)    (*(DWORD64 *)(name))
#define DEREF_32(name)    (*(DWORD *)(name))
#define DEREF_16(name)    (*(WORD *)(name))
#define DEREF_8(name)     (*(BYTE *)(name))

typedef ULONG_PTR (WINAPI *SELFLOADER)(ULONG_PTR);
typedef BOOL (WINAPI *DLLMAIN)(HINSTANCE, DWORD, LPVOID);
typedef HMODULE (WINAPI *LOADLIBRARYA)(LPCSTR);
typedef FARPROC (WINAPI *GETPROCADDRESS)(HMODULE, LPCSTR);
typedef BOOL    (WINAPI *DISABLETHREADLIBRARYCALLS)(HMODULE);

#define DLLEXPORT __declspec(dllexport)

/*
 * Direct syscall infrastructure — own implementation.
 */

#include "syscall.h"

/*
 * PEB structures — minimal definitions for loader walking.
 */

typedef struct _UNICODE_STR
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  pBuffer;
} UNICODE_STR, *PUNICODE_STR;

typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID      DllBase;
    PVOID      EntryPoint;
    ULONG      SizeOfImage;
    UNICODE_STR FullDllName;
    UNICODE_STR BaseDllName;
    ULONG      Flags;
    SHORT      LoadCount;
    SHORT      TlsIndex;
    LIST_ENTRY HashTableEntry;
    ULONG      TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA
{
    DWORD      dwLength;
    DWORD      dwInitialized;
    LPVOID     lpSsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    LPVOID     lpEntryInProgress;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct __PEB
{
    BYTE           bInheritedAddressSpace;
    BYTE           bReadImageFileExecOptions;
    BYTE           bBeingDebugged;
    BYTE           bSpareBool;
    LPVOID         lpMutant;
    LPVOID         lpImageBaseAddress;
    PPEB_LDR_DATA  pLdr;
    LPVOID         lpProcessParameters;
    LPVOID         lpSubSystemData;
    LPVOID         lpProcessHeap;
    PRTL_CRITICAL_SECTION pFastPebLock;
    LPVOID         lpFastPebLockRoutine;
    LPVOID         lpFastPebUnlockRoutine;
    DWORD          dwEnvironmentUpdateCount;
    LPVOID         lpKernelCallbackTable;
    DWORD          dwSystemReserved;
    DWORD          dwAtlThunkSListPtr32;
    LPVOID         pFreeList;
    DWORD          dwTlsExpansionCounter;
    LPVOID         lpTlsBitmap;
    DWORD          dwTlsBitmapBits[2];
    LPVOID         lpReadOnlySharedMemoryBase;
    LPVOID         lpReadOnlySharedMemoryHeap;
    LPVOID         lpReadOnlyStaticServerData;
    LPVOID         lpAnsiCodePageData;
    LPVOID         lpOemCodePageData;
    LPVOID         lpUnicodeCaseTableData;
    DWORD          dwNumberOfProcessors;
    DWORD          dwNtGlobalFlag;
    LARGE_INTEGER  liCriticalSectionTimeout;
    DWORD          dwHeapSegmentReserve;
    DWORD          dwHeapSegmentCommit;
    DWORD          dwHeapDeCommitTotalFreeThreshold;
    DWORD          dwHeapDeCommitFreeBlockThreshold;
    DWORD          dwNumberOfHeaps;
    DWORD          dwMaximumNumberOfHeaps;
    LPVOID         lpProcessHeaps;
    LPVOID         lpGdiSharedHandleTable;
    LPVOID         lpProcessStarterHelper;
    DWORD          dwGdiDCAttributeList;
    LPVOID         lpLoaderLock;
    DWORD          dwOSMajorVersion;
    DWORD          dwOSMinorVersion;
    WORD           wOSBuildNumber;
    WORD           wOSCSDVersion;
    DWORD          dwOSPlatformId;
    DWORD          dwImageSubsystem;
    DWORD          dwImageSubsystemMajorVersion;
    DWORD          dwImageSubsystemMinorVersion;
    DWORD          dwImageProcessAffinityMask;
    DWORD          dwGdiHandleBuffer[34];
    LPVOID         lpPostProcessInitRoutine;
    LPVOID         lpTlsExpansionBitmap;
    DWORD          dwTlsExpansionBitmapBits[32];
    DWORD          dwSessionId;
    ULARGE_INTEGER liAppCompatFlags;
    ULARGE_INTEGER liAppCompatFlagsUser;
    LPVOID         lppShimData;
    LPVOID         lpAppCompatInfo;
    UNICODE_STR    usCSDVersion;
    LPVOID         lpActivationContextData;
    LPVOID         lpProcessAssemblyStorageMap;
    LPVOID         lpSystemDefaultActivationContextData;
    LPVOID         lpSystemAssemblyStorageMap;
    DWORD          dwMinimumStackCommit;
} _PEB, *_PPEB;

/*
 * Page-lock support — prevent image from being paged out.
 */

#define ENABLE_STOPPAGING

/*
 * Relocation entry.
 */

typedef struct
{
    WORD offset : 12;
    WORD type   : 4;
} SELF_RELOC, *PSELF_RELOC;

/*
 * DJB2 hashes for PEB walking (kernel32 + ntdll module names,
 * LoadLibraryA + GetProcAddress function names).
 */

/* DJB2 over Unicode module name bytes (uppercase-normalized) */
#define MOD_KERNEL32 0x4FF6EC75
#define MOD_NTDLL    0x75E5074D

/* DJB2 over ASCII function names */
#define FN_LOADLIBRARYA              0x5FBFF0FB
#define FN_GETPROCADDRESS            0xCF31BB1F
#define FN_DISABLETHREADLIBRARYCALLS 0x530574F5

/*
 * Export name for the self-loader function.
 */

#define SELF_LOADER_EXPORT "_DllInit"

#endif /* _SELF_LOADER_H_ */
