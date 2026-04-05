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
 * UAC COT plugin — check elevation status and integrity level.
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


#define UAC_INFO \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       TAB_BASE, \
                       API_CALL)

#define TLV_TYPE_UAC_ELEVATED \
        TLV_TYPE_CUSTOM(TLV_TYPE_INT, TAB_BASE, API_TYPE)

#define TLV_TYPE_UAC_INTEGRITY \
        TLV_TYPE_CUSTOM(TLV_TYPE_INT, TAB_BASE, API_TYPE + 1)

#define TLV_TYPE_UAC_INTEGRITY_NAME \
        TLV_TYPE_CUSTOM(TLV_TYPE_STRING, TAB_BASE, API_TYPE)

#define INTEGRITY_UNKNOWN  0
#define INTEGRITY_LOW      1
#define INTEGRITY_MEDIUM   2
#define INTEGRITY_HIGH     3
#define INTEGRITY_SYSTEM   4

/* ------------------------------------------------------------------ */
/* Win32 typedefs                                                      */
/* ------------------------------------------------------------------ */

typedef BOOL  (WINAPI *fn_OpenProcessToken)(HANDLE, DWORD, PHANDLE);
typedef BOOL  (WINAPI *fn_GetTokenInformation)(HANDLE, TOKEN_INFORMATION_CLASS,
                                                LPVOID, DWORD, PDWORD);
typedef HANDLE (WINAPI *fn_GetCurrentProcess)(void);
typedef BOOL  (WINAPI *fn_CloseHandle)(HANDLE);
typedef PDWORD (WINAPI *fn_GetSidSubAuthority)(PSID, DWORD);
typedef PUCHAR (WINAPI *fn_GetSidSubAuthorityCount)(PSID);

static struct
{
    fn_OpenProcessToken         pOpenProcessToken;
    fn_GetTokenInformation      pGetTokenInformation;
    fn_GetCurrentProcess        pGetCurrentProcess;
    fn_CloseHandle              pCloseHandle;
    fn_GetSidSubAuthority       pGetSidSubAuthority;
    fn_GetSidSubAuthorityCount  pGetSidSubAuthorityCount;
} w;

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

static int uac_get_integrity_level(void)
{
    HANDLE hToken;
    DWORD dwLength;
    PTOKEN_MANDATORY_LABEL pTIL;
    DWORD dwIntegrityLevel;

    if (!w.pOpenProcessToken(w.pGetCurrentProcess(), TOKEN_QUERY, &hToken))
        return INTEGRITY_UNKNOWN;

    dwLength = 0;
    w.pGetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwLength);

    if (dwLength == 0)
    {
        w.pCloseHandle(hToken);
        return INTEGRITY_UNKNOWN;
    }

    pTIL = (PTOKEN_MANDATORY_LABEL)calloc(1, dwLength);
    if (pTIL == NULL)
    {
        w.pCloseHandle(hToken);
        return INTEGRITY_UNKNOWN;
    }

    if (!w.pGetTokenInformation(hToken, TokenIntegrityLevel, pTIL, dwLength, &dwLength))
    {
        free(pTIL);
        w.pCloseHandle(hToken);
        return INTEGRITY_UNKNOWN;
    }

    dwIntegrityLevel = *w.pGetSidSubAuthority(
        pTIL->Label.Sid,
        (DWORD)(UCHAR)(*w.pGetSidSubAuthorityCount(pTIL->Label.Sid) - 1)
    );

    free(pTIL);
    w.pCloseHandle(hToken);

    if (dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID)
        return INTEGRITY_SYSTEM;
    else if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID)
        return INTEGRITY_HIGH;
    else if (dwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID)
        return INTEGRITY_MEDIUM;
    else
        return INTEGRITY_LOW;
}

static int uac_is_elevated(void)
{
    HANDLE hToken;
    TOKEN_ELEVATION elevation;
    DWORD dwSize;

    if (!w.pOpenProcessToken(w.pGetCurrentProcess(), TOKEN_QUERY, &hToken))
        return 0;

    dwSize = sizeof(TOKEN_ELEVATION);
    if (!w.pGetTokenInformation(hToken, TokenElevation, &elevation,
                                sizeof(elevation), &dwSize))
    {
        w.pCloseHandle(hToken);
        return 0;
    }

    w.pCloseHandle(hToken);
    return elevation.TokenIsElevated ? 1 : 0;
}

static const char *uac_integrity_name(int level)
{
    switch (level)
    {
        case INTEGRITY_LOW:    return "Low";
        case INTEGRITY_MEDIUM: return "Medium";
        case INTEGRITY_HIGH:   return "High";
        case INTEGRITY_SYSTEM: return "System";
        default:               return "Unknown";
    }
}

/* ------------------------------------------------------------------ */
/* Handler                                                             */
/* ------------------------------------------------------------------ */

static tlv_pkt_t *uac_info(c2_t *c2)
{
    int elevated;
    int integrity;
    tlv_pkt_t *result;

    elevated = uac_is_elevated();
    integrity = uac_get_integrity_level();

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
    tlv_pkt_add_u32(result, TLV_TYPE_UAC_ELEVATED, elevated);
    tlv_pkt_add_u32(result, TLV_TYPE_UAC_INTEGRITY, integrity);
    tlv_pkt_add_string(result, TLV_TYPE_UAC_INTEGRITY_NAME,
                       (char *)uac_integrity_name(integrity));

    return result;
}

/* ------------------------------------------------------------------ */
/* COT entry                                                           */
/* ------------------------------------------------------------------ */

COT_ENTRY
{
    w.pOpenProcessToken        = (fn_OpenProcessToken)cot_resolve("advapi32.dll", "OpenProcessToken");
    w.pGetTokenInformation     = (fn_GetTokenInformation)cot_resolve("advapi32.dll", "GetTokenInformation");
    w.pGetCurrentProcess       = (fn_GetCurrentProcess)cot_resolve("kernel32.dll", "GetCurrentProcess");
    w.pCloseHandle             = (fn_CloseHandle)cot_resolve("kernel32.dll", "CloseHandle");
    w.pGetSidSubAuthority      = (fn_GetSidSubAuthority)cot_resolve("advapi32.dll", "GetSidSubAuthority");
    w.pGetSidSubAuthorityCount = (fn_GetSidSubAuthorityCount)cot_resolve("advapi32.dll", "GetSidSubAuthorityCount");

    api_call_register(api_calls, UAC_INFO, (api_t)uac_info);
}

#else /* POSIX */

#include <pwny/api.h>
#include <pwny/tab.h>

void register_tab_api_calls(api_calls_t **api_calls)
{
    (void)api_calls;
}

#endif
