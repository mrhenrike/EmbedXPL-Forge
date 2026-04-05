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
 * ARP COT plugin — enumerate the ARP table via GetIpNetTable.
 */

#ifdef __windows__

#include <pwny/api.h>
#include <pwny/tlv_types.h>
#include <pwny/c2.h>

#include <windows.h>

#define COT_PLUGIN
#include <pwny/tab_cot.h>

#define ARP_LIST \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       TAB_BASE, \
                       API_CALL)

#define TLV_TYPE_ARP_IP      TLV_TYPE_CUSTOM(TLV_TYPE_STRING, TAB_BASE, API_TYPE)
#define TLV_TYPE_ARP_MAC     TLV_TYPE_CUSTOM(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 1)
#define TLV_TYPE_ARP_TYPE    TLV_TYPE_CUSTOM(TLV_TYPE_INT,    TAB_BASE, API_TYPE)
#define TLV_TYPE_ARP_IFINDEX TLV_TYPE_CUSTOM(TLV_TYPE_INT,    TAB_BASE, API_TYPE + 1)
#define TLV_TYPE_ARP_GROUP   TLV_TYPE_CUSTOM(TLV_TYPE_GROUP,  TAB_BASE, API_TYPE)

/* ------------------------------------------------------------------ */
/* Win32 function pointer types                                        */
/* ------------------------------------------------------------------ */

/* MIB_IPNETROW structure */
typedef struct
{
    DWORD dwIndex;
    DWORD dwPhysAddrLen;
    BYTE  bPhysAddr[8];
    DWORD dwAddr;
    DWORD dwType;
} MIB_IPNETROW_COT;

/* MIB_IPNETTABLE structure */
typedef struct
{
    DWORD          dwNumEntries;
    MIB_IPNETROW_COT table[1];
} MIB_IPNETTABLE_COT;

typedef DWORD (WINAPI *fn_GetIpNetTable)(MIB_IPNETTABLE_COT *, ULONG *, BOOL);

static struct
{
    fn_GetIpNetTable pGetIpNetTable;
} w;

/* ------------------------------------------------------------------ */
/* Helper: format IP address                                           */
/* ------------------------------------------------------------------ */

static void ip_to_str(DWORD ip, char *buf, int bufsz)
{
    unsigned char *b = (unsigned char *)&ip;
    int i = 0;
    int n;

    for (n = 0; n < 4; n++)
    {
        unsigned char val = b[n];
        if (val >= 100) buf[i++] = '0' + val / 100;
        if (val >= 10)  buf[i++] = '0' + (val / 10) % 10;
        buf[i++] = '0' + val % 10;
        if (n < 3) buf[i++] = '.';
    }
    buf[i] = '\0';
}

/* ------------------------------------------------------------------ */
/* Helper: format MAC address                                          */
/* ------------------------------------------------------------------ */

static void mac_to_str(BYTE *mac, DWORD len, char *buf, int bufsz)
{
    static const char hex[] = "0123456789abcdef";
    DWORD i;
    int p = 0;

    for (i = 0; i < len && i < 6; i++)
    {
        if (i > 0) buf[p++] = ':';
        buf[p++] = hex[(mac[i] >> 4) & 0x0f];
        buf[p++] = hex[mac[i] & 0x0f];
    }
    buf[p] = '\0';
}

/* ------------------------------------------------------------------ */
/* ARP list handler                                                    */
/* ------------------------------------------------------------------ */

static tlv_pkt_t *arp_list(c2_t *c2)
{
    MIB_IPNETTABLE_COT *table = NULL;
    ULONG size = 0;
    DWORD ret;
    DWORD i;
    tlv_pkt_t *result;

    /* First call to get required size */
    ret = w.pGetIpNetTable(NULL, &size, FALSE);
    if (ret != ERROR_INSUFFICIENT_BUFFER || size == 0)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    table = (MIB_IPNETTABLE_COT *)malloc(size);
    if (table == NULL)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    ret = w.pGetIpNetTable(table, &size, FALSE);
    if (ret != NO_ERROR)
    {
        free(table);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);

    for (i = 0; i < table->dwNumEntries; i++)
    {
        MIB_IPNETROW_COT *row = &table->table[i];
        tlv_pkt_t *entry;
        char ip_buf[32];
        char mac_buf[32];

        entry = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);

        ip_to_str(row->dwAddr, ip_buf, sizeof(ip_buf));
        mac_to_str(row->bPhysAddr, row->dwPhysAddrLen, mac_buf, sizeof(mac_buf));

        tlv_pkt_add_string(entry, TLV_TYPE_ARP_IP, ip_buf);
        tlv_pkt_add_string(entry, TLV_TYPE_ARP_MAC, mac_buf);
        tlv_pkt_add_u32(entry, TLV_TYPE_ARP_TYPE, (int)row->dwType);
        tlv_pkt_add_u32(entry, TLV_TYPE_ARP_IFINDEX, (int)row->dwIndex);

        tlv_pkt_add_tlv(result, TLV_TYPE_ARP_GROUP, entry);
        tlv_pkt_destroy(entry);
    }

    free(table);
    return result;
}

/* ------------------------------------------------------------------ */
/* COT entry                                                           */
/* ------------------------------------------------------------------ */

COT_ENTRY
{
    w.pGetIpNetTable = (fn_GetIpNetTable)cot_resolve("iphlpapi.dll",
                                                      "GetIpNetTable");

    api_call_register(api_calls, ARP_LIST, (api_t)arp_list);
}

#endif
