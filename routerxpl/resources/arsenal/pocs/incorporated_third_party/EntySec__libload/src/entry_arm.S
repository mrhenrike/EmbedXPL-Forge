#ifdef __arm__

    .text
    .globl ll_entry_trampoline
    .type  ll_entry_trampoline, %function

/*
 * void ll_entry_trampoline(void *sp, void *entry)
 *
 * AAPCS: sp = r0, entry = r1
 * Sets the stack pointer to r0 and jumps to r1.
 * r0 is zeroed (convention at ELF entry).
 * Uses BX for Thumb/ARM interwork.
 */
ll_entry_trampoline:
    mov     sp, r0              @ switch stack
    mov     r0, #0              @ clear r0
    bx      r1                  @ jump to entry

    .size ll_entry_trampoline, . - ll_entry_trampoline

#endif
