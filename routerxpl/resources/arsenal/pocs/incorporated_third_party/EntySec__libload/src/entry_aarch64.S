/*
 * entry_aarch64.S — ELF entry point trampoline (aarch64)
 *
 * void ll_entry_trampoline(void *sp, void *entry)
 *
 * Switches to the new stack and jumps to the ELF entry point.
 * Does not return.
 *
 * AAPCS64 at _start:
 *   sp → argc
 *   x0 = 0
 */

#ifdef __aarch64__

    .text
    .globl ll_entry_trampoline
    .type  ll_entry_trampoline, %function

ll_entry_trampoline:
    mov     sp, x0
    mov     x0, #0
    br      x1

    .size ll_entry_trampoline, . - ll_entry_trampoline

#endif
