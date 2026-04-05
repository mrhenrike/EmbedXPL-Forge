#ifdef __sparc__

    .text
    .globl ll_entry_trampoline
    .type  ll_entry_trampoline, #function

/*
 * void ll_entry_trampoline(void *sp, void *entry)
 *
 * SPARC: sp = %o0, entry = %o1
 * Sets the stack pointer and jumps to entry.
 * %o0 is zeroed.
 */
ll_entry_trampoline:
    mov     %o0, %sp            ! switch stack
    clr     %o0                 ! clear first arg
    jmp     %o1                 ! jump to entry
    nop                         ! delay slot

    .size ll_entry_trampoline, (. - ll_entry_trampoline)

#endif
