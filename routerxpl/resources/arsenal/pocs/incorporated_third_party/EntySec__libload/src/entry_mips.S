#ifdef __mips__

    .text
    .globl ll_entry_trampoline
    .type  ll_entry_trampoline, @function
    .set   noreorder

/*
 * void ll_entry_trampoline(void *sp, void *entry)
 *
 * MIPS o32: sp = $a0, entry = $a1
 * Sets the stack pointer and jumps to entry.
 * $t9 is set to entry (PIC convention).
 * $a0 is zeroed.
 */
ll_entry_trampoline:
    move    $sp, $a0            /* switch stack */
    move    $t9, $a1            /* set $t9 for PIC entry */
    move    $a0, $zero          /* clear first arg */
    jr      $t9                 /* jump to entry */
    nop                         /* delay slot */

    .set   reorder
    .size  ll_entry_trampoline, . - ll_entry_trampoline

#endif
