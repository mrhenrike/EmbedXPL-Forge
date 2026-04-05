#ifdef __i386__

    .text
    .globl ll_entry_trampoline
    .type  ll_entry_trampoline, @function

/*
 * void ll_entry_trampoline(void *sp, void *entry)
 *
 * i386 cdecl: sp = [esp+4], entry = [esp+8]
 * Sets the stack pointer to sp and jumps to entry.
 * EDX is zeroed (rtld_fini convention).
 */
ll_entry_trampoline:
    mov     4(%esp), %ecx       /* ecx = sp */
    mov     8(%esp), %eax       /* eax = entry */
    mov     %ecx, %esp          /* switch stack */
    xor     %edx, %edx          /* rtld_fini = NULL */
    jmp     *%eax               /* jump to entry */

    .size ll_entry_trampoline, . - ll_entry_trampoline

#endif
