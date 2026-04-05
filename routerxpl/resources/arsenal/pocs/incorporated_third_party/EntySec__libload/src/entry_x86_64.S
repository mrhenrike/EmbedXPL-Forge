/*
 * entry_x86_64.S — ELF entry point trampoline (x86_64)
 *
 * void ll_entry_trampoline(void *sp, void *entry)
 *
 * Switches to the new stack and jumps to the ELF entry point.
 * Does not return.
 *
 * System V ABI at _start:
 *   %rsp → argc
 *   %rdx = 0 (rtld_fini, unused)
 */

#ifdef __x86_64__

    .text
    .globl ll_entry_trampoline
    .type  ll_entry_trampoline, @function

ll_entry_trampoline:
    mov     %rdi, %rsp
    xor     %rdx, %rdx
    jmp     *%rsi

    .size ll_entry_trampoline, . - ll_entry_trampoline

#endif
