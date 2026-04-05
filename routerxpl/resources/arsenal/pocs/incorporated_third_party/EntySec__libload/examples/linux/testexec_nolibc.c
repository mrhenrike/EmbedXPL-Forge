/*
 * testexec_nolibc.c — minimal executable using raw syscalls
 * Validates that the stack layout from the reflective loader is correct.
 * Build with: gcc -nostdlib -static -o testexec_nolibc testexec_nolibc.c
 */

#ifdef __x86_64__

static void write_str(const char *s)
{
    long len = 0;
    while (s[len]) len++;

    __asm__ volatile (
        "mov $1, %%rax\n"   /* sys_write */
        "mov $1, %%rdi\n"   /* fd = stdout */
        "syscall\n"
        :: "S"(s), "d"(len) : "rax", "rdi", "rcx", "r11", "memory"
    );
}

static void write_num(long n)
{
    char buf[32];
    int i = 30;
    buf[31] = 0;
    if (n == 0) { buf[i--] = '0'; }
    else while (n > 0) { buf[i--] = '0' + (n % 10); n /= 10; }
    write_str(buf + i + 1);
}

void _start(void)
{
    /* On entry, stack is: argc, argv[0], argv[1], ..., NULL, envp..., NULL, auxv... */
    long argc;
    char **argv;

    __asm__ volatile (
        "mov (%%rsp), %0\n"
        "lea 8(%%rsp), %1\n"
        : "=r"(argc), "=r"(argv)
    );

    write_str("[nolibc] argc=");
    write_num(argc);
    write_str("\n");

    for (long i = 0; i < argc; i++) {
        write_str("[nolibc] argv[");
        write_num(i);
        write_str("]=");
        write_str(argv[i]);
        write_str("\n");
    }

    __asm__ volatile (
        "mov $60, %%rax\n"  /* sys_exit */
        "xor %%rdi, %%rdi\n"
        "syscall\n"
        ::: "rax", "rdi"
    );
    __builtin_unreachable();
}

#elif defined(__aarch64__)

void _start(void) {
    __asm__ volatile ("mov x0, #0\nmov x8, #93\nsvc #0\n");
    __builtin_unreachable();
}

#endif
