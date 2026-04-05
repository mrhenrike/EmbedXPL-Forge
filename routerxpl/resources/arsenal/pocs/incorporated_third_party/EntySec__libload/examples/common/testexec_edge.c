/*
 * testexec_edge — Edge-case test executable for libload
 *
 * Exercises: global data, BSS zero-fill, function pointers,
 * pointer arrays (rebases), recursive calls, large stack frames,
 * multiple library imports, and heap allocation.
 *
 * Returns 0 on success, or the number of failed tests.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ── Edge 1: Global initialized data (__DATA segment) ──────────── */
static int g_value = 42;
static double g_pi = 3.14159265358979;

/* ── Edge 2: Global string pointer (requires rebase fixup) ─────── */
static const char *g_greeting = "Hello from global!";

/* ── Edge 3: Function pointer in global (requires rebase fixup) ── */
static int (*g_printf)(const char *, ...) = printf;

/* ── Edge 4: Another function pointer ─────────────────────────── */
typedef size_t (*strlen_fn)(const char *);
static strlen_fn g_strlen = strlen;

/* ── Edge 5: Uninitialized global / BSS (vmsize > filesize) ───── */
static char g_bss_buffer[8192];
static int g_bss_int;

/* ── Edge 6: Array of pointers (each entry needs rebase) ───────── */
static const char *g_strings[] = {
    "alpha",
    "beta",
    "gamma",
    "delta",
    "epsilon",
    NULL
};

/* ── Edge 7: Struct with embedded pointers ─────────────────────── */
struct test_entry {
    const char *name;
    int value;
};

static struct test_entry g_entries[] = {
    { "first",  1 },
    { "second", 2 },
    { "third",  3 },
    { NULL,     0 }
};

/* ── Edge 8: Recursive function (stack correctness) ────────────── */
static int fibonacci(int n)
{
    if (n <= 1) return n;
    return fibonacci(n - 1) + fibonacci(n - 2);
}

/* ── Edge 9: Large stack frame ─────────────────────────────────── */
static int stack_heavy(void)
{
    volatile char buf[16384];
    memset((char *)buf, 'X', sizeof(buf));
    buf[sizeof(buf) - 1] = '\0';
    return (int)strlen((const char *)buf);
}

/* ── Helpers ───────────────────────────────────────────────────── */

static int errors;

#define CHECK(cond, fmt, ...)                                       \
    do {                                                            \
        if (cond) {                                                 \
            printf("[edge] PASS: " fmt "\n", ##__VA_ARGS__);        \
        } else {                                                    \
            printf("[edge] FAIL: " fmt "\n", ##__VA_ARGS__);        \
            errors++;                                               \
        }                                                           \
    } while (0)

/* ── main ──────────────────────────────────────────────────────── */

int main(int argc, char **argv)
{
    errors = 0;

    printf("[edge] === Edge-case tests ===\n");
    printf("[edge] argc=%d\n", argc);
    for (int i = 0; i < argc; i++)
        printf("[edge] argv[%d]=%s\n", i, argv[i]);

    /* 1. Global int */
    CHECK(g_value == 42, "global int = %d", g_value);

    /* 2. Global double */
    CHECK(g_pi > 3.14 && g_pi < 3.15,
          "global double = %.6f", g_pi);

    /* 3. Global string pointer (rebase) */
    CHECK(strcmp(g_greeting, "Hello from global!") == 0,
          "global string = \"%s\"", g_greeting);

    /* 4. Function pointer (printf) */
    int n = g_printf("[edge] PASS: function pointer (printf) works\n");
    CHECK(n > 0, "printf returned %d", n);

    /* 5. Function pointer (strlen) */
    CHECK(g_strlen("abcde") == 5,
          "function pointer (strlen) = %zu", g_strlen("abcde"));

    /* 6. BSS zero-init */
    int bss_ok = 1;
    for (int i = 0; i < (int)sizeof(g_bss_buffer); i++) {
        if (g_bss_buffer[i] != 0) { bss_ok = 0; break; }
    }
    CHECK(bss_ok, "BSS char[%zu] is zero-initialized",
          sizeof(g_bss_buffer));
    CHECK(g_bss_int == 0, "BSS int = %d", g_bss_int);

    /* 7. Pointer array (each element rebased) */
    int pcount = 0;
    while (g_strings[pcount]) pcount++;
    CHECK(pcount == 5, "pointer array has %d entries", pcount);
    CHECK(strcmp(g_strings[2], "gamma") == 0,
          "pointer array[2] = \"%s\"", g_strings[2]);

    /* 8. Struct array with embedded pointers */
    CHECK(g_entries[0].value == 1 &&
          strcmp(g_entries[0].name, "first") == 0,
          "struct entry[0] = { \"%s\", %d }",
          g_entries[0].name, g_entries[0].value);
    CHECK(g_entries[2].value == 3 &&
          strcmp(g_entries[2].name, "third") == 0,
          "struct entry[2] = { \"%s\", %d }",
          g_entries[2].name, g_entries[2].value);

    /* 9. Recursion (stack) */
    int fib = fibonacci(20);
    CHECK(fib == 6765, "fibonacci(20) = %d", fib);

    /* 10. Large stack frame */
    int slen = stack_heavy();
    CHECK(slen == 16383, "stack_heavy() filled %d bytes", slen);

    /* 11. Multiple library imports */
    pid_t pid = getpid();
    CHECK(pid > 0, "getpid() = %d", pid);

    /* 12. Heap allocation */
    char *heap = malloc(256);
    CHECK(heap != NULL, "malloc(256) = %p", (void *)heap);
    if (heap) {
        snprintf(heap, 256, "heap string %d", 12345);
        CHECK(strcmp(heap, "heap string 12345") == 0,
              "snprintf on heap = \"%s\"", heap);
        free(heap);
    }

    /* 13. Write to BSS, then verify */
    memset(g_bss_buffer, 'A', 100);
    g_bss_buffer[100] = '\0';
    CHECK(strlen(g_bss_buffer) == 100,
          "BSS write/read = %zu bytes", strlen(g_bss_buffer));

    /* Summary */
    printf("[edge] === Results: %d error(s) ===\n", errors);
    return errors;
}
