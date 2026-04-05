/*
 * inject_payload.c — Payload library for injection tests
 *
 * Constructor creates a marker file when loaded via dlopen.
 */

#include <stdio.h>
#include <unistd.h>

__attribute__((constructor))
static void payload_init(void)
{
    FILE *f = fopen("/tmp/libload_inject_ok", "w");
    if (f) {
        fprintf(f, "payload loaded in PID %d\n", getpid());
        fclose(f);
    }
    fprintf(stderr, "[payload] injected into PID %d\n", getpid());
}
