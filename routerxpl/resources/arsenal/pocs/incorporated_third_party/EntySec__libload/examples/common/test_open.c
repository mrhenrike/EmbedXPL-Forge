/*
 * test_open.c — Tests libload_open, libload_sym, libload_close
 *
 * Loads test_lib.so/.dylib from memory, resolves test_add, calls it.
 *
 * Usage: test_open [path_to_shared_lib]
 */

#include <stdio.h>
#include <stdlib.h>
#include <libload.h>

static unsigned char *read_file(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return NULL; }
    fseek(f, 0, SEEK_END);
    *len = (size_t)ftell(f);
    rewind(f);
    unsigned char *buf = malloc(*len);
    if (!buf || fread(buf, 1, *len, f) != *len) {
        free(buf); fclose(f); return NULL;
    }
    fclose(f);
    return buf;
}

int main(int argc, char **argv)
{
    const char *path = argc > 1 ? argv[1] :
#ifdef __APPLE__
        "test_lib.dylib";
#else
        "test_lib.so";
#endif

    printf("=== libload_open test (%s) ===\n", path);

    size_t len;
    unsigned char *buf = read_file(path, &len);
    if (!buf) return 1;

    libload_t lib = libload_open(buf, len);
    free(buf);
    if (!lib) {
        fprintf(stderr, "FAIL: libload_open returned NULL\n");
        return 1;
    }
    printf("libload_open: OK\n");

    typedef int (*add_fn)(int, int);
    add_fn fn = (add_fn)libload_sym(lib, "test_add");
    if (!fn) {
        fprintf(stderr, "FAIL: libload_sym(test_add) returned NULL\n");
        libload_close(lib);
        return 1;
    }
    printf("libload_sym: OK\n");

    int result = fn(2, 3);
    if (result != 5) {
        fprintf(stderr, "FAIL: test_add(2, 3) = %d, expected 5\n", result);
        libload_close(lib);
        return 1;
    }
    printf("test_add(2, 3) = %d: OK\n", result);

    libload_close(lib);
    printf("libload_close: OK\n");

    printf("\n=== PASS ===\n");
    return 0;
}
