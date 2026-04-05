/*
 * test_llbin.c — Tests libload_exec with llbin pre-packed format
 *
 * Usage: test_llbin [path_to_llbin]
 *
 * Create an llbin first: llpack testexec testexec.llbin
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
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
    const char *path = argc > 1 ? argv[1] : "testexec.llbin";

    printf("=== libload_exec llbin test (%s) ===\n", path);

    size_t len;
    unsigned char *buf = read_file(path, &len);
    if (!buf) return 1;

    char *exec_argv[] = { (char *)path, "--hello", "world", NULL };
    pid_t pid = libload_exec(buf, len, exec_argv, NULL);
    free(buf);

    if (pid < 0) {
        fprintf(stderr, "FAIL: libload_exec returned -1\n");
        return 1;
    }

    printf("Forked child PID %d\n", pid);

    int status;
    waitpid(pid, &status, 0);

    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        printf("\n=== PASS ===\n");
        return 0;
    }

    printf("\n=== FAIL ===\n");
    return 1;
}
