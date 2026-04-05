/*
 * test_inject_spawn.c — Tests libload_inject_spawn (exception port inheritance)
 *
 * No root or entitlements required.
 *
 * Usage: test_inject_spawn <target_binary> <payload.dylib>
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <signal.h>
#include <sys/wait.h>
#include <libload.h>

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s <target> <payload.dylib>\n", argv[0]);
        return 1;
    }

    char abs[PATH_MAX];
    if (!realpath(argv[2], abs)) { perror("realpath"); return 1; }

    unlink("/tmp/libload_inject_ok");

    printf("=== libload_inject_spawn (exception ports) ===\n");

    char *targ_argv[] = { argv[1], NULL };
    pid_t pid = libload_inject_spawn(argv[1], abs, targ_argv, NULL);
    if (pid < 0) {
        fprintf(stderr, "FAIL: libload_inject_spawn returned -1\n");
        return 1;
    }

    printf("Spawned PID %d\n", pid);
    sleep(2);

    int ok = access("/tmp/libload_inject_ok", F_OK) == 0;
    printf("%s\n", ok ? "PASS" : "FAIL: marker not found");

    unlink("/tmp/libload_inject_ok");
    kill(pid, SIGTERM);
    waitpid(pid, NULL, 0);
    return ok ? 0 : 1;
}
