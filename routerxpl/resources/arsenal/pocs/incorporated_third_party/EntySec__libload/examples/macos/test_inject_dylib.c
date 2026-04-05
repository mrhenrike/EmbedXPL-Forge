/*
 * test_inject_dylib.c — Tests libload_inject_dylib (Mach task port + dlopen)
 *
 * Requires task_for_pid access (root, or target has get-task-allow).
 *
 * Usage: test_inject_dylib <target_binary> <payload.dylib>
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

    printf("=== libload_inject_dylib (Mach task port + dlopen) ===\n");

    /* Spawn target normally */
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return 1; }
    if (pid == 0) {
        execl(argv[1], argv[1], NULL);
        _exit(127);
    }

    printf("Target PID %d\n", pid);
    sleep(1);

    unlink("/tmp/libload_inject_ok");

    int ret = libload_inject_dylib(pid, abs);
    if (ret < 0) {
        fprintf(stderr, "FAIL: libload_inject_dylib returned -1\n");
        kill(pid, SIGTERM);
        waitpid(pid, NULL, 0);
        return 1;
    }

    sleep(1);

    int ok = access("/tmp/libload_inject_ok", F_OK) == 0;
    printf("%s\n", ok ? "PASS" : "FAIL: marker not found");

    unlink("/tmp/libload_inject_ok");
    kill(pid, SIGTERM);
    waitpid(pid, NULL, 0);
    return ok ? 0 : 1;
}
