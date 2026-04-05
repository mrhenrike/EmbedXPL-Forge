/*
 * test_inject.c — Tests libload_inject (Mach task port + PIC code)
 *
 * Injects minimal PIC shellcode that creates /tmp/libload_pic_ok.
 * Requires task_for_pid access (root, or target has get-task-allow).
 *
 * Usage: test_inject <target_binary>
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <libload.h>

#if defined(__aarch64__) || defined(__arm64__)
static const unsigned char pic_payload[] = {
    /* adr x0, path (PC+32 = 8 instructions ahead) */
    0x00, 0x01, 0x00, 0x10,
    /* mov w1, #0x601 (O_WRONLY|O_CREAT|O_TRUNC) */
    0x21, 0xC0, 0x80, 0x52,
    /* mov w2, #0x1a4 (0644) */
    0x82, 0x34, 0x80, 0x52,
    /* mov x16, #5 (SYS_open) */
    0xB0, 0x00, 0x80, 0xd2,
    /* svc #0x80 */
    0x01, 0x10, 0x00, 0xd4,
    /* mov x16, #6 (SYS_close) */
    0xD0, 0x00, 0x80, 0xd2,
    /* svc #0x80 */
    0x01, 0x10, 0x00, 0xd4,
    /* ret */
    0xc0, 0x03, 0x5f, 0xd6,
    /* path at offset 32 */
    '/', 't', 'm', 'p', '/', 'l', 'i', 'b',
    'l', 'o', 'a', 'd', '_', 'p', 'i', 'c',
    '_', 'o', 'k', '\0',
};
#elif defined(__x86_64__)
static const unsigned char pic_payload[] = {
    /* lea rdi, [rip+0x1b] (path at offset 34) */
    0x48, 0x8d, 0x3d, 0x1b, 0x00, 0x00, 0x00,
    /* mov esi, 0x601 (O_WRONLY|O_CREAT|O_TRUNC) */
    0xbe, 0x01, 0x06, 0x00, 0x00,
    /* mov edx, 0x1a4 (0644) */
    0xba, 0xa4, 0x01, 0x00, 0x00,
    /* mov eax, 0x2000005 (SYS_open) */
    0xb8, 0x05, 0x00, 0x00, 0x02,
    /* syscall */
    0x0f, 0x05,
    /* mov edi, eax */
    0x89, 0xc7,
    /* mov eax, 0x2000006 (SYS_close) */
    0xb8, 0x06, 0x00, 0x00, 0x02,
    /* syscall */
    0x0f, 0x05,
    /* ret */
    0xc3,
    /* path at offset 34 */
    '/', 't', 'm', 'p', '/', 'l', 'i', 'b',
    'l', 'o', 'a', 'd', '_', 'p', 'i', 'c',
    '_', 'o', 'k', '\0',
};
#endif

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <target_binary>\n", argv[0]);
        return 1;
    }

    printf("=== libload_inject (Mach task port + PIC code) ===\n");

    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return 1; }
    if (pid == 0) {
        execl(argv[1], argv[1], NULL);
        _exit(127);
    }

    printf("Target PID %d\n", pid);
    sleep(1);

    unlink("/tmp/libload_pic_ok");

    int ret = libload_inject(pid, pic_payload, sizeof(pic_payload), 0, 0);
    if (ret < 0) {
        fprintf(stderr, "FAIL: libload_inject returned -1\n");
        kill(pid, SIGTERM);
        waitpid(pid, NULL, 0);
        return 1;
    }

    sleep(1);

    int ok = access("/tmp/libload_pic_ok", F_OK) == 0;
    printf("%s\n", ok ? "PASS" : "FAIL: marker not found");

    unlink("/tmp/libload_pic_ok");
    kill(pid, SIGTERM);
    waitpid(pid, NULL, 0);
    return ok ? 0 : 1;
}
