/*
 * test_inject.c — Tests libload_inject (ptrace + PIC code)
 *
 * Injects minimal PIC shellcode that creates /tmp/libload_pic_ok.
 * Requires ptrace access (root or Yama scope 0).
 *
 * Usage: test_inject <target_binary>
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <libload.h>

#if defined(__aarch64__)
static const unsigned char pic_payload[] = {
    /* adr x1, path (PC+36) */
    0x21, 0x01, 0x00, 0x10,
    /* movn w0, #99 → w0 = -100 (AT_FDCWD) */
    0x60, 0x0c, 0x80, 0x12,
    /* mov x2, #0x241 (O_WRONLY|O_CREAT|O_TRUNC) */
    0x22, 0x48, 0x80, 0xd2,
    /* mov x3, #0x1a4 (0644) */
    0x83, 0x34, 0x80, 0xd2,
    /* mov x8, #56 (__NR_openat) */
    0x08, 0x07, 0x80, 0xd2,
    /* svc #0 */
    0x01, 0x00, 0x00, 0xd4,
    /* mov x8, #57 (__NR_close) */
    0x28, 0x07, 0x80, 0xd2,
    /* svc #0 */
    0x01, 0x00, 0x00, 0xd4,
    /* ret */
    0xc0, 0x03, 0x5f, 0xd6,
    /* path at offset 36 */
    '/', 't', 'm', 'p', '/', 'l', 'i', 'b',
    'l', 'o', 'a', 'd', '_', 'p', 'i', 'c',
    '_', 'o', 'k', '\0',
};
#elif defined(__x86_64__)
static const unsigned char pic_payload[] = {
    /* lea rdi, [rip+path] */
    0x48, 0x8d, 0x3d, 0x1c, 0x00, 0x00, 0x00,
    /* mov esi, 0x241 (O_WRONLY|O_CREAT|O_TRUNC) */
    0xbe, 0x41, 0x02, 0x00, 0x00,
    /* mov edx, 0x1a4 (0644) */
    0xba, 0xa4, 0x01, 0x00, 0x00,
    /* mov eax, 2 (SYS_open) */
    0xb8, 0x02, 0x00, 0x00, 0x00,
    /* syscall */
    0x0f, 0x05,
    /* mov edi, eax */
    0x89, 0xc7,
    /* mov eax, 3 (SYS_close) */
    0xb8, 0x03, 0x00, 0x00, 0x00,
    /* syscall */
    0x0f, 0x05,
    /* ret */
    0xc3,
    /* path */
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

    printf("=== libload_inject (ptrace + PIC code) ===\n");

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
