/*
 * MIT License
 *
 * Copyright (c) 2020-2026 EntySec
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <io.h>

#include <ev.h>
#include <pwny/misc.h>
#include <pwny/log.h>
#include <pwny/queue.h>
#include <pwny/child.h>

#include <uthash/uthash.h>

#include <pawn.h>

#define CHILD_RELAY_BUF 4096

/*
 * Create a loopback TCP socket pair suitable for use with libev's
 * select()-based backend. Returns CRT file descriptors in fds[0] (read)
 * and fds[1] (write). Also returns raw SOCKETs via out params if non-NULL.
 */

static int win32_socketpair(int fds[2], SOCKET *raw0, SOCKET *raw1)
{
    struct sockaddr_in addr;
    int addr_size;
    SOCKET listener;
    SOCKET s0, s1;
    u_long nb;

    listener = INVALID_SOCKET;
    s0 = INVALID_SOCKET;
    s1 = INVALID_SOCKET;

    listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET)
    {
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    addr_size = sizeof(addr);

    if (bind(listener, (struct sockaddr *)&addr, addr_size) != 0)
    {
        goto fail;
    }

    if (getsockname(listener, (struct sockaddr *)&addr, &addr_size) != 0)
    {
        goto fail;
    }

    if (listen(listener, 1) != 0)
    {
        goto fail;
    }

    s0 = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s0 == INVALID_SOCKET)
    {
        goto fail;
    }

    if (connect(s0, (struct sockaddr *)&addr, addr_size) != 0)
    {
        goto fail;
    }

    s1 = accept(listener, NULL, NULL);
    if (s1 == INVALID_SOCKET)
    {
        goto fail;
    }

    closesocket(listener);

    /* Set both sockets to non-blocking for libev */
    nb = 1;
    ioctlsocket(s0, FIONBIO, &nb);
    ioctlsocket(s1, FIONBIO, &nb);

    fds[0] = _open_osfhandle((intptr_t)s0, 0);
    fds[1] = _open_osfhandle((intptr_t)s1, 0);

    if (fds[0] == -1 || fds[1] == -1)
    {
        goto fail;
    }

    if (raw0) *raw0 = s0;
    if (raw1) *raw1 = s1;

    return 0;

fail:
    if (listener != INVALID_SOCKET) closesocket(listener);
    if (s0 != INVALID_SOCKET) closesocket(s0);
    if (s1 != INVALID_SOCKET) closesocket(s1);
    return -1;
}

/*
 * Build a flat command-line string for CreateProcess from argv.
 * Each argument with spaces/special chars is quoted.
 */

static char *build_cmdline(char **argv)
{
    size_t total;
    int i;
    char *cmdline;
    char *p;
    int needs_quote;

    total = 0;
    for (i = 0; argv[i] != NULL; i++)
    {
        total += strlen(argv[i]) + 3; /* quotes + space */
    }

    cmdline = malloc(total + 1);
    if (cmdline == NULL)
    {
        return NULL;
    }

    p = cmdline;
    for (i = 0; argv[i] != NULL; i++)
    {
        if (i > 0)
        {
            *p++ = ' ';
        }

        needs_quote = (strchr(argv[i], ' ') != NULL ||
                       strchr(argv[i], '\t') != NULL ||
                       argv[i][0] == '\0');

        if (needs_quote)
        {
            *p++ = '"';
        }

        memcpy(p, argv[i], strlen(argv[i]));
        p += strlen(argv[i]);

        if (needs_quote)
        {
            *p++ = '"';
        }
    }

    *p = '\0';
    return cmdline;
}

/*
 * Build a flat environment block for CreateProcess (null-delimited,
 * double-null-terminated).
 */

static char *build_env_block(char **env)
{
    size_t total;
    int i;
    char *block;
    char *p;

    if (env == NULL)
    {
        return NULL;
    }

    total = 0;
    for (i = 0; env[i] != NULL; i++)
    {
        total += strlen(env[i]) + 1;
    }
    total += 1; /* final null */

    block = malloc(total);
    if (block == NULL)
    {
        return NULL;
    }

    p = block;
    for (i = 0; env[i] != NULL; i++)
    {
        size_t len = strlen(env[i]);
        memcpy(p, env[i], len);
        p += len;
        *p++ = '\0';
    }
    *p = '\0';

    return block;
}

/*
 * Relay thread: reads from an anonymous pipe HANDLE and sends data
 * to a socket (via the CRT fd) so that libev's ev_io can detect it.
 */

typedef struct
{
    child_t *child;
    HANDLE hPipe;
    SOCKET sock;
} relay_ctx_t;

static DWORD WINAPI child_relay_thread(LPVOID param)
{
    relay_ctx_t *ctx;
    char buf[CHILD_RELAY_BUF];
    DWORD nread;
    int sent;
    int total;

    ctx = (relay_ctx_t *)param;

    while (!InterlockedCompareExchange(&ctx->child->stopping, 0, 0))
    {
        if (!ReadFile(ctx->hPipe, buf, sizeof(buf), &nread, NULL) || nread == 0)
        {
            break;
        }

        total = 0;
        while (total < (int)nread)
        {
            sent = send(ctx->sock, buf + total, (int)(nread - total), 0);
            if (sent <= 0)
            {
                goto done;
            }
            total += sent;
        }
    }

done:
    free(ctx);
    return 0;
}

/*
 * Waiter thread: waits for the child process to exit, then signals
 * the event loop via ev_async.
 */

static DWORD WINAPI child_wait_thread(LPVOID param)
{
    child_t *child;

    child = (child_t *)param;

    WaitForSingleObject(child->hProcess, INFINITE);
    log_debug("* Child process exited (pid: %lu)\n", child->pid);

    ev_async_send(child->loop, &child->exit_async);

    return 0;
}

/*
 * ev_async callback: invoked on the event loop thread when the
 * child process exits.
 */

static void child_exit_async_cb(struct ev_loop *loop, struct ev_async *w, int revents)
{
    child_t *child;

    child = (child_t *)w->data;
    log_debug("* Child exit async event (pid: %lu)\n", child->pid);

    child->status = CHILD_DEAD;

    if (child->exit_link)
    {
        child->exit_link(child->link_data);
    }

    ev_async_stop(loop, w);
    ev_io_stop(child->loop, &child->out_queue.io);
    ev_io_stop(child->loop, &child->err_queue.io);
}

void child_set_links(child_t *child,
                     link_t out_link,
                     link_t err_link,
                     link_t exit_link,
                     void *data)
{
    child->out_link = out_link;
    child->err_link = err_link;
    child->exit_link = exit_link;
    child->link_data = data != NULL ? data : child;
}

size_t child_read(child_t *child, void *buffer, size_t length)
{
    size_t bytes;

    if ((bytes = queue_remove(child->out_queue.queue, buffer, length)) < length)
    {
        bytes += queue_remove(child->err_queue.queue, buffer + bytes, length - bytes);
    }

    return bytes;
}

size_t child_write(child_t *child, void *buffer, size_t length)
{
    DWORD total;
    DWORD written;

    total = 0;

    while (total < (DWORD)length)
    {
        if (!WriteFile(child->hStdinWrite, (char *)buffer + total,
                       (DWORD)(length - total), &written, NULL))
        {
            break;
        }

        if (written == 0)
        {
            break;
        }

        log_debug("* Writing bytes to child (%lu)\n", written);
        total += written;
    }

    return total > 0 ? (size_t)total : (size_t)-1;
}

/*
 * Read from a non-blocking socket into a queue using recv().
 *
 * On Windows, CRT read() / ReadFile() ignores FIONBIO and blocks
 * when no data is available, which would deadlock the event loop.
 * Winsock recv() correctly honours FIONBIO and returns WSAEWOULDBLOCK.
 */

static size_t queue_from_socket(queue_t *queue, int fd)
{
    SOCKET sock;
    char buffer[QUEUE_FD_MAX];
    int count;
    size_t length;

    sock = (SOCKET)_get_osfhandle(fd);
    length = 0;

    while ((count = recv(sock, buffer, sizeof(buffer), 0)) > 0)
    {
        queue_add_raw(queue, buffer, count);
        length += count;
    }

    return length;
}

void child_out(struct ev_loop *loop, struct ev_io *w, int events)
{
    child_t *child;
    size_t length;

    child = w->data;

    while ((length = queue_from_socket(child->out_queue.queue, w->fd)) > 0)
    {
        log_debug("* Child read from out (%d bytes)\n", (int)length);

        if (child->out_link)
        {
            child->out_link(child->link_data);
        }
    }
}

void child_err(struct ev_loop *loop, struct ev_io *w, int events)
{
    child_t *child;
    size_t length;

    child = w->data;

    while ((length = queue_from_socket(child->err_queue.queue, w->fd)) > 0)
    {
        log_debug("* Child read from err (%d bytes)\n", (int)length);

        if (child->err_link)
        {
            child->err_link(child->link_data);
        }
    }
}

/*
 * Write an in-memory image to a temp file, return the path.
 * The caller is responsible for deleting the file after use.
 */

static char *write_image_to_temp(unsigned char *image, size_t length)
{
    char temp_dir[MAX_PATH];
    char temp_path[MAX_PATH];
    HANDLE hFile;
    DWORD written;

    if (GetTempPathA(sizeof(temp_dir), temp_dir) == 0)
    {
        return NULL;
    }

    if (GetTempFileNameA(temp_dir, "tmp", 0, temp_path) == 0)
    {
        return NULL;
    }

    /* Delete the zero-byte placeholder and rewrite with .exe suffix
     * so CreateProcess recognizes it. Using DeleteFile + CreateFile
     * avoids the MoveFile rename pattern that AV heuristics flag. */
    DeleteFileA(temp_path);
    {
        size_t len = strlen(temp_path);
        if (len + 4 < sizeof(temp_path))
        {
            memcpy(temp_path + len, ".exe", 5);
        }
    }

    hFile = CreateFileA(temp_path, GENERIC_WRITE, 0, NULL,
                        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE)
    {
        return NULL;
    }

    if (!WriteFile(hFile, image, (DWORD)length, &written, NULL) ||
        written != (DWORD)length)
    {
        CloseHandle(hFile);
        DeleteFileA(temp_path);
        return NULL;
    }

    CloseHandle(hFile);

    return _strdup(temp_path);
}

/*
 * Start a relay thread that bridges an anonymous pipe to a socket.
 */

static HANDLE start_relay_thread(child_t *child, HANDLE hPipe, SOCKET sock)
{
    relay_ctx_t *ctx;
    HANDLE hThread;

    ctx = malloc(sizeof(*ctx));
    if (ctx == NULL)
    {
        return NULL;
    }

    ctx->child = child;
    ctx->hPipe = hPipe;
    ctx->sock = sock;

    hThread = CreateThread(NULL, 0, child_relay_thread, ctx, 0, NULL);
    if (hThread == NULL)
    {
        free(ctx);
    }

    return hThread;
}

child_t *child_create(char *filename, unsigned char *image, child_options_t *options)
{
    child_t *child;
    PROCESS_INFORMATION pi;
    STARTUPINFOA si;
    SECURITY_ATTRIBUTES sa;

    child_pipes_t pipes;
    int out_pair[2], err_pair[2];
    SOCKET out_raw0, out_raw1, err_raw0, err_raw1;

    char *cmdline;
    char *env_block;
    char *exec_path;
    size_t argc;
    char *args_buf;

    BOOL created;

    child = NULL;
    cmdline = NULL;
    env_block = NULL;
    exec_path = NULL;
    args_buf = NULL;
    argc = 0;
    options->argv = NULL;

    memset(&pipes, 0, sizeof(pipes));
    out_pair[0] = out_pair[1] = -1;
    err_pair[0] = err_pair[1] = -1;
    out_raw0 = out_raw1 = err_raw0 = err_raw1 = INVALID_SOCKET;

    /* Determine the executable path */
    if (image != NULL && filename == NULL)
    {
        /* Write image to a temp file */
        exec_path = write_image_to_temp(image, options->length);
        if (exec_path == NULL)
        {
            log_debug("* Failed to write image to temp file\n");
            goto fail;
        }
    }
    else if (filename != NULL)
    {
        exec_path = _strdup(filename);
    }
    else
    {
        log_debug("* No filename or image provided\n");
        goto fail;
    }

    /* Build argv if args are provided */
    if (options->args)
    {
        int rc;

        rc = asprintf(&args_buf, "%s %s", exec_path, options->args);
        if (rc == -1 || args_buf == NULL)
        {
            log_debug("* Failed to build argv string\n");
            goto fail;
        }

        options->argv = misc_argv_split(args_buf, options->argv, &argc);
        if (!options->argv)
        {
            log_debug("* misc_argv_split() failed\n");
            goto fail;
        }
    }

    if (options->argv == NULL)
    {
        options->argv = realloc(options->argv, sizeof(char *) * 2);
        if (!options->argv)
        {
            log_debug("* Failed to allocate argv\n");
            goto fail;
        }

        options->argv[0] = exec_path;
        options->argv[1] = NULL;
    }

    /* Build command line string for CreateProcess */
    cmdline = build_cmdline(options->argv);
    if (cmdline == NULL)
    {
        log_debug("* Failed to build command line\n");
        goto fail;
    }

    log_debug("* CreateProcess cmdline: %s\n", cmdline);

    /* Build environment block */
    env_block = build_env_block(options->env);

    /* Create anonymous pipes for child stdio (inheritable) */
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    if (!CreatePipe(&pipes.hStdinRead, &pipes.hStdinWrite, &sa, 0))
    {
        log_debug("* Failed to create stdin pipe\n");
        goto fail;
    }

    if (!SetHandleInformation(pipes.hStdinWrite, HANDLE_FLAG_INHERIT, 0))
    {
        log_debug("* Failed to set stdin write handle info\n");
        goto fail;
    }

    if (!CreatePipe(&pipes.hStdoutRead, &pipes.hStdoutWrite, &sa, 0))
    {
        log_debug("* Failed to create stdout pipe\n");
        goto fail;
    }

    if (!SetHandleInformation(pipes.hStdoutRead, HANDLE_FLAG_INHERIT, 0))
    {
        log_debug("* Failed to set stdout read handle info\n");
        goto fail;
    }

    if (!CreatePipe(&pipes.hStderrRead, &pipes.hStderrWrite, &sa, 0))
    {
        log_debug("* Failed to create stderr pipe\n");
        goto fail;
    }

    if (!SetHandleInformation(pipes.hStderrRead, HANDLE_FLAG_INHERIT, 0))
    {
        log_debug("* Failed to set stderr read handle info\n");
        goto fail;
    }

    /* Create socket pairs for ev_io relay */
    if (win32_socketpair(out_pair, &out_raw0, &out_raw1) == -1)
    {
        log_debug("* Failed to create stdout socket pair\n");
        goto fail;
    }

    if (win32_socketpair(err_pair, &err_raw0, &err_raw1) == -1)
    {
        log_debug("* Failed to create stderr socket pair\n");
        goto fail;
    }

    /* Allocate child structure */
    child = calloc(1, sizeof(*child));
    if (child == NULL)
    {
        log_debug("* Failed to allocate child structure\n");
        goto fail;
    }

    child->stopping = 0;

    /* Save temp image path so we can delete it later */
    if (image != NULL && filename == NULL)
    {
        child->temp_image_path = exec_path;
        exec_path = NULL; /* ownership transferred */
    }

    /* Create the child process */
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = pipes.hStdinRead;
    si.hStdOutput = pipes.hStdoutWrite;
    si.hStdError = pipes.hStderrWrite;

    memset(&pi, 0, sizeof(pi));

    created = CreateProcessA(
        NULL,
        cmdline,
        NULL,
        NULL,
        TRUE,
        0,
        env_block,
        NULL,
        &si,
        &pi
    );

    if (!created)
    {
        log_debug("* CreateProcess failed (%lu)\n", GetLastError());
        goto fail;
    }

    child->hProcess = pi.hProcess;
    child->hThread = pi.hThread;
    child->pid = pi.dwProcessId;

    log_debug("* CreateProcess succeeded (pid: %lu)\n", child->pid);

    /* Close the child-side pipe handles (parent doesn't need them) */
    CloseHandle(pipes.hStdinRead);
    pipes.hStdinRead = NULL;
    CloseHandle(pipes.hStdoutWrite);
    pipes.hStdoutWrite = NULL;
    CloseHandle(pipes.hStderrWrite);
    pipes.hStderrWrite = NULL;

    /* Store parent-side handles */
    child->hStdinWrite = pipes.hStdinWrite;
    child->hStdoutRead = pipes.hStdoutRead;
    child->hStderrRead = pipes.hStderrRead;

    /* stdin uses WriteFile directly, store the HANDLE */
    child->in = -1; /* not using CRT fd for stdin */

    /* stdout/stderr: ev_io watches the socket read end */
    child->out = out_pair[0];
    child->out_relay_wr = out_pair[1];

    child->err = err_pair[0];
    child->err_relay_wr = err_pair[1];

    /* Set up event loop */
    child->loop = ev_default_loop(CHILD_EV_FLAGS);

    /* Set up ev_io for stdout socket */
    child->out_queue.io.data = child;
    child->out_queue.queue = queue_create();
    ev_io_init(&child->out_queue.io, child_out, child->out, EV_READ);
    ev_io_start(child->loop, &child->out_queue.io);

    /* Set up ev_io for stderr socket */
    child->err_queue.io.data = child;
    child->err_queue.queue = queue_create();
    ev_io_init(&child->err_queue.io, child_err, child->err, EV_READ);
    ev_io_start(child->loop, &child->err_queue.io);

    /* Set up ev_async for process exit notification */
    child->exit_async.data = child;
    ev_async_init(&child->exit_async, child_exit_async_cb);
    ev_async_start(child->loop, &child->exit_async);

    /* Start relay threads (pipe HANDLE → socket) */
    child->hOutThread = start_relay_thread(child, child->hStdoutRead, out_raw1);
    child->hErrThread = start_relay_thread(child, child->hStderrRead, err_raw1);

    if (child->hOutThread == NULL || child->hErrThread == NULL)
    {
        log_debug("* Failed to start relay threads\n");
        goto fail_after_create;
    }

    /* Start process waiter thread */
    child->hWaitThread = CreateThread(NULL, 0, child_wait_thread, child, 0, NULL);
    if (child->hWaitThread == NULL)
    {
        log_debug("* Failed to start wait thread\n");
        goto fail_after_create;
    }

    child->status = CHILD_ALIVE;

    /* Cleanup temporary allocations */
    if (options->argv)
    {
        free(options->argv);
        options->argv = NULL;
    }
    if (args_buf)
    {
        free(args_buf);
    }
    if (cmdline)
    {
        free(cmdline);
    }
    if (env_block)
    {
        free(env_block);
    }
    if (exec_path)
    {
        free(exec_path);
    }

    return child;

fail_after_create:
    InterlockedExchange(&child->stopping, 1);
    TerminateProcess(child->hProcess, 1);
    if (child->hOutThread) { WaitForSingleObject(child->hOutThread, 1000); CloseHandle(child->hOutThread); }
    if (child->hErrThread) { WaitForSingleObject(child->hErrThread, 1000); CloseHandle(child->hErrThread); }
    if (child->hWaitThread) { WaitForSingleObject(child->hWaitThread, 1000); CloseHandle(child->hWaitThread); }
    CloseHandle(child->hProcess);
    CloseHandle(child->hThread);
    ev_io_stop(child->loop, &child->out_queue.io);
    ev_io_stop(child->loop, &child->err_queue.io);
    ev_async_stop(child->loop, &child->exit_async);
    if (child->out_queue.queue) queue_free(child->out_queue.queue);
    if (child->err_queue.queue) queue_free(child->err_queue.queue);

fail:
    if (pipes.hStdinRead) CloseHandle(pipes.hStdinRead);
    if (pipes.hStdinWrite) CloseHandle(pipes.hStdinWrite);
    if (pipes.hStdoutRead) CloseHandle(pipes.hStdoutRead);
    if (pipes.hStdoutWrite) CloseHandle(pipes.hStdoutWrite);
    if (pipes.hStderrRead) CloseHandle(pipes.hStderrRead);
    if (pipes.hStderrWrite) CloseHandle(pipes.hStderrWrite);

    if (out_pair[0] != -1) close(out_pair[0]);
    if (out_pair[1] != -1) close(out_pair[1]);
    if (err_pair[0] != -1) close(err_pair[0]);
    if (err_pair[1] != -1) close(err_pair[1]);

    if (options->argv)
    {
        free(options->argv);
        options->argv = NULL;
    }
    if (args_buf)
    {
        free(args_buf);
    }
    if (cmdline)
    {
        free(cmdline);
    }
    if (env_block)
    {
        free(env_block);
    }
    if (exec_path)
    {
        free(exec_path);
    }
    if (child)
    {
        if (child->temp_image_path)
        {
            DeleteFileA(child->temp_image_path);
            free(child->temp_image_path);
        }
        free(child);
    }

    return NULL;
}

void child_kill(child_t *child)
{
    if (child->status == CHILD_ALIVE)
    {
        log_debug("* Terminating child process (pid: %lu)\n", child->pid);
        InterlockedExchange(&child->stopping, 1);
        TerminateProcess(child->hProcess, 0);
    }
}

void child_destroy(child_t *child)
{
    InterlockedExchange(&child->stopping, 1);

    /* Wait for relay threads to finish (they'll exit when pipe closes) */
    if (child->hOutThread)
    {
        WaitForSingleObject(child->hOutThread, 3000);
        CloseHandle(child->hOutThread);
    }

    if (child->hErrThread)
    {
        WaitForSingleObject(child->hErrThread, 3000);
        CloseHandle(child->hErrThread);
    }

    if (child->hWaitThread)
    {
        WaitForSingleObject(child->hWaitThread, 3000);
        CloseHandle(child->hWaitThread);
    }

    /* Stop event watchers */
    ev_io_stop(child->loop, &child->out_queue.io);
    ev_io_stop(child->loop, &child->err_queue.io);
    ev_async_stop(child->loop, &child->exit_async);

    /* Close pipe handles */
    if (child->hStdinWrite) CloseHandle(child->hStdinWrite);
    if (child->hStdoutRead) CloseHandle(child->hStdoutRead);
    if (child->hStderrRead) CloseHandle(child->hStderrRead);

    /* Close socket-pair CRT fds */
    if (child->out != -1) close(child->out);
    if (child->out_relay_wr != -1) close(child->out_relay_wr);
    if (child->err != -1) close(child->err);
    if (child->err_relay_wr != -1) close(child->err_relay_wr);

    /* Close process handles */
    if (child->hProcess) CloseHandle(child->hProcess);
    if (child->hThread) CloseHandle(child->hThread);

    /* Free queues */
    if (child->out_queue.queue) queue_free(child->out_queue.queue);
    if (child->err_queue.queue) queue_free(child->err_queue.queue);

    /* Delete temp image file if applicable */
    if (child->temp_image_path)
    {
        DeleteFileA(child->temp_image_path);
        free(child->temp_image_path);
    }

    free(child);
}
