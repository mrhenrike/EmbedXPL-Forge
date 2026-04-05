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

#include <pwny/c2.h>
#include <pwny/proc.h>
#include <pwny/log.h>

#include <stdlib.h>
#include <string.h>
#include <sigar.h>

#ifdef __windows__
#include <tlhelp32.h>

sigar_pid_t proc_find(sigar_t *sigar, const char *name)
{
    HANDLE hSnap;
    PROCESSENTRY32 pe32;

    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
    {
        log_debug("* Cannot build process tree\n");
        return -1;
    }

    pe32.dwSize = sizeof(pe32);
    if (!Process32First(hSnap, &pe32))
    {
        CloseHandle(hSnap);
        return -1;
    }

    do
    {
        if (strcmp(pe32.szExeFile, name) == 0)
        {
            sigar_pid_t pid = (sigar_pid_t)pe32.th32ProcessID;
            log_debug("* Found (%s) on PID (%d)\n", name, pid);
            CloseHandle(hSnap);
            return pid;
        }
    } while (Process32Next(hSnap, &pe32));

    CloseHandle(hSnap);
    return -1;
}

int proc_kill(sigar_t *sigar, sigar_pid_t pid)
{
    HANDLE hProc;
    BOOL ok;

    hProc = OpenProcess(PROCESS_TERMINATE, FALSE, (DWORD)pid);
    if (hProc == NULL)
    {
        log_debug("* Failed to open process for kill (%d) (%lu)\n",
                  pid, GetLastError());
        return -1;
    }

    ok = TerminateProcess(hProc, 1);
    CloseHandle(hProc);

    if (!ok)
    {
        log_debug("* Failed to terminate process (%d) (%lu)\n",
                  pid, GetLastError());
        return -1;
    }

    return 0;
}

#else

sigar_pid_t proc_find(sigar_t *sigar, const char *name)
{
    int iter;
    int status;

    sigar_pid_t proc_pid;
    sigar_proc_state_t proc_state;
    sigar_proc_list_t proc_list;

    if ((status = sigar_proc_list_get(sigar, &proc_list)) != SIGAR_OK)
    {
        log_debug("* Cannot build process tree\n");
        return -1;
    }

    for (iter = 0; iter < proc_list.number; iter++)
    {
        proc_pid = proc_list.data[iter];

        if ((status = sigar_proc_state_get(sigar, proc_pid, &proc_state)) != SIGAR_OK)
        {
            continue;
        }

        if (!strcmp(proc_state.name, name))
        {
            log_debug("* Found (%s) on PID (%d)\n", name, proc_pid);

            sigar_proc_list_destroy(sigar, &proc_list);
            return proc_pid;
        }
    }

    sigar_proc_list_destroy(sigar, &proc_list);
    return -1;
}

int proc_kill(sigar_t *sigar, sigar_pid_t pid)
{
    int status;

    if ((status = sigar_proc_kill(pid, 9)) != SIGAR_OK)
    {
        log_debug("* Failed to sigar process kill (%d) (%s)\n",
                  pid, sigar_strerror(sigar, status));
        return -1;
    }

    return 0;
}

#endif