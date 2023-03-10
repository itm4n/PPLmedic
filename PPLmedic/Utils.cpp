#include "Utils.h"

VOID Utils::PrintLastError()
{
    LPWSTR pwszErrorMessage = NULL;
    DWORD dwLastError;

    dwLastError = ::GetLastError();

    FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        dwLastError,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPWSTR)&pwszErrorMessage,
        0,
        NULL
    );

    if (!pwszErrorMessage)
        return;

    wprintf(L"[-] Error code %d | 0x%08x | %ws", dwLastError, dwLastError, pwszErrorMessage);

    LocalFree(pwszErrorMessage);
}

LPWSTR Utils::GenerateUuid()
{
    UUID Uuid;
    RPC_WSTR UuidRpcString = NULL;
    LPWSTR UuidString = NULL;

    EXIT_ON_ERROR(UuidCreate(&Uuid) != RPC_S_OK);
    EXIT_ON_ERROR(UuidToStringW(&Uuid, &UuidRpcString) != RPC_S_OK);
    EXIT_ON_ERROR(!(UuidString = (LPWSTR)LocalAlloc(LPTR, 64 * sizeof(WCHAR))));

    swprintf(UuidString, 64, L"%ws", (LPWSTR)UuidRpcString);

cleanup:
    if (UuidRpcString) RpcStringFreeW(&UuidRpcString);

    return UuidString;
}

BOOL Utils::GenerateTempPath(IN OUT LPWSTR Buffer)
{
    BOOL bResult = FALSE;
    const DWORD dwBufferLength = MAX_PATH + 1;
    LPWSTR pwszTempPath = NULL;

    EXIT_ON_ERROR(!(pwszTempPath = (LPWSTR)LocalAlloc(LPTR, dwBufferLength * sizeof(WCHAR))));
    EXIT_ON_ERROR(!GetTempPathW(dwBufferLength, pwszTempPath));
    EXIT_ON_ERROR(!GetTempFileNameW(pwszTempPath, L"", 0, Buffer));

    bResult = TRUE;

cleanup:
    Utils::SafeFree((PVOID*)&pwszTempPath);

    DEBUG(L"Temp path: %ws | Result: %d", Buffer, bResult);

    return bResult;
}

VOID Utils::SafeCloseHandle(IN PHANDLE Handle)
{
    if (Handle && *Handle && *Handle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(*Handle);
        *Handle = NULL;
    }
}

VOID Utils::SafeFree(IN PVOID* Memory)
{
    if (Memory && *Memory)
    {
        LocalFree(*Memory);
        *Memory = NULL;
    }
}

VOID Utils::SafeRelease(IN IUnknown** Interface)
{
    if (Interface && *Interface)
    {
        (*Interface)->Release();
        *Interface = NULL;
    }

    return VOID();
}

VOID Utils::SetLastErrorFromNtStatus(IN NTSTATUS Status)
{
    if (Status != STATUS_SUCCESS)
        SetLastError(RtlNtStatusToDosError(Status));
}

BOOL Utils::GetProcAddress(IN LPCWSTR Dll, IN LPCSTR ProcName, OUT FARPROC* ProcAddress)
{
    BOOL bResult = FALSE;
    HMODULE hModule;
    FARPROC pProcAddr = NULL;

    EXIT_ON_ERROR((hModule = GetModuleHandleW(Dll)) == NULL);
    EXIT_ON_ERROR((pProcAddr = ::GetProcAddress(hModule, ProcName)) == NULL);

    *ProcAddress = pProcAddr;
    bResult = TRUE;

cleanup:
    DEBUG(L"Proc @ 0x%llx", (DWORD64)pProcAddr);

    return bResult;
}

// https://twitter.com/0xrepnz/status/1401118056294846467
// https://github.com/antonioCoco/MalSeclogon/blob/master/MalSeclogon.c
BOOL Utils::GetTypeIndexByName(IN LPCWSTR TypeName, OUT LPDWORD TypeIndex)
{
    BOOL bResult = FALSE;
    POBJECT_TYPES_INFORMATION ObjectTypes = NULL;
    POBJECT_TYPE_INFORMATION CurrentType;
    ULONG i;

    *TypeIndex = 0;

    EXIT_ON_ERROR(!Utils::EnumObjectTypes(&ObjectTypes));

    CurrentType = (POBJECT_TYPE_INFORMATION)OBJECT_TYPES_FIRST_ENTRY(ObjectTypes);
    for (i = 0; i < ObjectTypes->NumberOfTypes; i++)
    {
        if (CurrentType->TypeName.Buffer && !_wcsicmp(CurrentType->TypeName.Buffer, TypeName))
        {
            bResult = TRUE;
            *TypeIndex = i + 2;
            break;
        }

        CurrentType = (POBJECT_TYPE_INFORMATION)OBJECT_TYPES_NEXT_ENTRY(CurrentType);
    }

cleanup:
    if (ObjectTypes) LocalFree(ObjectTypes);

    DEBUG(L"Object of type '%ws' has index: %d", TypeName, *TypeIndex);

    return bResult;
}

BOOL Utils::GetServiceProcessId(IN LPCWSTR ServiceName, OUT LPDWORD ProcessId)
{
    BOOL bResult = FALSE;
    SERVICE_STATUS_PROCESS ssp;

    *ProcessId = 0;

    bResult = Utils::QueryServiceStatusProcessByName(ServiceName, &ssp);
    *ProcessId = ssp.dwProcessId;

    DEBUG(L"PID of service with name '%ws': %d", ServiceName, *ProcessId);

    return bResult;
}

BOOL Utils::GetServiceStatusByHandle(IN SC_HANDLE ServiceHandle, OUT LPDWORD Status)
{
    BOOL bResult = FALSE;
    SERVICE_STATUS_PROCESS ssp;

    *Status = 0;

    bResult = Utils::QueryServiceStatusProcessByHandle(ServiceHandle, &ssp);
    *Status = ssp.dwCurrentState;

    DEBUG(L"State of service with handle 0x%04x: %d", HandleToULong(ServiceHandle), *Status);

    return bResult;
}

BOOL Utils::GetServiceStatusByName(IN LPCWSTR ServiceName, OUT LPDWORD Status)
{
    BOOL bResult = FALSE;
    SERVICE_STATUS_PROCESS ssp;

    *Status = 0;

    bResult = Utils::QueryServiceStatusProcessByName(ServiceName, &ssp);
    *Status = ssp.dwCurrentState;

    DEBUG(L"State of service with name '%ws': %d", ServiceName, *Status);

    return bResult;
}

// https://docs.microsoft.com/en-us/windows/win32/services/starting-a-service
BOOL Utils::StartServiceByName(IN LPCWSTR ServiceName, IN BOOL Wait)
{
    BOOL bResult = FALSE;
    SC_HANDLE hService = NULL;
    SERVICE_STATUS_PROCESS ssp;
    DWORD64 dwStartTime;
    DWORD dwWaitTime;

    dwStartTime = GetTickCount64();

    EXIT_ON_ERROR(!Utils::GetServiceHandle(ServiceName, SERVICE_QUERY_STATUS | SERVICE_START, &hService));
    EXIT_ON_ERROR(!StartServiceW(hService, 0, NULL));
    EXIT_ON_ERROR(!Utils::QueryServiceStatusProcessByHandle(hService, &ssp));

    if (Wait)
    {
        while (ssp.dwCurrentState != SERVICE_RUNNING)
        {
            dwWaitTime = ssp.dwWaitHint / 10;

            if (dwWaitTime < 1000)
                dwWaitTime = 1000;
            else if (dwWaitTime > 10000)
                dwWaitTime = 10000;

            Sleep(dwWaitTime);

            if (!Utils::QueryServiceStatusProcessByHandle(hService, &ssp))
                break;

            if (GetTickCount64() - dwStartTime > TIMEOUT)
            {
                SetLastError(ERROR_TIMEOUT);
                break;
            }
        }

        bResult = ssp.dwCurrentState == SERVICE_RUNNING;
    }
    else
    {
        bResult = TRUE;
    }

cleanup:
    if (hService) CloseServiceHandle(hService);

    DEBUG(L"Result: %d", bResult);

    return bResult;
}

// https://docs.microsoft.com/en-us/windows/win32/services/stopping-a-service
BOOL Utils::StopServiceByName(IN LPCWSTR ServiceName, IN BOOL Wait)
{
    BOOL bResult = FALSE;
    SC_HANDLE hService = NULL;
    SERVICE_STATUS_PROCESS ssp;
    DWORD64 dwStartTime;
    DWORD dwWaitTime;

    dwStartTime = GetTickCount64();

    EXIT_ON_ERROR(!Utils::GetServiceHandle(ServiceName, SERVICE_QUERY_STATUS | SERVICE_STOP, &hService));
    EXIT_ON_ERROR(!ControlService(hService, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&ssp));
    EXIT_ON_ERROR(!Utils::QueryServiceStatusProcessByHandle(hService, &ssp));

    if (Wait)
    {
        INFO("Stopping service %ws...", ServiceName);

        while (ssp.dwCurrentState != SERVICE_STOPPED)
        {
            DEBUG(L"Status: %d | Wait: %d", ssp.dwCurrentState, ssp.dwWaitHint);

            dwWaitTime = ssp.dwWaitHint / 10;

            if (dwWaitTime < 1000)
                dwWaitTime = 1000;
            else if (dwWaitTime > 10000)
                dwWaitTime = 10000;

            Sleep(dwWaitTime);

            if (!Utils::QueryServiceStatusProcessByHandle(hService, &ssp))
                break;

            if (GetTickCount64() - dwStartTime > TIMEOUT)
            {
                SetLastError(ERROR_TIMEOUT);
                break;
            }
        }

        bResult = ssp.dwCurrentState == SERVICE_STOPPED;
    }
    else
    {
        bResult = TRUE;
    }

cleanup:
    if (hService) CloseServiceHandle(hService);

    DEBUG(L"Result: %d", bResult);

    if (!bResult)
        ERROR(L"Failed to stop service %ws.", ServiceName);

    return bResult;
}

BOOL Utils::IsServiceRunning(IN LPCWSTR ServiceName)
{
    DWORD dwServiceStatus;

    if (!Utils::GetServiceStatusByName(ServiceName, &dwServiceStatus))
        return FALSE;

    return dwServiceStatus == SERVICE_RUNNING;
}

BOOL Utils::FindUniqueHandleValueByTypeName(IN DWORD ProcessId, IN LPCWSTR TypeName, OUT PULONG HandleValue)
{
    BOOL bResult = FALSE;
    NTSTATUS status;
    DWORD dwTypeIndex;
    DWORD dwSysHandleInfoSize, dwReturnLength;
    PSYSTEM_HANDLE_INFORMATION SysHandleInfo = NULL;
    POBJECT_NAME_INFORMATION NameInfo = NULL;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO HandleInfo;
    ULONG i, count = 0;

    EXIT_ON_ERROR(!Utils::GetTypeIndexByName(TypeName, &dwTypeIndex));

    dwSysHandleInfoSize = PAGE_SIZE;
    do
    {
        if (!(SysHandleInfo = (PSYSTEM_HANDLE_INFORMATION)LocalAlloc(LPTR, dwSysHandleInfoSize)))
            break;

        status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemHandleInformation, SysHandleInfo, dwSysHandleInfoSize, &dwReturnLength);
        if (NT_SUCCESS(status))
            break;

        dwSysHandleInfoSize *= 2;
        LocalFree(SysHandleInfo);
        SysHandleInfo = NULL;

        if (dwSysHandleInfoSize > LARGE_BUFFER_SIZE)
            return STATUS_INSUFFICIENT_RESOURCES;

    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    EXIT_ON_ERROR(!SysHandleInfo);
    EXIT_ON_ERROR(!(NameInfo = (POBJECT_NAME_INFORMATION)LocalAlloc(LPTR, 1024)));

    for (i = 0; i < SysHandleInfo->NumberOfHandles; i++)
    {
        HandleInfo = SysHandleInfo->Handles[i];

        if (HandleInfo.UniqueProcessId != ProcessId)
            continue;

        if (HandleInfo.ObjectTypeIndex == dwTypeIndex)
        {
            // Do not break if found, make sure we find only one handle with type "Directory".
            *HandleValue = HandleInfo.HandleValue;
            count++;
        }
    }

    if (count == 0)
    {
        ERROR(L"No handle of type '%ws' was found in the process with PID %d.", TypeName, ProcessId);
        goto cleanup;
    }
    else if (count > 1)
    {
        ERROR(L"More than one handle of type '%ws' was found in process with PID %d.", TypeName, ProcessId);
        goto cleanup;
    }

    bResult = TRUE;

cleanup:
    if (NameInfo) LocalFree(NameInfo);
    if (SysHandleInfo) LocalFree(SysHandleInfo);

    DEBUG(L"Handle of type '%ws' (count=%d) in process with PID %d: 0x%04x", TypeName, count, ProcessId, *HandleValue);

    return bResult;
}

BOOL Utils::EnablePrivilege(IN LPCWSTR PrivilegeName)
{   
    BOOL bResult = FALSE;
    HANDLE hToken = NULL;
    DWORD dwTokenPrivilegesSize, dwPrivilegeNameLength;
    PTOKEN_PRIVILEGES pTokenPrivileges = NULL;
    DWORD i;
    LUID_AND_ATTRIBUTES laa;
    LPWSTR pwszPrivilegeNameTemp = NULL;
    TOKEN_PRIVILEGES tp;

    EXIT_ON_ERROR(!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken));

    if (!GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &dwTokenPrivilegesSize))
    {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
            goto cleanup;
    }

    EXIT_ON_ERROR(!(pTokenPrivileges = (PTOKEN_PRIVILEGES)LocalAlloc(LPTR, dwTokenPrivilegesSize)));
    EXIT_ON_ERROR(!GetTokenInformation(hToken, TokenPrivileges, pTokenPrivileges, dwTokenPrivilegesSize, &dwTokenPrivilegesSize));

    for (i = 0; i < pTokenPrivileges->PrivilegeCount; i++)
    {
        laa = pTokenPrivileges->Privileges[i];
        dwPrivilegeNameLength = 0;

        if (!LookupPrivilegeNameW(NULL, &(laa.Luid), NULL, &dwPrivilegeNameLength))
        {
            EXIT_ON_ERROR(GetLastError() != ERROR_INSUFFICIENT_BUFFER);
        }

        dwPrivilegeNameLength++;

        if (pwszPrivilegeNameTemp = (LPWSTR)LocalAlloc(LPTR, dwPrivilegeNameLength * sizeof(WCHAR)))
        {
            if (LookupPrivilegeNameW(NULL, &(laa.Luid), pwszPrivilegeNameTemp, &dwPrivilegeNameLength))
            {
                if (!_wcsicmp(pwszPrivilegeNameTemp, PrivilegeName))
                {
                    ZeroMemory(&tp, sizeof(tp));
                    tp.PrivilegeCount = 1;
                    tp.Privileges[0].Luid = laa.Luid;
                    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

                    if (AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL))
                        bResult = TRUE;

                    break;
                }
            }

            LocalFree(pwszPrivilegeNameTemp);
        }
    }

cleanup:
    DEBUG(L"Enable '%ws': %d", PrivilegeName, bResult);

    if (pTokenPrivileges) LocalFree(pTokenPrivileges);
    if (hToken) CloseHandle(hToken);
    
    return bResult;
}

BOOL Utils::GetRegistryStringValue(IN HKEY Key, IN LPCWSTR SubKey, IN LPCWSTR ValueName, OUT LPWSTR* ValueData)
{
    BOOL bResult = FALSE;
    LSTATUS status = ERROR_SUCCESS;
    HKEY hKey = NULL;
    DWORD dwDataSize = 0;
    LPWSTR pwszStringData = NULL;

    EXIT_ON_ERROR((status = RegOpenKeyExW(Key, SubKey, 0, KEY_QUERY_VALUE, &hKey)) != ERROR_SUCCESS);
    EXIT_ON_ERROR((status = RegQueryValueExW(hKey, ValueName, NULL, NULL, NULL, &dwDataSize)) != ERROR_SUCCESS);
    EXIT_ON_ERROR(!(pwszStringData = (LPWSTR)LocalAlloc(LPTR, dwDataSize)));
    EXIT_ON_ERROR((status = RegQueryValueExW(hKey, ValueName, NULL, NULL, (LPBYTE)pwszStringData, &dwDataSize)) != ERROR_SUCCESS);
    
    *ValueData = pwszStringData;
    bResult = TRUE;

cleanup:
    if (!bResult && pwszStringData) LocalFree(pwszStringData);
    if (hKey) RegCloseKey(hKey);
    Utils::SetLastErrorFromNtStatus(status);

    DEBUG(L"Key: %ws | Value: %ws | Data: %ws | Status: 0x%08x", SubKey, ValueName, pwszStringData, status);

    return bResult;
}

BOOL Utils::SetRegistryStringValue(IN HKEY Key, IN LPCWSTR SubKey, IN LPCWSTR ValueName, IN LPCWSTR ValueData)
{
    BOOL bResult = FALSE;
    LSTATUS status = ERROR_SUCCESS;
    HKEY hKey = NULL;
    DWORD dwDataSize;

    dwDataSize = ((DWORD)wcslen(ValueData) + 1) * sizeof(WCHAR);

    EXIT_ON_ERROR((status = RegOpenKeyExW(Key, SubKey, 0, KEY_SET_VALUE, &hKey)) != ERROR_SUCCESS);
    EXIT_ON_ERROR((status = RegSetValueExW(hKey, ValueName, NULL, REG_SZ, (BYTE*)ValueData, dwDataSize)) != ERROR_SUCCESS);

    bResult = TRUE;

cleanup:
    if (hKey) RegCloseKey(hKey);
    Utils::SetLastErrorFromNtStatus(status);

    DEBUG(L"Key: %ws | Value: %ws | Data: %ws | Status: 0x%08x", SubKey, ValueName, ValueData, status);

    return bResult;
}

BOOL Utils::GetKnownDllsHandleAddress(OUT PULONG_PTR Address)
{
    BOOL bResult = FALSE;
    HMODULE hNtdll = NULL;
    DWORD i, dwSectionSize, dwIndex, dwMaxSize = 0x1000, dwCurrentCode;
    LPVOID pLdrGetKnownDllSectionHandle, pSectionAddress = NULL, pKnownDllsHandleAddr = NULL, pDataAddr;
    PIMAGE_DOS_HEADER DosHeader;
    PIMAGE_NT_HEADERS NtHeaders;
    PIMAGE_SECTION_HEADER SectionHeader;
    POBJECT_NAME_INFORMATION ObjectInfo = NULL;

    EXIT_ON_ERROR(!Utils::GetProcAddress(STR_MOD_NTDLL, STR_PROC_LDRGETKNOWNDLLSECTIONHANDLE, (FARPROC*)&pLdrGetKnownDllSectionHandle));
    EXIT_ON_ERROR((hNtdll = GetModuleHandleW(STR_MOD_NTDLL)) == NULL);

    DosHeader = (PIMAGE_DOS_HEADER)hNtdll;
    NtHeaders = RVA2VA(PIMAGE_NT_HEADERS, hNtdll, DosHeader->e_lfanew);
    SectionHeader = (PIMAGE_SECTION_HEADER)((LPBYTE)&NtHeaders->OptionalHeader + NtHeaders->FileHeader.SizeOfOptionalHeader);

    for (i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++)
    {
        if (!strcmp((char*)SectionHeader[i].Name, ".data"))
        {
            pSectionAddress = RVA2VA(PULONG_PTR, hNtdll, SectionHeader[i].VirtualAddress);
            dwSectionSize = SectionHeader[i].Misc.VirtualSize;
            break;
        }
    }

    EXIT_ON_ERROR(pSectionAddress == 0 || dwSectionSize == 0);
    EXIT_ON_ERROR(!(ObjectInfo = (POBJECT_NAME_INFORMATION)LocalAlloc(LPTR, 1024)));

    dwIndex = 0;
    do
    {
        // If we reach the RET instruction, we found the end of the function.
        if (*(PWORD)pLdrGetKnownDllSectionHandle == 0xccc3 || dwIndex >= dwMaxSize)
            break;

        // 1. Read the 4 bytes at the current position => Potential RIP relative offset.
        // 2. Add the offset to the current position => Absolute address.
        // 3. Check if the calculated address is in the .data section.
        // 4. If so, we have a candidate, check if we can find the \KnownDlls handle at this address.
        dwCurrentCode = *(PDWORD)pLdrGetKnownDllSectionHandle;
        pDataAddr = (PBYTE)pLdrGetKnownDllSectionHandle + sizeof(dwCurrentCode) + dwCurrentCode;
        if (pDataAddr >= pSectionAddress && pDataAddr < ((PBYTE)pSectionAddress + dwSectionSize))
        {
            if (NT_SUCCESS(NtQueryObject(*(LPHANDLE)pDataAddr, ObjectNameInformation, ObjectInfo, MAX_PATH, NULL)))
            {
                if (ObjectInfo->Name.Buffer && !wcscmp(ObjectInfo->Name.Buffer, STR_KNOWNDLLS))
                {
                    pKnownDllsHandleAddr = pDataAddr;
                    break;
                }
            }
        }

        pLdrGetKnownDllSectionHandle = (PBYTE)pLdrGetKnownDllSectionHandle + 1;
        dwIndex += 1;

    } while (!pKnownDllsHandleAddr);

    EXIT_ON_ERROR(!pKnownDllsHandleAddr);

    *Address = (ULONG_PTR)pKnownDllsHandleAddr;
    bResult = TRUE;

cleanup:
    Utils::SafeFree((PVOID*)&ObjectInfo);

    DEBUG(L"KnownDlls handle @ 0x%llx | Result: %d", (DWORD64)pKnownDllsHandleAddr, bResult);

    return bResult;
}

BOOL Utils::GetEmbeddedResource(IN DWORD ResourceId, OUT LPVOID* Buffer, OUT LPDWORD Size)
{
    BOOL bResult = FALSE;
    LPVOID lpData = NULL;
    HRSRC hResource = NULL;
    HGLOBAL hResourceData = NULL;
    DWORD dwResourceSize = 0;

    EXIT_ON_ERROR(!(hResource = FindResourceW(NULL, MAKEINTRESOURCE(ResourceId), RT_RCDATA)));
    EXIT_ON_ERROR(!(dwResourceSize = SizeofResource(NULL, hResource)));
    EXIT_ON_ERROR(!(hResourceData = LoadResource(NULL, hResource)));
    EXIT_ON_ERROR(!(lpData = LockResource(hResourceData)));

    *Buffer = lpData;
    *Size = dwResourceSize;
    bResult = TRUE;

cleanup:
    DEBUG(L"Buffer @ 0x%p (size: %d) | Result: %d", lpData, dwResourceSize, bResult);

    return bResult;
}

BOOL Utils::FindWritableSystemDll(IN DWORD MinSize, OUT LPWSTR* FilePath)
{
    BOOL bResult = FALSE, bCurrentDirectoryChanged = FALSE;
    LPWSTR pwszCurrentDirectory = NULL, pwszSystemDirectory = NULL, pwszFilePath = NULL;
    WIN32_FIND_DATA wfd;
    HANDLE hFind = NULL, hFile = NULL;
    DWORD dwFileSize;

    EXIT_ON_ERROR(!(pwszCurrentDirectory = (LPWSTR)LocalAlloc(LPTR, (MAX_PATH + 1) * sizeof(WCHAR))));
    EXIT_ON_ERROR(!(pwszSystemDirectory = (LPWSTR)LocalAlloc(LPTR, (MAX_PATH + 1) * sizeof(WCHAR))));
    EXIT_ON_ERROR(!(pwszFilePath = (LPWSTR)LocalAlloc(LPTR, (MAX_PATH + 1) * sizeof(WCHAR))));
    EXIT_ON_ERROR(!GetCurrentDirectoryW(MAX_PATH, pwszCurrentDirectory));
    EXIT_ON_ERROR(!GetSystemDirectoryW(pwszSystemDirectory, MAX_PATH));
    EXIT_ON_ERROR(!SetCurrentDirectoryW(pwszSystemDirectory));
    
    bCurrentDirectoryChanged = TRUE;

    EXIT_ON_ERROR((hFind = FindFirstFileW(L"*.dll", &wfd)) == INVALID_HANDLE_VALUE);

    do
    {
        if ((hFile = CreateFileW(wfd.cFileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE)
            goto loopcleanup;

        dwFileSize = GetFileSize(hFile, NULL);

        if (dwFileSize == INVALID_FILE_SIZE || dwFileSize < MinSize)
            goto loopcleanup;

        if (!(*FilePath = (LPWSTR)LocalAlloc(LPTR, (MAX_PATH + 1) * sizeof(WCHAR))))
            goto loopcleanup;

        swprintf_s(*FilePath, MAX_PATH, L"%ws\\%ws", pwszSystemDirectory, wfd.cFileName);
        bResult = TRUE;

    loopcleanup:
        Utils::SafeCloseHandle(&hFile);

    } while (FindNextFileW(hFind, &wfd) && !bResult);

cleanup:
    if (bCurrentDirectoryChanged) SetCurrentDirectoryW(pwszCurrentDirectory);
    if (hFind && hFind != INVALID_HANDLE_VALUE) FindClose(hFind);
    Utils::SafeFree((PVOID*)&pwszCurrentDirectory);
    Utils::SafeFree((PVOID*)&pwszSystemDirectory);
    Utils::SafeFree((PVOID*)&pwszFilePath);

    DEBUG(L"File: %ws | Result: %d", *FilePath, bResult);

    return bResult;
}

BOOL Utils::FindModuleSection(IN HMODULE Module, IN LPCSTR SectionName, OUT PULONG_PTR Address, OUT LPDWORD Size)
{
    BOOL bResult = FALSE;
    const DWORD dwBufferSize = PAGE_SIZE;
    PIMAGE_NT_HEADERS pNtHeaders = NULL;
    PIMAGE_SECTION_HEADER pSectionHeader;
    DWORD i;
    PBYTE pBuffer = NULL;

    EXIT_ON_ERROR(!(pBuffer = (PBYTE)LocalAlloc(LPTR, dwBufferSize)));
    EXIT_ON_ERROR(!(pNtHeaders = RtlImageNtHeader(Module)));

    for (i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++)
    {
        pSectionHeader = (PIMAGE_SECTION_HEADER)((PBYTE)pNtHeaders + sizeof(*pNtHeaders) + i * sizeof(*pSectionHeader));

        if (!strcmp((char*)pSectionHeader->Name, SectionName))
        {
            *Address = (ULONG_PTR)((PBYTE)Module + pSectionHeader->VirtualAddress);
            *Size = pSectionHeader->SizeOfRawData;
            bResult = TRUE;
            break;
        }
    }

cleanup:
    DEBUG(L"NT headers @ 0x%016llx | Address: 0x%016llx | Size: %d | Result: %d", (DWORD64)pNtHeaders, *Address, *Size, bResult);

    Utils::SafeFree((PVOID*)&pBuffer);

    return bResult;
}

BOOL Utils::FindModulePattern(IN PBYTE Pattern, IN DWORD PatternLength, IN ULONG_PTR Address, IN DWORD Size, OUT PULONG_PTR PatternAddress)
{
    BOOL bResult = FALSE;
    ULONG_PTR pModulePointer = NULL, pModuleLimit;

    pModulePointer = Address;
    pModuleLimit = Address + Size - PatternLength;

    do
    {
        if (!memcmp(Pattern, (PVOID)pModulePointer, PatternLength))
        {
            *PatternAddress = pModulePointer;
            bResult = TRUE;
            break;
        }

        pModulePointer++;

    } while ((pModulePointer < pModuleLimit) && !bResult);

    DEBUG(L"Pattern address: 0x%016llx | Result: %d", *PatternAddress, bResult);

    return bResult;
}

BOOL Utils::GetWindowsTempDirectory(OUT LPWSTR* Path)
{
    BOOL bResult = FALSE;
    LPWSTR pwszPath = NULL;

    EXIT_ON_ERROR(!(pwszPath = (LPWSTR)LocalAlloc(LPTR, (MAX_PATH + 1) * sizeof(WCHAR))));
    EXIT_ON_ERROR(!GetWindowsDirectoryW(pwszPath, MAX_PATH));

    swprintf_s(pwszPath, MAX_PATH, L"%ws\\Temp", pwszPath);

    *Path = pwszPath;
    bResult = TRUE;

cleanup:
    if (!bResult) Utils::SafeFree((PVOID*)&pwszPath);

    return bResult;
}

BOOL Utils::DeleteDirectory(IN LPWSTR Path)
{
    BOOL bResult = FALSE, bIsEmpty = TRUE;
    HANDLE hFind = NULL;
    LPWSTR pwszSearchPath = NULL, pwszFullPath = NULL;
    WIN32_FIND_DATAW FindData;

    EXIT_ON_ERROR(!(pwszFullPath = (LPWSTR)LocalAlloc(LPTR, (MAX_PATH + 1) * sizeof(WCHAR))));
    EXIT_ON_ERROR(!(pwszSearchPath = (LPWSTR)LocalAlloc(LPTR, (MAX_PATH + 1) * sizeof(WCHAR))));

    swprintf_s(pwszSearchPath, MAX_PATH, L"%ws\\*", Path);

    if ((hFind = FindFirstFileW(pwszSearchPath, &FindData)) == INVALID_HANDLE_VALUE)
    {
        if (GetLastError() == ERROR_FILE_NOT_FOUND)
            bResult = TRUE;

        goto cleanup;
    }

    do
    {
        swprintf_s(pwszFullPath, MAX_PATH, L"%ws\\%ws", Path, FindData.cFileName);

        if (FindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            if (!_wcsicmp(FindData.cFileName, L".") || !_wcsicmp(FindData.cFileName, L".."))
            {
                continue;
            }

            if (!Utils::DeleteDirectory(pwszFullPath))
            {
                bIsEmpty = FALSE;
            }
        }
        else
        {
            if (!DeleteFileW(pwszFullPath))
            {
                ERROR(L"Failed to delete file: %ws", pwszFullPath);
                bIsEmpty = FALSE;
            }
        }

    } while (FindNextFileW(hFind, &FindData));

    if (bIsEmpty)
    {
        EXIT_ON_ERROR(!RemoveDirectoryW(Path));
    }

    bResult = TRUE;

cleanup:
    if (hFind && hFind != INVALID_HANDLE_VALUE) FindClose(hFind);
    Utils::SafeFree((PVOID*)&pwszSearchPath);
    Utils::SafeFree((PVOID*)&pwszFullPath);

    if (!bResult)
        ERROR(L"Failed to delete directory: %ws", Path);

    return bResult;
}

BOOL Utils::GetFileVersion(IN LPCWSTR Filename, OUT LPWSTR* FileVersion)
{
    BOOL bResult = FALSE;
    DWORD dwHandle = 0, dwSize;
    LPVOID pData = NULL, pInfo;
    UINT uiInfoSize;
    LPWSTR pwszFileVersion = NULL;

    EXIT_ON_ERROR(!(pwszFileVersion = (LPWSTR)LocalAlloc(LPTR, 64 * sizeof(WCHAR))));
    EXIT_ON_ERROR((dwSize = GetFileVersionInfoSizeW(Filename, &dwHandle)) == 0);
    EXIT_ON_ERROR(!(pData = LocalAlloc(LPTR, dwSize)));

    dwHandle = 0;

    EXIT_ON_ERROR(!GetFileVersionInfoW(Filename, dwHandle, dwSize, pData));
    EXIT_ON_ERROR(!VerQueryValueW(pData, L"\\", &pInfo, &uiInfoSize));
    EXIT_ON_ERROR(((VS_FIXEDFILEINFO*)pInfo)->dwSignature != 0xfeef04bd);

    swprintf_s(pwszFileVersion, 64, L"%d.%d.%d.%d",
        (((VS_FIXEDFILEINFO*)pInfo)->dwFileVersionMS >> 16) & 0xffff,
        (((VS_FIXEDFILEINFO*)pInfo)->dwFileVersionMS) & 0xffff,
        (((VS_FIXEDFILEINFO*)pInfo)->dwFileVersionLS >> 16) & 0xffff,
        (((VS_FIXEDFILEINFO*)pInfo)->dwFileVersionLS) & 0xffff
    );

    bResult = TRUE;
   
cleanup:
    Utils::SafeFree((PVOID*)&pData);
    if (!bResult) Utils::SafeFree((PVOID*)&pwszFileVersion);

    return bResult;
}

BOOL Utils::FileExists(IN LPCWSTR FilePath)
{
    return PathFileExistsW(FilePath);
}

BOOL Utils::CreateProtectedProcess(IN LPCWSTR ImagePath, IN PS_PROTECTION Protection, OUT LPPROCESS_INFORMATION ProcessInformation)
{
    BOOL bResult = FALSE;
    NTSTATUS status;

    RTL_USER_PROCESS_INFORMATION pi;
    OBJECT_ATTRIBUTES poa, toa; // Process and Thread object attributes
    PRTL_USER_PROCESS_PARAMETERS pParams = NULL;
    PS_CREATE_INFO ci;
    PS_STD_HANDLE_INFO hi;
    ULONG_PTR attr[offsetof(PS_ATTRIBUTE_LIST, Attributes[5]) / sizeof(ULONG_PTR)];
    PPS_ATTRIBUTE_LIST pAttr = (PPS_ATTRIBUTE_LIST)attr;
    ULONG tflags, pflags;

    LPWSTR pwszCommandLine = NULL;
    UNICODE_STRING ImagePathName, CommandLine, WindowTitle, DesktopInfo;
    UNICODE_STRING ImagePathNameAttr;

    UINT index = 0;

    ZeroMemory(&pi, sizeof(pi));
    ZeroMemory(&ci, sizeof(ci));
    ZeroMemory(&hi, sizeof(hi));

    EXIT_ON_ERROR(!(pwszCommandLine = (LPWSTR)LocalAlloc(LPTR, (wcslen(ImagePath) + 3) * sizeof(WCHAR))));

    swprintf_s(pwszCommandLine, wcslen(ImagePath) + 3, L"\"%ws\"", ImagePath);

    RtlInitUnicodeString(&ImagePathName, ImagePath);
    RtlInitUnicodeString(&CommandLine, pwszCommandLine);
    RtlInitUnicodeString(&WindowTitle, ImagePath);
    RtlInitUnicodeString(&DesktopInfo, L"WinSta0\\Default");

    status = RtlCreateProcessParametersEx(&pParams, &ImagePathName, NULL, NULL, &CommandLine, NULL, &WindowTitle, &DesktopInfo, NULL, NULL, 0x00000001);
    SetLastError(RtlNtStatusToDosError(status));

    EXIT_ON_ERROR(!NT_SUCCESS(status));

    RtlDosPathNameToNtPathName_U(ImagePath, &ImagePathNameAttr, NULL, NULL);
    RtlNormalizeProcessParams(pParams);

    // Image name
    pAttr->Attributes[index].Attribute = PsAttributeImageName | PS_ATTRIBUTE_INPUT;
    pAttr->Attributes[index].Size = ImagePathNameAttr.Length;
    pAttr->Attributes[index].ValuePtr = ImagePathNameAttr.Buffer;
    pAttr->Attributes[index].ReturnLength = NULL;
    index++;
    // Client ID
    pAttr->Attributes[index].Attribute = PsAttributeClientId | PS_ATTRIBUTE_THREAD;
    pAttr->Attributes[index].Size = sizeof(pi.ClientId);
    pAttr->Attributes[index].ValuePtr = &pi.ClientId;
    pAttr->Attributes[index].ReturnLength = NULL;
    index++;
    // Image info
    pAttr->Attributes[index].Attribute = PsAttributeImageInfo;
    pAttr->Attributes[index].Size = sizeof(pi.ImageInformation);
    pAttr->Attributes[index].ValuePtr = &pi.ImageInformation;
    pAttr->Attributes[index].ReturnLength = NULL;
    index++;
    // Standard handles
    pAttr->Attributes[index].Attribute = PsAttributeStdHandleInfo | PS_ATTRIBUTE_INPUT;
    pAttr->Attributes[index].Size = sizeof(hi);
    pAttr->Attributes[index].ValuePtr = &hi;
    pAttr->Attributes[index].ReturnLength = NULL;
    index++;
    // Protection
    pAttr->Attributes[index].Attribute = PsAttributeProtectionLevel | PS_ATTRIBUTE_INPUT | PS_ATTRIBUTE_ADDITIVE;
    pAttr->Attributes[index].Size = sizeof(Protection);
    pAttr->Attributes[index].Value = *(UCHAR*)&Protection;
    pAttr->Attributes[index].ReturnLength = NULL;
    index++;

    pAttr->TotalLength = offsetof(PS_ATTRIBUTE_LIST, Attributes[index]);

    InitializeObjectAttributes(&poa, NULL, 0, NULL, NULL);
    InitializeObjectAttributes(&toa, NULL, 0, NULL, NULL);

    ci.Size = sizeof(ci);
    ci.State = PsCreateInitialState;

    tflags = THREAD_CREATE_FLAGS_CREATE_SUSPENDED;
    pflags = PROCESS_CREATE_FLAGS_PROTECTED_PROCESS;

    status = NtCreateUserProcess(&pi.ProcessHandle, &pi.ThreadHandle, MAXIMUM_ALLOWED, MAXIMUM_ALLOWED, &poa, &toa, pflags, tflags, pParams, &ci, pAttr);
    SetLastError(RtlNtStatusToDosError(status));

    DEBUG(L"NtCreateUserProcess: 0x%08x", status);
    EXIT_ON_ERROR(!NT_SUCCESS(status));

    status = NtResumeThread(pi.ThreadHandle, NULL);
    SetLastError(RtlNtStatusToDosError(status));

    DEBUG(L"NtResumeThread: 0x%08x", status);
    EXIT_ON_ERROR(!NT_SUCCESS(status));

    bResult = TRUE;
    ProcessInformation->hProcess = pi.ProcessHandle;
    ProcessInformation->hThread = &pi.ThreadHandle;
    ProcessInformation->dwProcessId = HandleToULong(pi.ClientId.UniqueProcess);
    ProcessInformation->dwThreadId = HandleToULong(pi.ClientId.UniqueThread);

cleanup:
    DEBUG(L"Result: %d", bResult);

    if (pwszCommandLine) LocalFree(pwszCommandLine);
    if (pParams) RtlDestroyProcessParameters(pParams);

    return bResult;
}

LPCWSTR Utils::GetProcessProtectionLevelAsString(IN DWORD ProtectionLevel)
{
    switch (ProtectionLevel)
    {
        CASE_STR(PROTECTION_LEVEL_WINTCB_LIGHT);
        CASE_STR(PROTECTION_LEVEL_WINDOWS);
        CASE_STR(PROTECTION_LEVEL_WINDOWS_LIGHT);
        CASE_STR(PROTECTION_LEVEL_ANTIMALWARE_LIGHT);
        CASE_STR(PROTECTION_LEVEL_LSA_LIGHT);
        CASE_STR(PROTECTION_LEVEL_WINTCB);
        CASE_STR(PROTECTION_LEVEL_CODEGEN_LIGHT);
        CASE_STR(PROTECTION_LEVEL_AUTHENTICODE);
        CASE_STR(PROTECTION_LEVEL_PPL_APP);
        CASE_STR(PROTECTION_LEVEL_NONE);
    }

    return L"Unknown";
}

LPCWSTR Utils::GetSigningLevelAsString(IN DWORD SigningLevel)
{
    switch (SigningLevel)
    {
        CASE_STR(SE_SIGNING_LEVEL_UNCHECKED);
        CASE_STR(SE_SIGNING_LEVEL_UNSIGNED);
        CASE_STR(SE_SIGNING_LEVEL_ENTERPRISE);
        CASE_STR(SE_SIGNING_LEVEL_DEVELOPER);
        CASE_STR(SE_SIGNING_LEVEL_AUTHENTICODE);
        CASE_STR(SE_SIGNING_LEVEL_CUSTOM_2);
        CASE_STR(SE_SIGNING_LEVEL_STORE);
        CASE_STR(SE_SIGNING_LEVEL_ANTIMALWARE);
        CASE_STR(SE_SIGNING_LEVEL_MICROSOFT);
        CASE_STR(SE_SIGNING_LEVEL_CUSTOM_4);
        CASE_STR(SE_SIGNING_LEVEL_CUSTOM_5);
        CASE_STR(SE_SIGNING_LEVEL_DYNAMIC_CODEGEN);
        CASE_STR(SE_SIGNING_LEVEL_WINDOWS);
        CASE_STR(SE_SIGNING_LEVEL_CUSTOM_7);
        CASE_STR(SE_SIGNING_LEVEL_WINDOWS_TCB);
        CASE_STR(SE_SIGNING_LEVEL_CUSTOM_6);
    }

    ERROR(L"Failed to retrieve the Signature level associated to the value %d.", SigningLevel);

    return STR_SE_SIGNING_LEVEL_UNKNOWN;
}

// https://github.com/winsiderss/systeminformer/blob/master/phlib/hndlinfo.c
BOOL Utils::EnumObjectTypes(OUT POBJECT_TYPES_INFORMATION* ObjectTypes)
{
    BOOL bResult = FALSE;
    NTSTATUS status = STATUS_SUCCESS;
    PVOID pBuffer = NULL;
    DWORD dwBufferSize;
    DWORD dwReturnLength;

    *ObjectTypes = NULL;
    dwBufferSize = PAGE_SIZE;
    pBuffer = LocalAlloc(LPTR, dwBufferSize);

    while ((status = NtQueryObject(NULL, (OBJECT_INFORMATION_CLASS)ObjectTypesInformation, pBuffer, dwBufferSize, &dwReturnLength)) == STATUS_INFO_LENGTH_MISMATCH)
    {
        LocalFree(pBuffer);
        dwBufferSize *= 2;

        if (dwBufferSize > LARGE_BUFFER_SIZE)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto cleanup;
        }

        pBuffer = LocalAlloc(LPTR, dwBufferSize);
    }

    bResult = TRUE;
    *ObjectTypes = (POBJECT_TYPES_INFORMATION)pBuffer;

cleanup:
    if (!bResult && pBuffer) LocalFree(pBuffer);
    Utils::SetLastErrorFromNtStatus(status);

    DEBUG(L"Object types buffer: 0x%p", *ObjectTypes);

    return bResult;
}

BOOL Utils::GetServiceHandle(IN LPCWSTR ServiceName, IN DWORD DesiredAccess, OUT LPSC_HANDLE ServiceHandle)
{
    BOOL bResult = FALSE;
    SC_HANDLE hSCM = NULL;

    *ServiceHandle = NULL;

    EXIT_ON_ERROR(!(hSCM = OpenSCManagerW(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT)));
    EXIT_ON_ERROR((*ServiceHandle = OpenServiceW(hSCM, ServiceName, DesiredAccess)) == NULL);
    
    bResult = TRUE;

cleanup:
    if (hSCM) CloseServiceHandle(hSCM);

    DEBUG(L"Handle for service '%ws': 0x%016llx", ServiceName, (DWORD64)*ServiceHandle);

    return bResult;
}

BOOL Utils::QueryServiceStatusProcessByHandle(IN SC_HANDLE ServiceHandle, IN OUT LPSERVICE_STATUS_PROCESS ServiceStatus)
{
    BOOL bResult = FALSE;
    DWORD dwBytesNeeded;

    ZeroMemory(ServiceStatus, sizeof(*ServiceStatus));

    bResult = QueryServiceStatusEx(ServiceHandle, SC_STATUS_PROCESS_INFO, (LPBYTE)ServiceStatus, sizeof(*ServiceStatus), &dwBytesNeeded);

    DEBUG(L"Query service with handle 0x%016llx: %d", (DWORD64)ServiceHandle, bResult);

    return bResult;
}

BOOL Utils::QueryServiceStatusProcessByName(IN LPCWSTR ServiceName, IN OUT LPSERVICE_STATUS_PROCESS ServiceStatus)
{
    BOOL bResult = FALSE;
    SC_HANDLE hService = NULL;

    EXIT_ON_ERROR(!Utils::GetServiceHandle(ServiceName, SERVICE_QUERY_STATUS, &hService));
    EXIT_ON_ERROR(!Utils::QueryServiceStatusProcessByHandle(hService, ServiceStatus));

    bResult = TRUE;

cleanup:
    if (hService) CloseServiceHandle(hService);

    DEBUG(L"Query service with name '%ws': %d", ServiceName, bResult);

    return bResult;
}