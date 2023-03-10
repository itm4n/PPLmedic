#pragma once

#include <Windows.h>
#include <iostream>
#include <shlwapi.h>
#include "globaldef.h"
#include "ntstuff.h"
#pragma comment(lib, "rpcrt4.lib")
#pragma comment(lib, "Version.lib")
#pragma comment(lib, "Shlwapi.lib")

#define CASE_STR( c ) case c: return STR_##c

class Utils
{
public:
    static VOID PrintLastError();
    static LPWSTR GenerateUuid();
    static BOOL GenerateTempPath(IN OUT LPWSTR Buffer);
    static VOID SafeCloseHandle(IN PHANDLE Handle);
    static VOID SafeFree(IN PVOID* Memory);
    static VOID SafeRelease(IN IUnknown** Interface);
    static VOID SetLastErrorFromNtStatus(IN NTSTATUS Status);
    static BOOL GetProcAddress(IN LPCWSTR Dll, IN LPCSTR ProcName, OUT FARPROC* ProcAddress);
    static BOOL GetTypeIndexByName(IN LPCWSTR TypeName, OUT LPDWORD TypeIndex);
    static BOOL GetServiceProcessId(IN LPCWSTR ServiceName, OUT LPDWORD ProcessId);
    static BOOL GetServiceStatusByHandle(IN SC_HANDLE ServiceHandle, OUT LPDWORD Status);
    static BOOL GetServiceStatusByName(IN LPCWSTR ServiceName, OUT LPDWORD Status);
    static BOOL StartServiceByName(IN LPCWSTR ServiceName, IN BOOL Wait);
    static BOOL StopServiceByName(IN LPCWSTR ServiceName, IN BOOL Wait);
    static BOOL IsServiceRunning(IN LPCWSTR ServiceName);
    static BOOL FindUniqueHandleValueByTypeName(IN DWORD ProcessId, IN LPCWSTR TypeName, OUT PULONG HandleValue);
    static BOOL EnablePrivilege(IN LPCWSTR PrivilegeName);
    static BOOL GetRegistryStringValue(IN HKEY Key, IN LPCWSTR SubKey, IN LPCWSTR ValueName, OUT LPWSTR* ValueData);
    static BOOL SetRegistryStringValue(IN HKEY Key, IN LPCWSTR SubKey, IN LPCWSTR ValueName, IN LPCWSTR ValueData);
    static BOOL GetKnownDllsHandleAddress(OUT PULONG_PTR Address);
    static BOOL GetEmbeddedResource(IN DWORD ResourceId, OUT LPVOID* Buffer, OUT LPDWORD Size);
    static BOOL FindWritableSystemDll(IN DWORD MinSize, OUT LPWSTR* FilePath);
    static BOOL FindModuleSection(IN HMODULE Module, IN LPCSTR SectionName, OUT PULONG_PTR Address, OUT LPDWORD Size);
    static BOOL FindModulePattern(IN PBYTE Pattern, IN DWORD PatternLength, IN ULONG_PTR Address, IN DWORD Size, OUT PULONG_PTR PatternAddress);
    static BOOL GetWindowsTempDirectory(OUT LPWSTR* Path);
    static BOOL DeleteDirectory(IN LPWSTR Path);
    static BOOL GetFileVersion(IN LPCWSTR Filename, OUT LPWSTR* FileVersion);
    static BOOL FileExists(IN LPCWSTR FilePath);
    static BOOL CreateProtectedProcess(IN LPCWSTR ImagePath, IN PS_PROTECTION Protection, OUT LPPROCESS_INFORMATION ProcessInformation);
    static LPCWSTR GetProcessProtectionLevelAsString(IN DWORD ProtectionLevel);
    static LPCWSTR GetSigningLevelAsString(IN DWORD SigningLevel);

private:
    static BOOL EnumObjectTypes(OUT POBJECT_TYPES_INFORMATION* ObjectTypes);
    static BOOL GetServiceHandle(IN LPCWSTR ServiceName, IN DWORD DesiredAccess, OUT LPSC_HANDLE ServiceHandle);
    static BOOL QueryServiceStatusProcessByHandle(IN SC_HANDLE ServiceHandle, IN OUT LPSERVICE_STATUS_PROCESS ServiceStatus);
    static BOOL QueryServiceStatusProcessByName(IN LPCWSTR ServiceName, IN OUT LPSERVICE_STATUS_PROCESS ServiceStatus);
};