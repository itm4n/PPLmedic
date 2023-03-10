#pragma once

#include <Windows.h>
#include "globaldef.h"

class Server
{
private:
    LPCWSTR _PipeName;
    HANDLE _PipeHandle;
    BOOL _PipeConnected;
    LPBYTE _PipeRequest;
    LPBYTE _PipeResponse;

public:
    Server(LPCWSTR PipeName);
    ~Server();
    BOOL Create();
    BOOL Listen();

private:
    // Helpers
    static HANDLE CreateCustomNamedPipe(LPCWSTR PipeName, BOOL Async);
    static BOOL PrivilegeCheckByName(LPCWSTR PrivilegeName, PBOOL PrivilegeHeld);
    static BOOL GetInitialLogonSessionToken(PHANDLE Token);
    static BOOL FindCatalogFile(LPWSTR* FilePath);
    static BOOL SetFileCatalogHint(HANDLE FileHandle, LPWSTR CatalogPath);
    static BOOL SetFileOpLock(LPWSTR FilePath, PHANDLE FileHandle, PHANDLE LockEvent);
    static BOOL GetFileSigningLevel(HANDLE FileHandle, PDWORD SigningLevel);
    static DWORD WINAPI CreateSectionThread(LPVOID Parameter);
    // Client request processing
    BOOL ProcessRequest(LPBYTE Request, LPBYTE Response, PDWORD ResponseSize);
    BOOL DoGetProtectionLevel(PMSG_REQUEST Request, PMSG_RESPONSE Response);
    BOOL DoDumpProcessMemory(PMSG_REQUEST Request, PMSG_RESPONSE Response);
    BOOL DoFakeSignDll(PMSG_REQUEST Request, PMSG_RESPONSE Response);
};
