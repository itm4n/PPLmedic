#pragma once

#include <Windows.h>
#include "globaldef.h"

class Client
{
private:
    LPCWSTR _PipeName;
    HANDLE _PipeHandle;
    LPBYTE _PipeRequest;
    LPBYTE _PipeResponse;
    DWORD _LastError;

public:
    Client(LPCWSTR PipeName);
    ~Client();
    BOOL Connect();
    BOOL GetLastError();
    BOOL SendAndReceive(PMSG_REQUEST Request, DWORD RequestSize, PMSG_RESPONSE Response, PDWORD ResponseSize);
    BOOL GetProtectionLevel(PDWORD ProtectionLevel);
    BOOL DumpProcessMemory(DWORD ProcessId, LPCWSTR FilePath);
    BOOL FakeSignDll(LPCWSTR UnsignedFilePath, LPCWSTR SignedFilePath, PDWORD SigningLevel);
};
