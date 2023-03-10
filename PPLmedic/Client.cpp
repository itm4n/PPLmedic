#include "Client.h"
#include <strsafe.h>

Client::Client(LPCWSTR PipeName)
{
    this->_PipeName = PipeName;
    this->_PipeHandle = INVALID_HANDLE_VALUE;
    this->_PipeRequest = (LPBYTE)LocalAlloc(LPTR, PAGE_SIZE);
    this->_PipeResponse = (LPBYTE)LocalAlloc(LPTR, PAGE_SIZE);
    this->_LastError = ERROR_SUCCESS;
}

Client::~Client()
{
    if (this->_PipeHandle != INVALID_HANDLE_VALUE) CloseHandle(this->_PipeHandle);
    if (this->_PipeRequest) LocalFree(this->_PipeRequest);
    if (this->_PipeResponse) LocalFree(this->_PipeResponse);
}

BOOL Client::Connect()
{
    BOOL bResult = TRUE;
    LPWSTR pwszPipeName = NULL;

    EXIT_ON_ERROR(!(pwszPipeName = (LPWSTR)LocalAlloc(LPTR, (MAX_PATH + 1) * sizeof(WCHAR))));

    swprintf_s(pwszPipeName, MAX_PATH, L"\\\\.\\pipe\\%ws", this->_PipeName);

    EXIT_ON_ERROR((this->_PipeHandle = CreateFileW(pwszPipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL)) == INVALID_HANDLE_VALUE);

    bResult = TRUE;

cleanup:
    DEBUG(L"Pipe name: %ws | Handle: 0x%04x | Result: %d", pwszPipeName, HandleToULong(this->_PipeHandle), bResult);

    if (pwszPipeName) LocalFree(pwszPipeName);

    return bResult;
}

BOOL Client::GetLastError()
{
    return this->_LastError;
}

BOOL Client::SendAndReceive(PMSG_REQUEST Request, DWORD RequestSize, PMSG_RESPONSE Response, PDWORD ResponseSize)
{
    BOOL bResult = FALSE;
    DWORD dwBytesWritten, dwBytesRead;

    EXIT_ON_ERROR(!WriteFile(this->_PipeHandle, Request, RequestSize, &dwBytesWritten, NULL));
    EXIT_ON_ERROR(!ReadFile(this->_PipeHandle, Response, PAGE_SIZE, &dwBytesRead, NULL));

    *ResponseSize = dwBytesRead;
    bResult = TRUE;

cleanup:
    DEBUG(L"LE: %d | Result: %d", LAST_ERROR(bResult), bResult);

    return bResult;
}

BOOL Client::GetProtectionLevel(PDWORD ProtectionLevel)
{
    BOOL bResult = FALSE;
    PMSG_REQUEST pRequest;
    PMSG_RESPONSE pResponse;
    DWORD dwResponseSize;

    pRequest = (PMSG_REQUEST)this->_PipeRequest;
    pResponse = (PMSG_RESPONSE)this->_PipeResponse;

    pRequest->Type = MessageType::DoGetProtectionLevel;

    EXIT_ON_ERROR(!SendAndReceive(pRequest, sizeof(*pRequest), pResponse, &dwResponseSize));

    bResult = pResponse->Result;
    *ProtectionLevel = pResponse->p.ProtectionLevel.Level;

cleanup:
    DEBUG(L"LE: %d | Result: %d", bResult ? ERROR_SUCCESS : pResponse->LastError, bResult);

    this->_LastError = pResponse->LastError;

    return bResult;
}

BOOL Client::DumpProcessMemory(DWORD ProcessId, LPCWSTR FilePath)
{
    BOOL bResult = FALSE;
    PMSG_REQUEST pRequest;
    PMSG_RESPONSE pResponse;
    DWORD dwResponseSize;

    pRequest = (PMSG_REQUEST)this->_PipeRequest;
    pResponse = (PMSG_RESPONSE)this->_PipeResponse;

    pRequest->Type = MessageType::DoDumpProcess;
    pRequest->p.DumpProcess.Pid = ProcessId;
    swprintf_s(pRequest->p.DumpProcess.OutputFilePath, sizeof(pRequest->p.DumpProcess.OutputFilePath) / sizeof(*pRequest->p.DumpProcess.OutputFilePath), L"%ws", FilePath);

    EXIT_ON_ERROR(!SendAndReceive(pRequest, sizeof(*pRequest), pResponse, &dwResponseSize));

    bResult = pResponse->Result;

cleanup:
    DEBUG(L"LE: %d | Result: %d", bResult ? ERROR_SUCCESS : pResponse->LastError, bResult);

    this->_LastError = pResponse->LastError;

    return bResult;
}

BOOL Client::FakeSignDll(LPCWSTR UnsignedFilePath, LPCWSTR SignedFilePath, PDWORD SigningLevel)
{
    BOOL bResult = FALSE;
    PMSG_REQUEST pRequest;
    PMSG_RESPONSE pResponse;
    DWORD dwResponseSize;

    pRequest = (PMSG_REQUEST)this->_PipeRequest;
    pResponse = (PMSG_RESPONSE)this->_PipeResponse;

    pRequest->Type = MessageType::DoFakeSignDll;
    swprintf_s(pRequest->p.FakeSignDll.InputFilePath, sizeof(pRequest->p.FakeSignDll.InputFilePath) / sizeof(*pRequest->p.FakeSignDll.InputFilePath), L"%ws", UnsignedFilePath);
    swprintf_s(pRequest->p.FakeSignDll.OutputFilePath, sizeof(pRequest->p.FakeSignDll.OutputFilePath) / sizeof(*pRequest->p.FakeSignDll.OutputFilePath), L"%ws", SignedFilePath);

    EXIT_ON_ERROR(!SendAndReceive(pRequest, sizeof(*pRequest), pResponse, &dwResponseSize));

    bResult = pResponse->Result;
    *SigningLevel = pResponse->p.SigningLevel.Level;

cleanup:
    DEBUG(L"LE: %d | Result: %d", bResult ? ERROR_SUCCESS : pResponse->LastError, bResult);

    this->_LastError = pResponse->LastError;

    return bResult;
}
