#pragma once

#include <Windows.h>

DWORD WINAPI PayloadThread(LPVOID Parameter);
BOOL SignalDllLoadEvent(LPCWSTR EventName);
BOOL GetExeFileName(LPWSTR* FileName);
