#include "common.h"
#include <strsafe.h>

void PrintDebug(LPCWSTR Format, ...)
{
    LPWSTR pwszDebugString = NULL;
    DWORD dwDebugStringLen = 0;
    va_list va;
    size_t st_Offset = 0;

    va_start(va, Format);

    dwDebugStringLen += _vscwprintf(Format, va) * sizeof(WCHAR) + 2;
    pwszDebugString = (LPWSTR)LocalAlloc(LPTR, dwDebugStringLen);

    if (pwszDebugString)
    {
        if (SUCCEEDED(StringCbLengthW(pwszDebugString, dwDebugStringLen, &st_Offset)))
        {
            StringCbVPrintfW(&pwszDebugString[st_Offset / sizeof(WCHAR)], dwDebugStringLen - st_Offset, Format, va);
            OutputDebugStringW(pwszDebugString);
        }

        LocalFree(pwszDebugString);
    }

    va_end(va);
}