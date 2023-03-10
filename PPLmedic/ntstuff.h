#pragma once

#include <Windows.h>

#ifndef __NTDLL_H__
#define __NTDLL_H__

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _NTDLL_SELF_                            // Auto-insert the library
#pragma comment(lib, "Ntdll.lib")
#endif

#pragma comment(lib, "ntdll.lib")

#define STATUS_SUCCESS                              0x00000000
#define STATUS_INFO_LENGTH_MISMATCH                 0xC0000004
#define STATUS_INSUFFICIENT_RESOURCES               0xC000009a

// https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntrtl.h
#define RtlOffsetToPointer(Base, Offset) ((PCHAR)(((PCHAR)(Base)) + ((ULONG_PTR)(Offset))))
#define RtlPointerToOffset(Base, Pointer) ((ULONG)(((PCHAR)(Pointer)) - ((PCHAR)(Base))))

// https://github.com/winsiderss/systeminformer/blob/master/phlib/include/phsup.h
#define PTR_ADD_OFFSET(Pointer, Offset) ((PVOID)((ULONG_PTR)(Pointer) + (ULONG_PTR)(Offset)))
#define PTR_SUB_OFFSET(Pointer, Offset) ((PVOID)((ULONG_PTR)(Pointer) - (ULONG_PTR)(Offset)))
#define ALIGN_UP_BY(Address, Align) (((ULONG_PTR)(Address) + (Align) - 1) & ~((Align) - 1))
#define ALIGN_UP_POINTER_BY(Pointer, Align) ((PVOID)ALIGN_UP_BY(Pointer, Align))
#define ALIGN_UP(Address, Type) ALIGN_UP_BY(Address, sizeof(Type))
#define ALIGN_UP_POINTER(Pointer, Type) ((PVOID)ALIGN_UP(Pointer, Type))
#define ALIGN_DOWN_BY(Address, Align) ((ULONG_PTR)(Address) & ~((ULONG_PTR)(Align) - 1))
#define ALIGN_DOWN_POINTER_BY(Pointer, Align) ((PVOID)ALIGN_DOWN_BY(Pointer, Align))
#define ALIGN_DOWN(Address, Type) ALIGN_DOWN_BY(Address, sizeof(Type))
#define ALIGN_DOWN_POINTER(Pointer, Type) ((PVOID)ALIGN_DOWN(Pointer, Type))

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes( innerPath, n, a, r, s ) {   \
    (innerPath)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (innerPath)->RootDirectory = r;                             \
    (innerPath)->Attributes = a;                                \
    (innerPath)->ObjectName = n;                                \
    (innerPath)->SecurityDescriptor = s;                        \
    (innerPath)->SecurityQualityOfService = NULL;               \
    }
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status)   ((NTSTATUS)(Status) >= 0)
#endif

typedef enum _SECTION_INHERIT
{
    ViewShare = 1,
    ViewUnmap = 2

} SECTION_INHERIT;

typedef enum _OBJECT_INFORMATION_CLASS
{
    ObjectBasicInformation,
    ObjectNameInformation,
    ObjectTypeInformation,
    ObjectTypesInformation,
    ObjectHandleFlagInformation,
    ObjectSessionInformation,
    MaxObjectInfoClass

} OBJECT_INFORMATION_CLASS;

typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemBasicInformation,                     // 0x00
    SystemProcessorInformation,                 // 0x01
    SystemPerformanceInformation,               // 0x02
    SystemTimeOfDayInformation,                 // 0x03
    SystemPathInformation,                      // 0x04 (Obsolete: Use KUSER_SHARED_DATA)
    SystemProcessInformation,                   // 0x05
    SystemCallCountInformation,                 // 0x06
    SystemDeviceInformation,                    // 0x07
    SystemProcessorPerformanceInformation,      // 0x08
    SystemFlagsInformation,                     // 0x09
    SystemCallTimeInformation,                  // 0x0a
    SystemModuleInformation,                    // 0x0b
    SystemLocksInformation,                     // 0x0c
    SystemStackTraceInformation,                // 0x0d
    SystemPagedPoolInformation,                 // 0x0e
    SystemNonPagedPoolInformation,              // 0x0f
    SystemHandleInformation,                    // 0x10
    SystemObjectInformation,                    // 0x11
    SystemPageFileInformation,                  // 0x12
    SystemVdmInstemulInformation,               // 0x13
    SystemVdmBopInformation,                    // 0x14
    SystemFileCacheInformation,                 // 0x15
    SystemPoolTagInformation,                   // 0x16
    SystemInterruptInformation,                 // 0x17
    SystemDpcBehaviorInformation,               // 0x18
    SystemFullMemoryInformation,                // 0x19
    SystemLoadGdiDriverInformation,             // 0x1a
    SystemUnloadGdiDriverInformation,           // 0x1b
    SystemTimeAdjustmentInformation,            // 0x1c
    SystemSummaryMemoryInformation,             // 0x1d
    SystemMirrorMemoryInformation,              // 0x1e
    SystemPerformanceTraceInformation,          // 0x1f
    SystemObsolete0,                            // 0x20
    SystemExceptionInformation,                 // 0x21
    SystemCrashDumpStateInformation,            // 0x22
    SystemKernelDebuggerInformation,            // 0x23
    SystemContextSwitchInformation,             // 0x24
    SystemRegistryQuotaInformation,             // 0x25
    SystemExtendServiceTableInformation,        // 0x26
    SystemPrioritySeperation,                   // 0x27
    SystemPlugPlayBusInformation,               // 0x28
    SystemDockInformation,                      // 0x29
    SystemPowerInformationNative,               // 0x2a
    SystemProcessorSpeedInformation,            // 0x2b
    SystemCurrentTimeZoneInformation,           // 0x2c
    SystemLookasideInformation,
    SystemTimeSlipNotification,
    SystemSessionCreate,
    SystemSessionDetach,
    SystemSessionInformation,
    SystemRangeStartInformation,
    SystemVerifierInformation,
    SystemAddVerifier,
    SystemSessionProcessesInformation,
    SystemLoadGdiDriverInSystemSpaceInformation,
    SystemNumaProcessorMap,
    SystemPrefetcherInformation,
    SystemExtendedProcessInformation,
    SystemRecommendedSharedDataAlignment,
    SystemComPlusPackage,
    SystemNumaAvailableMemory,
    SystemProcessorPowerInformation,
    SystemEmulationBasicInformation,
    SystemEmulationProcessorInformation,
    SystemExtendedHandleInformation,
    SystemLostDelayedWriteInformation,
    SystemBigPoolInformation,
    SystemSessionPoolTagInformation,
    SystemSessionMappedViewInformation,
    SystemHotpatchInformation,
    SystemObjectSecurityMode,
    SystemWatchDogTimerHandler,
    SystemWatchDogTimerInformation,
    SystemLogicalProcessorInformation,
    SystemWo64SharedInformationObosolete,
    SystemRegisterFirmwareTableInformationHandler,
    SystemFirmwareTableInformation,
    SystemModuleInformationEx,
    SystemVerifierTriageInformation,
    SystemSuperfetchInformation,
    SystemMemoryListInformation,
    SystemFileCacheInformationEx,
    SystemThreadPriorityClientIdInformation,
    SystemProcessorIdleCycleTimeInformation,
    SystemVerifierCancellationInformation,
    SystemProcessorPowerInformationEx,
    SystemRefTraceInformation,
    SystemSpecialPoolInformation,
    SystemProcessIdInformation,
    SystemErrorPortInformation,
    SystemBootEnvironmentInformation,
    SystemHypervisorInformation,
    SystemVerifierInformationEx,
    SystemTimeZoneInformation,
    SystemImageFileExecutionOptionsInformation,
    SystemCoverageInformation,
    SystemPrefetchPathInformation,
    SystemVerifierFaultsInformation,
    MaxSystemInfoClass,
} SYSTEM_INFORMATION_CLASS, * PSYSTEM_INFORMATION_CLASS;

typedef enum _PS_CREATE_STATE
{
    PsCreateInitialState,
    PsCreateFailOnFileOpen,
    PsCreateFailOnSectionCreate,
    PsCreateFailExeFormat,
    PsCreateFailMachineMismatch,
    PsCreateFailExeName, // Debugger specified
    PsCreateSuccess,
    PsCreateMaximumStates
} PS_CREATE_STATE;

// https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntpsapi.h
typedef enum _PS_ATTRIBUTE_NUM
{
    PsAttributeParentProcess, // in HANDLE
    PsAttributeDebugObject, // in HANDLE
    PsAttributeToken, // in HANDLE
    PsAttributeClientId, // out PCLIENT_ID
    PsAttributeTebAddress, // out PTEB *
    PsAttributeImageName, // in PWSTR
    PsAttributeImageInfo, // out PSECTION_IMAGE_INFORMATION
    PsAttributeMemoryReserve, // in PPS_MEMORY_RESERVE
    PsAttributePriorityClass, // in UCHAR
    PsAttributeErrorMode, // in ULONG
    PsAttributeStdHandleInfo, // 10, in PPS_STD_HANDLE_INFO
    PsAttributeHandleList, // in HANDLE[]
    PsAttributeGroupAffinity, // in PGROUP_AFFINITY
    PsAttributePreferredNode, // in PUSHORT
    PsAttributeIdealProcessor, // in PPROCESSOR_NUMBER
    PsAttributeUmsThread, // ? in PUMS_CREATE_THREAD_ATTRIBUTES
    PsAttributeMitigationOptions, // in PPS_MITIGATION_OPTIONS_MAP (PROCESS_CREATION_MITIGATION_POLICY_*) // since WIN8
    PsAttributeProtectionLevel, // in PS_PROTECTION // since WINBLUE
    PsAttributeSecureProcess, // in PPS_TRUSTLET_CREATE_ATTRIBUTES, since THRESHOLD
    PsAttributeJobList, // in HANDLE[]
    PsAttributeChildProcessPolicy, // 20, in PULONG (PROCESS_CREATION_CHILD_PROCESS_*) // since THRESHOLD2
    PsAttributeAllApplicationPackagesPolicy, // in PULONG (PROCESS_CREATION_ALL_APPLICATION_PACKAGES_*) // since REDSTONE
    PsAttributeWin32kFilter, // in PWIN32K_SYSCALL_FILTER
    PsAttributeSafeOpenPromptOriginClaim, // in
    PsAttributeBnoIsolation, // in PPS_BNO_ISOLATION_PARAMETERS // since REDSTONE2
    PsAttributeDesktopAppPolicy, // in PULONG (PROCESS_CREATION_DESKTOP_APP_*)
    PsAttributeChpe, // in BOOLEAN // since REDSTONE3
    PsAttributeMitigationAuditOptions, // in PPS_MITIGATION_AUDIT_OPTIONS_MAP (PROCESS_CREATION_MITIGATION_AUDIT_POLICY_*) // since 21H1
    PsAttributeMachineType, // in WORD // since 21H2
    PsAttributeComponentFilter,
    PsAttributeEnableOptionalXStateFeatures, // since WIN11
    PsAttributeMax
} PS_ATTRIBUTE_NUM;

// https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntpsapi.h
typedef enum _PS_PROTECTED_TYPE
{
    PsProtectedTypeNone,
    PsProtectedTypeProtectedLight,
    PsProtectedTypeProtected,
    PsProtectedTypeMax
} PS_PROTECTED_TYPE;

// https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntpsapi.h
typedef enum _PS_PROTECTED_SIGNER
{
    PsProtectedSignerNone,
    PsProtectedSignerAuthenticode,
    PsProtectedSignerCodeGen,
    PsProtectedSignerAntimalware,
    PsProtectedSignerLsa,
    PsProtectedSignerWindows,
    PsProtectedSignerWinTcb,
    PsProtectedSignerWinSystem,
    PsProtectedSignerApp,
    PsProtectedSignerMax
} PS_PROTECTED_SIGNER;

// https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntpsapi.h
#define PS_ATTRIBUTE_NUMBER_MASK 0x0000ffff
#define PS_ATTRIBUTE_THREAD 0x00010000 // may be used with thread creation
#define PS_ATTRIBUTE_INPUT 0x00020000 // input only
#define PS_ATTRIBUTE_ADDITIVE 0x00040000 // "accumulated" e.g. bitmasks, counters, etc.

// https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntpsapi.h
#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED 0x00000001 // NtCreateUserProcess & NtCreateThreadEx
#define THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH 0x00000002 // NtCreateThreadEx only
#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER 0x00000004 // NtCreateThreadEx only
#define THREAD_CREATE_FLAGS_LOADER_WORKER 0x00000010 // NtCreateThreadEx only
#define THREAD_CREATE_FLAGS_SKIP_LOADER_INIT 0x00000020 // NtCreateThreadEx only
#define THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE 0x00000040 // NtCreateThreadEx only
#define THREAD_CREATE_FLAGS_INITIAL_THREAD 0x00000080 // ?

// https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntpsapi.h
#define PROCESS_CREATE_FLAGS_BREAKAWAY 0x00000001 // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_NO_DEBUG_INHERIT 0x00000002 // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_INHERIT_HANDLES 0x00000004 // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_OVERRIDE_ADDRESS_SPACE 0x00000008 // NtCreateProcessEx only
#define PROCESS_CREATE_FLAGS_LARGE_PAGES 0x00000010 // NtCreateProcessEx only, requires SeLockMemory
#define PROCESS_CREATE_FLAGS_LARGE_PAGE_SYSTEM_DLL 0x00000020 // NtCreateProcessEx only, requires SeLockMemory
#define PROCESS_CREATE_FLAGS_PROTECTED_PROCESS 0x00000040 // NtCreateUserProcess only
#define PROCESS_CREATE_FLAGS_CREATE_SESSION 0x00000080 // NtCreateProcessEx & NtCreateUserProcess, requires SeLoadDriver
#define PROCESS_CREATE_FLAGS_INHERIT_FROM_PARENT 0x00000100 // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_SUSPENDED 0x00000200 // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_FORCE_BREAKAWAY 0x00000400 // NtCreateProcessEx & NtCreateUserProcess, requires SeTcb
#define PROCESS_CREATE_FLAGS_MINIMAL_PROCESS 0x00000800 // NtCreateProcessEx only
#define PROCESS_CREATE_FLAGS_RELEASE_SECTION 0x00001000 // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_CLONE_MINIMAL 0x00002000 // NtCreateProcessEx only
#define PROCESS_CREATE_FLAGS_CLONE_MINIMAL_REDUCED_COMMIT 0x00004000 //
#define PROCESS_CREATE_FLAGS_AUXILIARY_PROCESS 0x00008000 // NtCreateProcessEx & NtCreateUserProcess, requires SeTcb
#define PROCESS_CREATE_FLAGS_CREATE_STORE 0x00020000 // NtCreateProcessEx & NtCreateUserProcess
#define PROCESS_CREATE_FLAGS_USE_PROTECTED_ENVIRONMENT 0x00040000 // NtCreateProcessEx & NtCreateUserProcess

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

#define OBJ_INHERIT                             0x00000002L
#define OBJ_PERMANENT                           0x00000010L
#define OBJ_EXCLUSIVE                           0x00000020L
#define OBJ_CASE_INSENSITIVE                    0x00000040L
#define OBJ_OPENIF                              0x00000080L
#define OBJ_OPENLINK                            0x00000100L
#define OBJ_KERNEL_HANDLE                       0x00000200L
#define OBJ_FORCE_ACCESS_CHECK                  0x00000400L
#define OBJ_VALID_ATTRIBUTES                    0x000007F2L

typedef struct _OBJECT_ATTRIBUTES
{
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;        // Points to type SECURITY_DESCRIPTOR
    PVOID SecurityQualityOfService;  // Points to type SECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

// https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntobapi.h
typedef struct _OBJECT_TYPES_INFORMATION
{
    ULONG NumberOfTypes;
} OBJECT_TYPES_INFORMATION, * POBJECT_TYPES_INFORMATION;

// https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntobapi.h
typedef struct _OBJECT_TYPE_INFORMATION
{
    UNICODE_STRING TypeName;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG TotalPagedPoolUsage;
    ULONG TotalNonPagedPoolUsage;
    ULONG TotalNamePoolUsage;
    ULONG TotalHandleTableUsage;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    ULONG HighWaterPagedPoolUsage;
    ULONG HighWaterNonPagedPoolUsage;
    ULONG HighWaterNamePoolUsage;
    ULONG HighWaterHandleTableUsage;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccessMask;
    BOOLEAN SecurityRequired;
    BOOLEAN MaintainHandleCount;
    UCHAR TypeIndex; // since WINBLUE
    CHAR ReservedByte;
    ULONG PoolType;
    ULONG DefaultPagedPoolCharge;
    ULONG DefaultNonPagedPoolCharge;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

// https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntexapi.h
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

// https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntexapi.h
typedef struct _SYSTEM_HANDLE_INFORMATION
{
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

// https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntobapi.h
typedef struct _OBJECT_NAME_INFORMATION
{
    UNICODE_STRING Name;
} OBJECT_NAME_INFORMATION, * POBJECT_NAME_INFORMATION;

// https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntioapi.h
typedef struct _IO_STATUS_BLOCK
{
    union
    {
        NTSTATUS Status;
        PVOID Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_file_full_ea_information
typedef struct _FILE_FULL_EA_INFORMATION {
    ULONG NextEntryOffset;
    UCHAR Flags;
    UCHAR EaNameLength;
    USHORT EaValueLength;
    CHAR EaName[1];
} FILE_FULL_EA_INFORMATION, * PFILE_FULL_EA_INFORMATION;

// https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntpsapi.h
typedef struct _PS_CREATE_INFO
{
    SIZE_T Size;
    PS_CREATE_STATE State;
    union
    {
        // PsCreateInitialState
        struct
        {
            union
            {
                ULONG InitFlags;
                struct
                {
                    UCHAR WriteOutputOnExit : 1;
                    UCHAR DetectManifest : 1;
                    UCHAR IFEOSkipDebugger : 1;
                    UCHAR IFEODoNotPropagateKeyState : 1;
                    UCHAR SpareBits1 : 4;
                    UCHAR SpareBits2 : 8;
                    USHORT ProhibitedImageCharacteristics : 16;
                };
            };
            ACCESS_MASK AdditionalFileAccess;
        } InitState;

        // PsCreateFailOnSectionCreate
        struct
        {
            HANDLE FileHandle;
        } FailSection;

        // PsCreateFailExeFormat
        struct
        {
            USHORT DllCharacteristics;
        } ExeFormat;

        // PsCreateFailExeName
        struct
        {
            HANDLE IFEOKey;
        } ExeName;

        // PsCreateSuccess
        struct
        {
            union
            {
                ULONG OutputFlags;
                struct
                {
                    UCHAR ProtectedProcess : 1;
                    UCHAR AddressSpaceOverride : 1;
                    UCHAR DevOverrideEnabled : 1; // from Image File Execution Options
                    UCHAR ManifestDetected : 1;
                    UCHAR ProtectedProcessLight : 1;
                    UCHAR SpareBits1 : 3;
                    UCHAR SpareBits2 : 8;
                    USHORT SpareBits3 : 16;
                };
            };
            HANDLE FileHandle;
            HANDLE SectionHandle;
            ULONGLONG UserProcessParametersNative;
            ULONG UserProcessParametersWow64;
            ULONG CurrentParameterFlags;
            ULONGLONG PebAddressNative;
            ULONG PebAddressWow64;
            ULONGLONG ManifestAddress;
            ULONG ManifestSize;
        } SuccessState;
    };
} PS_CREATE_INFO, * PPS_CREATE_INFO;

// https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntpsapi.h
typedef struct _PS_STD_HANDLE_INFO
{
    union
    {
        ULONG Flags;
        struct
        {
            ULONG StdHandleState : 2; // PS_STD_HANDLE_STATE
            ULONG PseudoHandleMask : 3; // PS_STD_*
        };
    };
    ULONG StdHandleSubsystemType;
} PS_STD_HANDLE_INFO, * PPS_STD_HANDLE_INFO;

// https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntpsapi.h
typedef struct _PS_ATTRIBUTE
{
    ULONG_PTR Attribute;
    SIZE_T Size;
    union
    {
        ULONG_PTR Value;
        PVOID ValuePtr;
    };
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

// https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntpsapi.h
typedef struct _PS_ATTRIBUTE_LIST
{
    SIZE_T TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;

// https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntpsapi.h
typedef struct _PS_PROTECTION
{
    union
    {
        UCHAR Level;
        struct
        {
            UCHAR Type : 3;
            UCHAR Audit : 1;
            UCHAR Signer : 4;
        };
    };
} PS_PROTECTION, * PPS_PROTECTION;

// https://github.com/winsiderss/systeminformer/blob/master/phnt/include/phnt_ntdef.h
typedef struct _CLIENT_ID
{
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

// https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntmmapi.h
typedef struct _SECTION_IMAGE_INFORMATION
{
    PVOID TransferAddress;
    ULONG ZeroBits;
    SIZE_T MaximumStackSize;
    SIZE_T CommittedStackSize;
    ULONG SubSystemType;
    union
    {
        struct
        {
            USHORT SubSystemMinorVersion;
            USHORT SubSystemMajorVersion;
        };
        ULONG SubSystemVersion;
    };
    union
    {
        struct
        {
            USHORT MajorOperatingSystemVersion;
            USHORT MinorOperatingSystemVersion;
        };
        ULONG OperatingSystemVersion;
    };
    USHORT ImageCharacteristics;
    USHORT DllCharacteristics;
    USHORT Machine;
    BOOLEAN ImageContainsCode;
    union
    {
        UCHAR ImageFlags;
        struct
        {
            UCHAR ComPlusNativeReady : 1;
            UCHAR ComPlusILOnly : 1;
            UCHAR ImageDynamicallyRelocated : 1;
            UCHAR ImageMappedFlat : 1;
            UCHAR BaseBelow4gb : 1;
            UCHAR ComPlusPrefer32bit : 1;
            UCHAR Reserved : 2;
        };
    };
    ULONG LoaderFlags;
    ULONG ImageFileSize;
    ULONG CheckSum;
} SECTION_IMAGE_INFORMATION, * PSECTION_IMAGE_INFORMATION;

// https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntrtl.h
typedef struct _RTL_USER_PROCESS_INFORMATION
{
    ULONG Length;
    HANDLE ProcessHandle;
    HANDLE ThreadHandle;
    CLIENT_ID ClientId;
    SECTION_IMAGE_INFORMATION ImageInformation;

} RTL_USER_PROCESS_INFORMATION, * PRTL_USER_PROCESS_INFORMATION;

typedef struct _STRING
{
    USHORT Length;
    USHORT MaximumLength;
    _Field_size_bytes_part_opt_(MaximumLength, Length) PCHAR Buffer;
} STRING, * PSTRING, ANSI_STRING, * PANSI_STRING, OEM_STRING, * POEM_STRING;

typedef struct _CURDIR
{
    UNICODE_STRING DosPath;
    HANDLE Handle;
} CURDIR, * PCURDIR;

typedef struct _RTL_DRIVE_LETTER_CURDIR
{
    USHORT Flags;
    USHORT Length;
    ULONG TimeStamp;
    STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;

#define RTL_MAX_DRIVE_LETTERS 32

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
    ULONG MaximumLength;
    ULONG Length;

    ULONG Flags;
    ULONG DebugFlags;

    HANDLE ConsoleHandle;
    ULONG ConsoleFlags;
    HANDLE StandardInput;
    HANDLE StandardOutput;
    HANDLE StandardError;

    CURDIR CurrentDirectory;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    PVOID Environment;

    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;

    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING WindowTitle;
    UNICODE_STRING DesktopInfo;
    UNICODE_STRING ShellInfo;
    UNICODE_STRING RuntimeData;
    RTL_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];

    ULONG_PTR EnvironmentSize;
    ULONG_PTR EnvironmentVersion;

    PVOID PackageDependencyData;
    ULONG ProcessGroupId;
    ULONG LoaderThreads;

    UNICODE_STRING RedirectionDllName; // REDSTONE4
    UNICODE_STRING HeapPartitionName; // 19H1
    ULONG_PTR DefaultThreadpoolCpuSetMasks;
    ULONG DefaultThreadpoolCpuSetMaskCount;
    ULONG DefaultThreadpoolThreadMaximum;
    ULONG HeapMemoryTypeMask; // WIN11
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

// https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntrtl.h
typedef struct _RTLP_CURDIR_REF
{
    LONG ReferenceCount;
    HANDLE DirectoryHandle;
} RTLP_CURDIR_REF, * PRTLP_CURDIR_REF;

// https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntrtl.h
typedef struct _RTL_RELATIVE_NAME_U
{
    UNICODE_STRING RelativeName;
    HANDLE ContainingDirectory;
    PRTLP_CURDIR_REF CurDirRef;
} RTL_RELATIVE_NAME_U, * PRTL_RELATIVE_NAME_U;

NTSYSAPI
ULONG
NTAPI
RtlNtStatusToDosError(
    IN      NTSTATUS            Status
);

NTSYSAPI
VOID
NTAPI
RtlInitUnicodeString(
    OUT     PUNICODE_STRING     DestinationString,
    IN      PCWSTR              SourceString OPTIONAL
);

NTSYSAPI
NTSTATUS
NTAPI
NtQueryObject(
    IN      HANDLE              ObjectHandle,
    IN      OBJECT_INFORMATION_CLASS ObjectInformationClass,
    OUT     PVOID               ObjectInformation,
    IN      ULONG               Length,
    OUT     PULONG              ResultLength OPTIONAL
);

NTSYSAPI
NTSTATUS
NTAPI
NtQuerySystemInformation(
    IN      SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT     PVOID               SystemInformation,
    IN      ULONG               SystemInformationLength,
    OUT     PULONG              ReturnLength
);

NTSYSAPI
NTSTATUS
NTAPI
NtImpersonateThread(
    IN      HANDLE              ThreadHandle,
    IN      HANDLE              ThreadToImpersonate,
    IN      PSECURITY_QUALITY_OF_SERVICE SecurityQualityOfService
);

NTSYSAPI
NTSTATUS
NTAPI
NtMapViewOfSection(
    IN      HANDLE              SectionHandle,
    IN      HANDLE              ProcessHandle,
    IN OUT  PVOID*              BaseAddress,
    IN      ULONG_PTR           ZeroBits,
    IN      SIZE_T              CommitSize,
    IN OUT  PLARGE_INTEGER      SectionOffset OPTIONAL,
    IN OUT  PSIZE_T             ViewSize,
    IN      SECTION_INHERIT     InheritDisposition,
    IN      ULONG               AllocationType,
    IN      ULONG               Protect
);

NTSYSAPI
NTSTATUS
NTAPI
NtUnmapViewOfSection(
    IN      HANDLE              ProcessHandle,
    IN      PVOID               BaseAddress
);

NTSYSAPI
NTSTATUS
NTAPI
NtCreateSection(
    OUT     PHANDLE             SectionHandle,
    IN      ACCESS_MASK         DesiredAccess,
    IN      POBJECT_ATTRIBUTES  ObjectAttributes OPTIONAL,
    IN      PLARGE_INTEGER      MaximumSize OPTIONAL,
    IN      ULONG               SectionPageProtection,
    IN      ULONG               AllocationAttributes,
    IN      HANDLE              FileHandle OPTIONAL
);

NTSYSAPI
NTSTATUS
NTAPI
NtCreateTransaction(
    OUT     PHANDLE             TransactionHandle,
    IN      ACCESS_MASK         DesiredAccess,
    IN      POBJECT_ATTRIBUTES  ObjectAttributes OPTIONAL,
    IN      LPGUID              Uow OPTIONAL,
    IN      HANDLE              TmHandle OPTIONAL,
    IN      ULONG               CreateOptions OPTIONAL,
    IN      ULONG               IsolationLevel OPTIONAL,
    IN      ULONG               IsolationFlags OPTIONAL,
    IN      PLARGE_INTEGER      Timeout OPTIONAL,
    IN      PUNICODE_STRING     Description OPTIONAL
);

NTSYSAPI
PIMAGE_NT_HEADERS
NTAPI
RtlImageNtHeader(
    IN      PVOID               ModuleAddress
);

NTSYSAPI
NTSTATUS
NTAPI
NtGetCachedSigningLevel(
    IN      HANDLE              File,
    OUT     PULONG              Flags,
    OUT     PSE_SIGNING_LEVEL   SigningLevel,
    OUT     PUCHAR              Thumbprint OPTIONAL,
    IN OUT  PULONG              ThumbprintSize OPTIONAL,
    OUT     PULONG              ThumbprintAlgorithm OPTIONAL
);

NTSYSAPI
NTSTATUS
NTAPI
NtSetCachedSigningLevel(
    IN      ULONG               Flags,
    IN      SE_SIGNING_LEVEL    InputSigningLevel,
    IN      PHANDLE             SourceFiles,
    IN      ULONG               SourceFileCount,
    IN      HANDLE              TargetFile OPTIONAL
);

NTSYSAPI
NTSTATUS
NTAPI
NtSetEaFile(
    IN      HANDLE              FileHandle,
    OUT     PIO_STATUS_BLOCK    IoStatusBlock,
    IN      PVOID               EaBuffer,
    IN      ULONG               EaBufferSize
);

NTSYSAPI
NTSTATUS
NTAPI
NtCreateUserProcess(
    OUT     PHANDLE             ProcessHandle,
    OUT     PHANDLE             ThreadHandle,
    IN      ACCESS_MASK         ProcessDesiredAccess,
    IN      ACCESS_MASK         ThreadDesiredAccess,
    IN      POBJECT_ATTRIBUTES  ProcessObjectAttributes OPTIONAL,
    IN      POBJECT_ATTRIBUTES  ThreadObjectAttributes OPTIONAL,
    IN      ULONG               ProcessFlags,
    IN      ULONG               ThreadFlags,
    IN      PVOID               ProcessParameters OPTIONAL,
    IN OUT  PPS_CREATE_INFO     CreateInfo,
    IN      PPS_ATTRIBUTE_LIST  AttributeList OPTIONAL
);

NTSYSAPI
NTSTATUS
NTAPI
NtResumeThread(
    IN      HANDLE              ThreadHandle,
    OUT     PULONG              PreviousSuspendCount OPTIONAL
);

NTSYSAPI
BOOLEAN
NTAPI
RtlDosPathNameToNtPathName_U(
    IN      PCWSTR              DosFileName,
    OUT     PUNICODE_STRING     NtFileName,
    OUT     PWSTR*              FilePart OPTIONAL,
    OUT     PRTL_RELATIVE_NAME_U RelativeName OPTIONAL
);

NTSYSAPI
NTSTATUS
NTAPI
RtlCreateProcessParametersEx(
    OUT     PRTL_USER_PROCESS_PARAMETERS* pProcessParameters,
    IN      PUNICODE_STRING     ImagePathName,
    IN      PUNICODE_STRING     DllPath OPTIONAL,
    IN      PUNICODE_STRING     CurrentDirectory OPTIONAL,
    IN      PUNICODE_STRING     CommandLine OPTIONAL,
    IN      PVOID               Environment OPTIONAL,
    IN      PUNICODE_STRING     WindowTitle OPTIONAL,
    IN      PUNICODE_STRING     DesktopInfo OPTIONAL,
    IN      PUNICODE_STRING     ShellInfo OPTIONAL,
    IN      PUNICODE_STRING     RuntimeData OPTIONAL,
    IN      ULONG               Flags
);

NTSYSAPI
NTSTATUS
NTAPI
RtlDestroyProcessParameters(
    IN      PRTL_USER_PROCESS_PARAMETERS ProcessParameters
);

NTSYSAPI
PRTL_USER_PROCESS_PARAMETERS
NTAPI
RtlNormalizeProcessParams(
    IN OUT  PRTL_USER_PROCESS_PARAMETERS ProcessParameters
);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // __NTDLL_H__