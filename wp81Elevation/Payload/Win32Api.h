#pragma once
#include "windows.h"

// See https://github.com/tandasat/SecRuntimeSample/blob/master/SecRuntimeSampleNative/Win32Api.h

#define LOGON32_LOGON_INTERACTIVE       2
#define LOGON32_LOGON_NETWORK           3
#define LOGON32_LOGON_BATCH             4
#define LOGON32_LOGON_SERVICE           5
#define LOGON32_LOGON_UNLOCK            7
#define LOGON32_LOGON_NETWORK_CLEARTEXT 8
#define LOGON32_LOGON_NEW_CREDENTIALS   9

#define LOGON32_PROVIDER_DEFAULT    0
#define LOGON32_PROVIDER_WINNT35    1
#define LOGON32_PROVIDER_WINNT40    2
#define LOGON32_PROVIDER_WINNT50    3
#define LOGON32_PROVIDER_VIRTUAL    4

#define SEC_ENTRY __stdcall

//
// Service State -- for CurrentState
//
#define SERVICE_STOPPED                        0x00000001
#define SERVICE_START_PENDING                  0x00000002
#define SERVICE_STOP_PENDING                   0x00000003
#define SERVICE_RUNNING                        0x00000004
#define SERVICE_CONTINUE_PENDING               0x00000005
#define SERVICE_PAUSE_PENDING                  0x00000006
#define SERVICE_PAUSED                         0x00000007

//
// Controls Accepted  (Bit Mask)
//
#define SERVICE_ACCEPT_STOP                    0x00000001
#define SERVICE_ACCEPT_PAUSE_CONTINUE          0x00000002
#define SERVICE_ACCEPT_SHUTDOWN                0x00000004
#define SERVICE_ACCEPT_PARAMCHANGE             0x00000008
#define SERVICE_ACCEPT_NETBINDCHANGE           0x00000010
#define SERVICE_ACCEPT_HARDWAREPROFILECHANGE   0x00000020
#define SERVICE_ACCEPT_POWEREVENT              0x00000040
#define SERVICE_ACCEPT_SESSIONCHANGE           0x00000080
#define SERVICE_ACCEPT_PRESHUTDOWN             0x00000100
#define SERVICE_ACCEPT_TIMECHANGE              0x00000200
#define SERVICE_ACCEPT_TRIGGEREVENT            0x00000400

//
// Controls
//
#define SERVICE_CONTROL_STOP                   0x00000001
#define SERVICE_CONTROL_PAUSE                  0x00000002
#define SERVICE_CONTROL_CONTINUE               0x00000003
#define SERVICE_CONTROL_INTERROGATE            0x00000004
#define SERVICE_CONTROL_SHUTDOWN               0x00000005
#define SERVICE_CONTROL_PARAMCHANGE            0x00000006
#define SERVICE_CONTROL_NETBINDADD             0x00000007
#define SERVICE_CONTROL_NETBINDREMOVE          0x00000008
#define SERVICE_CONTROL_NETBINDENABLE          0x00000009
#define SERVICE_CONTROL_NETBINDDISABLE         0x0000000A
#define SERVICE_CONTROL_DEVICEEVENT            0x0000000B
#define SERVICE_CONTROL_HARDWAREPROFILECHANGE  0x0000000C
#define SERVICE_CONTROL_POWEREVENT             0x0000000D
#define SERVICE_CONTROL_SESSIONCHANGE          0x0000000E
#define SERVICE_CONTROL_PRESHUTDOWN            0x0000000F
#define SERVICE_CONTROL_TIMECHANGE             0x00000010
#define SERVICE_CONTROL_TRIGGEREVENT           0x00000020

#define TH32CS_SNAPHEAPLIST 0x00000001
#define TH32CS_SNAPPROCESS  0x00000002
#define TH32CS_SNAPTHREAD   0x00000004
#define TH32CS_SNAPMODULE   0x00000008
#define TH32CS_SNAPMODULE32 0x00000010
#define TH32CS_SNAPALL      (TH32CS_SNAPHEAPLIST | TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD | TH32CS_SNAPMODULE)
#define TH32CS_INHERIT      0x80000000

#define HANDLE_FLAG_INHERIT 0x00000001
#define HANDLE_FLAG_PROTECT_FROM_CLOSE 0x00000002

#define STARTF_USESTDHANDLES 0x00000100

#define STATUS_SUCCESS  ((NTSTATUS)0x00000000L)

DECLARE_HANDLE(SERVICE_STATUS_HANDLE);

typedef enum  {
  NameUnknown = 0,
  NameFullyQualifiedDN = 1,
  NameSamCompatible = 2,
  NameDisplay = 3,
  NameUniqueId = 6,
  NameCanonical = 7,
  NameUserPrincipal = 8,
  NameCanonicalEx = 9,
  NameServicePrincipal = 10,
  NameDnsDomain = 12,
  NameGivenName = 13,
  NameSurname = 14
} EXTENDED_NAME_FORMAT, *PEXTENDED_NAME_FORMAT;

typedef DWORD (WINAPI *LPHANDLER_FUNCTION_EX)(
    DWORD    dwControl,
    DWORD    dwEventType,
    LPVOID   lpEventData,
    LPVOID   lpContext
    );
	
typedef struct _SERVICE_STATUS {
    DWORD   dwServiceType;
    DWORD   dwCurrentState;
    DWORD   dwControlsAccepted;
    DWORD   dwWin32ExitCode;
    DWORD   dwServiceSpecificExitCode;
    DWORD   dwCheckPoint;
    DWORD   dwWaitHint;
} SERVICE_STATUS, *LPSERVICE_STATUS;	

typedef VOID (WINAPI *LPSERVICE_MAIN_FUNCTIONW)(
    DWORD   dwNumServicesArgs,
    LPWSTR  *lpServiceArgVectors
    );

typedef struct _SERVICE_TABLE_ENTRYW {
    LPWSTR                      lpServiceName;
    LPSERVICE_MAIN_FUNCTIONW    lpServiceProc;
}SERVICE_TABLE_ENTRYW, *LPSERVICE_TABLE_ENTRYW;

typedef struct _STARTUPINFOW {
    DWORD cb;
    LPWSTR lpReserved;
    LPWSTR lpDesktop;
    LPWSTR lpTitle;
    DWORD dwX;
    DWORD dwY;
    DWORD dwXSize;
    DWORD dwYSize;
    DWORD dwXCountChars;
    DWORD dwYCountChars;
    DWORD dwFillAttribute;
    DWORD dwFlags;
    WORD wShowWindow;
    WORD cbReserved2;
    LPBYTE lpReserved2;
    HANDLE hStdInput;
    HANDLE hStdOutput;
    HANDLE hStdError;
  } STARTUPINFOW, *LPSTARTUPINFOW;
  
typedef struct _PROCESS_INFORMATION {
    HANDLE hProcess;
    HANDLE hThread;
    DWORD dwProcessId;
    DWORD dwThreadId;
  } PROCESS_INFORMATION, *PPROCESS_INFORMATION, *LPPROCESS_INFORMATION;
  
typedef struct tagPROCESSENTRY32W
{
    DWORD   dwSize;
    DWORD   cntUsage;
    DWORD   th32ProcessID;          // this process
    ULONG_PTR th32DefaultHeapID;
    DWORD   th32ModuleID;           // associated exe
    DWORD   cntThreads;
    DWORD   th32ParentProcessID;    // this process's parent process
    LONG    pcPriClassBase;         // Base priority of process's threads
    DWORD   dwFlags;
    WCHAR   szExeFile[MAX_PATH];    // Path
} PROCESSENTRY32W;
typedef PROCESSENTRY32W *  PPROCESSENTRY32W;
typedef PROCESSENTRY32W *  LPPROCESSENTRY32W;  

typedef _Return_type_success_(return >= 0) LONG NTSTATUS;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    [size_is(MaximumLength / 2), length_is((Length) / 2) ] USHORT * Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;        // Points to type SECURITY_DESCRIPTOR
    PVOID SecurityQualityOfService;  // Points to type SECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES;
typedef OBJECT_ATTRIBUTES *POBJECT_ATTRIBUTES;

typedef struct _SID_BUILTIN
{
	UCHAR Revision;
	UCHAR SubAuthorityCount;
	SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
	ULONG SubAuthority[2];
} SID_BUILTIN, *PSID_BUILTIN;

typedef struct _SID_INTEGRITY
{
	UCHAR Revision;
	UCHAR SubAuthorityCount;
	SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
	ULONG SubAuthority[1];

} SID_INTEGRITY, *PSID_INTEGRITY;

typedef struct _BLUETOOTH_FIND_RADIO_PARAMS {
	DWORD   dwSize;             //  IN  sizeof this structure
} BLUETOOTH_FIND_RADIO_PARAMS;

typedef HANDLE      HBLUETOOTH_RADIO_FIND;

#define BLUETOOTH_MAX_SERVICE_NAME_SIZE     (256)
#define BLUETOOTH_DEVICE_NAME_SIZE          (256)

typedef ULONGLONG BTH_ADDR;

typedef struct _BLUETOOTH_ADDRESS {
	union {
		BTH_ADDR ullLong;       //  easier to compare again BLUETOOTH_NULL_ADDRESS
		BYTE    rgBytes[6];   //  easier to format when broken out
	};

} BLUETOOTH_ADDRESS_STRUCT;

#define BLUETOOTH_ADDRESS BLUETOOTH_ADDRESS_STRUCT

typedef struct _BLUETOOTH_LOCAL_SERVICE_INFO {
	BOOL                Enabled;                        //  If TRUE, the enable the services

	BLUETOOTH_ADDRESS   btAddr;                         //  If service is to be advertised for a particular remote device

	WCHAR szName[BLUETOOTH_MAX_SERVICE_NAME_SIZE];    //  SDP Service Name to be advertised.
	WCHAR szDeviceString[BLUETOOTH_DEVICE_NAME_SIZE]; //  Local device name (if any) like COM4 or LPT1

} BLUETOOTH_LOCAL_SERVICE_INFO_STRUCT;

#define BLUETOOTH_LOCAL_SERVICE_INFO BLUETOOTH_LOCAL_SERVICE_INFO_STRUCT

typedef BLUETOOTH_LOCAL_SERVICE_INFO * PBLUETOOTH_LOCAL_SERVICE_INFO;

typedef int WINBOOL, *PWINBOOL, *LPWINBOOL;

#define CR_SUCCESS                  (0x00000000)
#define CMAPI     DECLSPEC_IMPORT
#define CM_GETIDLIST_FILTER_PRESENT             (0x00000100)
#define CM_LOCATE_DEVNODE_NORMAL       0x00000000
#define DEVPROP_TYPE_STRING 0x12
typedef _Return_type_success_(return == 0) DWORD        RETURN_TYPE;
typedef RETURN_TYPE  CONFIGRET;
typedef DWORD       DEVNODE, DEVINST;
typedef DEVNODE    *PDEVNODE, *PDEVINST;
typedef _Null_terminated_ WCHAR *DEVNODEID_W, *DEVINSTID_W;
typedef ULONG DEVPROPTYPE, *PDEVPROPTYPE;
typedef GUID DEVPROPGUID, *PDEVPROPGUID;
typedef ULONG DEVPROPID, *PDEVPROPID;
typedef struct _DEVPROPKEY {
    DEVPROPGUID fmtid;
    DEVPROPID pid;
} DEVPROPKEY, *PDEVPROPKEY;
#define DEFINE_DEVPROPKEY(name, l, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8, pid) EXTERN_C const DEVPROPKEY DECLSPEC_SELECTANY name = { { l, w1, w2, { b1, b2,  b3,  b4,  b5,  b6,  b7,  b8 } }, pid }
DEFINE_DEVPROPKEY(DEVPKEY_Device_DeviceDesc,             0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0, 2);     // DEVPROP_TYPE_STRING
DEFINE_DEVPROPKEY(DEVPKEY_Device_Driver,                 0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0, 11);    // DEVPROP_TYPE_STRING
DEFINE_DEVPROPKEY(DEVPKEY_Device_PDOName,                0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0, 16);    // DEVPROP_TYPE_STRING
DEFINE_DEVPROPKEY(DEVPKEY_Device_EnumeratorName,         0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0, 24);    // DEVPROP_TYPE_STRING
DEFINE_DEVPROPKEY(DEVPKEY_Device_Parent,                 0x4340a6c5, 0x93fa, 0x4706, 0x97, 0x2c, 0x7b, 0x64, 0x80, 0x08, 0xa5, 0xa7, 8);     // DEVPROP_TYPE_STRING

DECLARE_HANDLE(SC_HANDLE);
typedef enum _SC_ENUM_TYPE {
    SC_ENUM_PROCESS_INFO        = 0
} SC_ENUM_TYPE;
typedef struct _SERVICE_STATUS_PROCESS {
    DWORD   dwServiceType;
    DWORD   dwCurrentState;
    DWORD   dwControlsAccepted;
    DWORD   dwWin32ExitCode;
    DWORD   dwServiceSpecificExitCode;
    DWORD   dwCheckPoint;
    DWORD   dwWaitHint;
    DWORD   dwProcessId;
    DWORD   dwServiceFlags;
} SERVICE_STATUS_PROCESS, *LPSERVICE_STATUS_PROCESS;
typedef struct _ENUM_SERVICE_STATUS_PROCESSW {
    LPWSTR                    lpServiceName;
    LPWSTR                    lpDisplayName;
    SERVICE_STATUS_PROCESS    ServiceStatusProcess;
} ENUM_SERVICE_STATUS_PROCESSW, *LPENUM_SERVICE_STATUS_PROCESSW;
#define SC_MANAGER_CONNECT             0x0001
#define SC_MANAGER_CREATE_SERVICE      0x0002
#define SC_MANAGER_ENUMERATE_SERVICE   0x0004
#define SC_MANAGER_LOCK                0x0008
#define SC_MANAGER_QUERY_LOCK_STATUS   0x0010
#define SC_MANAGER_MODIFY_BOOT_CONFIG  0x0020
#define SC_MANAGER_ALL_ACCESS          (STANDARD_RIGHTS_REQUIRED      | \
                                        SC_MANAGER_CONNECT            | \
                                        SC_MANAGER_CREATE_SERVICE     | \
                                        SC_MANAGER_ENUMERATE_SERVICE  | \
                                        SC_MANAGER_LOCK               | \
                                        SC_MANAGER_QUERY_LOCK_STATUS  | \
                                        SC_MANAGER_MODIFY_BOOT_CONFIG)
#define SERVICE_ACTIVE                 0x00000001
#define SERVICE_INACTIVE               0x00000002
#define SERVICE_STATE_ALL              (SERVICE_ACTIVE   | \
                                        SERVICE_INACTIVE)
										
										//
// Service object specific access type
//
#define SERVICE_QUERY_CONFIG           0x0001
#define SERVICE_CHANGE_CONFIG          0x0002
#define SERVICE_QUERY_STATUS           0x0004
#define SERVICE_ENUMERATE_DEPENDENTS   0x0008
#define SERVICE_START                  0x0010
#define SERVICE_STOP                   0x0020
#define SERVICE_PAUSE_CONTINUE         0x0040
#define SERVICE_INTERROGATE            0x0080
#define SERVICE_USER_DEFINED_CONTROL   0x0100

#define SERVICE_ALL_ACCESS             (STANDARD_RIGHTS_REQUIRED     | \
                                        SERVICE_QUERY_CONFIG         | \
                                        SERVICE_CHANGE_CONFIG        | \
                                        SERVICE_QUERY_STATUS         | \
                                        SERVICE_ENUMERATE_DEPENDENTS | \
                                        SERVICE_START                | \
                                        SERVICE_STOP                 | \
                                        SERVICE_PAUSE_CONTINUE       | \
                                        SERVICE_INTERROGATE          | \
                                        SERVICE_USER_DEFINED_CONTROL)

extern "C" {
	WINBASEAPI HMODULE WINAPI LoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);
	WINBASEAPI HMODULE WINAPI GetModuleHandleW(LPCWSTR lpModuleName);
	WINBASEAPI HANDLE WINAPI FindFirstFileW(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData);
	WINBASEAPI BOOL WINAPI FindNextFileW(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData);
	WINBASEAPI BOOL WINAPI FindClose(HANDLE hFindFile);
	WINBASEAPI HANDLE WINAPI CreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
	WINBASEAPI BOOL WINAPI WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);
	WINBASEAPI BOOL WINAPI CloseHandle(HANDLE hObject);
	BOOL WINAPI GetTokenInformation(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, LPVOID TokenInformation, DWORD TokenInformationLength, PDWORD ReturnLength);
	WINBASEAPI BOOL WINAPI QueryFullProcessImageNameW(HANDLE hProcess, DWORD dwFlags, LPWSTR lpExeName, PDWORD lpdwSize);
	DWORD WINAPI GetProcessImageFileNameW(HANDLE hProcess, LPWSTR lpImageFileName, DWORD nSize);
	WINBASEAPI HANDLE WINAPI CreateEventW(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState, LPCWSTR lpName);
	WINBASEAPI DWORD WINAPI WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds);
	WINADVAPI BOOL WINAPI CreateProcessAsUserW(HANDLE hToken, LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
	WINBASEAPI BOOL WINAPI CreateProcessW(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
	WINBASEAPI HANDLE WINAPI OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
	BOOL WINAPI DuplicateTokenEx(HANDLE hExistingToken, DWORD dwDesiredAccess, LPSECURITY_ATTRIBUTES lpTokenAttributes, SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, TOKEN_TYPE TokenType, PHANDLE phNewToken);
	WINBASEAPI int WINAPI lstrcmpiW(LPCWSTR lpString1, LPCWSTR lpString2);
	WINBASEAPI int WINAPI lstrcmpA(LPCSTR lpString1, LPCSTR lpString2);
	BOOL WINAPI AdjustTokenPrivileges(HANDLE TokenHandle,BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength);
	BOOL WINAPI OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
	WINBASEAPI BOOL WINAPI GetExitCodeThread(HANDLE hThread, LPDWORD lpExitCode);
	WINBASEAPI BOOL WINAPI GetExitCodeProcess(HANDLE hProcess, LPDWORD lpExitCode);
	WINBASEAPI BOOL WINAPI AllocConsole(VOID);
	WINBASEAPI BOOL WINAPI FreeConsole(VOID);
	WINBASEAPI BOOL WINAPI WriteConsoleW(HANDLE hConsoleOutput,CONST VOID *lpBuffer,DWORD nNumberOfCharsToWrite,LPDWORD lpNumberOfCharsWritten,LPVOID lpReserved);
	WINBASEAPI HANDLE WINAPI GetStdHandle(DWORD nStdHandle);
	WINBASEAPI BOOL WINAPI CreatePipe(PHANDLE hReadPipe, PHANDLE hWritePipe, LPSECURITY_ATTRIBUTES lpPipeAttributes, DWORD nSize);
	WINBASEAPI BOOL WINAPI SetHandleInformation(HANDLE hObject, DWORD dwMask, DWORD dwFlags);
	WINBASEAPI BOOL WINAPI ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
	WINADVAPI BOOL WINAPI AllocateAndInitializeSid(PSID_IDENTIFIER_AUTHORITY pIdentifierAuthority, BYTE nSubAuthorityCount, DWORD nSubAuthority0, DWORD nSubAuthority1, DWORD nSubAuthority2, DWORD nSubAuthority3, DWORD nSubAuthority4, DWORD nSubAuthority5, DWORD nSubAuthority6, DWORD nSubAuthority7, PSID *pSid);
	WINADVAPI BOOL WINAPI AllocateLocallyUniqueId(PLUID Luid);
	WINADVAPI PVOID WINAPI FreeSid(PSID pSid);

	BOOL WINAPI LogonUserExExW(LPTSTR lpszUsername, LPTSTR lpszDomain, LPTSTR lpszPassword, DWORD dwLogonType, DWORD dwLogonProvider, PTOKEN_GROUPS pTokenGroups, PHANDLE phToken, PSID *ppLogonSid, PVOID *ppProfileBuffer, LPDWORD pdwProfileLength, PQUOTA_LIMITS pQuotaLimits);
	BOOL SEC_ENTRY GetUserNameExW(EXTENDED_NAME_FORMAT NameFormat, LPWSTR lpNameBuffer,PULONG nSize);
	
	HRESULT WINAPI OpenProcessTokenForQuery(HANDLE ProcessHandle, HANDLE *TokenHandle);
	
	BOOL WINAPI LookupAccountSidW(LPCWSTR lpSystemName, PSID lpSid, LPWSTR lpName, LPDWORD cchName, LPWSTR lpReferencedDomainName, LPDWORD cchReferencedDomainName, PSID_NAME_USE peUse);
	BOOL WINAPI LookupPrivilegeNameW(LPCWSTR lpSystemName, PLUID lpLuid, LPWSTR lpName, LPDWORD cchName);
	BOOL WINAPI LookupPrivilegeValueW(LPCWSTR lpSystemName, LPCWSTR lpName, PLUID lpLuid);
	
	SERVICE_STATUS_HANDLE WINAPI RegisterServiceCtrlHandlerExW(LPCWSTR lpServiceName, LPHANDLER_FUNCTION_EX lpHandlerProc, LPVOID lpContext);
	BOOL WINAPI SetServiceStatus(SERVICE_STATUS_HANDLE hServiceStatus, LPSERVICE_STATUS lpServiceStatus);
	WINADVAPI BOOL WINAPI StartServiceCtrlDispatcherW(SERVICE_TABLE_ENTRYW    *lpServiceStartTable);
	SC_HANDLE WINAPI OpenSCManagerW(LPCWSTR lpMachineName, LPCWSTR lpDatabaseName, DWORD dwDesiredAccess);
	WINADVAPI BOOL WINAPI CloseServiceHandle(SC_HANDLE hSCObject);
	WINADVAPI BOOL WINAPI EnumServicesStatusExW(SC_HANDLE hSCManager, SC_ENUM_TYPE InfoLevel, DWORD dwServiceType, DWORD dwServiceState, LPBYTE lpServices, DWORD cbBufSize, LPDWORD pcbBytesNeeded, LPDWORD lpServicesReturned, LPDWORD lpResumeHandle, LPCWSTR pszGroupName);
	WINADVAPI SC_HANDLE WINAPI OpenServiceW(SC_HANDLE hSCManager,LPCWSTR lpServiceName,DWORD dwDesiredAccess);
	WINADVAPI BOOL WINAPI ControlService(SC_HANDLE hService,DWORD dwControl,LPSERVICE_STATUS lpServiceStatus);

		
	DWORD WTSGetActiveConsoleSessionId();
	HANDLE WINAPI CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID);
	BOOL WINAPI Process32FirstW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe);
	BOOL WINAPI Process32NextW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe);
	WINBASEAPI HLOCAL WINAPI LocalAlloc(UINT uFlags, SIZE_T uBytes);
	WINBASEAPI HLOCAL WINAPI LocalFree(HLOCAL hMem);
	
	NTSTATUS ZwCreateToken(HANDLE TokenHandle,ACCESS_MASK DesiredAccess,POBJECT_ATTRIBUTES ObjectAttributes,TOKEN_TYPE TokenType,PLUID AuthenticationId,PLARGE_INTEGER ExpirationTime,PTOKEN_USER TokenUser,PTOKEN_GROUPS TokenGroups,PTOKEN_PRIVILEGES TokenPrivileges,PTOKEN_OWNER TokenOwner,PTOKEN_PRIMARY_GROUP TokenPrimaryGroup,PTOKEN_DEFAULT_DACL TokenDefaultDacl,PTOKEN_SOURCE  TokenSource);
	
	HBLUETOOTH_RADIO_FIND WINAPI BluetoothFindFirstRadio(const BLUETOOTH_FIND_RADIO_PARAMS * pbtfrp, HANDLE * phRadio);	
	DWORD WINAPI BluetoothSetLocalServiceInfo(HANDLE  hRadioIn, const GUID * pClassGuid, ULONG ulInstance, const BLUETOOTH_LOCAL_SERVICE_INFO * pServiceInfoIn);
	
	WINBASEAPI HANDLE WINAPI OpenFileMappingW(DWORD dwDesiredAccess, WINBOOL bInheritHandle, LPCWSTR lpName);
	WINBASEAPI HANDLE WINAPI CreateFileMappingW(HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCWSTR lpName);
	WINBASEAPI LPVOID WINAPI MapViewOfFile(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap);
	WINBASEAPI WINBOOL WINAPI UnmapViewOfFile(LPCVOID lpBaseAddress);
	WINBASEAPI WINBOOL WINAPI SetPriorityClass(HANDLE hProcess, DWORD dwPriorityClass);
	WINBASEAPI HANDLE WINAPI CreateThread (LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
	WINBASEAPI WINBOOL WINAPI SetThreadPriority (HANDLE hThread, int nPriority);
	
	WINBASEAPI BOOL WINAPI EnumDeviceDrivers(LPVOID *lpImageBase, DWORD cb, LPDWORD lpcbNeeded);
	WINBASEAPI DWORD WINAPI GetDeviceDriverBaseNameW(LPVOID ImageBase, LPWSTR lpBaseName, DWORD nSize);	
	
	NTSTATUS WINAPI NtOpenDirectoryObject(PHANDLE DirectoryHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
	NTSTATUS WINAPI NtQueryDirectoryObject(HANDLE DirectoryHandle, PVOID Buffer, ULONG Length, BOOLEAN ReturnSingleEntry, BOOLEAN RestartScan, PULONG Context, PULONG ReturnLength);
	void RtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString);
	
	CMAPI CONFIGRET WINAPI CM_Get_Device_ID_List_SizeW(PULONG pulLen, PCWSTR pszFilter, ULONG ulFlags);
	CMAPI CONFIGRET WINAPI CM_Get_Device_ID_ListW(PCWSTR pszFilter, PWCHAR Buffer, ULONG BufferLen, ULONG ulFlags);
	CMAPI CONFIGRET WINAPI CM_Locate_DevNodeW(PDEVINST pdnDevInst,  DEVINSTID_W pDeviceID, ULONG ulFlags);
	CMAPI CONFIGRET WINAPI CM_Get_DevNode_PropertyW(DEVINST dnDevInst, CONST DEVPROPKEY *PropertyKey, DEVPROPTYPE *PropertyType, PBYTE PropertyBuffer, PULONG PropertyBufferSize, ULONG ulFlags);
	
}

#define WIN32API_TOSTRING(x) #x

// Link exported function
#define WIN32API_INIT_PROC(Module, Name)  \
  Name(reinterpret_cast<decltype(&::Name)>( \
      ::GetProcAddress((Module), WIN32API_TOSTRING(Name))))

// Convenientmacro to declare function
#define WIN32API_DEFINE_PROC(Name) const decltype(&::Name) Name

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
    }
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#define DIRECTORY_QUERY                 (0x0001)
#define DIRECTORY_TRAVERSE              (0x0002)

typedef struct _OBJECT_DIRECTORY_INFORMATION {
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, *POBJECT_DIRECTORY_INFORMATION;

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L) // ntsubauth
#endif // STATUS_SUCCESS
#ifndef STATUS_MORE_ENTRIES
#define STATUS_MORE_ENTRIES              ((NTSTATUS)0x00000105L)
#endif // STATUS_MORE_ENTRIES
#ifndef STATUS_NO_MORE_ENTRIES
#define STATUS_NO_MORE_ENTRIES           ((NTSTATUS)0x8000001AL)
#endif // STATUS_NO_MORE_ENTRIES

class Win32Api {

private:
	// Returns a base address of KernelBase.dll
	static HMODULE GetKernelBase() {
		return GetBaseAddress(&::DisableThreadLibraryCalls);
	}

	// Returns a base address of the given address
	static HMODULE GetBaseAddress(const void *Address) {
		MEMORY_BASIC_INFORMATION mbi = {};
		if (!::VirtualQuery(Address, &mbi, sizeof(mbi))) {
			return nullptr;
		}
		const auto mz = *reinterpret_cast<WORD *>(mbi.AllocationBase);
		if (mz != IMAGE_DOS_SIGNATURE) {
			return nullptr;
		}
		return reinterpret_cast<HMODULE>(mbi.AllocationBase);
	}

public:
	const HMODULE m_Kernelbase;
	WIN32API_DEFINE_PROC(LoadLibraryExW);
	WIN32API_DEFINE_PROC(GetModuleHandleW);
	WIN32API_DEFINE_PROC(FindFirstFileW);
	WIN32API_DEFINE_PROC(FindNextFileW);
	WIN32API_DEFINE_PROC(FindClose);
	WIN32API_DEFINE_PROC(CreateFileW);
	WIN32API_DEFINE_PROC(WriteFile);
	WIN32API_DEFINE_PROC(CloseHandle);
	WIN32API_DEFINE_PROC(GetTokenInformation);
	WIN32API_DEFINE_PROC(QueryFullProcessImageNameW);
	WIN32API_DEFINE_PROC(GetProcessImageFileNameW);	
	WIN32API_DEFINE_PROC(CreateEventW);	
	WIN32API_DEFINE_PROC(WaitForSingleObject);	
	WIN32API_DEFINE_PROC(CreateProcessAsUserW);	
	WIN32API_DEFINE_PROC(CreateProcessW);	
	WIN32API_DEFINE_PROC(OpenProcess);	
	WIN32API_DEFINE_PROC(DuplicateTokenEx);
	WIN32API_DEFINE_PROC(lstrcmpiW);
	WIN32API_DEFINE_PROC(lstrcmpA);
	WIN32API_DEFINE_PROC(AdjustTokenPrivileges);
	WIN32API_DEFINE_PROC(OpenProcessToken);
	WIN32API_DEFINE_PROC(GetExitCodeThread);
	WIN32API_DEFINE_PROC(GetExitCodeProcess);
	WIN32API_DEFINE_PROC(AllocConsole);
	WIN32API_DEFINE_PROC(FreeConsole);
	WIN32API_DEFINE_PROC(WriteConsoleW);
	WIN32API_DEFINE_PROC(GetStdHandle);
	WIN32API_DEFINE_PROC(CreatePipe);
	WIN32API_DEFINE_PROC(SetHandleInformation);
	WIN32API_DEFINE_PROC(ReadFile);
	WIN32API_DEFINE_PROC(AllocateAndInitializeSid);
	WIN32API_DEFINE_PROC(AllocateLocallyUniqueId);
	WIN32API_DEFINE_PROC(FreeSid);
	WIN32API_DEFINE_PROC(OpenFileMappingW);
	WIN32API_DEFINE_PROC(CreateFileMappingW);
	WIN32API_DEFINE_PROC(MapViewOfFile);
	WIN32API_DEFINE_PROC(UnmapViewOfFile);
	WIN32API_DEFINE_PROC(SetPriorityClass);	
	WIN32API_DEFINE_PROC(CreateThread);	
	WIN32API_DEFINE_PROC(SetThreadPriority);	
	WIN32API_DEFINE_PROC(EnumDeviceDrivers);
	WIN32API_DEFINE_PROC(GetDeviceDriverBaseNameW);	
	const HMODULE m_Sspicli;
	WIN32API_DEFINE_PROC(LogonUserExExW);
	WIN32API_DEFINE_PROC(GetUserNameExW);
	const HMODULE m_SecRuntime;
	WIN32API_DEFINE_PROC(OpenProcessTokenForQuery);
	const HMODULE m_Advapi32;
	WIN32API_DEFINE_PROC(LookupAccountSidW);	
	WIN32API_DEFINE_PROC(LookupPrivilegeNameW);
	WIN32API_DEFINE_PROC(LookupPrivilegeValueW);
	const HMODULE m_Sechost;
	WIN32API_DEFINE_PROC(RegisterServiceCtrlHandlerExW);	
	WIN32API_DEFINE_PROC(SetServiceStatus);
	WIN32API_DEFINE_PROC(StartServiceCtrlDispatcherW);
	WIN32API_DEFINE_PROC(OpenSCManagerW);
	WIN32API_DEFINE_PROC(CloseServiceHandle);
	WIN32API_DEFINE_PROC(EnumServicesStatusExW);
	WIN32API_DEFINE_PROC(OpenServiceW);
	WIN32API_DEFINE_PROC(ControlService);
	const HMODULE m_Kernel32legacy;
	WIN32API_DEFINE_PROC(WTSGetActiveConsoleSessionId);
	WIN32API_DEFINE_PROC(CreateToolhelp32Snapshot);
	WIN32API_DEFINE_PROC(Process32FirstW);
	WIN32API_DEFINE_PROC(Process32NextW);
	WIN32API_DEFINE_PROC(LocalAlloc);
	WIN32API_DEFINE_PROC(LocalFree);
	const HMODULE m_Ntdll;
	WIN32API_DEFINE_PROC(ZwCreateToken);
	WIN32API_DEFINE_PROC(NtOpenDirectoryObject);
	WIN32API_DEFINE_PROC(NtQueryDirectoryObject);
	WIN32API_DEFINE_PROC(RtlInitUnicodeString);
	const HMODULE m_BluetoothApis;
	WIN32API_DEFINE_PROC(BluetoothFindFirstRadio);	
	WIN32API_DEFINE_PROC(BluetoothSetLocalServiceInfo);
	const HMODULE m_CfgMgr32;
	WIN32API_DEFINE_PROC(CM_Get_Device_ID_List_SizeW);	
	WIN32API_DEFINE_PROC(CM_Get_Device_ID_ListW);	
	WIN32API_DEFINE_PROC(CM_Locate_DevNodeW);
	WIN32API_DEFINE_PROC(CM_Get_DevNode_PropertyW);
	

	Win32Api()
		: m_Kernelbase(GetKernelBase()),
		WIN32API_INIT_PROC(m_Kernelbase, LoadLibraryExW),
		WIN32API_INIT_PROC(m_Kernelbase, GetModuleHandleW),
		WIN32API_INIT_PROC(m_Kernelbase, FindFirstFileW),
		WIN32API_INIT_PROC(m_Kernelbase, FindNextFileW),
		WIN32API_INIT_PROC(m_Kernelbase, FindClose),
		WIN32API_INIT_PROC(m_Kernelbase, CreateFileW),
		WIN32API_INIT_PROC(m_Kernelbase, WriteFile),
		WIN32API_INIT_PROC(m_Kernelbase, CloseHandle),
		WIN32API_INIT_PROC(m_Kernelbase, GetTokenInformation),
		WIN32API_INIT_PROC(m_Kernelbase, QueryFullProcessImageNameW),
		WIN32API_INIT_PROC(m_Kernelbase, GetProcessImageFileNameW),	
		WIN32API_INIT_PROC(m_Kernelbase, CreateEventW),	
		WIN32API_INIT_PROC(m_Kernelbase, WaitForSingleObject),	
		WIN32API_INIT_PROC(m_Kernelbase, CreateProcessAsUserW),	
		WIN32API_INIT_PROC(m_Kernelbase, CreateProcessW),	
		WIN32API_INIT_PROC(m_Kernelbase, OpenProcess),	
		WIN32API_INIT_PROC(m_Kernelbase, DuplicateTokenEx),
		WIN32API_INIT_PROC(m_Kernelbase, lstrcmpiW),
		WIN32API_INIT_PROC(m_Kernelbase, lstrcmpA),
		WIN32API_INIT_PROC(m_Kernelbase, AdjustTokenPrivileges),
		WIN32API_INIT_PROC(m_Kernelbase, OpenProcessToken),
		WIN32API_INIT_PROC(m_Kernelbase, GetExitCodeThread),
		WIN32API_INIT_PROC(m_Kernelbase, GetExitCodeProcess),
		WIN32API_INIT_PROC(m_Kernelbase, AllocConsole),
		WIN32API_INIT_PROC(m_Kernelbase, FreeConsole),
		WIN32API_INIT_PROC(m_Kernelbase, WriteConsoleW),
		WIN32API_INIT_PROC(m_Kernelbase, GetStdHandle),
		WIN32API_INIT_PROC(m_Kernelbase, CreatePipe),
		WIN32API_INIT_PROC(m_Kernelbase, SetHandleInformation),
		WIN32API_INIT_PROC(m_Kernelbase, ReadFile),
		WIN32API_INIT_PROC(m_Kernelbase, AllocateAndInitializeSid),
		WIN32API_INIT_PROC(m_Kernelbase, AllocateLocallyUniqueId),
		WIN32API_INIT_PROC(m_Kernelbase, FreeSid),
		WIN32API_INIT_PROC(m_Kernelbase, OpenFileMappingW),
		WIN32API_INIT_PROC(m_Kernelbase, CreateFileMappingW),
		WIN32API_INIT_PROC(m_Kernelbase, MapViewOfFile),
		WIN32API_INIT_PROC(m_Kernelbase, UnmapViewOfFile),
		WIN32API_INIT_PROC(m_Kernelbase, SetPriorityClass),		
		WIN32API_INIT_PROC(m_Kernelbase, CreateThread),		
		WIN32API_INIT_PROC(m_Kernelbase, SetThreadPriority),
		WIN32API_INIT_PROC(m_Kernelbase, EnumDeviceDrivers),
		WIN32API_INIT_PROC(m_Kernelbase, GetDeviceDriverBaseNameW),		
		m_Sspicli(LoadLibraryExW(L"SSPICLI.DLL", NULL, NULL)),
		WIN32API_INIT_PROC(m_Sspicli, LogonUserExExW),
		WIN32API_INIT_PROC(m_Sspicli, GetUserNameExW),
		m_SecRuntime(LoadLibraryExW(L"SecRuntime.dll", NULL, NULL)),
        WIN32API_INIT_PROC(m_SecRuntime, OpenProcessTokenForQuery),
		m_Advapi32(LoadLibraryExW(L"Advapi32legacy.dll", NULL, NULL)),
        WIN32API_INIT_PROC(m_Advapi32, LookupAccountSidW),
		WIN32API_INIT_PROC(m_Advapi32, LookupPrivilegeNameW),
		WIN32API_INIT_PROC(m_Advapi32, LookupPrivilegeValueW),
		m_Sechost(LoadLibraryExW(L"SECHOST.dll", NULL, NULL)),
        WIN32API_INIT_PROC(m_Sechost, RegisterServiceCtrlHandlerExW),
		WIN32API_INIT_PROC(m_Sechost, SetServiceStatus),
		WIN32API_INIT_PROC(m_Sechost, StartServiceCtrlDispatcherW),
		WIN32API_INIT_PROC(m_Sechost, OpenSCManagerW),
		WIN32API_INIT_PROC(m_Sechost, CloseServiceHandle),
		WIN32API_INIT_PROC(m_Sechost, EnumServicesStatusExW),
		WIN32API_INIT_PROC(m_Sechost, OpenServiceW),
		WIN32API_INIT_PROC(m_Sechost, ControlService),
		m_Kernel32legacy(LoadLibraryExW(L"KERNEL32LEGACY.dll", NULL, NULL)),
        WIN32API_INIT_PROC(m_Kernel32legacy, WTSGetActiveConsoleSessionId),
		WIN32API_INIT_PROC(m_Kernel32legacy, CreateToolhelp32Snapshot),
		WIN32API_INIT_PROC(m_Kernel32legacy, Process32FirstW),
		WIN32API_INIT_PROC(m_Kernel32legacy, Process32NextW),
		WIN32API_INIT_PROC(m_Kernel32legacy, LocalAlloc),
		WIN32API_INIT_PROC(m_Kernel32legacy, LocalFree),
		m_Ntdll(LoadLibraryExW(L"ntdll.dll", NULL, NULL)),
		WIN32API_INIT_PROC(m_Ntdll, ZwCreateToken),
		WIN32API_INIT_PROC(m_Ntdll, NtOpenDirectoryObject),
		WIN32API_INIT_PROC(m_Ntdll, NtQueryDirectoryObject),
		WIN32API_INIT_PROC(m_Ntdll, RtlInitUnicodeString),
		m_BluetoothApis(LoadLibraryExW(L"BLUETOOTHAPIS.DLL", NULL, NULL)),
		WIN32API_INIT_PROC(m_BluetoothApis, BluetoothFindFirstRadio),		
		WIN32API_INIT_PROC(m_BluetoothApis, BluetoothSetLocalServiceInfo),
		m_CfgMgr32(LoadLibraryExW(L"CFGMGR32.dll", NULL, NULL)),
		WIN32API_INIT_PROC(m_CfgMgr32, CM_Get_Device_ID_List_SizeW),
		WIN32API_INIT_PROC(m_CfgMgr32, CM_Get_Device_ID_ListW),
		WIN32API_INIT_PROC(m_CfgMgr32, CM_Locate_DevNodeW),
		WIN32API_INIT_PROC(m_CfgMgr32, CM_Get_DevNode_PropertyW)

	{};

};