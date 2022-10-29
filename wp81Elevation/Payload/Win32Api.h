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
	
	DWORD WTSGetActiveConsoleSessionId();
	HANDLE WINAPI CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID);
	BOOL WINAPI Process32FirstW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe);
	BOOL WINAPI Process32NextW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe);
	WINBASEAPI HLOCAL WINAPI LocalAlloc(UINT uFlags, SIZE_T uBytes);
	WINBASEAPI HLOCAL WINAPI LocalFree(HLOCAL hMem);
	
	NTSTATUS ZwCreateToken(HANDLE TokenHandle,ACCESS_MASK DesiredAccess,POBJECT_ATTRIBUTES ObjectAttributes,TOKEN_TYPE TokenType,PLUID AuthenticationId,PLARGE_INTEGER ExpirationTime,PTOKEN_USER TokenUser,PTOKEN_GROUPS TokenGroups,PTOKEN_PRIVILEGES TokenPrivileges,PTOKEN_OWNER TokenOwner,PTOKEN_PRIMARY_GROUP TokenPrimaryGroup,PTOKEN_DEFAULT_DACL TokenDefaultDacl,PTOKEN_SOURCE  TokenSource);
}

#define WIN32API_TOSTRING(x) #x

// Link exported function
#define WIN32API_INIT_PROC(Module, Name)  \
  Name(reinterpret_cast<decltype(&::Name)>( \
      ::GetProcAddress((Module), WIN32API_TOSTRING(Name))))

// Convenientmacro to declare function
#define WIN32API_DEFINE_PROC(Name) const decltype(&::Name) Name

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
	const HMODULE m_Kernel32legacy;
	WIN32API_DEFINE_PROC(WTSGetActiveConsoleSessionId);
	WIN32API_DEFINE_PROC(CreateToolhelp32Snapshot);
	WIN32API_DEFINE_PROC(Process32FirstW);
	WIN32API_DEFINE_PROC(Process32NextW);
	WIN32API_DEFINE_PROC(LocalAlloc);
	WIN32API_DEFINE_PROC(LocalFree);
	const HMODULE m_Ntdll;
	WIN32API_DEFINE_PROC(ZwCreateToken);

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
		m_Kernel32legacy(LoadLibraryExW(L"KERNEL32LEGACY.dll", NULL, NULL)),
        WIN32API_INIT_PROC(m_Kernel32legacy, WTSGetActiveConsoleSessionId),
		WIN32API_INIT_PROC(m_Kernel32legacy, CreateToolhelp32Snapshot),
		WIN32API_INIT_PROC(m_Kernel32legacy, Process32FirstW),
		WIN32API_INIT_PROC(m_Kernel32legacy, Process32NextW),
		WIN32API_INIT_PROC(m_Kernel32legacy, LocalAlloc),
		WIN32API_INIT_PROC(m_Kernel32legacy, LocalFree),
		m_Ntdll(LoadLibraryExW(L"ntdll.dll", NULL, NULL)),
		WIN32API_INIT_PROC(m_Ntdll, ZwCreateToken)
	{};

};