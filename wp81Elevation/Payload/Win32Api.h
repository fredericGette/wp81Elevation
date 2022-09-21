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

	BOOL WINAPI LogonUserExExW(LPTSTR lpszUsername, LPTSTR lpszDomain, LPTSTR lpszPassword, DWORD dwLogonType, DWORD dwLogonProvider, PTOKEN_GROUPS pTokenGroups, PHANDLE phToken, PSID *ppLogonSid, PVOID *ppProfileBuffer, LPDWORD pdwProfileLength, PQUOTA_LIMITS pQuotaLimits);
	BOOL SEC_ENTRY GetUserNameExW(EXTENDED_NAME_FORMAT NameFormat, LPWSTR lpNameBuffer,PULONG nSize);
	
	HRESULT WINAPI OpenProcessTokenForQuery(HANDLE ProcessHandle, HANDLE *TokenHandle);
	
	BOOL WINAPI LookupAccountSidW(LPCWSTR lpSystemName, PSID lpSid, LPWSTR lpName, LPDWORD cchName, LPWSTR lpReferencedDomainName, LPDWORD cchReferencedDomainName, PSID_NAME_USE peUse);
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
	const HMODULE m_Sspicli;
	WIN32API_DEFINE_PROC(LogonUserExExW);
	WIN32API_DEFINE_PROC(GetUserNameExW);
	const HMODULE m_SecRuntime;
	WIN32API_DEFINE_PROC(OpenProcessTokenForQuery);
	const HMODULE m_Advapi32;
	WIN32API_DEFINE_PROC(LookupAccountSidW);	

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
		m_Sspicli(LoadLibraryExW(L"SSPICLI.DLL", NULL, NULL)),
		WIN32API_INIT_PROC(m_Sspicli, LogonUserExExW),
		WIN32API_INIT_PROC(m_Sspicli, GetUserNameExW),
		m_SecRuntime(LoadLibraryExW(L"SecRuntime.dll", NULL, NULL)),
        WIN32API_INIT_PROC(m_SecRuntime, OpenProcessTokenForQuery),
		m_Advapi32(LoadLibraryExW(L"Advapi32legacy.dll", NULL, NULL)),
        WIN32API_INIT_PROC(m_Advapi32, LookupAccountSidW)
	{};

};