//Visual Studio 2012 ARM Phone Tools Command Prompt:
// cl.exe /c /ZW:nostdlib /EHsc /D "PSAPI_VERSION=2" /D "WINAPI_FAMILY=WINAPI_FAMILY_PHONE_APP" /D "_UITHREADCTXT_SUPPORT=0" /D "_UNICODE" /D "UNICODE" /D "_DEBUG" /MDd ALG.cpp
// LINK.exe /LIBPATH:"C:\Program Files (x86)\Windows Phone Kits\8.1\lib\ARM" /MANIFEST:NO "WindowsPhoneCore.lib" "RuntimeObject.lib" "PhoneAppModelHost.lib" /DEBUG /MACHINE:ARM /NODEFAULTLIB:"kernel32.lib" /NODEFAULTLIB:"ole32.lib" /WINMD /SUBSYSTEM:WINDOWS ALG.obj
//
// Copy ALG.exe to windows\system32
// XbfGenerator.exe (XAML Binary Format generator)
// ALG.EXE (Application Layer Gateway)
//
// HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ALG
//	Start
//		0x2 automatic
//		0x3 manual
//  ObjectName
//		NT AUTHORITY\LocalService
//		LocalSystem

#include <stdio.h>
#include <stdlib.h>
#include <wtypes.h>
#include <malloc.h>
#include <WinError.h>
#include "Win32Api.h"


Win32Api win32Api;
SERVICE_STATUS_HANDLE g_ServiceStatusHandle;
HANDLE g_StopEvent;
DWORD g_CurrentState = 0;
bool g_SystemShutdown = false;
HANDLE hFile;

void write2File(HANDLE hFile, WCHAR* format, ...)
{
	va_list args;
	va_start(args, format);

	WCHAR buffer[1000];
	_vsnwprintf_s(buffer, sizeof(buffer), format, args);

	DWORD dwBytesToWrite = wcslen(buffer) * sizeof(WCHAR);
	DWORD dwBytesWritten = 0;
	win32Api.WriteFile(
		hFile,           // open file handle
		buffer,      // start of data to write
		dwBytesToWrite,  // number of bytes to write
		&dwBytesWritten, // number of bytes that were written
		NULL);            // no overlapped structure

	va_end(args);
}

int printAccessTokenInfo(HANDLE hAccessToken)
{
	////////////////////////// TokenUser ///////////////////////////////
	DWORD requiredSize = 0;
	if (!win32Api.GetTokenInformation(hAccessToken, TokenUser, nullptr, 0, &requiredSize))
	{
		DWORD error = GetLastError();
		if (error != ERROR_INSUFFICIENT_BUFFER)
		{
			write2File(hFile, L"\t\tError GetTokenInformation %d\n", GetLastError());
			return 1;					
		}
	}
	if (requiredSize == 0) 
	{
		write2File(hFile, L"\t\tError requiredSize == 0\n");
		return 1;
	}

	PTOKEN_USER userToken  = (PTOKEN_USER)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, requiredSize);
	if (!win32Api.GetTokenInformation(hAccessToken, TokenUser, userToken, requiredSize, &requiredSize)) 
	{
		write2File(hFile, L"\t\tError GetTokenInformation %d\n", GetLastError());
		return 1;		
	}
	
	WCHAR userName[MAX_PATH] = {};
	DWORD userNameLength = _countof(userName);
	WCHAR domainName[MAX_PATH] = {};
	DWORD domainNameLength = _countof(domainName);
	SID_NAME_USE sidType = SidTypeUnknown;
	if (!win32Api.LookupAccountSidW(nullptr, userToken->User.Sid, userName, &userNameLength, domainName, &domainNameLength, &sidType)) 
	{
		write2File(hFile, L"\t\tError LookupAccountSid %d\n", GetLastError());
		return 1;
	}
	write2File(hFile, L"\t\tProcess owner name: \\\\%ls\\%ls\n", domainName, userName);

	////////////////////////// TokenIntegrityLevel ///////////////////////////////

	requiredSize = 0;
	if (!win32Api.GetTokenInformation(hAccessToken, TokenIntegrityLevel, nullptr, 0, &requiredSize)) 
	{
		DWORD error = GetLastError();
		if (error != ERROR_INSUFFICIENT_BUFFER)
		{
			write2File(hFile, L"\t\tError GetTokenInformation %d\n", GetLastError());
			return 1;					
		}
	}
	if (requiredSize == 0) 
	{
		write2File(hFile, L"\t\tError requiredSize == 0\n");
		return 1;
	}
	
	PTOKEN_MANDATORY_LABEL uerToken  = (PTOKEN_MANDATORY_LABEL)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, requiredSize);
	if (!win32Api.GetTokenInformation(hAccessToken, TokenIntegrityLevel, uerToken, requiredSize, &requiredSize)) 
	{
		write2File(hFile, L"\t\tError GetTokenInformation %d\n", GetLastError());
		return 1;		
	}

	WCHAR userName2[MAX_PATH] = {};
	DWORD userNameLength2 = _countof(userName2);
	WCHAR domainName2[MAX_PATH] = {};
	DWORD domainNameLength2 = _countof(domainName2);
	sidType = SidTypeUnknown;
	if (!win32Api.LookupAccountSidW(nullptr, uerToken->Label.Sid, userName2, &userNameLength2, domainName2, &domainNameLength2, &sidType)) 
	{
		write2File(hFile, L"\t\tError LookupAccountSid %d\n", GetLastError());
		return 1;
	}
	write2File(hFile, L"\t\tProcess integrity level: %ls\n", userName2);

	////////////////////////// TokenPrivileges ///////////////////////////////

	requiredSize = 0;
	if (!win32Api.GetTokenInformation(hAccessToken, TokenPrivileges, nullptr, 0, &requiredSize)) 
	{
		DWORD error = GetLastError();
		if (error != ERROR_INSUFFICIENT_BUFFER)
		{
			write2File(hFile, L"\t\tError GetTokenInformation %d\n", GetLastError());
			return 1;					
		}
	}
	if (requiredSize == 0) 
	{
		write2File(hFile, L"\t\tError requiredSize == 0\n");
		return 1;
	}
	
	PTOKEN_PRIVILEGES tokenPrivileges = (PTOKEN_PRIVILEGES)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, requiredSize);
	if (!win32Api.GetTokenInformation(hAccessToken, TokenPrivileges, tokenPrivileges , requiredSize, &requiredSize)) 
	{
		write2File(hFile, L"\t\tError GetTokenInformation %d\n", GetLastError());
		return 1;		
	}
	write2File(hFile, L"\t\ttokenPrivileges->PrivilegeCount=%d\n", tokenPrivileges->PrivilegeCount);

	for (DWORD i = 0; i < tokenPrivileges->PrivilegeCount; ++i) 
	{
		requiredSize = 0;
		win32Api.LookupPrivilegeNameW(nullptr, &tokenPrivileges->Privileges[i].Luid, nullptr, &requiredSize);
		if (requiredSize == 0) 
		{
			write2File(hFile, L"\t\tError requiredSize == 0\n");
			return 1;
		}
		
		WCHAR privilegeName[100] = {};
		if (!win32Api.LookupPrivilegeNameW(nullptr, &tokenPrivileges->Privileges[i].Luid, privilegeName, &requiredSize)) 
		{
			write2File(hFile, L"\t\tError LookupPrivilegeName %d\n", GetLastError());
			return 1;	
		}
		write2File(hFile, L"\t\tprivilegeName=%ls ", privilegeName);
		
		WCHAR* state = L"Disabled";
		switch (tokenPrivileges->Privileges[i].Attributes) {
		  case SE_PRIVILEGE_ENABLED:
			state = L"Enabled";
			break;

		  case SE_PRIVILEGE_ENABLED_BY_DEFAULT:
			state = L"Enabled Default";
			break;
			
		  case SE_PRIVILEGE_ENABLED+SE_PRIVILEGE_ENABLED_BY_DEFAULT:
			state = L"Enabled Default";
			break;	

		  case SE_PRIVILEGE_REMOVED:
			state = L"Removed";
			break;

		  case SE_PRIVILEGE_USED_FOR_ACCESS:
			state = L"Used for access";
			break;
		}
		
		write2File(hFile, L"state=%ls\n", state);
	}
	
	////////////////////////// TokenType ///////////////////////////////
	
	requiredSize = 0;
	if (!win32Api.GetTokenInformation(hAccessToken, TokenType, nullptr, 0, &requiredSize)) 
	{
		DWORD error = GetLastError();
		if (error != ERROR_INSUFFICIENT_BUFFER)
		{
			write2File(hFile, L"\t\tError GetTokenInformation %d\n", GetLastError());
			return 1;					
		}
	}
	if (requiredSize == 0) 
	{
		write2File(hFile, L"\t\tError requiredSize == 0\n");
		return 1;
	}
	
	TOKEN_TYPE tokenType;
	if (!win32Api.GetTokenInformation(hAccessToken, TokenType, &tokenType, requiredSize, &requiredSize)) 
	{
		write2File(hFile, L"\t\tError GetTokenInformation %d\n", GetLastError());
		return 1;		
	}
	write2File(hFile, L"\t\ttokenType=%d (1=TokenPrimary)\n", tokenType);
	
	////////////////////////// TokenSessionId ///////////////////////////////
	
	requiredSize = 0;
	if (!win32Api.GetTokenInformation(hAccessToken, TokenSessionId, nullptr, 0, &requiredSize)) 
	{
		DWORD error = GetLastError();
		if (error != ERROR_INSUFFICIENT_BUFFER)
		{
			write2File(hFile, L"\t\tError GetTokenInformation %d\n", GetLastError());
			return 1;					
		}
	}
	if (requiredSize == 0) 
	{
		write2File(hFile, L"\t\tError requiredSize == 0\n");
		return 1;
	}
	
	DWORD tokenSessionId;
	if (!win32Api.GetTokenInformation(hAccessToken, TokenSessionId, &tokenSessionId, requiredSize, &requiredSize)) 
	{
		write2File(hFile, L"\t\tError GetTokenInformation %d\n", GetLastError());
		return 1;		
	}
	write2File(hFile, L"\t\ttokenSessionId=%d\n", tokenSessionId);
	
	return 0;
}

int printProcessInfo(HANDLE hProcess)
{
	write2File(hFile, L"************ hProcess=0x%08X information:\n",hProcess);
	
	WCHAR fullPath[MAX_PATH] = {};
	DWORD size = _countof(fullPath);
	if (!win32Api.QueryFullProcessImageNameW(hProcess, 0, fullPath, &size)) 
	{
		win32Api.GetProcessImageFileNameW(hProcess, fullPath,_countof(fullPath));
	}
	write2File(hFile, L"\tProcess full path: %ls\n", fullPath);
	
	HANDLE processToken = nullptr;
	if (S_OK != win32Api.OpenProcessTokenForQuery(hProcess, &processToken))
	{
		write2File(hFile, L"\tError OpenProcessTokenForQuery %d\n", GetLastError());
		return 1;
	}
	
	write2File(hFile, L"\t************ processToken=0x%08X information:\n",processToken);
	printAccessTokenInfo(processToken);
	
	return 0;
}

// https://learn.microsoft.com/en-us/windows/win32/secauthz/enabling-and-disabling-privileges-in-c--
BOOL SetPrivilege(
    HANDLE hToken,          // access token handle
    LPCWSTR lpszPrivilege,  // name of privilege to enable/disable
    BOOL bEnablePrivilege   // to enable or disable privilege
    ) 
{
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!win32Api.LookupPrivilegeValueW( 
            NULL,            // lookup privilege on local system
            lpszPrivilege,   // privilege to lookup 
            &luid ) )        // receives LUID of privilege
    {
        write2File(hFile, L"LookupPrivilegeValueW error: %u\n", GetLastError() ); 
        return FALSE; 
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tp.Privileges[0].Attributes = 0;
	
    // Enable the privilege or disable all privileges.

    if ( !win32Api.AdjustTokenPrivileges(
           hToken, 
           FALSE, 
           &tp, 
           sizeof(TOKEN_PRIVILEGES), 
           (PTOKEN_PRIVILEGES) NULL, 
           (PDWORD) NULL) )
    { 
          write2File(hFile, L"AdjustTokenPrivileges error: %u\n", GetLastError() ); 
          return FALSE; 
    } 
	DWORD result = GetLastError();

    if (result == ERROR_NOT_ALL_ASSIGNED)

    {
          write2File(hFile, L"The token does not have the specified privilege. \n");
          return FALSE;
    } 

    return TRUE;
}

int test(BOOL isService)
{
	write2File(hFile, L"win32Api.m_Kernelbase=0x%08X\n", win32Api.m_Kernelbase);
	write2File(hFile, L"win32Api.m_Sspicli=0x%08X\n", win32Api.m_Sspicli);
	write2File(hFile, L"win32Api.m_SecRuntime=0x%08X\n", win32Api.m_SecRuntime);
	write2File(hFile, L"win32Api.m_Advapi32=0x%08X\n", win32Api.m_Advapi32);
	write2File(hFile, L"win32Api.m_Sechost=0x%08X\n", win32Api.m_Sechost);
	write2File(hFile, L"win32Api.m_Kernel32legacy=0x%08X\n", win32Api.m_Kernel32legacy);	
	
	TCHAR username[1024] = {0};
	DWORD username_len = 1023;
	if (!win32Api.GetUserNameExW(NameSamCompatible, username, &username_len))
	{
		write2File(hFile, L"Error GetUserNameExW %d\n", GetLastError());
	}
	write2File(hFile, L"username=%ls\n",username);

	DWORD activeConsoleSessionId = win32Api.WTSGetActiveConsoleSessionId();
	write2File(hFile, L"activeConsoleSessionId=0x%08X\n",activeConsoleSessionId);

	DWORD currentProcessId = GetCurrentProcessId();
	write2File(hFile, L"currentProcessId=0x%08X\n", currentProcessId);

	HANDLE hCurrentProcess = GetCurrentProcess();
	write2File(hFile, L"hCurrentProcess=0x%08X\n", hCurrentProcess);
	printProcessInfo(hCurrentProcess);
	
	HANDLE hCurrentProcessToken = NULL;
	if (!win32Api.OpenProcessToken(hCurrentProcess, TOKEN_ALL_ACCESS, &hCurrentProcessToken))
	{
		write2File(hFile, L"Error OpenProcessToken %d\n", GetLastError());
		return 1;
	}
	write2File(hFile, L"************ hCurrentProcessToken=0x%08X information:\n", hCurrentProcessToken);
	printAccessTokenInfo(hCurrentProcessToken);
	
	DWORD dwSize = 0;
	PSECURITY_DESCRIPTOR pSD = NULL;
	if (!win32Api.GetKernelObjectSecurity(hCurrentProcessToken, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, pSD, 0, &dwSize))
	{
		HRESULT hr = GetLastError();
		write2File(hFile, L"Error GetKernelObjectSecurity %d (%d=ERROR_INSUFFICIENT_BUFFER)\n", hr, ERROR_INSUFFICIENT_BUFFER);
		if (hr != ERROR_INSUFFICIENT_BUFFER)
			return 1;
	}
	pSD = (PSECURITY_DESCRIPTOR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
	if (!win32Api.GetKernelObjectSecurity(hCurrentProcessToken, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, pSD, dwSize, &dwSize))
	{
		write2File(hFile, L"Error GetKernelObjectSecurity %d\n", GetLastError());
		return 1;
	}
	write2File(hFile, L"pSD=0x%08X\n", pSD);


	
	HANDLE hProcSnap;
	hProcSnap = win32Api.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hProcSnap) 
	{
		write2File(hFile, L"Error CreateToolhelp32Snapshot %d\n", GetLastError());
		return 1;
	}
	write2File(hFile, L"hProcSnap=0x%08X\n",hProcSnap);
	
	PROCESSENTRY32W pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32W); 
			
	if (!win32Api.Process32FirstW(hProcSnap, &pe32)) {
			write2File(hFile, L"Error Process32FirstW %d (18=ERROR_NO_MORE_FILES)\n", GetLastError());
			return 1;
	}
	write2File(hFile, L"First process ID=0x%08X (0x00000000=System Idle Process) ExeFile=%ls\n", pe32.th32ProcessID, pe32.szExeFile);

	HANDLE hSystemToken, hSystemProcess;			
	while (win32Api.Process32NextW(hProcSnap, &pe32)) {
		write2File(hFile, L"Next process ID=0x%08X ExeFile=%ls\n", pe32.th32ProcessID, pe32.szExeFile);
		
		hSystemProcess = win32Api.OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID);
		if (hSystemProcess == NULL)
		{
			write2File(hFile, L"Error OpenProcess %d (5=ERROR_ACCESS_DENIED)\n",GetLastError());
		}
		else
		{
			write2File(hFile, L"Next process handle=0x%08X\n",hSystemProcess);
			printProcessInfo(hSystemProcess);
			if (win32Api.lstrcmpiW(L"WININIT.EXE", pe32.szExeFile) == 0) 
			{
				write2File(hFile, L"WININIT.EXE found\n");
				if (!win32Api.OpenProcessToken(hSystemProcess, TOKEN_ALL_ACCESS, &hSystemToken))
				{
					write2File(hFile, L"Error OpenProcessToken %d\n", GetLastError());
					return 1;
				}
				write2File(hFile, L"WININIT.EXE token=0x%08X\n", hSystemToken);
			}
		}
	}
	write2File(hFile, L"Error Process32NextW %d (18=ERROR_NO_MORE_FILES)\n", GetLastError());
			
	win32Api.CloseHandle(hProcSnap);
	
	
	
	HANDLE systemLogonToken = NULL;
	if (!win32Api.LogonUserExExW(L"SYSTEM", L"NT AUTHORITY", NULL, LOGON32_LOGON_SERVICE, LOGON32_PROVIDER_DEFAULT, NULL, &systemLogonToken, NULL, NULL, NULL, NULL))
	{
		write2File(hFile, L"Error LogonUserExExW %d\n", GetLastError());
		return 1;
	}
	
	write2File(hFile, L"************ systemLogonToken=0x%08X information:\n", systemLogonToken);
	printAccessTokenInfo(systemLogonToken);
	
	HANDLE defappsLogonToken = NULL;
	SID logonSid = {};
	PSID pLogonSid = &logonSid;
	PVOID pProfileBuffer = NULL;
	DWORD profileLength = 0;
	QUOTA_LIMITS quotaLimits = {};
	if (!win32Api.LogonUserExExW(L"DefApps", L"", L"", LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, NULL, &defappsLogonToken, &pLogonSid, &pProfileBuffer, &profileLength, &quotaLimits))
	{
		write2File(hFile, L"Error LogonUserExExW %d\n", GetLastError());
		return 1;
	}
	
	write2File(hFile, L"************ defappsLogonToken=0x%08X information:\n", defappsLogonToken);
	printAccessTokenInfo(defappsLogonToken);

	if (isService)
	{
		HANDLE dupSystemToken = NULL;
		if (!win32Api.DuplicateTokenEx(hSystemToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &dupSystemToken))
		{
			write2File(hFile, L"Error DuplicateTokenEx %d\n", GetLastError());
			return 1;
		}	
		write2File(hFile, L"************ dupSystemToken=0x%08X information:\n", dupSystemToken);
		printAccessTokenInfo(dupSystemToken);
		
		SetPrivilege(dupSystemToken, L"SeAssignPrimaryTokenPrivilege", TRUE);
		SetPrivilege(dupSystemToken, L"SeIncreaseQuotaPrivilege", TRUE);
		SetPrivilege(dupSystemToken, L"SeSecurityPrivilege", TRUE);
		SetPrivilege(dupSystemToken, L"SeTakeOwnershipPrivilege", TRUE);
		SetPrivilege(dupSystemToken, L"SeLoadDriverPrivilege", TRUE);
		SetPrivilege(dupSystemToken, L"SeBackupPrivilege", TRUE);
		SetPrivilege(dupSystemToken, L"SeRestorePrivilege", TRUE);
		SetPrivilege(dupSystemToken, L"SeShutdownPrivilege", TRUE);
		SetPrivilege(dupSystemToken, L"SeSystemEnvironmentPrivilege", TRUE);
		SetPrivilege(dupSystemToken, L"SeUndockPrivilege", TRUE);
		SetPrivilege(dupSystemToken, L"SeManageVolumePrivilege", TRUE);
		SetPrivilege(dupSystemToken, L"SeManageVolumePrivilege", TRUE);
		write2File(hFile, L"************ dupSystemToken=0x%08X information:\n", dupSystemToken);
		printAccessTokenInfo(dupSystemToken);

		PROCESS_INFORMATION process_INFORMATION = {};
		STARTUPINFOW startupinfo = {};
		ZeroMemory(&startupinfo, sizeof(startupinfo));
		
		if(!win32Api.CreateProcessAsUserW(dupSystemToken, L"C:\\windows\\system32\\ALG.EXE", NULL, NULL, NULL, false, NORMAL_PRIORITY_CLASS, NULL, NULL, &startupinfo, &process_INFORMATION))
		//if(!win32Api.CreateProcessAsUserW(dupSystemToken, L"C:\\Data\\USERS\\Public\\Documents\\console.exe", NULL, NULL, NULL, false, NORMAL_PRIORITY_CLASS, NULL, NULL, &startupinfo, &process_INFORMATION))
		//if(!win32Api.CreateProcessAsUserW(dupSystemToken, L"C:\\windows\\system32\\XbfGenerator.exe", NULL, NULL, NULL, false, NORMAL_PRIORITY_CLASS, NULL, NULL, &startupinfo, &process_INFORMATION))
		{
			write2File(hFile, L"Error CreateProcessAsUserW %d\n", GetLastError());
		}
		write2File(hFile, L"process_INFORMATION.hProcess=0x%08X\n", process_INFORMATION.hProcess);
		write2File(hFile, L"process_INFORMATION.hThread=0x%08X\n", process_INFORMATION.hThread);
	}

    return 0;
}

void ReportStatus(DWORD state)
{
	write2File(hFile, L"Begin ReportStatus.\n");
	
	g_CurrentState = state;
	SERVICE_STATUS serviceStatus = {
		SERVICE_WIN32_OWN_PROCESS,
		g_CurrentState,
		state == SERVICE_START_PENDING ? 0 : SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN,
		NO_ERROR,
		0,
		0,
		0,
	};
	win32Api.SetServiceStatus(g_ServiceStatusHandle, &serviceStatus);
	
	write2File(hFile, L"End ReportStatus.\n");
}

DWORD WINAPI HandlerEx(DWORD control, DWORD eventType, void *eventData, void *context)
{
	write2File(hFile, L"Begin HandlerEx.\n");
	
	switch (control)
	{
		// Entrie system is shutting down.
	case SERVICE_CONTROL_SHUTDOWN:
		g_SystemShutdown = true;
		// continue...
		// Service is being stopped.
	case SERVICE_CONTROL_STOP:
		ReportStatus(SERVICE_STOP_PENDING);
		SetEvent(g_StopEvent);
		break;
		// Ignoring all other events, but we must always report service status.
	default:
		ReportStatus(g_CurrentState);
		break;
	}
	write2File(hFile, L"End HandlerEx.\n");
	
	return NO_ERROR;
}

void WINAPI ServiceMain(DWORD argc, LPTSTR *argv)
{
	write2File(hFile, L"Begin ServiceMain.\n");
	
	// Must be called at start.
	g_ServiceStatusHandle = win32Api.RegisterServiceCtrlHandlerExW(L"Service test", &HandlerEx, NULL);

	// Startup code.
	ReportStatus(SERVICE_START_PENDING);
	g_StopEvent = win32Api.CreateEventW(NULL, TRUE, FALSE, NULL);
	/* Here initialize service...
	Load configuration, acquire resources etc. */
	ReportStatus(SERVICE_RUNNING);

	/* Main service code
	Loop, do some work, block if nothing to do,
	wait or poll for g_StopEvent... */
	DWORD count = 0;
	while (win32Api.WaitForSingleObject(g_StopEvent, 3000) != WAIT_OBJECT_0 && count++ < 5)
	{
		test(TRUE);
	}

	ReportStatus(SERVICE_STOP_PENDING);
	/* Here finalize service...
	Save all unsaved data etc., but do it quickly.
	If g_SystemShutdown, you can skip freeing memory etc. */
	win32Api.CloseHandle(g_StopEvent);
	ReportStatus(SERVICE_STOPPED);
	
	write2File(hFile, L"End ServiceMain.\n");
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow)
{
	WIN32_FIND_DATA FindFileData;
	HANDLE hFind = win32Api.FindFirstFileW(L"C:\\Data\\USERS\\Public\\Documents\\wp81Elevation.log", &FindFileData);
	if (hFind == INVALID_HANDLE_VALUE) 
	{
		hFile = win32Api.CreateFileW(L"C:\\Data\\USERS\\Public\\Documents\\wp81Elevation.log",                // name of the write
			GENERIC_WRITE,          // open for writing
			0,                      // do not share
			NULL,                   // default security
			CREATE_ALWAYS,          // always create new file 
			FILE_ATTRIBUTE_NORMAL,  // normal file
			NULL);                  // no attr. template
	} 
	else 
	{
		hFile = win32Api.CreateFileW(L"C:\\Data\\USERS\\Public\\Documents\\wp81Elevation2.log",                // name of the write
			GENERIC_WRITE,          // open for writing
			0,                      // do not share
			NULL,                   // default security
			CREATE_ALWAYS,          // always create new file 
			FILE_ATTRIBUTE_NORMAL,  // normal file
			NULL);                  // no attr. template

		FindClose(hFind);
	}
	if (hFile == INVALID_HANDLE_VALUE)
	{
		return 1;
	}
	
	
	write2File(hFile, L"Begin wWinMain.\n");
	
	SERVICE_TABLE_ENTRYW serviceTable[] = {
		{ L"Service test", &ServiceMain },
		{ NULL, NULL }
	};

	if (win32Api.StartServiceCtrlDispatcherW(serviceTable))
	{
		write2File(hFile, L"Service ended.\n");
		win32Api.CloseHandle(hFile);
		return 0;
	}
	write2File(hFile, L"Error StartServiceCtrlDispatcherW : %d\n", GetLastError());
	test(FALSE);
	win32Api.CloseHandle(hFile);
	return 2;
}