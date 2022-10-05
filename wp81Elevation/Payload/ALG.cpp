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

		  case SE_PRIVILEGE_REMOVED:
			state = L"Removed";
			break;

		  case SE_PRIVILEGE_USED_FOR_ACCESS:
			state = L"Used for access";
			break;
		}
		
		write2File(hFile, L"state=%ls\n", state);
	}
	
	////////////////////////// TokenPrivileges ///////////////////////////////
	
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
		write2File(hFile, L"\tError OpenProcessTokenForQuery\n");
		return 1;
	}
	
	write2File(hFile, L"\t************ processToken=0x%08X information:\n",processToken);
	printAccessTokenInfo(processToken);
	
	return 0;
}

int test()
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

	PROCESS_INFORMATION process_INFORMATION = {};
	STARTUPINFOW startupinfo = {};
	ZeroMemory(&startupinfo, sizeof(startupinfo));
	
	if(!win32Api.CreateProcessAsUserW(defappsLogonToken, L"C:\\windows\\system32\\XBFGENERATOR.EXE", NULL, NULL, NULL, false, NORMAL_PRIORITY_CLASS, NULL, NULL, &startupinfo, &process_INFORMATION))
	{
		write2File(hFile, L"Error CreateProcessAsUserW %d\n", GetLastError());
//		return 1;
	}
	write2File(hFile, L"process_INFORMATION.hProcess=0x%08X\n", process_INFORMATION.hProcess);
	write2File(hFile, L"process_INFORMATION.hThread=0x%08X\n", process_INFORMATION.hThread);
   
	https://stackoverflow.com/questions/50644181/createprocessasuser-process-exits-with-1073741502/50743993#50743993

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
//	while (win32Api.WaitForSingleObject(g_StopEvent, 3000) != WAIT_OBJECT_0)
//	{
		test();
//	}

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
	hFile = win32Api.CreateFileW(L"C:\\Data\\USERS\\Public\\Documents\\wp81Elevation.log",                // name of the write
		GENERIC_WRITE,          // open for writing
		0,                      // do not share
		NULL,                   // default security
		CREATE_ALWAYS,          // always create new file 
		FILE_ATTRIBUTE_NORMAL,  // normal file
		NULL);                  // no attr. template
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
	win32Api.CloseHandle(hFile);
	return 2;
}