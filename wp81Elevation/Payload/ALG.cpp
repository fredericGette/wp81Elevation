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

int test()
{
	HANDLE hCurrentProcess = nullptr;
	hCurrentProcess = GetCurrentProcess();
	write2File(hFile, L"hCurrentProcess=0x%08X\n", hCurrentProcess);

	DWORD currentProcessId = GetCurrentProcessId();
	write2File(hFile, L"currentProcessId=%d\n", currentProcessId);
	
	write2File(hFile, L"win32Api.m_Kernelbase=0x%08X\n", win32Api.m_Kernelbase);
	write2File(hFile, L"win32Api.m_Sspicli=0x%08X\n", win32Api.m_Sspicli);
	write2File(hFile, L"win32Api.m_SecRuntime=0x%08X\n", win32Api.m_SecRuntime);
	write2File(hFile, L"win32Api.m_Advapi32=0x%08X\n", win32Api.m_Advapi32);
	
	TCHAR username[1024] = {0};
	DWORD username_len = 1023;
	if (!win32Api.GetUserNameExW(NameSamCompatible, username, &username_len))
	{
		write2File(hFile, L"Error GetUserNameExW %d\n", GetLastError());
	}
	write2File(hFile, L"username_len=%lu\n",username_len);
	write2File(hFile, L"username=%ls\n",username);
	
	HANDLE processTokenHandle = nullptr;
	if (S_OK != win32Api.OpenProcessTokenForQuery(hCurrentProcess, &processTokenHandle))
	{
		write2File(hFile, L"Error OpenProcessTokenForQuery\n");
		return 1;
	}
	write2File(hFile, L"processTokenHandle=0x%08X\n", processTokenHandle);
	
	DWORD requiredSize = 0;
	if (!win32Api.GetTokenInformation(processTokenHandle, TokenUser, nullptr, 0, &requiredSize))
	{
		DWORD error = GetLastError();
		if (error != ERROR_INSUFFICIENT_BUFFER)
		{
			write2File(hFile, L"Error GetTokenInformation %d\n", GetLastError());
			return 1;					
		}
	}
	if (requiredSize == 0) 
	{
		write2File(hFile, L"Error requiredSize == 0\n");
		return 1;
	}
	write2File(hFile, L"requiredSize=%d\n", requiredSize);

	PTOKEN_USER userToken  = (PTOKEN_USER)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, requiredSize);
	if (!win32Api.GetTokenInformation(processTokenHandle, TokenUser, userToken, requiredSize, &requiredSize)) 
	{
		write2File(hFile, L"Error GetTokenInformation %d\n", GetLastError());
		return 1;		
	}
	write2File(hFile, L"userToken->User.Sid=0x%08X\n", userToken->User.Sid);
	write2File(hFile, L"userToken->User.Attributes=%d\n", userToken->User.Attributes);
	
	WCHAR userName[MAX_PATH] = {};
	DWORD userNameLength = _countof(userName);
	WCHAR domainName[MAX_PATH] = {};
	DWORD domainNameLength = _countof(domainName);
	SID_NAME_USE sidType = SidTypeUnknown;
	if (!win32Api.LookupAccountSidW(nullptr, userToken->User.Sid, userName, &userNameLength, domainName, &domainNameLength, &sidType)) 
	{
		write2File(hFile, L"Error LookupAccountSid %d\n", GetLastError());
		return 1;
	}
	write2File(hFile, L"Process owner name: \\\\%ls\\%ls\n", domainName, userName);

	WCHAR fullPath[MAX_PATH] = {};
	DWORD size = _countof(fullPath);
	if (!win32Api.QueryFullProcessImageNameW(hCurrentProcess, 0, fullPath, &size)) 
	{
		win32Api.GetProcessImageFileNameW(hCurrentProcess, fullPath,_countof(fullPath));
	}
	
	write2File(hFile, L"Process full path: %ls\n", fullPath);
	
	requiredSize = 0;
	if (!win32Api.GetTokenInformation(processTokenHandle, TokenIntegrityLevel, nullptr, 0, &requiredSize)) 
	{
		DWORD error = GetLastError();
		if (error != ERROR_INSUFFICIENT_BUFFER)
		{
			write2File(hFile, L"Error GetTokenInformation %d\n", GetLastError());
			return 1;					
		}
	}
	if (requiredSize == 0) 
	{
		write2File(hFile, L"Error requiredSize == 0\n");
		return 1;
	}
	write2File(hFile, L"requiredSize=%d\n", requiredSize);
	
	PTOKEN_MANDATORY_LABEL uerToken  = (PTOKEN_MANDATORY_LABEL)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, requiredSize);
	if (!win32Api.GetTokenInformation(processTokenHandle, TokenIntegrityLevel, uerToken, requiredSize, &requiredSize)) 
	{
		write2File(hFile, L"Error GetTokenInformation %d\n", GetLastError());
		return 1;		
	}
	write2File(hFile, L"uerToken->Label.Sid=0x%08X\n", uerToken->Label.Sid);

	WCHAR userName2[MAX_PATH] = {};
	DWORD userNameLength2 = _countof(userName2);
	WCHAR domainName2[MAX_PATH] = {};
	DWORD domainNameLength2 = _countof(domainName2);
	sidType = SidTypeUnknown;
	if (!win32Api.LookupAccountSidW(nullptr, uerToken->Label.Sid, userName2, &userNameLength2, domainName2, &domainNameLength2, &sidType)) 
	{
		write2File(hFile, L"Error LookupAccountSid %d\n", GetLastError());
		return 1;
	}
	write2File(hFile, L"Process integrity level: %ls\n", userName2);

	requiredSize = 0;
	if (!win32Api.GetTokenInformation(processTokenHandle, TokenPrivileges, nullptr, 0, &requiredSize)) 
	{
		DWORD error = GetLastError();
		if (error != ERROR_INSUFFICIENT_BUFFER)
		{
			write2File(hFile, L"Error GetTokenInformation %d\n", GetLastError());
			return 1;					
		}
	}
	if (requiredSize == 0) 
	{
		write2File(hFile, L"Error requiredSize == 0\n");
		return 1;
	}
	write2File(hFile, L"requiredSize=%d\n", requiredSize);
	
	PTOKEN_PRIVILEGES tokenPrivileges = (PTOKEN_PRIVILEGES)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, requiredSize);
	if (!win32Api.GetTokenInformation(processTokenHandle, TokenPrivileges, tokenPrivileges , requiredSize, &requiredSize)) 
	{
		write2File(hFile, L"Error GetTokenInformation %d\n", GetLastError());
		return 1;		
	}
	write2File(hFile, L"tokenPrivileges->PrivilegeCount=%d\n", tokenPrivileges->PrivilegeCount);

	for (DWORD i = 0; i < tokenPrivileges->PrivilegeCount; ++i) 
	{
		write2File(hFile, L"tokenPrivileges->Privileges[i].Luid.LowPart=%d\n", tokenPrivileges->Privileges[i].Luid.LowPart);
		requiredSize = 0;
		win32Api.LookupPrivilegeNameW(nullptr, &tokenPrivileges->Privileges[i].Luid, nullptr, &requiredSize);
		if (requiredSize == 0) 
		{
			write2File(hFile, L"Error requiredSize == 0\n");
			return 1;
		}
		write2File(hFile, L"requiredSize=%d\n", requiredSize);
		
		WCHAR privilegeName[100] = {};
		if (!win32Api.LookupPrivilegeNameW(nullptr, &tokenPrivileges->Privileges[i].Luid, privilegeName, &requiredSize)) 
		{
			write2File(hFile, L"Error LookupPrivilegeName %d\n", GetLastError());
			return 1;	
		}
		write2File(hFile, L"privilegeName=%ls ", privilegeName);
		
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