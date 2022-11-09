//Visual Studio 2012 ARM Phone Tools Command Prompt:
// cl.exe /c /ZW:nostdlib /EHsc /D "PSAPI_VERSION=2" /D "WINAPI_FAMILY=WINAPI_FAMILY_PHONE_APP" /D "_UITHREADCTXT_SUPPORT=0" /D "_UNICODE" /D "UNICODE" /D "_DEBUG" /MDd wp81listProcess.cpp
// LINK.exe /LIBPATH:"C:\Program Files (x86)\Windows Phone Kits\8.1\lib\ARM" /MANIFEST:NO "WindowsPhoneCore.lib" "RuntimeObject.lib" "PhoneAppModelHost.lib"/DEBUG /MACHINE:ARM /NODEFAULTLIB:"kernel32.lib" /NODEFAULTLIB:"ole32.lib" /WINMD /SUBSYSTEM:WINDOWS wp81listProcess.obj
//

#include "Win32Api.h"
#include "cJSON.h"

Win32Api win32Api;

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
		write2File(hFile, L"(%d) ", tokenPrivileges->Privileges[i].Attributes);
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

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow)
{	
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
	
	return 0;
}
