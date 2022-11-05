//Visual Studio 2012 ARM Phone Tools Command Prompt:
// cl.exe /c /ZW:nostdlib /EHsc /D "PSAPI_VERSION=2" /D "WINAPI_FAMILY=WINAPI_FAMILY_PHONE_APP" /D "_UITHREADCTXT_SUPPORT=0" /D "_UNICODE" /D "UNICODE" /D "_DEBUG" /MDd wp81service.cpp
// LINK.exe /LIBPATH:"C:\Program Files (x86)\Windows Phone Kits\8.1\lib\ARM" /MANIFEST:NO "WindowsPhoneCore.lib" "RuntimeObject.lib" "PhoneAppModelHost.lib" "Ws2_32.lib" /DEBUG /MACHINE:ARM /NODEFAULTLIB:"kernel32.lib" /NODEFAULTLIB:"ole32.lib" /WINMD /SUBSYSTEM:WINDOWS wp81service.obj
//
// Copy ALG.exe to windows\system32
// XbfGenerator.exe (XAML Binary Format generator) Application "00000005	0001000000000000	0006000300010000	01c4	fe5440e3-8e00-4e47-9d9c-b8cb621a30e2	fkkem3zpb3x42	" found in cache
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
#include <winsock2.h>
#include "Win32Api.h"


Win32Api win32Api;
SERVICE_STATUS_HANDLE g_ServiceStatusHandle;
HANDLE g_StopEvent;
DWORD g_CurrentState = 0;
bool g_SystemShutdown = false;
HANDLE hFile;

HANDLE g_hChildStd_IN_Rd = NULL;
HANDLE g_hChildStd_IN_Wr = NULL;
HANDLE g_hChildStd_OUT_Rd = NULL;
HANDLE g_hChildStd_OUT_Wr = NULL;

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

int recvTimeOutTCP(SOCKET socket, long sec, long usec)
{
	// Setup timeval variable
	struct timeval timeout;
	struct fd_set fds;

	// assign the second and microsecond variables
	timeout.tv_sec = sec;
	timeout.tv_usec = usec;
	// Setup fd_set structure
	FD_ZERO(&fds);
	FD_SET(socket, &fds);
	// Possible return values:
	// -1: error occurred
	// 0: timed out
	// > 0: data ready to be read
	return select(0, &fds, 0, 0, &timeout);
}

// https://www.winsocketdotnetworkprogramming.com/winsock2programming/winsock2advancedcode1c.html
int waitConnection(SOCKET ListeningSocket)
{
	SOCKET NewConnection;
	SOCKADDR_IN SenderInfo;
	// Receiving part
	char recvbuff[1024];
	char sendbuff[1024];
	int ByteReceived, i, nlen, SelectTiming, ByteSent;
	
	write2File(hFile, L"Server: listen() during 10s...\n");
	// Set 10 seconds 10 useconds timeout
	SelectTiming = recvTimeOutTCP(ListeningSocket, 10, 10);

	switch (SelectTiming)
	{
	case 0:
		// Timed out, do whatever you want to handle this situation
		write2File(hFile, L"\nServer: Timeout while waiting you retard client!...\n");
		break;

	case -1:
		// Error occurred, more tweaking here and the recvTimeOutTCP()...
		write2File(hFile, L"\nServer: Some error encountered with code number : %ld\n", WSAGetLastError());
		break;

	default:
	{
		// Accept a new connection when available. 'while' always true
		while (1)
		{
			write2File(hFile, L"Server: connexion...\n");
			// Reset the NewConnection socket to SOCKET_ERROR
			// Take note that the NewConnection socket in not listening
			NewConnection = SOCKET_ERROR;
			// While the NewConnection socket equal to SOCKET_ERROR
			// which is always true in this case...
			while (NewConnection == SOCKET_ERROR)
			{
				// Accept connection on the ListeningSocket socket and assign
				// it to the NewConnection socket, let the ListeningSocket
				// do the listening for more connection
				NewConnection = accept(ListeningSocket, NULL, NULL);
				write2File(hFile, L"\nServer: accept() is OK...\n");
				write2File(hFile, L"Server: New client got connected, ready to	receive and send data...\n");

				// At this point you can do two things with these sockets
				// 1. Wait for more connections by calling accept again
				//    on ListeningSocket (loop)
				// 2. Start sending or receiving data on NewConnection.
				ByteReceived = recv(NewConnection, recvbuff, sizeof(recvbuff), 0);

				// When there is data
				if (ByteReceived > 0)
				{
					write2File(hFile, L"Server: recv() looks fine....\n");
					// Some info on the receiver side...
					//getsockname(ListeningSocket, (SOCKADDR *)&ServerAddr, (int *)sizeof(ServerAddr));
					//write2File(hFile, L"Server: Receiving IP(s) used : %s\n", inet_ntoa(ServerAddr.sin_addr));
					//write2File(hFile, L"Server: Receiving port used : %d\n", htons(ServerAddr.sin_port));

					// Some info on the sender side
					// Allocate the required resources
					memset(&SenderInfo, 0, sizeof(SenderInfo));
					nlen = sizeof(SenderInfo);

					getpeername(NewConnection, (SOCKADDR *)&SenderInfo, &nlen);
					write2File(hFile, L"Server: Sending IP used : %hs\n", inet_ntoa(SenderInfo.sin_addr));
					write2File(hFile, L"Server: Sending port used : %d\n", htons(SenderInfo.sin_port));

					// Print the received bytes. Take note that this is the total
					// byte received, it is not the size of the declared buffer
					write2File(hFile, L"Server: Bytes received : %d\n", ByteReceived);
					// Print what those bytes represent
					write2File(hFile, L"Server: Those bytes are : \n");
					// Print the string only, discard other
					// remaining 'rubbish' in the 1024 buffer size
					char *requestMethod = recvbuff;
					char *requestUrl;
					int nbParsedField = 0;
					for (i = 0; i < ByteReceived; i++)
					{
						write2File(hFile, L"%c", recvbuff[i]);
						if (recvbuff[i] == ' ' && nbParsedField < 2)
						{
							recvbuff[i] = '\0';
							nbParsedField++;
							if (nbParsedField == 1)
							{
								requestUrl = recvbuff+i+1;
							}
						}
					}
					write2File(hFile, L"\n");
					write2File(hFile, L"Request Method: %hs\n", requestMethod);
					write2File(hFile, L"Request URL: %hs\n", requestUrl);
					
					if (win32Api.lstrcmpA("/status", requestUrl) == 0)
					{	
						write2File(hFile, L"STATUS OK\n");
						strcpy_s(sendbuff, 1024, "HTTP/1.1 200 OK\nContent-type: application/json\nConnection: Closed\n\n{\"status\": \"OK\"}\n");
						int size = strlen(sendbuff);
						ByteSent = send( NewConnection, sendbuff, size, 0 );
						if (ByteSent == SOCKET_ERROR) {
							write2File(hFile, L"send failed with error: %d\n", WSAGetLastError());
						}
						
					} else if (win32Api.lstrcmpA("/stopService", requestUrl) == 0)
					{	
						write2File(hFile, L"Stopping service...\n");
						SetEvent(g_StopEvent);
						strcpy_s(sendbuff, 1024, "HTTP/1.1 200 OK\nContent-type: application/json\nConnection: Closed\n");
						int size = strlen(sendbuff);
						ByteSent = send( NewConnection, sendbuff, size, 0 );
						if (ByteSent == SOCKET_ERROR) {
							write2File(hFile, L"send failed with error: %d\n", WSAGetLastError());
						}
					}
					
				}
				// No data
				else if (ByteReceived == 0)
					write2File(hFile, L"Server: Connection closed!\n");
				// Others
				else
					write2File(hFile, L"Server: recv() failed with error code : %d\n", WSAGetLastError());
			}

			// Clean up all the send/recv communication, get ready for new one
			if (shutdown(NewConnection, SD_SEND) != 0)
				write2File(hFile, L"\nServer: Well, there is something wrong with the shutdown().The error code : %ld\n", WSAGetLastError());
			else
				write2File(hFile, L"\nServer: shutdown() looks OK...\n");

			// Well, if there is no more connection in 5 seconds,
			// just exit this listening loop...
			write2File(hFile, L"Server: listen() during 5s...\n");
			if (recvTimeOutTCP(ListeningSocket, 5, 0) == 0)
				break;
		}
	}
	}

	return 0;
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

int printCreateProcess(HANDLE accessToken, WCHAR* szCmdline)
{
	SECURITY_ATTRIBUTES saAttr; 
	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES); 
	saAttr.bInheritHandle = TRUE; 
	saAttr.lpSecurityDescriptor = NULL; 
	// Create a pipe for the child process's STDOUT. 
	if (!win32Api.CreatePipe(&g_hChildStd_OUT_Rd, &g_hChildStd_OUT_Wr, &saAttr, 0))
	{
		write2File(hFile, L"StdoutRd CreatePipe %d\n", GetLastError());
		return 1;
	}
	// Ensure the read handle to the pipe for STDOUT is not inherited.
	if (!win32Api.SetHandleInformation(g_hChildStd_OUT_Rd, HANDLE_FLAG_INHERIT, 0))
	{
		write2File(hFile, L"Stdout SetHandleInformation %d\n", GetLastError());
		return 1;
	}
	// Create a pipe for the child process's STDIN. 
	if (!win32Api.CreatePipe(&g_hChildStd_IN_Rd, &g_hChildStd_IN_Wr, &saAttr, 0)) 
	{
		write2File(hFile, L"Stdin CreatePipe %d\n", GetLastError());
		return 1;
	}
	// Ensure the write handle to the pipe for STDIN is not inherited. 
	if (!win32Api.SetHandleInformation(g_hChildStd_IN_Wr, HANDLE_FLAG_INHERIT, 0))
	{
		write2File(hFile, L"Stdin SetHandleInformation %d\n", GetLastError());
		return 1;
	}

	write2File(hFile, L"g_hChildStd_OUT_Rd=0x%08X\n", g_hChildStd_OUT_Rd);
	write2File(hFile, L"g_hChildStd_OUT_Wr=0x%08X\n", g_hChildStd_OUT_Wr);
	write2File(hFile, L"g_hChildStd_IN_Rd=0x%08X\n", g_hChildStd_IN_Rd);
	write2File(hFile, L"g_hChildStd_IN_Wr=0x%08X\n", g_hChildStd_IN_Wr);

	PROCESS_INFORMATION process_INFORMATION = {};
	ZeroMemory(&process_INFORMATION, sizeof(PROCESS_INFORMATION));
	STARTUPINFOW startupinfo = {};
	ZeroMemory(&startupinfo, sizeof(STARTUPINFOW));
	startupinfo.cb = sizeof(STARTUPINFOW); 
	startupinfo.hStdError = g_hChildStd_OUT_Wr;
	startupinfo.hStdOutput = g_hChildStd_OUT_Wr;
	startupinfo.hStdInput = g_hChildStd_IN_Rd;
	startupinfo.dwFlags |= STARTF_USESTDHANDLES;
	
	//WCHAR szCmdline[]=L"C:\\windows\\system32\\WPR.EXE -start CPU.light -filemode";
	// https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc786941(v=ws.10)
	// C:\\DATA\\SHAREDDATA\\PHONETOOLS\\PWTOOLS\\BIN\\WPWPR.EXE
	//if(!win32Api.CreateProcessAsUserW(dupSystemToken, L"C:\\windows\\system32\\OEMSVCHOST.EXE", NULL, NULL, NULL, false, NORMAL_PRIORITY_CLASS, NULL, NULL, &startupinfo, &process_INFORMATION))
	//if(!win32Api.CreateProcessAsUserW(dupSystemToken, L"C:\\windows\\system32\\ALG.EXE", NULL, NULL, NULL, false, NORMAL_PRIORITY_CLASS, NULL, NULL, &startupinfo, &process_INFORMATION))
	//if(!win32Api.CreateProcessAsUserW(dupSystemToken, L"C:\\Data\\USERS\\Public\\Documents\\console.exe", NULL, NULL, NULL, false, NORMAL_PRIORITY_CLASS, NULL, NULL, &startupinfo, &process_INFORMATION))
	if(!win32Api.CreateProcessAsUserW(accessToken, NULL, szCmdline, NULL, NULL, TRUE, NORMAL_PRIORITY_CLASS | CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_CONSOLE, NULL, NULL, &startupinfo, &process_INFORMATION))
	//if(!win32Api.CreateProcessAsUserW(dupSystemToken, L"C:\\windows\\system32\\XbfGenerator.exe", NULL, NULL, NULL, false, NORMAL_PRIORITY_CLASS, NULL, NULL, &startupinfo, &process_INFORMATION))
	{
		write2File(hFile, L"Error CreateProcessAsUserW %d\n", GetLastError());
	}
	write2File(hFile, L"process_INFORMATION.hProcess=0x%08X\n", process_INFORMATION.hProcess);
	write2File(hFile, L"process_INFORMATION.hThread=0x%08X\n", process_INFORMATION.hThread);
	
	if (!win32Api.CloseHandle(g_hChildStd_IN_Wr))
	{
		write2File(hFile, L"StdInWr CloseHandle %d\n", GetLastError());
		return 1;
	}
		
	DWORD count = 0;
	DWORD waitResult = 0;
	do
	{
		count++;
		waitResult = win32Api.WaitForSingleObject(process_INFORMATION.hThread, 1000);
	} while (waitResult == WAIT_TIMEOUT && count < 60);
	write2File(hFile, L"%05d WaitForSingleObject %d (%d=WAIT_TIMEOUT)\n", count, waitResult, WAIT_TIMEOUT);
	DWORD exitCode;
	win32Api.GetExitCodeThread(process_INFORMATION.hThread, &exitCode);
	write2File(hFile, L"Thread exit code: %d (%d=STILL_ACTIVE)\n", exitCode, STILL_ACTIVE);
	win32Api.GetExitCodeProcess(process_INFORMATION.hProcess, &exitCode);
	write2File(hFile, L"Process exit code: %x (%d=STILL_ACTIVE)\n", exitCode, STILL_ACTIVE); // 0xc0000135 = missing dll // 0xc0000005 = memory access violation

	win32Api.CloseHandle(process_INFORMATION.hProcess);
	win32Api.CloseHandle(process_INFORMATION.hThread);
	
	win32Api.CloseHandle(g_hChildStd_OUT_Wr);
	win32Api.CloseHandle(g_hChildStd_IN_Rd);
	
	DWORD dwRead, dwWritten; 
	CHAR chBuf[4096]; 
	ZeroMemory(chBuf, sizeof(chBuf));
	BOOL bSuccess = FALSE;
	write2File(hFile, L"Start reading output\n");
	for (;;) 
	{ 
	  write2File(hFile, L"Start ReadFile\n");
	  bSuccess = win32Api.ReadFile(g_hChildStd_OUT_Rd, chBuf, 4096, &dwRead, NULL);
	  if( ! bSuccess || dwRead == 0 ) break; 
	  write2File(hFile, L"dwRead=%d\n",dwRead);

	  for(DWORD i=0; i<dwRead; i++)
	  {
		CHAR c = chBuf[i];
		if (c >= ' ')
		{
			write2File(hFile, L"%c", c);
		}
		else
		{
			write2File(hFile, L".");
		}
	  }
	} 
	write2File(hFile, L"Stop reading output\n");
	win32Api.CloseHandle(g_hChildStd_OUT_Rd);
	win32Api.CloseHandle(g_hChildStd_IN_Wr);
		
	return 0;
}

void
get_system_privileges(PTOKEN_PRIVILEGES privileges)
{
	//TOKEN_PRIVILEGES privileges;
	LUID luid;

	privileges->PrivilegeCount = 34;

	win32Api.LookupPrivilegeValueW(NULL, L"SeCreateTokenPrivilege", &luid);
	privileges->Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	privileges->Privileges[0].Luid = luid;
	
	win32Api.LookupPrivilegeValueW(NULL, L"SeAssignPrimaryTokenPrivilege", &luid);
	privileges->Privileges[1].Attributes = SE_PRIVILEGE_ENABLED;
	privileges->Privileges[1].Luid = luid;
		
	win32Api.LookupPrivilegeValueW(NULL, L"SeLockMemoryPrivilege", &luid);
	privileges->Privileges[2].Attributes = SE_PRIVILEGE_ENABLED;
	privileges->Privileges[2].Luid = luid;
		
	win32Api.LookupPrivilegeValueW(NULL, L"SeIncreaseQuotaPrivilege", &luid);
	privileges->Privileges[3].Attributes = SE_PRIVILEGE_ENABLED;
	privileges->Privileges[3].Luid = luid;
		
	win32Api.LookupPrivilegeValueW(NULL, L"SeMachineAccountPrivilege", &luid);
	privileges->Privileges[4].Attributes = SE_PRIVILEGE_ENABLED;
	privileges->Privileges[4].Luid = luid;
		
	win32Api.LookupPrivilegeValueW(NULL, L"SeTcbPrivilege", &luid);
	privileges->Privileges[5].Attributes = SE_PRIVILEGE_ENABLED;
	privileges->Privileges[5].Luid = luid;

	win32Api.LookupPrivilegeValueW(NULL, L"SeSecurityPrivilege", &luid);
	privileges->Privileges[6].Attributes = SE_PRIVILEGE_ENABLED;
	privileges->Privileges[6].Luid = luid;
		
	win32Api.LookupPrivilegeValueW(NULL, L"SeTakeOwnershipPrivilege", &luid);
	privileges->Privileges[7].Attributes = SE_PRIVILEGE_ENABLED;
	privileges->Privileges[7].Luid = luid;
		
	win32Api.LookupPrivilegeValueW(NULL, L"SeLoadDriverPrivilege", &luid);
	privileges->Privileges[8].Attributes = SE_PRIVILEGE_ENABLED;
	privileges->Privileges[8].Luid = luid;
		
	win32Api.LookupPrivilegeValueW(NULL, L"SeSystemProfilePrivilege", &luid);
	privileges->Privileges[9].Attributes = SE_PRIVILEGE_ENABLED;
	privileges->Privileges[9].Luid = luid;
			
	win32Api.LookupPrivilegeValueW(NULL, L"SeSystemtimePrivilege", &luid);
	privileges->Privileges[10].Attributes = SE_PRIVILEGE_ENABLED;
	privileges->Privileges[10].Luid = luid;
		
	win32Api.LookupPrivilegeValueW(NULL, L"SeProfileSingleProcessPrivilege", &luid);
	privileges->Privileges[11].Attributes = SE_PRIVILEGE_ENABLED;
	privileges->Privileges[11].Luid = luid;
		
	win32Api.LookupPrivilegeValueW(NULL, L"SeIncreaseBasePriorityPrivilege", &luid);
	privileges->Privileges[12].Attributes = SE_PRIVILEGE_ENABLED;
	privileges->Privileges[12].Luid = luid;
		
	win32Api.LookupPrivilegeValueW(NULL, L"SeCreatePagefilePrivilege", &luid);
	privileges->Privileges[13].Attributes = SE_PRIVILEGE_ENABLED;
	privileges->Privileges[13].Luid = luid;
		
	win32Api.LookupPrivilegeValueW(NULL, L"SeCreatePermanentPrivilege", &luid);
	privileges->Privileges[14].Attributes = SE_PRIVILEGE_ENABLED;
	privileges->Privileges[14].Luid = luid;
		
	win32Api.LookupPrivilegeValueW(NULL, L"SeBackupPrivilege", &luid);
	privileges->Privileges[15].Attributes = SE_PRIVILEGE_ENABLED;
	privileges->Privileges[15].Luid = luid;
		
	win32Api.LookupPrivilegeValueW(NULL, L"SeRestorePrivilege", &luid);
	privileges->Privileges[16].Attributes = SE_PRIVILEGE_ENABLED;
	privileges->Privileges[16].Luid = luid;
		
	win32Api.LookupPrivilegeValueW(NULL, L"SeShutdownPrivilege", &luid);
	privileges->Privileges[17].Attributes = SE_PRIVILEGE_ENABLED;
	privileges->Privileges[17].Luid = luid;
		
	win32Api.LookupPrivilegeValueW(NULL, L"SeDebugPrivilege", &luid);
	privileges->Privileges[18].Attributes = SE_PRIVILEGE_ENABLED;
	privileges->Privileges[18].Luid = luid;
		
	win32Api.LookupPrivilegeValueW(NULL, L"SeAuditPrivilege", &luid);
	privileges->Privileges[19].Attributes = SE_PRIVILEGE_ENABLED;
	privileges->Privileges[19].Luid = luid;
			
	win32Api.LookupPrivilegeValueW(NULL, L"SeSystemEnvironmentPrivilege", &luid);
	privileges->Privileges[20].Attributes = SE_PRIVILEGE_ENABLED;
	privileges->Privileges[20].Luid = luid;
		
	win32Api.LookupPrivilegeValueW(NULL, L"SeChangeNotifyPrivilege", &luid);
	privileges->Privileges[21].Attributes = SE_PRIVILEGE_ENABLED;
	privileges->Privileges[21].Luid = luid;
		
	win32Api.LookupPrivilegeValueW(NULL, L"SeRemoteShutdownPrivilege", &luid);
	privileges->Privileges[22].Attributes = SE_PRIVILEGE_ENABLED;
	privileges->Privileges[22].Luid = luid;
		
	win32Api.LookupPrivilegeValueW(NULL, L"SeUndockPrivilege", &luid);
	privileges->Privileges[23].Attributes = SE_PRIVILEGE_ENABLED;
	privileges->Privileges[23].Luid = luid;
		
	win32Api.LookupPrivilegeValueW(NULL, L"SeSyncAgentPrivilege", &luid);
	privileges->Privileges[24].Attributes = SE_PRIVILEGE_ENABLED;
	privileges->Privileges[24].Luid = luid;
		
	win32Api.LookupPrivilegeValueW(NULL, L"SeEnableDelegationPrivilege", &luid);
	privileges->Privileges[25].Attributes = SE_PRIVILEGE_ENABLED;
	privileges->Privileges[25].Luid = luid;
		
	win32Api.LookupPrivilegeValueW(NULL, L"SeManageVolumePrivilege", &luid);
	privileges->Privileges[26].Attributes = SE_PRIVILEGE_ENABLED;
	privileges->Privileges[26].Luid = luid;
		
	win32Api.LookupPrivilegeValueW(NULL, L"SeImpersonatePrivilege", &luid);
	privileges->Privileges[27].Attributes = SE_PRIVILEGE_ENABLED;
	privileges->Privileges[27].Luid = luid;
		
	win32Api.LookupPrivilegeValueW(NULL, L"SeCreateGlobalPrivilege", &luid);
	privileges->Privileges[28].Attributes = SE_PRIVILEGE_ENABLED;
	privileges->Privileges[28].Luid = luid;
		
	win32Api.LookupPrivilegeValueW(NULL, L"SeTrustedCredManAccessPrivilege", &luid);
	privileges->Privileges[29].Attributes = SE_PRIVILEGE_ENABLED;
	privileges->Privileges[29].Luid = luid;

	//ok
			
	win32Api.LookupPrivilegeValueW(NULL, L"SeRelabelPrivilege", &luid);
	privileges->Privileges[30].Attributes = SE_PRIVILEGE_ENABLED;
	privileges->Privileges[30].Luid = luid;
		
	win32Api.LookupPrivilegeValueW(NULL, L"SeIncreaseWorkingSetPrivilege", &luid);
	privileges->Privileges[31].Attributes = SE_PRIVILEGE_ENABLED;
	privileges->Privileges[31].Luid = luid;
		
	win32Api.LookupPrivilegeValueW(NULL, L"SeTimeZonePrivilege", &luid);
	privileges->Privileges[32].Attributes = SE_PRIVILEGE_ENABLED;
	privileges->Privileges[32].Luid = luid;
		
	win32Api.LookupPrivilegeValueW(NULL, L"SeCreateSymbolicLinkPrivilege", &luid);
	privileges->Privileges[33].Attributes = SE_PRIVILEGE_ENABLED;
	privileges->Privileges[33].Luid = luid;
	
	// nok:	
	// win32Api.LookupPrivilegeValueW(NULL, L"SeUnsolicitedInputPrivilege", &luid);
	// privileges->Privileges[34].Attributes = SE_PRIVILEGE_ENABLED;
	// privileges->Privileges[34].Luid = luid;	
}

PVOID
GetInfoFromToken(HANDLE current_token, TOKEN_INFORMATION_CLASS tic)
{
	DWORD n;
	PVOID data;

	if (!win32Api.GetTokenInformation(current_token, tic, 0, 0, &n) && GetLastError() != ERROR_INSUFFICIENT_BUFFER)
		return 0;

	data = (PVOID)malloc(n);

	if (win32Api.GetTokenInformation(current_token, tic, data, n, &n))
		return data;
	else
		free(data);

	return 0;
}

// see https://github.com/hatRiot/token-priv/blob/master/poptoke/poptoke/SeCreateTokenPrivilege.cpp
HANDLE
se_create_token_privilege(HANDLE base_token, BOOL isPrimary)
{
	LUID luid;
	PLUID pluidAuth;
	NTSTATUS ntStatus;
	LARGE_INTEGER li;
	PLARGE_INTEGER pli;
	DWORD sessionId;
	_TOKEN_TYPE token_type = isPrimary ? TokenPrimary : TokenImpersonation;

	HANDLE elevated_token;
	PTOKEN_STATISTICS stats;
	PTOKEN_PRIVILEGES privileges;
	PTOKEN_OWNER owner;
	PTOKEN_PRIMARY_GROUP primary_group;
	PTOKEN_DEFAULT_DACL default_dacl;
	PTOKEN_GROUPS groups;
	SECURITY_QUALITY_OF_SERVICE sqos = { sizeof(sqos), SecurityImpersonation, SECURITY_STATIC_TRACKING, FALSE };
	OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, 0, 0, 0, &sqos };
	SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
	PSID_AND_ATTRIBUTES pSid;
	PISID pSidSingle;
	TOKEN_USER userToken;
	TOKEN_SOURCE sourceToken = { { '!', '!', '!', '!', '!', '!', '!', '!' }, { 0, 0 } };
	PSID lpSidOwner = NULL;
	LUID authid = SYSTEM_LUID;

	SID_BUILTIN TkSidLocalAdminGroup = { 1, 2, { 0, 0, 0, 0, 0, 5 }, { 32, DOMAIN_ALIAS_RID_ADMINS } };
	SID_INTEGRITY IntegritySIDHigh = { 1, 1, SECURITY_MANDATORY_LABEL_AUTHORITY, SECURITY_MANDATORY_HIGH_RID };
	SID_INTEGRITY IntegritySIDSystem = { 1, 1, SECURITY_MANDATORY_LABEL_AUTHORITY, SECURITY_MANDATORY_SYSTEM_RID };
	SID_INTEGRITY IntegritySIDMedium = { 1, 1, SECURITY_MANDATORY_LABEL_AUTHORITY, SECURITY_MANDATORY_MEDIUM_RID };

	if (win32Api.ZwCreateToken == NULL){
		write2File(hFile,L"[-] Failed to load ZwCreateToken: %d\n", GetLastError());
		return NULL;
	}

	DWORD dwBufferSize = 0;
	PTOKEN_USER user;
	user = (PTOKEN_USER)GetInfoFromToken(base_token, TokenUser);

	win32Api.AllocateAndInitializeSid(&nt, 1, SECURITY_LOCAL_SYSTEM_RID,
		0, 0, 0, 0, 0, 0, 0, &lpSidOwner);

	userToken.User.Sid = lpSidOwner;
	userToken.User.Attributes = 0;

	win32Api.AllocateLocallyUniqueId(&luid);
	sourceToken.SourceIdentifier.LowPart = luid.LowPart;
	sourceToken.SourceIdentifier.HighPart = luid.HighPart;

	stats = (PTOKEN_STATISTICS)GetInfoFromToken(base_token, TokenStatistics);
	privileges = (PTOKEN_PRIVILEGES)win32Api.LocalAlloc(LMEM_FIXED, sizeof(TOKEN_PRIVILEGES) + (sizeof(LUID_AND_ATTRIBUTES) * 35));
	get_system_privileges(privileges);
	groups = (PTOKEN_GROUPS)GetInfoFromToken(base_token, TokenGroups);
	primary_group = (PTOKEN_PRIMARY_GROUP)GetInfoFromToken(base_token, TokenPrimaryGroup);
	default_dacl = (PTOKEN_DEFAULT_DACL)GetInfoFromToken(base_token, TokenDefaultDacl);

	pSid = groups->Groups;
	for (int i = 0; i < groups->GroupCount; ++i, pSid++)
	{
		// change IL
		if (pSid->Attributes & SE_GROUP_INTEGRITY)
			//memcpy(pSid->Sid, &IntegritySIDMedium, sizeof(IntegritySIDMedium));
			memcpy(pSid->Sid, &IntegritySIDSystem, sizeof(IntegritySIDSystem));

		PISID piSid = (PISID)pSid->Sid;
		if (piSid->SubAuthority[piSid->SubAuthorityCount - 1] == DOMAIN_ALIAS_RID_USERS){
			// found RID_USERS membership, overwrite with RID_ADMINS
			memcpy(piSid, &TkSidLocalAdminGroup, sizeof(TkSidLocalAdminGroup));
			pSid->Attributes = SE_GROUP_ENABLED;
		}
		else {
			pSid->Attributes &= ~SE_GROUP_USE_FOR_DENY_ONLY;
			pSid->Attributes &= ~SE_GROUP_ENABLED;
		}
	}

	owner = (PTOKEN_OWNER)win32Api.LocalAlloc(LPTR, sizeof(PSID));
	owner->Owner = user->User.Sid;
	//owner->Owner = GetLocalSystemSID();

	pluidAuth = &authid;
	li.LowPart = 0xFFFFFFFF;
	li.HighPart = 0xFFFFFFFF;
	pli = &li;
	ntStatus = win32Api.ZwCreateToken(&elevated_token,
		TOKEN_ALL_ACCESS,
		&oa,
		token_type,
		pluidAuth,
		pli,
		user,
		//&userToken,
		groups,
		privileges,
		owner,
		primary_group,
		default_dacl,
		&sourceToken // creates an anonymous impersonation token
		);

	if (ntStatus == STATUS_SUCCESS)
		return elevated_token;
	else
		write2File(hFile,L"[-] Failed to create new token: %d %08x\n", GetLastError(), ntStatus);

	win32Api.FreeSid(lpSidOwner);
	if (stats) win32Api.LocalFree(stats);
	if (groups) win32Api.LocalFree(groups);
	if (privileges) win32Api.LocalFree(privileges);
	return NULL;
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
		write2File(hFile, L"************ updated dupSystemToken=0x%08X information:\n", dupSystemToken);
		printAccessTokenInfo(dupSystemToken);
		
		//https://github.com/hatRiot/token-priv/blob/master/poptoke/poptoke/SeCreateTokenPrivilege.cpp
		write2File(hFile, L"se_create_token_privilege....\n");
		HANDLE createdToken = se_create_token_privilege(hCurrentProcessToken, TRUE);
		write2File(hFile, L"************ createdToken=0x%08X information:\n", createdToken);
		printAccessTokenInfo(createdToken);
		
		WCHAR szCmdline1[]=L"C:\\windows\\system32\\WPR.EXE -start CPU.light -filemode";
		printCreateProcess(createdToken, szCmdline1);
		
		WCHAR szCmdline2[]=L"C:\\windows\\system32\\WPR.EXE -stop C:\\Data\\USERS\\Public\\Documents\\wpr.etl";
		printCreateProcess(createdToken, szCmdline2);
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
	write2File(hFile, L"Begin ServiceMain wp81service.\n");
	
	// Must be called at start.
	g_ServiceStatusHandle = win32Api.RegisterServiceCtrlHandlerExW(L"Service test", &HandlerEx, NULL);

	// Startup code.
	ReportStatus(SERVICE_START_PENDING);
	g_StopEvent = win32Api.CreateEventW(NULL, TRUE, FALSE, NULL);
	/* Here initialize service...
	Load configuration, acquire resources etc. */
	ReportStatus(SERVICE_RUNNING);

	WSADATA            wsaData;
	SOCKET             ListeningSocket;
	SOCKADDR_IN        ServerAddr;
	int                Port = 7171;

	// Initialize Winsock version 2.2
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
	{
		// The WSAGetLastError() function is one of the only functions
		// in the Winsock 2.2 DLL that can be called in the case of a WSAStartup failure
		write2File(hFile, L"Server: WSAStartup failed with error %ld.\n", WSAGetLastError());
	}
	else
	{
		write2File(hFile, L"Server: The Winsock DLL found!\n");
		write2File(hFile, L"Server: The current status is %hs.\n", wsaData.szSystemStatus);
		
		if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2)
		{
			//Tell the user that we could not find a usable WinSock DLL
			write2File(hFile, L"Server: The dll do not support the Winsock version %u.%u!\n",LOBYTE(wsaData.wVersion), HIBYTE(wsaData.wVersion));
			// Do the clean up
			WSACleanup();
		}
		else
		{
			write2File(hFile, L"Server: The dll supports the Winsock version %u.%u!\n", LOBYTE(wsaData.wVersion), HIBYTE(wsaData.wVersion));
			write2File(hFile, L"Server: The highest version this dll can support is %u.%u\n", LOBYTE(wsaData.wHighVersion), HIBYTE(wsaData.wHighVersion));
			
			// Create a new socket to listen for client connections.
			ListeningSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

			// Check for errors to ensure that the socket is a valid socket.
			if (ListeningSocket == INVALID_SOCKET)
			{
				write2File(hFile, L"Server: Error at socket(), error code : %ld.\n", WSAGetLastError());
				// Clean up
				WSACleanup();
			}
			else
			{
				write2File(hFile, L"Server: socket() is OK!\n");
				// Set up a SOCKADDR_IN structure that will tell bind that we
				// want to listen for connections on all interfaces using port 7171.

				// The IPv4 family
				ServerAddr.sin_family = AF_INET;
				// host-to-network byte order
				ServerAddr.sin_port = htons(Port);
				// Listen on all interface, host-to-network byte order
				ServerAddr.sin_addr.s_addr = htonl(INADDR_ANY);

				// Associate the address information with the socket using bind.
				// Call the bind function, passing the created socket and the sockaddr_in
				// structure as parameters. Check for general errors.
				if (bind(ListeningSocket, (SOCKADDR *)&ServerAddr, sizeof(ServerAddr)) == SOCKET_ERROR)
				{
					write2File(hFile, L"Server: bind() failed!Error code : %ld.\n", WSAGetLastError());
					// Close the socket
					closesocket(ListeningSocket);
					// Do the clean up
					WSACleanup();
				}
				else
				{
					write2File(hFile, L"Server: bind() is OK!\n");
					// Listen for client connections with a backlog of 5
					if (listen(ListeningSocket, 5) == SOCKET_ERROR)
					{
						write2File(hFile, L"Server: listen() : Error listening on socket %ld.\n", WSAGetLastError());
						// Close the socket
						closesocket(ListeningSocket);
						// Do the clean up
						WSACleanup();
					}
					else
					{
						write2File(hFile, L"Server: listen() is OK, I'm listening for connections...\n");

						/* Main service code
						Loop, do some work,
						wait or poll for g_StopEvent... */
						DWORD count = 0;
						while (win32Api.WaitForSingleObject(g_StopEvent, 500) != WAIT_OBJECT_0) // && count++ < 3)
						{
							waitConnection(ListeningSocket);
							//test(TRUE);
						}						
						
						write2File(hFile, L"\nServer: The listening socket is timeout...\n");
						// When all the data communication and listening finished, close the socket
						if (closesocket(ListeningSocket) != 0)
							write2File(hFile, L"Server: Cannot close ListeningSocket socket.Error code : %ld\n", WSAGetLastError());
						else
							write2File(hFile, L"Server: Closing ListeningSocket socket...\n");

						// Finally and optionally, clean up all those WSA setup
						if (WSACleanup() != 0)
							write2File(hFile, L"Server: WSACleanup() failed!Error code : %ld\n", WSAGetLastError());
						else
							write2File(hFile, L"Server: WSACleanup() is OK...\n");
						
					}
				}
			}
		}
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
	hFile = win32Api.CreateFileW(L"C:\\Data\\USERS\\Public\\Documents\\wp81service.log",                // name of the write
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
	test(FALSE);
	win32Api.CloseHandle(hFile);
	return 2;
}