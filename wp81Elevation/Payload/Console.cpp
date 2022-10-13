//Visual Studio 2012 ARM Phone Tools Command Prompt:
// cl.exe /c /ZW:nostdlib /EHsc /D "PSAPI_VERSION=2" /D "WINAPI_FAMILY=WINAPI_FAMILY_PHONE_APP" /D "_UITHREADCTXT_SUPPORT=0" /D "_UNICODE" /D "UNICODE" /D "_DEBUG" /MDd Console.cpp
// LINK.exe /LIBPATH:"C:\Program Files (x86)\Windows Phone Kits\8.1\lib\ARM" /MANIFEST:NO "WindowsPhoneCore.lib" "RuntimeObject.lib" "PhoneAppModelHost.lib" /DEBUG /MACHINE:ARM /NODEFAULTLIB:"kernel32.lib" /NODEFAULTLIB:"ole32.lib" /WINMD /SUBSYSTEM:WINDOWS console.obj
//

#include <stdio.h>
#include <stdlib.h>
#include <wtypes.h>
#include <malloc.h>
#include <WinError.h>
#include "Win32Api.h"


Win32Api win32Api;
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

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow)
{
	hFile = win32Api.CreateFileW(L"C:\\Data\\USERS\\Public\\Documents\\console.log",                // name of the write
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
	
	write2File(hFile, L"pCmdLine=%ls\n", pCmdLine);
	
	WCHAR text[] = L"Hello, World!";

	if ( win32Api.AllocConsole() == TRUE )
	{
		write2File(hFile, L"AllocConsole.\n");
		
		HANDLE hStdOutput = win32Api.GetStdHandle(STD_OUTPUT_HANDLE);
		write2File(hFile, L"hStdOutput=0x%08X\n", hStdOutput);
		
		if(!win32Api.WriteConsoleW(hStdOutput, text, 13, NULL, NULL))
		{
			write2File(hFile, L"WriteConsoleW error %d\n", GetLastError());
		}
		// win32Api.WriteFile(hStdOutput, text, 26, NULL, NULL);
		
		write2File(hFile, L"WriteConsoleW.\n");

		win32Api.FreeConsole();
		
		write2File(hFile, L"FreeConsole.\n");
	}
	else
	{
		write2File(hFile, L"AllocConsole error %d\n", GetLastError());
	}
	
	win32Api.CloseHandle(hFile);
	return 0;
}