#include <stdio.h>
#include <stdlib.h>
#include "Win32Api.h"

Win32Api win32Api;
HANDLE hLogFile;

void log2File(HANDLE hFile, WCHAR* format, ...)
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

// https://stackoverflow.com/a/44444972
int PrintDirectoryObjects(WCHAR* directoryName)
{
	log2File(hLogFile,L"Begin PrintDirectoryObjects\n");
	log2File(hLogFile,L"[%s]\n",directoryName);
    NTSTATUS ntStatus;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING objname;
    HANDLE hDeviceDir = NULL;
    RtlInitUnicodeString(&objname, directoryName);
    InitializeObjectAttributes(&oa, &objname, 0, NULL, NULL);
    ntStatus = NtOpenDirectoryObject(&hDeviceDir, DIRECTORY_QUERY | DIRECTORY_TRAVERSE, &oa);
    if(NT_SUCCESS(ntStatus))
    {
        size_t const bufSize = 0x10000;
        BYTE buf[bufSize] = {0};
        ULONG start = 0, idx = 0, bytes;
        BOOLEAN restart = TRUE;
        for(;;)
        {
            ntStatus = NtQueryDirectoryObject(hDeviceDir, PBYTE(buf), bufSize, FALSE, restart, &idx, &bytes);
            if(NT_SUCCESS(ntStatus))
            {
                POBJECT_DIRECTORY_INFORMATION const pdilist = reinterpret_cast<POBJECT_DIRECTORY_INFORMATION>(PBYTE(buf));
                for(ULONG i = 0; i < idx - start; i++)
                {
					log2File(hLogFile,L"%s %s\n", pdilist[i].TypeName.Buffer, pdilist[i].Name.Buffer);
					printf("%S %S\n", pdilist[i].TypeName.Buffer, pdilist[i].Name.Buffer);
                }
            }
            if(STATUS_MORE_ENTRIES == ntStatus)
            {
                start = idx;
                restart = FALSE;
                continue;
            }
            if((STATUS_SUCCESS == ntStatus) || (STATUS_NO_MORE_ENTRIES == ntStatus))
            {
                break;
            }
        }
		win32Api.CloseHandle(hDeviceDir);
		log2File(hLogFile,L"End PrintDirectoryObjects\n");
        return 0;
    }
    log2File(hLogFile,L"Failed NtOpenDirectoryObject with 0x%08X\n", ntStatus);
    return 1;
}



int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow)
{	
	hLogFile = win32Api.CreateFileW(L"C:\\Data\\USERS\\Public\\Documents\\wp81listObject.log",
		GENERIC_WRITE,
		FILE_SHARE_READ,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (hLogFile == INVALID_HANDLE_VALUE)
	{
		return 1;
	}

	log2File(hLogFile, L"Begin wp81listObject\n");
	
	size_t cmdLineSize = wcslen(pCmdLine);
	printf("Command Line: %S (%d)\n", pCmdLine, cmdLineSize);
	
	if (cmdLineSize > 0)
	{
		PrintDirectoryObjects(pCmdLine);
	}
	else
	{
		printf("No parameter!\n");
	}
	
	//PrintDirectoryObjects(L"\\Device");
	//PrintDirectoryObjects(L"\\Driver");
	//PrintDirectoryObjects(L"\\GLOBAL\?\?");
	
	log2File(hLogFile, L"End wp81listObject\n");
	
	win32Api.CloseHandle(hLogFile);	

	return 0;
}
