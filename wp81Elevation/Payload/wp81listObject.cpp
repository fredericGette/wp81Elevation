#include <stdio.h>
#include <stdlib.h>
#include "Win32Api.h"

#define ARRAY_SIZE 1024

Win32Api win32Api;

void debug(WCHAR* format, ...)
{
	va_list args;
	va_start(args, format);

	WCHAR buffer[1000];
	_vsnwprintf_s(buffer, sizeof(buffer), format, args);

	OutputDebugStringW(buffer);

	va_end(args);
}

// https://stackoverflow.com/a/44444972
int PrintDirectoryObjects(WCHAR* directoryName)
{
	debug(L"Begin PrintDirectoryObjects\n");
	debug(L"[%s]\n",directoryName);
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
					printf("%S %S ", pdilist[i].TypeName.Buffer, pdilist[i].Name.Buffer);
					
					
					if(0 == wcsncmp((PWCHAR)(pdilist[i].TypeName.Buffer), L"SymbolicLink", pdilist[i].TypeName.Length / sizeof(WCHAR)))
                    {
						HANDLE hLink = NULL;
						InitializeObjectAttributes(&oa, &(pdilist[i].Name), OBJ_CASE_INSENSITIVE, hDeviceDir, NULL);
						ntStatus = NtOpenSymbolicLinkObject(&hLink, SYMBOLIC_LINK_QUERY, &oa);
						if(!NT_SUCCESS(ntStatus) || (hLink == NULL))
						{
							continue;
						}
						printf(" -> ");
						
						USHORT Buffer[256];
						ZeroMemory(Buffer, sizeof(Buffer));
						UNICODE_STRING InfoString;
						InfoString.Buffer = Buffer;
						InfoString.Length = 0xf;
						InfoString.MaximumLength = 256;
						ntStatus = NtQuerySymbolicLinkObject(hLink, &InfoString, NULL);
						if(NT_SUCCESS(ntStatus))
						{
							printf("%S", InfoString.Buffer);
						}
						win32Api.CloseHandle(hLink);
					}
					
					printf("\n");
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
		debug(L"End PrintDirectoryObjects\n");
        return 0;
    }
    debug(L"Failed NtOpenDirectoryObject with 0x%08X\n", ntStatus);
    return 1;
}


int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow)
{	

	debug(L"Begin wp81listObject\n");
		
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
	
	debug(L"End wp81listObject\n");

	return 0;
}
