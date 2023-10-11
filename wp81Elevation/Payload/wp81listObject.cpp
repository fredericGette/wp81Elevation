#include <stdio.h>
#include <stdlib.h>
#include "Win32Api.h"

#define ARRAY_SIZE 1024

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

VOID GetDevicePropertiesCfgmgr32(VOID)
{
    CONFIGRET cr = CR_SUCCESS;
    PWSTR DeviceList = NULL;
    ULONG DeviceListLength = 0;
    PWSTR CurrentDevice;
    DEVINST Devinst;
    WCHAR DeviceDesc[2048];
    DEVPROPTYPE PropertyType;
    ULONG PropertySize;
    DWORD Index = 0;

    cr = win32Api.CM_Get_Device_ID_List_SizeW(&DeviceListLength,
                                    NULL,
                                    CM_GETIDLIST_FILTER_PRESENT);

    if (cr != CR_SUCCESS)
    {
        goto Exit;
    }

    DeviceList = (PWSTR)HeapAlloc(GetProcessHeap(),
                                  HEAP_ZERO_MEMORY,
                                  DeviceListLength * sizeof(WCHAR));

    if (DeviceList == NULL) {
        goto Exit;
    }

    cr = win32Api.CM_Get_Device_ID_ListW(NULL,
                               DeviceList,
                               DeviceListLength,
                               CM_GETIDLIST_FILTER_PRESENT);

    if (cr != CR_SUCCESS)
    {
        goto Exit;
    }

    for (CurrentDevice = DeviceList;
         *CurrentDevice;
         CurrentDevice += wcslen(CurrentDevice) + 1)
    {
		log2File(hLogFile,L"%d Device: %s | ", Index, CurrentDevice);

        // If the list of devices also includes non-present devices,
        // CM_LOCATE_DEVNODE_PHANTOM should be used in place of
        // CM_LOCATE_DEVNODE_NORMAL.
        cr = win32Api.CM_Locate_DevNodeW(&Devinst,
                               CurrentDevice,
                               CM_LOCATE_DEVNODE_NORMAL);

        if (cr != CR_SUCCESS)
        {
            goto Exit;
        }

        // Query a property on the device.  For example, the device description.
        PropertySize = sizeof(DeviceDesc);
        cr = win32Api.CM_Get_DevNode_PropertyW(Devinst, &DEVPKEY_Device_DeviceDesc, &PropertyType, (PBYTE)DeviceDesc, &PropertySize, 0);
        if (cr == CR_SUCCESS && PropertyType == DEVPROP_TYPE_STRING)
        {
            log2File(hLogFile,L"DeviceDesc: %s | ", DeviceDesc);
        }
		
		
        PropertySize = sizeof(DeviceDesc);
        cr = win32Api.CM_Get_DevNode_PropertyW(Devinst, &DEVPKEY_Device_Driver, &PropertyType, (PBYTE)DeviceDesc, &PropertySize, 0);
		if (cr == CR_SUCCESS && PropertyType == DEVPROP_TYPE_STRING)
        {
            log2File(hLogFile,L"Driver: %s | ", DeviceDesc);
        }

        PropertySize = sizeof(DeviceDesc);
        cr = win32Api.CM_Get_DevNode_PropertyW(Devinst, &DEVPKEY_Device_PDOName, &PropertyType, (PBYTE)DeviceDesc, &PropertySize, 0);
		if (cr == CR_SUCCESS && PropertyType == DEVPROP_TYPE_STRING)
        {
            log2File(hLogFile,L"PDOName: %s | ", DeviceDesc);
        }

        PropertySize = sizeof(DeviceDesc);
        cr = win32Api.CM_Get_DevNode_PropertyW(Devinst, &DEVPKEY_Device_EnumeratorName, &PropertyType, (PBYTE)DeviceDesc, &PropertySize, 0);
		if (cr == CR_SUCCESS && PropertyType == DEVPROP_TYPE_STRING)
        {
            log2File(hLogFile,L"EnumeratorName: %s | ", DeviceDesc);
        }

        PropertySize = sizeof(DeviceDesc);
        cr = win32Api.CM_Get_DevNode_PropertyW(Devinst, &DEVPKEY_Device_Parent, &PropertyType, (PBYTE)DeviceDesc, &PropertySize, 0);
		if (cr == CR_SUCCESS && PropertyType == DEVPROP_TYPE_STRING)
        {
            log2File(hLogFile,L"Parent: %s | ", DeviceDesc);
        }

		log2File(hLogFile,L"\n");

		
        Index++;
    }

  Exit:

    if (DeviceList != NULL)
    {
        HeapFree(GetProcessHeap(),
                 0,
                 DeviceList);
    }

    return;
}

void listDeviceDrivers()
{
	LPVOID drivers[ARRAY_SIZE];
	DWORD cbNeeded;
	int cDrivers, i;

	if (win32Api.EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded < sizeof(drivers))
	{
		TCHAR szDriver[ARRAY_SIZE];

		cDrivers = cbNeeded / sizeof(drivers[0]);

		log2File(hLogFile,L"There are %d drivers:\n", cDrivers);
		for (i = 0; i < cDrivers; i++)
		{
			if (win32Api.GetDeviceDriverBaseNameW(drivers[i], szDriver, sizeof(szDriver) / sizeof(szDriver[0])))
			{
				log2File(hLogFile,L"%d: %s\n", i + 1, szDriver);
			}
		}
	}
	else
	{
		log2File(hLogFile,L"EnumDeviceDrivers error: %d\n", GetLastError());
		log2File(hLogFile,L"EnumDeviceDrivers failed; array size needed is %d\n", cbNeeded / sizeof(LPVOID));
	}
}

void listServiceDrivers()
{
	SC_HANDLE hSCManager;
	LPENUM_SERVICE_STATUS_PROCESSW services;
    DWORD size, i, count, resume;
	
	hSCManager = win32Api.OpenSCManagerW(NULL,NULL,SC_MANAGER_ALL_ACCESS);
	if (NULL == hSCManager) 
    {
		log2File(hLogFile,L"OpenSCManager failed (%d)\n", GetLastError());
        return;
    }
	
	win32Api.EnumServicesStatusExW(hSCManager, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER, SERVICE_STATE_ALL, NULL, 0, &size, &count, NULL, NULL);
    if(GetLastError() != ERROR_MORE_DATA)
    {
        log2File(hLogFile,L"First call to EnumServicesStatusExW failed (%d)\n", GetLastError());
        goto end;
    }
    services = (LPENUM_SERVICE_STATUS_PROCESSW)HeapAlloc(GetProcessHeap(), 0, size);
    resume = 0;
    if(!win32Api.EnumServicesStatusExW(hSCManager, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER, SERVICE_STATE_ALL, (LPBYTE)services, size, &size, &count, &resume, NULL))
    {
		log2File(hLogFile,L"Second call to EnumServicesStatusExW failed (%d)\n", GetLastError());
        goto end;
    }

	log2File(hLogFile,L"Found %d service drivers\n",count);

    for(i = 0; i < count; i++)
    {
       log2File(hLogFile,L"service=%s %s type=%d (1=kernel driver; 2=file system driver) state=%d (1=stopped; 4=running) controls=%x (1=can be stopped)\n",
				   services[i].lpServiceName,
                   services[i].lpDisplayName,
				   services[i].ServiceStatusProcess.dwServiceType,
                   services[i].ServiceStatusProcess.dwCurrentState,
                   services[i].ServiceStatusProcess.dwControlsAccepted);
    }
	
end:
	win32Api.CloseServiceHandle(hSCManager);
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
	
	listDeviceDrivers();
	
	GetDevicePropertiesCfgmgr32();
	
	listServiceDrivers();
	
	
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
