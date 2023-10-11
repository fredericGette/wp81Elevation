#include <stdio.h>
#include <stdlib.h>
#include "Win32Api.h"

Win32Api win32Api;

void listServiceDrivers()
{
	SC_HANDLE hSCManager;
	LPENUM_SERVICE_STATUS_PROCESSW services;
    DWORD size, i, count, resume;
	
	hSCManager = win32Api.OpenSCManagerW(NULL,NULL,SC_MANAGER_ALL_ACCESS);
	if (NULL == hSCManager) 
    {
		printf("OpenSCManager failed (%d)\n", GetLastError());
        return;
    }
	
	win32Api.EnumServicesStatusExW(hSCManager, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER, SERVICE_STATE_ALL, NULL, 0, &size, &count, NULL, NULL);
    if(GetLastError() != ERROR_MORE_DATA)
    {
		printf("First call to EnumServicesStatusExW failed (%d)\n", GetLastError());
        goto end;
    }
    services = (LPENUM_SERVICE_STATUS_PROCESSW)HeapAlloc(GetProcessHeap(), 0, size);
    resume = 0;
    if(!win32Api.EnumServicesStatusExW(hSCManager, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER, SERVICE_STATE_ALL, (LPBYTE)services, size, &size, &count, &resume, NULL))
    {
		printf("Second call to EnumServicesStatusExW failed (%d)\n", GetLastError());
        goto end;
    }

	printf("Found %d service drivers\n",count);

    for(i = 0; i < count; i++)
    {
		printf("service=%S %S type=", services[i].lpServiceName, services[i].lpDisplayName);
		switch(services[i].ServiceStatusProcess.dwServiceType)
		{
			case 1:
				printf("SERVICE_KERNEL_DRIVER");
				break;
			case 2:
				printf("SERVICE_FILE_SYSTEM_DRIVER");
				break;
			default:
				printf("unkown(%x)", services[i].ServiceStatusProcess.dwServiceType);
		}
		printf(" state=");
		switch(services[i].ServiceStatusProcess.dwCurrentState)
		{
			case 1:
				printf("SERVICE_STOPPED");
				break;
			case 4:
				printf("SERVICE_RUNNING");
				break;
			default:
				printf("unkown(%x)", services[i].ServiceStatusProcess.dwCurrentState);
		}	
		printf(" controls=");	
		switch(services[i].ServiceStatusProcess.dwControlsAccepted)
		{
			case 1:
				printf("SERVICE_ACCEPT_STOP");
				break;
			default:
				printf("unkown(%x)", services[i].ServiceStatusProcess.dwControlsAccepted);
		}	
		printf("\n");			
    }
	
end:
	win32Api.CloseServiceHandle(hSCManager);
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow)
{	
	
	listServiceDrivers();

	return 0;
}
