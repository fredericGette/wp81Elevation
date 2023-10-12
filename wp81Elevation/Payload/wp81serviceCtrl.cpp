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
		printf("serviceName=%S displayName=%S type=", services[i].lpServiceName, services[i].lpDisplayName);
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

void stopServiceDriver(PWSTR driverName)
{
	SC_HANDLE hSCManager;
	SC_HANDLE hSc;
	SERVICE_STATUS_PROCESS ssp;
	
	printf("Try to stop driver [%S]\n",driverName);
	
	hSCManager = win32Api.OpenSCManagerW(NULL,NULL,SC_MANAGER_ALL_ACCESS);
	if (NULL == hSCManager) 
    {
		printf("OpenSCManager failed (%d)\n", GetLastError());
        return;
    }

	hSc = win32Api.OpenServiceW(hSCManager, driverName, SERVICE_ALL_ACCESS);
	if (NULL == hSc) 
    {
		printf("OpenService failed (%d) 1060=ERROR_SERVICE_DOES_NOT_EXIST\n", GetLastError());
        goto end;
    }
	
	if (!win32Api.ControlService(hSc, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS) &ssp))
    {
        printf("ControlService failed (%d) 1052=ERROR_INVALID_SERVICE_CONTROL\n", GetLastError() );
    }
	else
	{
		printf("dwServiceType=%d\n",ssp.dwServiceType);
	}
	
	win32Api.CloseServiceHandle(hSc);	
end:
	win32Api.CloseServiceHandle(hSCManager);	
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow)
{	
	
	size_t cmdLineSize = wcslen(pCmdLine);
	printf("Command Line: %S (%d)\n", pCmdLine, cmdLineSize);
	
	PWSTR command = wcstok(pCmdLine, L" ");
	if (command == NULL || wcscmp(command,L"list")==0)
	{
		listServiceDrivers();
	}
	else if (wcscmp(command,L"stop")==0)
	{
		PWSTR driverName = wcstok(NULL, L" ");
		if (driverName != NULL)
		{
			stopServiceDriver(driverName);
		}
		else
		{
			printf("Missing driver name.\n");
		}
	}
	else if (wcscmp(command,L"start")==0)
	{
	}
	else
	{
		printf("Usage:\n");
		printf("wp81serviceCtrl <command>\n");
		printf("Commands:\n");
		printf("list\n");
		printf("stop <driver name>\n");
		printf("start <driver name>\n");
	}
	
	return 0;
}
