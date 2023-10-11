#include <stdio.h>
#include <stdlib.h>
#include "Win32Api.h"

Win32Api win32Api;

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
		printf("%d Device: %S | ", Index, CurrentDevice);

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
			printf("DeviceDesc: %S | ", DeviceDesc);
        }
		
		
        PropertySize = sizeof(DeviceDesc);
        cr = win32Api.CM_Get_DevNode_PropertyW(Devinst, &DEVPKEY_Device_Driver, &PropertyType, (PBYTE)DeviceDesc, &PropertySize, 0);
		if (cr == CR_SUCCESS && PropertyType == DEVPROP_TYPE_STRING)
        {
			printf("Driver: %S | ", DeviceDesc);
        }

        PropertySize = sizeof(DeviceDesc);
        cr = win32Api.CM_Get_DevNode_PropertyW(Devinst, &DEVPKEY_Device_PDOName, &PropertyType, (PBYTE)DeviceDesc, &PropertySize, 0);
		if (cr == CR_SUCCESS && PropertyType == DEVPROP_TYPE_STRING)
        {
			printf("PDOName: %S | ", DeviceDesc);
        }

        PropertySize = sizeof(DeviceDesc);
        cr = win32Api.CM_Get_DevNode_PropertyW(Devinst, &DEVPKEY_Device_EnumeratorName, &PropertyType, (PBYTE)DeviceDesc, &PropertySize, 0);
		if (cr == CR_SUCCESS && PropertyType == DEVPROP_TYPE_STRING)
        {
			printf("EnumeratorName: %S | ", DeviceDesc);
        }

        PropertySize = sizeof(DeviceDesc);
        cr = win32Api.CM_Get_DevNode_PropertyW(Devinst, &DEVPKEY_Device_Parent, &PropertyType, (PBYTE)DeviceDesc, &PropertySize, 0);
		if (cr == CR_SUCCESS && PropertyType == DEVPROP_TYPE_STRING)
        {
			printf("Parent: %S | ", DeviceDesc);
        }

		printf("\n");
		
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


int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow)
{	
	
	GetDevicePropertiesCfgmgr32();
	
	return 0;
}
