//
// MainPage.xaml.cpp
// Implementation of the MainPage class.
//

#include "pch.h"
#include "MainPage.xaml.h"
#include "Win32Api.h"

using namespace wp81Elevation;

using namespace Platform;
using namespace Windows::Foundation;
using namespace Windows::Foundation::Collections;
using namespace Windows::UI::Xaml;
using namespace Windows::UI::Xaml::Controls;
using namespace Windows::UI::Xaml::Controls::Primitives;
using namespace Windows::UI::Xaml::Data;
using namespace Windows::UI::Xaml::Input;
using namespace Windows::UI::Xaml::Media;
using namespace Windows::UI::Xaml::Navigation;
using namespace Windows::Storage;
using namespace concurrency;

// The Blank Page item template is documented at http://go.microsoft.com/fwlink/?LinkId=234238

MainPage::MainPage()
{
	InitializeComponent();
}

void debug(WCHAR* format, ...)
{
	va_list args;
	va_start(args, format);

	WCHAR buffer[1000];
	_vsnwprintf_s(buffer, sizeof(buffer), format, args);

	OutputDebugStringW(buffer);

	va_end(args);
}

void debugMultiSz(WCHAR *multisz)
{
	WCHAR* c = multisz;
	WCHAR* value = nullptr;
	boolean isFirstString = true;
	do
	{
		if (isFirstString)
		{
			isFirstString = false;
		}
		else
		{
			debug(L",");
		}
		value = c;
		while (*c != L'\0')
		{
			c++;
		}
		c++; // skip \0
		debug(L"%ls\n", value);
	} while (*c != L'\0');
}

DWORD appendMultiSz(WCHAR* src, WCHAR* dst)
{
	DWORD size = 0;
	WCHAR* s = src;
	WCHAR* d = dst;
	do
	{
		*d = *s;
		s++;
		d++;
		size++;
	} while (*s != L'\0');
	*d = L'\0';
	size++;
	return size;
}

/// <summary>
/// Invoked when this page is about to be displayed in a Frame.
/// </summary>
/// <param name="e">Event data that describes how this page was reached.  The Parameter
/// property is typically used to configure the page.</param>
void MainPage::OnNavigatedTo(NavigationEventArgs^ e)
{
	Win32Api win32Api;

	HKEY HKEY_LOCAL_MACHINE = (HKEY)0x80000002;
	DWORD retCode;

	HKEY servicesKey = {};
	retCode = win32Api.RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services", 0, KEY_ALL_ACCESS, &servicesKey);
	if (retCode != ERROR_SUCCESS)
	{
		debug(L"Error RegOpenKeyExW : %d\n", retCode);
		return;
	}

	HKEY wp81serviceKey = {};
	retCode = win32Api.RegCreateKeyExW(servicesKey, L"WP81SERVICE", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &wp81serviceKey, NULL);
	if (retCode != ERROR_SUCCESS)
	{
		debug(L"Error RegCreateKeyExW : %d\n", retCode);
		return;
	}

	PBYTE ValueData = new BYTE[100];
	ZeroMemory(ValueData, 100);

	wcscpy_s((WCHAR*)ValueData, 100, L"Wp81Service");
	retCode = win32Api.RegSetValueExW(wp81serviceKey, L"Description", NULL, REG_SZ, ValueData, 100);
	if (retCode != ERROR_SUCCESS)
	{
		debug(L"Error RegSetValueExW 'Description': %d\n", retCode);
	}

	wcscpy_s((WCHAR*)ValueData, 100, L"Wp81Service");
	retCode = win32Api.RegSetValueExW(wp81serviceKey, L"DisplayName", NULL, REG_SZ, ValueData, 100);
	if (retCode != ERROR_SUCCESS)
	{
		debug(L"Error RegSetValueExW 'DisplayName': %d\n", retCode);
	}

	wcscpy_s((WCHAR*)ValueData, 100, L"C:\\WINDOWS\\SYSTEM32\\WP81SERVICE.EXE");
	retCode = win32Api.RegSetValueExW(wp81serviceKey, L"ImagePath", NULL, REG_SZ, ValueData, 100);
	if (retCode != ERROR_SUCCESS)
	{
		debug(L"Error RegSetValueExW 'ImagePath': %d\n", retCode);
	}

	// If the service represented by the subkey is a Win32 service, this entry specifies the account name that the service uses to log on to Windows.
	wcscpy_s((WCHAR*)ValueData, 100, L"LocalSystem");
	retCode = win32Api.RegSetValueExW(wp81serviceKey, L"ObjectName", NULL, REG_SZ, ValueData, 100);
	if (retCode != ERROR_SUCCESS)
	{
		debug(L"Error RegSetValueExW 'ObjectName': %d\n", retCode);
	}

	*(PDWORD)ValueData = 1; // Normal: If the driver fails to load or initialize, startup proceeds, but a warning message appears.
	retCode = win32Api.RegSetValueExW(wp81serviceKey, L"ErrorControl", NULL, REG_DWORD, ValueData, 4);
	if (retCode != ERROR_SUCCESS)
	{
		debug(L"Error RegSetValueExW 'ErrorControl': %d\n", retCode);
	}

	*(PDWORD)ValueData = 2; // Automatic: Loaded by Service Control Manager. Specifies that the service is loaded or started automatically.
	retCode = win32Api.RegSetValueExW(wp81serviceKey, L"Start", NULL, REG_DWORD, ValueData, 4);
	if (retCode != ERROR_SUCCESS)
	{
		debug(L"Error RegSetValueExW 'Start': %d\n", retCode);
	}

	*(PDWORD)ValueData = 16; // A Win32 program that runs in a process by itself. This type of Win32 service can be started by the service controller.
	retCode = win32Api.RegSetValueExW(wp81serviceKey, L"Type", NULL, REG_DWORD, ValueData, 4);
	if (retCode != ERROR_SUCCESS)
	{
		debug(L"Error RegSetValueExW 'Type': %d\n", retCode);
	}

	*(PDWORD)ValueData = 1; // Defines the unrestricted type of service SID for the specified service..
	retCode = win32Api.RegSetValueExW(wp81serviceKey, L"ServiceSidType", NULL, REG_DWORD, ValueData, 4);
	if (retCode != ERROR_SUCCESS)
	{
		debug(L"Error RegSetValueExW 'ServiceSidType': %d\n", retCode);
	}

	retCode = win32Api.RegCloseKey(wp81serviceKey);
	if (retCode != ERROR_SUCCESS)
	{
		debug(L"Error RegCloseKey 'wp81serviceKey': %d\n", retCode);
	}

	retCode = win32Api.RegCloseKey(servicesKey);
	if (retCode != ERROR_SUCCESS)
	{
		debug(L"Error RegCloseKey 'servicesKey': %d\n", retCode);
	}

	HKEY principalClassTcbKey = {};
	retCode = win32Api.RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\SecurityManager\\PrincipalClasses\\PRINCIPAL_CLASS_TCB", 0, KEY_ALL_ACCESS, &principalClassTcbKey);
	if (retCode != ERROR_SUCCESS)
	{
		debug(L"Error RegOpenKeyExW : %d\n", retCode);
		return;
	}

	ValueData = new BYTE[10000];
	DWORD ValueType;
	DWORD ValueDataSize = 10000;
	retCode = win32Api.RegQueryValueExW(principalClassTcbKey, L"Executables", NULL, &ValueType, ValueData, &ValueDataSize);
	if (retCode == ERROR_SUCCESS)
	{
		debug(L"ValueType : %d (%d=REG_MULTI_SZ)\n", ValueType, REG_MULTI_SZ);
		debug(L"ValueDataSize : %d\n", ValueDataSize);
		debug(L"ValueData : ");

		debugMultiSz((WCHAR*)ValueData);

		WCHAR *newValueData = (WCHAR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 5000);
		DWORD newValueDataSize = 0;
		newValueDataSize += appendMultiSz(L"C:\\WINDOWS\\SYSTEM32\\ALG.EXE", newValueData);
		newValueDataSize += appendMultiSz(L"C:\\WINDOWS\\SYSTEM32\\APPVERIF.EXE", newValueData + newValueDataSize);
		newValueDataSize += appendMultiSz(L"C:\\WINDOWS\\SYSTEM32\\AUDIODG.EXE", newValueData + newValueDataSize);
		newValueDataSize += appendMultiSz(L"C:\\WINDOWS\\SYSTEM32\\CSRSS.EXE", newValueData + newValueDataSize);
		newValueDataSize += appendMultiSz(L"C:\\WINDOWS\\SYSTEM32\\DIAGTRACK_CORESYS.EXE", newValueData + newValueDataSize);
		newValueDataSize += appendMultiSz(L"C:\\WINDOWS\\SYSTEM32\\FLTMC.EXE", newValueData + newValueDataSize);
		newValueDataSize += appendMultiSz(L"C:\\WINDOWS\\SYSTEM32\\LSASS.EXE", newValueData + newValueDataSize);
		newValueDataSize += appendMultiSz(L"C:\\WINDOWS\\SYSTEM32\\MUIUNATTEND.EXE", newValueData + newValueDataSize);
		newValueDataSize += appendMultiSz(L"C:\\WINDOWS\\SYSTEM32\\OEMSVCHOST.EXE", newValueData + newValueDataSize);
		newValueDataSize += appendMultiSz(L"C:\\WINDOWS\\SYSTEM32\\RMACTIVATE.EXE", newValueData + newValueDataSize);
		newValueDataSize += appendMultiSz(L"C:\\WINDOWS\\SYSTEM32\\SERVICES.EXE", newValueData + newValueDataSize);
		newValueDataSize += appendMultiSz(L"C:\\WINDOWS\\SYSTEM32\\SMSS.EXE", newValueData + newValueDataSize);
		newValueDataSize += appendMultiSz(L"C:\\WINDOWS\\SYSTEM32\\TASKHOSTEX.EXE", newValueData + newValueDataSize);
		newValueDataSize += appendMultiSz(L"C:\\WINDOWS\\SYSTEM32\\TRACELOG.EXE", newValueData + newValueDataSize);
		newValueDataSize += appendMultiSz(L"C:\\WINDOWS\\SYSTEM32\\USERINIT.EXE", newValueData + newValueDataSize);
		newValueDataSize += appendMultiSz(L"C:\\WINDOWS\\SYSTEM32\\WIMSERV.EXE", newValueData + newValueDataSize);
		newValueDataSize += appendMultiSz(L"C:\\WINDOWS\\SYSTEM32\\WININIT.EXE", newValueData + newValueDataSize);
		newValueDataSize += appendMultiSz(L"C:\\WINDOWS\\SYSTEM32\\WINLOGON.EXE", newValueData + newValueDataSize);
		newValueDataSize += appendMultiSz(L"C:\\WINDOWS\\SYSTEM32\\WLANEXT.EXE", newValueData + newValueDataSize);
		newValueDataSize += appendMultiSz(L"C:\\WINDOWS\\SYSTEM32\\WUDFHOST.EXE", newValueData + newValueDataSize);
		newValueDataSize += appendMultiSz(L"C:\\WINDOWS\\SYSTEM32\\BATTERYLOGGER.EXE", newValueData + newValueDataSize);
		newValueDataSize += appendMultiSz(L"C:\\WINDOWS\\SYSTEM32\\BOOTPREP.EXE", newValueData + newValueDataSize);
		newValueDataSize += appendMultiSz(L"C:\\WINDOWS\\SYSTEM32\\CMRECOVERYHOST.EXE", newValueData + newValueDataSize);
		newValueDataSize += appendMultiSz(L"C:\\WINDOWS\\SYSTEM32\\DTLAUNCHER.EXE", newValueData + newValueDataSize);
		newValueDataSize += appendMultiSz(L"C:\\WINDOWS\\SYSTEM32\\ENABLEUEFISB.EXE", newValueData + newValueDataSize);
		newValueDataSize += appendMultiSz(L"C:\\WINDOWS\\SYSTEM32\\FEEDBACKCPL.EXE", newValueData + newValueDataSize);
		newValueDataSize += appendMultiSz(L"C:\\WINDOWS\\SYSTEM32\\INTLSETTINGSREPLICATOR.EXE", newValueData + newValueDataSize);
		newValueDataSize += appendMultiSz(L"C:\\WINDOWS\\SYSTEM32\\LEGACYCAMERASECURITY.EXE", newValueData + newValueDataSize);
		newValueDataSize += appendMultiSz(L"C:\\WINDOWS\\SYSTEM32\\NFCSECURITY.EXE", newValueData + newValueDataSize);
		newValueDataSize += appendMultiSz(L"C:\\WINDOWS\\SYSTEM32\\OEMSERVICEHOST.EXE", newValueData + newValueDataSize);
		newValueDataSize += appendMultiSz(L"C:\\WINDOWS\\SYSTEM32\\RILADAPTATIONSERVICE.EXE", newValueData + newValueDataSize);
		newValueDataSize += appendMultiSz(L"C:\\WINDOWS\\SYSTEM32\\RLD.EXE", newValueData + newValueDataSize);
		newValueDataSize += appendMultiSz(L"C:\\WINDOWS\\SYSTEM32\\STORAGECLEANUPHOST.EXE", newValueData + newValueDataSize);
		newValueDataSize += appendMultiSz(L"C:\\WINDOWS\\SYSTEM32\\SVCHOST.EXE", newValueData + newValueDataSize);
		newValueDataSize += appendMultiSz(L"C:\\WINDOWS\\SYSTEM32\\TELSVC.EXE", newValueData + newValueDataSize);
		newValueDataSize += appendMultiSz(L"C:\\WINDOWS\\SYSTEM32\\TELWP.EXE", newValueData + newValueDataSize);
		newValueDataSize += appendMultiSz(L"C:\\WINDOWS\\SYSTEM32\\UPDATEUEFIDB.EXE", newValueData + newValueDataSize);
		newValueDataSize += appendMultiSz(L"C:\\WINDOWS\\SYSTEM32\\USSBOOT.EXE", newValueData + newValueDataSize);
		newValueDataSize += appendMultiSz(L"C:\\WINDOWS\\SYSTEM32\\USSSCAN.EXE", newValueData + newValueDataSize);
		newValueDataSize += appendMultiSz(L"C:\\WINDOWS\\SYSTEM32\\WINSOCKSEC.EXE", newValueData + newValueDataSize);
		newValueDataSize += appendMultiSz(L"C:\\WINDOWS\\SYSTEM32\\SECTASK.EXE", newValueData + newValueDataSize);
		newValueDataSize += appendMultiSz(L"C:\\WINDOWS\\SYSTEM32\\WPPERFMONSERVER.EXE", newValueData + newValueDataSize);
		newValueDataSize += appendMultiSz(L"C:\\WINDOWS\\SYSTEM32\\WPTOOLSWRAPPER.EXE", newValueData + newValueDataSize);
		newValueDataSize += appendMultiSz(L"C:\\PROGRAMS\\DEVICEREG\\DEVICEREG.EXE", newValueData + newValueDataSize);
		newValueDataSize += appendMultiSz(L"C:\\WINDOWS\\SYSTEM32\\XbfGenerator.exe", newValueData + newValueDataSize);
		newValueDataSize += appendMultiSz(L"C:\\WINDOWS\\SYSTEM32\\WPR.EXE", newValueData + newValueDataSize);
		newValueDataSize += appendMultiSz(L"C:\\WINDOWS\\SYSTEM32\\WP81SERVICE.EXE", newValueData + newValueDataSize);
		newValueDataSize++; // add final \0
		debug(L"newValueDataSize : %d\n", newValueDataSize*2); // convert WCHAR to BYTE
		debug(L"newValueData : ");
		debugMultiSz(newValueData);

		retCode = win32Api.RegSetValueExW(principalClassTcbKey, L"Executables", NULL, ValueType, (BYTE*)newValueData, newValueDataSize*2);
		if (retCode != ERROR_SUCCESS)
		{
			debug(L"Error RegSetValueExW 'ObjectName': %d\n", retCode);
		}
	}
	else
	{
		debug(L"Error RegQueryValueExW 'Start': %d\n", retCode);
	}

	retCode = win32Api.RegCloseKey(principalClassTcbKey);
	if (retCode != ERROR_SUCCESS)
	{
		debug(L"Error RegCloseKey : %d\n", retCode);
	}

	Uri^ uri = ref new Uri("ms-appx:///Payload/wp81service.exe");
	create_task(StorageFile::GetFileFromApplicationUriAsync(uri)).then([win32Api](task<StorageFile^> t)
	{
		StorageFile ^storageFile = t.get();
		Platform::String^ filePath = storageFile->Path;
		debug(L"FilePath : %ls\n", filePath->Data());
		if (!win32Api.CopyFileW(filePath->Data(), L"C:\\windows\\system32\\wp81service.exe", FALSE))
		{
			debug(L"CopyFileW error: %d\n", GetLastError());
		}
		debug(L"File copied\n");
	});

}
