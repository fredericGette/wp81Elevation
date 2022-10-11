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

	HKEY subKey = {};
	DWORD retCode = win32Api.RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\ALG", 0, KEY_ALL_ACCESS, &subKey);
	if (retCode != ERROR_SUCCESS)
	{
		debug(L"Error RegOpenKeyExW : %d\n", retCode);
		return;
	}

	DWORD ValueType;
	PBYTE ValueData = new BYTE[100];
	DWORD ValueDataSize = 100;
	retCode = win32Api.RegQueryValueExW(subKey, L"Start", NULL, &ValueType, ValueData, &ValueDataSize);
	if (retCode == ERROR_SUCCESS)
	{
		debug(L"ValueType : %d (%d=REG_DWORD)\n", ValueType, REG_DWORD);
		debug(L"ValueDataSize : %d\n", ValueDataSize);
		debug(L"ValueData : 0x%08X\n", *(PDWORD)ValueData);

		*(PDWORD)ValueData = 2; // Automatic start
		retCode = win32Api.RegSetValueExW(subKey, L"Start", NULL, ValueType, ValueData, ValueDataSize);
		if (retCode != ERROR_SUCCESS)
		{
			debug(L"Error RegSetValueExW 'Start': %d\n", retCode);
		}

		PBYTE ValueData2 = new BYTE[100];
		DWORD ValueDataSize2 = 100;
		retCode = win32Api.RegQueryValueExW(subKey, L"ObjectName", NULL, &ValueType, ValueData2, &ValueDataSize2);
		if (retCode == ERROR_SUCCESS)
		{
			debug(L"ValueType : %d (%d=REG_SZ)\n", ValueType, REG_SZ);
			debug(L"ValueDataSize : %d\n", ValueDataSize2);
			debug(L"ValueData : %ls\n", (WCHAR*)ValueData2);

			wcscpy_s((WCHAR*)ValueData2, 100, L"LocalSystem");

			retCode = win32Api.RegSetValueExW(subKey, L"ObjectName", NULL, ValueType, ValueData2, ValueDataSize2);
			if (retCode != ERROR_SUCCESS)
			{
				debug(L"Error RegSetValueExW 'ObjectName': %d\n", retCode);
			}
		}
		else
		{
			debug(L"Error RegQueryValueExW 'ObjectName': %d\n", retCode);
		}
	}
	else
	{
		debug(L"Error RegQueryValueExW 'Start': %d\n", retCode);
	}

	retCode = win32Api.RegCloseKey(subKey);
	if (retCode != ERROR_SUCCESS)
	{
		debug(L"Error RegCloseKey : %d\n", retCode);
	}

	retCode = win32Api.RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\SecurityManager\\PrincipalClasses\\PRINCIPAL_CLASS_TCB", 0, KEY_ALL_ACCESS, &subKey);
	if (retCode != ERROR_SUCCESS)
	{
		debug(L"Error RegOpenKeyExW : %d\n", retCode);
		return;
	}

	ValueData = new BYTE[10000];
	ValueDataSize = 10000;
	retCode = win32Api.RegQueryValueExW(subKey, L"Executables", NULL, &ValueType, ValueData, &ValueDataSize);
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
		newValueDataSize += appendMultiSz(L"C:\\Data\\USERS\\Public\\Documents\\console.exe", newValueData + newValueDataSize);
		newValueDataSize++; // add final \0
		debug(L"newValueDataSize : %d\n", newValueDataSize*2); // convert WCHAR to BYTE
		debug(L"newValueData : ");
		debugMultiSz(newValueData);

		retCode = win32Api.RegSetValueExW(subKey, L"Executables", NULL, ValueType, (BYTE*)newValueData, newValueDataSize*2);
		if (retCode != ERROR_SUCCESS)
		{
			debug(L"Error RegSetValueExW 'ObjectName': %d\n", retCode);
		}
	}
	else
	{
		debug(L"Error RegQueryValueExW 'Start': %d\n", retCode);
	}

	retCode = win32Api.RegCloseKey(subKey);
	if (retCode != ERROR_SUCCESS)
	{
		debug(L"Error RegCloseKey : %d\n", retCode);
	}
}
