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
}
