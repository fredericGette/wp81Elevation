cl.exe /c /EHsc /D "PSAPI_VERSION=2" /D "WINAPI_FAMILY=WINAPI_FAMILY_PHONE_APP" /D "_UITHREADCTXT_SUPPORT=0" /D "_UNICODE" /D "UNICODE" /D "_DEBUG" /MDd cJSON.c

cl.exe /c /EHsc /D "PSAPI_VERSION=2" /D "WINAPI_FAMILY=WINAPI_FAMILY_PHONE_APP" /D "_UITHREADCTXT_SUPPORT=0" /D "_UNICODE" /D "UNICODE" /D "_DEBUG" /MDd wp81service.cpp
LINK.exe /LIBPATH:"C:\Program Files (x86)\Windows Phone Kits\8.1\lib\ARM" /MANIFEST:NO "WindowsPhoneCore.lib" "RuntimeObject.lib" "PhoneAppModelHost.lib" "Ws2_32.lib" /DEBUG /MACHINE:ARM /NODEFAULTLIB:"kernel32.lib" /NODEFAULTLIB:"ole32.lib" /WINMD /SUBSYSTEM:WINDOWS wp81service.obj cJSON.obj 

cl.exe /c /EHsc /D "PSAPI_VERSION=2" /D "WINAPI_FAMILY=WINAPI_FAMILY_PHONE_APP" /D "_UITHREADCTXT_SUPPORT=0" /D "_UNICODE" /D "UNICODE" /D "_DEBUG" /MDd wp81listProcess.cpp
LINK.exe /LIBPATH:"C:\Program Files (x86)\Windows Phone Kits\8.1\lib\ARM" /MANIFEST:NO "WindowsPhoneCore.lib" "RuntimeObject.lib" "PhoneAppModelHost.lib" /DEBUG /MACHINE:ARM /NODEFAULTLIB:"kernel32.lib" /NODEFAULTLIB:"ole32.lib" /WINMD /SUBSYSTEM:WINDOWS wp81listProcess.obj cJSON.obj 