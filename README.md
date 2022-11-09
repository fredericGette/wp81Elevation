# wp81Elevation
Install a little web server running as a service on a Windows Phone 8.1

Currently, only 4 actions are possible:

- Get the status of the service
```
GET http://\<phone IP address\>:7171/status
```
Returns HTTP 200 and `{"status":"OK"}` when the service is running.
- Execute a program
```
POST http://\<phone IP address\>:7171/execute
body: {"command":"\<path to an executable file\>"}
```
The program is executed by user system with high integrity and all privileges enabled.  
This action waits the complete execution of the program before returning.  
And the response contains the console output of the executed program.  
- Download a file
```
GET http://\<phone IP address\>:7171/download?path=\<path to a file\>
```
- Stop the service
```
GET or POST http://\<phone IP address\>:7171/stopService
```
Could be useful to update the .exe of the service.

Compilation requires Visual Studio 2015 with Windows Phone 8.1 support.

Execution requires a Windows Phone 8.1 rooted with [WPinternals](https://github.com/ReneLergner/WPinternals).
