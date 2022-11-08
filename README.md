# wp81Elevation
Install a little web server running as a service on a Windows Phone 8.1

Currently, only 4 actions are possible:

GET http://\<phone IP address\>:7171/status

POST http://\<phone IP address\>:7171/execute

body: {"command":"\<path to an executable file\>"}

GET http://\<phone IP address\>:7171/download?path=\<path to a file\>

GET or POST http://\<phone IP address\>:7171/stopService

Compilation requires Visual Studio 2015 with Windows Phone 8.1 support.

Execution requires a Windows Phone 8.1 rooted with [WPinternals](https://github.com/ReneLergner/WPinternals).
