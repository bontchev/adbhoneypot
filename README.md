# ADBhoneypot

ADBhoneypot - Twisted implementation.   

--------------------------------------------------------------------------------

## Disclaimer
I’ve been working on plugins and configuration to the [ADBHoney](https://github.com/huuck/ADBHoney). But in one moment I completely rewrite the project to implement Twisted communication. To distinguish this from the other implementation I created this repository. 

--------------------------------------------------------------------------------

## ADB (Android Debug Bridge) 

ADB (Android Debug Bridge) and its protocol is what a computer uses to communicate with Android devices (like phones and TVs). The protocol itself is an application layer protocol, which can sit inside TCP or USB. ADB is used to implement various control commands (e.g. "adb shell", "adb pull", etc.) for the benefit of clients (like command-line users). These commands are called 'services' in ADB. ADB usually communicates with the device over USB, but it is also possible to use ADB over Wi-Fi after some initial setup over USB. The  device can be set to listen for a TCP/IP connection on port 5555 issuing the command `adb tcpip 5555`. Devices that do not support authentication and are accessed remotely can be attacked. The combination of the following commands can allow full control over the device.   
   
For now the honeypot accepts:   
* `adb connect host[:port] - Connect to a device over TCP/IP. If you do not specify a port, then the default port, 5555, is used;`   
* `adb disconnect [host | host:port] - Disconnect from the specified TCP/IP device running on the specified port. If you do not specify a host or a port, then all devices are disconnected from all TCP/IP ports. If you specify a host, but not a port, the default port, 5555, is used`.    
* `adb shell command - Issue a shell command in the target device and then exit the remote shell;`   
* `adb push local remote - Copy files and directories from the local device (computer) to a remote location on the device;`   

--------------------------------------------------------------------------------

## Useful sources   

Android Open Source Project - [ADB Overview](https://github.com/aosp-mirror/platform_system_core/blob/master/adb/OVERVIEW.TXT)   

Android Developer - [ADB Documentation](https://developer.android.com/studio/command-line/adb)

Reverse-engeenered documentation - [ADB Protocol](https://github.com/cstyan/adbDocumentation#adb-protocol-documentation)   


--------------------------------------------------------------------------------

## Installation and test [docs](docs/INSTALL.md)    
