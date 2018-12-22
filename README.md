# ADBhoneypot

ADBhoneypot - Twisted implementation.

--------------------------------------------------------------------------------

## Disclaimer
I’ve been working on implementig output plug-ins and configuration file functionality in my [forked]() repository of [ADBHoney](https://github.com/huuck/ADBHoney). 
However, in one moment I completely rewrite the project in order to make the network 
communication based on [Twisted](https://twistedmatrix.com) framework, which is an event-driven networking engine written in Python. 
To distinguish this from the other implementation I created this repository.

--------------------------------------------------------------------------------

## ADB (Android Debug Bridge)

ADB (Android Debug Bridge) and its protocol is what a computer uses to communicate with
Android devices (like phones and TVs). The protocol itself is an application layer protocol,
which can be on the top of TCP or USB. ADB implements various control commands (e.g. "adb shell",
"adb pull", etc.) for the benefit of clients (like command-line users). These commands are called
'services' in ADB. ADB usually communicates with the device over USB, but it is also possible to
use ADB over Wi-Fi after some initial setup over USB. The  device can be set to listen for a TCP/IP
connection on port 5555 by issuing the command `adb tcpip 5555`. Devices that do not support
authentication can be accessed and attacked remotely, allowing the attacker to take full control
of the device by using combination of the following commands.

For now the honeypot accepts:

* `adb connect host[:port]` - Connect to a device over TCP/IP. If you do not specify a port,
5555 is used by default;

* `adb disconnect [host | host:port]` - Disconnect from the specified TCP/IP device running
on the specified port. If you do not specify a host or a port, then all devices are disconnected
from all TCP/IP ports. If you specify a host, but not a port, the default port 5555 is used.

* `adb shell command` - Issue a shell command in the target device and then exit the remote shell;

* `adb push local_filepath remote_fiepath` - Copy files and directories from the local device
(computer) to a remote location on the device.

--------------------------------------------------------------------------------

## Links

Android Open Source Project - [ADB Overview](https://github.com/aosp-mirror/platform_system_core/blob/master/adb/OVERVIEW.TXT)

Android Developer - [ADB Documentation](https://developer.android.com/studio/command-line/adb)

Reverse-engeenered documentation - [ADB Protocol](https://github.com/cstyan/adbDocumentation#adb-protocol-documentation)

Geir Sporsheim - [protocol.py](https://github.com/sporsh/twisted-adb/blob/master/adb/protocol.py)

--------------------------------------------------------------------------------

## The installation guide can be found [here](INSTALL.md).
