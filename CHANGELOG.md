# Version History

## Release 3.0.0

* Python 3.x compatibility
* Fixed an error in the MySQL error handler

## Release 2.0.1

* The honeypot now has primitive emulation of some shell commands (echo, wget, curl)
* Various bug fixes

## Release 2.0.0

* Honeypot rewritten from scratch based on the Twisted framework
* Implemented config file
* Implemented the ability to create output plugins
* Implemented JSON logging as an output plugin
* Implemented logging to a MySQL database as an output plugin
* Implemented script for starting, stopping, and restarting the honeypot
