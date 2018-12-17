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

## Step 1: Install dependencies

First we install system-wide support for Python virtual environments and other dependencies.
Actual Python packages are installed later.

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
`adbhoney.cfg`. Both files are read on startup, where entries from
`adbhoney.cfg` take precedence. The `.base` file contains the default settings and can be overwritten by
upgrades, while `adbhoney.cfg` will not be touched. To run with a standard
configuration, there is no need to change anything.

For instance, in order to enable JSON logging, and to store the captured samples in a directory named `dl`,
create `adbhoney.cfg` and put in it only the following:

```adbhoney.cfg
[honeypot]
download_path = dl

[output_jsonlog]
enabled = true
logfile = log/adbhoney.json
epoch_timestamp = true
```

For more information about how to configure additional output plugins (from the available ones),
please consult the appropriate `INSTALL.md` file in the subdirectory corresponding to the plugin
inside the `docs` directory.

## Step 6: Starting ADBHoneypot

```bash
nohup python adbhoney.py &>/dev/null &
```

## Configure Additional Output Plugins (OPTIONAL)

ADBHoneypot automatically outputs event data to text in `log/adbhoney.log`. Additional output
plugins can be configured to record the data other ways. Supported output plugins include:

* JSON
* SQL (MySQL, SQLite3)

More plugins are likely to be added in the future.

See `~/adbh/adbhoneypot/docs/[Output Plugin]/README.md` for details.

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

The settings specified via command-line options take precedence over the corresponding settings in the `.cfg` files.

## Log rotation

You can use the system utility `logrotate` to rotate the logs. For instance, in order to keep one day
worth of text and JSON logs for up to a year, create a file `~/adbhoneypot/logrotate.conf` with the
following contents:

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

Change the log directory and file names above if you haven't used the default values.

Then create a crontab job (`crontab -e`) to run logrotate daily:

```crontab
@daily /usr/sbin/logrotate -s /home/adbh/adbhoneypot/logrotate.status /home/adbh/adbhoneypot/logrotate.conf
```

A future version of the honeypot is likely to do log rotation itself, instead of
relying on an external utility.
