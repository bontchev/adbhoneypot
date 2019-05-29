#!/usr/bin/env python

from __future__ import print_function
from twisted.internet.protocol import Factory, Protocol
from twisted.internet import reactor, endpoints
from argparse import ArgumentParser
from core.config import CONFIG
from adb import protocol
import time
import datetime
import binascii
import hashlib
import requests
import socket
import errno
import sys
import os


__VERSION__ = '2.0.1'


def log(message, cfg):
    if cfg['logfile'] is None:
        print(message)
        sys.stdout.flush()
    else:
        with open(cfg['logfile'], 'a') as f:
            print(message, file=f)


def stop_plugins(cfg):
    log('Stoping plugins ... ', cfg)
    for plugin in cfg['output_plugins']:
        try:
            plugin.stop()
        except Exception as e:
            log(e, cfg)
            continue


def import_plugins(cfg):
    # Load output modules (inspired by the Cowrie honeypot)
    log('Loading plugins...', cfg)
    output_plugins = []
    general_options = cfg
    for x in CONFIG.sections():
        if not x.startswith('output_'):
            continue
        if CONFIG.getboolean(x, 'enabled') is False:
            continue
        engine = x.split('_')[1]
        try:
            output = __import__('output_plugins.{}'.format(engine),
                                globals(), locals(), ['output'], 0).Output(general_options)
            output_plugins.append(output)
            log('Loaded output engine: {}'.format(engine), cfg)
        except ImportError as e:
            log('Failed to load output engine: {} due to ImportError: {}'.format(engine, e), cfg)
        except Exception as e:
            log('Failed to load output engine: {} {}'.format(engine, e), cfg)
    return output_plugins


def write_event(event, cfg):
    output_plugins = cfg['output_plugins']
    for plugin in output_plugins:
        try:
            plugin.write(event)
        except Exception as e:
            log(e, cfg)
            continue


def mkdir(path):
    if not path:
        return
    try:
        os.makedirs(path)
    except OSError as exc:
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise


def getutctime(unixtime):
        return datetime.datetime.utcfromtimestamp(unixtime).isoformat() + 'Z'


def getlocalip():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('10.255.255.255', 1))
            ip = s.getsockname()[0]
        except:
            ip = '127.0.0.1'
        finally:
            s.close()
        return ip


class AdbHoneyProtocolBase(Protocol):
    version = protocol.VERSION
    maxPayload = protocol.MAX_PAYLOAD

    def __init__(self, options):
        self.cfg = options
        self.buff = b''
        self.streams = {}
        self.messageHandler = self

        self.filename = 'tmp'
        self.sending_data = False
        self.data_file = ''
        self.large_data_size = False
        self.start = time.time()

    def connectionMade(self):
        self.cfg['session'] = binascii.hexlify(os.urandom(6))
        unixtime = time.time()
        humantime = getutctime(unixtime)
        self.start = unixtime
        log('{}\t{}\tconnection start ({})'.format(humantime, self.cfg['src_addr'],
            self.cfg['session']), self.cfg)
        localip = getlocalip()
        event = {
            'eventid': 'adbhoney.session.connect',
            'timestamp': humantime,
            'unixtime': unixtime,
            'session': self.cfg['session'],
            'message': 'New connection: {}:{} ({}:{}) [session: {}]'.format(self.cfg['src_addr'],
                self.cfg['src_port'], localip, self.cfg['port'], self.cfg['session']),
            'src_ip': self.cfg['src_addr'],
            'src_port': self.cfg['src_port'],
            'dst_ip': localip,
            'dst_port': self.cfg['port'],
            'sensor': self.cfg['sensor']
        }
        write_event(event, self.cfg)

    def dataReceived(self, data):
        self.buff += data
        message = self.getMessage(data)
        while message:
            self.dispatchMessage(message)
            message = self.getMessage(data)

    def connectionLost(self, reason):
        if reason:
            close_msg = reason.getErrorMessage()
            unixtime = time.time()
            humantime = getutctime(unixtime)
            duration = unixtime - self.start
            log('{}\t{}\tconnection closed ({})'.format(humantime, self.cfg['src_addr'],
                self.cfg['session']), self.cfg)
            event = {
                'eventid': 'adbhoney.session.closed',
                'timestamp': humantime,
                'unixtime': unixtime,
                'session': self.cfg['session'],
                'message': '{} Duration {} second(s).'.format(close_msg, int(round(duration))),
                'src_ip': self.cfg['src_addr'],
                'duration': duration,
                'sensor': self.cfg['sensor']
            }
            write_event(event, self.cfg)

    def getMessage(self, data):
        try:
            message, self.buff = protocol.AdbMessage.decode(self.buff)
        except Exception as e:
            # TODO: correctly handle corrupt messages
            # log(e, cfg)
            return
        return message

    def dispatchMessage(self, message):
        if self.cfg['debug'] and not self.large_data_size:
            string = str(message)
            if len(string) > 96:
                log('<<<<<< {} ...... {}'.format(string[0:64], string[-32:]), self.cfg)
            else:
                log('<<<<<< {}'.format(string), self.cfg)
        str_command = protocol.getCommandString(message.command)
        name = 'handle_{}'.format(str(str_command, 'utf-8'))
        handler = getattr(self.messageHandler, name, self.unhandledMessage)
        states = [str_command, message.command, message.data]
        if message.arg0 in self.streams:
            if str_command == 'CLSE':
                del self.streams[message.arg0]
            else:
                self.streams[message.arg0].append(states)
        else:
            self.streams[message.arg0] = []
            self.streams[message.arg0].append(states)
        handler(message.arg0, message.arg1, message.data, message)

    def unhandledMessage(self, message):
        log('Unhandled message: {}'.format(message), self.cfg)

    def sendCommand(self, command, arg0, arg1, data):
        #TODO: split data into chunks of MAX_PAYLOAD ?
        message = protocol.AdbMessage(command, arg0, arg1, data)
        if self.cfg['debug'] and not self.large_data_size:
            log('>>>>>> {}'.format(message), self.cfg)
        self.transport.write(message.encode())

    def dump_file_data(self, real_fname, data):
        data_len = len(data)
        shasum = hashlib.sha256(data).hexdigest()
        fname = 'data-{}.raw'.format(shasum)
        fullname = os.path.join(self.cfg['download_dir'], fname)
        unixtime = time.time()
        humantime = getutctime(unixtime)
        log('{}\t{}\tfile:{} - dumping {} bytes of data to {}...'.format(
            humantime, self.cfg['src_addr'], real_fname, data_len, fullname), self.cfg)
        event = {
            'eventid': 'adbhoney.session.file_upload',
            'timestamp': humantime,
            'unixtime': unixtime,
            'session': self.cfg['session'],
            'message': 'Downloaded file {} with SHA-256 {} to {}'.format(real_fname, shasum, fullname),
            'src_ip': self.cfg['src_addr'],
            'shasum': shasum,
            'dst_path': real_fname,
            'fullname': fullname,
            'file_size': data_len,
            'sensor': self.cfg['sensor'],
        }
        write_event(event, self.cfg)
        mkdir(self.cfg['download_dir'])
        if os.path.exists(fullname):
            log('File already exists, nothing written to disk.', self.cfg)
        else:
            with open(fullname, 'wb') as f:
                f.write(data)

    def download_from_url(self, dl_link, real_fname):
        try:
            r = requests.get(dl_link, stream=True)
        except Exception as e:
            log(e, self.cfg)
            r = None
        if r and r.status_code == 200:
            download_limit_size = CONFIG.getint('honeypot', 'download_limit_size', fallback=0)
            unixtime = time.time()
            humantime = getutctime(unixtime)
            dl_len = 0
            file_data = b''
            for chunk in r.iter_content(chunk_size=100000):
                dl_len += len(chunk)
                if dl_len <= download_limit_size or download_limit_size == 0:
                    file_data += chunk
                else:
                    log('{}\tfile:{} is too large, not saved.'.format(
                                                humantime, dl_link), self.cfg)
                    return
            shasum = hashlib.sha256(file_data).hexdigest()
            fname = 'data-{}.raw'.format(shasum)
            fullname = os.path.join(self.cfg['download_dir'], fname)
            event = {
                    'eventid': 'adbhoney.session.file_upload',
                    'timestamp': humantime,
                    'unixtime': unixtime,
                    'session': self.cfg['session'],
                    'message': 'Downloaded file {} from {} with SHA-256 {} to {}'.format(real_fname, dl_link, shasum, fullname),
                    'src_ip': self.cfg['src_addr'],
                    'shasum': shasum,
                    'dst_path': real_fname,
                    'fullname': fullname,
                    'file_size': dl_len,
                    'sensor': self.cfg['sensor'],
                    'url': dl_link
                }
            write_event(event, self.cfg)
            mkdir(self.cfg['download_dir'])
            if os.path.exists(fullname):
                log('File already exists, nothing written to disk.', self.cfg)
            else:
                with open(fullname, 'wb') as f:
                    f.write(file_data)
                log('{}\tfile:{} - dumping {} bytes of data to {}...'.format(
                    humantime, dl_link, dl_len, fullname), self.cfg)

    def download_shell_links(self, arguments):
        # This code downloads files from [busybox] wget and curl
        download_files = CONFIG.getboolean('honeypot', 'download_files', fallback=True)
        if not download_files:
            return
        for word in arguments:
            if b'://' in word:
                dl_link = word.strip(b'/')
                real_fname = dl_link.split(b'/')[-1]
                self.download_from_url(dl_link, real_fname)

    def handle_CNXN(self, version, maxPayload, systemIdentityString, message):
        """
        Called when we get an incoming CNXN message
        """
        systemIdentityString = self.cfg['device_id'].encode('utf8')
        if version != self.version or maxPayload < maxPayload:
            log('Disconnecting: Protocol version or max payload mismatch', self.cfg)
            self.transport.loseConnection()
        else:
            self.sendCommand(protocol.CMD_CNXN,
                             self.version,
                             self.maxPayload,
                             str(systemIdentityString, 'utf-8') + '\x00')

    def handle_OPEN(self, remoteId, sessionId, destination, message):
        """
        Called when we receive a message indicating that the other side
        has a stream identified by :remoteId: that it wishes to connect to
        the named :destination: on our side.

        We reply to this message with either a OKAY, indicating the connection
        has been established, or a CLSE message indicating failure.

        An OPEN message implies an OKAY message from the connecting remote stream.
        """
        if b'shell:' in message.data:
            self.sendCommand(protocol.CMD_OKAY, 2, message.arg0, '')
            if not b'echo' in message.data:
                # Send terminal prompt
                self.sendCommand(protocol.CMD_WRTE, 2, message.arg0, '#')
            # Move self.sendCommand(protocol.CMD_CLSE, 2, message.arg0, '') in handle_OKAY
            # in responce of the client.

            # Find last valid shell string in message.data
            msg  = message.data.split(b'shell:')[-1]
            shell_msg = b'shell:' + msg
            unixtime = time.time()
            humantime = getutctime(unixtime)
            log('{}\t{}\t{}'.format(humantime, self.cfg['src_addr'], shell_msg[:-1]), self.cfg)
            event = {
                'eventid': 'adbhoney.command.input',
                'timestamp': humantime,
                'unixtime': unixtime,
                'session': self.cfg['session'],
                'message': shell_msg[:-1],
                'src_ip': self.cfg['src_addr'],
                'input': msg[:-1],
                'sensor': self.cfg['sensor']
            }
            write_event(event, self.cfg)
            commands = event['input'].split(b';')
            for command in commands:
                words = command.strip().split()
                first_word = words[0]
                words.pop(0)
                if first_word == b'busybox':
                    first_word = words[0]
                    words.pop(0)
                if first_word == b'echo':
                    self.sendCommand(protocol.CMD_WRTE, 2, message.arg0, b' '.join(words))
                elif first_word == b'wget' or first_word == b'curl':
                    self.download_shell_links(words)
        elif b'sync:' in message.data:
            self.sendCommand(protocol.CMD_OKAY, 2, message.arg0, '')
        else:
            self.sendCommand(protocol.CMD_OKAY, 2, message.arg0, '')
            self.sendCommand(protocol.CMD_CLSE, 2, message.arg0, '')

    def handle_OKAY(self, remoteId, localId, data, message):
        """
        Called when the stream on the remote side is ready for write.
        @param data: should be ''
        """
        if b'shell' in self.streams[remoteId][0][2]:
            self.sendCommand(protocol.CMD_CLSE, 2, message.arg0, '')

    def handle_CLSE(self, remoteId, localId, data, message):
        self.sendCommand(protocol.CMD_CLSE, 2, message.arg0, '')

    def handle_WRTE(self, remoteId, localId, data, message):

        if b'STAT' in message.data:
            self.sendCommand(protocol.CMD_OKAY, 2, message.arg0, '')

        if self.streams[remoteId][-1][1] == protocol.CMD_WRTE and \
           self.streams[remoteId][-2][1] == protocol.CMD_WRTE and \
           b'STAT' in self.streams[remoteId][-2][2]:
            self.sendCommand(protocol.CMD_OKAY, 2, message.arg0, '')
            # Because ADB state machine sometimes we need to send duplicate messages
            self.sendCommand(protocol.CMD_WRTE, 2, message.arg0, 'STAT\x01\x00\x00\x00')
            self.sendCommand(protocol.CMD_WRTE, 2, message.arg0, 'STAT\x01\x00\x00\x00')

        if b'SEND' in message.data:
            self.data_file = ''
            self.sendCommand(protocol.CMD_OKAY, 2, message.arg0, '')

        # Corner case for binary sending
        download_limit_size = CONFIG.getint('honeypot', 'download_limit_size', fallback=0)
        if self.sending_data:
            if download_limit_size == 0 or len(self.data_file) <= download_limit_size:
                self.large_data_size = False
            if download_limit_size and len(self.data_file) > download_limit_size and not self.large_data_size:
                self.large_data_size = True
                humantime = getutctime(time.time())
                log('{}\t{}\tfile:{} is too large, not saved.'.format(
                    humantime, self.cfg['src_addr'], self.filename), self.cfg)

            if not self.large_data_size:
                # Look for that DATAXXXX where XXXX is the length of the data block
                # that's about to be sent (i.e. DATA\x00\x00\x01\x00)
                if b'DATA' in message.data:
                    data_index = message.data.index(b'DATA')
                    payload_fragment = message.data[:data_index] + message.data[data_index + 8:]
                    self.data_file += payload_fragment
                else:
                    self.data_file += message.data
            self.sendCommand(protocol.CMD_OKAY, 2, message.arg0, '')

            if b'DONE' in message.data:
                if not self.large_data_size:
                    self.data_file = self.data_file[:-8]
                    self.dump_file_data(self.filename, self.data_file)
                self.sending_data = False
                self.large_data_size = False
                self.sendCommand(protocol.CMD_WRTE, 2, message.arg0, 'OKAY')
                self.sendCommand(protocol.CMD_WRTE, 2, message.arg0, 'OKAY')
                self.sendCommand(protocol.CMD_OKAY, 2, message.arg0, '')
        else:
            if b'DATA' in message.data[:128]:
                # If the message is really short, wrap it up
                if b'DONE' in message.data[-8:]:
                    dr_file = ''
                    predata = message.data.split(b'DATA')[0]
                    if predata:
                        # Wished destination filename
                        fname = predata.split(b',')[0]
                    dr_file = message.data.split(b'DATA')[1][4:-8]
                    self.sendCommand(protocol.CMD_WRTE, 2, message.arg0, 'OKAY')
                    self.sendCommand(protocol.CMD_WRTE, 2, message.arg0, 'OKAY')
                    self.sendCommand(protocol.CMD_OKAY, 2, message.arg0, '')
                    self.sending_data = False
                    if len(dr_file) <= download_limit_size or download_limit_size == 0:
                        self.dump_file_data(fname, dr_file)
                else:
                    self.sending_data = True
                    predata = message.data.split(b'DATA')[0]
                    if predata:
                        # Wished destination filename
                        self.filename = predata.split(b',')[0]
                    self.data_file = message.data.split(b'DATA')[1][4:]

                if b'SEND' not in message.data[:128]:
                    self.sendCommand(protocol.CMD_OKAY, 2, message.arg0, '')

        if b'QUIT' in message.data:
            self.sendCommand(protocol.CMD_OKAY, 2, message.arg0, '')
            self.sendCommand(protocol.CMD_CLSE, 2, message.arg0, '')


class ADBFactory(Factory):

    def __init__(self, options):
        self.options = options

    def buildProtocol(self, addr):
        self.options['src_addr'] = addr.host
        self.options['src_port'] = addr.port
        return AdbHoneyProtocolBase(self.options)


def main():

    cfg_options = {}
    cfg_options['addr'] = CONFIG.get('honeypot', 'out_addr', fallback='0.0.0.0')
    cfg_options['port'] = CONFIG.getint('honeypot', 'listen_port', fallback=5555)
    cfg_options['download_dir'] = CONFIG.get('honeypot', 'download_path', fallback='')
    log_name = CONFIG.get('honeypot', 'log_filename', fallback='')
    if log_name:
        logdir = CONFIG.get('honeypot', 'log_path', fallback='')
        mkdir(logdir)
        cfg_options['logfile'] = os.path.join(logdir, log_name)
    else:
        cfg_options['logfile'] = None
    cfg_options['sensor'] = CONFIG.get('honeypot', 'sensor_name', fallback=socket.gethostname())
    cfg_options['debug'] = CONFIG.getboolean('honeypot', 'debug', fallback=False)
    cfg_options['device_id'] = CONFIG.get('honeypot', 'id_string',
                                  fallback='device::http://ro.product.name =starltexx;ro.product.model=SM-G960F;ro.product.device=starlte;features=cmd,stat_v2,shell_v2')

    parser = ArgumentParser(prog='adbhoneypot', description='ADB Honeypot')

    parser.add_argument('-v', '--version', action='version', version='%(prog)s version ' + __VERSION__)
    parser.add_argument('-a', '--addr', type=str, default=cfg_options['addr'],
                        help='Address to bind to (default: {})'.format(cfg_options['addr']))
    parser.add_argument('-p', '--port', type=int, default=cfg_options['port'],
                        help='Port to listen on (default: {})'.format(cfg_options['port']))
    parser.add_argument('-d', '--dlfolder', type=str, default=cfg_options['download_dir'],
                        help='Directory for the uploaded samples (default: current)')
    parser.add_argument('-l', '--logfile', type=str, default=cfg_options['logfile'],
                        help='Log file (default: stdout)')
    parser.add_argument('-s', '--sensor', type=str, default=cfg_options['sensor'],
                        help='Sensor name (default: {})'.format(cfg_options['sensor']))
    parser.add_argument('-b', '--debug', action='store_true', help='Produce verbose output')

    args = parser.parse_args()

    cfg_options['addr'] = args.addr
    cfg_options['port'] = args.port
    cfg_options['download_dir'] = args.dlfolder
    cfg_options['logfile'] = args.logfile
    cfg_options['sensor'] = args.sensor
    if args.debug:
        cfg_options['debug'] = True

    log('Listening on {}:{}.'.format(cfg_options['addr'], cfg_options['port']), cfg_options)
    cfg_options['output_plugins'] = import_plugins(cfg_options)

    connect = 'tcp:{}:interface={}'.format(cfg_options['port'], cfg_options['addr'])
    endpoints.serverFromString(reactor, connect).listen(ADBFactory(cfg_options))
    reactor.run()

    # After the reactor is stoped by hitting Control-C in a terminal
    log('Exiting...', cfg_options)
    stop_plugins(cfg_options)


if __name__ == '__main__':
    main()
