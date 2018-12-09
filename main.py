#!/usr/bin/env python

from __future__ import print_function
import hashlib
import os
import protocol
import socket
import struct
import sys
import threading
import time
import datetime
import binascii
from argparse import ArgumentParser
from core.config import CONFIG

__VERSION__ = '1.00'

MAX_READ_COUNT = 4096 * 4096
# sleep 1 second after each empty packets, wait 1 hour in total
MAX_EMPTY_PACKETS = 360

def stop_plugins(output_plugins, cfg):
    log('Stoping plugins ... ', cfg)
    for plugin in output_plugins:
        try:
            plugin.stop()
        except:
            continue

def import_plugins(cfg):
    # Load output modules (inspired by the Cowrie honeypot)
    log('Loading plugins...', cfg)
    output_plugins = []
    sensor = cfg['sensor']
    for x in CONFIG.sections():
        if not x.startswith('output_'):
            continue
        if CONFIG.getboolean(x, 'enabled') is False:
            continue
        engine = x.split('_')[1]
        try:
            output = __import__('output_plugins.{}'.format(engine),
                                globals(), locals(), ['output'], -1).Output(sensor)
            output_plugins.append(output)
            log('Loaded output engine: {}'.format(engine), cfg)
        except ImportError as e:
            log('Failed to load output engine: {} due to ImportError: {}'.format(engine, e), cfg)
        except Exception:
            log('Failed to load output engine: {}'.format(engine), cfg)
    return output_plugins

def write_event(event, output_plugins):
    for plugin in output_plugins:
        try:
            plugin.write(event)
        except:
            continue

def log(message, cfg):
    if cfg['logfile'] is None:
        print(message)
        sys.stdout.flush()
    else:
        with open(cfg['logfile'], 'a') as f:
            print(message, file=f)

def getutctime():
    return datetime.datetime.utcnow().isoformat() + 'Z'

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

def dump_file_data(addr, real_fname, data, session, cfg, output_plugins):
    download_limit_size = CONFIG.getint('honeypot', 'download_limit_size', fallback=0)
    data_len = len(data)
    if download_limit_size and data_len > download_limit_size:
        return
    if cfg['download_dir'] and not os.path.exists(cfg['download_dir']):
        os.makedirs(cfg['download_dir'])
    shasum = hashlib.sha256(data).hexdigest()
    fname = 'data-{}.raw'.format(shasum)
    fullname = os.path.join(cfg['download_dir'], fname)
    log('{}\t{}\tfile:{} - dumping {} bytes of data to {}...'.format(
        getutctime(), addr[0], real_fname, len(data), fullname), cfg)
    event = {
        'eventid': 'adbhoney.session.file_upload',
        'timestamp': getutctime(),
        'unixtime': int(time.time()),
        'session': session,
        'message': 'Downloaded file with SHA-256 {} to {}'.format(shasum, fullname),
        'src_ip': addr[0],
        'shasum': shasum,
        'outfile': fullname,
        'sensor': cfg['sensor']
    }
    write_event(event, output_plugins)
    if not os.path.exists(fullname):
        with open(fullname, 'wb') as f:
            f.write(data)

def send_message(conn, command, arg0, arg1, data, cfg):
    newmessage = protocol.AdbMessage(command, arg0, arg1, data)
    if cfg['debug']:
        log('>>>>{}'.format(newmessage), cfg)
    conn.sendall(newmessage.encode())

def send_twice(conn, command, arg0, arg1, data, cfg):
    send_message(conn, command, arg0, arg1, data, cfg)
    send_message(conn, command, arg0, arg1, data, cfg)

def process_connection(conn, addr, cfg, output_plugins):
    start = time.time()
    session = binascii.hexlify(os.urandom(6))
    localip = getlocalip()
    sensor = cfg['sensor']
    log('{}\t{}\tconnection start ({})'.format(getutctime(), addr[0], session), cfg)
    event = {
        'eventid': 'adbhoney.session.connect',
        'timestamp': getutctime(),
        'unixtime': int(start),
        'session': session,
        'message': 'New connection: {}:{} ({}:{}) [session: {}]'.format(addr[0], addr[1], localip, cfg['port'], session),
        'src_ip': addr[0],
        'src_port': addr[1],
        'dst_ip': localip,
        'dst_port': cfg['port'],
        'sensor': sensor
    }
    write_event(event, output_plugins)

    states = []
    sending_binary = False
    dropped_file = ''
    empty_packets = 0
    filename = 'unknown'
    closedmessage = 'Connection closed'
    while True:
        debug_content = bytes()
        try:
            command = conn.recv(4)
            if not command:
                empty_packets += 1
                if empty_packets > MAX_EMPTY_PACKETS:
                    break
                # wait for more data
                time.sleep(1)
                continue
            empty_packets = 0
            debug_content += command
            arg1 = conn.recv(4)
            debug_content += arg1
            arg2 = conn.recv(4)
            debug_content += arg2
            data_length_raw = conn.recv(4)
            debug_content += data_length_raw
            data_length = struct.unpack('<L', data_length_raw)[0]
            data_crc = conn.recv(4)
            magic = conn.recv(4)
            data_content = bytes()

            if data_length > 0:
                # prevent reading the same stuff over and over again from some other attackers and locking the honeypot
                # max 1 byte read 64*4096 times (max packet length for ADB)
                read_count = 0

                while len(data_content) < data_length and read_count < MAX_READ_COUNT:
                    read_count += 1
                    # don't overread the content of the next data packet
                    bytes_to_read = data_length - len(data_content)
                    data_content += conn.recv(bytes_to_read)
            # check integrity of read data
            if len(data_content) < data_length:
                # corrupt content, abort the connection (probably not an ADB client)
                break
            # assemble a full data packet as per ADB specs
            data = command + arg1 + arg2 + data_length_raw + data_crc + magic + data_content
        except Exception as ex:
            closedmessage = 'Connection reset by peer'
            log('{}\t{}\t {} : {}'.format(getutctime(), addr[0], repr(ex), repr(debug_content)), cfg)
            break

        try:
            message = protocol.AdbMessage.decode(data)[0]
            if cfg['debug']:
                # print message
                string = str(message)
                if len(string) > 96:
                    log('<<<<{} ...... {}'.format(string[0:64], string[-32:]), cfg)
                else:
                    log('<<<<{}'.format(string), cfg)
        except:
            # don't print anything, a lot of garbage coming in usually, just drop the connection
            break

        # keep a record of all the previous states in order to handle some weird cases
        states.append(message.command)

        # corner case for binary sending
        if sending_binary:
            # look for that shitty DATAXXXX where XXXX is the length of the data block that's about to be sent
            # (i.e. DATA\x00\x00\x01\x00)
            if message.command == protocol.CMD_WRTE and 'DATA' in message.data:
                data_index = message.data.index('DATA')
                payload_fragment = message.data[:data_index] + message.data[data_index + 8:]
                dropped_file += payload_fragment
            elif message.command == protocol.CMD_WRTE:
                dropped_file += message.data

            # truncate
            if 'DONE' in message.data:
                dropped_file = dropped_file[:-8]
                sending_binary = False
                dump_file_data(addr, filename, dropped_file, session, cfg, output_plugins)
                # ADB has a shitty state machine, sometimes we need to send duplicate messages
                send_twice(conn, protocol.CMD_WRTE, 2, message.arg0, 'OKAY', cfg)
                send_twice(conn, protocol.CMD_OKAY, 2, message.arg0, '', cfg)
                continue

            if message.command != protocol.CMD_WRTE:
                dropped_file += data

            send_twice(conn, protocol.CMD_OKAY, 2, message.arg0, '', cfg)
            continue

        else:   # regular flow
            # look for the data header that is first sent when initiating a data connection
            '''  /sdcard/stuff/exfiltrator-network-io.PNG,33206DATA '''
            if 'DATA' in message.data[:128]:
                sending_binary = True
                dropped_file = ''
                seq_number = 1
                # if the message is really short, wrap it up
                if 'DONE' in message.data[-8:]:
                    sending_binary = False
                    predata = message.data.split('DATA')[0]
                    if predata:
                        filename = predata.split(',')[0]

                    dropped_file = message.data.split('DATA')[1][4:-8]

                    send_twice(conn, protocol.CMD_WRTE, 2, message.arg0, 'OKAY', cfg)
                    send_twice(conn, protocol.CMD_OKAY, 2, message.arg0, '', cfg)

                    dump_file_data(addr, filename, dropped_file, session, cfg, output_plugins)
                    continue
                else:
                    predata = message.data.split('DATA')[0]
                    if predata:
                        filename = predata.split(',')[0]
                    dropped_file = message.data.split('DATA')[1][4:]

                send_twice(conn, protocol.CMD_OKAY, 2, message.arg0, '', cfg)
                continue

            if len(states) >= 2 and states[-2:] == [protocol.CMD_WRTE, protocol.CMD_WRTE]:
                # last block of messages before the big block of data
                filename = message.data
                send_message(conn, protocol.CMD_OKAY, 2, message.arg0, '', cfg)
                # why do I have to send the command twice??? science damn it!
                send_twice(conn, protocol.CMD_WRTE, 2, message.arg0, 'STAT\x07\x00\x00\x00', cfg)
            elif len(states) > 2 and states[-2:] == [protocol.CMD_OKAY, protocol.CMD_WRTE]:
                send_message(conn, protocol.CMD_OKAY, 2, message.arg0, '', cfg)
                # send_message(conn, protocol.CMD_WRTE, 2, message.arg0, 'FAIL', cfg)
            elif len(states) > 1 and states[-2:] == [protocol.CMD_OPEN, protocol.CMD_WRTE]:
                send_message(conn, protocol.CMD_OKAY, 2, message.arg0, '', cfg)
                if len(message.data) > 8:
                    send_twice(conn, protocol.CMD_WRTE, 2, message.arg0, 'STAT\x01\x00\x00\x00', cfg)
                    filename = message.data[8:]
            elif states[-1] == protocol.CMD_OPEN and 'shell' in message.data:
                send_message(conn, protocol.CMD_OKAY, 2, message.arg0, '', cfg)
                # change the WRTE contents with whatever you'd like to send to the attacker
                send_message(conn, protocol.CMD_WRTE, 2, message.arg0, '', cfg)
                send_message(conn, protocol.CMD_CLSE, 2, message.arg0, '', cfg)
                # print the shell command that was sent
                # also remove trailing \00
                log('{}\t{}\t{}'.format(getutctime(), addr[0], message.data[:-1]), cfg)
                event = {
                    'eventid': 'adbhoney.command.input',
                    'timestamp': getutctime(),
                    'unixtime': int(time.time()),
                    'session': session,
                    'message': message.data[:-1],
                    'src_ip': addr[0],
                    'input': message.data[6:-1],
                    'sensor': sensor
                }
                write_event(event, output_plugins)
            elif states[-1] == protocol.CMD_CNXN:
                send_message(conn, protocol.CMD_CNXN, 0x01000000, 4096, cfg['device_id'].encode('utf8'), cfg)
            elif states[-1] == protocol.CMD_OPEN and 'sync' not in message.data:
                send_message(conn, protocol.CMD_OKAY, 2, message.arg0, '', cfg)
            elif states[-1] == protocol.CMD_OPEN:
                send_message(conn, protocol.CMD_OKAY, 2, message.arg0, '', cfg)
            elif states[-1] == protocol.CMD_CLSE and not sending_binary:
                send_message(conn, protocol.CMD_CLSE, 2, message.arg0, '', cfg)
            elif states[-1] == protocol.CMD_WRTE and 'QUIT' in message.data:
                send_message(conn, protocol.CMD_OKAY, 2, message.arg0, '', cfg)
                send_message(conn, protocol.CMD_CLSE, 2, message.arg0, '', cfg)

    duration = time.time() - start
    log('{}\t{}\tconnection closed ({})'.format(getutctime(), addr[0], session), cfg)
    event = {
        'eventid': 'adbhoney.session.closed',
        'timestamp': getutctime(),
        'unixtime': int(time.time()),
        'session': session,
        'message': '{} after {} seconds'.format(closedmessage, int(round(duration))),
        'src_ip': addr[0],
        'duration': duration,
        'sensor': sensor
    }
    write_event(event, output_plugins)
    conn.close()

def main_coonection_loop(cfg):
    bind_addr = cfg['addr']
    bind_port = cfg['port']
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    """ Set TCP keepalive on an open socket.

        It activates after 1 second (after_idle_sec) of idleness,
        then sends a keepalive ping once every 1 seconds (interval_sec),
        and closes the connection after 100 failed ping (max_fails)
    """
    s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    # pylint: disable=no-member
    if hasattr(socket, 'TCP_KEEPIDLE'):
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 1)
    elif hasattr(socket, 'TCP_KEEPALIVE'):
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPALIVE, 1)
    if hasattr(socket, 'TCP_KEEPINTVL'):
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 1)
    if hasattr(socket, 'TCP_KEEPCNT'):
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 100)
    # pylint: enable=no-member
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)
    s.bind((bind_addr, bind_port))
    s.listen(1)
    log('Listening on {}:{}.'.format(bind_addr, bind_port), cfg)
    output_plugins = import_plugins(cfg)
    try:
        while True:
            conn, addr = s.accept()
            thread = threading.Thread(target=process_connection, args=(conn, addr, cfg, output_plugins))
            thread.daemon = True
            thread.start()
    except KeyboardInterrupt:
        log('Exiting...', cfg)
        stop_plugins(output_plugins, cfg)
        s.close()

if __name__ == '__main__':

    cfg = {}

    cfg['addr'] = CONFIG.get('honeypot', 'out_addr', fallback='0.0.0.0')
    cfg['port'] = CONFIG.getint('honeypot', 'listen_port', fallback=5555)
    cfg['download_dir'] = CONFIG.get('honeypot', 'download_path', fallback='')
    log_name = CONFIG.get('honeypot', 'log_filename', fallback='')
    if log_name:
        cfg['logfile'] = os.path.join(CONFIG.get('honeypot', 'log_path', fallback=''), log_name)
    else:
        cfg['logfile'] = None
    cfg['sensor'] = CONFIG.get('honeypot', 'sensor_name', fallback=socket.gethostname())
    cfg['debug'] = CONFIG.getboolean('honeypot', 'debug', fallback=False)
    cfg['device_id'] = CONFIG.get('honeypot', 'id_string',
                                  fallback='device::http://ro.product.name =starltexx;ro.product.model=SM-G960F;ro.product.device=starlte;features=cmd,stat_v2,shell_v2')

    parser = ArgumentParser(version='%(prog)s version ' + __VERSION__, description='ADB Honeypot')

    parser.add_argument('-a', '--addr', type=str, default=cfg['addr'], help='Address to bind to (default: {})'.format(cfg['addr']))
    parser.add_argument('-p', '--port', type=int, default=cfg['port'], help='Port to listen on (default: {})'.format(cfg['port']))
    parser.add_argument('-d', '--dlfolder', type=str, default=cfg['download_dir'], help='Directory for the uploaded samples (default: current)')
    parser.add_argument('-l', '--logfile', type=str, default=cfg['logfile'], help='Log file (default: stdout')
    parser.add_argument('-s', '--sensor', type=str, default=cfg['sensor'], help='Sensor name (default: {})'.format(cfg['sensor']))
    parser.add_argument('-b', '--debug', action='store_true', help='Produce verbose output')

    args = parser.parse_args()

    cfg['addr'] = args.addr
    cfg['port'] = args.port
    cfg['download_dir'] = args.dlfolder
    cfg['logfile'] = args.logfile
    cfg['sensor'] = args.sensor
    cfg['debug'] = args.debug

    main_coonection_loop(cfg)
