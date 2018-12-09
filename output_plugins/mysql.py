from __future__ import print_function
import os
import json
import MySQLdb
import logging
import time
import datetime
import calendar
import geoip2.database
import requests
import core.output
from core.config import CONFIG


class Output(core.output.Output):

    def __init__(self, sensor=None):

        self.host = CONFIG.get('output_mysql', 'host', fallback='localhost')
        self.database = CONFIG.get('output_mysql', 'database', fallback='')
        self.user = CONFIG.get('output_mysql', 'username', fallback='')
        self.password = CONFIG.get('output_mysql', 'password', fallback='')
        self.port = CONFIG.getint('output_mysql', 'port', fallback=3306)

        self.geoipdb_city_path = CONFIG.get('output_mysql', 'geoip_citydb', fallback='')
        self.geoipdb_asn_path = CONFIG.get('output_mysql', 'geoip_asndb', fallback='')

        self.debug = CONFIG.getboolean('output_mysql', 'debug', fallback=False)
        self.geoip = CONFIG.getboolean('output_mysql', 'geopip', fallback=True)

        self.virustotal = CONFIG.getboolean('output_mysql', 'virustotal', fallback=True)
        self.vtapikey = CONFIG.get('output_mysql', 'virustotal_api_key', fallback='')

        core.output.Output.__init__(self, sensor)


    def start(self):
        try:
            self.dbh = MySQLdb.connect(host=self.host, user=self.user, passwd=self.password, db=self.database, port=self.port, charset="utf8", use_unicode=True)
        except:
            print("Unable to connect the database")

        self.cursor = self.dbh.cursor()

        try:
            self.reader_city = geoip2.database.Reader(self.geoipdb_city_path)
        except:
            logger.warning("Failed to open GeoIP database %s", self.geoipdb_city_path)

        try:
            self.reader_asn = geoip2.database.Reader(self.geoipdb_asn_path)
        except:
            logger.warning("Failed to open GeoIP database %s", self.geoipdb_asn_path)


    def stop(self):
        self.cursor.close()
        self.cursor = None
        self.dbh.close()
        self.dbh = None
        if self.reader_city is not None:
           self.reader_city.close()
        if self.reader_asn is not None:
           self.reader_asn.close()

    def write(self, event):
        # self.sensor -> `sensors`
        if event['eventid'] == 'adbhoney.session.file_upload':
            # `downloads`
            # `virustotals`
            # `virustotalscans`
            pass
        if event['eventid'] == 'adbhoney.session.connect':
            # `connections`
            pass
        if event['eventid'] == 'adbhoney.command.input':
            # `commands`
            pass
        if event['eventid'] == 'adbhoney.session.closed':
            # `connections` ?
            pass



# event = {
#             'eventid': 'adbhoney.session.file_upload',
#             'timestamp': getutctime(),
#             'unixtime': int(time.time()),
#             'session': session,
#             'message': 'Downloaded file with SHA-256 {} to {}'.format(shasum, fullname),
#             'src_ip': addr[0],
#             'shasum': shasum,
#             'outfile': fullname,
#             'sensor': sensor
#         }

# event = {
#         'eventid': 'adbhoney.session.connect',
#         'timestamp': getutctime(),
#         'unixtime': int(start),
#         'session': session,
#         'message': ''.format(),
#         'src_ip': addr[0],
#         'src_port': addr[1],
#         'dst_ip': getlocalip(),
#         'dst_port': bind_port,
#         'sensor': sensor
#     }


# event = {
#         'eventid': 'adbhoney.command.input',
#         'timestamp': getutctime(),
#         'unixtime': int(time.time()),
#         'session': session,
#         'message': message.data[:-1],
#         'src_ip': addr[0],
#         'input': message.data[6:-1],
#         'sensor': sensor
#     }


# event = {
#         'eventid': 'adbhoney.session.closed',
#         'timestamp': getutctime(),
#         'unixtime': int(time.time()),
#         'session': session,
#         'message': '{} after {} seconds'.format(closedmessage, int(round(duration))),
#         'src_ip': addr[0],
#         'duration': duration,
#         'sensor': sensor
#     }

