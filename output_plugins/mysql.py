from __future__ import print_function
import os
import json
import MySQLdb
import time
import datetime
import calendar
import geoip2.database
import requests
import hashlib
import core.output
from core.config import CONFIG
from adbhoney import log


class Output(core.output.Output):

    def __init__(self, general_options):

        self.host = CONFIG.get('output_mysql', 'host', fallback='localhost')
        self.database = CONFIG.get('output_mysql', 'database', fallback='')
        self.user = CONFIG.get('output_mysql', 'username', fallback='')
        self.password = CONFIG.get('output_mysql', 'password', fallback='')
        self.port = CONFIG.getint('output_mysql', 'port', fallback=3306)

        self.geoipdb_city_path = CONFIG.get('output_mysql', 'geoip_citydb', fallback='')
        self.geoipdb_asn_path = CONFIG.get('output_mysql', 'geoip_asndb', fallback='')

        self.debug = CONFIG.getboolean('output_mysql', 'debug', fallback=False)
        self.geoip = CONFIG.getboolean('output_mysql', 'geoip', fallback=True)

        self.virustotal = CONFIG.getboolean('output_mysql', 'virustotal', fallback=True)
        self.vtapikey = CONFIG.get('output_mysql', 'virustotal_api_key', fallback='')

        core.output.Output.__init__(self, general_options)

    def _local_log(self, msg):
        if self.debug:
            log(msg, self.cfg)

    def start(self):
        try:
            self.dbh = MySQLdb.connect(host=self.host, user=self.user, passwd=self.password,
                db=self.database, port=self.port, charset='utf8', use_unicode=True)
        except:
            self._local_log('Unable to connect the database')

        self.cursor = self.dbh.cursor()

        if self.geoip:
            try:
                self.reader_city = geoip2.database.Reader(self.geoipdb_city_path)
            except:
                self._local_log('Failed to open GeoIP database {}'.format(self.geoipdb_city_path))

            try:
                self.reader_asn = geoip2.database.Reader(self.geoipdb_asn_path)
            except:
                self._local_log('Failed to open GeoIP database {}'.format(self.geoipdb_asn_path))

    def stop(self):
        self.cursor.close()
        self.cursor = None
        self.dbh.close()
        self.dbh = None
        if self.geoip:
            if self.reader_city is not None:
               self.reader_city.close()
            if self.reader_asn is not None:
               self.reader_asn.close()

    def write(self, event):
        """
        TODO: Check if the type (date, datetime or timestamp) of columns is appropriate for your needs and timezone
        - MySQL Documentation - The DATE, DATETIME, and TIMESTAMP Types
            (https://dev.mysql.com/doc/refman/5.7/en/datetime.html):
        "MySQL converts TIMESTAMP values from the current time zone to UTC for storage,
        and back from UTC to the current time zone for retrieval.
        (This does not occur for other types such as DATETIME.)"
        """
        if 'connect' in event['eventid']:
            self._connect_event(event)

        if 'file_upload' in event['eventid']:
            try:
                self.cursor.execute("""
                    INSERT INTO downloads (
                        session, timestamp, filesize, download_sha_hash, fullname)
                    VALUES (%s,FROM_UNIXTIME(%s),%s,%s,%s)""",
                    (event['session'], event['unixtime'], event['file_size'],
                        event['shasum'], event['fullname']))
                self.dbh.commit()
            except Exception as e:
                self._local_log(e)

            if self.virustotal:
                self._upload_event_vt(event)

        if 'input' in event['eventid']:
            self._input_event(event)

        if 'closed' in event['eventid']:
            try:
                self.cursor.execute("UPDATE connections SET endtime = FROM_UNIXTIME(%s) WHERE session = %s",
                                        (event['unixtime'], event['session']) )
                self.dbh.commit()
            except Exception as e:
                self._local_log(e)

    def _connect_event(self, event):
        remote_ip = event['src_ip']
        if self.geoip:
            try:
                response_city = self.reader_city.city(remote_ip)
                city = response_city.city.name
                if city is None:
                    city = ''
                country = response_city.country.name
                if country is None:
                    country = ''
                    country_code = ''
                else:
                    country_code = response_city.country.iso_code
            except Exception as e:
                self._local_log(e)
                city = ''
                country = ''
                country_code = ''

            try:
                response_asn = self.reader_asn.asn(remote_ip)
                if response_asn.autonomous_system_organization is not None:
                    org = response_asn.autonomous_system_organization.encode('utf8')
                else:
                    org = ''

                if response_asn.autonomous_system_number is not None:
                    asn_num = response_asn.autonomous_system_number
                else:
                    asn_num = 0
            except Exception as e:
                self._local_log(e)
                org = ''
                asn_num = 0
        else:
            city = ''
            country = ''
            country_code = ''
            org = ''
            asn_num = 0

        try:
            is_exist = self.cursor.execute("SELECT id, name FROM sensors WHERE name='%s'" % event['sensor'])
            if not is_exist:
                self.cursor.execute("INSERT INTO sensors (name) VALUES ('%s')" % (event['sensor']))
                self.dbh.commit()
                sensor_id = self.cursor.lastrowid
            else:
                sensor_id = self.cursor.fetchall()[0][0]
        except Exception as e:
            self._local_log(e)
            sensor_id = None

        try:
            self.cursor.execute("""
                INSERT INTO connections (
                    session, starttime, endtime, sensor, ip, local_port,
                    country_name, city_name, org, country_iso_code, org_asn,
                    local_host, remote_port)
                VALUES (%s,FROM_UNIXTIME(%s),%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """,
                (event['session'], event['unixtime'], None, sensor_id,
                    event['src_ip'], event['dst_port'], country, city, org,
                    country_code, asn_num, event['dst_ip'], event['src_port']))
            self.dbh.commit()
        except Exception as e:
            self._local_log(e)

    def _upload_event_vt(self, event):
        shasum = event['shasum']
        is_exist = self.cursor.execute("""SELECT virustotal_sha256_hash
                                            FROM virustotals
                                            WHERE virustotal_sha256_hash='%s'""" % shasum)
        if is_exist == 0:
            if self.vtapikey:
                url = 'https://www.virustotal.com/vtapi/v2/file/report'
                params = {'apikey': self.vtapikey, 'resource': shasum}
                try:
                    response = requests.get(url, params=params)
                    j = response.json()
                    if j['response_code'] == -2:
                        time.sleep(63)
                        response = requests.get(url, params=params)
                        j = response.json()
                except Exception as e:
                    self._local_log(e)
                    j = {'response_code': -2}

            if j['response_code'] == 1: # file was known to virustotal
                permalink = j['permalink']
                # Convert UTC scan_date to local Unix time
                unixtime = time.mktime(time.strptime(j['scan_date'], '%Y-%m-%d %H:%M:%S')) - time.timezone
                try:
                    self.cursor.execute("""INSERT INTO virustotals (
                                                virustotal_sha256_hash,
                                                virustotal_permalink,
                                                virustotal_timestamp)
                                                VALUES (%s,%s,%s)""",
                                        (shasum, permalink, unixtime))
                except Exception as e:
                    self._local_log(e)

                self.dbh.commit()

                virustotal = self.cursor.lastrowid

                scans = j['scans']
                for av, val in scans.items():
                    res = val['result']
                    # not detected = '' -> NULL
                    if res == '':
                        res = None
                    try:
                        self.cursor.execute("""INSERT INTO virustotalscans (
                                                    virustotal,
                                                    virustotalscan_scanner,
                                                    virustotalscan_result)
                                                    VALUES (%s,%s,%s)""",
                                            (virustotal, av, res))
                    except Exception as e:
                        self._local_log(e)
                    # self._local_log("scanner {} result {}".format(av, scans[av]))

                self.dbh.commit()

    def _emulate_command(self, command):
        # TODO: implement the logic
        return False

    def _input_event(self, event):
        commands = event['input'].split(';')
        for command in commands:
            sc = command.strip()
            shasum = hashlib.sha256(sc).hexdigest()
            command_id = self.cursor.execute("""SELECT id
                                            FROM commands
                                            WHERE inputhash='%s'""" % shasum)
            if not command_id:
                try:
                    self.cursor.execute("""INSERT INTO commands (
                                                input,
                                                inputhash)
                                                VALUES (%s,%s)""",
                                        (sc, shasum))
                    self.dbh.commit()
                    command_id = self.cursor.lastrowid
                except Exception as e:
                    self._local_log(e)
                    command_id = 0
            else:
                command_id = self.cursor.fetchall()[0][0]

            success = self._emulate_command(sc)
            try:
                self.cursor.execute("""INSERT INTO input (
                                        session,
                                        timestamp,
                                        success,
                                        input)
                                        VALUES (%s,FROM_UNIXTIME(%s),%s,%s)""",
                                (event['session'], event['unixtime'], success, command_id))
                self.dbh.commit()

            except Exception as e:
                self._local_log(e)
