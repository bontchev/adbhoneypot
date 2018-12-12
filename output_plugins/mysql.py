from __future__ import print_function
import os
import json
import MySQLdb
import time
import datetime
import calendar
import geoip2.database
import requests
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
        self.geoip = CONFIG.getboolean('output_mysql', 'geopip', fallback=True)

        self.virustotal = CONFIG.getboolean('output_mysql', 'virustotal', fallback=True)
        self.vtapikey = CONFIG.get('output_mysql', 'virustotal_api_key', fallback='')

        core.output.Output.__init__(self, general_options)


    def start(self):
        try:
            self.dbh = MySQLdb.connect(host=self.host, user=self.user, passwd=self.password, 
                db=self.database, port=self.port, charset='utf8', use_unicode=True)
        except:
            log('Unable to connect the database', self.cfg)

        self.cursor = self.dbh.cursor()

        try:
            self.reader_city = geoip2.database.Reader(self.geoipdb_city_path)
        except:
            log('Failed to open GeoIP database {}'.fomrat(self.geoipdb_city_path), self.cfg)

        try:
            self.reader_asn = geoip2.database.Reader(self.geoipdb_asn_path)
        except:
            log('Failed to open GeoIP database {}'.fomrat(self.geoipdb_asn_path), self.cfg)


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
        if 'connect' in event['eventid']:
            self._connect_event(event)

        if 'file_upload' in event['eventid']:
            try:
                timestamp = datetime.datetime.strptime(event['timestamp'], '%Y-%m-%dT%H:%M:%S.%fZ')
                self.cursor.execute("""
                    INSERT INTO downloads (
                        session, timestamp, filesize, download_sha_hash, fullname) 
                    VALUES (%s,%s,%s,%s,%s)""",
                    (event['session'], timestamp, event['file_size'], 
                        event['shasum'], event['fullname']))
                self.dbh.commit()
            except Exception as e:
                log(e, self.cfg)
            
            if self.virustotal:
                self._upload_event_vt(event)

        if 'input' in event['eventid']:
            # `commands` - string separated by ; 
            pass

        if 'closed' in event['eventid']:
            try:
                endtime = datetime.datetime.strptime(event['timestamp'], '%Y-%m-%dT%H:%M:%S.%fZ')
                self.cursor.execute("UPDATE connections SET endtime = %s WHERE session = %s",
                                        (endtime, event['session']) )
                self.dbh.commit()
            except Exception as e:
                log(e, self.cfg)

    def _connect_event(self, event):
        remote_ip = event['src_ip']
        try:
            response_city = self.reader_city.city(remote_ip)
            city = response_city.city.name
            if city is None:
                city = ""
            country = response_city.country.name
            if country is None:
                country = ''
                country_code = ''
            else:            
                country_code = response_city.country.iso_code
        except Exception as e:
            log(e, self.cfg)
            city = ""
            country = ""
            country_code = ''
        
        try:
            response_asn = self.reader_asn.asn(remote_ip)
            if response_asn.autonomous_system_organization is not None:
                org = response_asn.autonomous_system_organization.encode('utf8')
            else:
                org = ""
                
            if response_asn.autonomous_system_number is not None:
                asn_num = response_asn.autonomous_system_number
            else:
                asn_num = 0
        except Exception as e:
            log(e, self.cfg)
            org = ""
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
            log(e, self.cfg)
            sensor_id = None    

        try:
            starttime = datetime.datetime.strptime(event['timestamp'], '%Y-%m-%dT%H:%M:%S.%fZ')
            self.cursor.execute("""
                INSERT INTO connections (
                    session, starttime, endtime, sensor, ip, local_port, 
                    country_name, city_name, org, country_iso_code, org_asn, 
                    local_host, remote_port) 
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """, 
                (event['session'], starttime, None, sensor_id, 
                    event['src_ip'], event['dst_port'], country, city, org, 
                    country_code, asn_num, event['dst_ip'], event['src_port']))
            self.dbh.commit()                            
        except Exception as e:
            log(e, self.cfg)        

    def _upload_event_vt(self, event):
            # `virustotals`
            # `virustotalscans`
            pass 
