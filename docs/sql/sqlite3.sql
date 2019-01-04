CREATE TABLE IF NOT EXISTS `commands` (
  `id` INTEGER PRIMARY KEY,
  `input` varchar(3000) NOT NULL,
  `inputhash` varchar(66) NOT NULL
);

CREATE TABLE IF NOT EXISTS `connections` (
  `id` INTEGER PRIMARY KEY,
  `session` char(32) NOT NULL,
  `starttime` datetime DEFAULT NULL,
  `endtime` datetime DEFAULT NULL,
  `sensor` int(4) DEFAULT NULL,
  `ip` varchar(15) DEFAULT NULL,
  `local_port` int(11) DEFAULT NULL,
  `country_name` varchar(45) DEFAULT '',
  `city_name` varchar(128) DEFAULT '',
  `org` varchar(128) DEFAULT '',
  `country_iso_code` varchar(2) DEFAULT '',
  `org_asn` int(11) DEFAULT NULL,
  `local_host` varchar(15) DEFAULT NULL,
  `remote_port` int(11) DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS `downloads` (
  `id` INTEGER PRIMARY KEY,
  `session` varchar(32) DEFAULT NULL,
  `timestamp` datetime DEFAULT NULL,
  `filesize` int(11) DEFAULT NULL,
  `download_sha_hash` varchar(65) DEFAULT NULL,
  `outfile` text
);

CREATE TABLE IF NOT EXISTS `input` (
  `id` INTEGER PRIMARY KEY,
  `session` char(32) NOT NULL,
  `timestamp` datetime NOT NULL,
  `success` tinyint(1) NOT NULL,
  `input` int(11) NOT NULL
);

CREATE TABLE IF NOT EXISTS `sensors` (
  `id` INTEGER PRIMARY KEY,
  `name` varchar(255) DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS `virustotals` (
  `virustotal` INTEGER PRIMARY KEY,
  `virustotal_md5_hash` varchar(32) NOT NULL,
  `virustotal_timestamp` int(11) NOT NULL,
  `virustotal_permalink` text NOT NULL
);

CREATE TABLE IF NOT EXISTS `virustotalscans` (
  `virustotalscan` INTEGER PRIMARY KEY,
  `virustotal` int(11) NOT NULL,
  `virustotalscan_scanner` varchar(256) NOT NULL,
  `virustotalscan_result` varchar(512) DEFAULT NULL
);


