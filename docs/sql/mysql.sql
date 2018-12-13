CREATE TABLE IF NOT EXISTS `commands` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `input` varchar(3000) NOT NULL,
  `inputhash` varchar(66) NOT NULL,
  PRIMARY KEY (`id`)
);   

CREATE TABLE IF NOT EXISTS `connections` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
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
  `remote_port` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`)
);   

CREATE TABLE IF NOT EXISTS `downloads` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `session` varchar(32) DEFAULT NULL,
  `timestamp` datetime DEFAULT NULL,
  `filesize` int(11) DEFAULT NULL,
  `download_sha_hash` varchar(65) DEFAULT NULL,
  `fullname` text,
  PRIMARY KEY (`id`)
);   

CREATE TABLE IF NOT EXISTS `input` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `session` char(32) NOT NULL,
  `timestamp` datetime NOT NULL,
  `success` tinyint(1) NOT NULL,
  `input` int(11) NOT NULL,
  PRIMARY KEY (`id`)
);   

CREATE TABLE IF NOT EXISTS `sensors` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
);   

CREATE TABLE IF NOT EXISTS `virustotals` (
  `virustotal` int(11) NOT NULL AUTO_INCREMENT,
  `virustotal_sha256_hash` varchar(65) NOT NULL,
  `virustotal_timestamp` int(11) NOT NULL,
  `virustotal_permalink` text NOT NULL,
  PRIMARY KEY (`virustotal`)
);
   
CREATE TABLE IF NOT EXISTS `virustotalscans` (
  `virustotalscan` int(11) NOT NULL AUTO_INCREMENT,
  `virustotal` int(11) NOT NULL,
  `virustotalscan_scanner` varchar(256) NOT NULL,
  `virustotalscan_result` varchar(512) DEFAULT NULL,
  PRIMARY KEY (`virustotalscan`)
);   


