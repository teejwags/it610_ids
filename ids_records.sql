CREATE TABLE `ids_records` (
  `x` int(11) NOT NULL AUTO_INCREMENT,
  `timestamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `source_mac` varchar(20) NOT NULL,
  `source_ip` varchar(15) NOT NULL,
  `source_port` int(5) DEFAULT NULL,
  `dest_port` int(5) DEFAULT NULL,
  `payload` text,
  PRIMARY KEY (`x`,`timestamp`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=latin1;
