CREATE TABLE `prne-hi` (
	`instance_id` binary(16) NOT NULL,
	`inserted` datetime NOT NULL,
	`updated` datetime NOT NULL,
	`parent_uptime` bigint(20) unsigned DEFAULT NULL,
	`child_uptime` bigint(20) unsigned DEFAULT NULL,
	`bne_cnt` bigint(20) unsigned DEFAULT NULL,
	`infect_cnt` bigint(20) unsigned DEFAULT NULL,
	`parent_pid` int(11) unsigned DEFAULT NULL,
	`child_pid` int(11) unsigned DEFAULT NULL,
	`prog_ver` binary(16) DEFAULT NULL,
	`boot_id` binary(16) DEFAULT NULL,
	`cred_id` varchar(255) DEFAULT NULL,
	`cred_pw` varchar(255) DEFAULT NULL,
	`crash_cnt` int(10) unsigned DEFAULT NULL,
	`arch` varchar(255) DEFAULT NULL,
	`ipaddr` binary(16) DEFAULT NULL,
	PRIMARY KEY (`instance_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
