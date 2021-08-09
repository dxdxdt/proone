CREATE TABLE `prne-hi` (
	`instance_id` binary(16) NOT NULL,
	`org_id` binary(16) DEFAULT NULL,
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
	`arch` tinyint unsigned DEFAULT NULL,
	`os` tinyint unsigned DEFAULT NULL,
	`flags` varbinary(255) DEFAULT NULL,
	`ipaddr` binary(16) DEFAULT NULL,
	PRIMARY KEY (`instance_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE VIEW `prne`.`prne-hi-view` AS
	SELECT
		HEX(`prne`.`prne-hi`.`instance_id`) AS `HEX(instance_id)`,
		HEX(`prne`.`prne-hi`.`org_id`) AS `HEX(org_id)`,
		`prne`.`prne-hi`.`inserted` AS `inserted`,
		`prne`.`prne-hi`.`updated` AS `updated`,
		`prne`.`prne-hi`.`parent_uptime` AS `parent_uptime`,
		`prne`.`prne-hi`.`child_uptime` AS `child_uptime`,
		`prne`.`prne-hi`.`bne_cnt` AS `bne_cnt`,
		`prne`.`prne-hi`.`infect_cnt` AS `infect_cnt`,
		`prne`.`prne-hi`.`parent_pid` AS `parent_pid`,
		`prne`.`prne-hi`.`child_pid` AS `child_pid`,
		HEX(`prne`.`prne-hi`.`prog_ver`) AS `HEX(prog_ver)`,
		HEX(`prne`.`prne-hi`.`boot_id`) AS `HEX(boot_id)`,
		`prne`.`prne-hi`.`cred_id` AS `cred_id`,
		`prne`.`prne-hi`.`cred_pw` AS `cred_pw`,
		`prne`.`prne-hi`.`crash_cnt` AS `crash_cnt`,
		`prne`.`prne-hi`.`arch` AS `arch`,
		`prne`.`prne-hi`.`os` AS `os`,
		HEX(`prne`.`prne-hi`.`flags`) AS `flags`,
		INET6_NTOA(`prne`.`prne-hi`.`ipaddr`) AS `INET6_NTOA(ipaddr)`
	FROM
		`prne`.`prne-hi`;
