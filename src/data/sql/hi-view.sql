SELECT
	HEX(instance_id),
	inserted,
	updated,
	parent_uptime,
	child_uptime,
	bne_cnt,
	infect_cnt,
	parent_pid,
	child_pid,
	HEX(prog_ver),
	HEX(boot_id),
	cred_id,
	cred_pw,
	crash_cnt,
	arch,
	INET6_NTOA(ipaddr)
FROM prne.`prne-hi`;
