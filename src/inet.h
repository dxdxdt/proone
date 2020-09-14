#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// TODO: don't use these
#include <linux/ip.h>
#include <linux/ipv6.h>


void prne_netmask_from_cidr (uint8_t *out, size_t cidr);
uint16_t prne_calc_tcp_chksum4 (
	const struct iphdr *ih,
	const uint8_t *th,
	size_t th_len,
	const uint8_t *data,
	size_t data_len);
uint16_t prne_calc_tcp_chksum6 (
	const struct ipv6hdr *ih,
	const uint8_t *th,
	size_t th_len,
	const uint8_t *data,
	size_t data_len);
