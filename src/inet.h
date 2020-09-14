#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "protocol.h"


// Workaround for header issues in uClibc
typedef struct prne_iphdr4 prne_iphdr4_t;
typedef struct prne_iphdr6 prne_iphdr6_t;

struct prne_iphdr4 {
	uint8_t saddr[4];
	uint8_t daddr[4];
	uint16_t total_len;
	uint16_t id;
	uint8_t ttl;
	uint8_t protocol;
	uint8_t ihl;
};

struct prne_iphdr6 {
	uint8_t saddr[16];
	uint8_t daddr[16];
	uint32_t flow_label;
	uint16_t payload_len;
	uint8_t next_hdr;
	uint8_t hop_limit;
};

void prne_netmask_from_cidr (uint8_t *out, size_t cidr);
uint16_t prne_calc_tcp_chksum4 (
	const prne_iphdr4_t *ih,
	const uint8_t *th,
	size_t th_len,
	const uint8_t *data,
	size_t data_len);
uint16_t prne_calc_tcp_chksum6 (
	const prne_iphdr6_t *ih,
	const uint8_t *th,
	size_t th_len,
	const uint8_t *data,
	size_t data_len);

void prne_ser_iphdr4 (uint8_t *mem, const prne_iphdr4_t *in);
void prne_ser_iphdr6 (uint8_t *mem, const prne_iphdr6_t *in);

void prne_dser_iphdr4 (const uint8_t *data, prne_iphdr4_t *out);
void prne_dser_iphdr6 (const uint8_t *data, prne_iphdr6_t *out);
