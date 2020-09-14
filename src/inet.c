#include "inet.h"
#include "endian.h"


void prne_netmask_from_cidr (uint8_t *out, size_t cidr) {
	size_t shft = 7;

	while (cidr >= 8) {
		*out = 0xFF;
		cidr -= 8;
		out += 1;
	}
	*out = 0;
	while (cidr > 0) {
		*out |= (uint8_t)(1 << shft);
		shft -= 1;
		cidr -= 1;
	}
}

uint16_t prne_calc_tcp_chksum4 (
	const struct iphdr *ih,
	const uint8_t *th,
	size_t th_len,
	const uint8_t *data,
	size_t data_len)
{
	uint_fast32_t sum = 0;

	// pseudo
	sum += prne_recmb_msb16(
		((uint8_t*)&ih->saddr)[0],
		((uint8_t*)&ih->saddr)[1]);
	sum += prne_recmb_msb16(
		((uint8_t*)&ih->saddr)[2],
		((uint8_t*)&ih->saddr)[3]);

	sum += prne_recmb_msb16(
		((uint8_t*)&ih->daddr)[0],
		((uint8_t*)&ih->daddr)[1]);
	sum += prne_recmb_msb16(
		((uint8_t*)&ih->daddr)[2],
		((uint8_t*)&ih->daddr)[3]);
	sum += 6; // IPPROTO_TCP
	sum += (uint16_t)(th_len + data_len);

	// tcp header
	while (th_len > 1) {
		sum += prne_recmb_msb16(th[0], th[1]);
		th += 2;
		th_len -= 2;
	}
	if (th_len > 0) {
		sum += th[0];
	}

	// data
	while (data_len > 1) {
		sum += prne_recmb_msb16(data[0], data[1]);
		data += 2;
		data_len -= 2;
	}
	if (data_len > 0) {
		sum += data[0];
	}

	return ~((sum & 0xFFFF) + (sum >> 16));
}

uint16_t prne_calc_tcp_chksum6 (
	const struct ipv6hdr *ih,
	const uint8_t *th,
	size_t th_len,
	const uint8_t *data,
	size_t data_len)
{
	uint_fast32_t sum = 0;
	const uint_fast32_t tcp_length = (uint32_t)(th_len + data_len);

	// pseudo
	sum += prne_recmb_msb16(
		((const uint8_t*)&ih->saddr)[0],
		((const uint8_t*)&ih->saddr)[1]);
	sum += prne_recmb_msb16(
		((const uint8_t*)&ih->saddr)[2],
		((const uint8_t*)&ih->saddr)[3]);
	sum += prne_recmb_msb16(
		((const uint8_t*)&ih->saddr)[4],
		((const uint8_t*)&ih->saddr)[5]);
	sum += prne_recmb_msb16(
		((const uint8_t*)&ih->saddr)[6],
		((const uint8_t*)&ih->saddr)[7]);
	sum += prne_recmb_msb16(
		((const uint8_t*)&ih->saddr)[8],
		((const uint8_t*)&ih->saddr)[9]);
	sum += prne_recmb_msb16(
		((const uint8_t*)&ih->saddr)[10],
		((const uint8_t*)&ih->saddr)[11]);
	sum += prne_recmb_msb16(
		((const uint8_t*)&ih->saddr)[12],
		((const uint8_t*)&ih->saddr)[13]);
	sum += prne_recmb_msb16(
		((const uint8_t*)&ih->saddr)[14],
		((const uint8_t*)&ih->saddr)[15]);

	sum += prne_recmb_msb16(
		((const uint8_t*)&ih->daddr)[0],
		((const uint8_t*)&ih->daddr)[1]);
	sum += prne_recmb_msb16(
		((const uint8_t*)&ih->daddr)[2],
		((const uint8_t*)&ih->daddr)[3]);
	sum += prne_recmb_msb16(
		((const uint8_t*)&ih->daddr)[4],
		((const uint8_t*)&ih->daddr)[5]);
	sum += prne_recmb_msb16(
		((const uint8_t*)&ih->daddr)[6],
		((const uint8_t*)&ih->daddr)[7]);
	sum += prne_recmb_msb16(
		((const uint8_t*)&ih->daddr)[8],
		((const uint8_t*)&ih->daddr)[9]);
	sum += prne_recmb_msb16(
		((const uint8_t*)&ih->daddr)[10],
		((const uint8_t*)&ih->daddr)[11]);
	sum += prne_recmb_msb16(
		((const uint8_t*)&ih->daddr)[12],
		((const uint8_t*)&ih->daddr)[13]);
	sum += prne_recmb_msb16(
		((const uint8_t*)&ih->daddr)[14],
		((const uint8_t*)&ih->daddr)[15]);

	sum += (uint16_t)((tcp_length & 0xFFFF0000) >> 16);
	sum += (uint16_t)(tcp_length & 0xFFFF);
	sum += 6; // IPPROTO_TCP

	// tcp header
	while (th_len > 1) {
		sum += prne_recmb_msb16(th[0], th[1]);
		th += 2;
		th_len -= 2;
	}
	if (th_len > 0) {
		sum += th[0];
	}

	// data
	while (data_len > 1) {
		sum += prne_recmb_msb16(data[0], data[1]);
		data += 2;
		data_len -= 2;
	}
	if (data_len > 0) {
		sum += data[0];
	}

	return ~((sum & 0xFFFF) + (sum >> 16));
}
