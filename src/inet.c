/*
* Copyright (c) 2019-2022 David Timber <dxdt@dev.snart.me>
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*/
#include "inet.h"
#include "endian.h"

#include <string.h>


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
	const prne_iphdr4_t *ih,
	const uint8_t *th,
	size_t th_len,
	const uint8_t *data,
	size_t data_len)
{
	uint_fast32_t sum = 0;

	// pseudo
	sum += prne_recmb_msb16(
		ih->saddr[0],
		ih->saddr[1]);
	sum += prne_recmb_msb16(
		ih->saddr[2],
		ih->saddr[3]);
	sum += prne_recmb_msb16(
		ih->daddr[0],
		ih->daddr[1]);
	sum += prne_recmb_msb16(
		ih->daddr[2],
		ih->daddr[3]);
	sum += ih->protocol;
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
	const prne_iphdr6_t *ih,
	const uint8_t *th,
	size_t th_len,
	const uint8_t *data,
	size_t data_len)
{
	uint_fast32_t sum = 0;
	const uint_fast32_t tcp_length = (uint32_t)(th_len + data_len);

	// pseudo
	sum += prne_recmb_msb16(ih->saddr[0], ih->saddr[1]);
	sum += prne_recmb_msb16(ih->saddr[2], ih->saddr[3]);
	sum += prne_recmb_msb16(ih->saddr[4], ih->saddr[5]);
	sum += prne_recmb_msb16(ih->saddr[6], ih->saddr[7]);
	sum += prne_recmb_msb16(ih->saddr[8], ih->saddr[9]);
	sum += prne_recmb_msb16(ih->saddr[10], ih->saddr[11]);
	sum += prne_recmb_msb16(ih->saddr[12], ih->saddr[13]);
	sum += prne_recmb_msb16(ih->saddr[14], ih->saddr[15]);

	sum += prne_recmb_msb16(ih->daddr[0], ih->daddr[1]);
	sum += prne_recmb_msb16(ih->daddr[2], ih->daddr[3]);
	sum += prne_recmb_msb16(ih->daddr[4], ih->daddr[5]);
	sum += prne_recmb_msb16(ih->daddr[6], ih->daddr[7]);
	sum += prne_recmb_msb16(ih->daddr[8], ih->daddr[9]);
	sum += prne_recmb_msb16(ih->daddr[10], ih->daddr[11]);
	sum += prne_recmb_msb16(ih->daddr[12], ih->daddr[13]);
	sum += prne_recmb_msb16(ih->daddr[14], ih->daddr[15]);

	sum += (uint16_t)((tcp_length & 0xFFFF0000) >> 16);
	sum += (uint16_t)(tcp_length & 0xFFFF);
	sum += ih->next_hdr;

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

void prne_ser_iphdr4 (uint8_t *mem, const prne_iphdr4_t *in) {
	mem[0] = (4 << 4) | (in->ihl & 0x0F);
	mem[1] = 0;
	mem[2] = prne_getmsb16(in->total_len, 0);
	mem[3] = prne_getmsb16(in->total_len, 1);
	mem[4] = prne_getmsb16(in->id, 0);
	mem[5] = prne_getmsb16(in->id, 1);
	mem[6] = 0;
	mem[7] = 0;
	mem[8] = in->ttl;
	mem[9] = in->protocol;
	mem[10] = 0;
	mem[11] = 0;
	mem[12] = in->saddr[0];
	mem[13] = in->saddr[1];
	mem[14] = in->saddr[2];
	mem[15] = in->saddr[3];
	mem[16] = in->daddr[0];
	mem[17] = in->daddr[1];
	mem[18] = in->daddr[2];
	mem[19] = in->daddr[3];
}

void prne_ser_iphdr6 (uint8_t *mem, const prne_iphdr6_t *in) {
	mem[0] = (6 << 4);
	mem[1] = prne_getmsb32(in->flow_label, 1) & 0xF;
	mem[2] = prne_getmsb32(in->flow_label, 2);
	mem[3] = prne_getmsb32(in->flow_label, 3);
	mem[4] = prne_getmsb16(in->payload_len, 0);
	mem[5] = prne_getmsb16(in->payload_len, 1);
	mem[6] = in->next_hdr;
	mem[7] = in->hop_limit;
	memcpy(mem + 8, in->saddr, 16);
	memcpy(mem + 24, in->daddr, 16);
}

void prne_dser_iphdr4 (const uint8_t *data, prne_iphdr4_t *out) {
	out->ihl = data[0] & 0x0F;
	out->total_len = prne_recmb_msb16(data[2], data[3]);
	out->id = prne_recmb_msb16(data[4], data[5]);
	out->ttl = data[8];
	out->protocol = data[9];
	out->saddr[0] = data[12];
	out->saddr[1] = data[13];
	out->saddr[2] = data[14];
	out->saddr[3] = data[15];
	out->daddr[0] = data[16];
	out->daddr[1] = data[17];
	out->daddr[2] = data[18];
	out->daddr[3] = data[19];
}

void prne_dser_iphdr6 (const uint8_t *data, prne_iphdr6_t *out) {
	out->flow_label = prne_recmb_msb32(0, data[1] & 0x0F, data[2], data[3]);
	out->payload_len = prne_recmb_msb16(data[4], data[5]);
	out->next_hdr = data[6];
	out->hop_limit = data[7];
	memcpy(out->saddr, data + 8, 16);
	memcpy(out->daddr, data + 24, 16);
}
