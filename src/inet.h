/** \file
 * \brief The utility functions for the internet protocol.
 * \note The header includes functions which are required when using raw TCP/IP
 *	sockets.
 */
/*
* Copyright (c) 2019-2021 David Timber <mieabby@gmail.com>
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
#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "protocol.h"


/* Alias declarations */
typedef struct prne_iphdr4 prne_iphdr4_t;
typedef struct prne_iphdr6 prne_iphdr6_t;

/** \struct prne_iphdr4 \struct prne_iphdr6
 * \brief The workaround for the issues in uClibc headers.
 * \note At the time of writing the code, the IPv6 support of uClibc was not
 *	complete and there were some problems using the IP headers provided by
 *	uClibc. These structures are exactly the same as the counterparts in the
 *	standard IP headers.
 * \note The values must be in the host byte order. Unlike the standard
 * 	functions, the serialisation and deserialisation functions are responsible
 * 	for byte order conversion.
 */

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

/**
 * \brief Set bits to represent the CIDR
 * \param out The byte array used to represent the netmask.
 * \param cidr The CIDR value.
 * \note The number of elements modified is calculated by dividing \p cidr by 8.
 *	For example, if the \p cidr is passed as 24, only the first 3 elements of
 *	\p out are modified to set the first 24 bits.
 * \warning The behaviour is undefined if \p cidr divided by 8 is larger than
 *	the size of \p out (buffer overflow).
 */
void prne_netmask_from_cidr (uint8_t *out, size_t cidr);
/**
 * \brief Calculate the checksum of the IPv4 TCP packet.
 * \param ih The pointer to the IPv4 header structure.
 * \param th The pointer to the TCP header data.
 * \param th_len The byte length of the TCP header data.
 * \param data The pointer to the payload data.
 * \param data_len The byte length of the payload data.
 * \return The calculated checksum value in the host byte order. The value must
 *	be converted to the network byte order.
 */
uint16_t prne_calc_tcp_chksum4 (
	const prne_iphdr4_t *ih,
	const uint8_t *th,
	size_t th_len,
	const uint8_t *data,
	size_t data_len);
/**
 * \brief Calculate the checksum of the IPv6 TCP packet.
 * \param ih The pointer to the IPv6 header structure.
 * \param th The pointer to the TCP header data.
 * \param th_len The byte length of the TCP header data.
 * \param data The pointer to the payload data.
 * \param data_len The byte length of the payload data.
 * \return The calculated checksum value in the host byte order. The value must
 *	be converted to the network byte order.
 * \note The same algorithm(the function) can be used to calculate the checksum
 *	values of ICMP packets.
 */
uint16_t prne_calc_tcp_chksum6 (
	const prne_iphdr6_t *ih,
	const uint8_t *th,
	size_t th_len,
	const uint8_t *data,
	size_t data_len);

/**
 * \brief Serialise the IPv4 header structure for transmission.
 * \param mem The destination buffer. The length of the buffer must be at least
 *	20 bytes.
 * \param in The pointer to the IPv4 header structure.
 */
void prne_ser_iphdr4 (uint8_t *mem, const prne_iphdr4_t *in);
/**
 * \brief Serialise the IPv6 header structure for transmission.
 * \param mem The destination buffer. The length of the buffer must be at least
 *	40 bytes.
 * \param in The pointer to the IPv6 header structure.
 */
void prne_ser_iphdr6 (uint8_t *mem, const prne_iphdr6_t *in);
/**
 * \brief Deserialise the IPv4 header from the binary data.
 * \param data The binary data. The length must be at least 20 bytes.
 * \param out The pointer to the IPv4 header structure.
 */
void prne_dser_iphdr4 (const uint8_t *data, prne_iphdr4_t *out);
/**
 * \brief Deserialise the IPv6 header from the binary data.
 * \param data The binary data. The length must be at least 40 bytes.
 * \param out The pointer to the IPv6 header structure.
 */
void prne_dser_iphdr6 (const uint8_t *data, prne_iphdr6_t *out);
