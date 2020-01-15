#include "protocol.h"

#include <string.h>

#include <arpa/inet.h>


const char *prne_arch_tostr (const prne_arch_t x) {
	switch (x){
	case PRNE_ARCH_ARMV4T:
		return "armv4t";
	case PRNE_ARCH_ARMV7:
		return "armv7";
	case PRNE_ARCH_I686:
		return "i686";
	case PRNE_ARCH_M68K:
		return "m68k";
	case PRNE_ARCH_MIPS:
		return "mips";
	case PRNE_ARCH_MPSL:
		return "mpsl";
	case PRNE_ARCH_PPC:
		return "ppc";
	case PRNE_ARCH_RV32:
		return "rv32";
	case PRNE_ARCH_RV64:
		return "rv64";
	case PRNE_ARCH_SH4:
		return "sh4";
	case PRNE_ARCH_SPC:
		return "spc";
	}
	
	return NULL;
}

prne_arch_t prne_arch_fstr (const char *str) {
	if (strcmp(str, prne_arch_tostr(PRNE_ARCH_ARMV4T)) == 0) {
		return PRNE_ARCH_ARMV4T;
	}
	else if (strcmp(str, prne_arch_tostr(PRNE_ARCH_ARMV7)) == 0) {
		return PRNE_ARCH_ARMV7;
	}
	else if (strcmp(str, prne_arch_tostr(PRNE_ARCH_I686)) == 0) {
		return PRNE_ARCH_I686;
	}
	else if (strcmp(str, prne_arch_tostr(PRNE_ARCH_M68K)) == 0) {
		return PRNE_ARCH_M68K;
	}
	else if (strcmp(str, prne_arch_tostr(PRNE_ARCH_MIPS)) == 0) {
		return PRNE_ARCH_MIPS;
	}
	else if (strcmp(str, prne_arch_tostr(PRNE_ARCH_MPSL)) == 0) {
		return PRNE_ARCH_MPSL;
	}
	else if (strcmp(str, prne_arch_tostr(PRNE_ARCH_PPC)) == 0) {
		return PRNE_ARCH_PPC;
	}
	else if (strcmp(str, prne_arch_tostr(PRNE_ARCH_RV32)) == 0) {
		return PRNE_ARCH_RV32;
	}
	else if (strcmp(str, prne_arch_tostr(PRNE_ARCH_RV64)) == 0) {
		return PRNE_ARCH_RV64;
	}
	else if (strcmp(str, prne_arch_tostr(PRNE_ARCH_SH4)) == 0) {
		return PRNE_ARCH_SH4;
	}
	else if (strcmp(str, prne_arch_tostr(PRNE_ARCH_SPC)) == 0) {
		return PRNE_ARCH_SPC;
	}

	return PRNE_ARCH_NONE;
}

void prne_net_ep_tosin4 (const prne_net_endpoint_t *ep, struct sockaddr_in *out) {
	memcpy(&out->sin_addr, ep->addr.addr, 4);
	out->sin_family = AF_INET;
	out->sin_port = htons(ep->port);
}

void prne_net_ep_tosin6 (const prne_net_endpoint_t *ep, struct sockaddr_in6 *out) {
	memcpy(&out->sin6_addr, ep->addr.addr, 16);
	out->sin6_family = AF_INET6;
	out->sin6_port = htons(ep->port);
}

bool prne_net_ep_set_ipv4 (const char *str, const uint16_t port, prne_net_endpoint_t *out) {
	out->port = port;
	out->addr.ver = PRNE_IPV_4;
	return inet_pton(AF_INET, str, &out->addr.addr) != 0;
}

bool prne_net_ep_set_ipv6 (const char *str, const uint16_t port, prne_net_endpoint_t *out) {
	out->port = port;
	out->addr.ver = PRNE_IPV_6;
	return inet_pton(AF_INET6, str, &out->addr.addr) != 0;
}
