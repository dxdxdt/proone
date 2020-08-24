#pragma once
#include "protocol.h"

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>


#if INTPTR_MAX == INT32_MAX
	#define PRNE_HOST_WORDSIZE 32
#elif INTPTR_MAX == INT64_MAX
	#define PRNE_HOST_WORDSIZE 64
#else
	#error "FIXME!"
#endif

#define PRNE_PROG_VER { 0x11, 0xf7, 0x6b, 0x87, 0x62, 0x1a, 0x47, 0x9c, 0xa2, 0x18, 0x5c, 0x55, 0x40, 0x33, 0x7c, 0x9f }
extern const prne_arch_t prne_host_arch;

#define PRNE_CNC_TXT_REC "cnc.prne.mydomain.test" // CHANGE ME
