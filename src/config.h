/** \file
 * \brief The general project configuration
 * \note This header defines "static" macros, which include system config
 * 	detection mechanism, option values for external libraries used across the
 * 	project and project meta data such as version info.
 *
 */
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
#pragma once
#ifndef CONFIG_GEN_H
#include "config_gen.h"
#define CONFIG_GEN_H
#endif
#include "protocol.h"

#include <limits.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <zlib.h>

// Refuse 7-bit byte
#if CHAR_BIT != 8
#error "FIXME!"
#endif

/** \def PRNE_HOST_WORDSIZE
 * \brief Th system "word size". 32 if the system is a 32-bit machine. 64 if the
 * 	system is a 64-bit machine.
 */
#if INTPTR_MAX == INT32_MAX
	#define PRNE_HOST_WORDSIZE 32
#elif INTPTR_MAX == INT64_MAX
	#define PRNE_HOST_WORDSIZE 64
#else
	#error "FIXME!"
#endif

// The program version
#define PRNE_PROG_VER {\
	0x11, 0xf7, 0x6b, 0x87, 0x62, 0x1a, 0x47, 0x9c,\
	0xa2, 0x18, 0x5c, 0x55, 0x40, 0x33, 0x7c, 0x9f\
}
/**
 * \brief The shared global file name salt value
 * \note This is the protocol uuid used as the salt value for calculating the
 * 	hashed name of the shm file.
 * \see prne_shared_global
 */
#define PRNE_SHG_SALT {\
	0x31, 0xe4, 0xf1, 0x7c, 0xdb, 0x76, 0x43, 0x32,\
	0xaf, 0x48, 0xfd, 0x9f, 0xb8, 0x45, 0x3f, 0x8f\
}

/**
 * \brief The version matrix
 * \note The version matrix is a array of previous known version uuids of
 * 	Proone. The byte size of the array must be a multiple of 16.
 * \note If there's no previous version, the array must contain one or more
 * 	placeholder versions because the ISO-C does not allow empty initialiser
 * 	lists. The placeholder versions may be used to reserve uuids for future
 * 	versions.
 */
#define PRNE_VER_MAT {\
	/* 76f2f748-3b6f-420c-abd7-e9929a0b67d6: placeholder version 1 */\
	/* Remove/replace it when you add the first old version */\
	0x76, 0xf2, 0xf7, 0x48, 0x3b, 0x6f, 0x42, 0x0c,\
	0xab, 0xd7, 0xe9, 0x92, 0x9a, 0x0b, 0x67, 0xd6,\
	/* ce6fe199-5595-49a1-96c6-261d1cce9e32: placeholder version 2 */\
	/* Remove/replace it when you add the first old version */\
	0xce, 0x6f, 0xe1, 0x99, 0x55, 0x95, 0x49, 0xa1,\
	0x96, 0xc6, 0x26, 0x1d, 0x1c, 0xce, 0x9e, 0x32\
}

// The common zlib compression level
#define PRNE_PACK_Z_LEVEL Z_DEFAULT_COMPRESSION

/** \def PRNE_HOST_ARCH
 * \brief The system CPU architecture
 * \note Compiler-specific macros are used. Expand this macro to support other
 * 	compilers.
 * \see prne_arch_t
 */
#ifdef __GNUC__
	#if defined(__i386__)
		#define PRNE_HOST_ARCH PRNE_ARCH_I686
	#elif defined(__x86_64__)
		#define PRNE_HOST_ARCH PRNE_ARCH_X86_64
	#elif defined(__ARM_ARCH_4T__)
		#define PRNE_HOST_ARCH PRNE_ARCH_ARMV4T
	#elif defined(__ARM_ARCH_7A__)
		#define PRNE_HOST_ARCH PRNE_ARCH_ARMV7
	#elif defined(__aarch64__)
		#define PRNE_HOST_ARCH PRNE_ARCH_AARCH64
	#elif defined(__mips__)
		#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
			#define PRNE_HOST_ARCH PRNE_ARCH_MIPS
		#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
			#define PRNE_HOST_ARCH PRNE_ARCH_MPSL
		#else
			#error "FIXME!"
		#endif
	#elif defined(__powerpc__)
		#define PRNE_HOST_ARCH PRNE_ARCH_PPC
	#elif defined(__SH4__)
		#define PRNE_HOST_ARCH PRNE_ARCH_SH4
	#elif defined(__m68k__)
		#define PRNE_HOST_ARCH PRNE_ARCH_M68K
	#elif defined(__arc__)
		#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
			#define PRNE_HOST_ARCH PRNE_ARCH_ARCEB
		#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
			#define PRNE_HOST_ARCH PRNE_ARCH_ARC
		#else
			#error "FIXME!"
		#endif
	#else
		#error "FIXME!"
	#endif
#else
	#error "FIXME!"
#endif

/** \def PRNE_HOST_OS
 * \brief The system operating system
 * \note Compiler-specific macros are used. Expand this macro to support other
 * 	compilers.
 * \see prne_os_t
 */
#ifdef __GNUC__
	#if defined(__linux__)
		#define PRNE_HOST_OS PRNE_OS_LINUX
	#else
		#error "FIXME!"
	#endif
#else
	#error "FIXME!"
#endif
