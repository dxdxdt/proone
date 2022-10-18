/** \file
 * \brief Executable packing facility.
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
#include <stdint.h>
#include <stdbool.h>

#include "protocol.h"

#include <zlib.h>


/* Alias declarations */
typedef struct prne_bin_host prne_bin_host_t;
typedef struct prne_bin_tuple prne_bin_tuple_t;
typedef struct prne_bin_archive prne_bin_archive_t;
typedef struct prne_bin_rcb_ctx prne_bin_rcb_ctx_t;
typedef struct prne_rcb_param prne_rcb_param_t;

// The pack function result codes
typedef enum {
	PRNE_PACK_RC_OK, // Successful
	PRNE_PACK_RC_EOF, // End of file reached
	PRNE_PACK_RC_INVAL, // Invalid data
	PRNE_PACK_RC_FMT_ERR, // Format error
	PRNE_PACK_RC_ERRNO, // Syscall error, errno set
	PRNE_PACK_RC_Z_ERR, // zlib function error
	PRNE_PACK_RC_NO_ARCH, // Arch not found
	PRNE_PACK_RC_UNIMPL_REV, // Unimplemented revision number

	NB_PRNE_PACK_RC // Meta: the number of result codes
} prne_pack_rc_t;

// The executable host info record
struct prne_bin_host {
	prne_os_t os;
	prne_arch_t arch;
};

// The executable host info record - executable size pair
struct prne_bin_tuple {
	size_t size;
	prne_bin_host_t host;
};

// The indexed binary archive object
struct prne_bin_archive {
	const uint8_t *data; // The pointer to the start of the binary archive
	size_t data_size; // The byte length of the binary archive
	size_t nb_bin; // The number of the tuples
	prne_bin_tuple_t *bin; // The array of the tuples
};

// The recombination context object
struct prne_bin_rcb_ctx {
	void *o_ctx; // The opaque context
	/**
	 * \brief The function used to free the opaque context. Not to be used
	 *	directly.
	 * \note Use \c prne_free_bin_rcb_ctx() to free the object!
	 * \see \c prne_free_bin_rcb_ctx()
	 */
	void (*ctx_free_f)(void*);
	/**
	 * \brief The adaptive read callback function. Not to be used directly.
	 * \note Use \c prne_bin_rcb_read()
	 * \see \c prne_bin_rcb_read()
	 */
	ssize_t(*read_f)(
		prne_bin_rcb_ctx_t *ctx,
		uint8_t *buf,
		size_t len,
		prne_pack_rc_t *prc,
		int *err);
};

/**
 * \brief The recombination parameter object for initiating binary
 *	recombination. The members are the parameters to \c prne_start_bin_rcb()
 *	call excluding the target info. An instance of this object is set up on
 *	program initialisation and shared globally.
 * \see \c prne_start_bin_rcb()
 */
struct prne_rcb_param {
	const uint8_t *m_self;
	size_t self_len;
	size_t exec_len;
	const uint8_t *m_dv;
	size_t dv_len;
	const prne_bin_archive_t *ba;
	const prne_bin_host_t *self;
};

/**
 * \brief The binary archive identity magic "pr-ba"
 * \see /doc/fmts.md
 */
static const char PRNE_PACK_BA_IDEN_DATA[] = { 'p', 'r', '-', 'b', 'a' };
/**
 * \brief The nybin file format identity magic "nybin"
 * \see /doc/fmts.md
 */
static const char PRNE_PACK_NYBIN_IDEN_DATA[] = { 'n', 'y', 'b', 'i', 'n' };

/**
 * \brief The equality operator of the executable host info record
 * \retval true if the contents of the records are equal.
 * \retval false otherwise.
 */
bool prne_eq_bin_host (const prne_bin_host_t *a, const prne_bin_host_t *b);
/**
 * \brief The in-range operator of the executable host info record. Check both
 *	enums are in range(ie, recognised by the current implementation).
 * \retval true if the enums are in range.
 * \retval false otherwise.
 */
bool prne_bin_host_inrange (const prne_bin_host_t *x);
/**
 * \brief Initialise the indexed binary archive object.
 * \note \p a can be freed using \c prne_free_bin_archive() once initialised.
 * \see \c prne_free_bin_archive()
 */
void prne_init_bin_archive (prne_bin_archive_t *a);
/**
 * \brief Free resources allocated for the indexed binary archive object.
 * \see \c prne_init_bin_archive()
 */
void prne_free_bin_archive (prne_bin_archive_t *a);
/**
 * \brief Index the binary archive from the binary.
 * \param data The binary data, usually the address obtained using \c mmap() on
 *	the executable.
 * \param len The byte length of the binary data.
 * \param[out] out The pointer to the binary archive object for index info.
 * \retval PRNE_PACK_RC_OK The binary archive has been successfully index and
 *	\p out is ready to use.
 * \retval PRNE_PACK_RC_FMT_ERR The binary could not be parsed due to a format
 *	error.
 * \retval PRNE_PACK_RC_UNIMPL_REV An unimplemented revision number encountered.
 * \retval PRNE_PACK_RC_ERRNO A memory allocation error has occurred. \c errno
 *	is set to \c ENOMEM
 * \note Any resource allocated previously for \p out is freed using
 *	\c prne_free_bin_archive() if the operation is successful.
 */
prne_pack_rc_t prne_index_bin_archive (
	const uint8_t *data,
	size_t len,
	prne_bin_archive_t *out);

/**
 * \brief Initialise the recombination context object.
 * \see \c prne_free_bin_rcb_ctx()
 */
void prne_init_bin_rcb_ctx (prne_bin_rcb_ctx_t *ctx);
/**
 * \brief Free resources allocated for the recombination context object.
 * \see \c prne_init_bin_rcb_ctx()
 */
void prne_free_bin_rcb_ctx (prne_bin_rcb_ctx_t *ctx);
/**
 * \brief Initiate binary recombination. Get the recombination context object
 *	ready for \c prne_bin_rcb_read()
 * \param ctx The recombination context object.
 * \param target The recombination target host info.
 * \param self The executable host info record of the running executable.
 * \param m_self The pointer to the start of the running executable (the image
 *	of the current process). Usually the address obtained using \c mmap()
 * \param self_len The total byte length of the running executable(the size of
 *	the file).
 * \param exec_len The byte length of the ELF part of the running executable.
 * \param m_dvault The pointer to the start of the data vault binary.
 * \param dvault_len The byte length of the data vault binary.
 * \param ba The indexed binary archive object.
 * \retval PRNE_PACK_RC_OK if the initiation was successful.
 * \retval PRNE_PACK_RC_INVAL if \p ba is NULL, or \p target or \p self is not
 *	in range.
 * \retval PRNE_PACK_RC_ERRNO if a memory allocation error has occurred and
 *	\c errno is set to \c ENOMEM
 * \retval PRNE_PACK_RC_NO_ARCH if \p ba does not contain the executable for
 *	\p target
 * \retval PRNE_PACK_RC_Z_ERR if a zlib function returned an error. Probably
 *	allocation error or an incompatible zlib variant.
 */
prne_pack_rc_t prne_start_bin_rcb (
	prne_bin_rcb_ctx_t *ctx,
	const prne_bin_host_t target,
	const prne_bin_host_t *self,
	const uint8_t *m_self,
	const size_t self_len,
	const size_t exec_len,
	const uint8_t *m_dvault,
	const size_t dvault_len,
	const prne_bin_archive_t *ba);
/**
 * \brief A variant of \c prne_start_bin_rcb() that try to initiate for a
 *	compatible arch target on \c PRNE_PACK_RC_NO_ARCH
 * \param[out] actual The pointer to the executable host info record for
 *	returning the actual target initiated (optional)
 * \see \c prne_start_bin_rcb()
 * \see \c prne_compat_arch()
 */
prne_pack_rc_t prne_start_bin_rcb_compat (
	prne_bin_rcb_ctx_t *ctx,
	const prne_bin_host_t target,
	const prne_bin_host_t *self,
	const uint8_t *m_self,
	const size_t self_len,
	const size_t exec_len,
	const uint8_t *m_dvault,
	const size_t dvault_len,
	const prne_bin_archive_t *ba,
	prne_bin_host_t *actual);
/**
 * \brief Read the recombined binary.
 * \param ctx The initiated recombination context object.
 * \param buf The output buffer.
 * \param len The number of bytes available in \p buf
 * \param[out] prc The pointer to a pack function result code variable(optional)
 * \param[out] err The pointer to an int for library function return values
 *	(optional)
 * \return The number of bytes written to \p buf
 * \retval 0 with \p prc PRNE_PACK_RC_OK means no data could be produced in a
 *	reasonable amount of CPU time and the function had to return for other
 *	threads. This is not an error and the function may be called again with the
 *	same arguments after yielding to other threads.
 * \retval 0 with \p prc PRNE_PACK_RC_EOF means all the data for the target
 *	has been produced and the output file can be closed. The subsequent calls
 *	will result in the same return values.
 * \retval -1 on error. \p ctx cannot be used for read and must be freed or
 *	reinitialised. \p prc is set to either \c PRNE_PACK_RC_ERRNO or
 *	\c PRNE_PACK_RC_Z_ERR
 */
ssize_t prne_bin_rcb_read (
	prne_bin_rcb_ctx_t *ctx,
	uint8_t *buf,
	size_t len,
	prne_pack_rc_t *prc,
	int *err);

/**
 * \brief Index the NYBIN file. The file must be mmaped first.
 * \param[in] m_nybin The pointer to the start of the contents of the NYBIN file.
 * \param[in] nybin_len The byte length of the contents of the NYBIN file.
 * \param[out] m_dv The start of the data vault.
 * \param[out] dv_len The byte length of the data vault.
 * \param[out] m_ba The start of the binary archive.
 * \param[out] ba_len The byte length of the binary archive.
 * \retval true if the parsing was successful and the output parameters are all
 *	set.
 * \retval false with \c errno set to \c EPROTO on invalid format.
 * \retval false with \c errno set to \c ENOSYS if the revision of the file is
 *	unrecognised.
 */
bool prne_index_nybin (
	const uint8_t *m_nybin,
	const size_t nybin_len,
	const uint8_t **m_dv,
	size_t *dv_len,
	const uint8_t **m_ba,
	size_t *ba_len);

/**
 * \brief Initialise the recombination parameter object. Reserved for any
 *	dynamically allocated members in the future.
 */
void prne_init_rcb_param (prne_rcb_param_t *rp);
/**
 * \brief Free resources allocated for the recombination parameter object.
 *	Reserved for any dynamically allocated members in the future.
 */
void prne_free_rcb_param (prne_rcb_param_t *rp);

/**
 * \brief Get the array of the compatible arches for \p arch
 * \retval NULL if there's no known compatible arch for \p arch
 * \return The pointer to an internal array, terminated by \c PRNE_ARCH_NONE
 * \see \c prne_start_bin_rcb_compat()
 * \note This function can be used to examine the "compat tree" of the arches.
 */
const prne_arch_t *prne_compat_arch (const prne_arch_t arch);

/**
 * \brief Get the descriptive string for the enum value.
 * \retval NULL if \p prc is not in range.
 * \return The pointer to the internal string describing the enum value.
 */
const char *prne_pack_rc_tostr (const prne_pack_rc_t prc);
