/** \file
 *  \brief The data vault implementation
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
#include "util_ct.h"
#include "data.h"

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

/* Alias declarations */
typedef struct prne_dvault_mask_result prne_dvault_mask_result_t;
typedef struct prne_dvault prne_dvault_t;

/**
 * \brief The data type for the entry
 * \note Suitable storage type: int8_t
 */
typedef enum {
	PRNE_DATA_TYPE_NONE = -1, // Null value

	// Null-terminated narrow character string, usually in UTF-8 encoding
	PRNE_DATA_TYPE_CSTR,
	PRNE_DATA_TYPE_BIN, // Binary data

	NB_PRNE_DATA_TYPE // Meta value: the number of enums
} prne_data_type_t;
PRNE_LIMIT_ENUM(prne_data_type_t, NB_PRNE_DATA_TYPE, 0xFF);

// The masking operation result code
typedef enum {
	PRNE_DVAULT_MASK_OK, // Success
	PRNE_DVAULT_MASK_MEM_ERR, // Memory allocation error
	PRNE_DVAULT_MASK_TOO_LARGE, // Entry data too large
	PRNE_DVAULT_MASK_INVALID_TYPE // Invalid prne_data_type_t
} prne_dvault_mask_result_code_t;

// The masking operation result object
struct prne_dvault_mask_result {
	size_t size; // The length of data in bytes
	uint8_t *data; // The masked data
	/* The result code.
	 * size and data are valid only if the result code is PRNE_DVAULT_MASK_OK.
	 */
	prne_dvault_mask_result_code_t result;
};


/**
 * \brief Convert the enum value to a descriptive string
 * \return A pointer to the string from the read-only static string pool.
 * \retval Null if \p t is out of bounds of the valid range with \c errno set to
 * 	\c EINVAL
 */
const char *prne_data_type_tostr (const prne_data_type_t t);
/**
 * \brief The inverse function of \c prne_data_type_tostr()
 * \retval PRNE_DATA_TYPE_NONE if \p str does not match any enum. \c errno set
 * 	to \c EINVAL
 * \return The parsed enum
 */
prne_data_type_t prne_data_type_fstr (const char *str);
/**
 * \brief Mask or unmask memory using parameters
 * \param size The length of \p m, in bytes, to invert.
 * \param m The memory to invert
 * \param salt The salt offset
 * \param salt_ofs The offset in addition to \p salt
 * \param mask The pointer to the 256-byte mask key
 * \note This is a primitve function that "inverts" a portion of memory to mask
 * 	the original data or to unmask the masked data.
 * \note The final offset is \p salt plus \p salt_ofs.
 */
void prne_dvault_invert_mem (
	const size_t size,
	void *m,
	const uint8_t salt,
	const size_t salt_ofs,
	const uint8_t *mask);

/**
 * \brief Initialisation function
 * \see [/doc/impl.md#Resource Allocation](/doc/impl.md#resource_allocation)
 */
void prne_init_dvault_mask_result (prne_dvault_mask_result_t *r);
/**
 * \brief Deinitialisation function
 * \see [/doc/impl.md#Resource Allocation](/doc/impl.md#resource_allocation)
 */
void prne_free_dvault_mask_result (prne_dvault_mask_result_t *r);
/**
 * \brief Mask the source data
 * \param type The data type of the source data.
 * \param salt The randomly generated salt value.
 * \param mask The 256-byte mask key.
 * \param data_size The length of \p data in bytes.
 * \param data The source data.
 * \return An instance of the data vault masking operation object, with memory
 * 	allocated to return the masked data. The instance must always be freed using
 * 	\c prne_free_dvault_mask_result() regardless of the result code.
 */
prne_dvault_mask_result_t prne_dvault_mask (
	const prne_data_type_t type,
	const uint8_t salt,
	const uint8_t *mask,
	const size_t data_size,
	const uint8_t *data);
/**
 * \brief Convert the enum value to a descriptive string
 * \return A pointer to the string from the read-only static string pool.
 * \retval Null if \p code is out of bounds of the valid range with \c errno set
 * 	to \c EINVAL
 */
const char *prne_dvault_mask_result_tostr (
	const prne_dvault_mask_result_code_t code);

/**
 * \brief Initialise the internal global variables with the data vault binary
 * \param m The pointer to the binary data dump. The memory must be readable and
 * 	writeable. The data dump is produced by proone-mkdvault
 * \note The function cannot be called again without calling
 * 	\c prne_deinit_dvault() beforehand.
 * \warning The behaviour is undefined if the data at \p m is not valid.
 */
void prne_init_dvault (const void *m);
/**
 * \brief Deinitialise the internal global variables and resources allocated for
 * 	the data vault
 * \note \c prne_init_dvault() can be called when the function returns.
 */
void prne_deinit_dvault (void);
/**
 * \brief Unmask and get the pointer to the string from the entry
 * \param key The key to the entry.
 * \param[out] len (optional)The length of the string, excluding the null
 * 	terminator.
 * \return The pointer to the unmasked string from the entry.
 * \warning The behaviour is undefined if the data entry at \p key is not of
 * 	string or \p key is out of bounds.
 */
const char *prne_dvault_get_cstr (const prne_data_key_t key, size_t *len);
/**
 * \brief Unmask and get the pointer to the binary data from the entry
 * \param key The key to the entry.
 * \param[out] len (optional)The length of the data in bytes.
 * \return The pointer to the unmasked binary data from the entry.
 * \warning The behaviour is undefined if the data entry at \p key is not of
 * 	binary data or \p key is out of bounds.
 */
const uint8_t *prne_dvault_get_bin (const prne_data_key_t key, size_t *len);
/**
 * \brief Mask all the data currently unmmasked
 * \note This function has to be called soon after the unmasked data entry is
 * 	no longer required.
 * \warning The behaviour is undefined if the data vault is not initialised with
 * 	\c prne_init_dvault()
 */
void prne_dvault_reset (void);
