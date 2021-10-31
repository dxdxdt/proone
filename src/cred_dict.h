/** \file
 * \brief The credential dictionary implementation
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
#include <stddef.h>
#include <stdbool.h>

/* Alias declaration */
typedef struct prne_cred_dict_entry prne_cred_dict_entry_t;
typedef struct prne_cred_dict_raw_entry prne_cred_dict_raw_entry_t;
typedef struct prne_cred_dict prne_cred_dict_t;

// The index entry object
struct prne_cred_dict_entry {
	uint16_t id; // Index of start of the user name
	uint16_t pw; // Index of start of the password
	uint8_t weight; // The weight value
};

// The raw entry entry object used to build the dictionary
struct prne_cred_dict_raw_entry {
	char *id; // Pointer to the user name string
	char *pw; // Pointer to the password string
	uint8_t weight; // Weight value
};

// The dictionary object
struct prne_cred_dict {
	const char *m; // Pointer to the string pool
	prne_cred_dict_entry_t *arr;
	size_t cnt;
};

/**
 * \brief Initialise the credential dictionary object
 * \note Initialises the members of \p p to initial values. Prepares \p p so
 * 	that it can be freed using \c prne_free_cred_dict()
 */
void prne_init_cred_dict (prne_cred_dict_t *p);
/**
 * \brief Free the resources allocated for the credential dictionary object.
 * \param p The pointer to the object that has been initialised using
 * 	\c prne_init_cred_dict()
 */
void prne_free_cred_dict (prne_cred_dict_t *p);

/**
 * \brief Build a credential dictionary
 * \param arr The raw entries.
 * \param cnt The number of entries in \p arr
 * \param[out] out_m The serialised credential dictionary deserialisable with
 * 	\c prne_dser_cred_dict(). The returned memory is freeable with
 * 	\c prne_free().
 * \param[out] out_l The length of \p out_m in bytes.
 * \retval True if successful.
 * \retval False on error with \c errno set to an appropriate value.
 * \note The size of the binary credential dictionary is limited to 2^16 bytes
 * 	as indices are 16-bit integers. \c E2BIG is used to indicate this error.
 */
bool prne_build_cred_dict (
	const prne_cred_dict_raw_entry_t *arr,
	const size_t cnt,
	uint8_t **out_m,
	size_t *out_l);
/**
 * \brief Deserialise the credential dictionary
 * \param[out] dict The output object. Must be initiaised with
 * 	\c prne_init_cred_dict() beforehand.
 * \param buf The pointer to the memory containing the serialised credential
 * 	dictionary.
 * \param len The readable length of \p buf in bytes.
 * \retval True on successful parsing and allocation of \p dict members.
 * \retval False otherwise with \c errno set to an appropriate value.
 */
bool prne_dser_cred_dict (
	prne_cred_dict_t *dict,
	const uint8_t *buf,
	const size_t len);
