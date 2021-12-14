/** \file
 * \brief The string map implementation
 * \note The C equivalent of \c std::map<std::string,uintptr_t>
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
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>


/* Aliases and forward declarations */
typedef struct prne_strmap prne_strmap_t;
typedef struct prne_strmap_tuple prne_strmap_tuple_t;
typedef uintptr_t prne_strmap_val_t;

// The string map object
struct prne_strmap {
	prne_strmap_tuple_t *tbl; // The table array sorted in ascending order
	size_t size; // The number of elements in the table
};

// The tuple object
struct prne_strmap_tuple {
	const char *key;
	prne_strmap_val_t val;
};

/**
 * \brief Initialise the string map object
 * \note Initialises the members of \p map to initial values. Prepares \p map so
 * 	that it can be freed using \c prne_free_strmap()
 */
void prne_init_strmap (prne_strmap_t *map);
/**
 * \brief Free the resources allocated for the string map object
 * \param map The pointer to the object that has been initialised using
 * 	\c prne_init_strmap()
 */
void prne_free_strmap (prne_strmap_t *map);

/**
 * \brief Clear the elements of the string map object.
 * \param s The pointer to the string map object.
 * \warning The function call may have the exact same effect as
 *	\c prne_free_strmap() but \c prne_free_strmap() must always be used to free
 * 	the resources allocated for the object.
 */
void prne_strmap_clear (prne_strmap_t *map);
/**
 * \brief Insert a tuple into the string map object.
 * \param im The pointer to the string map object.
 * \param key The key of the new tuple.
 * \param val The value of the new tuple.
 * \return The pointer to the new tuple allocated in the map. The pointer is
 *	valid as long as the map object remains unmodified.
 * \retval NULL if memory allocation error has occurred and \c errno is set to
 *	\c ENOMEM
 * \note Calling the function invalidates the pointers previously returned by
 *	other functions.
 */
const prne_strmap_tuple_t *prne_strmap_insert (
	prne_strmap_t *map,
	const char* key,
	const prne_strmap_val_t val);
/**
 * \brief Erase the tuple with the \p key from the string map object.
 * \param im The pointer to the string map object.
 * \param key The key of the tuple to erase.
 * \note Calling the function invalidates the pointers previously returned by
 *	other functions.
 */
void prne_strmap_erase (prne_strmap_t *map, const char* key);
/**
 * \brief Look up the tuple with \p key in the string map object.
 * \param im The pointer to the string map object.
 * \param key The key to look for.
 * \return The pointer to the tuple in the map. The pointer is valid as long as
 *	the map object remains unmodified.
 * \retval NULL if the tuple with \p key is not found.
 */
const prne_strmap_tuple_t *prne_strmap_lookup (
	prne_strmap_t *map,
	const char* key);
