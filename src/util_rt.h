/** \file
 * \brief Runtime utility and convenience functions
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
#include "pack.h"

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include <sys/poll.h>

#include <mbedtls/ctr_drbg.h>


/**
 * \brief Call \c close() only if the \p fd is zero or greater to preserve
 * \c errno
 * \retval 0 if \p fd is less than zero (no op)
 * \return the value returned from \c close() otherwise
 * \see \c close()
 * \see [/doc/impl.md#Resource Allocation Hook](/doc/impl.md#resource_allocation_hook)
 */
int prne_close (const int fd);
/**
 * \brief Call \c shutdown() only if the \p fd is zero or greater to preserve
 * \c errno
 * \see \c shutdown()
 */
void prne_shutdown (const int fd, const int how);
/* prne_sck_fcntl(fd)
*
* Sets FD_CLOEXEC and O_NONBLOCK. Failure to set FD_CLOEXEC is ignored.
*/

/**
 * \brief Set the commmon socket flags associated with the fd. The common flags
 * are \c FD_CLOEXEC and \c O_NONBLOCK
 * \retval true if the mission critial flags(O_NONBLOCK) are successfully set
 * \retval false otherwise. \c errno is set by \c fcntl()
 * \warning The error occurred setting \c FD_CLOEXEC is ignored as the flag is
 * considered non mission critial.
 * \see \c fcntl()
 */
bool prne_sck_fcntl (const int fd);
/**
 * \brief Convenience function for changing the fd to a new fd using \c dup2()
 * 	Upon successful \c dup2() call, the old fd is closed and the new fd is
 * 	returned.
 * \param old The old fd
 * \param ny The desired value for the new fd
 * \retval -1 on error
 * \return The new fd returned by \c dup2()
 * \see \c dup2()
 * \warning This function assumes that as long as the new fd stays open, closing
 * the old fd won't block the calling thread. There might be cases where close()
 * fails or blocks regardless?
 * \note As per the behaviour of \c dup2(), the new fd is silently closed if if
 * is a valid fd. Use this function if you're absolutely sure that the new fd is
 * not used. Like setting up a pipe as standard IO(fd 0, 1 and 2).
 */
int prne_chfd (const int old, const int ny);

/**
 * \brief Zero-fill the region of memory - call \c memset() with zero
 */
void prne_memzero(void *addr, const size_t len);

/**
 * \brief Safe \c malloc() - do overflow check and return NULL for zero length
 * 	allocation
 * \param se the size of an element
 * \param cnt the number of elements
 * \retval NULL if the size calculated is zero. \c errno left untouched
 * \retval NULL on allocation failure or integer overflow. \c errno set to
 * 	\c ENOMEM
 * \return The pointer returned from \c malloc()
 * \note The purpose of the functions including \c prne_realloc()
 * 	\c prne_calloc() is following.
 * - To have a version of \c malloc() that always returns NULL for zero-length
 *   allocation. A valid pointer is returned on most platforms and NULL is
 *   returned on some platforms.
 * - Integer overflow check (especially for 16-bit machines)
 * - To implement a memory allocation event system in the future. Valgrind might
 *   not be a suitable candidate to debug Proone and a different approach(like
 *   the one chosen for MSVCRT) could be desired.
 * \see \c malloc()
 */
void *prne_malloc (const size_t se, const size_t cnt);\
/**
 * \brief Do \c reallocarray() See \c prne_malloc()
 * \param ptr the pointer to the previously dynamically allocated memory
 * 	acceptable by \c realloc()
 * \param se the size of an element
 * \param cnt the number of elements
 * \retval NULL if the size calculated is zero. \c errno is left untouched. If
 * 	\p ptr is not NULL, free() has been performed to free the memory.
 * \retval NULL on allocation failure or integer overflow. \c errno set to
 * 	\c ENOMEM
 * \return The pointer returned from \c realloc()
 * \note Unlike \c realloc() using this function with \p ptr to dynamically
 * 	allocated memory and either of \p se or \p cnt zero has the same effect as
 * 	\c free()
 * \see \c prne_malloc()
 */
void *prne_realloc (void *ptr, const size_t se, const size_t cnt);
/**
 * \brief Call \c calloc() but ensure that NULL is always returned for
 * 	zero-length allocation
 * \param se the size of an element
 * \param cnt the number of elements
 * \retval NULL if the size calculated is zero. \c errno left untouched
 * \retval NULL on allocation failure or integer overflow. \c errno set to
 * 	\c ENOMEM
 * \return The pointer returned from \c calloc()
 * \see \c prne_malloc()
 */
void *prne_calloc (const size_t se, const size_t cnt);
/**
 * \brief Dynamically allocate memory for a string of the specified length. This
 * 	is a convenience function for performing \c malloc(strlen(str)+1)
 * \param len the byte length of the string excluding the null-terminator
 * \retval NULL on allocation failure or integer overflow. \c errno set to
 * 	\c ENOMEM
 * \return The pointer to the dynamically allocated memory for storing the
 * 	string of the specified length
 * \see \c prne_realloc_str()
 * \note Implemented using \c prne_realloc_str()
 */
char *prne_alloc_str (const size_t len);
/**
 * \brief Dynamically allocate memory for a string of the specified length. This
 * 	is a convenience function for performing \c realloc(ptr,strlen(str)+1)
 * \param old the pointer to the previously dynamically allocated memory
 * \param len the new byte length of the string excluding the null-terminator
 * \retval NULL on allocation failure or integer overflow. \c errno set to
 * 	\c ENOMEM
 * \return The pointer to the newly dynamically allocated memory for storing the
 * 	string of the specified length
 * \note Unlike \c prne_realloc() calling this function with zero \p len won't
 * 	free \p old since the length of the new string is calculated as len + 1
 */
char *prne_realloc_str (char *old, const size_t len);
/**
 * \brief Make a new copy of the string. This is a convenience function for
 * performing \c malloc(strlen(str)+1) and then \c strcpy()
 * \retval NULL on memory allocation error, \c errno set to \c ENOMEM
 * \return The pointer to the new copy of the string
 * \see \c prne_redup_str()
 * \note Implemented using \c prne_redup_str()
 */
char *prne_dup_str (const char *str);
/**
 * \brief Make a new copy of the string. This is a convenience function for
 * performing \c realloc(ptr,strlen(str)+1) and then \c strcpy()
 * \retval NULL on memory allocation error, \c errno set to \c ENOMEM
 * \return The pointer to the new copy of the string
 * \see \c prne_redup_str()
 * \note Implemented using \c prne_redup_str()
 */
char *prne_redup_str (char *old, const char *str);
/**
 * \brief Scrub and free the string. For freeing strings containing sensitive
 * data
 */
void prne_sfree_str (char *s);
/**
 * \brief Do \c free()
 * \see [/doc/impl.md#Resource Allocation Hook](/doc/impl.md#resource_allocation_hook)
 */
void prne_free (void *ptr);
/**
 * \brief Do \c sysconf(_SC_PAGESIZE) Call \c abort() on failure
 */
size_t prne_getpagesize (void);

/**
 * \brief Assume the ownership of the memory by doing \c realloc() if necessary.
 * If \p ownership is unset, the function allocates new memory and copies the
 * content of the original memory to the new memory, leaving the original memory
 * intact. The \p ownership will always be set upon successful operation. If the
 * flag is set, calling the function is equivalent to calling \c realloc()
 *
 * \param p The pointer to the pointer holding the address
 * \param ownership The pointer to the the current ownership flag
 * \param se The byte size of each element
 * \param old The current number of elements
 * \param req The number of elements requested
 * \retval true if the operation was successful
 * \retval false otherwise, \c errno set
 * \see [/doc/impl.md#Ownership of Dynamically Resources](/doc/impl.md#ownership_of_dynamically_resources)
 */
bool prne_own_realloc (
	void **p,
	bool *ownership,
	const size_t se,
	size_t *old,
	const size_t req);

/* Locale "C" character category functions */
/**
 * \brief The POSIX locale \c toupper() that does not use any global
 */
char prne_ctoupper (const char c);
/**
 * \brief The POSIX locale \c tolower() that does not use any global
 */
char prne_ctolower (const char c);
/**
 * \brief The POSIX locale \c isspace() that does not use any global
 */
bool prne_cisspace (const char c);
/**
 * \brief The POSIX locale \c isprint() that does not use any global
 */
bool prne_cisprint (const char c);
/**
 * \brief Test if \p c is zero
 */
bool prne_ciszero (const char c);

/**
 * \brief Test if two strings are equal, treating a null pointer as an empty
 * string
 */
bool prne_nstreq (const char *a, const char *b);
/**
 * \brief Calculate the number of non-zero characters in the string. A null
 * pointer is treated as an empty string
 */
size_t prne_nstrlen (const char *s);
/**
 * \brief Find the first occurence of a character in the string
 *
 * \param p The string
 * \param c The character to look for. A null character is valid
 * \param n The number of characters in the string
 * \return The pointer to the original string offset to the first character
 * found in the string
 * \retval NULL if the character is not found in the string or a null terminator
 * was encountered
 */
char *prne_strnchr (const char *p, const char c, const size_t n);
/**
 * \brief Test the string with \p chk_f
 *
 * \param str The string
 * \param chk_f The test function
 * \retval true if \p chk_f returned true for all characters in the string
 * \retval false otherwise
 */
bool prne_chkcstr (const char *str, bool(*chk_f)(const char));
/**
 * \brief Test the memory with \c chk_f
 *
 * \param m The memory
 * \param len The byte length of the memory
 * \param chk_f The test function
 * \retval true if \p chk_f returned true for all bytes in the memory
 * \retval false otherwise
 */
bool prne_chkcmem (const void *m, size_t len, bool(*chk_f)(const char));
/**
 * \brief Transform the string using \p trans_f
 */
void prne_transstr (char *str,  int(*trans_f)(int));
/**
 * \brief Transform the string using \p trans_f
 */
void prne_transcstr (char *str, char(*trans_f)(char));
/**
 * \brief Transform the memory using \p trans_f
 */
void prne_transmem (void *m, size_t len, int(*trans_f)(int));
/**
 * \brief Transform the memory using \p trans_f
 */
void prne_transcmem (void *m, size_t len, char(*trans_f)(char));
/**
 * \brief Find the last occurrence of the character in the memory
 *
 * \param haystack The memory
 * \param c The character
 * \param hs_len The byte length of the memory
 * \return The pointer to the original string offset to the last character found
 * in the string
 * \retval NULL if the character is not found in the string
 */
void *prne_memrchr (
	const void *haystack,
	const int c,
	const size_t hs_len);
/**
 * \brief Find the last occurrence of the data in the memory
 *
 * \param haystack The memory
 * \param hs_len The byte length of the memory
 * \param needle The data
 * \param n_len The byte length of the data
 * \return The pointer to the original memory offset to the last occurrence of
 * the data found in the memory
 * \retval NULL if the data is not found in the memory
 */
void *prne_memrmem (
	const void *haystack,
	const size_t hs_len,
	const void *const needle,
	const size_t n_len);
/**
 * \brief Find the first occurrence of the data in the memory
 *
 * \param haystack The memory
 * \param hs_len The byte length of the memory
 * \param needle The data
 * \param n_len The byte length of the data
 * \return The pointer to the original memory offset to the first occurrence of
 * the data found in the memory
 * \retval NULL if the data is not found in the memory
 */
void *prne_memmem (
	const void *haystack,
	const size_t hs_len,
	const void *const needle,
	const size_t n_len);
/**
 * \brief Concatenate strings to build a new string
 *
 * \param arr The pointer to the array of null-terminated strings
 * \param cnt The number of elements in \p arr
 * \return The new string
 * \retval NULL on error, \c errno set
 * \see \c prne_rebuild_str()
 */
char *prne_build_str (const char **const arr, const size_t cnt);
/**
 * \brief Concatenate strings to build a new string, doing \c realloc() if
 * necessary
 *
 * \param arr The pointer to the array of null-terminated strings
 * \param cnt The number of elements in \p arr
 * \return The new/reallocated string
 * \retval NULL on error, \c errno set
 * \see \c prne_build_str()
 */
char *prne_rebuild_str (void *prev, const char **const arr, const size_t cnt);
/**
 * \brief Scrub the string. Do nothing if \p str is NULL
 */
void prne_strzero (char *str);

/**
 * \brief Parse an \c uint8_t from the hex characters
 *
 * \param str The pointer to an array of characters at least 2 in length
 * \param out The output
 * \retval true on success
 * \retval false if the array contains invalid characters, \c errno set to
 * \c EINVAL
 */
bool prne_hex_fromstr (const char *str, uint_fast8_t *out);
/**
 * \brief Convert an \c uint8_t to hex characters
 *
 * \param in The value
 * \param out The pointer to an array of characters at least 2 in length
 * \param upper The uppercase flag. If set, uppercase characters will be used.
 * Lowercase characters will be used otherwise.
 */
void prne_hex_tochar (const uint_fast8_t in, char *out, const bool upper);

/**
 * \brief Parse a UUID from the string
 *
 * \param str The string containing a UUID, at least 36 characters long
 * \param out The output memory, at least 16 bytes long
 * \retval true on success
 * \retval false on format error, \c errno set to EINVAL
 */
bool prne_uuid_fromstr (const char *str, uint8_t *out);
/**
 * \brief Convert the UUID to a null-terminated string
 *
 * \param in The memory of the UUID, at least 16 bytes long
 * \param out The preallocated string for output, at least 37 characters long
 */
void prne_uuid_tostr (const uint8_t *in, char *out);

/**
 * \brief Compare two UUIDs
 *
 * \param a The pointer to memory at least 16 bytes long
 * \param b The pointer to memory at least 16 bytes long
 * \return an integer less than, equal to, or greater than zero if \p a is found
 * respectively, to be less than, to match, or be greater than \p b
 */
int prne_cmp_uuid_asc (const void *a, const void *b);
/**
 * \brief Reverse function of \c prne_cmp_uuid_asc()
 * \see \c prne_cmp_uuid_asc()
 */
int prne_cmp_uuid_desc (const void *a, const void *b);

/**
 * \brief Calculate the addition of two timespec structures
 */
struct timespec prne_add_timespec (
	const struct timespec a,
	const struct timespec b);
/**
 * \brief Calculate the subtraction of two timespec structures
 */
struct timespec prne_sub_timespec (
	const struct timespec a,
	const struct timespec b);
/**
 * \brief Convert the timespec structure to seconds
 */
double prne_real_timespec (const struct timespec ts);
/**
 * \brief Convert the timespec structure to milliseconds
 */
long prne_timespec_ms (const struct timespec ts);
/**
 * \brief Construct a timespec structure from milliseconds
 */
struct timespec prne_ms_timespec (const long ms);
/**
 * \brief Compare two timespec strucrures
 * \return an integer less than, equal to, or greater than zero if \p a is found
 * respectively, to be less than, to match, or be greater than \p b
 */
int prne_cmp_timespec (const struct timespec a, const struct timespec b);
/**
 * \brief Return the timespec structure with the smallest value
 */
struct timespec prne_min_timespec (
	const struct timespec a,
	const struct timespec b);
/**
 * \brief Return the timespec structure with the largest value
 */
struct timespec prne_max_timespec (
	const struct timespec a,
	const struct timespec b);
/**
 * \brief Do \c clock_gettime() call, \c abort() on error
 */
struct timespec prne_gettime (const clockid_t cid);

/**
 * \brief Convert a timespec structure to a timeval structure
 */
struct timeval prne_ts2tv (const struct timespec ts);
/**
 * \brief Construct a timeval structure from milliseconds
 */
struct timeval prne_ms_timeval (const long ms);

/**
 * \brief Encode data in Base64 in memory. Allocates memory for output
 *
 * \param data The data to encode
 * \param size The byte length of the data
 * \return The pointer to a newly allocated string containing encoded data
 */
char *prne_enc_base64_mem (const uint8_t *data, const size_t size);
/**
 * \brief Decode the base64 string. Allocates memory for output
 *
 * \param str The input string containing base64 encoded data
 * \param str_len The length of the input string
 * \param data The pointer for output data
 * \param size The pointer for the byte length of the output data
 * \retval true on success
 * \retval false on memory error(ENOMEM) or parsing error(EINVAL)
 */
bool prne_dec_base64_mem (
	const char *str,
	const size_t str_len,
	uint8_t **data,
	size_t *size);

/**
 * \brief Read \c /dev/urandom directly.
 *
 * \param buf The pointer to memory for output
 * \param len The number of bytes to read
 * \return The value returned from \c read() function. \c errno set to the value
 * from the \c read() function
 * \note This function is made to avoid the use of \c getrandom() which can
 * potentially block the caller thread in the event of insufficient entropy
 */
ssize_t prne_geturandom (void *buf, const size_t len);

/**
 * \brief Output the result of bitwise AND operation of the contents of two byte
 * arrays to \p c
 */
void prne_bitop_and (
	const uint8_t *a,
	const uint8_t *b,
	uint8_t *c,
	const size_t len);
/**
 * \brief Output the result of bitwise OR operation of the contents of two byte
 * arrays to \p c
 */
void prne_bitop_or (
	const uint8_t *a,
	const uint8_t *b,
	uint8_t *c,
	const size_t len);
/**
 * \brief Output the result of bitwise NOT operation of the contents of the byte
 * array \p x to \p y
 */
void prne_bitop_inv (
	const uint8_t *x,
	uint8_t *y,
	const size_t len);
