/** \file
 * \brief The IO buffer implementation.
 * \note The IO buffer is a FIFO byte array object with some extra convenience
 *	functions. The IO buffer is similar to the C++ counterpart,
 *	\c std::vector<uint8_t>
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
#include <stddef.h>
#include <stdbool.h>

#include <sys/types.h>


/* Alias declarations */
typedef struct prne_iobuf prne_iobuf_t;

// The IO buffer object.
struct prne_iobuf {
	uint8_t *m; // The buffer
	size_t size; // The size of buffer
	size_t avail; // The length of the buffer available (size - len)
	size_t len; // The length of the contents
	/* The ownership status of the buffer.
	 * True if the object is responsible for freeing the allocated memory for
	 * the buffer. False otherwise.
	 */
	bool ownership;
};


/**
 * \brief Initialise the IO buffer object.
 * \param ib The pointer to the IO buffer object.
 * \note \p ib can be freed using \c prne_free_iobuf() once initialised.
 * \see \c prne_free_iobuf()
 */
void prne_init_iobuf (prne_iobuf_t *ib);
/**
 * \brief Free resources allocated for the IO buffer object.
 * \param ib The pointer to the IO buffer object.
 * \see \c prne_init_iobuf()
 */
void prne_free_iobuf (prne_iobuf_t *ib);
/**
 * \brief Allocate memory to set the size of the buffer.
 * \param ib The pointer to the IO buffer object.
 * \param ny_size The new byte size of the buffer.
 * \retval true if allocation has been successful.
 * \retval false otherwise with \c errno set.
 */
bool prne_alloc_iobuf (prne_iobuf_t *ib, const size_t ny_size);
/**
 * \brief Try allocating memory for the buffer using the sizes specified in the
 *	array.
 * \param ib The pointer to the IO buffer object.
 * \param ny_size The pointer to the array of new sizes of the buffer.
 * \retval true if the size of the buffer has been successfully set to one of
 *	the sizes in \p ny_size.
 * \retval false otherwise with \c errno set.
 * \note The sizes are tried from the first element of \p ny_size. Usually,
 *	you'd want to set the elements of the array in the descending order so the
 *	largest size is tried first which is optimal in most cases.
 */
bool prne_try_alloc_iobuf (prne_iobuf_t *ib, const size_t *ny_size);
/**
 * \brief Set up the IO buffer object to use the external buffer, relieving the
 *	IO buffer object's responsibility of freeing the buffer.
 * \param ib The pointer to the IO buffer object.
 * \param m The pointer to the external buffer.
 * \param size The size of the external buffer.
 * \param len The initial length of the contents in the external buffer.
 *	This is usually zero unless there are contents in the external buffer to be
 *	used.
 * \note The function is useful when the use of static type of memory such as
 *	.bss or stack is desired. Any dynamic resource previously allocated is
*	freed.
 */
void prne_iobuf_setextbuf (
	prne_iobuf_t *ib,
	uint8_t *m,
	const size_t size,
	const size_t len);
/**
 * \brief Reset the buffer state - Set \c len to zero and \c avail to the size
 *	of the buffer.
 * \param ib The pointer to the io buffer object.
 * \note Use this function to discard the contents of the buffer. The contents
 *	of the buffer will remain untouched. You may want to use
 *	\c prne_iobuf_zero() to scrub the data off memory.
 * \see \c prne_iobuf_zero()
 */
void prne_iobuf_reset (prne_iobuf_t *ib);
/**
 * \brief Zero-fill the entire buffer - \c memset() convenience function.
 * \param ib The pointer to the IO buffer object.
 * \note This is the equivalent of calling \c memset() and
 *	\c prne_iobuf_reset().
 */
void prne_iobuf_zero (prne_iobuf_t *ib);
/**
 * \brief Shift the contents of the buffer - \c memmove() convenience function.
 * \param ib The pointer to the IO buffer object.
 * \param amount The number of bytes to shift. A positive value simply increases
 *	\c len and decreases \c avail. A negative value causes the function to call
 *	\c memmove() to discard the amount of data specified, increasing \c avail
 *	and decreasing \c len
 * \warning When shifting the contents of the buffer to the left, depending on
 *	the behaviour of \c memmove(), the contents of the buffer on the right may
 *	remain intact on memory. Do not use IO buffer to store sensitive data.
 */
void prne_iobuf_shift (prne_iobuf_t *ib, const ssize_t amount);
