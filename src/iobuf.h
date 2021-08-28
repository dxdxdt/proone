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

#include <sys/types.h>


typedef struct prne_iobuf prne_iobuf_t;

struct prne_iobuf {
	uint8_t *m;
	size_t size;
	size_t avail;
	size_t len;
	bool ownership;
};


void prne_init_iobuf (prne_iobuf_t *ib);
void prne_free_iobuf (prne_iobuf_t *ib);
bool prne_alloc_iobuf (prne_iobuf_t *ib, const size_t ny_size);
bool prne_try_alloc_iobuf (prne_iobuf_t *ib, const size_t *ny_size);
void prne_iobuf_setextbuf (
	prne_iobuf_t *ib,
	uint8_t *m,
	const size_t size,
	const size_t len);
void prne_iobuf_reset (prne_iobuf_t *ib);
void prne_iobuf_zero (prne_iobuf_t *ib);
void prne_iobuf_shift (prne_iobuf_t *ib, const ssize_t amount);
