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
#include "iobuf.h"
#include "util_ct.h"
#include "util_rt.h"

#include <string.h>


void prne_init_iobuf (prne_iobuf_t *ib){
	prne_memzero(ib ,sizeof(prne_iobuf_t));
}

void prne_free_iobuf (prne_iobuf_t *ib) {
	if (ib->ownership) {
		prne_free(ib->m);
		ib->m = NULL;
		ib->size = 0;
		ib->avail = 0;
		ib->len = 0;
	}
}

bool prne_alloc_iobuf (prne_iobuf_t *ib, const size_t ny_size) {
	uint8_t *ny;

	ny = (uint8_t*)prne_realloc(ib->ownership ? ib->m : NULL, 1, ny_size);
	if (ny == NULL && ny_size > 0) {
		return false;
	}

	if (!ib->ownership) {
		memcpy(ny, ib->m, prne_op_min(ny_size, ib->size));
	}

	if (ib->size < ny_size) {
		ib->avail += ny_size - ib->size;
	}
	else {
		ib->avail -= ib->size - ny_size;
	}
	ib->m = ny;
	ib->size = ny_size;
	ib->ownership = true;

	return true;
}

bool prne_try_alloc_iobuf (prne_iobuf_t *ib, const size_t *ny_size) {
	for (; *ny_size != 0; ny_size += 1) {
		if (prne_alloc_iobuf(ib, *ny_size)) {
			return true;
		}
	}
	return false;
}

void prne_iobuf_setextbuf (
	prne_iobuf_t *ib,
	uint8_t *m,
	const size_t size,
	const size_t len)
{
	prne_dbgast(size >= len);
	prne_free_iobuf(ib);
	ib->m = m;
	ib->size = size;
	ib->len = len;
	ib->avail = size - len;
	ib->ownership = false;
}

void prne_iobuf_reset (prne_iobuf_t *ib) {
	ib->avail = ib->size;
	ib->len = 0;
}

void prne_iobuf_shift (prne_iobuf_t *ib, const ssize_t amount) {
	if (amount == 0) {
		return;
	}
	else if (amount > 0) {
		prne_dbgast(ib->avail >= (size_t)amount);
	}
	else {
		prne_dbgast(ib->len >= (size_t)(amount * -1));
	}

	ib->len += amount;
	ib->avail -= amount;
	if (amount < 0) {
		memmove(ib->m, ib->m + (-amount), ib->len);
	}
}

void prne_iobuf_zero (prne_iobuf_t *ib) {
	prne_memzero(ib->m, ib->size);
	prne_iobuf_reset(ib);
}
