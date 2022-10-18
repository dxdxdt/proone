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
#include "imap.h"
#include "util_rt.h"

#include <stdlib.h>
#include <string.h>


static int imap_cmp_func (const void *in_a, const void *in_b) {
	const prne_imap_tuple_t *a = (const prne_imap_tuple_t*)in_a;
	const prne_imap_tuple_t *b = (const prne_imap_tuple_t*)in_b;

	return
		a->key < b->key ? -1 :
		a->key > b->key ? 1 :
		0;
}

void prne_init_imap (prne_imap_t *im) {
	im->tbl = NULL;
	im->size = 0;
}

void prne_free_imap (prne_imap_t *im) {
	prne_free(im->tbl);
	im->tbl = NULL;
	im->size = 0;
}

void prne_imap_clear (prne_imap_t *im) {
	prne_free(im->tbl);
	im->tbl = NULL;
	im->size = 0;
}

const prne_imap_tuple_t *prne_imap_insert (
	prne_imap_t *im,
	const prne_imap_key_type_t key,
	const prne_imap_val_type_t val)
{
	prne_imap_tuple_t *ret;
	prne_imap_tuple_t t;

	t.key = key;
	t.val = val;

	ret = (prne_imap_tuple_t*)bsearch(
		&t,
		im->tbl,
		im->size,
		sizeof(prne_imap_tuple_t),
		imap_cmp_func);
	if (ret == NULL) {
		void *ny_mem;

		ny_mem = prne_realloc(im->tbl, sizeof(prne_imap_tuple_t), im->size + 1);
		if (ny_mem == NULL) {
			return NULL;
		}
		im->tbl = (prne_imap_tuple_t*)ny_mem;
		im->tbl[im->size] = t;
		im->size += 1;

		qsort(im->tbl, im->size, sizeof(prne_imap_tuple_t), imap_cmp_func);
		ret = (prne_imap_tuple_t*)prne_imap_lookup(im, key);
	}
	else {
		ret->val = t.val;
	}

	return ret;
}

void prne_imap_erase (prne_imap_t *im, const prne_imap_key_type_t key) {
	prne_imap_tuple_t *ext;
	prne_imap_tuple_t t;

	t.key = key;
	t.val = 0;

	ext = bsearch(
		&t,
		im->tbl,
		im->size,
		sizeof(prne_imap_tuple_t),
		imap_cmp_func);
	if (ext == NULL) {
		return;
	}

	if (im->size - 1 == 0) {
		prne_free(im->tbl);
		im->tbl = NULL;
		im->size = 0;
	}
	else {
		void *ny_mem;

		memmove(
			ext,
			ext + 1,
			sizeof(prne_imap_tuple_t) * (im->size - 1 - (ext - im->tbl)));
		im->size -= 1;
		ny_mem = prne_realloc(im->tbl, sizeof(prne_imap_tuple_t), im->size);
		if (ny_mem != NULL) {
			im->tbl = (prne_imap_tuple_t*)ny_mem;
		}
	}
}

const prne_imap_tuple_t *prne_imap_lookup (
	prne_imap_t *im,
	const prne_imap_key_type_t key)
{
	prne_imap_tuple_t t;

	t.key = key;
	t.val = 0;

	return (const prne_imap_tuple_t*)bsearch(
		&t,
		im->tbl,
		im->size,
		sizeof(prne_imap_tuple_t),
		imap_cmp_func);
}
