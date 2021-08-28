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


struct prne_imap;
struct prne_imap_tuple;
typedef uintptr_t prne_imap_key_type_t;
typedef uintptr_t prne_imap_val_type_t;
typedef struct prne_imap prne_imap_t;
typedef struct prne_imap_tuple prne_imap_tuple_t;

struct prne_imap {
	prne_imap_tuple_t *tbl;
	size_t size;
};

struct prne_imap_tuple {
	prne_imap_key_type_t key;
	prne_imap_val_type_t val;
};


void prne_init_imap (prne_imap_t *im);
void prne_free_imap (prne_imap_t *im);

void prne_imap_clear (prne_imap_t *im);
const prne_imap_tuple_t *prne_imap_insert (
	prne_imap_t *im,
	const prne_imap_key_type_t key,
	const prne_imap_val_type_t val);
void prne_imap_erase (prne_imap_t *im, const prne_imap_key_type_t key);
const prne_imap_tuple_t *prne_imap_lookup (
	prne_imap_t *im,
	const prne_imap_key_type_t key);
