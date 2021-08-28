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
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>


typedef struct prne_iset prne_iset_t;
typedef uintptr_t prne_iset_val_t;

struct prne_iset {
	prne_iset_val_t *arr;
	size_t size;
};


void prne_init_iset (prne_iset_t *s);
void prne_free_iset (prne_iset_t *s);

void prne_iset_clear (prne_iset_t *s);
bool prne_iset_insert (prne_iset_t *s, const prne_iset_val_t v);
void prne_iset_erase (prne_iset_t *s, const prne_iset_val_t v);
bool prne_iset_lookup (prne_iset_t *s, const prne_iset_val_t v);
