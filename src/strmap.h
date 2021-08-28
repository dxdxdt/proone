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


typedef struct prne_strmap prne_strmap_t;
typedef struct prne_strmap_tuple prne_strmap_tuple_t;
typedef uintptr_t prne_strmap_val_t;

struct prne_strmap {
	prne_strmap_tuple_t *tbl;
	size_t size;
};

struct prne_strmap_tuple {
	const char *key;
	prne_strmap_val_t val;
};

void prne_init_strmap (prne_strmap_t *map);
void prne_free_strmap (prne_strmap_t *map);

void prne_strmap_clear (prne_strmap_t *map);
const prne_strmap_tuple_t *prne_strmap_insert (
	prne_strmap_t *map,
	const char* key,
	const prne_strmap_val_t val);
void prne_strmap_erase (prne_strmap_t *map, const char* key);
const prne_strmap_tuple_t *prne_strmap_lookup (
	prne_strmap_t *map,
	const char* key);
