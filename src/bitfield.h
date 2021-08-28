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

#include "util_ct.h"

// This macro accepts zero
#define prne_bf_get_size(nb_bits)\
	((nb_bits) % 8 == 0 ? (nb_bits) / 8 : (nb_bits) / 8 + 1)

typedef void(*prne_bf_foreach_ft)(
	void *ctx,
	const unsigned int bit,
	const bool v);


void prne_bf_set (uint8_t *bf, const unsigned int bit, const bool v);
bool prne_bf_test (
	const uint8_t *bf,
	const size_t size,
	const unsigned int bit);
void prne_bf_foreach (
	void *ctx,
	const uint8_t *bf,
	const size_t size,
	prne_bf_foreach_ft f);
