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
#include "bitfield.h"


void prne_bf_set (uint8_t *bf, const unsigned int bit, const bool v) {
	const unsigned int p = bit / 8;
	const unsigned int s = bit - p * 8;

	if (v) {
		bf[p] |= 1 << s;
	}
	else {
		bf[p] &= ~(1 << s);
	}
}

bool prne_bf_test (
	const uint8_t *bf,
	const size_t size,
	const unsigned int bit)
{
	const unsigned int p = bit / 8;
	const unsigned int s = bit - p * 8;

	if (size <= p) {
		// treat unset if the index is out of bounds
		return false;
	}

	return (bf[p] & (1 << s)) != 0;
}

void prne_bf_foreach (
	void *ctx,
	const uint8_t *bf,
	const size_t size,
	prne_bf_foreach_ft f)
{
	unsigned int bit = 0;

	for (size_t i = 0; i < size; i += 1) {
		for (unsigned int j = 0; j < 8; j += 1) {
			f(ctx, bit, (bf[i] & (1 << j)) != 0);
			bit += 1;
		}
	}
}
