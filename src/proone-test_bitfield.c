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
#include <stdio.h>
#include <assert.h>

#include "util_rt.h"
#include "bitfield.h"


static void chk_func (void *ctx, const unsigned int bit, const bool v) {
	static unsigned int nb_calls = 0;

	assert(nb_calls == bit);
	nb_calls += 1;
	assert(ctx == (void*)UINTPTR_MAX);
	if (v) {
		assert(
			bit == 0 ||
			bit == 2 ||
			bit == 4 ||
			bit == 6 ||
			bit == 8 ||
			bit == 10 ||
			bit == 12 ||
			bit == 14);
	}
	else {
		assert(
			bit == 1 ||
			bit == 3 ||
			bit == 5 ||
			bit == 7 ||
			bit == 9 ||
			bit == 11 ||
			bit == 13 ||
			bit == 15);
	}
}

int main (void) {
	static uint8_t bf[2];

	assert(prne_bf_get_size(0) == 0);
	assert(prne_bf_get_size(1) == 1);
	assert(prne_bf_get_size(8) == 1);
	assert(prne_bf_get_size(9) == 2);
	assert(prne_bf_get_size(16) == 2);
	assert(prne_bf_get_size(20) == 3);
	assert(prne_bf_get_size(32) == 4);

	prne_memzero(bf, sizeof(bf));
	prne_bf_set(bf, 1, true);
	prne_bf_set(bf, 3, true);
	prne_bf_set(bf, 5, true);
	prne_bf_set(bf, 7, true);
	prne_bf_set(bf, 9, true);
	prne_bf_set(bf, 11, true);
	prne_bf_set(bf, 13, true);
	prne_bf_set(bf, 15, true);
	assert(prne_bf_test(bf, sizeof(bf), 0) == false);
	assert(prne_bf_test(bf, sizeof(bf), 1) == true);
	assert(prne_bf_test(bf, sizeof(bf), 2) == false);
	assert(prne_bf_test(bf, sizeof(bf), 3) == true);
	assert(prne_bf_test(bf, sizeof(bf), 4) == false);
	assert(prne_bf_test(bf, sizeof(bf), 5) == true);
	assert(prne_bf_test(bf, sizeof(bf), 6) == false);
	assert(prne_bf_test(bf, sizeof(bf), 7) == true);
	assert(prne_bf_test(bf, sizeof(bf), 8) == false);
	assert(prne_bf_test(bf, sizeof(bf), 9) == true);
	assert(prne_bf_test(bf, sizeof(bf), 10) == false);
	assert(prne_bf_test(bf, sizeof(bf), 11) == true);
	assert(prne_bf_test(bf, sizeof(bf), 12) == false);
	assert(prne_bf_test(bf, sizeof(bf), 13) == true);
	assert(prne_bf_test(bf, sizeof(bf), 14) == false);
	assert(prne_bf_test(bf, sizeof(bf), 15) == true);
	assert(bf[0] == 0xAA && bf[1] == 0xAA);
	prne_bf_set(bf, 1, false);
	prne_bf_set(bf, 3, false);
	prne_bf_set(bf, 5, false);
	prne_bf_set(bf, 7, false);
	prne_bf_set(bf, 9, false);
	prne_bf_set(bf, 11, false);
	prne_bf_set(bf, 13, false);
	prne_bf_set(bf, 15, false);
	assert(prne_bf_test(bf, sizeof(bf), 0) == false);
	assert(prne_bf_test(bf, sizeof(bf), 1) == false);
	assert(prne_bf_test(bf, sizeof(bf), 2) == false);
	assert(prne_bf_test(bf, sizeof(bf), 3) == false);
	assert(prne_bf_test(bf, sizeof(bf), 4) == false);
	assert(prne_bf_test(bf, sizeof(bf), 5) == false);
	assert(prne_bf_test(bf, sizeof(bf), 6) == false);
	assert(prne_bf_test(bf, sizeof(bf), 7) == false);
	assert(prne_bf_test(bf, sizeof(bf), 8) == false);
	assert(prne_bf_test(bf, sizeof(bf), 9) == false);
	assert(prne_bf_test(bf, sizeof(bf), 10) == false);
	assert(prne_bf_test(bf, sizeof(bf), 11) == false);
	assert(prne_bf_test(bf, sizeof(bf), 12) == false);
	assert(prne_bf_test(bf, sizeof(bf), 13) == false);
	assert(prne_bf_test(bf, sizeof(bf), 14) == false);
	assert(prne_bf_test(bf, sizeof(bf), 15) == false);
	assert(bf[0] == 0x00 && bf[1] == 0x00);

	prne_memzero(bf, sizeof(bf));
	prne_bf_set(bf, 0, true);
	prne_bf_set(bf, 2, true);
	prne_bf_set(bf, 4, true);
	prne_bf_set(bf, 6, true);
	prne_bf_set(bf, 8, true);
	prne_bf_set(bf, 10, true);
	prne_bf_set(bf, 12, true);
	prne_bf_set(bf, 14, true);
	assert(bf[0] == 0x55 && bf[1] == 0x55);
	prne_bf_foreach((void*)UINTPTR_MAX, bf, sizeof(bf), chk_func);

	return 0;
}
