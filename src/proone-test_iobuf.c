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
#include "iobuf.h"

#include <assert.h>


int main (void) {
	static const size_t FAIL_ARR0[] = { 0 };
	static const size_t FAIL_ARR1[] = { SIZE_MAX, 0 };
	static const size_t FAIL_ARR2[] = { SIZE_MAX, SIZE_MAX, SIZE_MAX, 0 };
	static const size_t OK_ARR0[] = { 4096, 0 };
	static const size_t OK_ARR1[] = { SIZE_MAX, 4096, 0 };
	prne_iobuf_t ib;

	prne_init_iobuf(&ib);
	assert(!prne_try_alloc_iobuf(&ib, FAIL_ARR0));
	assert(!prne_try_alloc_iobuf(&ib, FAIL_ARR1));
	assert(!prne_try_alloc_iobuf(&ib, FAIL_ARR2));
	assert(prne_try_alloc_iobuf(&ib, OK_ARR0));
	assert(prne_try_alloc_iobuf(&ib, OK_ARR1));
	prne_free_iobuf(&ib);

	return 0;
}
