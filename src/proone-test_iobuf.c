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
