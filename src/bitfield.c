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

bool prne_bf_test (const uint8_t *bf, const unsigned int bit) {
	const unsigned int p = bit / 8;
	const unsigned int s = bit - p * 8;

	return bf[p] & (1 << s);
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
