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
