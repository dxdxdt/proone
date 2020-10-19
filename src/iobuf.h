#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <sys/types.h>


typedef struct prne_iobuf prne_iobuf_t;

struct prne_iobuf {
	uint8_t *m;
	size_t size;
	size_t avail;
	size_t len;
	bool ownership;
};


void prne_init_iobuf (prne_iobuf_t *ib);
void prne_free_iobuf (prne_iobuf_t *ib);
bool prne_alloc_iobuf (prne_iobuf_t *ib, const size_t ny_size);
void prne_iobuf_setextbuf (
	prne_iobuf_t *ib,
	uint8_t *m,
	const size_t size,
	const size_t len);
void prne_iobuf_reset (prne_iobuf_t *ib);
void prne_iobuf_zero (prne_iobuf_t *ib);
void prne_iobuf_shift (prne_iobuf_t *ib, const ssize_t amount);
