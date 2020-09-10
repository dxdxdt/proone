#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>


struct prne_rnd {
	void *ctx;
	void (*free_ctx_f)(void*);
	bool (*random)(void*, uint8_t *buf, size_t len);
};

typedef struct prne_rnd prne_rnd_t;


void prne_init_rnd (prne_rnd_t *p);
void prne_free_rnd (prne_rnd_t *p);
bool prne_rnd (prne_rnd_t *p, uint8_t *buf, const size_t len);

/*
* is_len should be 64 bytes(512 bits).
*/
bool prne_rnd_alloc_well512 (
	prne_rnd_t *p,
	const uint8_t *is,
	const size_t is_len);
