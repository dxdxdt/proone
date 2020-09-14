#include "rnd.h"
#include "util_rt.h"

#include <string.h>
#include <errno.h>


typedef struct {
	uint32_t state[16];
	size_t index;
} rnd_well512_ctx_t;

static uint32_t rnd_well512_pull (rnd_well512_ctx_t *ctx) {
	uint32_t a, b, c, d;

	a = ctx->state[ctx->index];
	c = ctx->state[(ctx->index + 13) & 15];
	b = a ^ c ^ (a << 16) ^ (c << 15);
	c = ctx->state[(ctx->index + 9) & 15];
	c ^= (c >> 11);
	a = ctx->state[ctx->index] = b ^ c;
	d = a ^ ((a << 5) & 0xDA442D24UL);
	ctx->index = (ctx->index + 15) & 15;
	a = ctx->state[ctx->index];
	ctx->state[ctx->index] = a ^ b ^ d ^ (a << 2) ^ (b << 18) ^ (c << 28);

	return ctx->state[ctx->index];
}

static bool rnd_well512_f (void *p, uint8_t *buf, size_t len) {
	rnd_well512_ctx_t *ctx = (rnd_well512_ctx_t*)p;
	size_t consume;
	uint32_t n;


	while (len > 0) {
		n = rnd_well512_pull(ctx);
		consume = prne_op_min(len, sizeof(n));
		memcpy(buf, &n, consume);
		buf += consume;
		len -= consume;
	}

	return true;
}

static void rnd_free_well512 (void *p) {
	prne_free(p);
}

bool prne_rnd_alloc_well512 (
	prne_rnd_t *p,
	const uint8_t *is)
{
	rnd_well512_ctx_t *ctx;

	ctx = (rnd_well512_ctx_t*)prne_calloc(sizeof(rnd_well512_ctx_t), 1);
	if (ctx == NULL) {
		return false;
	}

	prne_free_rnd(p);
	memcpy(ctx->state, is, sizeof(ctx->state));
	p->ctx = ctx;
	p->free_ctx_f = rnd_free_well512;
	p->random = rnd_well512_f;

	return true;
}
