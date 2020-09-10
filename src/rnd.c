#include "rnd.h"
#include "util_rt.h"


void prne_init_rnd (prne_rnd_t *p) {
	prne_memzero(p, sizeof(prne_rnd_t));
}

void prne_free_rnd (prne_rnd_t *p) {
	if (p == NULL) {
		return;
	}

	if (p->free_ctx_f != NULL) {
		p->free_ctx_f(p->ctx);
	}
	prne_memzero(p, sizeof(prne_rnd_t));
}

bool prne_rnd (prne_rnd_t *p, uint8_t *buf, const size_t len) {
	return p->random(p->ctx, buf, len);
}
