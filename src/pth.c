#include <errno.h>

#include "util_rt.h"
#include "pth.h"


void prne_init_worker (prne_worker_t *w) {
	w->ctx = NULL;
	w->entry = NULL;
	w->fin = NULL;
	w->free_ctx = NULL;
	w->pth = NULL;
}

void prne_free_worker (prne_worker_t *w) {
	if (w->ctx != NULL) {
		prne_assert(w->free_ctx != NULL);
		w->free_ctx(w->ctx);
		w->ctx = NULL;
	}
}

void prne_fin_worker (prne_worker_t *w) {
	if (w->fin != NULL) {
		w->fin(w->ctx);
	}
}

void prne_pth_cv_notify (pth_mutex_t *lock, pth_cond_t *cond, bool broadcast) {
	prne_assert(pth_mutex_acquire(lock, FALSE, NULL));
	prne_assert(pth_cond_notify(cond, broadcast));
	pth_mutex_release(lock);
}

pth_time_t prne_pth_tstimeout (const struct timespec ts) {
	return pth_timeout(ts.tv_sec, ts.tv_nsec / 1000);
}
