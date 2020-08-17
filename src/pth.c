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

bool prne_pth_cv_notify (prne_pth_cv_t *cv) {
	bool ret;

	if (pth_mutex_acquire(cv->lock, FALSE, NULL)) {
		ret = pth_cond_notify(cv->cond, cv->broadcast) == 0;
		prne_assert(pth_mutex_release(cv->lock));
	}
	else {
		ret = false;
	}

	return ret;
}

bool prne_pth_cond_timedwait (prne_pth_cv_t *cv, const struct timespec *timeout, bool *to_reached) {
	pth_event_t ev;
	bool ret, reached;

	if (timeout != NULL) {
		ev = pth_event(PTH_EVENT_TIME, pth_timeout(timeout->tv_sec, timeout->tv_nsec / 1000));
		if (ev == NULL) {
			return -1;
		}
	}
	else {
		ev = NULL;
	}

	if (pth_mutex_acquire(cv->lock, FALSE, NULL)) {
		ret = pth_cond_await(cv->cond, cv->lock, ev);
		prne_assert(pth_mutex_release(cv->lock));
	}
	else {
		ret = false;
	}
	
	if (ev != NULL && pth_event_occurred(ev)) {
		ret = true;
		reached = true;
	}
	else {
		reached = false;
	}

	if (to_reached != NULL) {
		*to_reached = reached;
	}

	pth_event_free(ev, FALSE);
	return ret;
}

int prne_unint_pth_poll (struct pollfd *fds, nfds_t nfds, const struct timespec *timeout) {
	pth_event_t ev;
	int ret;

	if (timeout != NULL) {
		ev = pth_event(PTH_EVENT_TIME, pth_timeout(timeout->tv_sec, timeout->tv_nsec / 1000));
		if (ev == NULL) {
			return -1;
		}
	}
	else {
		ev = NULL;
	}

	do {
		ret = pth_poll_ev(fds, nfds, -1, ev);
		if (ev != NULL && pth_event_occurred(ev)) {
			ret = 0;
			break;
		}
		if (ret < 0 && errno == EINTR) {
			continue;
		}
	} while (false);

	pth_event_free(ev, FALSE);
	return ret;
}

void prne_unint_pth_nanosleep (struct timespec dur) {
	struct timespec rem;

	while (pth_nanosleep(&dur, &rem) < 0 && errno == EINTR) {
		dur = rem;
	}
}
