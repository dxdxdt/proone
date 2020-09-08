#pragma once
#include <stdbool.h>

#include <pthsem.h>


struct prne_worker {
	void *ctx;
	void *(*entry)(void*);
	void (*fin)(void*);
	void (*free_ctx)(void*);
	pth_t pth;
};
typedef struct prne_worker prne_worker_t;

struct prne_pth_cv {
	pth_mutex_t *lock;
	pth_cond_t *cond;
	bool broadcast;
};
typedef struct prne_pth_cv prne_pth_cv_t;


void prne_init_worker (prne_worker_t *w);
void prne_free_worker (prne_worker_t *w);
void prne_fin_worker (prne_worker_t *w);

/* Workaround for bug in GNU Pth
* Calling pth_poll() with pollfd element whose fd is negative value results in
* undefined behaviour as stated in POSIX(FD_SET() with invalid value is
* undefined). GNU Pth uses FD_SET() with invalid values on purpose to achieve
* something.
*/
int prne_pth_poll (
	struct pollfd *pfd,
	const nfds_t nfs,
	const int timeout,
	pth_event_t ev);
void prne_pth_cv_notify (pth_mutex_t *lock, pth_cond_t *cond, bool broadcast);
pth_time_t prne_pth_tstimeout (const struct timespec ts);
