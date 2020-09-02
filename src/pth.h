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

void prne_pth_cv_notify (pth_mutex_t *lock, pth_cond_t *cond, bool broadcast);
pth_time_t prne_pth_tstimeout (const struct timespec ts);
