#pragma once
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <poll.h>

#include "llist.h"


struct prne_wkr_timeout_slot;
struct prne_wkr_pollfd_slot;
struct prne_wkr_tick_info;
struct prne_wkr_sched_req;
typedef struct prne_wkr_timeout_slot* prne_wkr_timeout_slot_pt;
typedef struct prne_wkr_pollfd_slot* prne_wkr_pollfd_slot_pt;
typedef struct prne_wkr_sched_req prne_wkr_sched_req_t;
typedef struct prne_wkr_tick_info prne_wkr_tick_info_t;
typedef struct prne_worker prne_worker_t;

struct prne_wkr_slot_parent {
	prne_llist_entry_t *ent;
	prne_wkr_sched_req_t *wsr;
};

struct prne_wkr_timeout_slot {
	struct timespec dur;
	struct prne_wkr_slot_parent parent;
	bool active;
	bool reached;
};

struct prne_wkr_pollfd_slot {
	struct pollfd pfd;
	struct prne_wkr_slot_parent parent;
};

struct prne_wkr_sched_req {
	struct pollfd *pfd_arr;
	size_t pfd_arr_size;
	struct timespec timeout;
	prne_llist_t tos_list;
	prne_llist_t pfd_list;
	bool timeout_active;
};

struct prne_wkr_tick_info {
	struct timespec last_tick;
	struct timespec this_tick;
	struct timespec tick_diff;
	double real_tick_diff;
};

struct prne_worker {
	intptr_t id;
	void *ctx;

	void (*free)(void *ctx);
	void (*fin)(void *ctx);
	void (*work)(void *ctx, const prne_wkr_tick_info_t *sched_info);
	bool (*has_finalised)(void *ctx);
};


void prne_init_wkr_sched_req (prne_wkr_sched_req_t *r);
void prne_free_wkr_sched_req (prne_wkr_sched_req_t *r);
bool prne_wkr_sched_req_prep_poll (prne_wkr_sched_req_t *r);
void prne_wkr_sched_req_refl_poll (prne_wkr_sched_req_t *r, const int poll_ret, const struct timespec elapsed);
bool prne_wkr_sched_req_do_poll (prne_wkr_sched_req_t *r, int *poll_ret);

prne_wkr_timeout_slot_pt prne_alloc_wkr_timeout_slot (prne_wkr_sched_req_t *r);
void prne_free_wkr_timeout_slot (prne_wkr_timeout_slot_pt s);
prne_wkr_pollfd_slot_pt prne_alloc_wkr_pollfd_slot (prne_wkr_sched_req_t *r);
void prne_free_wkr_pollfd_slot (prne_wkr_pollfd_slot_pt s);

void prne_init_wkr_tick_info (prne_wkr_tick_info_t *ti);
void prne_free_wkr_tick_info (prne_wkr_tick_info_t *ti);
void prne_wkr_tick_info_set_start (prne_wkr_tick_info_t *ti);
void prne_wkr_tick_info_set_tick (prne_wkr_tick_info_t *ti);