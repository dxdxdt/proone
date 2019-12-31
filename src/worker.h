#pragma once
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <poll.h>


typedef uint8_t prne_worker_sched_flag_t;

typedef struct prne_worker_sched_req prne_worker_sched_req_t;
typedef bool(*prne_worker_sched_req_alloc_func_t)(prne_worker_sched_req_t *, const size_t);
typedef void(*prne_worker_sched_req_free_func_t)(prne_worker_sched_req_t *);
typedef struct prne_worker_sched_req_mem_func prne_worker_sched_req_mem_func_t;
typedef struct prne_worker_sched_info prne_worker_sched_info_t;
typedef struct prne_worker prne_worker_t;

struct prne_worker_sched_req_mem_func {
	prne_worker_sched_req_alloc_func_t alloc;
	prne_worker_sched_req_free_func_t free;
	void *ctx;
};

struct prne_worker_sched_req {
	size_t pollfd_arr_size;
	struct pollfd *pollfd_arr;
	struct timespec timeout;
	prne_worker_sched_req_mem_func_t mem_func;
	prne_worker_sched_flag_t flags;
	bool pollfd_ready;
};

struct prne_worker_sched_info {
	prne_worker_sched_flag_t tick_flags;
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
	void (*work)(void *ctx, const prne_worker_sched_info_t *sched_info, prne_worker_sched_req_t *sched_req);
	bool (*has_finalised)(void *ctx);
};

/* Do nothing. The worker has more work to do and is yielding cpu time to the
* other workers.
*/
static const prne_worker_sched_flag_t PRNE_WORKER_SCHED_FLAG_NONE 		= 0x00;
/* Do `poll()`. The worker has to set `shed_req` properly.
*/
static const prne_worker_sched_flag_t PRNE_WORKER_SCHED_FLAG_POLL 		= 0x01;
/* Do `poll()` with timeout or just sleep. The worker has to set
* `prne_worker_sched_req_t::timeout` properly.
*/
static const prne_worker_sched_flag_t PRNE_WORKER_SCHED_FLAG_TIMEOUT	= 0x02;


bool prne_init_worker_sched_req (prne_worker_sched_req_t *wsr, prne_worker_sched_req_mem_func_t *mem_func);
