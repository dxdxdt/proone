#include "worker.h"
#include "util_rt.h"

#include <stdlib.h>


static void def_free_func (prne_worker_sched_req_t *wsr) {
	prne_free(wsr->pollfd_arr);
	wsr->pollfd_arr = NULL;
	wsr->pollfd_arr_size = 0;
}

static bool def_alloc_func (prne_worker_sched_req_t *wsr, const size_t ny_size) {
	if (ny_size == 0) {
		def_free_func(wsr);
	}
	else if (ny_size != wsr->pollfd_arr_size) {
		void *ny_buf = prne_realloc(wsr->pollfd_arr, sizeof(struct pollfd), ny_size);

		if (ny_buf == NULL) {
			return false;
		}
		wsr->pollfd_arr = (struct pollfd*)ny_buf;
		wsr->pollfd_arr_size = ny_size;
	}

	return true;
}

static prne_worker_sched_req_mem_func_t def_mem_func = { def_alloc_func, def_free_func, NULL };


bool prne_init_worker_sched_req (prne_worker_sched_req_t *wsr, prne_worker_sched_req_mem_func_t *in_mem_func) {
	prne_worker_sched_req_t ret;

	ret.pollfd_arr_size = 0;
	ret.pollfd_arr = NULL;
	ret.timeout.tv_sec = 0;
	ret.timeout.tv_nsec = 0;
	ret.mem_func = *(in_mem_func != NULL ? in_mem_func : &def_mem_func);
	ret.flags = PRNE_WORKER_SCHED_FLAG_NONE;
	ret.pollfd_ready = false;

	if (!ret.mem_func.alloc(&ret, 0)) {
		return false;
	}

	*wsr = ret;
	return true;
}
