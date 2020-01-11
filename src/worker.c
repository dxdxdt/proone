#include "worker.h"
#include "util_rt.h"

#include <string.h>
#include <time.h>
#include <assert.h>
#include <errno.h>


void prne_init_wkr_sched_req (prne_wkr_sched_req_t *r) {
	r->pfd_arr = NULL;
	r->pfd_arr_size = 0;
	prne_init_llist(&r->tos_list);	
	prne_init_llist(&r->pfd_list);	
	r->timeout_active = false;
}

void prne_free_wkr_sched_req (prne_wkr_sched_req_t *r) {
	prne_llist_entry_t *cur;
	prne_wkr_timeout_slot_pt to_slot;
	prne_wkr_pollfd_slot_pt pfd_slot;

	if (r == NULL) {
		return;
	}

	cur = r->tos_list.head;
	while (cur != NULL) {
		to_slot = (prne_wkr_timeout_slot_pt)cur->element;
		to_slot->parent.ent = NULL;
		to_slot->parent.wsr = NULL;
		cur = cur->next;
	}
	cur = r->pfd_list.head;
	while (cur != NULL) {
		pfd_slot = (prne_wkr_pollfd_slot_pt)cur->element;
		pfd_slot->parent.ent = NULL;
		pfd_slot->parent.wsr = NULL;
		cur = cur->next;
	}

	prne_free(r->pfd_arr);
	prne_free_llist(&r->tos_list);	
	prne_free_llist(&r->pfd_list);	
	r->pfd_arr = NULL;
	r->pfd_arr_size = 0;
	r->timeout_active = false;
}

bool prne_wkr_sched_req_prep_poll (prne_wkr_sched_req_t *r) {
	prne_llist_entry_t *cur;
	prne_wkr_timeout_slot_pt to_slot;
	prne_wkr_pollfd_slot_pt pfd_slot;
	size_t i = 0;

	cur = r->pfd_list.head;
	while (cur != NULL) {
		pfd_slot = (prne_wkr_pollfd_slot_pt)cur->element;
		if (pfd_slot->pfd.fd >= 0) {
			i += 1;
		}
		cur = cur->next;
	}
	if (i > 0) {
		void *ny_mem;

		ny_mem = prne_realloc(r->pfd_arr, sizeof(struct pollfd), i);
		if (ny_mem != NULL) {
			r->pfd_arr = (struct pollfd*)ny_mem;
			r->pfd_arr_size = i;

			i = 0;
			cur = r->pfd_list.head;
			while (cur != NULL) {
				pfd_slot = (prne_wkr_pollfd_slot_pt)cur->element;
				if (pfd_slot->pfd.fd >= 0) {
					pfd_slot->pfd.revents = 0;
					r->pfd_arr[i].fd = pfd_slot->pfd.fd;
					r->pfd_arr[i].events = pfd_slot->pfd.events;
					i += 1;
				}
				cur = cur->next;
			}
		}
		else {
			return false;
		}
	}
	else {
		prne_free(r->pfd_arr);
		r->pfd_arr = NULL;
		r->pfd_arr_size = 0;
	}

	r->timeout_active = false;
	cur = r->tos_list.head;
	while (cur != NULL) {
		to_slot = (prne_wkr_timeout_slot_pt)cur->element;
		if (to_slot->active) {
			if (r->timeout_active) {
				r->timeout = prne_min_timespec(r->timeout, to_slot->dur);
			}
			else {
				r->timeout = to_slot->dur;
				r->timeout_active = true;
			}
		}
		cur = cur->next;
	}

	return true;
}

void prne_wkr_sched_req_refl_poll (prne_wkr_sched_req_t *r, const int poll_ret, const struct timespec elapsed) {
	prne_llist_entry_t *cur;

	if (r->timeout_active) {
		prne_wkr_timeout_slot_pt to_slot;

		cur = r->tos_list.head;
		while (cur != NULL) {
			to_slot = (prne_wkr_timeout_slot_pt)cur->element;
			if (to_slot->active) {
				if (prne_cmp_timespec(to_slot->dur, elapsed) > 0) {
					to_slot->dur = prne_sub_timespec(to_slot->dur, elapsed);
					to_slot->reached = false;
				}
				else {
					to_slot->dur.tv_sec = 0;
					to_slot->dur.tv_nsec = 0;					
					to_slot->reached = true;
				}
			}

			cur = cur->next;
		}
	}

	if (poll_ret > 0) {
		prne_wkr_pollfd_slot_pt pfd_slot;
		size_t i = 0, ret_evts = 0;

		cur = r->pfd_list.head;
		while (cur != NULL) {
			pfd_slot = (prne_wkr_pollfd_slot_pt)cur->element;
			if (pfd_slot->pfd.fd >= 0) {
				assert(pfd_slot->pfd.fd == r->pfd_arr[i].fd);

				pfd_slot->pfd.revents = r->pfd_arr[i].revents;
				if (pfd_slot->pfd.revents) {
					ret_evts += 1;
				}
				if (ret_evts >= (size_t)poll_ret) {
					break;
				}
				i += 1;
			}
			cur = cur->next;
		}
	} 
}

bool prne_wkr_sched_req_do_poll (prne_wkr_sched_req_t *r, int *poll_ret) {
	bool ret = false;

	*poll_ret = 0;
	if (r->pfd_arr_size > 0) {
		*poll_ret = ppoll(r->pfd_arr, r->pfd_arr_size, r->timeout_active ? &r->timeout : NULL, NULL);
		if (*poll_ret < 0) {
			switch (errno) {
			case EINTR:
			case ENOMEM:
				break;
			default:
				abort();
			}
		}
		else {
			ret = true;
		}
	}
	else if (r->timeout_active) {
		if (nanosleep(&r->timeout, NULL) < 0 && errno != EINTR) {
			abort();
		}
		ret = true;
	}
	else {
		ret = true;
	}

	return ret;
}

prne_wkr_timeout_slot_pt prne_alloc_wkr_timeout_slot (prne_wkr_sched_req_t *r) {
	prne_wkr_timeout_slot_pt ret = NULL;
	prne_llist_entry_t *ent = NULL;

	ret = prne_malloc(sizeof(struct prne_wkr_timeout_slot), 1);
	if (ret == NULL) {
		goto ERR;
	}
	ent = prne_llist_append(&r->tos_list, ret);
	if (ent == NULL) {
		goto ERR;
	}

	ret->parent.ent = ent;
	ret->parent.wsr = r;
	ret->active = false;
	ret->reached = false;
	return ret;
ERR:
	prne_free(ret);
	prne_llist_erase(&r->tos_list, ent);

	return NULL;
}

void prne_free_wkr_timeout_slot (prne_wkr_timeout_slot_pt s) {
	if (s == NULL) {
		return;
	}

	if (s->parent.wsr != NULL) {
		prne_llist_erase(&s->parent.wsr->tos_list, s->parent.ent);
	}
	prne_free(s);
}

prne_wkr_pollfd_slot_pt prne_alloc_wkr_pollfd_slot (prne_wkr_sched_req_t *r) {
	prne_wkr_pollfd_slot_pt ret = NULL;
	prne_llist_entry_t *ent = NULL;

	ret = prne_malloc(sizeof(struct prne_wkr_pollfd_slot), 1);
	if (ret == NULL) {
		goto ERR;
	}
	ent = prne_llist_append(&r->pfd_list, ret);
	if (ent == NULL) {
		goto ERR;
	}

	ret->parent.ent = ent;
	ret->parent.wsr = r;
	ret->pfd.fd = -1;
	ret->pfd.events = 0;
	ret->pfd.revents = 0;
	return ret;
ERR:
	prne_free(ret);
	prne_llist_erase(&r->pfd_list, ent);

	return NULL;
}

void prne_free_wkr_pollfd_slot (prne_wkr_pollfd_slot_pt s) {
	if (s == NULL) {
		return;
	}

	if (s->parent.wsr != NULL) {
		prne_llist_erase(&s->parent.wsr->pfd_list, s->parent.ent);
	}
	prne_free(s);
}

void prne_init_wkr_tick_info (prne_wkr_tick_info_t *ti) {
	memset(ti, 0, sizeof(prne_wkr_tick_info_t));
}

void prne_free_wkr_tick_info (prne_wkr_tick_info_t *ti) {
	// left for future code
}

void prne_wkr_tick_info_set_start (prne_wkr_tick_info_t *ti) {
	prne_ok_or_die(clock_gettime(CLOCK_MONOTONIC, &ti->this_tick));
	ti->last_tick = ti->this_tick;
	ti->tick_diff.tv_sec = 0;
	ti->tick_diff.tv_nsec = 0;
	ti->real_tick_diff = 0.0;
}

void prne_wkr_tick_info_set_tick (prne_wkr_tick_info_t *ti) {
	ti->last_tick = ti->this_tick;
	prne_ok_or_die(clock_gettime(CLOCK_MONOTONIC, &ti->this_tick));
	ti->tick_diff = prne_sub_timespec(ti->this_tick, ti->last_tick);
	ti->real_tick_diff = prne_real_timespec(ti->tick_diff);
}
