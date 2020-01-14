#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>

#include <unistd.h>
#include <signal.h>
#include <regex.h>
#include <fcntl.h>
#include <sys/types.h>
#include <arpa/inet.h>

#include <mbedtls/entropy.h>

#include "util_rt.h"
#include "util_ct.h"
#include "llist.h"
#include "resolv_worker.h"


static int caught_signal = 0;
static int int_pipe[2] = { -1, -1 };
static regex_t prmpt_regex, empty_line_regex;

static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context rnd;
static prne_wkr_sched_req_t wsr;

static prne_wkr_pollfd_slot_pt stdin_pfd = NULL;
typedef struct {
	prne_resolv_prm_t prm;
	prne_wkr_pollfd_slot_pt slot;
} prm_tuple_t;
prne_llist_t prm_list;

prne_resolv_wkr_ctx_t resolv = NULL;

static void upperstr (char *str, const size_t n) {
	for (size_t i = 0; i < n; i += 1) {
		if ('a' <= str[i] && str[i] <= 'z') {
			str[i] -= 'a' - 'A';
		}
	}
}

static bool printable_str (const char *str, const size_t n) {
	for (size_t i = 0; i < n; i += 1) {
		if (!isprint(str[i])) {
			return false;
		}
	}
	return true;
} 

static void proc_prompt_line (char *line, const size_t line_len) {
	static regmatch_t rm[3];
	
	if (regexec(&prmpt_regex, line, 3, rm, 0) == 0) {
		char *verb, *obj;
		size_t verb_len, obj_len;
		prm_tuple_t tpl;
		bool has_prm = false;

		assert(rm[1].rm_so >= 0 && rm[2].rm_so >= 0);

		verb = line + rm[1].rm_so;
		verb_len = rm[1].rm_eo - rm[1].rm_so;
		upperstr(verb, verb_len);
		obj = line + rm[2].rm_so;
		obj_len = rm[2].rm_eo - rm[2].rm_so;
		obj[obj_len] = 0;

		if (strncmp(verb, "A", verb_len) == 0) {
			has_prm = prne_resolv_prm_gethostbyname(resolv, obj, PRNE_IPV_4, &tpl.prm, NULL);
		}
		else if (strncmp(verb, "AAAA", verb_len) == 0) {
			has_prm = prne_resolv_prm_gethostbyname(resolv, obj, PRNE_IPV_6, &tpl.prm, NULL);
		}
		else if (strncmp(verb, "TXT", verb_len) == 0) {
			has_prm = prne_resolv_prm_gettxtrec(resolv, obj, &tpl.prm, NULL);
		}
		else {
			abort();
		}

		if (has_prm) {
			prm_tuple_t *e;
			
			tpl.slot = prne_alloc_wkr_pollfd_slot(&wsr);
			tpl.slot->pfd.fd = tpl.prm.evtfd;
			tpl.slot->pfd.events = POLLIN;
			e = prne_malloc(sizeof(prm_tuple_t), 1);
			memcpy(e, &tpl, sizeof(prm_tuple_t));
			
			assert(prne_llist_append(&prm_list, e) != NULL);
		}
		else {
			perror("* Queue failed");
		}
	}
	else if (line_len > 0 && regexec(&empty_line_regex, line, 0, NULL, 0) != 0) {
		fprintf(stderr, "* Line not recognised.\n");
	}

	fprintf(stderr, "> ");
	fflush(stderr);
}

static void main_wkr_free (void *ctx) {
	prne_llist_entry_t *cur;

	prne_free_wkr_pollfd_slot(stdin_pfd);
	stdin_pfd = NULL;

	cur = prm_list.head;
	while (cur != NULL) {
		prm_tuple_t *tpl = (prm_tuple_t*)cur->element;
		prne_free_wkr_pollfd_slot(tpl->slot);
		prne_resolv_free_prm(&tpl->prm);
		prne_free(tpl);
		cur = cur->next;
	}

	prne_free_llist(&prm_list);
}

static void main_wkr_fin (void *ctx) {
	prne_free_wkr_pollfd_slot(stdin_pfd);
	stdin_pfd = NULL;
}

static void main_wkr_work (void *ctx, const prne_wkr_tick_info_t *sched_info) {
	if (stdin_pfd != NULL) {
		if (stdin_pfd->pfd.revents & POLLIN) {
			static char line_buf[512]; 
			static size_t line_buf_cnt = 0;
			static bool missed_line = false;
			int read_len;

			read_len = read(STDIN_FILENO, line_buf + line_buf_cnt, sizeof(line_buf) - line_buf_cnt);
			if (read_len > 0) {
				char *line_buf_end, *line, *line_end;
				size_t line_len, consumed = 0;

				line_buf_cnt += (size_t)read_len;
				line_buf_end = line_buf + line_buf_cnt;
				line = line_buf;
				while (line < line_buf_end) {
					line_end = prne_strnchr(line, '\n', line_buf_end - line);
					if (line_end == NULL) {
						break;
					}

					if (missed_line) {
						missed_line = false;
					}
					else {
						*line_end = 0;
						line_len = line_end - line;
						proc_prompt_line(line, line_len);
					}
					consumed += line_end - line + 1;
					line = line_end + 1;
				}

				if (consumed > 0) {
					memmove(line_buf, line, line_buf_cnt - consumed);
					line_buf_cnt -= consumed;
				}
				else {
					line_buf_cnt = 0;	
					if (!missed_line) {
						fprintf(stderr, "* Line too long!\n");
					}
					missed_line = true;
				}
			}
			else {
				kill(getpid(), SIGTERM);
				return;
			}
		}
		else if (stdin_pfd->pfd.revents) {
			kill(getpid(), SIGTERM);
			return;
		}
	}
	if (prm_list.size > 0) {
		prm_tuple_t *tpl;
		prne_llist_entry_t *cur;
		bool output = false;

		cur = prm_list.head;
		while (cur != NULL) {
			tpl = (prm_tuple_t*)cur->element;
			
			assert((tpl->slot->pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) == 0);

			if (tpl->slot->pfd.revents) {
				static char ntop_buf[INET6_ADDRSTRLEN];
				const char *qr_str, *status_str;
				size_t i;

				output = true;
				fprintf(stderr, "\n");

				qr_str = prne_resolv_qr_tostr(tpl->prm.fut->qr);
				assert(qr_str != NULL);
				status_str = NULL;
				if (tpl->prm.fut->qr == PRNE_RESOLV_QR_OK || tpl->prm.fut->qr == PRNE_RESOLV_QR_STATUS) {
					status_str = prne_resolv_rcode_tostr(tpl->prm.fut->status);
				}
				if (status_str == NULL) {
					status_str = "";
				}
				printf("; qr: %7s, err: %3d, status: (%u)%s\n",
					qr_str, tpl->prm.fut->err, tpl->prm.fut->status, status_str);
				for (i = 0; i < tpl->prm.fut->rr_cnt; i += 1) {
					prne_resolv_rr_t *rr = tpl->prm.fut->rr + i;
					const char *type_str;

					type_str = prne_resolv_rrtype_tostr(rr->rr_type);
					if (type_str == NULL) {
						type_str = "";
					}

					printf(";\ttype: (%2u)%5s, ttl: %10u, len: %5u, name: %s\n",
						rr->rr_type, type_str, rr->rr_ttl, rr->rd_len, rr->name);
					switch (rr->rr_type) {
					case PRNE_RESOLV_RTYPE_A: printf(";\t\t%s\n", inet_ntop(AF_INET, rr->rd_data, ntop_buf, INET6_ADDRSTRLEN)); break;
					case PRNE_RESOLV_RTYPE_AAAA: printf(";\t\t%s\n", inet_ntop(AF_INET6, rr->rd_data, ntop_buf, INET6_ADDRSTRLEN)); break;
					case PRNE_RESOLV_RTYPE_TXT:
						if (isatty(STDOUT_FILENO) && !printable_str((const char *)rr->rd_data + 1, rr->rd_data[0])) {
							printf(";\t\t* (binary data - unable to print on terminal)\n");
						}
						else {
							uint8_t tmp = rr->rd_data[0];

							memmove(rr->rd_data, rr->rd_data + 1, tmp);
							rr->rd_data[tmp] = 0;
							printf(";\t\t%s\n", rr->rd_data);
							memmove(rr->rd_data + 1, rr->rd_data, tmp);
							rr->rd_data[0] = tmp;
						}
						break;
					default: abort();
					}
				}
				printf(";\n");

				prne_resolv_free_prm(&tpl->prm);
				prne_free_wkr_pollfd_slot(tpl->slot);
				prne_free(tpl);
				cur = prne_llist_erase(&prm_list, cur);
			}
			else {
				cur = cur->next;
			}
		}

		if (output) {
			fprintf(stderr, "> ");
			fflush(stdout);
			fflush(stderr);
		}
	}
}

static bool main_wkr_has_finalised (void *ctx) {
	return stdin_pfd == NULL && prm_list.size == 0;
}

static void init_main_wkr (prne_worker_t *wkr) {
	wkr->ctx = NULL;
	wkr->free = main_wkr_free;
	wkr->fin = main_wkr_fin;
	wkr->work = main_wkr_work;
	wkr->has_finalised = main_wkr_has_finalised;

	stdin_pfd = prne_alloc_wkr_pollfd_slot(&wsr);
	stdin_pfd->pfd.fd = STDIN_FILENO;
	stdin_pfd->pfd.events = POLLIN;

	prne_init_llist(&prm_list);
}

static void handle_interrupt (const int sn) {
	caught_signal = sn;
	write(int_pipe[1], &sn, 1);
}

static void install_signal_handlers (void) {
	struct sigaction sa;

	if (pipe(int_pipe) == 0) {
        prne_set_pipe_size(int_pipe[0], 1);
        prne_ok_or_die(fcntl(int_pipe[0], F_SETFL, O_NONBLOCK));
        prne_ok_or_die(fcntl(int_pipe[1], F_SETFL, O_NONBLOCK));
        prne_ok_or_die(fcntl(int_pipe[0], F_SETFD, FD_CLOEXEC));
        prne_ok_or_die(fcntl(int_pipe[1], F_SETFD, FD_CLOEXEC));
    }

	memzero(&sa, sizeof(struct sigaction));
	sa.sa_flags = SA_RESETHAND;
	sa.sa_handler = handle_interrupt;
	
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
}

int main (void) {
	static prne_worker_t wkr_arr[2];
	static size_t i;
	static prne_wkr_tick_info_t ti;
	static int poll_ret;
	static bool finalising = false;
	static prne_wkr_pollfd_slot_pt int_pfd = NULL;

	/* org regex: (A|AAAA|TXT)\s+([a-z0-9\-\.]+) */
	assert(regcomp(&prmpt_regex, "(A|AAAA|TXT)\\s+([a-z0-9\\-\\.]+)", REG_ICASE | REG_EXTENDED) == 0);
	/* org regex: ^\s+$ */
	assert(regcomp(&empty_line_regex, "^\\s+$", REG_NOSUB | REG_EXTENDED) == 0);
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&rnd);
	assert(mbedtls_ctr_drbg_seed(&rnd, mbedtls_entropy_func, &entropy, (const uint8_t*)PRNE_BUILD_ENTROPY, sizeof(PRNE_BUILD_ENTROPY) - 1) == 0);
	prne_init_wkr_sched_req(&wsr);
	prne_init_wkr_tick_info(&ti);

	prne_ok_or_die(fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK));
	install_signal_handlers();
	int_pfd = prne_alloc_wkr_pollfd_slot(&wsr);
	int_pfd->pfd.fd = int_pipe[0];
	int_pfd->pfd.events = POLLIN;

	init_main_wkr(&wkr_arr[0]);
	wkr_arr[0].id = 0;
	resolv = prne_alloc_resolv_worker(&wkr_arr[1], &wsr, &rnd);
	assert(resolv != NULL);

	fprintf(stderr, "> ");
	fflush(stderr);

	prne_wkr_tick_info_set_start(&ti);
	while (true) {
		static bool worked;

		if (caught_signal && !finalising) {
			int_pfd->pfd.fd = -1;
			
			for (i = 0; i < sizeof(wkr_arr) / sizeof(prne_worker_t); i += 1) {
				if (wkr_arr[i].has_finalised(wkr_arr[i].ctx)) {
					continue;
				}
				wkr_arr[i].fin(wkr_arr[i].ctx);
			}
			finalising = true;
		}

		worked = false;
		for (i = 0; i < sizeof(wkr_arr) / sizeof(prne_worker_t); i += 1) {
			if (wkr_arr[i].has_finalised(wkr_arr[i].ctx)) {
				if (!finalising) {
					fprintf(stderr, "** worker #%zu finalised!\n", wkr_arr[i].id);
					abort();
				}
			}
			else {
				wkr_arr[i].work(wkr_arr[i].ctx, &ti);
				worked = true;
			}
		}
		if (!worked) {
			break;
		}

		poll_ret = -1;
		if (prne_wkr_sched_req_prep_poll(&wsr)) {
			prne_wkr_sched_req_do_poll(&wsr, &poll_ret);
		}
		prne_wkr_tick_info_set_tick(&ti);
		prne_wkr_sched_req_refl_poll(&wsr, poll_ret, ti.tick_diff);
	}

	for (i = 0; i < sizeof(wkr_arr) / sizeof(prne_worker_t); i += 1) {
		wkr_arr[i].free(wkr_arr[i].ctx);
	}
	prne_free_wkr_pollfd_slot(int_pfd);
	prne_free_wkr_sched_req(&wsr);
	prne_free_wkr_tick_info(&ti);

	mbedtls_ctr_drbg_free(&rnd);
	mbedtls_entropy_free(&entropy);
	regfree(&prmpt_regex);
	regfree(&empty_line_regex);

	fprintf(stderr, "\n");

	return 0;
}
