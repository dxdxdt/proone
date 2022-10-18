/*
* Copyright (c) 2019-2022 David Timber <dxdt@dev.snart.me>
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*/
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

#include <pthsem.h>
#include <mbedtls/entropy.h>

#include "util_rt.h"
#include "util_ct.h"
#include "llist.h"
#include "pth.h"
#include "resolv.h"
#include "mbedtls.h"


static regex_t prmpt_regex, empty_line_regex;

static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context rnd;

bool main_flag = false;
pth_t pth_main;
prne_llist_t prm_list;
pth_mutex_t prm_lock = PTH_MUTEX_INIT;
pth_cond_t prm_cond = PTH_COND_INIT;
prne_pth_cv_t prm_cv = { &prm_lock, &prm_cond, false };

prne_resolv_t *resolv = NULL;
struct {
	bool parse_err;
	bool query_err;
	bool proc;
} exec_result;

static void proc_prompt_line (char *line, const size_t line_len) {
	static regmatch_t rm[3];

	if (regexec(&prmpt_regex, line, 3, rm, 0) == 0) {
		prne_resolv_prm_t *prm = (prne_resolv_prm_t*)prne_malloc(
			sizeof(prne_resolv_prm_t),
			1);
		char *verb, *obj;
		size_t verb_len, obj_len;
		bool has_prm = false;

		prne_dbgast(rm[1].rm_so >= 0 && rm[2].rm_so >= 0);
		prne_resolv_init_prm(prm);

		verb = line + rm[1].rm_so;
		verb_len = rm[1].rm_eo - rm[1].rm_so;
		prne_transcmem(verb, verb_len, prne_ctoupper);
		obj = line + rm[2].rm_so;
		obj_len = rm[2].rm_eo - rm[2].rm_so;
		obj[obj_len] = 0;

		if (strncmp(verb, "A", verb_len) == 0) {
			has_prm = prne_resolv_prm_gethostbyname(
				resolv,
				obj,
				PRNE_IPV_4,
				&prm_cv,
				prm);
		}
		else if (strncmp(verb, "AAAA", verb_len) == 0) {
			has_prm = prne_resolv_prm_gethostbyname(
				resolv,
				obj,
				PRNE_IPV_6,
				&prm_cv,
				prm);
		}
		else if (strncmp(verb, "TXT", verb_len) == 0) {
			has_prm = prne_resolv_prm_gettxtrec(
				resolv,
				obj,
				&prm_cv,
				prm);
		}
		else {
			abort();
		}

		if (has_prm) {
			prne_assert(prne_llist_append(
				&prm_list,
				(prne_llist_element_t)prm) != NULL);
		}
		else {
			exec_result.query_err = true;
			perror("* Queue failed");
			prne_resolv_free_prm(prm);
			prne_free(prm);
		}
	}
	else if (line_len > 0 &&
		regexec(&empty_line_regex, line, 0, NULL, 0) != 0)
	{
		exec_result.parse_err = true;
		fprintf(stderr, "* Line not recognised.\n");
	}
}

static void *stdin_wkr_entry (void *ctx) {
	while (main_flag) {
		static char line_buf[512];
		static size_t line_buf_cnt = 0;
		static bool missed_line = false;
		int read_len;

		read_len = pth_read(
			STDIN_FILENO,
			line_buf + line_buf_cnt,
			sizeof(line_buf) - line_buf_cnt);
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
					exec_result.parse_err = true;
					fprintf(stderr, "* Line too long!\n");
				}
				missed_line = true;
			}
		}
		else if (read_len == 0) {
			pth_raise(pth_main, SIGTERM);
			break;
		}
		else {
			break;
		}

		fflush(stderr);
	}

	return NULL;
}

static void *stdout_wkr_entry (void *ctx) {
	prne_resolv_prm_t *prm;
	prne_llist_entry_t *cur;
	bool output = false;

	while (main_flag || prm_list.size > 0) {
		prne_assert(pth_mutex_acquire(prm_cv.lock, FALSE, NULL));
		pth_cond_await(prm_cv.cond, prm_cv.lock, NULL);
		pth_mutex_release(prm_cv.lock);

		cur = prm_list.head;
		while (cur != NULL) {
			prm = (prne_resolv_prm_t*)cur->element;

			if (prm->fut != NULL && prm->fut->qr != PRNE_RESOLV_QR_NONE) {
				static char ntop_buf[INET6_ADDRSTRLEN];
				const char *qr_str, *status_str;
				size_t i;

				output = true;

				qr_str = prne_resolv_qr_tostr(prm->fut->qr);
				prne_assert(qr_str != NULL);
				status_str = NULL;
				if (prm->fut->qr == PRNE_RESOLV_QR_OK ||
					prm->fut->qr == PRNE_RESOLV_QR_STATUS)
				{
					exec_result.proc = true;
					status_str = prne_resolv_rcode_tostr(prm->fut->status);
				}
				else {
					exec_result.query_err = true;
				}
				if (status_str == NULL) {
					status_str = "";
				}
				printf("; qr: %7s, err: %3d, status: (%u)%s\n",
					qr_str, prm->fut->err, prm->fut->status, status_str);
				for (i = 0; i < prm->fut->rr_cnt; i += 1) {
					prne_resolv_rr_t *rr = prm->fut->rr + i;
					const char *type_str;

					type_str = prne_resolv_rrtype_tostr(rr->rr_type);
					if (type_str == NULL) {
						type_str = "";
					}

					printf(
						";\ttype: (%2u)%5s, ttl: %10u, len: %5u, name: %s\n",
						rr->rr_type,
						type_str,
						rr->rr_ttl,
						rr->rd_len,
						rr->name);
					switch (rr->rr_type) {
					case PRNE_RESOLV_RTYPE_A:
						printf(
							";\t\t%s\n",
							inet_ntop(
								AF_INET,
								rr->rd_data,
								ntop_buf,
								INET6_ADDRSTRLEN));
						break;
					case PRNE_RESOLV_RTYPE_AAAA:
						printf(
							";\t\t%s\n",
							inet_ntop(
								AF_INET6,
								rr->rd_data,
								ntop_buf,
								INET6_ADDRSTRLEN));
						break;
					case PRNE_RESOLV_RTYPE_TXT:
						if (isatty(STDOUT_FILENO) &&
							!prne_chkcmem(
								(const char *)rr->rd_data + 1,
								rr->rd_data[0],
								prne_cisprint))
						{
							printf(
								";\t\t* (binary data - "
								"unable to print on terminal)\n");
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

				prne_resolv_free_prm(prm);
				prne_free(prm);
				cur = prne_llist_erase(&prm_list, cur);
			}
			else {
				cur = cur->next;
			}
		}

		if (output) {
			fflush(stdout);
		}
	}

	return NULL;
}

int main (void) {
	prne_worker_t wkr_arr[3];
	sigset_t sigset;
	int caught;

	for (size_t i = 0; i < sizeof(wkr_arr)/sizeof(prne_worker_t); i += 1) {
		prne_init_worker(wkr_arr + i);
	}
	prne_assert(sigemptyset(&sigset) == 0);
	prne_assert(sigaddset(&sigset, SIGTERM) == 0);
	prne_assert(sigaddset(&sigset, SIGINT) == 0);

	prne_assert(pth_init() != 0);
	pth_main = pth_self();

	// org regex: (A|AAAA|TXT)\s+([a-z0-9\-\.]+)
	prne_assert(regcomp(
		&prmpt_regex,
		"(A|AAAA|TXT)\\s+([a-z0-9\\-\\.]+)",
		REG_ICASE | REG_EXTENDED) == 0);
	// org regex: (^[#;].*)|(^(\s+)?$)
	prne_assert(regcomp(
		&empty_line_regex,
		"(^[#;].*)|(^(\\s+)?$)",
		REG_NOSUB | REG_EXTENDED) == 0);
	prne_mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&rnd);
	prne_assert(mbedtls_ctr_drbg_seed(
		&rnd,
		mbedtls_entropy_func,
		&entropy,
		NULL,
		0) == 0);
	prne_init_llist(&prm_list);

	resolv = prne_alloc_resolv(
		&wkr_arr[0],
		&rnd,
		PRNE_RESOLV_DEF_IPV4_POOL,
		PRNE_RESOLV_DEF_IPV6_POOL);
	prne_assert(resolv != NULL);

	wkr_arr[1].entry = stdin_wkr_entry;
	wkr_arr[2].entry = stdout_wkr_entry;

	main_flag = true;
	for (size_t i = 0; i < sizeof(wkr_arr)/sizeof(prne_worker_t); i += 1) {
		wkr_arr[i].pth = pth_spawn(
			PTH_ATTR_DEFAULT,
			wkr_arr[i].entry,
			wkr_arr[i].ctx);
	}

	pth_sigmask(SIG_BLOCK, &sigset, NULL);
	pth_sigwait(&sigset, &caught);
	pth_sigmask(SIG_UNBLOCK, &sigset, NULL);

	main_flag = false;
	close(STDIN_FILENO);
	prne_pth_cv_notify(prm_cv.lock, prm_cv.cond, true);
	for (size_t i = 0; i < sizeof(wkr_arr)/sizeof(prne_worker_t); i += 1) {
		prne_fin_worker(wkr_arr + i);
	}
	for (size_t i = 0; i < sizeof(wkr_arr)/sizeof(prne_worker_t); i += 1) {
		assert(pth_join(wkr_arr[i].pth, NULL));
		wkr_arr[i].pth = NULL;
		prne_free_worker(wkr_arr + i);
	}

	mbedtls_ctr_drbg_free(&rnd);
	mbedtls_entropy_free(&entropy);
	regfree(&prmpt_regex);
	regfree(&empty_line_regex);

	for (prne_llist_entry_t *cur = prm_list.head;
		cur != NULL;
		cur = cur->next)
	{
		prne_resolv_prm_t *prm = (prne_resolv_prm_t*)cur->element;
		prne_resolv_free_prm(prm);
		prne_free(prm);
	}
	prne_free_llist(&prm_list);

	pth_kill();

	if (exec_result.proc) {
		if (exec_result.parse_err || exec_result.query_err) {
			return 3;
		}
		return 0;
	}
	if (exec_result.parse_err) {
		return 2;
	}
	return 1;
}
