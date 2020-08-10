#include "resolv_worker.h"
#include "util_rt.h"
#include "util_ct.h"
#include "llist.h"
#include "imap.h"
#include "iset.h"
#include "protocol.h"
#include "mbedtls.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <mbedtls/ssl.h>
#include <mbedtls/ctr_drbg.h>

_Static_assert(sizeof(uint_fast16_t) <= sizeof(prne_imap_key_type_t), "prne_imap cannot contain uint_fast16_t");

#define OK_OR_ERR(v) if (v < 0) { goto ERR; }

typedef enum {
	RESOLV_WKR_STATE_OK,
	RESOLV_WKR_STATE_FIN_CALLED,
	RESOLV_WKR_STATE_FINALISED,
} resolv_wkr_state_t;

typedef enum {
	RESOLV_CTX_STATE_NONE,
	RESOLV_CTX_STATE_CONN,
	RESOLV_CTX_STATE_HNDSHK,
	RESOLV_CTX_STATE_READY,
	RESOLV_CTX_STATE_CLOSING,
} resolv_ctx_state_t;

typedef struct {
	prne_net_endpoint_t *arr;
	size_t cnt;
	size_t ptr;
} resolv_dnssrv_pool_t;

typedef struct {
	prne_resolv_wkr_ctx_t wkr;
	prne_llist_entry_t *qlist_ent;
	char *qname;
	size_t qname_size;
	int evtfd[2];
	prne_wkr_timeout_slot_pt to_slot;
	uint_fast16_t qid; // 0 reserved
	prne_resolv_fut_t fut;
	prne_ipv_t ipv;
	prne_resolv_query_type_t type;
} query_entry_t;

struct prne_resolv_wkr_ctx {
	int dnss_fd[2];
	int evtfd[2];
	size_t read_cnt_len;
	size_t write_cnt_len;
	prne_wkr_sched_req_t *wsr;
	prne_wkr_timeout_slot_pt sckop_to_slot;
	prne_wkr_timeout_slot_pt err_to_slot;
	prne_wkr_pollfd_slot_pt evt_pfd_slot;
	prne_wkr_pollfd_slot_pt sck_pfd_slot[2];
	int act_dns_fd;
	resolv_dnssrv_pool_t dnssrv_4, dnssrv_6;
	resolv_ctx_state_t ctx_state;
	resolv_wkr_state_t wkr_state;
	uint8_t write_buf[514];
	uint8_t read_buf[514];
	prne_llist_t qlist;
	prne_imap_t qid_map; // uint16_t:q_ent(could be null)
	struct {
		mbedtls_ssl_config conf;
		mbedtls_ssl_context ctx;
		mbedtls_ctr_drbg_context *ctr_drbg;
	} ssl;
};

#define DECL_CTX_PTR(p) prne_resolv_wkr_ctx_t ctx = (prne_resolv_wkr_ctx_t)p

static const struct timespec RESOLV_RSRC_ERR_PAUSE = { 1, 0 }; // 1s
static const struct timespec RESOLV_CONN_ERR_PAUSE = { 0, 100000000 }; // 100ms
static const struct timespec RESOLV_QUERY_TIMEOUT = { 15, 0 }; // 15s
static const struct timespec RESOLV_SCK_OP_TIMEOUT = { 10, 0 }; // 10s
static const struct timespec RESOLV_SCK_IDLE_TIMEOUT = { 15, 0 }; // 15s
static const struct timespec RESOLV_SCK_CLOSE_TIMEOUT = { 1, 0 }; // 1s
static const size_t RESOLV_PIPELINE_SIZE = 4; 

static bool resolv_wkr_has_finalised (void *p) {
	DECL_CTX_PTR(p);
	return ctx->wkr_state == RESOLV_WKR_STATE_FINALISED;
}

static int resolv_set_cmn_fd_opt (const int fd) {
	return fcntl(fd, F_SETFL, O_NONBLOCK) == 0 ? fcntl(fd, F_SETFD, FD_CLOEXEC) : -1;
}

static void resolv_free_q_ent (query_entry_t *q_ent) {
	if (q_ent == NULL) {
		return;
	}

	prne_free(q_ent->qname);
	prne_free_resolv_fut(&q_ent->fut);
	prne_close(q_ent->evtfd[0]);
	prne_close(q_ent->evtfd[1]);
	prne_free_wkr_timeout_slot(q_ent->to_slot);

	prne_free(q_ent);
}

static bool resolv_gen_qname (const char *name, char **out, size_t *out_size) {
	size_t len = prne_nstrlen(name);
	char *ptr = (char*)name, *delim;
	char *end = ptr + len;
	size_t label_size;
	char *ret_ptr;
	size_t ret_size;

	if (len == 0) {
		errno = EINVAL;
		return false;
	}
	if (name[len - 1] != '.') {
		len += 1;
	}
	if (len > 255) {
		errno = EINVAL;
		return false;
	}
	for (; *name != 0; name += 1) {
		if (((uint_fast8_t)*name & 0xC0) == 0xC0) {
			errno = EINVAL;
			return false;
		}
	}

	ret_ptr = prne_alloc_str(len);
	if (ret_ptr == NULL) {
		return false;
	}

	ret_size = 0;
	while (ptr < end) {
		delim = strchr(ptr, '.');
		if (delim == NULL) {
			delim = strchr(ptr, 0);
		}

		label_size = delim - ptr;
		if (label_size == 0 || label_size > 63) {
			errno = EINVAL;
			goto ERR;
		}

		ret_ptr[ret_size] = (uint8_t)label_size;
		memcpy(ret_ptr + ret_size + 1, ptr, label_size);
		ret_size += 1 + label_size;
		ptr = delim + 1;
	}
	ret_ptr[ret_size] = 0;
	ret_size += 1;

	*out = prne_realloc(ret_ptr, 1, ret_size);
	if (*out == NULL) {
		*out = ret_ptr;
	}
	*out_size = ret_size;

	return true;
ERR:
	prne_free(ret_ptr);
	return false;
}

char *resolv_qname_tostr (const char *qname) {
	char *ret, *p, *end;
	const size_t qname_size = strlen(qname) + 1;
	size_t label_len;

	ret = p = (char*)prne_malloc(1, qname_size);
	if (p == NULL) {
		return NULL;
	}
	memcpy(p, qname, qname_size);
	end = p + qname_size;

	while (p < end) {
		label_len = *p;
		if (label_len == 0) {
			break;
		}
		else if (p + label_len > end) {
			goto ERR;
		}

		memmove(p, p + 1, label_len);
		p[label_len] = '.';
		p += label_len + 1;
	}

	return ret;
ERR:
	prne_free(ret);
	return NULL;
}

static bool resolv_qq (prne_resolv_wkr_ctx_t wkr, const char *name, prne_resolv_prm_t *out, const struct timespec *timeout, query_entry_t **ny_q_ent) {
	query_entry_t *q_ent = NULL;

	if (resolv_wkr_has_finalised(wkr)) {
		errno = ECANCELED;
		return false;
	}

	q_ent = (query_entry_t*)prne_malloc(sizeof(query_entry_t), 1);
	if (q_ent == NULL) {
		goto ERR;
	}
	q_ent->wkr = wkr;
	q_ent->qlist_ent = NULL;
	q_ent->qname = NULL;
	q_ent->qname_size = 0;
	q_ent->evtfd[0] = q_ent->evtfd[1] = -1;
	q_ent->to_slot = NULL;
	q_ent->qid = 0;
	q_ent->ipv = PRNE_IPV_NONE;
	prne_init_resolv_fut(&q_ent->fut);

	if (!resolv_gen_qname(name, &q_ent->qname, &q_ent->qname_size)) {
		goto ERR;
	}

	q_ent->qlist_ent = prne_llist_append(&wkr->qlist, q_ent);
	if (q_ent->qlist_ent == NULL) {
		goto ERR;
	}

	OK_OR_ERR(pipe(q_ent->evtfd));
	prne_set_pipe_size(q_ent->evtfd[0], 1);
	OK_OR_ERR(resolv_set_cmn_fd_opt(q_ent->evtfd[0]));
	OK_OR_ERR(resolv_set_cmn_fd_opt(q_ent->evtfd[1]));

	if (write(wkr->evtfd[1], &q_ent, 1) < 0) {
		prne_die_not_nonblock_err();
	}

	q_ent->to_slot = prne_alloc_wkr_timeout_slot(wkr->wsr);
	if (q_ent == NULL) {
		goto ERR;
	}
	q_ent->to_slot->active = true;
	q_ent->to_slot->dur = RESOLV_QUERY_TIMEOUT;

	out->ctx = q_ent;
	out->fut = &q_ent->fut;
	out->evtfd = q_ent->evtfd[0];
	*ny_q_ent = q_ent;

	return true;
ERR:
	if (q_ent != NULL) {
		prne_llist_erase(&wkr->qlist, q_ent->qlist_ent);
		prne_free(q_ent->qname);
		prne_close(q_ent->evtfd[0]);
		prne_close(q_ent->evtfd[1]);

		prne_free(q_ent);
	}

	return false;
}

static void resolv_disown_qent (query_entry_t *qent) {
	uint8_t rubbish = 0;

	prne_free_wkr_timeout_slot(qent->to_slot);
	qent->to_slot = NULL;
	qent->wkr = NULL;
	qent->qlist_ent = NULL;
	qent->qid = 0;

	if (write(qent->evtfd[1], &rubbish, 1) < 0) {
		prne_die_not_nonblock_err();
	}
}

#if 0
static void resolv_disown_all_qent (prne_resolv_wkr_ctx_t ctx) {
	query_entry_t *qent;
	prne_llist_entry_t *cur;
	size_t i;

	cur = ctx->qlist.head;
	while (cur != NULL) {
		qent = (query_entry_t*)cur->element;
		qent->fut.qr = PRNE_RESOLV_QR_FIN;
		resolv_disown_qent(qent);
		cur = cur->next;
	}

	for (i = 0; i < ctx->qid_map.size; i += 1) {
		qent = (query_entry_t*)ctx->qid_map.tbl[i].val;
		qent->fut.qr = PRNE_RESOLV_QR_FIN;
		resolv_disown_qent(qent);
	}

	prne_llist_clear(&ctx->qlist);
	prne_imap_clear(&ctx->qid_map);
}
#endif

static size_t resolv_next_pool_ptr (prne_resolv_wkr_ctx_t ctx, const size_t cnt) {
	size_t ret = 0;

	if (mbedtls_ctr_drbg_random(ctx->ssl.ctr_drbg, (unsigned char*)&ret, sizeof(size_t)) != 0) {
		abort();
	}
	return ret % cnt;
}

static uint16_t resolv_next_qid (prne_resolv_wkr_ctx_t ctx) {
	uint16_t i, ret;

	for (i = 0; i < UINT16_MAX; i += 1) {
		if (mbedtls_ctr_drbg_random(ctx->ssl.ctr_drbg, (unsigned char*)&ret, sizeof(uint16_t)) != 0) {
			abort();
		}
		ret = (ret % UINT16_MAX) + 1;
		if (prne_imap_lookup(&ctx->qid_map, ret) == NULL) {
			return ret;
		}
	}

	return 0;
}

static void resolv_close_sck (prne_resolv_wkr_ctx_t ctx, const struct timespec *pause, bool change_srvr) {
	size_t i;
	query_entry_t *qent;
	prne_llist_entry_t *lent;

	// ctx->qid_map -> ctx->qlist
	for (i = 0; i < ctx->qid_map.size; i += 1) {
		qent = (query_entry_t*)ctx->qid_map.tbl[i].val;
		if (qent == NULL) {
			continue;
		}

		lent = prne_llist_append(&ctx->qlist, qent);
		if (lent == NULL) {
			qent->fut.qr = PRNE_RESOLV_QR_ERR;
			qent->fut.err = errno;
			resolv_disown_qent(qent);
		}
		else {
			qent->qid = 0;
			qent->qlist_ent = lent;
		}
	}
	prne_imap_clear(&ctx->qid_map);

	prne_shutdown(ctx->dnss_fd[0], SHUT_RDWR);
	prne_shutdown(ctx->dnss_fd[1], SHUT_RDWR);
	prne_shutdown(ctx->act_dns_fd, SHUT_RDWR);
	prne_close(ctx->dnss_fd[0]);
	prne_close(ctx->dnss_fd[1]);
	prne_close(ctx->act_dns_fd);
	ctx->dnss_fd[0] = ctx->dnss_fd[1] = ctx->act_dns_fd = -1;
	ctx->read_cnt_len = 0;
	ctx->write_cnt_len = 0;
	ctx->sckop_to_slot->active = false;
	ctx->sck_pfd_slot[0]->pfd.fd = ctx->sck_pfd_slot[1]->pfd.fd = -1;
	ctx->ctx_state = RESOLV_CTX_STATE_NONE;
	mbedtls_ssl_free(&ctx->ssl.ctx);
	mbedtls_ssl_init(&ctx->ssl.ctx);

	if (pause != NULL) {
		ctx->err_to_slot->active = true;
		ctx->err_to_slot->dur = *pause;
	}
	if (change_srvr) {
		ctx->dnssrv_4.ptr = resolv_next_pool_ptr(ctx, ctx->dnssrv_4.cnt);
		ctx->dnssrv_6.ptr = resolv_next_pool_ptr(ctx, ctx->dnssrv_6.cnt);
	}
}

static bool resolv_ensure_conn (prne_resolv_wkr_ctx_t ctx) {
	size_t i;

	switch (ctx->ctx_state) {
	case RESOLV_CTX_STATE_NONE: {
		int optval = 1;

		ctx->dnss_fd[0] = socket(AF_INET6, SOCK_STREAM, 0);
		ctx->dnss_fd[1] = socket(AF_INET, SOCK_STREAM, 0);
		if (ctx->dnss_fd[0] >= 0) {
			setsockopt(ctx->dnss_fd[0], SOL_TCP, TCP_NODELAY, &optval, sizeof(int));
			if (resolv_set_cmn_fd_opt(ctx->dnss_fd[0]) < 0) {
				prne_close(ctx->dnss_fd[0]);
				ctx->dnss_fd[0] = -1;
			}
			else {
				struct sockaddr_in6 addr;

				memzero(&addr, sizeof(addr));
				prne_net_ep_tosin6(ctx->dnssrv_6.arr + ctx->dnssrv_6.ptr, &addr);
				connect(ctx->dnss_fd[0], (const struct sockaddr*)&addr, sizeof(addr));
			}
		}
		if (ctx->dnss_fd[1] >= 0) {
			setsockopt(ctx->dnss_fd[1], SOL_TCP, TCP_NODELAY, &optval, sizeof(int));
			if (resolv_set_cmn_fd_opt(ctx->dnss_fd[1]) < 0) {
				prne_close(ctx->dnss_fd[1]);
				ctx->dnss_fd[1] = -1;
			}
			else {
				struct sockaddr_in addr;

				memzero(&addr, sizeof(addr));
				prne_net_ep_tosin4(ctx->dnssrv_4.arr + ctx->dnssrv_4.ptr, &addr);
				connect(ctx->dnss_fd[1], (const struct sockaddr*)&addr, sizeof(addr));
			}
		}

		if (ctx->dnss_fd[0] < 0 && ctx->dnss_fd[1] < 0) {
			ctx->err_to_slot->active = true;
			ctx->err_to_slot->dur = RESOLV_RSRC_ERR_PAUSE;
			ctx->sckop_to_slot->active = false;
		}
		else {
			ctx->sckop_to_slot->active = true;
			ctx->sckop_to_slot->dur = RESOLV_SCK_OP_TIMEOUT;
			for (i = 0; i < 2; i += 1) {
				ctx->sck_pfd_slot[i]->pfd.fd = ctx->dnss_fd[i];
				ctx->sck_pfd_slot[i]->pfd.events = POLLIN | POLLOUT;
			}

			ctx->ctx_state = RESOLV_CTX_STATE_CONN;
		}

		return false;
		}
	case RESOLV_CTX_STATE_CONN: {
		int optval;
		socklen_t optval_len;

		for (i = 0; i < 2; i += 1) {
			assert(ctx->sck_pfd_slot[i]->pfd.fd == ctx->dnss_fd[i]);
			if (ctx->sck_pfd_slot[i]->pfd.revents & (POLLHUP | POLLERR | POLLNVAL)) {
				prne_close(ctx->dnss_fd[i]);
				ctx->dnss_fd[i] = ctx->sck_pfd_slot[i]->pfd.fd = -1;
			}
		}
		if (ctx->dnss_fd[0] < 0 && ctx->dnss_fd[1] < 0) {
			ctx->err_to_slot->active = true;
			ctx->err_to_slot->dur = RESOLV_CONN_ERR_PAUSE;
			ctx->sckop_to_slot->active = false;
			ctx->ctx_state = RESOLV_CTX_STATE_NONE;

			return false;
		}

		for (i = 0; i < 2; i += 1) {
			if (ctx->sck_pfd_slot[i]->pfd.fd < 0) {
				continue;
			}

			if (ctx->sck_pfd_slot[i]->pfd.revents & (POLLIN | POLLOUT)) {
				optval_len = sizeof(optval);
				if (getsockopt(ctx->sck_pfd_slot[i]->pfd.fd, SOL_SOCKET, SO_ERROR, &optval, &optval_len) < 0 || optval != 0) {
					prne_close(ctx->dnss_fd[i]);
					ctx->dnss_fd[i] = ctx->sck_pfd_slot[i]->pfd.fd = -1;
				}
				else {
					ctx->act_dns_fd = ctx->dnss_fd[i];
					ctx->dnss_fd[i] = -1;
					break;
				}
			}
		}

		if (ctx->act_dns_fd >= 0) {
			for (i = 0; i < 2; i += 1) {
				prne_close(ctx->dnss_fd[i]);
				ctx->dnss_fd[i] = ctx->sck_pfd_slot[i]->pfd.fd = -1;
			}

			if (mbedtls_ssl_setup(&ctx->ssl.ctx, &ctx->ssl.conf) != 0 || mbedtls_ssl_set_hostname(&ctx->ssl.ctx, NULL) != 0) {
				resolv_close_sck(ctx, &RESOLV_RSRC_ERR_PAUSE, false);
				return false;
			}
			mbedtls_ssl_set_bio(&ctx->ssl.ctx, &ctx->act_dns_fd, prne_mbedtls_ssl_send_cb, prne_mbedtls_ssl_recv_cb, NULL);

			ctx->sck_pfd_slot[0]->pfd.fd = ctx->act_dns_fd;
			ctx->sck_pfd_slot[0]->pfd.events = POLLIN | POLLOUT;
			ctx->sckop_to_slot->active = true;
			ctx->sckop_to_slot->dur = RESOLV_SCK_OP_TIMEOUT;
			ctx->ctx_state = RESOLV_CTX_STATE_HNDSHK;
		}
		else if (ctx->dnss_fd[0] < 0 && ctx->dnss_fd[1] < 0) {
			resolv_close_sck(ctx, &RESOLV_CONN_ERR_PAUSE, true);
		}

		return false;
		}
	case RESOLV_CTX_STATE_HNDSHK: {
		assert(ctx->sck_pfd_slot[0]->pfd.fd == ctx->act_dns_fd && ctx->act_dns_fd >= 0);

		if (ctx->sck_pfd_slot[0]->pfd.revents & (POLLERR | POLLNVAL | POLLHUP)) {
			resolv_close_sck(ctx, &RESOLV_CONN_ERR_PAUSE, true);

			return false;
		}
		if (ctx->sck_pfd_slot[0]->pfd.revents & (POLLIN | POLLOUT)) {
			switch (mbedtls_ssl_handshake(&ctx->ssl.ctx)) {
			case MBEDTLS_ERR_SSL_WANT_READ:
				ctx->sck_pfd_slot[0]->pfd.events = POLLIN;
				break;
			case MBEDTLS_ERR_SSL_WANT_WRITE:
				ctx->sck_pfd_slot[0]->pfd.events = POLLOUT;
				break;
			case 0:
				ctx->sck_pfd_slot[0]->pfd.events = POLLIN;
				ctx->sckop_to_slot->active = true;
				ctx->sckop_to_slot->dur = RESOLV_SCK_IDLE_TIMEOUT;
				ctx->ctx_state = RESOLV_CTX_STATE_READY;

				return true;
			default:
				resolv_close_sck(ctx, &RESOLV_CONN_ERR_PAUSE, true);

				return false;
			}
		}

		return false;
		}
	case RESOLV_CTX_STATE_READY:
		return true;
	}

#ifdef PRNE_DEBUG
	abort();
#endif
	return false;
}

static const uint8_t* resolv_index_labels (prne_imap_t *map, const uint8_t *start, const uint8_t *end, const uint8_t *p, prne_resolv_qr_t *qr, int *err) {
	uint16_t ptr;
	const prne_imap_tuple_t *tpl;

	assert(qr != NULL);
	assert(err != NULL);
	if (p >= end) {
		*qr = PRNE_RESOLV_QR_PRO_ERR;
		return NULL;
	}

	while (*p != 0 && p < end) {
		if ((p[0] & 0xC0) == 0xC0) {
			// met pointer. don't go further.
			ptr = ((uint16_t)p[0] << 8) | (uint16_t)p[1];
			tpl = prne_imap_lookup(map, ptr);
			if (tpl == NULL) {
				*qr = PRNE_RESOLV_QR_ERR;
				*err = errno;
				return NULL;
			}
			return p + 2;
		}
		else if (*p > 63) {
			*qr = PRNE_RESOLV_QR_PRO_ERR;
			return NULL;
		}
		else {
			// index the label
			ptr = (uint16_t)(p - start) | 0xC000;
			if (prne_imap_insert(map, ptr, (void*)p) == NULL) {
				*qr = PRNE_RESOLV_QR_ERR;
				*err = errno;
				return NULL;
			}
			p += *p + 1;
		}
	}

	return p + 1;
}

static int resolv_mapped_qname_cmp (prne_imap_t *map, const uint8_t *a, const uint8_t *b, prne_resolv_qr_t *qr) {
	const uint8_t *p[2] = { a, b };
	size_t i;
	uint16_t ptr;
	const prne_imap_tuple_t *tpl;
	int ret;


	assert(qr != NULL);

	do {
		// deref the pointers
		for (i = 0; i < 2; i += 1) {
			if ((p[i][0] & 0xC0) == 0xC0) {
				ptr = ((uint16_t)p[i][0] << 8) | (uint16_t)p[i][1];
				tpl = prne_imap_lookup(map, ptr);
				if (tpl == NULL) {
					ret = -1;
					*qr = PRNE_RESOLV_QR_PRO_ERR;
					break;
				}
				p[i] = (const uint8_t*)tpl->val;
			}
		}

		if (*p[0] != *p[1]) {
			ret = 0;
			break;
		}
		if (*p[0] == 0 || *p[1] == 0) {
			ret = 1;
			break;
		}
		
		p[0] += 1;
		p[1] += 1;
	} while (true);

	return ret;
}

static bool resolv_proc_dns_msg (prne_resolv_wkr_ctx_t ctx, const uint8_t *data, const size_t len, bool *err_flag) {
	typedef struct {
		const uint8_t *name;
		const uint8_t *data;
		uint32_t ttl;
		uint16_t rtype;
		uint16_t rclass;
		uint16_t data_len;
	} rr_tuple_t;
	rr_tuple_t *tpl;
	prne_resolv_qr_t qr;
	int err = 0, cmp_ret;
	uint_fast16_t qid, status, ancount, ttype;
	prne_imap_t ptr_map; // val in msg(uint8_t):(uint8_t*)real addr
	prne_llist_t rr_list, ret_list;
	prne_iset_t alias_set;
	prne_llist_entry_t *cur;
	query_entry_t *qent;
	const uint8_t *qname, *alias, *end = data + len, *p, *rname;
	size_t i, j, loop_cnt;
	bool ret;

	if (len < 12) {
		*err_flag = true;
		return false;
	}
	*err_flag = false;

	qr = PRNE_RESOLV_QR_NONE;
	status = 0;
	ttype = 0;
	prne_init_imap(&ptr_map);
	prne_init_llist(&rr_list);
	prne_init_llist(&ret_list);
	prne_init_iset(&alias_set);

	// ID
	{
		const prne_imap_tuple_t *tpl;
		
		qid = ((uint16_t)data[0] << 8) | (uint16_t)data[1];
		tpl = prne_imap_lookup(&ctx->qid_map, qid);
		ret = tpl != NULL;
		if (ret) {
			qent = (query_entry_t*)tpl->val;
			if (qent != NULL) {
				switch (qent->type) {
				case PRNE_RESOLV_QT_A: ttype = 1; break;
				case PRNE_RESOLV_QT_AAAA: ttype = 28; break;
				case PRNE_RESOLV_QT_TXT: ttype = 16; break;
				default: abort();
				}
			}
		}
		else {
			qent = NULL;
		}
		prne_imap_erase(&ctx->qid_map, qid);		
	}
	// QR
	if ((data[2] & 0x80) == 0) {
		qr = PRNE_RESOLV_QR_PRO_ERR;
		*err_flag = true;
		goto END;
	}
	// Opcode
	if ((data[2] & 0x78) != 0) {
		qr = PRNE_RESOLV_QR_PRO_ERR;
		*err_flag = true;
		goto END;
	}
	// AA - don't care
	// RCODE
	status = data[3] & 0x0F;
	if (status != 0) {
		qr = PRNE_RESOLV_QR_STATUS;
		goto END;
	}
	// TC
	if ((data[2] & 0x02) != 0) {
		qr = PRNE_RESOLV_QR_IMPL;
		goto END;
	}
	// QDCOUNT
	if ((((uint_fast16_t)data[4] << 8) | (uint_fast16_t)data[5]) != 1) {
		qr = PRNE_RESOLV_QR_PRO_ERR;
		*err_flag = true;
		goto END;
	}
	// ANCOUNT
	ancount = ((uint_fast16_t)data[6] << 8) | (uint_fast16_t)data[7];

	// decode question
	if (len < 12 + 1 + 4) { // min msg with 1 QDCOUNT length
		qr = PRNE_RESOLV_QR_PRO_ERR;
		*err_flag = true;
		goto END;
	}
	qname = data + 12;
	p = resolv_index_labels(&ptr_map, data, end, (const uint8_t*)qname, &qr, &err);
	if (p == NULL) {
		goto END;
	}
	if ((size_t)(p - data + 4) > len) {
		qr = PRNE_RESOLV_QR_PRO_ERR;
		*err_flag = true;
		goto END;
	}
	if (qent != NULL && strcmp((const char*)qname, qent->qname) != 0) {
		qr = PRNE_RESOLV_QR_PRO_ERR;
		*err_flag = true;
		goto END;
	}
	if ((ttype != 0 && ttype != (((uint_fast16_t)p[0] << 8) | (uint_fast16_t)p[1])) ||
		(((uint_fast16_t)p[2] << 8) | (uint_fast16_t)p[3]) != 1) {
		qr = PRNE_RESOLV_QR_PRO_ERR;
		*err_flag = true;
		goto END;
	}
	
	p += 4;
	// decode answer RRs
	for (i = 0; i < ancount; i += 1) {
		tpl = prne_malloc(sizeof(rr_tuple_t), 1);
		if (tpl == NULL)  {
			err = errno;
			qr = PRNE_RESOLV_QR_ERR;
			goto END;
		}
		if (prne_llist_append(&rr_list, tpl) == NULL) {
			prne_free(tpl);
			err = errno;
			qr = PRNE_RESOLV_QR_ERR;
			goto END;
		}

		tpl->name = p;
		p = resolv_index_labels(&ptr_map, data, end, p, &qr, &err);
		if (p == NULL) {
			goto END;
		}
		if (p >= end || end - p < 10) {
			qr = PRNE_RESOLV_QR_PRO_ERR;
			*err_flag = true;
			goto END;
		}
		tpl->rtype = ((uint_fast16_t)p[0] << 8) | (uint_fast16_t)p[1];
		tpl->rclass = ((uint_fast16_t)p[2] << 8) | (uint_fast16_t)p[3];
		tpl->ttl = ((uint_fast32_t)p[4]) | ((uint_fast32_t)p[5]) | ((uint_fast32_t)p[6]) | ((uint_fast32_t)p[7]);
		tpl->data_len = ((uint_fast16_t)p[8] << 8) | (uint_fast16_t)p[9];
		rname = tpl->data = p + 10;

		switch (tpl->rtype) {
		case PRNE_RESOLV_RTYPE_SOA:
			loop_cnt = 2;
			break;
		case PRNE_RESOLV_RTYPE_CNAME:
		case PRNE_RESOLV_RTYPE_MX: 
		case PRNE_RESOLV_RTYPE_NS:
		case PRNE_RESOLV_RTYPE_PTR:
			loop_cnt = 1;
			break;
		default:
			loop_cnt = 0;
		}
		for (j = 0; j < loop_cnt; j += 1) {
			rname = resolv_index_labels(&ptr_map, data, tpl->data + tpl->data_len, rname, &qr, &err);
			if (rname == NULL) {
				goto END;
			}
		}

		p += 10 + tpl->data_len;
	}

	// resolve cname
	alias = qname;
	if (!prne_iset_insert(&alias_set, (prne_iset_val_t)alias)) {
		qr = PRNE_RESOLV_QR_ERR;
		err = errno;
		goto END;
	}
QNAME_START:
	cur = rr_list.head;
	while (cur != NULL) {
		tpl = (rr_tuple_t*)cur->element;

		if (tpl->rtype == PRNE_RESOLV_RTYPE_CNAME) {
			cmp_ret = resolv_mapped_qname_cmp(&ptr_map, tpl->name, alias, &qr);
			if (cmp_ret < 0) {
				goto END;
			}
			if (cmp_ret) {
				if (prne_iset_lookup(&alias_set, (prne_iset_val_t)tpl->data)) {
					qr = PRNE_RESOLV_QR_PRO_ERR;
					goto END;
				}
				if (!prne_iset_insert(&alias_set, (prne_iset_val_t)tpl->data)) {
					qr = PRNE_RESOLV_QR_ERR;
					err = errno;
					goto END;
				}
				alias = tpl->data;
				goto QNAME_START;
			}
		}

		cur = cur->next;
	}

	// index the selected(alias) resources
	cur = rr_list.head;
	while (cur != NULL) {
		tpl = (rr_tuple_t*)cur->element;

		cmp_ret = resolv_mapped_qname_cmp(&ptr_map, tpl->name, alias, &qr);
		if (cmp_ret < 0) {
			goto END;
		}
		if (cmp_ret && ttype == tpl->rtype) {
			if (prne_llist_append(&ret_list, tpl) == NULL) {
				qr = PRNE_RESOLV_QR_ERR;
				err = errno;
				goto END;
			}
		}

		cur = cur->next;
	}

	// return data
	if (ret_list.size > 0 && qent != NULL) {
		prne_llist_entry_t *cur;
		rr_tuple_t *tpl;

		qent->fut.rr = (prne_resolv_rr_t*)prne_malloc(sizeof(prne_resolv_rr_t), ret_list.size);
		if (qent->fut.rr == NULL) {	
			qr = PRNE_RESOLV_QR_ERR;
			err = errno;
			goto END;
		}
		qent->fut.rr_cnt = ret_list.size;
		for (i = 0; i < qent->fut.rr_cnt; i += 1) {
			prne_init_resolv_rr(qent->fut.rr + i);
		}

		i = 0;
		cur = ret_list.head;
		while (cur != NULL) {
			tpl = (rr_tuple_t*)cur->element;

			qent->fut.rr[i].rr_class = tpl->rclass;
			qent->fut.rr[i].rr_type = tpl->rtype;
			qent->fut.rr[i].rr_ttl = tpl->ttl;
			if (tpl->data_len > 0) {
				if ((qent->fut.rr[i].name = resolv_qname_tostr(qent->qname)) == NULL ||
					(qent->fut.rr[i].rd_data = (uint8_t*)prne_malloc(1, tpl->data_len)) == NULL) {
					qr = PRNE_RESOLV_QR_ERR;
					err = errno;
					goto END;
				}
				qent->fut.rr[i].rd_len = tpl->data_len;
				memcpy(qent->fut.rr[i].rd_data, tpl->data, tpl->data_len);
			}
			else {
				qent->fut.rr[i].rd_data = NULL;
				qent->fut.rr[i].rd_len = 0;				
			}

			i += 1;
			cur = cur->next;
		}
	}

	qr = PRNE_RESOLV_QR_OK;
	
END:
	cur = rr_list.head;
	while (cur != NULL) {
		prne_free(cur->element);
		cur = cur->next;
	}
	prne_free_llist(&rr_list);
	prne_free_llist(&ret_list);
	prne_free_imap(&ptr_map);
	prne_free_iset(&alias_set);
	if (qent != NULL) {
		if (qr != PRNE_RESOLV_QR_OK) {
			for (i = 0; i < qent->fut.rr_cnt; i += 1) {
				prne_free_resolv_rr(qent->fut.rr + i);
			}
			prne_free(qent->fut.rr);
			qent->fut.rr = NULL;
			qent->fut.rr_cnt = 0;
		}
		qent->fut.qr = qr;
		qent->fut.err = err;
		qent->fut.status = status;
		resolv_disown_qent(qent);
	}

	return ret;
}

static size_t resolv_calc_dot_msg_len (query_entry_t *qent) {
	return 2/*DoT head*/ + 12/*msg head*/ + qent->qname_size + 4/*QCLASS, QTYPE*/;
}

static void resolv_write_dns_msg (query_entry_t *qent, uint8_t *mem) {
	// ID
	mem[0] = (uint8_t)((qent->qid & 0xFF00) >> 8);
	mem[1] = (uint8_t)(qent->qid & 0x00FF);
	// QR: 0, Opcode: 0, AA:0, TC: 0, RD: 1, RA: 0, Z: 0, RCODE: 0
	mem[2] = 0x01;
	mem[3] = 0x00;
	// QDCOUNT: 1 
	mem[4] = 0x00;
	mem[5] = 0x01;
	// ANCOUNT, NSCOUNT, ARCOUNT: 0
	mem[6] = mem[7] = mem[8] = mem[9] = mem[10] = mem[11] = 0x00;

	// QNAME
	memcpy(mem + 12, qent->qname, qent->qname_size);
	// QTYPE
	switch (qent->type) {
	case PRNE_RESOLV_QT_A:
		mem[qent->qname_size + 12] = 0x00;
		mem[qent->qname_size + 13] = 0x01;
		break;
	case PRNE_RESOLV_QT_AAAA:
		mem[qent->qname_size + 12] = 0x00;
		mem[qent->qname_size + 13] = 0x1C;
		break;
	case PRNE_RESOLV_QT_TXT:
		mem[qent->qname_size + 12] = 0x00;
		mem[qent->qname_size + 13] = 0x10;
		break;
	default: abort();
	}
	// QCLASS: IN
	mem[qent->qname_size + 14] = 0x00;
	mem[qent->qname_size + 15] = 0x01;
}

static bool resolv_send_dns_msgs (prne_resolv_wkr_ctx_t ctx) {
	prne_llist_entry_t *cur;
	query_entry_t *qent;
	size_t dot_msg_len, dns_msg_len;
	uint16_t qid;
	bool ret = false;

	cur = ctx->qlist.head;
	while (cur != NULL && ctx->qid_map.size < RESOLV_PIPELINE_SIZE) {
		qent = (query_entry_t*)cur->element;

		dot_msg_len = resolv_calc_dot_msg_len(qent);
		dns_msg_len = dot_msg_len - 2;
		if (dot_msg_len + ctx->write_cnt_len <= sizeof(ctx->write_buf)) {
			qid = resolv_next_qid(ctx);
			if (qid == 0) {
				qent->fut.qr = PRNE_RESOLV_QR_ERR;
				qent->fut.err = 0;
				prne_llist_erase(&ctx->qlist, qent->qlist_ent);
				resolv_disown_qent(qent);

				return ret;
			}

			if (prne_imap_insert(&ctx->qid_map, qid, qent) == NULL) {
				qent->fut.err = errno;
				qent->fut.qr = PRNE_RESOLV_QR_ERR;
				prne_llist_erase(&ctx->qlist, cur);
				resolv_disown_qent(qent);

				return ret;
			}
			else {
				cur = prne_llist_erase(&ctx->qlist, cur);

				ctx->write_buf[ctx->write_cnt_len + 0] = (uint8_t)((dns_msg_len & 0xFF00) >> 8);
				ctx->write_buf[ctx->write_cnt_len + 1] = (uint8_t)(dns_msg_len & 0x00FF);
				qent->qid = qid;
				resolv_write_dns_msg(qent, ctx->write_buf + ctx->write_cnt_len + 2);

				ctx->write_cnt_len += dot_msg_len;
				ret |= true;
			}
		}
		else {
			break;
		}
	}

	return ret;
}

static void resolv_proc_q (prne_resolv_wkr_ctx_t ctx) {
	bool proc = false; // true if any meaningful message has been processed.
	int ret;

	if (ctx->ctx_state == RESOLV_CTX_STATE_READY) {
		assert(ctx->act_dns_fd >= 0);
		assert(ctx->act_dns_fd == ctx->sck_pfd_slot[0]->pfd.fd);

		if (ctx->sck_pfd_slot[0]->pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
			resolv_close_sck(ctx, &RESOLV_CONN_ERR_PAUSE, true);
			return;
		}
		if (ctx->sck_pfd_slot[0]->pfd.revents & POLLIN) {
			size_t pos, msg_len;
			bool err_flag = false;

			ret = mbedtls_ssl_read(&ctx->ssl.ctx, ctx->read_buf + ctx->read_cnt_len, sizeof(ctx->read_buf) - ctx->read_cnt_len);
			if (ret <= 0) {
				// we don't renegotiate with terrorists.
				resolv_close_sck(ctx, &RESOLV_CONN_ERR_PAUSE, true);
				return;
			}
			ctx->read_cnt_len += (size_t)ret;

			pos = 0;
			while (true) {
				if (pos + 1 >= ctx->read_cnt_len) {
					break;
				}
				msg_len = ((size_t)ctx->read_buf[pos] << 8) | (size_t)ctx->read_buf[pos + 1];
				if (msg_len > 512) { // unimplemented.
#ifdef PRNE_DEBUG
					fprintf(stderr, "* [resolv_wkr] Protocol error: received %zu bytes long msg. Dropping connection!\n", msg_len);
#endif
					// try to get qid
					if (ctx->read_cnt_len > pos + 4) {
						const uint16_t qid = ((uint_fast16_t)ctx->read_buf[pos + 2] << 8) | (uint_fast16_t)ctx->read_buf[pos + 3];
						const prne_imap_tuple_t *tpl = prne_imap_lookup(&ctx->qid_map, qid);

						if (tpl->val != NULL) {
							query_entry_t *qent = (query_entry_t*)tpl->val;
							qent->fut.qr = PRNE_RESOLV_QR_IMPL;
							resolv_disown_qent(qent);
						}
						prne_imap_erase(&ctx->qid_map, qid);
					}
					resolv_close_sck(ctx, &RESOLV_CONN_ERR_PAUSE, true);
					return;
				}
				if (pos + 1 + msg_len >= ctx->read_cnt_len) {
					break;
				}

				proc |= resolv_proc_dns_msg(ctx, ctx->read_buf + pos + 2, msg_len, &err_flag);
				if (err_flag) {
					resolv_close_sck(ctx, &RESOLV_CONN_ERR_PAUSE, true);
					return;
				}
				pos += 2 + msg_len;
			}
			if (pos > 0) {
				memmove(ctx->read_buf, ctx->read_buf + pos, ctx->read_cnt_len - pos);
				ctx->read_cnt_len -= pos;
			}
		}
	}

	if (ctx->qlist.size > 0 || ctx->write_cnt_len > 0) {
		if (!resolv_ensure_conn(ctx)) {
			return;
		}

		if ((ctx->sck_pfd_slot[0]->pfd.revents & POLLOUT) && ctx->write_cnt_len > 0) {
			ret = mbedtls_ssl_write(&ctx->ssl.ctx, ctx->write_buf, ctx->write_cnt_len);
			if (ret <= 0) {
				// we don't renegotiate with terrorists.
				resolv_close_sck(ctx, &RESOLV_CONN_ERR_PAUSE, true);
				return;
			}

			memmove(ctx->write_buf, ctx->write_buf + (size_t)ret, ctx->write_cnt_len - (size_t)ret);
			ctx->write_cnt_len -= (size_t)ret;
		}
		if (ctx->write_cnt_len == 0) {
			proc |= resolv_send_dns_msgs(ctx);
		}

		if (ctx->write_cnt_len > 0 || (0 < ctx->qlist.size && ctx->qid_map.size < RESOLV_PIPELINE_SIZE)) {
			ctx->sck_pfd_slot[0]->pfd.events = POLLIN | POLLOUT;
		}
		else {
			ctx->sck_pfd_slot[0]->pfd.events = POLLIN;
		}
	}

	if (proc) {
		if (ctx->qlist.size == 0 && ctx->qid_map.size == 0 &&
			ctx->read_cnt_len == 0 && ctx->write_cnt_len == 0) {
			ctx->sckop_to_slot->dur = RESOLV_SCK_IDLE_TIMEOUT;
		}
		else {
			ctx->sckop_to_slot->dur = RESOLV_SCK_OP_TIMEOUT;
		}
	}
}

static bool resolv_proc_close (prne_resolv_wkr_ctx_t ctx) {
	assert(ctx->ctx_state == RESOLV_CTX_STATE_CLOSING);

	if (ctx->sck_pfd_slot[0]->pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
		resolv_close_sck(ctx, &RESOLV_CONN_ERR_PAUSE, true);
		return false;
	}
	if (ctx->sck_pfd_slot[0]->pfd.revents) {
		switch (mbedtls_ssl_close_notify(&ctx->ssl.ctx)) {
		case MBEDTLS_ERR_SSL_WANT_READ:
			ctx->sck_pfd_slot[0]->pfd.events = POLLIN;
			return false;
		case MBEDTLS_ERR_SSL_WANT_WRITE:
			ctx->sck_pfd_slot[0]->pfd.events = POLLOUT;
			return false;
		case 0:
			resolv_close_sck(ctx, NULL, false);
			return true;
		default:
			resolv_close_sck(ctx, &RESOLV_CONN_ERR_PAUSE, true);
			return false;
		}
	}

	return false;
}

static void resolv_proc_expired (prne_resolv_wkr_ctx_t ctx) {
	prne_llist_entry_t *cur;
	query_entry_t *qent;

	cur = ctx->qlist.head;
	while (cur != NULL) {
		qent = (query_entry_t*)cur->element;

		if (qent->to_slot != NULL && qent->to_slot->reached) {
			qent->fut.qr = PRNE_RESOLV_QR_TIMEOUT;
			cur = prne_llist_erase(&ctx->qlist, cur);
			resolv_disown_qent(qent);
		}
		else {
			cur = cur->next;
		}
	}
}

static void resolv_wkr_free (void *p) {
	DECL_CTX_PTR(p);

	if (p == NULL) {
		return;
	}

	prne_free_wkr_timeout_slot(ctx->sckop_to_slot);
	prne_free_wkr_timeout_slot(ctx->err_to_slot);
	prne_free_wkr_pollfd_slot(ctx->evt_pfd_slot);
	prne_free_wkr_pollfd_slot(ctx->sck_pfd_slot[0]);
	prne_free_wkr_pollfd_slot(ctx->sck_pfd_slot[1]);
	prne_free(ctx->dnssrv_4.arr);
	prne_free(ctx->dnssrv_6.arr);
	prne_free_llist(&ctx->qlist);
	prne_free_imap(&ctx->qid_map);
	mbedtls_ssl_config_free(&ctx->ssl.conf);
	mbedtls_ssl_free(&ctx->ssl.ctx);

	prne_close(ctx->act_dns_fd);
	prne_close(ctx->dnss_fd[0]);
	prne_close(ctx->dnss_fd[1]);
	prne_close(ctx->evtfd[0]);
	prne_close(ctx->evtfd[1]);

	prne_free(ctx);
}

static void resolv_wkr_fin (void *p) {
	DECL_CTX_PTR(p);

	assert(ctx->wkr_state == RESOLV_WKR_STATE_OK);
	ctx->wkr_state = RESOLV_WKR_STATE_FIN_CALLED;
}

static void resolv_wkr_work (void *p, const prne_wkr_tick_info_t *tick_info) {
	DECL_CTX_PTR(p);

	assert(ctx->wkr_state != RESOLV_WKR_STATE_FINALISED);
	assert((ctx->evt_pfd_slot->pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) == 0);

	if (ctx->evt_pfd_slot->pfd.revents & POLLIN) {
		uint8_t rubbish;

		if (read(ctx->evtfd[0], &rubbish, 1) < 0) {
			prne_die_not_nonblock_err();
		}
	}
	
	resolv_proc_expired(ctx);

	if (ctx->err_to_slot->active) {
		if (ctx->err_to_slot->reached) {
			ctx->err_to_slot->active = false;
		}
		else {
			return;
		}
	}

	if (ctx->sckop_to_slot->active && ctx->sckop_to_slot->reached) {
		if (ctx->ctx_state == RESOLV_CTX_STATE_READY) {
			ctx->ctx_state = RESOLV_CTX_STATE_CLOSING;
			ctx->sckop_to_slot->dur = RESOLV_SCK_CLOSE_TIMEOUT;
			ctx->sck_pfd_slot[0]->pfd.fd = ctx->act_dns_fd;
			ctx->sck_pfd_slot[0]->pfd.events = POLLIN | POLLOUT;
			return;
		}
		else {
			resolv_close_sck(ctx, NULL, true);
		}
	}
	if (ctx->ctx_state == RESOLV_CTX_STATE_CLOSING && !resolv_proc_close(ctx)) {
		return;
	}

	resolv_proc_q(ctx);
	if (ctx->wkr_state == RESOLV_WKR_STATE_FIN_CALLED && ctx->qid_map.size == 0 && ctx->qlist.size == 0) {
		if (ctx->ctx_state == RESOLV_CTX_STATE_READY) {
			ctx->ctx_state = RESOLV_CTX_STATE_CLOSING;
			ctx->sckop_to_slot->dur = RESOLV_SCK_CLOSE_TIMEOUT;
			ctx->sck_pfd_slot[0]->pfd.fd = ctx->act_dns_fd;
			ctx->sck_pfd_slot[0]->pfd.events = POLLIN | POLLOUT;
		}
		else {
			ctx->wkr_state = RESOLV_WKR_STATE_FINALISED;
			resolv_close_sck(ctx, NULL, false);
			ctx->evt_pfd_slot->pfd.fd = -1;
			ctx->err_to_slot->active = false;
		}
	}
}

prne_resolv_wkr_ctx_t prne_alloc_resolv_worker (prne_worker_t *w, prne_wkr_sched_req_t *wsr, mbedtls_ctr_drbg_context *ctr_drbg) {
	prne_resolv_wkr_ctx_t ctx = NULL;

	if (wsr == NULL || ctr_drbg == NULL) {
		errno = EINVAL;
		return NULL;
	}

	ctx = (prne_resolv_wkr_ctx_t)prne_malloc(sizeof(struct prne_resolv_wkr_ctx), 1);
	if (ctx == NULL) {
		return NULL;
	}
	ctx->dnss_fd[0] = ctx->dnss_fd[1] = -1;
	ctx->evtfd[0] = ctx->evtfd[1] = -1;
	ctx->read_cnt_len = 0;
	ctx->write_cnt_len = 0;
	ctx->wsr = wsr;
	ctx->sckop_to_slot = prne_alloc_wkr_timeout_slot(wsr);
	ctx->err_to_slot = prne_alloc_wkr_timeout_slot(wsr);
	ctx->evt_pfd_slot = prne_alloc_wkr_pollfd_slot(wsr);
	ctx->sck_pfd_slot[0] = prne_alloc_wkr_pollfd_slot(wsr);
	ctx->sck_pfd_slot[1] = prne_alloc_wkr_pollfd_slot(wsr);
	ctx->act_dns_fd = -1;
	ctx->ctx_state = RESOLV_CTX_STATE_NONE;
	ctx->wkr_state = RESOLV_WKR_STATE_OK;
	ctx->ssl.ctr_drbg = ctr_drbg;
	prne_init_llist(&ctx->qlist);
	prne_init_imap(&ctx->qid_map);
	mbedtls_ssl_config_init(&ctx->ssl.conf);
	mbedtls_ssl_init(&ctx->ssl.ctx);
	if (ctx->sckop_to_slot == NULL ||
		ctx->err_to_slot == NULL ||
		ctx->evt_pfd_slot == NULL ||
		ctx->sck_pfd_slot[0] == NULL ||
		ctx->sck_pfd_slot[1] == NULL) {
		goto ERR;
	}

	ctx->dnssrv_4.arr = NULL;
	ctx->dnssrv_6.arr = NULL;
	ctx->dnssrv_4.cnt = 8;
	ctx->dnssrv_6.cnt = 8;
	ctx->dnssrv_4.ptr = resolv_next_pool_ptr(ctx, ctx->dnssrv_4.cnt);
	ctx->dnssrv_6.ptr = resolv_next_pool_ptr(ctx, ctx->dnssrv_6.cnt);
	ctx->dnssrv_4.arr = prne_malloc(sizeof(prne_net_endpoint_t), ctx->dnssrv_4.cnt);
	ctx->dnssrv_6.arr = prne_malloc(sizeof(prne_net_endpoint_t), ctx->dnssrv_6.cnt);
	if (ctx->dnssrv_4.arr == NULL || ctx->dnssrv_6.arr == NULL) {
		goto ERR;
	}
	// IPv4 servers
	// Google
	prne_true_or_die(prne_net_ep_set_ipv4("8.8.8.8", 853, ctx->dnssrv_4.arr + 0));
	prne_true_or_die(prne_net_ep_set_ipv4("8.8.4.4", 853, ctx->dnssrv_4.arr + 1));
	// Cloudflare
	prne_true_or_die(prne_net_ep_set_ipv4("1.1.1.1", 853, ctx->dnssrv_4.arr + 2));
	prne_true_or_die(prne_net_ep_set_ipv4("1.0.0.1", 853, ctx->dnssrv_4.arr + 3));
	// Quad9
	prne_true_or_die(prne_net_ep_set_ipv4("9.9.9.10", 853, ctx->dnssrv_4.arr + 4));
	prne_true_or_die(prne_net_ep_set_ipv4("149.112.112.10", 853, ctx->dnssrv_4.arr + 5));
	// CleanBrowsing
	prne_true_or_die(prne_net_ep_set_ipv4("185.228.168.9", 853, ctx->dnssrv_4.arr + 6));
	prne_true_or_die(prne_net_ep_set_ipv4("185.228.169.9", 853, ctx->dnssrv_4.arr + 7));
	// IPv6 servers
	// Google
	prne_true_or_die(prne_net_ep_set_ipv6("2001:4860:4860::8888", 853, ctx->dnssrv_6.arr + 0));
	prne_true_or_die(prne_net_ep_set_ipv6("2001:4860:4860::8844", 853, ctx->dnssrv_6.arr + 1));
	// Cloudflare
	prne_true_or_die(prne_net_ep_set_ipv6("2606:4700:4700::1111", 853, ctx->dnssrv_6.arr + 2));
	prne_true_or_die(prne_net_ep_set_ipv6("2606:4700:4700::1001", 853, ctx->dnssrv_6.arr + 3));
	// Quad9
	prne_true_or_die(prne_net_ep_set_ipv6("2620:fe::fe", 853, ctx->dnssrv_6.arr + 4));
	prne_true_or_die(prne_net_ep_set_ipv6("2620:fe::9", 853, ctx->dnssrv_6.arr + 5));
	// CleanBrowsing
	prne_true_or_die(prne_net_ep_set_ipv6("2a0d:2a00:1::2", 853, ctx->dnssrv_6.arr + 6));
	prne_true_or_die(prne_net_ep_set_ipv6("2a0d:2a00:2::2", 853, ctx->dnssrv_6.arr + 7));

	OK_OR_ERR(pipe(ctx->evtfd));
	OK_OR_ERR(resolv_set_cmn_fd_opt(ctx->evtfd[0]));
	OK_OR_ERR(resolv_set_cmn_fd_opt(ctx->evtfd[1]));
	prne_set_pipe_size(ctx->evtfd[0], 1);
	ctx->evt_pfd_slot->pfd.fd = ctx->evtfd[0];
	ctx->evt_pfd_slot->pfd.events = POLLIN;

	if (mbedtls_ssl_config_defaults(&ctx->ssl.conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
		goto ERR;
	}
	mbedtls_ssl_conf_rng(&ctx->ssl.conf, mbedtls_ctr_drbg_random, ctx->ssl.ctr_drbg);
	mbedtls_ssl_conf_authmode(&ctx->ssl.conf, MBEDTLS_SSL_VERIFY_NONE);

	w->ctx = ctx;
	w->free = resolv_wkr_free;
	w->fin = resolv_wkr_fin;
	w->work = resolv_wkr_work;
	w->has_finalised = resolv_wkr_has_finalised;
	return ctx;
ERR:
	if (ctx != NULL) {
		prne_free_wkr_timeout_slot(ctx->sckop_to_slot);
		prne_free_wkr_timeout_slot(ctx->err_to_slot);
		prne_free_wkr_pollfd_slot(ctx->evt_pfd_slot);
		prne_free_wkr_pollfd_slot(ctx->sck_pfd_slot[0]);
		prne_free_wkr_pollfd_slot(ctx->sck_pfd_slot[1]);
		prne_free(ctx->dnssrv_4.arr);
		prne_free(ctx->dnssrv_6.arr);
		prne_free_llist(&ctx->qlist);
		prne_free_imap(&ctx->qid_map);
		mbedtls_ssl_config_free(&ctx->ssl.conf);
		mbedtls_ssl_free(&ctx->ssl.ctx);

		prne_close(ctx->evtfd[0]);
		prne_close(ctx->evtfd[1]);

		prne_free(ctx);
	}

	return NULL;
}

bool prne_resolv_prm_gethostbyname (prne_resolv_wkr_ctx_t wkr, const char *name, const prne_ipv_t ipv, prne_resolv_prm_t *out, const struct timespec *timeout) {
	bool ret;
	query_entry_t *q_ent;
	prne_resolv_query_type_t qt;

	if (wkr->wkr_state != RESOLV_WKR_STATE_OK) {
		errno = EPIPE;
		return false;
	}
	
	switch (ipv) {
	case PRNE_IPV_4: qt = PRNE_RESOLV_QT_A; break;
	case PRNE_IPV_6: qt = PRNE_RESOLV_QT_AAAA; break;
	default:
		errno = EINVAL;
		return false;
	}

	ret = resolv_qq(wkr, name, out, timeout, &q_ent);
	if (ret) {
		q_ent->ipv = ipv;
		q_ent->type = qt;
	}

	return ret;
}

bool prne_resolv_prm_gettxtrec (prne_resolv_wkr_ctx_t wkr, const char *name, prne_resolv_prm_t *out, const struct timespec *timeout) {
	bool ret;
	query_entry_t *q_ent;

	if (wkr->wkr_state != RESOLV_WKR_STATE_OK) {
		errno = EPIPE;
		return false;
	}

	ret = resolv_qq(wkr, name, out, timeout, &q_ent);
	if (ret) {
		q_ent->type = PRNE_RESOLV_QT_TXT;
	}

	return ret;
}

void prne_resolv_free_prm (prne_resolv_prm_t *prm) {
	if (prm->ctx != NULL) {
		query_entry_t *ent = (query_entry_t*)prm->ctx;

		if (ent->wkr != NULL) {
			prne_llist_erase(&ent->wkr->qlist, ent->qlist_ent);

			if (prne_imap_lookup(&ent->wkr->qid_map, ent->qid) != NULL) {
				prne_imap_insert(&ent->wkr->qid_map, ent->qid, 0);
			}
		}
		resolv_free_q_ent(ent);
	}

	prm->ctx = NULL;
	prm->fut = NULL;
	prm->evtfd = -1;
}

void prne_resolv_init_prm (prne_resolv_prm_t *prm) {
	prm->ctx = NULL;
	prm->fut = NULL;
	prm->evtfd = -1;
}

void prne_init_resolv_fut (prne_resolv_fut_t *fut) {
	fut->rr_cnt = 0;
	fut->rr = NULL;
	fut->qr = PRNE_RESOLV_QR_NONE;
	fut->err = 0;
	fut->status = 0;
}

void prne_free_resolv_fut (prne_resolv_fut_t *fut) {
	size_t i;

	for (i = 0; i < fut->rr_cnt; i += 1) {
		prne_free_resolv_rr(fut->rr + i);
	}
	prne_free(fut->rr);
	fut->rr = NULL;
	fut->rr_cnt = 0;
}

void prne_init_resolv_rr (prne_resolv_rr_t *rr) {
	rr->name = NULL;
	rr->rr_class = 0;
	rr->rr_type = 0;
	rr->rr_ttl = 0;
	rr->rd_data = NULL;
	rr->rd_len = 0;
}

void prne_free_resolv_rr (prne_resolv_rr_t *rr) {
	prne_free(rr->name);
	prne_free(rr->rd_data);
	rr->rd_data = NULL;
	rr->rd_len = 0;
}

const char *prne_resolv_qr_tostr (const prne_resolv_qr_t qr) {
	switch (qr) {
	case PRNE_RESOLV_QR_OK: return "OK";
	case PRNE_RESOLV_QR_ERR: return "ERR";
	case PRNE_RESOLV_QR_PRO_ERR: return "PRO_ERR";
	case PRNE_RESOLV_QR_FIN: return "FIN";
	case PRNE_RESOLV_QR_IMPL: return "IMPL";
	case PRNE_RESOLV_QR_TIMEOUT: return "TIMEOUT";
	case PRNE_RESOLV_QR_STATUS: return "STATUS";
	}
	return NULL;
}

const char *prne_resolv_rcode_tostr (const prne_resolv_rcode_t rc) {
	switch (rc) {
	case PRNE_RESOLV_RCODE_NOERROR: return "NOERROR";
	case PRNE_RESOLV_RCODE_FORMERR: return "FORMERR";
	case PRNE_RESOLV_RCODE_SERVFAIL: return "SERVFAIL";
	case PRNE_RESOLV_RCODE_NXDOMAIN: return "NXDOMAIN";
	case PRNE_RESOLV_RCODE_NOTIMP: return "NOTIMP";
	case PRNE_RESOLV_RCODE_REFUSED: return "REFUSED";	
	}
	return NULL;
}

const char *prne_resolv_rrtype_tostr (const uint16_t rrt) {
	switch (rrt) {
	case PRNE_RESOLV_RTYPE_A: return "A";
	case PRNE_RESOLV_RTYPE_NS: return "NS";
	case PRNE_RESOLV_RTYPE_CNAME: return "CNAME";
	case PRNE_RESOLV_RTYPE_SOA: return "SOA";
	case PRNE_RESOLV_RTYPE_PTR: return "PTR";
	case PRNE_RESOLV_RTYPE_MX: return "MX";
	case PRNE_RESOLV_RTYPE_TXT: return "TXT";
	case PRNE_RESOLV_RTYPE_AAAA: return "AAAA";
	}
	return NULL;
}
