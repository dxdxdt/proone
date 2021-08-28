/*
* Copyright (c) 2019-2021 David Timber <mieabby@gmail.com>
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
#include "libssh2.h"
#include "util_ct.h"
#include "util_rt.h"
#include "pth.h"

#include <stdbool.h>
#include <errno.h>


typedef struct {
	LIBSSH2_SESSION *s;
	int fd;
} lssh2_cbctx_s_t;

typedef struct {
	LIBSSH2_SESSION *s;
	const char *id;
	const char *pw;
	unsigned int id_len;
	unsigned int pw_len;
	void *ret;
} lssh2_cbctx_ua_cred_t;

typedef struct {
	LIBSSH2_SESSION *s;
	LIBSSH2_CHANNEL *ret;
} lssh2_cbctx_open_channel_t;

typedef struct {
	LIBSSH2_CHANNEL *c;
	void *buf;
	size_t len;
	int s_id;
} lssh2_cbctx_ch_f_t;

typedef struct {
	LIBSSH2_SESSION *s;
	int reason;
	const char *desc;
	const char *lang;
} lssh2_cbctx_discon_t;

static ssize_t lssh2_crippled_send (
	int __fd,
	const void *__buf,
	size_t __n,
	int __flags)
{
	errno = 0;
	return -1;
}

static ssize_t lssh2_crippled_recv (
	int __fd,
	void *__buf,
	size_t __n,
	int __flags)
{
	errno = 0;
	return -1;
}

static int lssh2_handle (
	LIBSSH2_SESSION *s,
	const int fd,
	pth_event_t ev,
	void *ctx,
	int (*lssh2_f)(void*))
{
	int f_ret;
	struct pollfd pfd;

	pfd.fd = fd;
	while (true) {
		f_ret = lssh2_f(ctx);
		if (f_ret != LIBSSH2_ERROR_EAGAIN) {
			break;
		}

		f_ret = libssh2_session_block_directions(s);
		pfd.events = 0;
		if (f_ret & LIBSSH2_SESSION_BLOCK_INBOUND) {
			pfd.events |= POLLIN;
		}
		if (f_ret & LIBSSH2_SESSION_BLOCK_OUTBOUND) {
			pfd.events |= POLLOUT;
		}

		f_ret = prne_pth_poll(&pfd, 1, -1, ev);
		if (f_ret < 0) {
			f_ret = -1;
			break;
		}
	}

	return f_ret;
}

static int lssh2_handshake_f (void *p) {
	lssh2_cbctx_s_t *ctx = (lssh2_cbctx_s_t*)p;
	return libssh2_session_handshake(ctx->s, ctx->fd);
}

int prne_lssh2_handshake (LIBSSH2_SESSION *s, const int fd, pth_event_t ev) {
	lssh2_cbctx_s_t ctx;
	ctx.fd = fd;
	ctx.s = s;
	return lssh2_handle(s, fd, ev, &ctx, lssh2_handshake_f);
}

static int lssh2_ua_pwd_f (void *p) {
	lssh2_cbctx_ua_cred_t *ctx = (lssh2_cbctx_ua_cred_t*)p;
	return libssh2_userauth_password_ex(
		ctx->s,
		ctx->id,
		ctx->id_len,
		ctx->pw,
		ctx->pw_len,
		NULL);
}

int prne_lssh2_ua_pwd (
	LIBSSH2_SESSION *s,
	const int fd,
	const char *id,
	const char *pw,
	pth_event_t ev)
{
	lssh2_cbctx_ua_cred_t ctx;
	const size_t id_len = prne_nstrlen(id);
	const size_t pw_len = prne_nstrlen(pw);

	if (id_len > UINT_MAX || pw_len > UINT_MAX) {
		errno = EOVERFLOW;
		return -1;
	}

	ctx.s = s;
	ctx.id = id;
	ctx.id_len = (unsigned int)id_len;
	ctx.pw = pw;
	ctx.pw_len = (unsigned int)pw_len;

	return lssh2_handle(s, fd, ev, &ctx, lssh2_ua_pwd_f);
}

static int lssh2_open_channel_f (void *p) {
	lssh2_cbctx_open_channel_t *ctx = (lssh2_cbctx_open_channel_t*)p;
	int err;

	ctx->ret = libssh2_channel_open_session(ctx->s);
	if (ctx->ret == NULL) {
		err = libssh2_session_last_errno(ctx->s);
		prne_dbgast(err != 0);
	}
	else {
		err = 0;
	}

	return err;
}

LIBSSH2_CHANNEL *prne_lssh2_open_ch (
	LIBSSH2_SESSION *s,
	const int fd,
	pth_event_t ev,
	int *err)
{
	lssh2_cbctx_open_channel_t ctx;
	int f_ret;
	ctx.s = s;
	ctx.ret = NULL;

	f_ret = lssh2_handle(s, fd, ev, &ctx, lssh2_open_channel_f);
	prne_chk_assign(err, f_ret);
	return ctx.ret;
}

static int lssh2_close_ch_f (void *p) {
	lssh2_cbctx_ch_f_t *ctx = (lssh2_cbctx_ch_f_t*)p;
	return libssh2_channel_close(ctx->c);
}

int prne_lssh2_close_ch (
	LIBSSH2_SESSION *s,
	LIBSSH2_CHANNEL *c,
	const int fd,
	pth_event_t ev)
{
	lssh2_cbctx_ch_f_t ctx;
	ctx.c = c;
	return lssh2_handle(s, fd, ev, &ctx, lssh2_close_ch_f);
}

static int lssh2_ch_wait_closed_f (void *p) {
	lssh2_cbctx_ch_f_t *ctx = (lssh2_cbctx_ch_f_t*)p;
	return libssh2_channel_wait_closed(ctx->c);
}

int prne_lssh2_ch_wait_closed (
	LIBSSH2_SESSION *s,
	LIBSSH2_CHANNEL *c,
	const int fd,
	pth_event_t ev)
{
	lssh2_cbctx_ch_f_t ctx;
	ctx.c = c;
	return lssh2_handle(s, fd, ev, &ctx, lssh2_ch_wait_closed_f);
}

static int lssh2_ch_req_pty_f (void *p) {
	lssh2_cbctx_ch_f_t *ctx = (lssh2_cbctx_ch_f_t*)p;
	return libssh2_channel_request_pty(ctx->c, (const char*)ctx->buf);
}

int prne_lssh2_ch_req_pty (
	LIBSSH2_SESSION *s,
	LIBSSH2_CHANNEL *c,
	const int fd,
	const char *term,
	pth_event_t ev)
{
	lssh2_cbctx_ch_f_t ctx;
	ctx.c = c;
	ctx.buf = (void*)term;
	return lssh2_handle(s, fd, ev, &ctx, lssh2_ch_req_pty_f);
}

static int lssh2_ch_sh_f (void *p) {
	lssh2_cbctx_ch_f_t *ctx = (lssh2_cbctx_ch_f_t*)p;
	return libssh2_channel_shell(ctx->c);
}

int prne_lssh2_ch_sh (
	LIBSSH2_SESSION *s,
	LIBSSH2_CHANNEL *c,
	const int fd,
	pth_event_t ev)
{
	lssh2_cbctx_ch_f_t ctx;
	ctx.c = c;
	return lssh2_handle(s, fd, ev, &ctx, lssh2_ch_sh_f);
}

static int lssh2_ch_io_f (void *p) {
	lssh2_cbctx_ch_f_t *ctx = (lssh2_cbctx_ch_f_t*)p;
	ssize_t ret;

	switch (ctx->s_id) {
	case 0:
		ret = libssh2_channel_write(ctx->c, ctx->buf, ctx->len);
		break;
	case 1:
		ret = libssh2_channel_read(ctx->c, ctx->buf, ctx->len);
		break;
	case 2:
		ret = libssh2_channel_read_stderr(ctx->c, ctx->buf, ctx->len);
		break;
	default: ret = -1;
	}

	return (int)ret;
}

int prne_lssh2_ch_read (
	LIBSSH2_SESSION *s,
	LIBSSH2_CHANNEL *c,
	const int fd,
	const bool s_err,
	void *buf,
	const size_t len,
	pth_event_t ev)
{
	lssh2_cbctx_ch_f_t ctx;
	if (len > INT_MAX) {
		errno = EOVERFLOW;
		return -1;
	}
	ctx.c = c;
	ctx.buf = buf;
	ctx.len = len;
	ctx.s_id = s_err ? 2 : 1;

	return lssh2_handle(s, fd, ev, &ctx, lssh2_ch_io_f);
}

int prne_lssh2_ch_write (
	LIBSSH2_SESSION *s,
	LIBSSH2_CHANNEL *c,
	const int fd,
	const void *buf,
	const size_t len,
	pth_event_t ev)
{
	lssh2_cbctx_ch_f_t ctx;
	if (len > INT_MAX) {
		errno = EOVERFLOW;
		return -1;
	}
	ctx.c = c;
	ctx.buf = (void*)buf;
	ctx.len = len;
	ctx.s_id = 0;

	return lssh2_handle(s, fd, ev, &ctx, lssh2_ch_io_f);
}

static int lssh2_disconn_f (void *p) {
	lssh2_cbctx_discon_t *ctx = (lssh2_cbctx_discon_t*)p;
	return libssh2_session_disconnect_ex(
		ctx->s,
		ctx->reason,
		ctx->desc,
		ctx->lang);
}

int prne_lssh2_discon (
	LIBSSH2_SESSION *s,
	const int fd,
	const int reason,
	const char *desc,
	const char *lang,
	pth_event_t ev)
{
	lssh2_cbctx_discon_t ctx;
	ctx.s = s;
	ctx.reason = reason;
	ctx.desc = desc;
	ctx.lang = lang;

	return lssh2_handle(s, fd, ev, &ctx, lssh2_disconn_f);
}

static int lssh2_ua_list_f (void *p) {
	lssh2_cbctx_ua_cred_t *ctx = (lssh2_cbctx_ua_cred_t*)p;
	int err;

	ctx->ret = libssh2_userauth_list(ctx->s, ctx->id, ctx->id_len);
	if (ctx->ret == NULL) {
		err = libssh2_session_last_errno(ctx->s);
	}
	else {
		err = 0;
	}

	return err;
}

const char *prne_lssh2_ua_list (
	LIBSSH2_SESSION *s,
	const int fd,
	const char *username,
	pth_event_t ev,
	int *out_err)
{
	lssh2_cbctx_ua_cred_t ctx;
	int err;
	ctx.s = s;
	ctx.id = username;
	ctx.id_len = strlen(username);

	err = lssh2_handle(s, fd, ev, &ctx, lssh2_ua_list_f);
	prne_chk_assign(out_err, err);
	return (const char*)ctx.ret;
}

static int lssh2_ua_authd (void *p) {
	lssh2_cbctx_s_t *ctx = (lssh2_cbctx_s_t*)p;
	return libssh2_userauth_authenticated(ctx->s);
}

int prne_lssh2_ua_authd (
	LIBSSH2_SESSION *s,
	const int fd,
	pth_event_t ev)
{
	lssh2_cbctx_s_t ctx;
	ctx.s = s;
	ctx.fd = fd;
	return lssh2_handle(s, fd, ev, &ctx, lssh2_ua_authd);
}

void prne_lssh2_cripple_session (LIBSSH2_SESSION *s) {
	#pragma GCC diagnostic push
	#pragma GCC diagnostic ignored "-Wpedantic"
	libssh2_session_callback_set(
		s,
		LIBSSH2_CALLBACK_SEND,
		(void*)lssh2_crippled_send);
	libssh2_session_callback_set(
		s,
		LIBSSH2_CALLBACK_RECV,
		(void*)lssh2_crippled_recv);
	#pragma GCC diagnostic pop
}

void prne_lssh2_free_session (LIBSSH2_SESSION *s) {
	if (s == NULL) {
		return;
	}
	prne_lssh2_cripple_session(s);
	libssh2_session_free(s);
}
