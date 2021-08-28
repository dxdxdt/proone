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
#include "mbedtls.h"
#include "util_ct.h"
#include "util_rt.h"
#include "pth.h"

#include <errno.h>
#include <string.h>

#include <unistd.h>
#include <fcntl.h>

#include <mbedtls/ssl.h>
#include <mbedtls/entropy_poll.h>
#include <mbedtls/error.h>


int prne_mbedtls_x509_crt_verify_cb (
	void *param,
	mbedtls_x509_crt *crt,
	int crt_depth,
	uint32_t *flags)
{
	*flags &= ~(uint32_t)MBEDTLS_X509_BADCERT_EXPIRED;
	return 0;
}

int prne_mbedtls_ssl_send_cb (
	void *ctx,
	const unsigned char *buf,
	size_t len)
{
	const int fd = *(int*)ctx;
	ssize_t ret;

	ret = write(fd, buf, len);
	if (ret < 0) {
		switch (errno) {
#if EAGAIN == EWOULDBLOCK
		case EAGAIN:
#else
		case EAGAIN:
		case EWOULDBLOCK:
#endif
			return MBEDTLS_ERR_SSL_WANT_WRITE;
		}
	}

	return ret;
}

int prne_mbedtls_ssl_recv_cb (void *ctx, unsigned char *buf, size_t len) {
	const int fd = *(int*)ctx;
	ssize_t ret;

	ret = read(fd, buf, len);
	if (ret < 0) {
		switch (errno) {
#if EAGAIN == EWOULDBLOCK
		case EAGAIN:
#else
		case EAGAIN:
		case EWOULDBLOCK:
#endif
			return MBEDTLS_ERR_SSL_WANT_READ;
		}
	}

	return ret;
}

static int prne_mbedtls_entropy_urand_src_f (
	void *data,
	unsigned char *output,
	size_t len,
	size_t *olen)
{
	const int fd = open("/dev/urandom", O_RDONLY);
	int func_ret = 0;

	if (fd < 0 || read(fd, output, len) != (ssize_t)len) {
		func_ret = MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
	}
	*olen = len;

	if (fd >= 0) {
		close(fd);
	}

	return func_ret;
}

typedef struct {
	pid_t pid;
	pid_t ppid;
	clock_t clock;
	struct timespec now;
	struct timespec datetime;
} ent_buf_t;

static int prne_mbedtls_entropy_proc_src_f (
	void *data,
	unsigned char *output,
	size_t len,
	size_t *olen)
{
	ent_buf_t buf;

	prne_memzero(&buf, sizeof(buf));
	buf.pid = getpid();
	buf.ppid = getppid();
	buf.clock = clock();
	clock_gettime(CLOCK_MONOTONIC, &buf.now);
	clock_gettime(CLOCK_REALTIME, &buf.datetime);

	*olen = prne_op_min(len, sizeof(buf));
	memcpy(output, &buf, sizeof(*olen));

	return 0;
}

void prne_mbedtls_entropy_init (mbedtls_entropy_context *ctx) {
	mbedtls_entropy_init(ctx);

	/*
	* Remove platform source, which could call getrandom().
	* Add our own implementation as the one just got removed could be the only
	* source.
	*/
	for (int i = 0; i < ctx->source_count; i += 1) {
		if (ctx->source[i].f_source == mbedtls_platform_entropy_poll) {
			memmove(
				ctx->source + i,
				ctx->source + i + 1,
				sizeof(mbedtls_entropy_source_state) *
					(ctx->source_count - i - 1));
			ctx->source_count -= 1;
			mbedtls_entropy_add_source(
				ctx,
				prne_mbedtls_entropy_urand_src_f,
				NULL,
				MBEDTLS_ENTROPY_MIN_PLATFORM,
				MBEDTLS_ENTROPY_SOURCE_STRONG);
			mbedtls_entropy_add_source(
				ctx,
				prne_mbedtls_entropy_proc_src_f,
				NULL,
				sizeof(ent_buf_t),
				MBEDTLS_ENTROPY_SOURCE_STRONG);
			break;
		}
	}
}

bool prne_mbedtls_pth_handle (
	mbedtls_ssl_context *ssl,
	int(*mbedtls_f)(mbedtls_ssl_context*),
	const int fd,
	pth_event_t ev)
{
	int pollret;
	struct pollfd pfd;

	pfd.fd = fd;

	while (true) {
		switch (mbedtls_f(ssl)) {
		case MBEDTLS_ERR_SSL_WANT_READ:
			pfd.events = POLLIN;
			break;
		case MBEDTLS_ERR_SSL_WANT_WRITE:
			pfd.events = POLLOUT;
			break;
		case 0:
			return true;
		default:
			return false;
		}

		do {
			pollret = prne_pth_poll(&pfd, 1, -1, ev);
			if (pollret < 0) {
				return false;
			}
		} while (false);
	}
}

bool prne_mbedtls_verify_alp (
	const mbedtls_ssl_config *conf,
	const mbedtls_ssl_context *ctx,
	const char *alp)
{
	bool has_alpn = false;

	for (const char **a = conf->alpn_list; a != NULL && *a != NULL; a += 1) {
		if (strcmp(*a, alp) == 0) {
			has_alpn = true;
			break;
		}
	}

	if (!has_alpn) {
		// ALP verification is disabled.
		return true;
	}
	return prne_nstreq(
		mbedtls_ssl_get_alpn_protocol(ctx),
		alp);
}

void prne_mbedtls_perror (const int err, const char *s) {
	char str[256];

	str[0] = 0;
	mbedtls_strerror(err, str, sizeof(str));

	fprintf(stderr, "%s: %s\n", s, str);
}
