#include "mbedtls.h"
#include "util_ct.h"
#include "util_rt.h"

#include <errno.h>
#include <string.h>

#include <unistd.h>
#include <fcntl.h>

#include <mbedtls/ssl.h>
#include <mbedtls/entropy_poll.h>


int prne_mbedtls_x509_crt_verify_cb (void *param, mbedtls_x509_crt *crt, int crt_depth, uint32_t *flags) {
	*flags &= ~MBEDTLS_X509_BADCERT_EXPIRED;
	return 0;
}

int prne_mbedtls_ssl_send_cb (void *ctx, const unsigned char *buf, size_t len) {
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

static int prne_mbedtls_entropy_urand_src_f (void *data, unsigned char *output, size_t len, size_t *olen) {
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

static int prne_mbedtls_entropy_proc_src_f (void *data, unsigned char *output, size_t len, size_t *olen) {
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

	// Remove platform source, which could call getrandom()
	for (int i = 0; i < ctx->source_count; i += 1) {
		if (ctx->source[i].f_source == mbedtls_platform_entropy_poll) {
			memmove(ctx->source + i, ctx->source + i + 1, sizeof(mbedtls_entropy_source_state) * (ctx->source_count - i - 1));
			ctx->source_count -= 1;
			// Add our own implementation as the one just got removed could be the only source.
			mbedtls_entropy_add_source(ctx, prne_mbedtls_entropy_urand_src_f, NULL, MBEDTLS_ENTROPY_MIN_PLATFORM, MBEDTLS_ENTROPY_SOURCE_STRONG);
			mbedtls_entropy_add_source(ctx, prne_mbedtls_entropy_proc_src_f, NULL, sizeof(ent_buf_t), MBEDTLS_ENTROPY_SOURCE_STRONG);
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
			pollret = pth_poll_ev(&pfd, 1, -1, ev);
			if (pollret < 0) {
				if (errno == EINTR) {
					continue;
				}
				else {
					return false;
				}
			}
			if (pollret == 0 || pth_event_status(ev) == PTH_STATUS_OCCURRED) {
				return false;
			}
		} while (false);
	}
}
