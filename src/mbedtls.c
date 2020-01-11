#include "mbedtls.h"

#include <unistd.h>
#include <errno.h>

#include <mbedtls/ssl.h>


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
