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
#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>

#include <poll.h>

#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/entropy.h>
#include <pthsem.h>

#define prne_mbedtls_is_nberr(expr) \
	((expr) == MBEDTLS_ERR_SSL_WANT_READ || \
		(expr) == MBEDTLS_ERR_SSL_WANT_WRITE)


// Callback that masks `MBEDTLS_X509_BADCERT_EXPIRED`
int prne_mbedtls_x509_crt_verify_cb (
	void *param,
	mbedtls_x509_crt *crt,
	int crt_depth,
	uint32_t *flags);
int prne_mbedtls_ssl_send_cb (void *ctx, const unsigned char *buf, size_t len);
int prne_mbedtls_ssl_recv_cb (void *ctx, unsigned char *buf, size_t len);
/*
* Workaround for a bug - getrandom() blocks
*/
void prne_mbedtls_entropy_init (mbedtls_entropy_context *ctx);

/* Convenience Functions
*/

// Handles mbedtls_ssl_handshake(), mbedtls_ssl_close_notify()
bool prne_mbedtls_pth_handle (
	mbedtls_ssl_context *ssl,
	int(*mbedtls_f)(mbedtls_ssl_context*),
	const int fd,
	pth_event_t ev);

bool prne_mbedtls_verify_alp (
	const mbedtls_ssl_config *conf,
	const mbedtls_ssl_context *ctx,
	const char *alp);

void prne_mbedtls_perror (const int err, const char *s);
