/** \file
 * \brief The MbedTLS utility functions.
 */
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

/** \def prne_mbedtls_is_nberr
 * \brief Test whether \p expr is a non-blocking operation error.
 */
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
/**
 * \brief Workaround for blocking issue - getrandom() blocks. Remove the
 *	\c mbedtls_platform_entropy_poll() source and add Proone's own entropy
 *	sources.
 * \warning Proone removes the entropy source because the point of Proone using
 *	TLS is only for obsecurity, not security. Ordinary applications should never
 *	do this! From Proone's perspective, using \c getrandom() is unacceptable as
 *	it could block the calling thread.
 *	https://github.com/ARMmbed/mbedtls/issues/3551
 */
void prne_mbedtls_entropy_init (mbedtls_entropy_context *ctx);

/* Convenience functions */

/**
 * \brief Process functions like mbedtls_ssl_handshake() and
 *	mbedtls_ssl_close_notify(), handling non-blocking error on the fly.
 * \param ssl The pointer to the SSL context object.
 * \param mbedtls_f The MbedTLS function to handle.
 * \param fd The open file descriptor for the connection.
 * \param ev The event object to poll() with.
 * \param[out] f_ret The pointer to an \c int for the value returned from
 *	\p mbedtls_f (optional)
 * \retval true if the function returned zero, meaning successful operation.
 * \retval false if the function returned a negative value.
 */
bool prne_mbedtls_pth_handle (
	mbedtls_ssl_context *ssl,
	int(*mbedtls_f)(mbedtls_ssl_context*),
	const int fd,
	pth_event_t ev,
	int *f_ret);
/**
 * \brief Find the specified ALP string in the negotiated ALPs.
 * \param conf The pointer to the SSL config object.
 * \param ctx The pointer to the SSL context object.
 * \param alp The pointer to the null-terminated ALP string to look for.
 * \retval true if the ALP string is not in the SSL config or the ALP is found
 *	in the SSL config and is one of the negotiated ALPs for the connection.
 * \retval false otherwise - the ALP is configured and not negotiated for the
 *	connection.
 * \note The function assumes that the ALPN is disabled and will return true if
 *	the ALP is not configured!
 */
bool prne_mbedtls_verify_alp (
	const mbedtls_ssl_config *conf,
	const mbedtls_ssl_context *ctx,
	const char *alp);
/**
 * \brief perror() for MbedTLS errors.
 * \param err The MbedTLS error returned from the functions.
 * \param s The messsage to print.
 * \see mbedtls_strerror()
 */
void prne_mbedtls_perror (const int err, const char *s);
