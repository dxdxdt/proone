#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include <mbedtls/x509_crt.h>


// Callback that masks `MBEDTLS_X509_BADCERT_EXPIRED`
int prne_mbedtls_x509_crt_verify_cb (void *param, mbedtls_x509_crt *crt, int crt_depth, uint32_t *flags);
int prne_mbedtls_ssl_send_cb (void *ctx, const unsigned char *buf, size_t len);
int prne_mbedtls_ssl_recv_cb (void *ctx, unsigned char *buf, size_t len);
