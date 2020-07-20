#pragma once
#include "pack.h"

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include <mbedtls/ctr_drbg.h>


struct prne_stdin_base64_rf_ctx;
typedef struct prne_stdin_base64_rf_ctx prne_stdin_base64_rf_ctx_t;

struct prne_stdin_base64_rf_ctx {
	size_t line_len;
	size_t out_len;
	char line_buf[78];
	uint8_t out_buf[58];
};


#if 0
bool prne_strendsw (const char *str, const char *w) {
	const size_t len_str = strlen(str);
	const size_t len_w = strlen(w);

	if (len_str < len_w) {
		return false;
	}
	return strcmp(str + (len_str - len_w), w) == 0;
}
#endif

void prne_ok_or_die (const int ret);
void prne_true_or_die (const bool ret);
void prne_empty_func (void);
bool prne_is_nonblock_errno (void);
void prne_die_not_nonblock_err (void);
void prne_close (const int fd);
void prne_shutdown (const int fd, const int how);

void *prne_malloc (const size_t se, const size_t cnt);
void *prne_realloc (void *ptr, const size_t se, const size_t cnt);
void *prne_calloc (const size_t se, const size_t cnt);
char *prne_alloc_str (const size_t len);
void prne_free (void *ptr);
size_t prne_getpagesize (void);

bool prne_nstreq (const char *a, const char *b);
size_t prne_nstrlen (const char *s);
void prne_rnd_anum_str (mbedtls_ctr_drbg_context *rnd, char *str, const size_t len);
char *prne_strnchr (const char *p, const char c, const size_t n);
size_t prne_str_shift_spaces (char *str, const size_t len);

bool prne_hex_fromstr (const char *str, uint_fast8_t *out);
void prne_hex_tochar (const uint_fast8_t in, char *out, const bool upper);

bool prne_uuid_fromstr (const char *str, uint8_t *out);
void prne_uuid_tostr (const uint8_t *in, char *out);

struct timespec prne_sub_timespec (const struct timespec a, const struct timespec b);
double prne_real_timespec (const struct timespec ts);
int prne_cmp_timespec (const struct timespec a, const struct timespec b);
struct timespec prne_min_timespec (const struct timespec a, const struct timespec b);
struct timespec prne_max_timespec (const struct timespec a, const struct timespec b);

char *prne_enc_base64_mem (const uint8_t *data, const size_t size);
bool prne_dec_base64_mem (const char *str, const size_t str_len, uint8_t **data, size_t *size);
void prne_init_stdin_base64_rf_ctx (prne_stdin_base64_rf_ctx_t *ctx);
void prne_free_stdin_base64_rf_ctx (prne_stdin_base64_rf_ctx_t *ctx);
prne_pack_ret_t prne_stdin_base64_rf (void *ctx, const size_t req, uint8_t *out, size_t *out_len);

bool prne_set_pipe_size (const int fd, const int size);
