#pragma once
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include <mbedtls/ctr_drbg.h>


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
void prne_free (void *ptr);

void prne_rnd_anum_str (mbedtls_ctr_drbg_context *rnd, char *str, const size_t len);
char *prne_strnchr (const char *p, const char c, const size_t n);
size_t prne_str_shift_spaces (char *str, const size_t len);

struct timespec prne_sub_timespec (const struct timespec a, const struct timespec b);
double prne_real_timespec (const struct timespec ts);
int prne_cmp_timespec (const struct timespec a, const struct timespec b);
struct timespec prne_min_timespec (const struct timespec a, const struct timespec b);
struct timespec prne_max_timespec (const struct timespec a, const struct timespec b);

char *prne_enc_base64_mem (const uint8_t *data, const size_t size);
bool prne_dec_base64_mem (const char *str, const size_t str_len, uint8_t **data, size_t *size);

bool prne_set_pipe_size (const int fd, const int size);
