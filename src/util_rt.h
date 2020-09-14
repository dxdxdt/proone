#pragma once
#include "pack.h"

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include <sys/poll.h>

#include <mbedtls/ctr_drbg.h>


void prne_empty_func (void);
void prne_close (const int fd);
void prne_shutdown (const int fd, const int how);
/* prne_sck_fcntl(fd)
*
* Sets FD_CLOEXEC and O_NONBLOCK. Failure to set FD_CLOEXEC is ignored.
*/
bool prne_sck_fcntl (const int fd);
int prne_chfd (const int old, const int ny);

void prne_memzero(void *addr, const size_t len);

void *prne_malloc (const size_t se, const size_t cnt);
void *prne_realloc (void *ptr, const size_t se, const size_t cnt);
void *prne_calloc (const size_t se, const size_t cnt);
char *prne_alloc_str (const size_t len);
void prne_free (void *ptr);
size_t prne_getpagesize (void);

bool prne_own_realloc (
	void **p,
	bool *ownership,
	const size_t se,
	size_t *old,
	const size_t req);

bool prne_nstreq (const char *a, const char *b);
size_t prne_nstrlen (const char *s);
void prne_rnd_anum_str (mbedtls_ctr_drbg_context *rnd, char *str, const size_t len);
char *prne_strnchr (const char *p, const char c, const size_t n);
size_t prne_str_shift_spaces (char *str, const size_t len);
void prne_transstr (char *str,  int(*trans_f)(int));

bool prne_hex_fromstr (const char *str, uint_fast8_t *out);
void prne_hex_tochar (const uint_fast8_t in, char *out, const bool upper);

bool prne_uuid_fromstr (const char *str, uint8_t *out);
void prne_uuid_tostr (const uint8_t *in, char *out);

struct timespec prne_add_timespec (const struct timespec a, const struct timespec b);
struct timespec prne_sub_timespec (const struct timespec a, const struct timespec b);
double prne_real_timespec (const struct timespec ts);
struct timespec prne_ms_timespec (const long ms);
int prne_cmp_timespec (const struct timespec a, const struct timespec b);
struct timespec prne_min_timespec (const struct timespec a, const struct timespec b);
struct timespec prne_max_timespec (const struct timespec a, const struct timespec b);
struct timespec prne_gettime (const clockid_t cid);

struct timeval prne_ts2tv (const struct timespec ts);
struct timeval prne_ms_timeval (const long ms);

char *prne_enc_base64_mem (const uint8_t *data, const size_t size);
bool prne_dec_base64_mem (const char *str, const size_t str_len, uint8_t **data, size_t *size);

// getrandom polyfill
ssize_t prne_geturandom (void *buf, const size_t len);

void prne_bitop_and (
	const uint8_t *a,
	const uint8_t *b,
	uint8_t *c,
	const size_t len);
void prne_bitop_or (
	const uint8_t *a,
	const uint8_t *b,
	uint8_t *c,
	const size_t len);
void prne_bitop_inv (
	const uint8_t *x,
	uint8_t *y,
	const size_t len);
