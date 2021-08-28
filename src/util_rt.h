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
char *prne_realloc_str (char *old, const size_t len);
char *prne_dup_str (const char *str);
char *prne_redup_str (char *old, const char *str);
void prne_free (void *ptr);
size_t prne_getpagesize (void);

bool prne_own_realloc (
	void **p,
	bool *ownership,
	const size_t se,
	size_t *old,
	const size_t req);

/* Locale "C" character category functions
*/
char prne_ctoupper (const char c);
char prne_ctolower (const char c);
bool prne_cisspace (const char c);
bool prne_cisprint (const char c);

bool prne_ciszero (const char c);

bool prne_nstreq (const char *a, const char *b);
size_t prne_nstrlen (const char *s);
char *prne_strnchr (const char *p, const char c, const size_t n);
size_t prne_str_shift_spaces (char *str, const size_t len);
bool prne_chkcstr (const char *str, bool(*chk_f)(const char));
bool prne_chkcmem (const void *m, size_t len, bool(*chk_f)(const char));
void prne_transstr (char *str,  int(*trans_f)(int));
void prne_transcstr (char *str, char(*trans_f)(char));
void prne_transmem (void *m, size_t len, int(*trans_f)(int));
void prne_transcmem (void *m, size_t len, char(*trans_f)(char));
void *prne_memrchr (
	const void *haystack,
	const int c,
	const size_t hs_len);
void *prne_memrmem (
	const void *haystack,
	const size_t hs_len,
	const void *const needle,
	const size_t n_len);
void *prne_memmem (
	const void *haystack,
	const size_t hs_len,
	const void *const needle,
	const size_t n_len);
char *prne_build_str (const char **const arr, const size_t cnt);
char *prne_rebuild_str (void *prev, const char **const arr, const size_t cnt);
void prne_strzero (char *str);

bool prne_hex_fromstr (const char *str, uint_fast8_t *out);
void prne_hex_tochar (const uint_fast8_t in, char *out, const bool upper);

/*
* \param str: at least 36 bytes
* \param out: at least 16 bytes
*/
bool prne_uuid_fromstr (const char *str, uint8_t *out);
/*
* \param in: at least 16 bytes
* \param out: at least 37 bytes (null-terminated)
*/
void prne_uuid_tostr (const uint8_t *in, char *out);

int prne_cmp_uuid_asc (const void *a, const void *b);
int prne_cmp_uuid_desc (const void *a, const void *b);

struct timespec prne_add_timespec (
	const struct timespec a,
	const struct timespec b);
struct timespec prne_sub_timespec (
	const struct timespec a,
	const struct timespec b);
double prne_real_timespec (const struct timespec ts);
long prne_timespec_ms (const struct timespec ts);
struct timespec prne_ms_timespec (const long ms);
int prne_cmp_timespec (const struct timespec a, const struct timespec b);
struct timespec prne_min_timespec (
	const struct timespec a,
	const struct timespec b);
struct timespec prne_max_timespec (
	const struct timespec a,
	const struct timespec b);
struct timespec prne_gettime (const clockid_t cid);

struct timeval prne_ts2tv (const struct timespec ts);
struct timeval prne_ms_timeval (const long ms);

char *prne_enc_base64_mem (const uint8_t *data, const size_t size);
bool prne_dec_base64_mem (
	const char *str,
	const size_t str_len,
	uint8_t **data,
	size_t *size);

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
