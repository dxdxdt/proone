#include "util_rt.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <mbedtls/base64.h>
#include <pthsem.h>


void prne_empty_func (void) {}

void prne_close (const int fd) {
	if (fd >= 0) {
		close(fd);
	}
}

void prne_shutdown (const int fd, const int how) {
	if (fd >= 0) {
		shutdown(fd, how);
	}
}

bool prne_sck_fcntl (const int fd) {
	fcntl(fd, F_SETFD, FD_CLOEXEC);
	return fcntl(fd, F_SETFL, O_NONBLOCK) == 0;
}

int prne_chfd (const int old, const int ny) {
	int ret;

	if (old == ny) {
		return old;
	}

	ret = dup2(old, ny);
	if (ret < 0) {
		return ret;
	}
	close(old);

	return ret;
}

void prne_memzero(void *addr, const size_t len) {
	memset(addr, 0, len);
}

void *prne_malloc (const size_t se, const size_t cnt) {
	size_t size;

	if (se == 0) {
		return NULL;
	}
	if (SIZE_MAX / se < cnt) {
		errno = ENOMEM;
		return NULL;
	}

	size = cnt * se;
	if (size == 0) {
		return NULL;
	}

	return malloc(size);
}

void *prne_realloc (void *ptr, const size_t se, const size_t cnt) {
	size_t size;

	if (se == 0) {
		prne_free(ptr);
		return NULL;
	}
	if (SIZE_MAX / se < cnt) {
		errno = ENOMEM;
		return NULL;
	}

	size = cnt * se;
	if (size == 0) {
		prne_free(ptr);
		return NULL;
	}

	return realloc(ptr, size);
}

void *prne_calloc (const size_t se, const size_t cnt) {
	if (se == 0 || cnt == 0) {
		return NULL;
	}

	return calloc(se, cnt);
}

char *prne_alloc_str (const size_t len) {
	if (len == SIZE_MAX) {
		errno = ENOMEM;
		return NULL;
	}
	return (char*)prne_malloc(1, len + 1);
}

char *prne_dup_str (const char *str) {
	const size_t len = prne_nstrlen(str);
	char *ret = prne_alloc_str(len);

	if (ret == NULL) {
		return NULL;
	}
	memcpy(ret, str, len + 1);

	return ret;
}

void prne_free (void *ptr) {
	free(ptr);
}

size_t prne_getpagesize (void) {
	long ret;

	ret = sysconf(_SC_PAGESIZE);
	prne_massert(ret > 0, "sysconf(_SC_PAGESIZE) failed.");

	return (size_t)ret;
}

bool prne_own_realloc (
	void **p,
	bool *ownership,
	const size_t se,
	size_t *old,
	const size_t req)
{
	void *ny = prne_realloc(
		*ownership ? *p : NULL,
		se,
		req);

	if (req > 0 && ny == NULL) {
		return false;
	}

	if (!*ownership) {
		memcpy(ny, *p, prne_op_min(*old, req) * se);
	}
	*p = ny;
	*old = req;
	*ownership = true;

	return true;
}

char prne_ctoupper (const char c) {
	if ('a' <= c && c <= 'z') {
		return c - ('a' - 'A');
	}
	return c;
}

char prne_ctolower (const char c) {
	if ('A' <= c && c <= 'Z') {
		return c + ('a' - 'A');
	}
	return c;
}

bool prne_cisspace (const char c) {
	switch (c) {
	case ' ':
	case '\f':
	case '\n':
	case '\r':
	case '\t':
	case '\v':
		return true;
	}
	return false;
}

bool prne_cisprint (const char c) {
	return 32 <= c && c < 127;
}

bool prne_nstreq (const char *a, const char *b) {
	return strcmp(a == NULL ? "" : a, b == NULL ? "" : b) == 0;
}

size_t prne_nstrlen (const char *s) {
	return s == NULL ? 0 : strlen(s);
}

char *prne_strnchr (const char *p, const char c, const size_t n) {
	size_t i;

	for (i = 0; i < n; i += 1) {
		if (p[i] == c) {
			return (char*)p + i;
		}
		else if (p[i] == 0) {
			return NULL;
		}
	}

	return NULL;
}

size_t prne_str_shift_spaces (char *str, const size_t len) {
	size_t i, ret = len;

	for (i = 0; i < ret; ) {
		if (prne_cisspace(str[i])) {
			if (i + 1 >= ret) {
				// last trailing whitespace
				ret -= 1;
				break;
			}
			memmove(str + i, str + i + 1, ret - i - 1);
			ret -= 1;
		}
		else {
			i += 1;
		}
	}

	return ret;
}

bool prne_chkcstr (const char *str, bool(*chk_f)(const char)) {
	bool ret = true;

	for (; *str != 0 && ret; str += 1) {
		ret &= chk_f(*str);
	}
	return ret;
}

bool prne_chkcmem (const void *m, size_t len, bool(*chk_f)(const char)) {
	bool ret = true;

	for (size_t i = 0; i < len && ret; i += 1) {
		ret &= chk_f(((uint8_t*)m)[i]);
	}
	return ret;
}

void prne_transstr (char *str,  int(*trans_f)(int)) {
	for (; *str != 0; str += 1) {
		*str = (char)trans_f(*str);
	}
}

void prne_transcstr (char *str, char(*trans_f)(char)) {
	for (; *str != 0; str += 1) {
		*str = trans_f(*str);
	}
}

void prne_transmem (void *m, size_t len, int(*trans_f)(int)) {
	for (size_t i = 0; i < len; i += 1) {
		((uint8_t*)m)[i] = (uint8_t)trans_f(((uint8_t*)m)[i]);
	}
}

void prne_transcmem (void *m, size_t len, char(*trans_f)(char)) {
	for (size_t i = 0; i < len; i += 1) {
		((uint8_t*)m)[i] = (uint8_t)trans_f(((uint8_t*)m)[i]);
	}
}

void *prne_memrchr (
	const void *haystack,
	const int c,
	const size_t hs_len)
{
	for (size_t i = 0, idx = hs_len - 1; i < hs_len; i += 1, idx -= 1) {
		if (((const uint8_t*)haystack)[idx] == (uint8_t)c) {
			return (uint8_t*)haystack + idx;
		}
	}
	return NULL;
}

void *prne_memrmem (
	const void *in_haystack,
	const size_t in_hs_len,
	const void *const needle,
	const size_t n_len)
{
	const uint8_t *haystack = (const uint8_t *)in_haystack - n_len + in_hs_len;
	size_t hs_len = in_hs_len;

	if (n_len == 0) {
		return NULL;
	}

	while (hs_len >= n_len) {
		if (memcmp(haystack, needle, n_len) == 0) {
			return (void*)haystack;
		}
		haystack -= 1;
		hs_len -= 1;
	}

	return NULL;
}

void *prne_memmem (
	const void *in_haystack,
	const size_t in_hs_len,
	const void *const needle,
	const size_t n_len)
{
	const uint8_t *haystack = (const uint8_t *)in_haystack;
	size_t hs_len = in_hs_len;

	if (n_len == 0) {
		return NULL;
	}

	while (hs_len >= n_len) {
		if (memcmp(haystack, needle, n_len) == 0) {
			return (void*)haystack;
		}
		haystack += 1;
		hs_len -= 1;
	}

	return NULL;
}

char *prne_build_str (const char **const arr, const size_t cnt) {
	return prne_rebuild_str(NULL, arr, cnt);
}

char *prne_rebuild_str (void *prev, const char **const arr, const size_t cnt) {
	char *ret, *p;
	size_t len;

	len = 0;
	for (size_t i = 0; i < cnt; i += 1) {
		len += prne_nstrlen(arr[i]);
	}
	ret = prne_realloc(prev, 1, len + 1);
	if (ret == NULL) {
		return NULL;
	}

	p = ret;
	for (size_t i = 0; i < cnt; i += 1) {
		len = prne_nstrlen(arr[i]);
		memcpy(p, arr[i], len);
		p += len;
	}
	*p = 0;

	return ret;
}

void prne_strzero (char *str) {
	for (; *str != 0; str += 1) {
		*str = 0;
	}
}

bool prne_hex_fromstr (const char *str, uint_fast8_t *out) {
	static const uint_fast8_t shift[2] = { 4, 0 };
	size_t i;
	uint_fast8_t ret[2];
	char c;

	for (i = 0; i < 2; i += 1) {
		c = str[i];

		if ('0' <= c && c <= '9') {
			ret[i] = (c - '0') << shift[i];
		}
		else if ('a' <= c && c <= 'f') {
			ret[i] = (c - 'a' + 10) << shift[i];
		}
		else if ('A' <= c && c <= 'F') {
			ret[i] = (c - 'A' + 10) << shift[i];
		}
		else {
			errno = EINVAL;
			return false;
		}
	}

	*out = ret[0] | ret[1];
	return true;
}

void prne_hex_tochar (const uint_fast8_t in, char *out, const bool upper) {
	static const uint_fast8_t mask[2] = { 0xF0, 0x0F };
	static const uint_fast8_t shift[2] = { 4, 0 };
	size_t i;
	uint_fast8_t v;

	for (i = 0; i < 2; i += 1) {
		v = (in & mask[i]) >> shift[i];
		if (v <= 9) {
			out[i] = '0' + v;
		}
		else {
			out[i] = (upper ? 'A' : 'a') + (v - 10);
		}
	}
}

bool prne_uuid_fromstr (const char *str, uint8_t *out) {
	size_t i, ptr = 0;

	if (prne_nstrlen(str) != 36) {
		errno = EINVAL;
		return false;
	}

	for (i = 0; i < 36;) {
		switch (i) {
		case 8:
		case 13:
		case 18:
		case 23:
			if (str[i] != '-') {
				errno = EINVAL;
				return false;
			}
			i += 1;
			break;
		default:
			if (!prne_hex_fromstr(str + i, out + ptr)) {
				return false;
			}
			ptr += 1;
			i += 2;
		}
	}

	return true;
}

void prne_uuid_tostr (const uint8_t *in, char *out) {
	size_t i, ptr = 0;

	for (i = 0; i < 16; i += 1) {
		prne_hex_tochar(in[i], out + ptr, false);

		switch (i) {
		case 3:
		case 5:
		case 7:
		case 9:
			out[ptr + 2] = '-';
			ptr += 3;
			break;
		default:
			ptr += 2;
		}
	}
	out[ptr] = 0;
}

int prne_cmp_uuid_asc (const void *a, const void *b) {
	return memcmp(a, b, 16);
}
int prne_cmp_uuid_desc (const void *a, const void *b) {
	return prne_cmp_uuid_asc(a, b) * -1;
}

struct timespec prne_add_timespec (
	const struct timespec a,
	const struct timespec b)
{
	struct timespec ret;

	ret.tv_nsec = a.tv_nsec + b.tv_nsec;
	ret.tv_sec = a.tv_sec + b.tv_sec + (ret.tv_nsec / 1000000000);
	ret.tv_nsec %= 1000000000;

	return ret;
}

struct timespec prne_sub_timespec (
	const struct timespec a,
	const struct timespec b)
{
	struct timespec ret;

	if (a.tv_nsec < b.tv_nsec) {
		ret.tv_sec = a.tv_sec - 1 - b.tv_sec;
		ret.tv_nsec = 1000000000 + a.tv_nsec - b.tv_nsec;
	}
	else {
		ret.tv_sec = a.tv_sec - b.tv_sec;
		ret.tv_nsec = a.tv_nsec - b.tv_nsec;
	}

	return ret;
}

double prne_real_timespec (const struct timespec ts) {
	return (double)ts.tv_sec + (double)ts.tv_nsec / 1000000000.0;
}

long prne_timespec_ms (const struct timespec ts) {
	return
		ts.tv_sec * 1000 +
		ts.tv_nsec / 1000000;
}

struct timespec prne_ms_timespec (const long ms) {
	struct timespec ret;

	ret.tv_sec = ms / 1000;
	ret.tv_nsec = (ms - ret.tv_sec * 1000) * 1000000;

	return ret;
}

int prne_cmp_timespec (const struct timespec a, const struct timespec b) {
	if (a.tv_sec < b.tv_sec) {
		return -1;
	}
	else if (a.tv_sec > b.tv_sec) {
		return 1;
	}

	return a.tv_nsec < b.tv_nsec ? -1 : a.tv_nsec > b.tv_nsec ? 1 : 0;
}

struct timespec prne_min_timespec (
	const struct timespec a,
	const struct timespec b)
{
	return prne_cmp_timespec(a, b) < 0 ? a : b;
}

struct timespec prne_max_timespec (
	const struct timespec a,
	const struct timespec b)
{
	return prne_cmp_timespec(a, b) > 0 ? a : b;
}

struct timespec prne_gettime (const clockid_t cid) {
	struct timespec ret;
	prne_assert(clock_gettime(cid, &ret) == 0);
	return ret;
}

struct timeval prne_ts2tv (const struct timespec ts) {
	struct timeval ret;
	ret.tv_sec = ts.tv_sec;
	ret.tv_usec = ts.tv_nsec / 1000;
	return ret;
}

struct timeval prne_ms_timeval (const long ms) {
	struct timeval ret;
	ret.tv_sec = ms / 1000;
	ret.tv_usec = (ms - ret.tv_sec * 1000) * 1000;
	return ret;
}

char *prne_enc_base64_mem (const uint8_t *data, const size_t size) {
	size_t ret_size;
	char *ret;

	mbedtls_base64_encode(NULL, 0, &ret_size, data, size);
	if (ret_size == 0) {
		return NULL;
	}
	ret = (char*)prne_malloc(1, ret_size);
	if (ret == NULL) {
		return NULL;
	}

	if (mbedtls_base64_encode(
		(uint8_t*)ret,
		ret_size,
		&ret_size,
		data,
		size) < 0)
	{
		prne_free(ret);
		return NULL;
	}

	return ret;
}

bool prne_dec_base64_mem (
	const char *str,
	const size_t str_len,
	uint8_t **data,
	size_t *size)
{
	size_t ret_size;
	uint8_t *ret;

	mbedtls_base64_decode(NULL, 0, &ret_size, (uint8_t*)str, str_len);
	if (ret_size == 0) {
		*data = NULL;
		*size = 0;
		return true;
	}
	ret = prne_malloc(1, ret_size);
	if (ret == NULL) {
		return false;
	}

	if (mbedtls_base64_decode(
		ret,
		ret_size,
		&ret_size,
		(uint8_t*)str,
		str_len) < 0)
	{
		prne_free(ret);
		errno = EINVAL;
		return false;
	}

	*data = ret;
	*size = ret_size;
	return true;
}

ssize_t prne_geturandom (void *buf, const size_t len) {
	const int fd = open("/dev/urandom", O_RDONLY);
	ssize_t ret;
	int save_errno;

	if (fd < 0) {
		return -1;
	}
	ret = read(fd, buf, len);
	save_errno = errno;
	close(fd);
	errno = save_errno;

	return ret;
}

void prne_bitop_and (
	const uint8_t *a,
	const uint8_t *b,
	uint8_t *c,
	const size_t len)
{
	for (size_t i = 0; i < len; i += 1) {
		c[i] = a[i] & b[i];
	}
}

void prne_bitop_or (
	const uint8_t *a,
	const uint8_t *b,
	uint8_t *c,
	const size_t len)
{
	for (size_t i = 0; i < len; i += 1) {
		c[i] = a[i] | b[i];
	}
}

void prne_bitop_inv (
	const uint8_t *x,
	uint8_t *y,
	const size_t len)
{
	for (size_t i = 0; i < len; i += 1) {
		y[i] = ~x[i];
	}
}
