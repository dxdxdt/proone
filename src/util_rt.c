#include "util_rt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <mbedtls/base64.h>


void prne_ok_or_die (const int ret) {
	if (ret < 0) {
		abort();
	}
}

void prne_true_or_die (const bool ret) {
	if (!ret) {
		abort();
	}
}

void prne_empty_func (void) {}

bool prne_is_nonblock_errno (void) {
	switch (errno) {
#if EAGAIN == EWOULDBLOCK
	case EAGAIN:
#else
	case EAGAIN:
	case EWOULDBLOCK:
#endif
	case EINPROGRESS:
		return true;
	}
	return false;
}

void prne_die_not_nonblock_err (void) {
	if (!prne_is_nonblock_errno()) {
		abort();
	}
}

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

void *prne_malloc (const size_t se, const size_t cnt) {
	size_t size;

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

void prne_free (void *ptr) {
	free(ptr);
}

size_t prne_getpagesize (void) {
	long ret;

	ret = sysconf(_SC_PAGESIZE);
	if (ret > 0) {
		return ret;
	}

	return 4096;
}

bool prne_nstreq (const char *a, const char *b) {
	if (a == NULL && b == NULL) {
		return true;
	}
	if (a == NULL || b == NULL) {
		return false;
	}
	return strcmp(a, b) == 0;
}

size_t prne_nstrlen (const char *s) {
	return s == NULL ? 0 : strlen(s);
}

void prne_rnd_anum_str (mbedtls_ctr_drbg_context *rnd, char *str, const size_t len) {
	static const char SET[] = "qwertyuiopasdfghjklzxcvbnm0123456789";
	size_t i = 0;
	uint32_t n;

	if (len >= 4) {
		for (; i < len / 4 * 4; i += 4) {
			mbedtls_ctr_drbg_random(rnd, (uint8_t*)&n, sizeof(n));
			str[i + 0] = SET[((uint8_t*)&n)[0] % sizeof(SET)];
			str[i + 1] = SET[((uint8_t*)&n)[1] % sizeof(SET)];
			str[i + 2] = SET[((uint8_t*)&n)[2] % sizeof(SET)];
			str[i + 3] = SET[((uint8_t*)&n)[3] % sizeof(SET)];
		}
	}
	if (i < len) {
		mbedtls_ctr_drbg_random(rnd, (uint8_t*)&n, sizeof(n));
		for (; i < len; i += 1) {
			str[i] = SET[((uint8_t*)&n)[i % 4] % sizeof(SET)];
		}
	}
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
		if (isspace(str[i])) {
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

bool prne_uuid_fromstr (const char *str, uint8_t *out) {
	return sscanf(str, "%hhx%hhx%hhx%hhx-%hhx%hhx-%hhx%hhx-%hhx%hhx-%hhx%hhx%hhx%hhx%hhx%hhx",
		&out[0],
		&out[1],
		&out[2],
		&out[3],
		&out[4],
		&out[5],
		&out[6],
		&out[7],
		&out[8],
		&out[9],
		&out[10],
		&out[11],
		&out[12],
		&out[13],
		&out[14],
		&out[15]) == 16;
}

bool prne_uuid_tostr (const uint8_t *in, const size_t out_size, char *out) {
	return snprintf(out, out_size, "%hhx%hhx%hhx%hhx-%hhx%hhx-%hhx%hhx-%hhx%hhx-%hhx%hhx%hhx%hhx%hhx%hhx",
		in[0],
		in[1],
		in[2],
		in[3],
		in[4],
		in[5],
		in[6],
		in[7],
		in[8],
		in[9],
		in[10],
		in[11],
		in[12],
		in[13],
		in[14],
		in[15]) == 16;
}


struct timespec prne_sub_timespec (const struct timespec a, const struct timespec b) {
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

int prne_cmp_timespec (const struct timespec a, const struct timespec b) {
	if (a.tv_sec < b.tv_sec) {
		return -1;
	}
	else if (a.tv_sec > b.tv_sec) {
		return 1;
	}

	return a.tv_nsec < b.tv_nsec ? -1 : a.tv_nsec > b.tv_nsec ? 1 : 0;
}

struct timespec prne_min_timespec (const struct timespec a, const struct timespec b) {
	return prne_cmp_timespec(a, b) < 0 ? a : b;
}

struct timespec prne_max_timespec (const struct timespec a, const struct timespec b) {
	return prne_cmp_timespec(a, b) > 0 ? a : b;
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

	if (mbedtls_base64_encode((uint8_t*)ret, ret_size, &ret_size, data, size) < 0) {
		prne_free(ret);
		return NULL;
	}

	return ret;
}

bool prne_dec_base64_mem (const char *str, const size_t str_len, uint8_t **data, size_t *size) {
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

	if (mbedtls_base64_decode(ret, ret_size, &ret_size, (uint8_t*)str, str_len) < 0) {
		prne_free(ret);
		errno = EINVAL;
		return false;
	}

	*data = ret;
	*size = ret_size;
	return true;
}

void prne_init_stdin_base64_rf_ctx (prne_stdin_base64_rf_ctx_t *ctx) {
	ctx->line_len = 0;
	ctx->out_len = 0;
}

void prne_free_stdin_base64_rf_ctx (prne_stdin_base64_rf_ctx_t *ctx) {
	ctx->line_len = 0;
	ctx->out_len = 0;
}

prne_pack_ret_t prne_stdin_base64_rf (void *in_ctx, const size_t req, uint8_t *out, size_t *out_len) {
	prne_stdin_base64_rf_ctx_t *ctx = (prne_stdin_base64_rf_ctx_t*)in_ctx;
	size_t rem = req, have;
	prne_pack_ret_t ret;

	ret.rc = PRNE_PACK_RC_OK;
	ret.err = 0;
	*out_len = 0;

	while (true) {
		have = prne_op_min(rem, ctx->out_len);
		memcpy(out, ctx->out_buf, have);
		memmove(ctx->out_buf, ctx->out_buf + have, ctx->out_len - have);
		rem -= have;
		ctx->out_len -= have;
		out += have;
		*out_len += have;

		if (rem == 0) {
			break;
		}

		if (fgets(ctx->line_buf, sizeof(ctx->line_buf), stdin) == NULL) {
			if (feof(stdin)) {
				break;
			}
			ret.rc = PRNE_PACK_RC_ERRNO;
			ret.err = errno;
			break;
		}
		ctx->line_len = prne_str_shift_spaces(ctx->line_buf, strlen(ctx->line_buf));

		if ((ret.err = mbedtls_base64_decode(ctx->out_buf, sizeof(ctx->out_buf), &ctx->out_len, (unsigned char*)ctx->line_buf, ctx->line_len)) != 0) {
			ret.rc = PRNE_PACK_RC_MBEDTLS_ERR;
			break;
		}
	}

	return ret;
}

bool prne_set_pipe_size (const int fd, const int size) {
	return 
#if defined(F_SETPIPE_SZ)
		fcntl(fd, F_SETPIPE_SZ, size) == 0
#elif defined(FIONREAD)
		ioctl(fd, FIONREAD, &size) == 0
#endif
		;
}
