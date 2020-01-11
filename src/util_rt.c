#include "util_rt.h"

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
	if (SIZE_MAX / se < cnt) {
		errno = ENOMEM;
		return NULL;
	}
	return malloc(cnt * se);
}

void *prne_realloc (void *ptr, const size_t se, const size_t cnt) {
	if (SIZE_MAX / se < cnt) {
		errno = ENOMEM;
		return NULL;
	}
	return realloc(ptr, se * cnt);
}

void *prne_calloc (const size_t se, const size_t cnt) {
	return calloc(se, cnt);
}

void prne_free (void *ptr) {
	free(ptr);
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

bool prne_set_pipe_size (const int fd, const int size) {
	return 
#if defined(F_SETPIPE_SZ)
		fcntl(fd, F_SETPIPE_SZ, size) == 0
#elif defined(FIONREAD)
		ioctl(fd, FIONREAD, &size) == 0
#endif
		;
}
