#include "util_rt.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <errno.h>

#include <mbedtls/base64.h>


void prne_succeed_or_die (const int ret) {
	if (ret < 0) {
		abort();
	}
}

void prne_empty_func () {}

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

void prne_rnd_anum_str (prne_rnd_engine_t *rnd_engine, char *str, const size_t len) {
	static const char SET[] = "qwertyuiopasdfghjklzxcvbnm0123456789";
	size_t i = 0;
	uint32_t n;

	if (len >= 4) {
		for (; i < len / 4 * 4; i += 4) {
			n = prne_rnd_gen_int(rnd_engine);
			str[i + 0] = SET[((uint8_t*)&n)[0] % sizeof(SET)];
			str[i + 1] = SET[((uint8_t*)&n)[1] % sizeof(SET)];
			str[i + 2] = SET[((uint8_t*)&n)[2] % sizeof(SET)];
			str[i + 3] = SET[((uint8_t*)&n)[3] % sizeof(SET)];
		}
	}
	if (i < len) {
		n = prne_rnd_gen_int(rnd_engine);
		for (; i < len; i += 1) {
			str[i] = SET[((uint8_t*)&n)[i % 4] % sizeof(SET)];
		}
	}
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


struct timespec prne_sub_timespec (const struct timespec *a, const struct timespec *b) {
	struct timespec ret;

	if (a->tv_nsec < b->tv_nsec) {
		ret.tv_sec = a->tv_sec - 1 - b->tv_sec;
		ret.tv_nsec = 1000000000 + a->tv_nsec - b->tv_nsec;
	}
	else {
		ret.tv_sec = a->tv_sec - b->tv_sec;
		ret.tv_nsec = a->tv_nsec - b->tv_nsec;
	}

	return ret;
}

double prne_real_timespec (const struct timespec *ts) {
	return (double)ts->tv_sec + (double)ts->tv_nsec / 1000000000.0;
}

int prne_cmp_timespec (const struct timespec *a, const struct timespec *b) {
	if (a->tv_sec < b->tv_sec) {
		return -1;
	}
	else if (a->tv_sec > b->tv_sec) {
		return 1;
	}

	return a->tv_nsec < b->tv_nsec ? -1 : a->tv_nsec > b->tv_nsec ? 1 : 0;
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
