#include "util.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <errno.h>

#include <openssl/bio.h>
#include <openssl/evp.h>


void prne_succeed_or_die (const int ret) {
	if (ret < 0) {
		abort();
	}
}

void prne_empty_func () {}

void prne_rnd_alphanumeric_str (prne_rnd_engine_t *rnd_engine, char *str, const size_t len) {
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
	char *ret = NULL, *p = NULL;
	BIO *b64_bio = NULL, *mem_bio = NULL;
	bool ok = true;
	int out_len;

	if (size > INT32_MAX || size == 0) {
		return NULL;
	}

	b64_bio = BIO_new(BIO_f_base64());
	mem_bio = BIO_new(BIO_s_mem());
	if (b64_bio == NULL || mem_bio == NULL) {
		ok = false;
		goto END;
	}
	BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);
	BIO_push(b64_bio, mem_bio);

	if (BIO_write(b64_bio, data, size) != (int)size) {
		ok = false;
		goto END;
	}

	out_len = BIO_get_mem_data(mem_bio, &p);
	if (out_len < 0) {
		ok = false;
		goto END;
	}
	if (out_len > 0) {
		ret = (char*)malloc(out_len + 1);
		if (ret == NULL) {
			ok = false;
			goto END;
		}
		memcpy(ret, p, out_len);
		ret[out_len] = 0;
	}

END:
	BIO_free(b64_bio);
	BIO_free(mem_bio);
	if (!ok) {
		free(ret);
		ret = NULL;
	}

	return ret;
}

bool prne_dec_base64_mem (const char *str, const size_t str_len, uint8_t **data, size_t *size) {
	char *in_mem = NULL;
	size_t in_mem_len, out_len;
	uint8_t *out_mem = NULL;
	BIO *b64_bio = NULL, *mem_bio = NULL;
	bool ret = true;
	int read_size = 0;

	if (str_len > INT32_MAX) {
		errno = EINVAL;
		return false;
	}
	if (str_len == 0) {
		ret = true;
		goto END;
	}

	in_mem = (char*)malloc(str_len);
	if (in_mem == NULL) {
		ret = false;
		goto END;
	}
	memcpy(in_mem, str, str_len);
	in_mem_len = prne_str_shift_spaces(in_mem, str_len);
	if (in_mem_len == 0) {
		ret = true;
		goto END;
	}

	b64_bio = BIO_new(BIO_f_base64());
	mem_bio = BIO_new_mem_buf(in_mem, in_mem_len);
	if (b64_bio == NULL || mem_bio == NULL) {
		ret = false;
		goto END;
	}
	BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);
	BIO_push(b64_bio, mem_bio);
	
	out_len = in_mem_len * 3 / 4;
	out_mem = (uint8_t*)malloc((size_t)out_len);
	if (out_mem == NULL) {
		ret = false;
		goto END;
	}

	read_size = BIO_read(b64_bio, out_mem, out_len);
	if (read_size < 0) {
		ret = false;
		goto END;
	}

END:
	BIO_free(b64_bio);
	BIO_free(mem_bio);
	free(in_mem);
	if (ret) {
		if (read_size > 0) {
			*data = out_mem;
			*size = (size_t)read_size;
		}
		else {
			free(out_mem);
			*data = NULL;
			*size = 0;
		}
	}
	else {
		free(out_mem);
	}

	return ret;
}
