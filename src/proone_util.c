#include "proone_util.h"

#include <stdlib.h>


void proone_succeed_or_die (const int ret) {
	if (ret < 0) {
		abort();
	}
}

void proone_rnd_alphanumeric_str (proone_rnd_engine_t *rnd_engine, char *str, const size_t len) {
	static const char SET[] = "qwertyuiopasdfghjklzxcvbnm0123456789";
	size_t i = 0;
	uint32_t n;

	if (len >= 4) {
		for (; i < len / 4 * 4; i += 4) {
			n = proone_rnd_gen_int(rnd_engine);
			str[i + 0] = SET[((uint8_t*)&n)[0] % sizeof(SET)];
			str[i + 1] = SET[((uint8_t*)&n)[1] % sizeof(SET)];
			str[i + 2] = SET[((uint8_t*)&n)[2] % sizeof(SET)];
			str[i + 3] = SET[((uint8_t*)&n)[3] % sizeof(SET)];
		}
	}
	if (i < len) {
		n = proone_rnd_gen_int(rnd_engine);
		for (; i < len; i += 1) {
			str[i] = SET[((uint8_t*)&n)[i % 4] % sizeof(SET)];
		}
	}
}

void proone_empty_func () {}

struct timespec proone_sub_timespec (const struct timespec *a, const struct timespec *b) {
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

double proone_real_timespec (const struct timespec *ts) {
	return (double)ts->tv_sec + (double)ts->tv_nsec / 1000000000.0;
}

int proone_cmp_timespec (const struct timespec *a, const struct timespec *b) {
	if (a->tv_sec < b->tv_sec) {
		return -1;
	}
	else if (a->tv_sec > b->tv_sec) {
		return 1;
	}

	return a->tv_nsec < b->tv_nsec ? -1 : a->tv_nsec > b->tv_nsec ? 1 : 0;
}
