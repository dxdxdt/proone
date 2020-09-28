#include "util_rt.h"

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <errno.h>


static void test_uuid (void);
static void test_alloc (void);
static void test_str (void);

int main (void) {
	test_alloc();
	test_str();
	test_uuid();

	return 0;
}

static void test_str (void) {
	static const char *const str_a = "a";
	static const char *const str_b = "b";
	static const char *const str_sample = "abcdefg";

	assert(prne_nstreq(NULL, NULL));
	assert(!prne_nstreq(str_a, NULL));
	assert(!prne_nstreq(NULL, str_b));
	assert(!prne_nstreq(str_a, str_b));
	assert(prne_nstreq(str_a, str_a));

	assert(prne_nstrlen(NULL) == 0);
	assert(prne_nstrlen("") == 0);
	assert(prne_nstrlen(str_a) == 1);
	assert(prne_nstrlen(str_sample) == 7);

	assert(prne_strnchr(str_sample, 'a', 7) == str_sample);
	assert(prne_strnchr(str_sample, 'g', 7) == str_sample + 6);
	assert(prne_strnchr(str_sample, 0, 8) == str_sample + 7);
	assert(prne_strnchr(str_sample, 'g', 6) == NULL);
	assert(prne_strnchr(str_sample, 'a', 0) == NULL);
	assert(prne_strnchr(str_sample, 'x', 7) == NULL);

	for (int i = 0; i <= UINT_FAST8_MAX; i += 1) {
		char exp_str[3], str[3];
		uint_fast8_t out;

		str[2] = 0;

		sprintf(exp_str, "%02hhx", i);
		prne_hex_tochar((uint8_t)i, str, false);
		assert(memcmp(exp_str, str, 3) == 0);
		assert(prne_hex_fromstr(str, &out) && out == i);

		sprintf(exp_str, "%02hhX", i);
		prne_hex_tochar((uint8_t)i, str, true);
		assert(memcmp(exp_str, str, 3) == 0);
		assert(prne_hex_fromstr(str, &out) && out == i);
	}
}

static void test_alloc (void) {
	prne_free(NULL);

	errno = 0;
	assert(
		prne_malloc(0, 0) == NULL &&
		prne_malloc(1, 0) == NULL &&
		prne_malloc(0, 1) == NULL &&
		errno == 0);
	errno = 0;
	assert(prne_malloc(2, SIZE_MAX / 2 + 1) == NULL);
	assert(errno == ENOMEM);
	errno = 0;
	assert(prne_malloc(SIZE_MAX / 2 + 1, 2) == NULL);
	assert(errno == ENOMEM);

	errno = 0;
	assert(
		prne_calloc(0, 0) == NULL &&
		prne_calloc(1, 0) == NULL &&
		prne_calloc(0, 1) == NULL &&
		errno == 0);
	errno = 0;
	assert(prne_calloc(2, SIZE_MAX / 2 + 1) == NULL);
	assert(errno == ENOMEM);
	errno = 0;
	assert(prne_calloc(SIZE_MAX / 2 + 1, 2) == NULL);
	assert(errno == ENOMEM);

	errno = 0;
	assert(
		prne_realloc(NULL, 0, 0) == NULL &&
		prne_realloc(NULL, 1, 0) == NULL &&
		prne_realloc(NULL, 0, 1) == NULL &&
		errno == 0);
	errno = 0;
	assert(prne_realloc(NULL, 2, SIZE_MAX / 2 + 1) == NULL);
	assert(errno == ENOMEM);
	errno = 0;
	assert(prne_realloc(NULL, SIZE_MAX / 2 + 1, 2) == NULL);
	assert(errno == ENOMEM);

	errno = 0;
	assert(prne_alloc_str(SIZE_MAX) == NULL);
	assert(errno == ENOMEM);
}

static void test_uuid (void) {
	static const char *sample_str = "f31605bb-5ec9-46e7-918d-4810a39a858d";
	static const uint8_t sample_arr[16] = {
		0xf3, 0x16, 0x05, 0xbb, 0x5e, 0xc9, 0x46, 0xe7,
		0x91, 0x8d, 0x48, 0x10, 0xa3, 0x9a, 0x85, 0x8d
	};
	static const char *empty_str = "00000000-0000-0000-0000-000000000000";
	static const uint8_t empty_arr[16];
	uint8_t out_arr[16];
	char out_str[37];

	prne_memzero(out_arr, 16);
	prne_memzero(out_str, 37);
	assert(prne_uuid_fromstr(sample_str, out_arr));
	assert(memcmp(sample_arr, out_arr, 16) == 0);
	prne_uuid_tostr(out_arr, out_str);
	assert(memcmp(sample_str, out_str, 37) == 0);

	memset(out_arr, 0xFF, 16);
	prne_memzero(out_str, 37);
	assert(prne_uuid_fromstr(empty_str, out_arr));
	assert(memcmp(empty_arr, out_arr, 16) == 0);
	prne_uuid_tostr(out_arr, out_str);
	assert(memcmp(empty_str, out_str, 37) == 0);

	errno = 0;
	assert(!prne_uuid_fromstr("", out_arr));
	assert(errno == EINVAL);
	errno = 0;
	assert(!prne_uuid_fromstr(
		"f31605bb-5ec9-46e7-918d-4810a39a858da",
		out_arr));
	assert(errno == EINVAL);
	assert(!prne_uuid_fromstr(
		"f31605bb-5ec9-46e7-918d-4810a39a858d-",
		out_arr));
	assert(errno == EINVAL);
	assert(!prne_uuid_fromstr(
		"f31605bb-5ec9-46e7-918d-4810Z39a858d",
		out_arr));
	assert(errno == EINVAL);
	assert(!prne_uuid_fromstr(
		"f31605bb-5ec9046e7-918d-4810a39a858d",
		out_arr));
	assert(errno == EINVAL);
}
