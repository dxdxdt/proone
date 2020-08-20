#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/random.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/shm.h>
#include <sys/mman.h>
#include <signal.h>
#include <errno.h>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

#include "util_ct.h"
#include "util_rt.h"
#include "llist.h"
#include "mbedtls.h"


typedef struct {
	bool good;
} shared_t;

typedef struct {
	uint64_t nb_cycles;
	uint64_t last_cycles;
} shared_ctx_t;

typedef struct {
	mbedtls_entropy_context ent;
	mbedtls_ctr_drbg_context ctx;	
} priv_ctx_t;

shared_t *shared = NULL;
shared_ctx_t *ctx_arr = NULL;
struct timespec last_report;
size_t pagesize;
unsigned int nb_pages_min = 1;
unsigned int nb_pages_max = 1;
pid_t parent;
unsigned int nproc;

static void child_main (shared_ctx_t *ctx);
static void handle_signal (const int sn);
static void report (shared_ctx_t *arr);
static void child_signal_handler (const int sn);
static void sendall(const int sn);

int main (const int argc, const char **args) {
	static const size_t ALIGNED_SHARED_SIZE = prne_salign_next(sizeof(shared_t), 8);
#define END_ON_ERR(retval, val, fname, eq)\
	if ((eq && retval != val) || (!eq && retval == val)) {\
		perror(fname);\
		exit_code = 1;\
		goto END;\
	}

	unsigned int nb_proc_started = 0;
	int exit_code = 0;
	int zfd = -1;
	size_t shm_size;
	uint8_t *shm_ptr = MAP_FAILED;
	bool is_parent = true;
	
	parent = getpid();

	{
		const long ps = sysconf(_SC_PAGESIZE);

		if (ps < 0) {
			perror("sysconf(_SC_PAGESIZE) returned error");
			abort();
		}
		else if (ps == 0) {
			fprintf(stderr, "sysconf(_SC_PAGESIZE) returned 0");
			abort();
		}
		else {
			pagesize = (size_t)ps;
		}

		assert(pagesize % sizeof(unsigned long) == 0);
	}
	
	if (argc < 2) {
		fprintf(stderr,
			"Usage: %s <nproc> [page num range]\n"
			"\t<nproc>: number of processes to spawn\n"
			"\t[page num range]: number of page to use. '1-5' for 1 to 5 pages, '1' for just one page. Defaults to '1'\n",
			args[0]);
		return 2;
	}
	if (sscanf(args[1], "%u", &nproc) != 1 || nproc == 0) {
		fprintf(stderr, "Invalid <nproc> value %u\n", nproc);
		return 2;
	}
	if (argc >= 3) {
		if (sscanf(args[2], "%u-%u", &nb_pages_min, &nb_pages_max) == 2) {
			if (nb_pages_min > nb_pages_max || nb_pages_min == 0) {
				goto DROP;
			}
		}
		else if (sscanf(args[2], "%u", &nb_pages_min) == 1) {
			if (nb_pages_min == 0) {
				goto DROP;
			}
			nb_pages_max = nb_pages_min;
		}
		else {
			goto DROP;
		}

		if (false) {
DROP:
			fprintf(stderr, "Invalid page num range.\n");
			return 2;
		}
	}

	// init mem
	shm_size = ALIGNED_SHARED_SIZE + sizeof(shared_ctx_t) * nproc;
	zfd = open("/dev/zero", O_RDWR);
	if (zfd < 0) {
		perror("open()");
		exit_code = 1;
		goto END;
	}
	shm_ptr = mmap(NULL, shm_size, PROT_READ | PROT_WRITE, MAP_SHARED, zfd, 0);
	END_ON_ERR(shm_ptr, MAP_FAILED, "mmap()", false);
	close(zfd);
	zfd = -1;	

	// prep shared
	shared = (shared_t*)shm_ptr;
	shm_ptr += ALIGNED_SHARED_SIZE;
	shared->good = true;

	ctx_arr = (shared_ctx_t*)shm_ptr;

	for (unsigned int i = 0; i < nproc; i += 1) {
		const pid_t f_ret = fork();

		if (f_ret < 0) {
			perror("fork()");
			exit_code = 1;
			goto END;
		}
		else if (f_ret == 0) {
			struct sigaction sa;

			memzero(&sa, sizeof(struct sigaction));
			sa.sa_handler = child_signal_handler;
			sigaction(SIGINT, &sa, NULL);

			is_parent = false;

			child_main(ctx_arr + i);
			goto END;
		}
		else {
			nb_proc_started += 1;
		}
	}

	{
		struct sigaction sa;

		memzero(&sa, sizeof(struct sigaction));
		sa.sa_handler = handle_signal;

		sigaction(SIGINT, &sa, NULL);
		sigaction(SIGTERM, &sa, NULL);
		sigaction(SIGCHLD, &sa, NULL);
		sigaction(SIGUSR1, &sa, NULL);
	}

	clock_gettime(CLOCK_MONOTONIC, &last_report);

	
	while (shared->good) {
		pause();
	}

END:
	sigaction(SIGCHLD, NULL, NULL);

	if (is_parent) {
		if (shm_ptr != MAP_FAILED) {
			shared->good = false;

			if (nb_proc_started > 0) {
				printf("Reaping child processes ...\n");

				for (unsigned int i = 0; i < nb_proc_started; i += 1) {
					wait(NULL);
				}
			}

			munmap(shm_ptr, shm_size);
		}
		if (zfd >= 0) {
			close(zfd);
		}
	}

	return exit_code;
}

static void handle_signal (const int sn) {
	const int save_errno = errno;

	switch (sn) {
	case SIGINT:
	case SIGTERM:
		shared->good = false;
		if (sn == SIGTERM) {
			sendall(SIGTERM);
		}
		sigaction(SIGINT, NULL, NULL);
		sigaction(SIGTERM, NULL, NULL);		
		break;
	case SIGCHLD:
		if (shared->good) {
			fprintf(stderr, "Death of a child!\n");
			kill(0, SIGABRT);
			raise(SIGABRT);
		}
		break;
	case SIGUSR1:
		report(ctx_arr);
		break;
	}

	errno = save_errno;
}

static void report (shared_ctx_t *arr) {
	struct timespec ts_now, ts_delta;
	const time_t now = time(NULL);
	uint64_t sum_delta = 0, sum_all = 0;

	clock_gettime(CLOCK_MONOTONIC, &ts_now);

	printf(
		"=== proone-stress ===\n"
		"%s",
		ctime(&now));
	for (unsigned int i = 0; i < nproc; i += 1) {
		shared_ctx_t *ctx = arr + i;
		uint64_t delta;

		delta = ctx->nb_cycles - ctx->last_cycles;
		sum_delta += delta;
		sum_all += ctx->nb_cycles;
		ctx->last_cycles = ctx->nb_cycles;

		printf("%"PRIu64" ", delta);
	}

	ts_delta = prne_sub_timespec(ts_now, last_report);
	printf(
		"\n"
		"Delta: %"PRIu64"\n"
		"Sum: %"PRIu64"\n"
		"Last report: %"PRIdMAX".%03lds ago\n"
		"Thoughput: %.1lf events per second\n",
		sum_delta,
		sum_all,
		(intmax_t)ts_delta.tv_sec,
		ts_delta.tv_nsec / 1000000,
		(double)sum_delta / prne_real_timespec(ts_delta));

	fflush(stdout);

	last_report = ts_now;
}

static void do_cycle (priv_ctx_t *priv_ctx, shared_ctx_t *ctx) {
	unsigned int pages;
	unsigned long *arr;
	size_t nb_elements;

	assert(mbedtls_ctr_drbg_random(&priv_ctx->ctx, (unsigned char*)&pages, sizeof(pages)) == 0);

	pages = (pages % (nb_pages_max - nb_pages_min + 1)) + nb_pages_min;
	nb_elements = pagesize / sizeof(unsigned long) * pages;

	arr = (unsigned long*)prne_malloc(pagesize, pages);
	assert(mbedtls_ctr_drbg_random(&priv_ctx->ctx, (unsigned char*)arr, 2 * sizeof(unsigned int)) == 0);

	for (size_t i = 2; i < nb_elements; i += 1) {
		arr[i] = arr[i - 2] + arr[i - 1];
	}

	prne_free(arr);
}

static void child_main (shared_ctx_t *ctx) {
	priv_ctx_t priv_ctx;

	prne_mbedtls_entropy_init(&priv_ctx.ent);
	mbedtls_ctr_drbg_init(&priv_ctx.ctx);
	assert(mbedtls_ctr_drbg_seed(&priv_ctx.ctx, mbedtls_entropy_func, &priv_ctx.ent, NULL, 0) == 0);
	
	while (shared->good) {
		do_cycle(&priv_ctx, ctx);
		ctx->nb_cycles += 1;
	}
}

static void child_signal_handler (const int sn) {}

static void sendall(const int sn) {
	for (unsigned int i = 0; i < nproc; i += 1) {

	}
}
