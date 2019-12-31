#include "pack.h"
#include "rnd.h"

#include <stdint.h>
#include <stdbool.h>


struct prne_global {
    uint8_t *host_cred_data;
    size_t host_cred_size;
    bool has_proc_lim_lock;
    bool bin_ready;
    int caught_signal;
    prne_rnd_engine_t *rnd;
    prne_unpack_bin_archive_result_t bin_pack;
    prne_bin_archive_t bin_archive;
};


extern struct prne_global pne_g;
