#include "proone_pack.h"
#include "proone_rnd.h"

#include <stdint.h>
#include <stdbool.h>


struct proone_global {
    uint8_t *host_cred_data;
    size_t host_cred_size;
    bool has_proc_lim_lock;
    bool bin_ready;
    int caught_signal;
    proone_rnd_engine_t *rnd;
    proone_unpack_bin_archive_result_t bin_pack;
    proone_bin_archive_t bin_archive;
};


extern struct proone_global pne_global;
