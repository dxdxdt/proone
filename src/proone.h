#include "proone_pack.h"
#include "proone_rnd.h"

#include <stdint.h>
#include <stdbool.h>


typedef struct {
    bool has_proc_lim_lock;
    bool bin_ready;
    proone_rnd_engine_t *rnd;
    proone_unpack_bin_archive_result_t bin_pack;
    proone_bin_archive_t bin_archive;
} proone_global_t;


extern proone_global_t pne_global;
