#pragma once
#include <stdint.h>
#include <stdbool.h>

#include "protocol.h"


typedef struct prne_bin_archive prne_bin_archive_t;
typedef struct prne_unpack_bin_archive_result prne_unpack_bin_archive_result_t;

struct prne_bin_archive {
    size_t data_size;
    uint8_t *data;
    size_t nb_binaries;
    prne_arch_t *arch_arr;
    size_t *offset_arr;
    size_t *size_arr;
};

typedef enum {
    PRNE_UNPACK_BIN_ARCHIVE_OK,
    PRNE_UNPACK_BIN_ARCHIVE_OPENSSL_ERR,
    PRNE_UNPACK_BIN_ARCHIVE_Z_ERR,
    PRNE_UNPACK_BIN_ARCHIVE_ERRNO,
    PRNE_UNPACK_BIN_ARCHIVE_MEM_ERR,
    PRNE_UNPACK_BIN_ARCHIVE_FMT_ERR
} prne_unpack_bin_archive_result_code_t;

struct prne_unpack_bin_archive_result {
    size_t data_size;
    uint8_t *data;
    prne_unpack_bin_archive_result_code_t result;
    long err;
};

typedef enum {
    PRNE_INDEX_BIN_ARCHIVE_OK,
    PRNE_INDEX_BIN_ARCHIVE_FMT_ERR,
    PRNE_INDEX_BIN_ARCHIVE_MEM_ERR
} prne_index_bin_archive_result_code_t;


void prne_init_bin_archive (prne_bin_archive_t *a);
void prne_init_unpack_bin_archive_result (prne_unpack_bin_archive_result_t *r);
prne_unpack_bin_archive_result_t prne_unpack_bin_archive (const int fd);
prne_index_bin_archive_result_code_t prne_index_bin_archive (prne_unpack_bin_archive_result_t *in, prne_bin_archive_t *out);
void prne_free_unpack_bin_archive_result (prne_unpack_bin_archive_result_t *r);
void prne_free_bin_archive (prne_bin_archive_t *a);
