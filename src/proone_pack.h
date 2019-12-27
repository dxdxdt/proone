#pragma once
#include <stdint.h>
#include <stdbool.h>

#include "proone_protocol.h"

typedef struct {
    size_t data_size;
    uint8_t *data;
    size_t nb_binaries;
    proone_arch_t *arch_arr;
    size_t *offset_arr;
    size_t *size_arr;
} bin_archive_t;

typedef enum {
    PROONE_UNPACK_BIN_ARCHIVE_OK,
    PROONE_UNPACK_BIN_ARCHIVE_OPENSSL_ERR,
    PROONE_UNPACK_BIN_ARCHIVE_Z_ERR,
    PROONE_UNPACK_BIN_ARCHIVE_ERRNO,
    PROONE_UNPACK_BIN_ARCHIVE_MEM_ERR
} proone_unpack_bin_archive_result_code_t;

typedef struct {
    size_t data_size;
    uint8_t *data;
    size_t raw_data_size;
    uint8_t *raw_data;
    proone_unpack_bin_archive_result_code_t result;
    long err;
} proone_unpack_bin_archive_result_t;

typedef enum {
    PROONE_INDEX_BIN_ARCHIVE_OK,
    PROONE_INDEX_BIN_ARCHIVE_FMT_ERR,
    PROONE_INDEX_BIN_ARCHIVE_MEM_ERR
} proone_index_bin_archive_result_code_t;

void proone_init_bin_archive (bin_archive_t *a);
void proone_init_unpack_bin_archive_result (proone_unpack_bin_archive_result_t *r);
proone_unpack_bin_archive_result_t proone_unpack_bin_archive (const int fd);
proone_index_bin_archive_result_code_t proone_index_bin_archive (proone_unpack_bin_archive_result_t *in, bin_archive_t *out);
void proone_free_unpack_bin_archive_result (proone_unpack_bin_archive_result_t *r);
void proone_free_bin_archive (bin_archive_t *a);
