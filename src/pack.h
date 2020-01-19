#pragma once
#include <stdint.h>
#include <stdbool.h>

#include "protocol.h"

struct prne_bin_tuple;
struct prne_bin_archive;
struct prne_pack_ret;
struct prne_unpack_ctx;
typedef struct prne_bin_tuple prne_bin_tuple_t;
typedef struct prne_bin_archive prne_bin_archive_t;
typedef struct prne_pack_ret prne_pack_ret_t;
typedef struct prne_unpack_ctx* prne_unpack_ctx_pt;

typedef enum {
	PRNE_PACK_RC_OK,
	PRNE_PACK_RC_FMT_ERR,
	PRNE_PACK_RC_ERRNO,
	PRNE_PACK_RC_Z_ERR,
	PRNE_PACK_RC_MBEDTLS_ERR,
	PRNE_PACK_RC_NO_BIN,
} prne_pack_rc_t;

struct prne_bin_tuple {
	prne_arch_t arch;
	size_t offset;
	size_t size;
};

struct prne_bin_archive {
	uint8_t *data;
	size_t data_size;
	size_t nb_bin;
	prne_bin_tuple_t *bin;
};

struct prne_pack_ret {
	prne_pack_rc_t rc;
	int err;
};

typedef prne_pack_ret_t(*prne_bin_archive_read_ft)(void *ctx, const size_t req, uint8_t *out, size_t *out_len);


void prne_init_bin_archive (prne_bin_archive_t *a);
void prne_free_bin_archive (prne_bin_archive_t *a);
prne_pack_ret_t prne_index_bin_archive (void *rf_ctx, prne_bin_archive_read_ft rf, prne_bin_archive_t *out);

prne_unpack_ctx_pt prne_alloc_unpack_ctx (const prne_bin_archive_t *archive, const prne_arch_t arch, prne_pack_ret_t *pr_out);
void prne_free_unpack_ctx (prne_unpack_ctx_pt ctx);
ssize_t prne_do_unpack (prne_unpack_ctx_pt ctx, uint8_t *out, const size_t out_len, prne_pack_ret_t *pr_out);

char *prne_pack_ret_tostr (const prne_pack_ret_t pr);
