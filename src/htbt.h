#pragma once
#include "pth.h"
#include "resolv.h"
#include "protocol.h"
#include "pack.h"

#include <mbedtls/ssl.h>


struct prne_htbt;
typedef struct prne_htbt prne_htbt_t;
typedef struct prne_htbt_param prne_htbt_param_t;
typedef struct prne_htbt_cbset prne_htbt_cbset_t;
typedef bool(*prne_htbt_cnc_txtrec_ft)(void *ctx, char *out);
typedef bool(*prne_htbt_hostinfo_ft)(void *ctx, prne_htbt_host_info_t *out);
typedef int(*prne_htbt_tmpfile_ft)(
	void *ctx,
	const int flags,
	const mode_t mode,
	size_t req_size,
	char **path);
typedef bool(*prne_htbt_bin_ft)(
	void *ctx,
	const char *path,
	const prne_htbt_cmd_t *cmd);

struct prne_htbt_cbset {
	// All callback functions are optional.
	prne_htbt_cnc_txtrec_ft cnc_txtrec;
	prne_htbt_hostinfo_ft hostinfo;
	prne_htbt_tmpfile_ft tmpfile;
	prne_htbt_bin_ft upbin;
};

struct prne_htbt_param {
	mbedtls_ssl_config *lbd_ssl_conf;
	mbedtls_ssl_config *main_ssl_conf;
	mbedtls_ctr_drbg_context *ctr_drbg;
	prne_resolv_t *resolv;
	prne_htbt_cbset_t cb_f;
	void *cb_ctx;
	const prne_rcb_param_t *rcb;
	int blackhole;
};


prne_htbt_t *prne_alloc_htbt (prne_worker_t *w, const prne_htbt_param_t *param);

void prne_htbt_init_param (prne_htbt_param_t *p);
void prne_htbt_free_param (prne_htbt_param_t *p);
