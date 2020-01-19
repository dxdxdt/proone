#include "pack.h"
#include "util_rt.h"
#include "util_ct.h"

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <errno.h>

#include <zlib.h>
#include <mbedtls/error.h>


struct prne_unpack_ctx {
	size_t end;
	z_stream zs;
};

static int bin_tpl_comp_func (const void *a, const void *b) {
	return ((const prne_bin_tuple_t*)a)->arch < ((const prne_bin_tuple_t*)b)->arch ? -1 : ((const prne_bin_tuple_t*)a)->arch > ((const prne_bin_tuple_t*)b)->arch ? 1 : 0;
}


void prne_init_bin_archive (prne_bin_archive_t *a) {
	a->data_size = 0;
	a->data = NULL;
	a->nb_bin = 0;
	a->bin = NULL;
}

void prne_free_bin_archive (prne_bin_archive_t *a) {
	prne_free(a->data);
	prne_free(a->bin);
	a->data_size = 0;
	a->data = NULL;
	a->nb_bin = 0;
	a->bin = NULL;
}

prne_pack_ret_t prne_index_bin_archive (void *rf_ctx, prne_bin_archive_read_ft rf, prne_bin_archive_t *out) {
	prne_pack_ret_t ret;
	uint8_t *data = NULL;
	prne_bin_tuple_t *bin = NULL;
	size_t i, r_len, pos = 0, data_size = 0, nb_bin = 0;
	uint8_t head[4];
	void *ny_mem;
	const size_t pagesize = prne_getpagesize();

	r_len = 0;
	ret = rf(rf_ctx, 1, head, &r_len);
	if (ret.rc != PRNE_PACK_RC_OK) {
		goto ERR;
	}
	if (r_len != 1) {
		ret.rc = PRNE_PACK_RC_FMT_ERR;
		goto ERR;
	}

	nb_bin = head[0];
	bin = (prne_bin_tuple_t*)prne_malloc(sizeof(prne_bin_tuple_t), nb_bin);
	if (bin == NULL) {
		ret.rc = PRNE_PACK_RC_ERRNO;
		ret.err = errno;
		goto ERR;
	}
	for (i = 0; i < nb_bin; i += 1) {
		r_len = 0;
		ret = rf(rf_ctx, 4, head, &r_len);
		if (ret.rc != PRNE_PACK_RC_OK) {
			goto ERR;
		}
		if (r_len != 4) {
			ret.rc = PRNE_PACK_RC_FMT_ERR;
			goto ERR;
		}

		bin[i].arch = (prne_arch_t)head[0];
		bin[i].offset = pos;
		pos += bin[i].size = ((size_t)head[1] << 16) | ((size_t)head[2] << 8) | ((size_t)head[3]);
	}

	pos = 0;
	do {
		ny_mem = prne_realloc(data, 1, pos + pagesize);
		if (ny_mem == NULL) {
			ret.rc = PRNE_PACK_RC_ERRNO;
			ret.err = errno;
			goto ERR;
		}
		data = (uint8_t*)ny_mem;

		ret = rf(rf_ctx, pagesize, data + pos, &r_len);
		if (ret.rc != PRNE_PACK_RC_OK) {
			goto ERR;
		}
		data_size += r_len;
		pos += pagesize;
	} while (r_len == pagesize);
	ny_mem = prne_realloc(data, 1, data_size);
	if (ny_mem == NULL) {
		ret.rc = PRNE_PACK_RC_ERRNO;
		ret.err = errno;
		goto ERR;
	}
	data = (uint8_t*)ny_mem;

	qsort(bin, nb_bin, sizeof(prne_bin_tuple_t), bin_tpl_comp_func);
	out->data = data;
	out->data_size = data_size;
	out->nb_bin = nb_bin;
	out->bin = bin;

	return ret;
ERR:
	prne_free(bin);
	prne_free(data);

	return ret;
}

prne_unpack_ctx_pt prne_alloc_unpack_ctx (const prne_bin_archive_t *archive, const prne_arch_t arch, prne_pack_ret_t *pr_out) {
	prne_bin_tuple_t main_tpl;
	prne_bin_tuple_t *tpl;
	prne_unpack_ctx_pt ret = NULL;
	uint8_t buf[4096];
	size_t i, cnt;
	prne_pack_ret_t pr;

	pr.rc = PRNE_PACK_RC_OK;
	pr.err = 0;

	main_tpl.arch = arch;
	tpl = (prne_bin_tuple_t*)bsearch(&main_tpl, archive->bin, archive->nb_bin, sizeof(prne_bin_tuple_t), bin_tpl_comp_func);
	if (tpl == NULL) {
		pr.rc = PRNE_PACK_RC_NO_BIN;
		goto ERR;
	}
	main_tpl = *tpl;

	ret = (prne_unpack_ctx_pt)prne_malloc(sizeof(struct prne_unpack_ctx), 1);
	if (ret == NULL) {
		pr.rc = PRNE_PACK_RC_ERRNO;
		pr.err = errno;
		goto ERR;
	}
	memzero(&ret->zs, sizeof(ret->zs));
	if (Z_OK != (pr.err = inflateInit(&ret->zs))) {
		prne_free(ret);
		ret = NULL;

		pr.rc = PRNE_PACK_RC_Z_ERR;
		goto ERR;
	}
	ret->zs.avail_in = archive->data_size;
	ret->zs.next_in = archive->data;

	cnt = main_tpl.offset / sizeof(buf);
	for (i = 0; i < cnt; i += 1) {
		ret->zs.avail_out = sizeof(buf);
		ret->zs.next_out = buf;
		switch (inflate(&ret->zs, Z_SYNC_FLUSH)) {
		case Z_OK:
		case Z_BUF_ERROR:
			break;
		default:
			pr.rc = PRNE_PACK_RC_FMT_ERR;
			goto ERR;
		}
		if (ret->zs.avail_out != 0) {
			pr.rc = PRNE_PACK_RC_FMT_ERR;
			goto ERR;
		}
	}

	ret->zs.avail_out = main_tpl.offset - cnt * sizeof(buf);
	ret->zs.next_out = buf;
	switch (inflate(&ret->zs, Z_SYNC_FLUSH)) {
	case Z_OK:
	case Z_BUF_ERROR:
		break;
	default:
		pr.rc = PRNE_PACK_RC_FMT_ERR;
		goto ERR;
	}
	if (ret->zs.total_out != main_tpl.offset) {
		pr.rc = PRNE_PACK_RC_FMT_ERR;
		goto ERR;
	}

	ret->end = main_tpl.offset + main_tpl.size;
	if (pr_out != NULL) {
		*pr_out = pr;
	}
	return ret;
ERR:
	if (ret != NULL) {
		inflateEnd(&ret->zs);
		prne_free(ret);
	}
	if (pr_out != NULL) {
		*pr_out = pr;
	}

	return NULL;
}

void prne_free_unpack_ctx (prne_unpack_ctx_pt ctx) {
	if (ctx != NULL) {
		inflateEnd(&ctx->zs);
		prne_free(ctx);
	}
}

ssize_t prne_do_unpack (prne_unpack_ctx_pt ctx, uint8_t *out, const size_t out_len, prne_pack_ret_t *pr_out) {
	const size_t rem = ctx->end - ctx->zs.total_out;
	const size_t req = prne_op_min(rem, out_len);
	prne_pack_ret_t pr;

	pr.rc = PRNE_PACK_RC_OK;
	pr.err = 0;

	if (req == 0) {
		return 0;
	}

	ctx->zs.next_out = out;
	ctx->zs.avail_out = req;
	switch ((pr.err = inflate(&ctx->zs, Z_SYNC_FLUSH))) {
	case Z_OK:
	case Z_STREAM_END:
	case Z_BUF_ERROR:
		pr.err = 0;
		break;
	default:
		pr.rc = PRNE_PACK_RC_Z_ERR;
		goto END;
	}
	if (ctx->zs.avail_out != 0) {
		pr.rc = PRNE_PACK_RC_FMT_ERR;
		goto END;
	}

END:
	if (pr_out != NULL) {
		*pr_out = pr;
	}
	if (pr.rc != PRNE_PACK_RC_OK) {
		return -1;
	}

	return req;
}

char *prne_pack_ret_tostr (const prne_pack_ret_t pr) {
	const char *rc_str;
	const char *err_str;
	char *buf = NULL, err_buf[31];
	size_t buf_size;

	switch (pr.rc) {
	case PRNE_PACK_RC_OK: rc_str = "ok"; break;
	case PRNE_PACK_RC_FMT_ERR: rc_str = "fmt err"; break;
	case PRNE_PACK_RC_NO_BIN: rc_str = "no bin"; break;
	default: rc_str = NULL;
	}
	if (rc_str != NULL) {
		buf_size = strlen(rc_str) + 1;
		buf = (char*)prne_malloc(1, buf_size);
		if (buf != NULL) {
			memcpy(buf, rc_str, buf_size);
		}
		return buf;
	}

	switch (pr.rc) {
	case PRNE_PACK_RC_ERRNO:
		rc_str = "errno";
		err_str = strerror(pr.err);
		break;
	case PRNE_PACK_RC_Z_ERR:
		rc_str = "zlib err";
		err_str = zError(pr.err);
		break;
	case PRNE_PACK_RC_MBEDTLS_ERR:
		rc_str = "mbedtls err";
		mbedtls_strerror(pr.err, err_buf, sizeof(err_buf));
		err_str = err_buf;
		break;
	default:
		errno = EINVAL;
		return NULL;
	}

	buf_size = strlen(rc_str) + 4 + 11 + 1 + strlen(err_str) + 1;
	buf = (char*)prne_malloc(1, buf_size);
	if (buf != NULL) {
		if (sprintf(buf, "%s - (%d)%s", rc_str, pr.err, err_str) < 0) {
			prne_free(buf);
			return NULL;
		}
	}
	return buf;
}
