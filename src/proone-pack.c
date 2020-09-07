#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <zlib.h>

#include "util_rt.h"
#include "util_ct.h"
#include "endian.h"
#include "protocol.h"
#include "config.h"
#include "pack.h"

#define ENABLE_TEST 0
#define TEST_DEPTH 2


typedef struct {
	prne_arch_t arch;
	const char *path;
	struct stat st;
	uint8_t *m_exec;
} archive_tuple_t;

const archive_tuple_t *encounter_arr[NB_PRNE_ARCH];
archive_tuple_t archive_arr[NB_PRNE_ARCH];
size_t archive_arr_cnt;
uint8_t *m_dv;
size_t dv_len;
uint8_t *m_ba;
size_t ba_size, ba_len;
size_t PAGESIZE;

static void report_zerror (const int z_ret, const char *msg) {
	fprintf(stderr, "%s: (%d)%s\n", msg, z_ret, zError(z_ret));
}

static bool load_dv (const char *path, uint8_t **m_dv, size_t *len) {
	bool ret = false;
	int fd;
	off_t ofs;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		goto END;
	}

	ofs = lseek(fd, 0, SEEK_END);
	if (ofs < 0 || lseek(fd, 0, SEEK_SET) < 0) {
		goto END;
	}

	*m_dv = (uint8_t*)prne_realloc(*m_dv, 1, ofs);
	prne_assert(*m_dv != NULL);
	*len = (size_t)ofs;

	if (read(fd, *m_dv, *len) != (ssize_t)*len) {
		goto END;
	}
	ret = true;

END:
	prne_close(fd);
	return ret;
}

static size_t do_read (
	uint8_t **m,
	size_t *size,
	prne_bin_rcb_ctx_t *ctx)
{
	prne_pack_rc_t prc;
	int err;
	size_t len = 0;
	ssize_t f_ret;

	prne_free(*m);
	*m = NULL;
	*size = 0;

	do {
		if (*size - len == 0) {
			*size += PAGESIZE;
			*m = (uint8_t*)prne_realloc(*m, 1, *size);
			prne_assert(*m != NULL);
		}

		f_ret = prne_bin_rcb_read(
			ctx,
			*m + len,
			*size - len,
			&prc,
			&err);
		prne_assert(f_ret >= 0);
		len += f_ret;
	} while (prc != PRNE_PACK_RC_EOF);

	return len;
}

static void do_test (
	const uint8_t *m,
	const size_t len,
	const archive_tuple_t *t,
	const size_t depth)
{
	prne_bin_rcb_ctx_t ctx;
	prne_bin_archive_t ba;
	const size_t ofs_dv =
		prne_salign_next(t->st.st_size, PRNE_BIN_ALIGNMENT) + // exec
		8; // appendix;
	const size_t ofs_ba =
		ofs_dv +
		prne_salign_next(dv_len, PRNE_BIN_ALIGNMENT); // dv
	size_t out_size = 0, out_len;
	uint8_t *m_out = NULL;

	if (depth > TEST_DEPTH) {
		return;
	}

	prne_assert(ofs_ba < len);
	prne_assert(memcmp(m, t->m_exec, t->st.st_size) == 0);
	prne_assert(memcmp(m + ofs_dv, m_dv, dv_len) == 0);

	prne_init_bin_archive(&ba);
	prne_init_bin_rcb_ctx(&ctx);
	prne_assert(prne_index_bin_archive(
		m + ofs_ba,
		len - ofs_ba,
		&ba) == PRNE_PACK_RC_OK);

	fprintf(stderr, "%s\t\t", prne_arch_tostr(t->arch));
	for (size_t i = 0; i < ba.nb_bin; i += 1) {
		fprintf(stderr, "%s\t", prne_arch_tostr(ba.bin[i].arch));
	}
	fprintf(stderr, "\n");

	for (size_t i = 0; i < archive_arr_cnt; i += 1) {
		prne_assert(prne_start_bin_rcb(
			&ctx,
			archive_arr[i].arch,
			t->arch,
			m,
			len,
			t->st.st_size,
			m_dv,
			dv_len,
			&ba) == PRNE_PACK_RC_OK);
		out_len = do_read(&m_out, &out_size, &ctx);

		if (archive_arr[i].arch == t->arch) {
			prne_assert(out_len == len && memcmp(m_out, m, len) == 0);
		}
		else {
			do_test(m_out, out_len, &archive_arr[i], depth + 1);
		}
	}

	prne_free_bin_archive(&ba);
	prne_free_bin_rcb_ctx(&ctx);
	prne_free(m_out);
}

static bool do_rcb (const char *prefix) {
	prne_pack_rc_t prc;
	bool ret = true;
	prne_bin_rcb_ctx_t ctx;
	prne_bin_archive_t ba;
	uint8_t *m_out = NULL;
	size_t out_size = 0, out_len = 0;
	int fd = -1;
	char *out_path = NULL;
	const size_t prefix_len = strlen(prefix);
	const char *arch_str;

	prne_init_bin_rcb_ctx(&ctx);
	prne_init_bin_archive(&ba);

	out_path = prne_alloc_str(
		prefix_len + strlen(".nybin"));
	strcpy(out_path, prefix);
	strcat(out_path, ".nybin");

	prc = prne_index_bin_archive(m_ba, ba_len, &ba);
	prne_assert(prc == PRNE_PACK_RC_OK);

	// TODO: dvault + nybin
	fd = open(out_path, O_WRONLY | O_CREAT | O_TRUNC, 0755);
	if (fd < 0 || write(fd, m_ba, ba_len) != (ssize_t)ba_len) {
		perror(out_path);
		ret = false;
		goto END;
	}
	close(fd);
	fd = -1;

	for (size_t i = 0; i < archive_arr_cnt; i += 1) {
		arch_str = prne_arch_tostr(archive_arr[i].arch);
		prne_assert(arch_str != NULL);

		prc = prne_start_bin_rcb(
			&ctx,
			archive_arr[i].arch,
			PRNE_ARCH_NONE,
			NULL,
			0,
			0,
			m_dv,
			dv_len,
			&ba);
		prne_assert(prc == PRNE_PACK_RC_OK);
		out_len = do_read(&m_out, &out_size, &ctx);

		if (ENABLE_TEST) {
			do_test(m_out, out_len, &archive_arr[i], 0);
		}

		prne_free(out_path);
		out_path = prne_alloc_str(
			prefix_len + 1 + strlen(arch_str));
		strcpy(out_path, prefix);
		strcat(out_path, ".");
		strcat(out_path, arch_str);

		fd = open(out_path, O_WRONLY | O_CREAT | O_TRUNC, 0755);
		if (fd < 0 || write(fd, m_out, out_len) != (ssize_t)out_len) {
			perror(out_path);
			ret = false;
			goto END;
		}
		close(fd);
		fd = -1;
	}

END:
	prne_free(out_path);
	prne_free(m_out);
	prne_free_bin_rcb_ctx(&ctx);
	prne_free_bin_archive(&ba);
	prne_close(fd);
	return ret;
}

int main (const int argc, const char **args) {
	size_t i;
	archive_tuple_t *archive;
	const char *path, *ext;
	const char *o_prefix;
	bool proc_result = true;
	prne_arch_t arch;
	int bin_fd = -1;
	int z_ret, ret = 0;
	z_stream zs;
	size_t out_len;

	PAGESIZE = prne_getpagesize(); // TODO: test

	prne_memzero(&zs, sizeof(z_stream));
	if ((z_ret = deflateInit(&zs, PRNE_PACK_Z_LEVEL)) != Z_OK) {
		report_zerror(z_ret, "deflateInit()");
		abort();
	}

	if (argc < 3) {
		fprintf(
			stderr,
			"Usage: %s <outfile prefix> <path to dvault> [path to binary 1 [path to binary ...]]\n",
			args[0]);
		ret = 2;
		goto END;
	}
	o_prefix = args[1];

	if (!load_dv(args[2], &m_dv, &dv_len)) {
		perror("load_dv()");
		goto END;
	}

	// Check the file names are valid
	for (i = 3; i < (size_t)argc; i += 1) {
		struct stat st;

		if (archive_arr_cnt >= NB_PRNE_ARCH) {
			fprintf(
				stderr,
				"** Too many files given (%d > %d).\n",
				argc - 1,
				NB_PRNE_ARCH);
			ret = 2;
			goto END;
		}

		path = args[i];
		ext = strrchr(path, '.');
		if (ext == NULL) {
			fprintf(stderr, "** %s: file extension not found\n", path);
			proc_result = false;
			continue;
		}
		ext += 1;

		arch = prne_arch_fstr(ext);
		if (arch == PRNE_ARCH_NONE) {
			fprintf(stderr, "** %s: unknown arch \"%s\"\n", path, ext);
			proc_result = false;
			continue;
		}

		if (encounter_arr[arch] != NULL) {
			fprintf(
				stderr,
				"** Duplicate arch!\n%s\n%s\n",
				encounter_arr[arch]->path,
				path);
			proc_result = false;
			continue;
		}

		if (stat(path, &st) != 0) {
			perror(path);
			proc_result = false;
			continue;
		}
		if (st.st_size <= 0) {
			fprintf(stderr, "%s: empty file!\n", path);
			proc_result = false;
			continue;
		}
		if (st.st_size > 0x00FFFFFF) {
			fprintf(stderr, "%s: file too large!\n", path);
			proc_result = false;
			continue;
		}

		archive_arr[archive_arr_cnt].arch = arch;
		archive_arr[archive_arr_cnt].path = path;
		archive_arr[archive_arr_cnt].st = st;
		encounter_arr[arch] = &archive_arr[archive_arr_cnt];
		archive_arr_cnt += 1;
	}
	if (!proc_result) {
		ret = 2;
		goto END;
	}

	ba_len = ba_size = 4 + archive_arr_cnt * 4;
	m_ba = (uint8_t*)prne_malloc(1, ba_size);
	prne_assert(m_ba != NULL);

	// write head
	m_ba[0] = (uint8_t)(archive_arr_cnt & 0xFF);
	m_ba[1] = 0;
	m_ba[2] = 0;
	m_ba[3] = 0;
	ba_len = 4;
	for (i = 0; i < archive_arr_cnt; i += 1) {
		archive = archive_arr + i;

		m_ba[ba_len + 0] = (uint8_t)archive->arch;
		m_ba[ba_len + 1] = prne_getmsb32(archive->st.st_size, 1);
		m_ba[ba_len + 2] = prne_getmsb32(archive->st.st_size, 2);
		m_ba[ba_len + 3] = prne_getmsb32(archive->st.st_size, 3);
		ba_len += 4;
	}

	// compress executables
	for (i = 0; i < archive_arr_cnt; i += 1) {
		archive = archive_arr + i;

		archive->m_exec = prne_malloc(1, archive->st.st_size);
		prne_assert(archive->m_exec != NULL);

		bin_fd = open(archive->path, O_RDONLY);
		if (bin_fd < 0) {
			perror(archive->path);
			ret = 1;
			goto END;
		}

		if (read(
			bin_fd,
			archive->m_exec,
			archive->st.st_size) != (ssize_t)archive->st.st_size)
		{
			perror(archive->path);
			ret = 1;
			goto END;
		}
		close(bin_fd);
		bin_fd = -1;

		zs.avail_in = archive->st.st_size;
		zs.next_in = archive->m_exec;

		do {
			if (ba_size - ba_len == 0) {
				ba_size += PAGESIZE;
				m_ba = (uint8_t*)prne_realloc(m_ba, 1, ba_size);
				prne_assert(m_ba != NULL);
			}
			zs.avail_out = ba_size - ba_len;
			zs.next_out = m_ba + ba_len;
			out_len = zs.avail_out;

			z_ret = deflate(&zs, Z_NO_FLUSH);
			switch (z_ret) {
			case Z_BUF_ERROR:
			case Z_OK:
				break;
			default:
				report_zerror(z_ret, archive->path);
				ret = 1;
				goto END;
			}
			out_len -= zs.avail_out;
			ba_len += out_len;
		} while (zs.avail_in > 0);
	}

	while (z_ret != Z_STREAM_END) {
		if (ba_size - ba_len == 0) {
			ba_size += PAGESIZE;
			m_ba = (uint8_t*)prne_realloc(m_ba, 1, ba_size);
			prne_assert(m_ba != NULL);
		}
		zs.avail_out = ba_size - ba_len;
		zs.next_out = m_ba + ba_len;
		out_len = zs.avail_out;

		z_ret = deflate(&zs, Z_FINISH);
		switch (z_ret) {
		case Z_STREAM_END:
		case Z_BUF_ERROR:
		case Z_OK:
			break;
		default:
			report_zerror(z_ret, "finishing deflate()");
			ret = 1;
			goto END;
		}
		out_len -= zs.avail_out;
		ba_len += out_len;
	}

	ret = do_rcb(o_prefix) ? 0 : 1;

END:
	prne_free(m_dv);
	prne_free(m_ba);
	for (size_t i = 0; i < archive_arr_cnt; i += 1) {
		prne_free(archive_arr[i].m_exec);
	}
	deflateEnd(&zs);
	prne_close(bin_fd);
	bin_fd = -1;

	return ret;
}
