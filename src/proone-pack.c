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
#include "protocol.h"

typedef struct {
	prne_arch_t arch;
	const char *path;
	struct stat st;
} archive_tuple_t;

uint8_t buf_in[16384], buf_out[16384];
const archive_tuple_t *encounter_arr[NB_PRNE_ARCH];
archive_tuple_t archive_arr[NB_PRNE_ARCH];
size_t archive_arr_cnt = 0;

static void report_zerror (const int z_ret, const char *msg) {
	fprintf(stderr, "%s: (%d)%s\n", msg, z_ret, zError(z_ret));
}


int main (const int argc, const char **args) {
	size_t i;
	archive_tuple_t *archive;
	const char *path, *ext;
	bool proc_result = true;
	prne_arch_t arch;
	int bin_fd = -1;
	uint8_t head[4];
	int z_ret;
	z_stream zs;
	ssize_t io_ret;
	size_t out_len;

	if (argc <= 1) {
		fprintf(stderr, "Usage: %s <path to binary 1> [path to binary 2 [path to binary ...]]\n", args[0]);
		return 1;
	}
	// refuse to run if stdout is terminal
	if (isatty(STDOUT_FILENO)) {
		fprintf(stderr, "** Refusing to print on terminal.\n");
		return 1;
	}
	// too many files
	if (argc - 1 > NB_PRNE_ARCH) {
		fprintf(stderr, "** Too many files given (%d > %d).\n", argc - 1, NB_PRNE_ARCH);
		return 1;
	}

	// init
	memzero(encounter_arr, sizeof(archive_tuple_t*) * NB_PRNE_ARCH);
	memzero(archive_arr, sizeof(archive_tuple_t) * NB_PRNE_ARCH);
	memzero(&zs, sizeof(z_stream));

	if ((z_ret = deflateInit(&zs, Z_BEST_COMPRESSION)) != Z_OK) {
		report_zerror(z_ret, "deflateInit()");
		abort();
	}

	// Check the file names are valid
	for (i = 1; i < (size_t)argc; i += 1) {
		struct stat st;

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
			fprintf(stderr, "** Duplicate arch!\n%s\n%s\n", encounter_arr[arch]->path, path);
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
		if (st.st_ino > 0x00FFFFFF) {
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
		goto END;
	}

	// write head
	head[0] = (uint8_t)(archive_arr_cnt & 0x000000FF);
	if (write(STDOUT_FILENO, head, 1) != 1) {
		perror("write()");
		proc_result = false;
		goto END;
	}
	for (i = 0; i < archive_arr_cnt; i += 1) {
		archive = archive_arr + i;

		head[0] = (uint8_t)archive->arch;
		head[1] = (uint8_t)(((uint_fast32_t)archive->st.st_size & 0x00FF0000) >> 16);
		head[2] = (uint8_t)(((uint_fast32_t)archive->st.st_size & 0x0000FF00) >> 8);
		head[3] = (uint8_t)((uint_fast32_t)archive->st.st_size & 0x000000FF);
		if (write(STDOUT_FILENO, head, 4) != 4) {
			perror("write()");
			proc_result = false;
			goto END;
			break;
		}
	}

	// write binary
	for (i = 0; i < archive_arr_cnt; i += 1) {
		archive = archive_arr + i;

		bin_fd = open(archive->path, O_RDONLY);
		if (bin_fd < 0) {
			perror(archive->path);
			proc_result = false;
			goto END;
		}

		while (true) {
			io_ret = read(bin_fd, buf_in, sizeof(buf_in));
			if (io_ret == 0) {
				break;
			}
			if (io_ret < 0) {
				perror(archive->path);
				proc_result = false;
				goto END;
			}

			zs.avail_in = io_ret;
			zs.next_in = buf_in;
			do {
				zs.avail_out = sizeof(buf_out);
				zs.next_out = buf_out;
				z_ret = deflate(&zs, Z_NO_FLUSH);
				switch (z_ret) {
				case Z_BUF_ERROR:
				case Z_OK:
					break;
				default:
					report_zerror(z_ret, archive->path);
					proc_result = false;
					goto END;
				}
				out_len = sizeof(buf_out) - zs.avail_out;

				if (write(STDOUT_FILENO, buf_out, out_len) != (ssize_t)out_len) {
					perror("write()");
					proc_result = false;
					goto END;
				}
			} while (zs.avail_out == 0);
		}

		prne_close(bin_fd);
		bin_fd = -1;
	}

	zs.next_in = NULL;
	zs.avail_in = 0;
	do {
		zs.next_out = buf_out;
		zs.avail_out = sizeof(buf_out);
		z_ret = deflate(&zs, Z_FINISH);
		switch (z_ret) {
		case Z_BUF_ERROR:
		case Z_STREAM_END:
		case Z_OK:
			break;
		default:
			report_zerror(z_ret, "finishing deflate()");
			proc_result = false;
			break;
		}
		out_len = sizeof(buf_out) - zs.avail_out;

		if (write(STDOUT_FILENO, buf_out, out_len) != (ssize_t)out_len) {
			perror("write()");
			proc_result = false;
			break;
		}
	} while (zs.avail_out == 0);

END:
	deflateEnd(&zs);
	prne_close(bin_fd);
	bin_fd = -1;

	return proc_result ? 0 : 1;
}
