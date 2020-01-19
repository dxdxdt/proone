#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "pack.h"
#include "util_rt.h"

#define USE_MMAP 1


static void report_pack_ret (const prne_pack_ret_t pr) {
	char *str = prne_pack_ret_tostr(pr);

	fprintf(stderr, "%s\n", str);
	prne_free(str);
}


int main (const int argc, const char **args) {
	int exit_code = 0;
	const char *path_prefix;
	size_t path_prefix_len;
	prne_stdin_base64_rf_ctx_t rf_ctx;
	prne_bin_archive_t bin_archive;
	prne_pack_ret_t pr;
	size_t i;
	const char *arch_str;
	char *path = NULL;
	size_t path_size;
	void *ny_buf;
	int fd = -1;
	prne_unpack_ctx_pt unpack_ctx = NULL;
#if USE_MMAP
	void *addr = NULL;
#else
	uint8_t write_buf[512];
	ssize_t write_len;
#endif

	if (argc <= 1) {
		fprintf(stderr, "Usage: %s <prefix>\n", args[0]);
		return 2;
	}

	path_prefix = args[1];
	path_prefix_len = strlen(path_prefix);
	prne_init_bin_archive(&bin_archive);
	prne_init_stdin_base64_rf_ctx(&rf_ctx);

	pr = prne_index_bin_archive(&rf_ctx, prne_stdin_base64_rf, &bin_archive);
	if (pr.rc != PRNE_PACK_RC_OK) {
		report_pack_ret(pr);
		exit_code = 1;
		goto END;
	}

	for (i = 0; i < bin_archive.nb_bin; i += 1) {
		arch_str = prne_arch_tostr(bin_archive.bin[i].arch);
		if (arch_str == NULL) {
			fprintf(stderr, "** unrecognised arch!");
			exit_code = 1;
			goto END;
		}

		unpack_ctx = prne_alloc_unpack_ctx(&bin_archive, bin_archive.bin[i].arch, &pr);
		if (unpack_ctx == NULL) {
			report_pack_ret(pr);
			exit_code = 1;
			goto END;
		}
		
		path_size = 2 + path_prefix_len + strlen(arch_str);
		ny_buf = prne_realloc(path, 1, path_size);
		if (ny_buf == NULL) {
			perror("prne_realloc()");
			exit_code = 1;
			goto END;
		}
		path = (char*)ny_buf;
		if (sprintf(path, "%s.%s", path_prefix, arch_str) < 0) {
			perror("sprintf()");
			exit_code = 1;
			goto END;
		}

		fd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0666);
		if (fd < 0) {
			perror("open()");
			exit_code = 1;
			goto END;
		}
#if USE_MMAP
		if (ftruncate(fd, bin_archive.bin[i].size) != 0) {
			perror("ftruncate()");
			exit_code = 1;
			goto END;
		}
		addr = mmap(NULL, bin_archive.bin[i].size, PROT_WRITE, MAP_SHARED, fd, 0);
		if (addr == MAP_FAILED) {
			perror("mmap()");
			exit_code = 1;
			goto END;
		}

		if (prne_do_unpack(unpack_ctx, (uint8_t*)addr, bin_archive.bin[i].size, &pr) != (ssize_t)bin_archive.bin[i].size) {
			report_pack_ret(pr);
			exit_code = 1;
			goto END;
		}

		munmap(addr, bin_archive.bin[i].size);
		addr = NULL;
#else
		do {
			write_len = prne_do_unpack(unpack_ctx, write_buf, sizeof(write_buf), &pr);
			if (write_len < 0) {
				report_pack_ret(pr);
				exit_code = 1;
				goto END;
			}
			write(fd, write_buf, (size_t)write_len);
		} while (write_len != 0);
#endif
		prne_free_unpack_ctx(unpack_ctx);
		unpack_ctx = NULL;
		prne_close(fd);
		fd = -1;
	}

END:
#if USE_MMAP
	if (addr != NULL) {
		munmap(addr, bin_archive.bin[i].size);
	}
#endif
	prne_free_unpack_ctx(unpack_ctx);
	prne_free(path);
	prne_close(fd);
	prne_free_bin_archive(&bin_archive);
	prne_free_stdin_base64_rf_ctx(&rf_ctx);

	return exit_code;
}
