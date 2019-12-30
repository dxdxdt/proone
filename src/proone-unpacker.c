#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <unistd.h>
#include <fcntl.h>

#include <openssl/err.h>
#include <zlib.h>

#include "proone_pack.h"


static void report_unpack_bin_archive_err (const proone_unpack_bin_archive_result_t *r) {
    const char *err_str, *err_msg = NULL;

    switch (r->result) {
    case PROONE_UNPACK_BIN_ARCHIVE_OK:
        err_str = "ok";
        break;
    case PROONE_UNPACK_BIN_ARCHIVE_OPENSSL_ERR:
        err_str = "openssl error";
        err_msg = ERR_error_string(r->err, NULL);
        break;
    case PROONE_UNPACK_BIN_ARCHIVE_Z_ERR:
        err_str = "zlib error";
        err_msg = zError((int)r->err);
        break;
    case PROONE_UNPACK_BIN_ARCHIVE_ERRNO:
        err_str = "errno";
        err_msg = strerror((int)r->err);
        break;
    case PROONE_UNPACK_BIN_ARCHIVE_MEM_ERR:
        err_str = "memory error";
        err_msg = strerror((int)r->err);
        break;
    default:
        err_str = "* unknown";
    }

    if (err_msg == NULL) {
        fprintf(stderr, "%s.\n", err_str);
    }
    else {
        fprintf(stderr, "%s: %s\n", err_str, err_msg);
    }
}

static void report_index_bin_archive_err (const proone_index_bin_archive_result_code_t c) {
    const char *msg;

    switch (c) {
    case PROONE_INDEX_BIN_ARCHIVE_OK:
        msg = "ok"; break;
    case PROONE_INDEX_BIN_ARCHIVE_FMT_ERR:
        msg = "format error"; break;
    case PROONE_INDEX_BIN_ARCHIVE_MEM_ERR:
        msg = "memory error"; break;
    default:
        msg = "* unknown"; break;
    }

    fprintf(stderr, "%s.\n", msg);
}

int main (const int argc, const char **args) {
    int exit_code = 0;
    const char *path_prefix;
    size_t path_prefix_len;
    proone_unpack_bin_archive_result_t unpack_ret;
    proone_bin_archive_t bin_archive;
    proone_index_bin_archive_result_code_t index_ret;
    size_t i;
    const char *arch_str;
    char *path = NULL;
    size_t path_size;
    void *ny_buf;
    int fd = -1;

    if (argc <= 1) {
        fprintf(stderr, "Usage: %s <prefix>\n", args[0]);
        return 1;
    }

    path_prefix = args[1];
    path_prefix_len = strlen(path_prefix);
    proone_init_bin_archive(&bin_archive);

    do { // fake loop
        unpack_ret = proone_unpack_bin_archive(STDIN_FILENO);
        if (unpack_ret.result != PROONE_UNPACK_BIN_ARCHIVE_OK) {
            report_unpack_bin_archive_err(&unpack_ret);
            exit_code = 2;
            break;
        }

        index_ret = proone_index_bin_archive(&unpack_ret, &bin_archive);
        if (index_ret != PROONE_INDEX_BIN_ARCHIVE_OK) {
            report_index_bin_archive_err(index_ret);
            exit_code = 2;
            break;
        }

        for (i = 0; i < bin_archive.nb_binaries; i += 1) {
            arch_str = proone_arch2str(bin_archive.arch_arr[i]);
            if (arch_str == NULL) {
                fprintf(stderr, "** unrecognised arch!");
                exit_code = 2;
                break;
            }
            
            path_size = 2 + path_prefix_len + strlen(arch_str);
            ny_buf = realloc(path, path_size);
            if (ny_buf == NULL) {
                perror("realloc()");
                exit_code = 2;
                break;
            }
            path = (char*)ny_buf;
            sprintf(path, "%s.%s", path_prefix, arch_str);

            fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0666);
            if (fd < 0) {
                perror("open()");
                exit_code = 2;
                break;
            }
            if (write(fd, bin_archive.data + bin_archive.offset_arr[i], bin_archive.size_arr[i]) != (ssize_t)bin_archive.size_arr[i]) {
                perror("write()");
                exit_code = 2;
                break;
            }
            close(fd);
        }
    } while (false);

    free(path);
    close(fd);
    proone_free_unpack_bin_archive_result(&unpack_ret);
    proone_free_bin_archive(&bin_archive);

    return exit_code;
}
