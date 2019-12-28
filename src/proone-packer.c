#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sendfile.h>
#include <fcntl.h>

#include "proone_protocol.h"


int main (const int argc, const char **args) {
    typedef struct {
        proone_arch_t arch;
        const char *path;
    } archive_tuple_t;
    size_t i;
    const archive_tuple_t *encounter_arr[NB_PROONE_ARCH];
    archive_tuple_t archive_arr[NB_PROONE_ARCH];
    archive_tuple_t *archive;
    size_t archive_arr_cnt = 0;
    const char *path, *ext;
    bool proc_result = true;
    proone_arch_t arch;
    int bin_fd = -1;
    struct stat st;
    uint8_t head[4];

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
    if (argc - 1 > NB_PROONE_ARCH) {
        fprintf(stderr, "** Too many files given (%d > %d).\n", argc - 1, NB_PROONE_ARCH);
        return 1;
    }

    // init
    memset(encounter_arr, 0, sizeof(archive_tuple_t*) * NB_PROONE_ARCH);
    memset(archive_arr, 0, sizeof(archive_tuple_t) * NB_PROONE_ARCH);

    // Check the file names are valid
    for (i = 1; i < (size_t)argc; i += 1) {
        path = args[i];

        ext = strrchr(path, '.');
        if (ext == NULL) {
            fprintf(stderr, "** %s: file extension not found\n", path);
            proc_result = false;
            continue;
        }
        ext += 1;

        arch = proone_str2arch(ext);
        if (arch == PROONE_ARCH_NONE) {
            fprintf(stderr, "** %s: unknown arch \"%s\"\n", path, ext);
            proc_result = false;
            continue;
        }

        if (encounter_arr[arch] != NULL) {
            fprintf(stderr, "** Duplicate arch!\n%s\n%s\n", encounter_arr[arch]->path, path);
            proc_result = false;
            continue;
        }

        archive_arr[archive_arr_cnt].arch = arch;
        archive_arr[archive_arr_cnt].path = path;
        encounter_arr[arch] = &archive_arr[archive_arr_cnt];
        archive_arr_cnt += 1;
    }
    if (!proc_result) {
        return 1;
    }

    // do packing
    fprintf(stderr, archive_arr_cnt == NB_PROONE_ARCH ? "Packing %zu binaries.\n" : "* Warning: packing only %zu binaries\n", archive_arr_cnt);
    for (i = 0; i < archive_arr_cnt; i += 1) {
        archive = &archive_arr[i];
        fprintf(stderr, "Packing: %s ...\n", archive->path);

        bin_fd = open(archive->path, O_RDONLY);
        if (bin_fd < 0) {
            perror("** open()");
            proc_result = false;
            break;
        }

        // get size
        if (fstat(bin_fd, &st) != 0) {
            perror("** fstat()");
            proc_result = false;
            break;
        }
        if (st.st_size == 0) {
            fprintf(stderr, "** empty file!\n");
            proc_result = false;
            break;
        }
        if (st.st_size > 0x00FFFFFE) {
            fprintf(stderr, "** binary too large!\n");
            proc_result = false;
            break;
        }

        // write head
        head[0] = (uint8_t)archive->arch;
        // endian conversion as the file is big endian
        head[1] = (uint8_t)(((uint32_t)st.st_size & 0x00FF0000) >> 16);
        head[2] = (uint8_t)(((uint32_t)st.st_size & 0x0000FF00) >> 8);
        head[3] = (uint8_t)((uint32_t)st.st_size & 0x000000FF);
        if (write(STDOUT_FILENO, head, 4) != 4) {
            perror("write()");
            proc_result = false;
            break;
        }
        
        // write binary
        if (sendfile(STDOUT_FILENO, bin_fd, NULL, st.st_size) < 0) {
            perror("** sendfile()");
            proc_result = false;
            break;
        }

        close(bin_fd);
        bin_fd = -1;
    }

    close(bin_fd);
    bin_fd = -1;
    errno = 0;

    return proc_result ? 0 : 2;
}
