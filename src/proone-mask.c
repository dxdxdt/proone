#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include <unistd.h>
#include <fcntl.h>

#include "dvault.h"


static const char *RND_DEV_PATH = "/dev/random";

int main (const int argc, const char **args) {
    int exit_code = 0;
    int rnd_fd = -1;
    ssize_t fd_read_size;
    uint8_t salt;
    size_t read_size = 0;
    prne_dvault_mask_result_t mask_result;
    prne_data_type_t type;

    prne_init_dvault_mask_result(&mask_result);

    if (argc <= 1) {
        fprintf(stderr,
            "Usage: %s <type>\n"
            "<type>: 'cstr'\n"
            "\n"
            "using random device: %s\n",
            args[0], RND_DEV_PATH);
        exit_code = 2;
        goto END;
    }

    rnd_fd = open(RND_DEV_PATH, O_RDONLY);
    if (rnd_fd < 0) {
        perror("Error opening random device");
        exit_code = 1;
        goto END;
    }

    fd_read_size = read(rnd_fd, &salt, 1);
    if (fd_read_size < 0) {
        perror("Error reading random device");
        exit_code = 1;
        goto END;
    }
    if (fd_read_size == 0) {
        fprintf(stderr, "Nothing read from random device. Low entropy?\n");
        exit_code = 1;
        goto END;
    }
    close(rnd_fd);
    rnd_fd = -1;

    type = prne_str2data_type(args[1]);
    switch (type) {
    case PRNE_DATA_TYPE_CSTR: {
        static const size_t buf_size = 0x0000FFFF + 1;
        uint8_t buf[buf_size];

        do {
            fd_read_size = read(STDIN_FILENO, buf + read_size, buf_size - read_size);
            if (fd_read_size < 0) {
                perror("Error reading stdin");
                exit_code = 1;
                goto END;
            }
            if (fd_read_size > 0) {
                read_size += fd_read_size;
                if (read_size >= buf_size) {
                    fprintf(stderr, "Error: data too large\n");
                    exit_code = 1;
                    goto END;
                }
            }
        } while (fd_read_size > 0);

        if (read_size == 0) {
            fprintf(stderr, "Error: no data read\n");
            exit_code = 1;
            goto END;
        }

        mask_result = prne_dvault_mask(type, salt, read_size, buf);
        if (mask_result.result == PRNE_DVAULT_MASK_OK) {
            printf("(uint8_t*)\"%s\"\n", mask_result.str);
        }
        else {
            fprintf(stderr, "Error: prne_dvault_mask() returned %d\n", (int)mask_result.result);
            exit_code = 1;
            goto END;
        }
        break;
    }
    default:
        fprintf(stderr, "Error: unknown data type '%s'\n", args[1]);
        exit_code = 2;
        goto END;
    }    

END:
    close(rnd_fd);
    prne_free_dvault_mask_result(&mask_result);

    return exit_code;
}
