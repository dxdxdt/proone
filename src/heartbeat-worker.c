#include "heartbeat-worker.h"
#include "util_rt.h"
#include "dvault.h"

#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define DECL_CTX_PTR(p) hb_w_ctx_t *ctx = (hb_w_ctx_t*)p;

typedef struct hb_w_ctx hb_w_ctx_t;

struct hb_w_ctx {
	int fd;
	int domain;
	uint8_t rcv_buf[256];
	bool finalised;
};

static const uint16_t HEARTBEAT_DEFAULT_BIND_PORT = 55420;

static void heartbeat_worker_free (void *in_ctx) {
	DECL_CTX_PTR(in_ctx);
	close(ctx->fd);
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


bool prne_alloc_heartbeat_worker (prne_worker_t *w) {
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
		local_addr.sin_port = htons(HEARTBEAT_DEFAULT_BIND_PORT);
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
		local_addr.sin6_port = htons(HEARTBEAT_DEFAULT_BIND_PORT);		

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
			close(ctx->fd);
		}
		prne_free(ctx);
	}

	return ret;
}
