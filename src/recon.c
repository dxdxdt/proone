#include "recon.h"
#include "config.h"
#include "rnd.h"
#include "llist.h"
#include "util_rt.h"
#include "endian.h"
#include "inet.h"

#include <string.h>
#include <errno.h>

#include <unistd.h>
#include <fcntl.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>

#include <ifaddrs.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>


static const struct timespec RCN_ERR_PAUSE_INT = { 1, 0 }; // 1 s
#define RCN_II_UPDATE_INT_MIN 43200 // 0.5 days
#define RCN_II_UPDATE_INT_VAR 43200 // 0.5 days
#define RCN_SRC_PORT_MIN 1024
#define RCN_SRC_PORT_VAR 64511
// 800ms ~ 1200ms tick
#define RCN_SYN_TICK_MIN 800
#define RCN_SYN_TICK_VAR 400
// 60 ~ 160 syn packets per tick
static const uint_fast32_t RCN_SYN_PPT_MIN = 60;
static const uint_fast32_t RCN_SYN_PPT_VAR = 100;

#define RCN_IDX_IPV4	0
#define RCN_IDX_IPV6	1
#define RCN_NB_FD		2

typedef struct {
	uint32_t cur;
	uint32_t max;
} rcn_srcaddr_ctr_t;

typedef struct {
	prne_ip_addr_t ep;
	uint8_t network[16];
	uint8_t hostmask[16];
	rcn_srcaddr_ctr_t ctr;
} rcn_ifaceinfo_t;

struct prne_recon {
	prne_recon_param_t param;
	pth_mutex_t lock;
	pth_cond_t cond;
	prne_rnd_t rnd;
	struct {
		struct timespec ii_up; // next subnet update
	} ts;
	prne_llist_t ii_list;
	prne_llist_entry_t *ii_ptr;
	size_t t_ptr;
	int fd[RCN_NB_FD][2];
	uint8_t v6_saddr[16];
	uint8_t v4_saddr[4];
	uint32_t seq_mask;
	uint16_t s_port;
	bool loop;
	bool send_ptr;
};

static void rcn_main_empty_ii_list (prne_recon_t *ctx) {
	prne_llist_entry_t *ent = ctx->ii_list.head;

	while (ent != NULL) {
		prne_free((void*)ent->element);
		ent = ent->next;
	}
	prne_llist_clear(&ctx->ii_list);
	ctx->ii_ptr = NULL;
}

static bool rcn_main_good_iface (const struct ifaddrs *ia) {
	return
		ia->ifa_addr != NULL &&
		ia->ifa_netmask != NULL &&
		(ia->ifa_flags & 0x1) && // up
		!(ia->ifa_flags & 0x8); // and not loopback
}

static uint32_t rcn_build_srcaddr4_ctr (const uint8_t *arr) {
	return ~prne_recmb_msb32(arr[0], arr[1], arr[2], arr[3]);
}

static uint32_t rcn_build_srcaddr6_ctr (const uint8_t *arr) {
	return ~prne_recmb_msb32(arr[14], arr[13], arr[14], arr[15]);
}

static bool rcn_main_do_ifaddrs (prne_recon_t *ctx) {
	bool ret = false;
	struct ifaddrs *ia_arr = NULL, *ia_ent;
	struct sockaddr_in *sa4;
	struct sockaddr_in6 *sa6;
	rcn_ifaceinfo_t *info;
	prne_llist_entry_t *ent;

	rcn_main_empty_ii_list(ctx);

	if (getifaddrs(&ia_arr) != 0) {
		goto END;
	}

	for (ia_ent = ia_arr; ia_ent != NULL; ia_ent = ia_ent->ifa_next) {
		if (!rcn_main_good_iface(ia_ent)) {
			continue;
		}

		switch (ia_ent->ifa_addr->sa_family) {
		case AF_INET:
			if (ctx->fd[RCN_IDX_IPV4][1] < 0) {
				continue;
			}
			break;
		case AF_INET6:
			if (ctx->fd[RCN_IDX_IPV6][1] < 0) {
				continue;
			}
			break;
		}

		switch (ia_ent->ifa_addr->sa_family) {
		case AF_INET6:
			sa6 = (struct sockaddr_in6*)ia_ent->ifa_addr;
			if (sa6->sin6_scope_id != 0) {
				continue;
			}
			/* fall-through */
		case AF_INET:
			ent = prne_llist_append(&ctx->ii_list, 0);
			if (ent == NULL) {
				goto END;
			}
			info = (rcn_ifaceinfo_t*)prne_calloc(sizeof(rcn_ifaceinfo_t), 1);
			if (info == NULL) {
				goto END;
			}
			ent->element = (prne_llist_element_t)info;
			break;
		default: continue;
		}

		switch (ia_ent->ifa_addr->sa_family) {
		case AF_INET:
			info->ep.ver = PRNE_IPV_4;
			sa4 = (struct sockaddr_in*)ia_ent->ifa_addr;
			memcpy(info->ep.addr, &sa4->sin_addr, 4);

			sa4 = (struct sockaddr_in*)ia_ent->ifa_netmask;
			prne_bitop_and(
				info->ep.addr,
				(const uint8_t*)&sa4->sin_addr,
				info->network,
				4);
			prne_bitop_inv((const uint8_t*)&sa4->sin_addr, info->hostmask, 4);
			info->ctr.max = rcn_build_srcaddr4_ctr(
				(const uint8_t*)&sa4->sin_addr);
			break;
		case AF_INET6:
			info->ep.ver = PRNE_IPV_6;
			sa6 = (struct sockaddr_in6*)ia_ent->ifa_addr;
			memcpy(info->ep.addr, &sa6->sin6_addr, 16);

			sa6 = (struct sockaddr_in6*)ia_ent->ifa_netmask;
			prne_bitop_and(
				info->ep.addr,
				(const uint8_t*)&sa6->sin6_addr,
				info->network,
				16);
			prne_bitop_inv((const uint8_t*)&sa6->sin6_addr, info->hostmask, 16);
			info->ctr.max = rcn_build_srcaddr6_ctr(
				(const uint8_t*)&sa6->sin6_addr);
			break;
		}
	}

	ctx->ii_ptr = ctx->ii_list.head;
	ret = true;
END:
	if (!ret) {
		rcn_main_empty_ii_list(ctx);
	}
	freeifaddrs(ia_arr);

	return ret;
}

static prne_ipv_t rcn_main_genaddr_ii (
	prne_recon_t *ctx,
	uint8_t *src,
	uint8_t *dst)
{
	prne_ipv_t ret = PRNE_IPV_NONE;
	rcn_ifaceinfo_t *info;
	size_t l;

	while (ctx->ii_ptr != NULL && ret == PRNE_IPV_NONE) {
		info = (rcn_ifaceinfo_t*)ctx->ii_ptr->element;

		if (info->ctr.cur >= info->ctr.max) {
			prne_free(info);
			ctx->ii_ptr = prne_llist_erase(&ctx->ii_list, ctx->ii_ptr);
		}
		else {
			ctx->ii_ptr = ctx->ii_ptr->next;
			switch (info->ep.ver) {
			case PRNE_IPV_4: l = 4; break;
			case PRNE_IPV_6: l = 16; break;
			default: abort();
			}

			memcpy(src, info->ep.addr, l);
			prne_rnd(&ctx->rnd, dst, l);
			prne_bitop_and(dst, info->hostmask, dst, l);
			prne_bitop_or(dst, info->network, dst, l);

			info->ctr.cur += 1;
			if (memcmp(src, dst, l) != 0) {
				ret = info->ep.ver;
			}
		}

		if (ctx->ii_ptr == NULL) {
			ctx->ii_ptr = ctx->ii_list.head;
		}
	}

	return ret;
}

static void rcn_main_update_saddr (prne_recon_t *ctx) {
	int fd;
	socklen_t sl;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd >= 0) {
		static const uint8_t TEST_ADDR[4] = { 192, 0, 2, 1 };
		struct sockaddr_in sa;

		prne_memzero(&sa, sizeof(sa));
		sa.sin_family = AF_INET;
		sa.sin_port = 1024;
		memcpy(&sa.sin_addr, TEST_ADDR, 4);

		sl = sizeof(sa);
		if (connect(fd, (struct sockaddr*)&sa, sl) == 0 &&
			getsockname(fd, (struct sockaddr*)&sa, &sl) == 0 &&
			sl >= sizeof(sa))
		{
			memcpy(ctx->v4_saddr, &sa.sin_addr, 4);
		}
		prne_close(fd);
	}

	fd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (fd >= 0) {
		static const uint8_t TEST_ADDR[16] = {
			0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
		};
		struct sockaddr_in6 sa;

		prne_memzero(&sa, sizeof(sa));
		sa.sin6_family = AF_INET6;
		sa.sin6_port = 1024;
		memcpy(&sa.sin6_addr, TEST_ADDR, 16);

		sl = sizeof(sa);
		if (connect(fd, (struct sockaddr*)&sa, sl) == 0 &&
			getsockname(fd, (struct sockaddr*)&sa, &sl) == 0 &&
			sl >= sizeof(sa))
		{
			memcpy(ctx->v6_saddr, &sa.sin6_addr, 16);
		}
		prne_close(fd);
	}
}

static prne_ipv_t rcn_main_genaddr_param (
	prne_recon_t *ctx,
	uint8_t *src,
	uint8_t *dst)
{
	const prne_recon_network_t *net;

	for (size_t i = 0; i < ctx->param.target.cnt; i += 1) {
		ctx->t_ptr = (ctx->t_ptr + 1) % ctx->param.target.cnt;
		net = ctx->param.target.arr + ctx->t_ptr;

		switch (net->addr.ver) {
		case PRNE_IPV_4:
			if (ctx->fd[RCN_IDX_IPV4][1] < 0) {
				continue;
			}
			prne_rnd(&ctx->rnd, dst, 4);
			prne_bitop_inv(net->mask, src, 4); // use src as host mask
			prne_bitop_and(src, dst, dst, 4); // extract host
			prne_bitop_or(net->addr.addr, dst, dst, 4); // combine with network
			memcpy(src, ctx->v4_saddr, 4);
			return PRNE_IPV_4;
		case PRNE_IPV_6:
			if (ctx->fd[RCN_IDX_IPV6][1] < 0) {
				continue;
			}
			prne_rnd(&ctx->rnd, dst, 16);
			prne_bitop_inv(net->mask, src, 16); // use src as host mask
			prne_bitop_and(src, dst, dst, 16); // extract host
			prne_bitop_or(net->addr.addr, dst, dst, 16); // combine with network
			memcpy(src, ctx->v6_saddr, 16);
			return PRNE_IPV_6;
		}
	}

	return PRNE_IPV_NONE;
}

static prne_ipv_t rcn_main_gen_addr (
	prne_recon_t *ctx,
	uint8_t *src,
	uint8_t *dst,
	int *snd_flags)
{
	prne_ipv_t ret = PRNE_IPV_NONE;

	ctx->send_ptr = !ctx->send_ptr;
	if (ctx->send_ptr) {
		ret = rcn_main_genaddr_ii(ctx, src, dst);
		if (ret != PRNE_IPV_NONE) {
			*snd_flags |= MSG_DONTROUTE;
			return ret;
		}
	}
	return rcn_main_genaddr_param(ctx, src, dst);
}

static bool rcn_main_chk_blist (
	prne_recon_t *ctx,
	const prne_ipv_t v,
	uint8_t *addr)
{
	const prne_recon_network_t *net;
	uint8_t tmp[16];
	size_t l = 0;

	for (size_t i = 0; i < ctx->param.blist.cnt; i += 1) {
		net = ctx->param.blist.arr + i;

		if (net->addr.ver != v) {
			continue;
		}
		switch (v) {
		case PRNE_IPV_4: l = 4; break;
		case PRNE_IPV_6: l = 16; break;
		}

		prne_bitop_and(addr, net->mask, tmp, l);
		if (memcmp(tmp, net->addr.addr, l) == 0) {
			return true;
		}
	}

	return false;
}

static void rcn_main_send_syn (prne_recon_t *ctx) {
	prne_ipv_t ret;
	uint8_t src[16], dst[16];
	uint8_t m_head[prne_op_max(sizeof(prne_iphdr4_t), sizeof(prne_iphdr6_t))];
	uint8_t m_pkt[40 + sizeof(struct tcphdr)];
	uint8_t m_sa[prne_op_max(
		sizeof(struct sockaddr_in),
		sizeof(struct sockaddr_in6))];
	prne_iphdr4_t *ih4;
	prne_iphdr6_t *ih6;
	struct sockaddr_in *sa4;
	struct sockaddr_in6 *sa6;
	socklen_t sl = 0;
	struct tcphdr th;
	size_t coin, pkt_len = 0;
	uint16_t d_port;
	int snd_flags = MSG_NOSIGNAL, f_ret, fd = -1;

	ret = rcn_main_gen_addr(ctx, src, dst, &snd_flags);
	if (ret == PRNE_IPV_NONE || rcn_main_chk_blist(ctx, ret, dst)) {
		return;
	}

	prne_memzero(m_head, sizeof(m_head));
	prne_memzero(m_sa, sizeof(m_sa));
	prne_memzero(&th, sizeof(th));
	prne_rnd(&ctx->rnd, (uint8_t*)&coin, sizeof(coin));
	d_port = ctx->param.ports.arr[coin % ctx->param.ports.cnt];

	th.source = htons(ctx->s_port);
	th.dest = htons(d_port);
	th.doff = 5;
	th.syn = 1;
	prne_rnd(&ctx->rnd, (uint8_t*)&th.window, sizeof(th.window));
	th.window = htons(100 + (th.window % (UINT16_MAX - 100)));

	switch (ret) {
	case PRNE_IPV_4:
		ih4 = (prne_iphdr4_t*)m_head;
		ih4->ihl = 5;
		ih4->total_len = 20 + sizeof(struct tcphdr);
		// let kernel fill this in
		// prne_rnd(&ctx->rnd, &ih4->id, sizeof(ih4->id));
		ih4->ttl = 64;
		ih4->protocol = IPPROTO_TCP;
		memcpy(ih4->saddr, src, 4);
		memcpy(ih4->daddr, dst, 4);
		// filled in by kernel
		// ih4->check = htons(rcn_main_ih_chk(m_head, sizeof(struct iphdr)));

		th.seq =
			prne_recmb_msb32(dst[0], dst[1], dst[2], dst[3]) ^
			ctx->seq_mask;
		th.seq = htonl(th.seq);
		th.check = htons(prne_calc_tcp_chksum4(
			ih4,
			(const uint8_t*)&th,
			sizeof(th),
			NULL,
			0));

		prne_ser_iphdr4(m_pkt, ih4);
		memcpy(m_pkt + 20, &th, sizeof(struct tcphdr));
		pkt_len = 20 + sizeof(struct tcphdr);

		sa4 = (struct sockaddr_in*)m_sa;
		sa4->sin_family = AF_INET;
		memcpy(&sa4->sin_addr, dst, 4);
		sl = sizeof(struct sockaddr_in);
		fd = ctx->fd[RCN_IDX_IPV4][1];

		if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_DBG0 + 1) {
			char s_str[INET_ADDRSTRLEN];
			char d_str[INET_ADDRSTRLEN];

			prne_assert(
				inet_ntop(AF_INET, ih4->saddr, s_str, sizeof(s_str)) &&
				inet_ntop(AF_INET, ih4->daddr, d_str, sizeof(d_str)));
			prne_dbgpf(
				"Send SYN %s:%"PRIu16 " -> %s:%"PRIu16"\n",
				s_str,
				ntohs(th.source),
				d_str,
				ntohs(th.dest));
		}
		break;
	case PRNE_IPV_6:
		ih6 = (prne_iphdr6_t*)m_head;
		prne_rnd(
			&ctx->rnd,
			(uint8_t*)&ih6->flow_label,
			sizeof(ih6->flow_label));
		ih6->payload_len = sizeof(struct tcphdr);
		ih6->next_hdr = IPPROTO_TCP;
		ih6->hop_limit = 64;
		memcpy(ih6->saddr, src, 16);
		memcpy(ih6->daddr, dst, 16);

		th.seq =
			prne_recmb_msb32(dst[0], dst[1], dst[2], dst[3]) ^
			prne_recmb_msb32(dst[4], dst[5], dst[6], dst[7]) ^
			prne_recmb_msb32(dst[8], dst[9], dst[10], dst[11]) ^
			prne_recmb_msb32(dst[12], dst[13], dst[14], dst[15]) ^
			ctx->seq_mask;
		th.seq = htonl(th.seq);
		th.check = htons(prne_calc_tcp_chksum6(
			ih6,
			(const uint8_t*)&th,
			sizeof(th),
			NULL,
			0));

		prne_ser_iphdr6(m_pkt, ih6);
		memcpy(m_pkt + 40, &th, sizeof(struct tcphdr));
		pkt_len = 40 + sizeof(struct tcphdr);

		sa6 = (struct sockaddr_in6*)m_sa;
		sa6->sin6_family = AF_INET6;
		memcpy(&sa6->sin6_addr, dst, 16);
		sl = sizeof(struct sockaddr_in6);
		fd = ctx->fd[RCN_IDX_IPV6][1];

		if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_DBG0 + 1) {
			char s_str[INET6_ADDRSTRLEN];
			char d_str[INET6_ADDRSTRLEN];

			prne_assert(
				inet_ntop(AF_INET6, ih6->saddr, s_str, sizeof(s_str)) &&
				inet_ntop(AF_INET6, ih6->daddr, d_str, sizeof(d_str)));
			prne_dbgpf(
				"Send SYN [%s]:%"PRIu16 " -> [%s]:%"PRIu16"\n",
				s_str,
				ntohs(th.source),
				d_str,
				ntohs(th.dest));
		}
		break;
	}

	f_ret = sendto(
		fd,
		m_pkt,
		pkt_len,
		snd_flags,
		(struct sockaddr*)m_sa,
		sl);
	if (f_ret < 0 && PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_DBG0) {
		prne_dbgperr("** SYN sendto()@rcn");
	}
}

static void rcn_main_recv_syn_tail (
	prne_recon_t *ctx,
	const struct tcphdr *th,
	const uint32_t exp_ack,
	const prne_net_endpoint_t *ep)
{
	if (ntohs(th->dest) == ctx->s_port &&
		ntohl(th->ack_seq) == exp_ack &&
		th->ack && th->syn && !th->rst && !th->fin)
	{
		ctx->param.evt_cb(ctx->param.cb_ctx, ep);
	}
}

static void rcn_main_recv_syn4 (prne_recon_t *ctx) {
	int f_ret;
	uint8_t buf[
		20 +
		60 + // options
		sizeof(struct tcphdr)];
	struct tcphdr th;
	prne_iphdr4_t ih;
	uint32_t exp_ack;
	prne_net_endpoint_t ep;

	while (true) {
		f_ret = recv(
			ctx->fd[RCN_IDX_IPV4][0],
			buf,
			sizeof(buf),
			0);
		if (f_ret < 0) {
			if (errno != EAGAIN &&
				errno != EWOULDBLOCK &&
				PRNE_DEBUG &&
				PRNE_VERBOSE >= PRNE_VL_ERR)
			{
				prne_dbgperr("** SYN recv()@rcn");
			}
			break;
		}
		if ((size_t)f_ret < 20) {
			continue;
		}
		prne_dser_iphdr4(buf, &ih);
		if (ih.ihl * 4 + sizeof(struct tcphdr) > (size_t)f_ret) {
			continue;
		}
		memcpy(&th, buf + ih.ihl * 4, sizeof(struct tcphdr));

		prne_memzero(&ep, sizeof(prne_net_endpoint_t));
		ep.addr.ver = PRNE_IPV_4;
		memcpy(ep.addr.addr, ih.saddr, 4);
		ep.port = ntohs(th.source);
		exp_ack = prne_recmb_msb32(
			ih.saddr[0],
			ih.saddr[1],
			ih.saddr[2],
			ih.saddr[3]) ^
			ctx->seq_mask;
		exp_ack += 1;
		rcn_main_recv_syn_tail(ctx, &th, exp_ack, &ep);
	}
}

static void rcn_main_recv_syn6 (prne_recon_t *ctx) {
	int f_ret;
	uint8_t buf[1024];
	prne_iphdr6_t ih;
	struct tcphdr th;
	size_t ext_pos;
	uint8_t next_hdr;
	uint32_t exp_ack;
	prne_net_endpoint_t ep;

LOOP:
	while (true) {
		f_ret = recv(
			ctx->fd[RCN_IDX_IPV6][0],
			buf,
			sizeof(buf),
			0);
		if (f_ret < 0) {
			if (errno != EAGAIN &&
				errno != EWOULDBLOCK &&
				PRNE_DEBUG &&
				PRNE_VERBOSE >= PRNE_VL_ERR)
			{
				prne_dbgperr("** SYN recv()@rcn");
			}
			break;
		}
		if ((size_t)f_ret < 40) {
			continue;
		}
		prne_dser_iphdr6(buf, &ih);

		ext_pos = 40;
		next_hdr = ih.next_hdr;
		while (next_hdr != IPPROTO_TCP && ext_pos + 1 > (size_t)f_ret) {
			switch (next_hdr) {
			case 0:
			case 43:
			case 60:
				if (ext_pos + 2 > (size_t)f_ret) {
					goto LOOP;
				}
				next_hdr = buf[ext_pos];
				ext_pos += buf[ext_pos + 1] * 8 + 8;
				break;
			case 59: // no next header
			default: // can't parse this packet
				goto LOOP;
			}
		}
		if ((size_t)f_ret < ext_pos + sizeof(struct tcphdr)) {
			continue;
		}
		memcpy(&th, buf + ext_pos, sizeof(struct tcphdr));

		prne_memzero(&ep, sizeof(prne_net_endpoint_t));
		ep.addr.ver = PRNE_IPV_6;
		memcpy(ep.addr.addr, ih.saddr, 16);
		ep.port = ntohs(th.source);
		exp_ack =
			prne_recmb_msb32(
				ep.addr.addr[0],
				ep.addr.addr[1],
				ep.addr.addr[2],
				ep.addr.addr[3]) ^
			prne_recmb_msb32(
				ep.addr.addr[4],
				ep.addr.addr[5],
				ep.addr.addr[6],
				ep.addr.addr[7]) ^
			prne_recmb_msb32(
				ep.addr.addr[8],
				ep.addr.addr[9],
				ep.addr.addr[10],
				ep.addr.addr[11]) ^
			prne_recmb_msb32(
				ep.addr.addr[12],
				ep.addr.addr[13],
				ep.addr.addr[14],
				ep.addr.addr[15]) ^
			ctx->seq_mask;
		exp_ack += 1;
		rcn_main_recv_syn_tail(ctx, &th, exp_ack, &ep);
	}
}

static void rcn_main_recv_syn (prne_recon_t *ctx) {
	if (ctx->fd[RCN_IDX_IPV4][0] >= 0) {
		rcn_main_recv_syn4(ctx);
	}
	if (ctx->fd[RCN_IDX_IPV6][0] >= 0) {
		rcn_main_recv_syn6(ctx);
	}
}

static void *rcn_main_entry (void *ctx_p) {
	prne_recon_t *ctx = (prne_recon_t*)ctx_p;
	struct timespec ts_now;
	unsigned int syn_cnt, tick_dur;
	pth_event_t ev_root = NULL, ev;
	pth_time_t to_pth;
	struct timespec to_ts, tick_dur_ts;

	while (ctx->loop) {
		ts_now = prne_gettime(CLOCK_MONOTONIC);

		// periodic op
		if (prne_cmp_timespec(ctx->ts.ii_up, ts_now) <= 0) {
			unsigned int n;

			rcn_main_update_saddr(ctx);

			if (rcn_main_do_ifaddrs(ctx)) {
				prne_rnd(&ctx->rnd, (uint8_t*)&n, sizeof(n));
				n = RCN_II_UPDATE_INT_MIN + (n % RCN_II_UPDATE_INT_VAR);
				ctx->ts.ii_up = prne_add_timespec(ts_now, prne_ms_timespec(n));
			}
			else {
				ctx->ts.ii_up = prne_add_timespec(ts_now, RCN_ERR_PAUSE_INT);
			}

			prne_rnd(&ctx->rnd, (uint8_t*)&n, sizeof(n));
			ctx->s_port = (uint16_t)(RCN_SRC_PORT_MIN + (n % RCN_SRC_PORT_VAR));
		}

		// random
		prne_rnd(&ctx->rnd, (uint8_t*)&syn_cnt, sizeof(syn_cnt));
		syn_cnt = RCN_SYN_PPT_MIN + (syn_cnt % RCN_SYN_PPT_VAR);
		prne_rnd(&ctx->rnd, (uint8_t*)&tick_dur, sizeof(tick_dur));
		tick_dur = RCN_SYN_TICK_MIN + (tick_dur % RCN_SYN_TICK_VAR);
		prne_rnd(&ctx->rnd, (uint8_t*)&ctx->seq_mask, sizeof(ctx->seq_mask));

		for (unsigned int i = 0; i < syn_cnt; i += 1) {
			rcn_main_send_syn(ctx);
		}

		ts_now = prne_gettime(CLOCK_MONOTONIC);
		tick_dur_ts = prne_ms_timespec(tick_dur);
		to_pth = prne_pth_tstimeout(tick_dur_ts);
		to_ts = prne_add_timespec(ts_now, tick_dur_ts);
		while (ctx->loop) {
			ts_now = prne_gettime(CLOCK_MONOTONIC);
			if (prne_cmp_timespec(to_ts, ts_now) <= 0) {
				break;
			}

			// build event
			pth_event_free(ev_root, TRUE);
			ev_root = pth_event(PTH_EVENT_TIME, to_pth);
			prne_assert(ev_root != NULL);

			for (size_t i = 0; i < RCN_NB_FD; i += 1) {
				if (ctx->fd[i][0] < 0) {
					continue;
				}
				ev = pth_event(
					PTH_EVENT_FD | PTH_UNTIL_FD_READABLE,
					ctx->fd[i][0]);
				prne_assert(ev != NULL);
				pth_event_concat(ev_root, ev, NULL);
			}

			prne_dbgtrap(pth_mutex_acquire(&ctx->lock, FALSE, NULL));
			pth_cond_await(&ctx->cond, &ctx->lock, ev_root);
			pth_mutex_release(&ctx->lock);

			// process
			for (size_t i = 0; i < RCN_NB_FD; i += 1) {
				if (ctx->fd[i][0] < 0) {
					continue;
				}
				rcn_main_recv_syn(ctx);
			}
		}
	}

	pth_event_free(ev_root, TRUE);

	return NULL;
}

static void rcn_free_f (void *ctx_p) {
	prne_recon_t *ctx = (prne_recon_t*)ctx_p;

	if (ctx == NULL) {
		return;
	}

	rcn_main_empty_ii_list(ctx);

	prne_free_rnd(&ctx->rnd);
	prne_free_llist(&ctx->ii_list);
	prne_close(ctx->fd[RCN_IDX_IPV4][0]);
	prne_close(ctx->fd[RCN_IDX_IPV4][1]);
	prne_close(ctx->fd[RCN_IDX_IPV6][0]);
	prne_close(ctx->fd[RCN_IDX_IPV6][1]);
	prne_free_recon_param(&ctx->param);

	prne_free(ctx);
}

static void rcn_fin_f (void *ctx_p) {
	prne_recon_t *ctx = (prne_recon_t*)ctx_p;

	prne_dbgtrap(pth_mutex_acquire(&ctx->lock, FALSE, NULL));
	ctx->loop = false;
	pth_cond_notify(&ctx->cond, TRUE);
	pth_mutex_release(&ctx->lock);
}

static void rcn_create_rsck (
	const int af,
	const int pp,
	int *fd)
{
	fd[0] = socket(AF_PACKET, SOCK_DGRAM, pp);
	fd[1] = socket(af, SOCK_RAW, IPPROTO_RAW);

	if (fd[0] < 0 ||
		fd[1] < 0 ||
		!prne_sck_fcntl(fd[0]) ||
		!prne_sck_fcntl(fd[1]))
	{
		prne_close(fd[0]);
		prne_close(fd[1]);
		fd[0] = -1;
		fd[1] = -1;
	}
}

prne_recon_t *prne_alloc_recon (
	prne_worker_t *wkr,
	mbedtls_ctr_drbg_context *ctr_drbg,
	const prne_recon_param_t *param)
{
	prne_recon_t *ctx = NULL;
	int fd[RCN_NB_FD][2] = {
		{ -1, -1 },
		{ -1, -1 }
	};
	uint8_t seed[PRNE_RND_WELL512_SEEDLEN];

	if (param->target.cnt == 0 ||
		param->ports.cnt == 0 ||
		param->evt_cb == NULL)
	{
		errno = EINVAL;
		return NULL;
	}

	rcn_create_rsck(AF_INET, htons(ETH_P_IP), fd[RCN_IDX_IPV4]);
	rcn_create_rsck(AF_INET6, htons(ETH_P_IPV6), fd[RCN_IDX_IPV6]);
	if (fd[RCN_IDX_IPV4][0] < 0 && fd[RCN_IDX_IPV6][0] < 0) {
		goto ERR;
	}

	ctx = (prne_recon_t*)prne_calloc(sizeof(prne_recon_t), 1);
	if (ctx == NULL) {
		goto ERR;
	}

	prne_init_recon_param(&ctx->param);
	pth_mutex_init(&ctx->lock);
	pth_cond_init(&ctx->cond);
	prne_init_rnd(&ctx->rnd);
	ctx->loop = true;

	ctx->fd[RCN_IDX_IPV4][0] = fd[RCN_IDX_IPV4][0];
	ctx->fd[RCN_IDX_IPV4][1] = fd[RCN_IDX_IPV4][1];
	ctx->fd[RCN_IDX_IPV6][0] = fd[RCN_IDX_IPV6][0];
	ctx->fd[RCN_IDX_IPV6][1] = fd[RCN_IDX_IPV6][1];

	if (mbedtls_ctr_drbg_random(ctr_drbg, seed, sizeof(seed)) != 0) {
		goto ERR;
	}
	if (!prne_rnd_alloc_well512(&ctx->rnd, seed)) {
		goto ERR;
	}

	ctx->param = *param;
	wkr->ctx = ctx;
	wkr->entry = rcn_main_entry;
	wkr->fin = rcn_fin_f;
	wkr->free_ctx = rcn_free_f;

	return ctx;
ERR:
	prne_close(fd[RCN_IDX_IPV4][0]);
	prne_close(fd[RCN_IDX_IPV4][1]);
	prne_close(fd[RCN_IDX_IPV6][0]);
	prne_close(fd[RCN_IDX_IPV6][1]);
	rcn_free_f(ctx);

	return NULL;
}

void prne_init_recon_param (prne_recon_param_t *p) {
	prne_memzero(p, sizeof(prne_recon_param_t));
}

void prne_free_recon_param (prne_recon_param_t *p) {
	if (p == NULL) {
		return;
	}

	if (p->ownership) {
		prne_free(p->blist.arr);
		prne_free(p->target.arr);
		prne_free(p->ports.arr);
	}
	prne_memzero(p, sizeof(prne_recon_param_t));
}

bool prne_alloc_recon_param (
	prne_recon_param_t *p,
	const size_t blist,
	const size_t target,
	const size_t ports)
{
	bool ret;

	if (p->ownership) {
		ret =
			prne_own_realloc(
				(void**)&p->blist.arr,
				&p->ownership,
				sizeof(prne_recon_network_t),
				&p->blist.cnt,
				blist) &&
			prne_own_realloc(
				(void**)&p->target.arr,
				&p->ownership,
				sizeof(prne_recon_network_t),
				&p->target.cnt,
				target) &&
			prne_own_realloc(
				(void**)&p->ports.arr,
				&p->ownership,
				sizeof(uint16_t),
				&p->ports.cnt,
				ports);
	}
	else {
		void *arr_blist = prne_malloc(
			sizeof(prne_recon_network_t),
			blist);
		void *arr_target = prne_malloc(
			sizeof(prne_recon_network_t),
			target);
		void *arr_ports = prne_malloc(sizeof(uint16_t), ports);

		ret =
			(blist > 0 && arr_blist == NULL) ||
			(target > 0 && arr_target == NULL) ||
			(ports > 0 && arr_ports == NULL);
		ret = !ret;
		if (ret) {
			memcpy(
				arr_blist,
				p->blist.arr,
				sizeof(prne_recon_network_t) *
					prne_op_min(p->blist.cnt, blist));
			memcpy(
				arr_target,
				p->target.arr,
				sizeof(prne_recon_network_t) *
					prne_op_min(p->target.cnt, target));
			memcpy(
				arr_ports,
				p->ports.arr,
				sizeof(uint16_t) *
					prne_op_min(p->ports.cnt, ports));
			p->blist.arr = (prne_recon_network_t*)arr_blist;
			p->blist.cnt = blist;
			p->target.arr = (prne_recon_network_t*)arr_target;
			p->target.cnt = target;
			p->ports.arr = (uint16_t*)arr_ports;
			p->ports.cnt = ports;
			p->ownership = true;
		}
		else {
			prne_free(arr_blist);
			prne_free(arr_target);
			prne_free(arr_ports);
		}
	}

	return ret;
}

prne_recon_param_t prne_own_recon_param (
	const prne_recon_param_t *p,
	const bool ownership)
{
	prne_recon_param_t ret = *p;
	ret.ownership = ownership;
	return ret;
}
