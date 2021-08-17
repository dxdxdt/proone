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
#include <netinet/icmp6.h>
/*
* This header defines IFF_*. But since _POSIX_C_SOURCE=200112L has to be used,
* IFF_* flags can not be used.
*/
// #include <net/if.h>

#if PRNE_HOST_OS == PRNE_OS_LINUX
	#include <ifaddrs.h>
	#include <linux/if_ether.h>
	#include <linux/tcp.h>
#else
	#error "FIXME!"
#endif

static const struct timespec RCN_ERR_PAUSE_INT = { 10, 0 }; // 10 s
#define RCN_II_UPDATE_INT_MIN 43200000 // 0.5 days
#define RCN_II_UPDATE_INT_VAR 43200000 // 0.5 days
#define RCN_SRC_PORT_MIN 1024
#define RCN_SRC_PORT_VAR 64511
// 800ms ~ 1200ms tick
#define RCN_SYN_TICK_MIN 800
#define RCN_SYN_TICK_VAR 400
// 60 ~ 160 syn packets per tick
static const uint_fast32_t RCN_SYN_PPT_MIN = 60;
static const uint_fast32_t RCN_SYN_PPT_VAR = 100;
#define RCN_IPV6_PROBE_CNT 4

#define RCN_IDX_IPV4	0
#define RCN_IDX_IPV6	1
#define RCN_NB_FD		2

static const uint8_t RCN_IPV6_DST_LL[] = {
	0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
};
prne_static_assert(sizeof(RCN_IPV6_DST_LL) == 16, "RCN_IPV6_DST_LL");
static const uint8_t RCN_ICMP_ECHO_DATA[] = {
	' ', '!', '\"', '#', '$', '%', '&', '\'',
	'(', ')', '*', '+', ',', '-', '.',
	'/', '0', '1', '2', '3', '4', '5', '6', '7'
};

typedef struct {
	uint32_t cur;
	uint32_t max;
} rcn_srcaddr_ctr_t;

typedef struct {
	uint8_t addr[4];
	uint8_t network[4];
	uint8_t hostmask[4];
	rcn_srcaddr_ctr_t ctr;
} rcn_v4ifaceinfo_t;

typedef struct {
	uint8_t addr[16];
	uint32_t scope_id;
} rcn_v6ifaceinfo_t;

struct prne_recon {
	uint8_t buf[1504]; // typical MTU aligned to 8 bytes
	prne_recon_param_t param;
	pth_mutex_t lock;
	pth_cond_t cond;
	prne_rnd_t rnd;
	struct {
		struct timespec ii_up; // next subnet update
	} ts;
	struct {
		prne_llist_t list;
		prne_llist_entry_t *ptr;
	} v4_ii;
	struct {
		rcn_v6ifaceinfo_t *arr; // sorted by addr
		size_t cnt;
	} v6_ii;
	size_t t_ptr;
	size_t ping_cnt;
	int fd[RCN_NB_FD][2];
	struct timespec ts_now;
	uint8_t v6_saddr[16];
	uint8_t v4_saddr[4];
	uint32_t seq_mask;
	uint16_t s_port;
	bool loop;
	bool send_ptr;
};

static int rcn_v4ii_cmp_asc (const void *a, const void *b) {
	return memcmp(
		((rcn_v6ifaceinfo_t*)a)->addr,
		((rcn_v6ifaceinfo_t*)b)->addr,
		16);
}

static void rcn_main_empty_v4_ii (prne_recon_t *ctx) {
	prne_llist_entry_t *ent = ctx->v4_ii.list.head;

	while (ent != NULL) {
		prne_free((void*)ent->element);
		ent = ent->next;
	}
	prne_llist_clear(&ctx->v4_ii.list);
	ctx->v4_ii.ptr = NULL;
}

static void rcn_main_empty_v6_ii (prne_recon_t *ctx) {
	prne_free(ctx->v6_ii.arr);
	ctx->v6_ii.arr = NULL;
	ctx->v6_ii.cnt = 0;
}

static uint32_t rcn_build_srcaddr4_ctr (const uint8_t *arr) {
	return ~prne_recmb_msb32(arr[0], arr[1], arr[2], arr[3]);
}

static bool rcn_main_do_ifaddr_4 (
	prne_recon_t *ctx,
	const struct ifaddrs *ia,
	prne_llist_t *list)
{
	const struct ifaddrs *ia_ent;
	const struct sockaddr_in *sa;
	rcn_v4ifaceinfo_t *info;
	prne_llist_entry_t *ent;

	if (ctx->fd[RCN_IDX_IPV4][1] < 0) {
		return true;
	}

	for (ia_ent = ia; ia_ent != NULL; ia_ent = ia_ent->ifa_next) {
		if (ia_ent->ifa_addr->sa_family != AF_INET || // is not v4
			ia_ent->ifa_addr == NULL || // no address
			ia_ent->ifa_netmask == NULL || // no netmask
			(ia_ent->ifa_flags & 0x1) == 0 || // is not up
			(ia_ent->ifa_flags & 0x8) != 0) // is loopback
		{
			continue;
		}

		ent = prne_llist_append(list, 0);
		if (ent == NULL) {
			return false;
		}
		info = (rcn_v4ifaceinfo_t*)prne_calloc(sizeof(rcn_v4ifaceinfo_t), 1);
		if (info == NULL) {
			return false;
		}
		ent->element = (prne_llist_element_t)info;

		sa = (const struct sockaddr_in*)ia_ent->ifa_addr;
		memcpy(info->addr, &sa->sin_addr, 4);

		sa = (const struct sockaddr_in*)ia_ent->ifa_netmask;
		prne_bitop_and(
			info->addr,
			(const uint8_t*)&sa->sin_addr,
			info->network,
			4);
		prne_bitop_inv((const uint8_t*)&sa->sin_addr, info->hostmask, 4);
		info->ctr.max = rcn_build_srcaddr4_ctr((const uint8_t*)&sa->sin_addr);
	}

	return true;
}

static bool rcn_main_do_ifaddr_6 (
	prne_recon_t *ctx,
	const struct ifaddrs *ia,
	rcn_v6ifaceinfo_t **oarr,
	size_t *olen)
{
#define is_good_ia() \
	(ia_ent->ifa_addr->sa_family == AF_INET6 /* is v6 */ &&\
	ia_ent->ifa_addr != NULL /* has address */ &&\
	ia_ent->ifa_netmask != NULL /* has netmask */ &&\
	(ia_ent->ifa_flags & 0x1) != 0 /* is up */ &&\
	(ia_ent->ifa_flags & 0x8) == 0 /* is not loopback */ &&\
	(ia_ent->ifa_flags & 0x1000) != 0 /* supports multicast */ &&\
	/* is scoped */\
	((const struct sockaddr_in6*)ia_ent->ifa_addr)->sin6_scope_id != 0)

	const struct ifaddrs *ia_ent;
	const struct sockaddr_in6 *sa;
	rcn_v6ifaceinfo_t *info;
	size_t cnt = 0;

	if (ctx->fd[RCN_IDX_IPV6][1] < 0) {
		return true;
	}

	for (ia_ent = ia; ia_ent != NULL; ia_ent = ia_ent->ifa_next) {
		if (!is_good_ia()) {
			continue;
		}
		cnt += 1;
	}
	info = (rcn_v6ifaceinfo_t*)prne_malloc(sizeof(rcn_v6ifaceinfo_t), cnt);
	if (info == NULL && cnt > 0) {
		return false;
	}
	*oarr = info;
	*olen = cnt;

	for (ia_ent = ia; ia_ent != NULL; ia_ent = ia_ent->ifa_next) {
		if (!is_good_ia()) {
			continue;
		}
		sa = (const struct sockaddr_in6*)ia_ent->ifa_addr;
		memcpy(info->addr, &sa->sin6_addr, 16);
		info->scope_id = sa->sin6_scope_id;

		info += 1;
	}

	return true;
#undef is_good_ia
}

static bool rcn_main_do_ifaddrs (prne_recon_t *ctx) {
	bool ret = false;
	struct ifaddrs *ia;
	prne_llist_t v4list;
	rcn_v6ifaceinfo_t *v6arr = NULL;
	size_t v6cnt = 0;

	prne_init_llist(&v4list);

	if (getifaddrs(&ia) != 0) {
		goto END;
	}
	if (!rcn_main_do_ifaddr_4(ctx, ia, &v4list) ||
		!rcn_main_do_ifaddr_6(ctx, ia, &v6arr, &v6cnt))
	{
		goto END;
	}

	rcn_main_empty_v4_ii(ctx);
	prne_free_llist(&ctx->v4_ii.list);
	ctx->v4_ii.list = v4list;
	ctx->v4_ii.ptr = ctx->v4_ii.list.head;
	prne_init_llist(&v4list);
	rcn_main_empty_v6_ii(ctx);
	ctx->v6_ii.arr = v6arr;
	ctx->v6_ii.cnt = v6cnt;
	v6arr = NULL;
	v6cnt = 0;

	qsort(
		ctx->v6_ii.arr,
		ctx->v6_ii.cnt,
		sizeof(rcn_v6ifaceinfo_t),
		rcn_v4ii_cmp_asc);

	ret = true;
END:
	freeifaddrs(ia);
	prne_free_llist(&v4list);
	prne_free(v6arr);

	return ret;
}

static uint32_t rcn_main_get_iiv6_scope_id (
	prne_recon_t *ctx,
	const uint8_t *addr)
{
	rcn_v6ifaceinfo_t key;
	const rcn_v6ifaceinfo_t *found;

	// Because recvfrom() does not return scope_id ...
	memcpy(key.addr, addr, 16);
	key.scope_id = 0;
	found = (const rcn_v6ifaceinfo_t*)bsearch(
		&key,
		ctx->v6_ii.arr,
		ctx->v6_ii.cnt,
		sizeof(rcn_v6ifaceinfo_t),
		rcn_v4ii_cmp_asc);

	if (found == NULL) {
		return 0;
	}
	return found->scope_id;
}

static bool rcn_main_genaddr_ii_4 (
	prne_recon_t *ctx,
	uint8_t *src,
	uint8_t *dst)
{
	bool ret = false;
	rcn_v4ifaceinfo_t *info;

	while (ctx->v4_ii.ptr != NULL && !ret) {
		info = (rcn_v4ifaceinfo_t*)ctx->v4_ii.ptr->element;

		if (info->ctr.cur >= info->ctr.max) {
			prne_free(info);
			ctx->v4_ii.ptr = prne_llist_erase(&ctx->v4_ii.list, ctx->v4_ii.ptr);
		}
		else {
			ctx->v4_ii.ptr = ctx->v4_ii.ptr->next;

			memcpy(src, info->addr, 4);
			prne_rnd(&ctx->rnd, dst, 4);
			prne_bitop_and(dst, info->hostmask, dst, 4);
			prne_bitop_or(dst, info->network, dst, 4);

			info->ctr.cur += 1;
			if (memcmp(src, dst, 4) != 0) {
				ret = true;
			}
		}

		if (ctx->v4_ii.ptr == NULL) {
			ctx->v4_ii.ptr = ctx->v4_ii.list.head;
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
	if (ctx->send_ptr && rcn_main_genaddr_ii_4(ctx, src, dst)) {
		ret = PRNE_IPV_4;
		*snd_flags |= MSG_DONTROUTE;
		return ret;
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

static bool rcn_main_send_syn (
	prne_recon_t *ctx,
	const prne_ipv_t ipv,
	const uint8_t *src,
	const uint8_t *dst,
	const uint32_t dst_scope,
	const int snd_flags)
{
	prne_static_assert(
		sizeof(ctx->buf) >= 40 + sizeof(struct tcphdr),
		"buffer short for tcpv4");
	bool ret;
	uint8_t m_head[prne_op_max(sizeof(prne_iphdr4_t), sizeof(prne_iphdr6_t))];
	uint8_t m_sa[prne_op_max(
		sizeof(struct sockaddr_in),
		sizeof(struct sockaddr_in6))];
	prne_iphdr4_t *ih4;
	prne_iphdr6_t *ih6;
	struct sockaddr_in *sa4;
	struct sockaddr_in6 *sa6;
	socklen_t sl = 0;
	struct tcphdr th;
	size_t coin, pkt_len;
	uint16_t d_port;
	int f_ret, fd = -1;

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

	switch (ipv) {
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

		prne_ser_iphdr4(ctx->buf, ih4);
		memcpy(ctx->buf + 20, &th, sizeof(struct tcphdr));
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

		prne_ser_iphdr6(ctx->buf, ih6);
		memcpy(ctx->buf + 40, &th, sizeof(struct tcphdr));
		pkt_len = 40 + sizeof(struct tcphdr);

		sa6 = (struct sockaddr_in6*)m_sa;
		sa6->sin6_family = AF_INET6;
		memcpy(&sa6->sin6_addr, dst, 16);
		sa6->sin6_scope_id = dst_scope;
		sl = sizeof(struct sockaddr_in6);
		fd = ctx->fd[RCN_IDX_IPV6][1];

		if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_DBG0 + 1) {
			char s_str[INET6_ADDRSTRLEN];
			char d_str[INET6_ADDRSTRLEN];

			prne_assert(
				inet_ntop(AF_INET6, ih6->saddr, s_str, sizeof(s_str)) &&
				inet_ntop(AF_INET6, ih6->daddr, d_str, sizeof(d_str)));
			prne_dbgpf(
				"Send SYN [%s]:%"PRIu16 " -> [%s%%%"PRIu32"]:%"PRIu16"\n",
				s_str,
				ntohs(th.source),
				d_str,
				dst_scope,
				ntohs(th.dest));
		}
		break;
	default: abort();
	}

	f_ret = sendto(
		fd,
		ctx->buf,
		pkt_len,
		snd_flags | MSG_NOSIGNAL,
		(struct sockaddr*)m_sa,
		sl);
	prne_assert(f_ret != 0);
	ret = f_ret > 0;

	if (!ret) {
		if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_DBG0) {
			prne_dbgperr("** SYN sendto()@rcn");
		}
	}
	return ret;
}

static void rcn_main_do_syn (prne_recon_t *ctx) {
	prne_ipv_t ret;
	uint8_t src[16], dst[16];
	int snd_flags = 0;

	ret = rcn_main_gen_addr(ctx, src, dst, &snd_flags);
	if (ret == PRNE_IPV_NONE || rcn_main_chk_blist(ctx, ret, dst)) {
		return;
	}
	rcn_main_send_syn(ctx, ret, src, dst, 0, snd_flags);
}

// RFC7707 Section 4.3
static void rcn_main_send_v6probe_from (
	prne_recon_t *ctx,
	const rcn_v6ifaceinfo_t *from)
{
#define PKT_LEN\
	40 + /* IPv6 header */\
	8 + /* Malicious options */\
	sizeof(struct icmp6_hdr) + /* Legit ICMPv6 that shouldn't be processed */\
	sizeof(RCN_ICMP_ECHO_DATA) /* ECHO data */

	prne_static_assert(
		sizeof(ctx->buf) >= PKT_LEN,
		"buffer short for v6prove");
	prne_iphdr6_t iph;
	struct icmp6_hdr icmph;
	uint8_t *p = ctx->buf;
	struct sockaddr_in6 sa;
	int f_ret;

	prne_memzero(&iph, sizeof(iph));
	prne_memzero(&icmph, sizeof(icmph));
	prne_memzero(&sa, sizeof(sa));

	sa.sin6_family = AF_INET6;
	memcpy(&sa.sin6_addr, RCN_IPV6_DST_LL, 16);
	sa.sin6_scope_id = from->scope_id;

	iph.payload_len = 8 + sizeof(struct icmp6_hdr) + sizeof(RCN_ICMP_ECHO_DATA);
	iph.next_hdr = IPPROTO_ICMPV6;
	iph.hop_limit = 1;
	memcpy(iph.saddr, from->addr, 16);
	memcpy(iph.daddr, RCN_IPV6_DST_LL, 16);

	icmph.icmp6_type = ICMP6_ECHO_REQUEST;
	icmph.icmp6_id = htons((uint16_t)ctx->seq_mask);
	icmph.icmp6_cksum = htons(prne_calc_tcp_chksum6(
		&iph,
		(const uint8_t*)&icmph,
		sizeof(icmph),
		RCN_ICMP_ECHO_DATA,
		sizeof(RCN_ICMP_ECHO_DATA)));

	iph.next_hdr = IPPROTO_DSTOPTS;
	prne_ser_iphdr6(p, &iph);
	p += 40;
// https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml
// RFC4727
	p[0] = IPPROTO_ICMPV6;
	p[1] = 0;
	p[2] = 0x9e;
	p[3] = 4;
	prne_rnd(&ctx->rnd, p + 4, 4);
	p += 8;
	memcpy(p, &icmph, sizeof(icmph));
	p += sizeof(icmph);
	memcpy(p, RCN_ICMP_ECHO_DATA, sizeof(RCN_ICMP_ECHO_DATA));
	p += sizeof(RCN_ICMP_ECHO_DATA);

	if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_DBG0 + 1) {
		char s_str[INET6_ADDRSTRLEN];
		char d_str[INET6_ADDRSTRLEN];

		prne_assert(
			inet_ntop(AF_INET6, iph.saddr, s_str, sizeof(s_str)) &&
			inet_ntop(AF_INET6, iph.daddr, d_str, sizeof(d_str)));
		prne_dbgpf(
			"Send bogus ICMPv6 ECHO [%s%%%"PRIu32"] -> "
			"[%s] id=%"PRIu16" seq=%"PRIu16"\n",
			s_str,
			from->scope_id,
			d_str,
			ntohs(icmph.icmp6_id),
			ntohs(icmph.icmp6_seq));
	}

	f_ret = sendto(
		ctx->fd[RCN_IDX_IPV6][1],
		ctx->buf,
		PKT_LEN,
		MSG_NOSIGNAL,
		(struct sockaddr*)&sa,
		sizeof(sa));
	if (f_ret < 0 && PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_DBG0) {
		prne_dbgperr("** ICMPv6 sendto()@rcn");
	}
#undef PKT_LEN
}

static void rcn_main_send_icmpv6 (prne_recon_t *ctx) {
	for (size_t i = 0; i < ctx->v6_ii.cnt; i += 1) {
		rcn_main_send_v6probe_from(ctx, ctx->v6_ii.arr + i);
	}
}

static void rcn_main_recv_syn_tail (
	prne_recon_t *ctx,
	const uint8_t *daddr,
	const struct tcphdr *th,
	const uint32_t exp_ack,
	prne_net_endpoint_t *ep)
{
	if (ntohs(th->dest) == ctx->s_port &&
		ntohl(th->ack_seq) == exp_ack &&
		th->ack && th->syn && !th->rst && !th->fin)
	{
		if (ep->addr.ver == PRNE_IPV_6) {
			ep->addr.scope_id = rcn_main_get_iiv6_scope_id(ctx, daddr);
		}
		ctx->param.evt_cb(ctx->param.cb_ctx, ep);
	}
}

static bool rcn_main_recv_4 (prne_recon_t *ctx) {
	prne_static_assert(
		sizeof(ctx->buf) >= 20 + 60/*options*/ + sizeof(struct tcphdr),
		"buffer short for tcpv4");
	ssize_t f_ret;
	struct tcphdr th;
	prne_iphdr4_t ih;
	uint32_t exp_ack;
	prne_net_endpoint_t ep;

	f_ret = recv(
		ctx->fd[RCN_IDX_IPV4][0],
		ctx->buf,
		sizeof(ctx->buf),
		0);
	if (f_ret < 0) {
		if (errno != EAGAIN &&
			errno != EWOULDBLOCK &&
			PRNE_DEBUG &&
			PRNE_VERBOSE >= PRNE_VL_ERR)
		{
			prne_dbgperr("** recv()@rcn");
		}
		return false;
	}
	if (f_ret < 20) {
		return true;
	}
	prne_dser_iphdr4(ctx->buf, &ih);
	if (ih.ihl * 4 + sizeof(struct tcphdr) > (size_t)f_ret) {
		return true;
	}
	memcpy(&th, ctx->buf + ih.ihl * 4, sizeof(struct tcphdr));

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
	rcn_main_recv_syn_tail(ctx, ih.daddr, &th, exp_ack, &ep);

	return true;
}

static void rcn_main_recv_6_icmp_tail (
	prne_recon_t *ctx,
	const prne_iphdr6_t *ih)
{
	rcn_main_send_syn(
		ctx,
		PRNE_IPV_6,
		ih->daddr,
		ih->saddr,
		rcn_main_get_iiv6_scope_id(ctx, ih->daddr),
		MSG_DONTROUTE);
}

static bool rcn_main_recv_6 (prne_recon_t *ctx) {
	prne_static_assert(
		sizeof(ctx->buf) >= 40 + prne_op_max(
			sizeof(struct tcphdr),
			sizeof(struct icmp6_hdr)),
		"buffer short for tcpv6");
	ssize_t f_ret;
	prne_iphdr6_t ih;
	uint8_t m_hdr[prne_op_max(
		sizeof(struct tcphdr),
		sizeof(struct icmp6_hdr))];
	struct tcphdr *th;
	struct icmp6_hdr *icmph;
	size_t ext_pos;
	uint8_t next_hdr;
	uint32_t exp_ack;
	prne_net_endpoint_t ep;
	size_t data_len;
	uint8_t *p = ctx->buf;
	uint32_t pptr;

	prne_memzero(&ep, sizeof(prne_net_endpoint_t));
	ep.addr.ver = PRNE_IPV_6;

	f_ret = recv(
		ctx->fd[RCN_IDX_IPV6][0],
		ctx->buf,
		sizeof(ctx->buf),
		0);
	if (f_ret < 0) {
		if (errno != EAGAIN &&
			errno != EWOULDBLOCK &&
			PRNE_DEBUG &&
			PRNE_VERBOSE >= PRNE_VL_ERR)
		{
			prne_dbgperr("** SYN recv()@rcn");
		}
		return false;
	}
	if (f_ret < 40) {
		return true;
	}
	prne_dser_iphdr6(ctx->buf, &ih);

	if (memcmp(ih.saddr, ih.daddr, 16) == 0) {
		return true;
	}

	ext_pos = 40;
	next_hdr = ih.next_hdr;
	// skip ext headers
	while (next_hdr != IPPROTO_TCP && next_hdr != IPPROTO_ICMPV6) {
		switch (next_hdr) {
		case 0:
		case 43:
		case 60:
			if (ext_pos + 1 >= (size_t)f_ret) {
				return true;
			}
			next_hdr = ctx->buf[ext_pos];
			ext_pos += ctx->buf[ext_pos + 1] * 8 + 8;
			break;
		case 59: // no next header
		default: // can't parse this packet
			return true;
		}
	}

	memcpy(ep.addr.addr, ih.saddr, 16);
	p += ext_pos;
	switch (next_hdr) {
	case IPPROTO_TCP:
		if ((size_t)f_ret < ext_pos + sizeof(struct tcphdr)) {
			return true;
		}
		memcpy(m_hdr, p, sizeof(struct tcphdr));
		p += sizeof(struct tcphdr);
		th = (struct tcphdr*)m_hdr;

		ep.port = ntohs(th->source);
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
		rcn_main_recv_syn_tail(ctx, ih.daddr, th, exp_ack, &ep);
		break;
	case IPPROTO_ICMPV6:
		if ((size_t)f_ret < ext_pos + sizeof(struct icmp6_hdr)) {
			return true;
		}
		memcpy(m_hdr, p, sizeof(struct icmp6_hdr));
		p += sizeof(struct icmp6_hdr);
		icmph = (struct icmp6_hdr*)m_hdr;
		data_len = f_ret - ext_pos - sizeof(struct icmp6_hdr);

		switch (icmph->icmp6_type) {
		case ICMP6_ECHO_REPLY:
			if (icmph->icmp6_code != 0 ||
				ntohs(icmph->icmp6_id) != (uint16_t)ctx->seq_mask ||
				ntohs(icmph->icmp6_seq) != 0 ||
				data_len != sizeof(RCN_ICMP_ECHO_DATA) ||
				memcmp(p, RCN_ICMP_ECHO_DATA, sizeof(RCN_ICMP_ECHO_DATA)) != 0)
			{
				return true;
			}
			// this node shouldn't have processed this packet, but we'll accept
			if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_WARN) {
				char s_str[INET6_ADDRSTRLEN];
				char d_str[INET6_ADDRSTRLEN];

				prne_assert(
					inet_ntop(AF_INET6, ih.saddr, s_str, sizeof(s_str)) &&
					inet_ntop(AF_INET6, ih.daddr, d_str, sizeof(d_str)));
				prne_dbgpf(
					"Bad IPv6 implementation! [%s] -> [%s]\n",
					s_str,
					d_str);
			}

			rcn_main_recv_6_icmp_tail(ctx, &ih);
			break;
		case ICMP6_PARAM_PROB:
			pptr = ntohl(icmph->icmp6_pptr);
			if (icmph->icmp6_code != ICMP6_PARAMPROB_OPTION ||
				data_len <= pptr ||
				p[pptr] != 0x9e)
			{
				return true;
			}
			if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_DBG0) {
				char s_str[INET6_ADDRSTRLEN];
				char d_str[INET6_ADDRSTRLEN];

				prne_assert(
					inet_ntop(AF_INET6, ih.saddr, s_str, sizeof(s_str)) &&
					inet_ntop(AF_INET6, ih.daddr, d_str, sizeof(d_str)));
				prne_dbgpf(
					"ICMP 4,2 [%s] -> [%s]\n",
					s_str,
					d_str);
			}

			rcn_main_recv_6_icmp_tail(ctx, &ih);
			break;
		}
		break;
	}

	return true;
}

static bool rcn_main_recv (prne_recon_t *ctx) {
	bool ret[2];

	if (ctx->fd[RCN_IDX_IPV4][0] >= 0) {
		ret[0] = rcn_main_recv_4(ctx);
	}
	else {
		ret[0] = false;
	}
	if (ctx->fd[RCN_IDX_IPV6][0] >= 0) {
		ret[1] = rcn_main_recv_6(ctx);
	}
	else {
		ret[1] = false;
	}

	return ret[0] || ret[1];
}

static void *rcn_main_entry (void *ctx_p) {
	prne_recon_t *ctx = (prne_recon_t*)ctx_p;
	unsigned int i, syn_cnt, tick_dur;
	pth_event_t ev_root = NULL, ev;
	pth_time_t to_pth;
	struct timespec to_ts, tick_dur_ts;

LOOP:
	while (ctx->loop) {
		ctx->ts_now = prne_gettime(CLOCK_MONOTONIC);

		// periodic op
		if (prne_cmp_timespec(ctx->ts.ii_up, ctx->ts_now) <= 0) {
			unsigned long n;

			rcn_main_update_saddr(ctx);

			if (rcn_main_do_ifaddrs(ctx)) {
				prne_rnd(&ctx->rnd, (uint8_t*)&n, sizeof(n));
				n = RCN_II_UPDATE_INT_MIN + (n % RCN_II_UPDATE_INT_VAR);
				ctx->ts.ii_up = prne_add_timespec(
					ctx->ts_now,
					prne_ms_timespec(n));
			}
			else {
				ctx->ts.ii_up = prne_add_timespec(
					ctx->ts_now,
					RCN_ERR_PAUSE_INT);
			}

			prne_rnd(&ctx->rnd, (uint8_t*)&n, sizeof(n));
			ctx->s_port = (uint16_t)(RCN_SRC_PORT_MIN + (n % RCN_SRC_PORT_VAR));
			ctx->ping_cnt = 0;
		}

		// random
		prne_rnd(&ctx->rnd, (uint8_t*)&syn_cnt, sizeof(syn_cnt));
		syn_cnt = RCN_SYN_PPT_MIN + (syn_cnt % RCN_SYN_PPT_VAR);
		prne_rnd(&ctx->rnd, (uint8_t*)&tick_dur, sizeof(tick_dur));
		tick_dur = RCN_SYN_TICK_MIN + (tick_dur % RCN_SYN_TICK_VAR);
		prne_rnd(&ctx->rnd, (uint8_t*)&ctx->seq_mask, sizeof(ctx->seq_mask));

		for (i = 0; i < syn_cnt; i += 1) {
			rcn_main_do_syn(ctx);
		}
		if (ctx->ping_cnt < RCN_IPV6_PROBE_CNT) {
			rcn_main_send_icmpv6(ctx);
			ctx->ping_cnt += 1;
		}

		ctx->ts_now = prne_gettime(CLOCK_MONOTONIC);
		tick_dur_ts = prne_ms_timespec(tick_dur);
		to_pth = prne_pth_tstimeout(tick_dur_ts);
		to_ts = prne_add_timespec(ctx->ts_now, tick_dur_ts);
		while (ctx->loop) {
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
			i = 0;
			do {
				// this loop is to prevent the thread starving other threads
				// because a continuous flow of packets could keep the loop
				// going forever
				ctx->ts_now = prne_gettime(CLOCK_MONOTONIC);
				if (prne_cmp_timespec(to_ts, ctx->ts_now) <= 0) {
					goto LOOP;
				}

				i += 1;
				if (i % syn_cnt == 0) {
					i = 0;
					pth_yield(NULL);
				}
				// the thread will wait on event when no packet has been
				// received. i.e. rcn_main_recv() returns false
			} while (ctx->loop && rcn_main_recv(ctx));
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

	rcn_main_empty_v4_ii(ctx);
	rcn_main_empty_v6_ii(ctx);

	prne_free_rnd(&ctx->rnd);
	prne_free_llist(&ctx->v4_ii.list);
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
