/*
* Copyright (c) 2019-2022 David Timber <dxdt@dev.snart.me>
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*/
#include <stdio.h>

#include <getopt.h>

#include "yaml.h"
#include "llist.h"
#include "util_rt.h"

#define HELP_STR \
"Proone YAML Utility Test Tool\n"\
"Usage: %s [options] [FILES ...]\n"\
"\n"\
"Options:\n"\
" -s <SEP>  specify path separator (default: '.')\n"\
" -o        allow path names to be overridden\n"\
" -a        accept aliases\n"\
" -h        print this message to stdout and exit normally\n"\
"FILES: use '-' to read stdin. This is default if no file is passed\n"

#define DEFAULT_PATH_SEP "/"


static struct {
	prne_llist_t files;
	char *path_sep;
	bool allow_override;
	prne_yaml_parse_opt_t p_opt;
} prog_conf;

typedef struct {
	char *path_str;
} uctx_t;


static void print_help (FILE *o, const char *arg0) {
	fprintf(o, HELP_STR, arg0);
}

static int load_opts (const int argc, const char **argv, int *ec) {
	int f_ret;

	while ((f_ret = getopt(argc, (char*const*)argv, "s:oha")) >= 0) {
		switch (f_ret) {
		case 's':
			prog_conf.path_sep = prne_redup_str(prog_conf.path_sep, optarg);
			prne_assert(prog_conf.path_sep != NULL);
			break;
		case 'o': prog_conf.allow_override = true; break;
		case 'a': prog_conf.p_opt.accept_alias = true; break;
		case 'h': print_help(stdout, argv[0]); return 0;
		default:
			fprintf(
				stderr,
				"Run `%s -h` for help.\n",
				argv[0]);
			*ec = 2;
			return -1;
		}
	}

	for (int i = optind; i < argc; i += 1) {
		prne_assert(prne_llist_append(
			&prog_conf.files,
			(const prne_llist_element_t)prne_dup_str(argv[i])) != NULL);
	}

	if (prog_conf.files.size == 0) {
		// Read stdin if no file given
		prne_assert(prne_llist_append(
			&prog_conf.files,
			(const prne_llist_element_t)prne_dup_str("-")) != NULL);
	}

	return 1;
}

static bool build_path_str (const prne_yaml_path_t *path, uctx_t *uc) {
	char *ny = prne_yaml_path_tostr(
		path,
		prog_conf.path_sep,
		prog_conf.allow_override,
		uc->path_str);

	if (ny == NULL) {
		perror("prne_yaml_path_tostr()");
		return false;
	}

	uc->path_str = ny;
	return true;
}

static bool doc_start_cb (void *ctx, const yaml_event_t *event) {
	printf("---\n");
	return true;
}

static bool doc_end_cb (void *ctx, const yaml_event_t *event) {
	return true;
}

static bool scalar_cb (
	void *ctx,
	const char *value,
	const prne_yaml_path_t *path)
{
	bool rv;
	uctx_t *uc = (uctx_t*)ctx;

	if (build_path_str(path, uc)) {
		printf("%s%s%s\n",
			uc->path_str,
			strlen(uc->path_str) > 0 ? ": " : "",
			value);
		rv = true;
	}
	else {
		rv = false;
	}

	return rv;
}

static bool anchor_cb (
	void *ctx,
	const char *anchor,
	const prne_yaml_path_t *path)
{
	bool rv;
	uctx_t *uc = (uctx_t*)ctx;

	if (build_path_str(path, uc)) {
		printf("%s: &%s\n", uc->path_str, anchor);
		rv = true;
	}
	else {
		rv = false;
	}

	return rv;
}

static bool alias_cb (
	void *ctx,
	const char *anchor,
	const prne_yaml_path_t *path)
{
	bool rv;
	uctx_t *uc = (uctx_t*)ctx;

	if (build_path_str(path, uc)) {
		printf("%s: *%s\n", uc->path_str, anchor);
		rv = true;
	}
	else {
		rv = false;
	}

	return rv;
}

static int do_parse (yaml_parser_t *parser, prne_yaml_ctx_t *p_ctx, FILE *f) {
	static prne_yaml_parse_ret_t p_ret;

	yaml_parser_set_input_file(parser, f);
	p_ret = prne_yaml_do_parse(parser, p_ctx, &prog_conf.p_opt);
	switch (p_ret) {
	case PRNE_YAML_PR_END:
		break;
	case PRNE_YAML_PR_ERRNO:
		perror("prne_yaml_do_parse()");
		break;
	case PRNE_YAML_PR_APIERR:
		fprintf(
			stderr,
			"%zu:%zu %s\n",
			parser->problem_mark.line,
			parser->problem_mark.column,
			parser->problem);
			/* fall-through */
	default:
		fprintf(
			stderr,
			"prne_yaml_do_parse(): %s\n",
			prne_yaml_pr_tostr(p_ret));
		return 1;
	}

	return 0;
}

int main (const int argc, const char **argv) {
	static int ec = 0;
	static prne_yaml_ctx_t p_ctx;
	static yaml_parser_t parser;
	static uctx_t uctx;

	prne_assert(yaml_parser_initialize(&parser) != 0);
	prne_yaml_init_ctx(&p_ctx);
	prne_yaml_init_parse_opt(&prog_conf.p_opt);
	prog_conf.path_sep = prne_redup_str(prog_conf.path_sep, DEFAULT_PATH_SEP);
	prne_init_llist(&prog_conf.files);
	prog_conf.p_opt.uctx = &uctx;
	prog_conf.p_opt.cb.doc_start = doc_start_cb;
	prog_conf.p_opt.cb.doc_end = doc_end_cb;
	prog_conf.p_opt.cb.scalar = scalar_cb;
	prog_conf.p_opt.cb.anchor = anchor_cb;
	prog_conf.p_opt.cb.alias = alias_cb;

	if (load_opts(argc, argv, &ec) <= 0) {
		goto END;
	}

	for (prne_llist_entry_t *i = prog_conf.files.head; i != NULL; i = i->next) {
		static FILE *f;
		static const char *path;
		static bool our_file;

		path = (const char*)i->element;
		if (prne_nstreq(path, "-")) {
			f = stdin;
			our_file = false;
		}
		else {
			f = fopen(path, "r");
			our_file = true;
		}

		if (f == NULL) {
			perror(path);
			ec = 1;
			break;
		}

		ec = do_parse(&parser, &p_ctx, f);

		if (our_file) {
			fclose(f);
			f = NULL;
		}
		if (ec != 0) {
			break;
		}
	}

END:
	for (prne_llist_entry_t *i = prog_conf.files.head; i != NULL; i = i->next) {
		prne_free((void*)i->element);
	}

	prne_yaml_free_ctx(&p_ctx);
	prne_yaml_free_parse_opt(&prog_conf.p_opt);
	yaml_parser_delete(&parser);
	prne_free_llist(&prog_conf.files);

	prne_free(uctx.path_str);
	prne_free(prog_conf.path_sep);

	return ec;
}
