/*
* Copyright (c) 2019-2021 David Timber <mieabby@gmail.com>
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
#include "yaml.h"

#include <inttypes.h>
#include <errno.h>

#include "util_rt.h"


static prne_yaml_path_entry_t *prne_yaml_pst_top (prne_yaml_ctx_t *ctx) {
	if (ctx->path_st.tail == NULL) {
		return NULL;
	}
	return (prne_yaml_path_entry_t*)ctx->path_st.tail->element;
}

static prne_yaml_path_entry_t *prne_yaml_pst_push (
	prne_yaml_ctx_t *ctx,
	const prne_yaml_ent_type_t t)
{
	prne_yaml_path_entry_t *ny;

	ny = prne_calloc(sizeof(prne_yaml_path_entry_t), 1);
	if (ny == NULL) {
		return false;
	}

	prne_yaml_init_path_entry(ny);
	ny->type = t;

	if (prne_llist_append(&ctx->path_st, (prne_llist_element_t)ny) == NULL) {
		prne_free(ny);
		ny = NULL;
	}

	return ny;
}

static void prne_yaml_pst_prep_last (prne_yaml_ctx_t *ctx) {
	prne_yaml_path_entry_t *top;

	top = prne_yaml_pst_top(ctx);
	if (top == NULL) {
		return;
	}
	else if (top->type == PRNE_YAML_ENT_MAP) {
		prne_free(top->map.name);
		top->map.name = NULL;
		top->map.own = false;
	}
	else if (top->type == PRNE_YAML_ENT_SEQ) {
		top->seq.idx += 1;
	}
}

static void prne_yaml_pst_pop (prne_yaml_ctx_t *ctx) {
	prne_yaml_path_entry_t *top;

	top = (prne_yaml_path_entry_t*)ctx->path_st.tail->element;
	prne_llist_erase(&ctx->path_st, ctx->path_st.tail);
	prne_yaml_free_path_entry(top);
	prne_free(top);
}

static void prne_yaml_path_st_clear (prne_yaml_ctx_t *ctx) {
	prne_yaml_path_entry_t *p;

	for (prne_llist_entry_t *i = ctx->path_st.head;
		i != NULL;
		i = i->next)
	{
		p = (prne_yaml_path_entry_t*)i->element;
		prne_yaml_free_path_entry(p);
		prne_free(p);
	}

	prne_llist_clear(&ctx->path_st);
	prne_yaml_free_path(&ctx->path);
}

static bool prne_yaml_build_path (prne_yaml_ctx_t *ctx) {
	size_t i;
	prne_llist_entry_t *e;
	const prne_yaml_path_entry_t *p;

	prne_yaml_free_path(&ctx->path);

	if (!prne_yaml_alloc_path(&ctx->path, ctx->path_st.size)) {
		return false;
	}

	i = 0;
	e = ctx->path_st.head;
	while (e != NULL) {
		p = (prne_yaml_path_entry_t*)e->element;
		ctx->path.entries[i] = *p;
		i += 1;
		e = e->next;
	}

	return true;
}

#define build_path_()\
if (!prne_yaml_build_path(ctx)) {\
	*ret = PRNE_YAML_PR_ERRNO;\
	return;\
}
#define handle_anchor_(a)\
if (!prne_yaml_handle_anchor(ctx, (const char*)(a), ret)) {\
	return;\
}

static bool prne_yaml_handle_anchor (
	prne_yaml_ctx_t *ctx,
	const char *anchor,
	prne_yaml_parse_ret_t *ret)
{
	if (prne_nstrlen(anchor) == 0) {
		return true;
	}

	if (!ctx->opt->accept_alias) {
		*ret = PRNE_YAML_PR_NALIAS;
		return false;
	}

	if (!prne_yaml_build_path(ctx)) {
		*ret = PRNE_YAML_PR_ERRNO;
		return false;
	}

	if (ctx->opt->cb.anchor != NULL &&
		!ctx->opt->cb.anchor(ctx->opt->uctx, anchor, &ctx->path))
	{
		*ret = PRNE_YAML_PR_CBHALT;
		return false;
	}

	return true;
}

static void prne_yaml_handle_event_doc_start (
	prne_yaml_ctx_t *ctx,
	const yaml_event_t *event,
	prne_yaml_parse_ret_t *ret)
{
	if (ctx->opt->cb.doc_start != NULL &&
		!ctx->opt->cb.doc_start(ctx->opt->uctx, event))
	{
		*ret = PRNE_YAML_PR_CBHALT;
	}
}

static void prne_yaml_handle_event_doc_end (
	prne_yaml_ctx_t *ctx,
	const yaml_event_t *event,
	prne_yaml_parse_ret_t *ret)
{
	if (ctx->opt->cb.doc_end != NULL &&
		!ctx->opt->cb.doc_end(ctx->opt->uctx, event))
	{
		*ret = PRNE_YAML_PR_CBHALT;
	}
	prne_yaml_path_st_clear(ctx);
}

static void prne_yaml_handle_event_alias (
	prne_yaml_ctx_t *ctx,
	const yaml_event_t *event,
	prne_yaml_parse_ret_t *ret)
{
	if (ctx->opt->accept_alias) {
		build_path_()

		if (ctx->opt->cb.alias != NULL &&
			!ctx->opt->cb.alias(
				ctx->opt->uctx,
				(const char*)event->data.alias.anchor,
				&ctx->path))
		{
			*ret = PRNE_YAML_PR_CBHALT;
		}
	}
	else {
		*ret = PRNE_YAML_PR_NALIAS;
	}
}

static void prne_yaml_handle_event_scalar (
	prne_yaml_ctx_t *ctx,
	const yaml_event_t *event,
	prne_yaml_parse_ret_t *ret)
{
	prne_yaml_path_entry_t *top = prne_yaml_pst_top(ctx);

	handle_anchor_(event->data.scalar.anchor);

	if (top == NULL) {
		// lone scalar
		build_path_()

		if (ctx->opt->cb.scalar != NULL &&
			!ctx->opt->cb.scalar(
				ctx->opt->uctx,
				(const char*)event->data.scalar.value,
				&ctx->path))
		{
			*ret = PRNE_YAML_PR_CBHALT;
		}
	}
	else if (top->type == PRNE_YAML_ENT_MAP) {
		if (top->map.name == NULL) {
			top->map.name = prne_dup_str((const char*)event->data.scalar.value);
			top->map.own = top->map.name != NULL;
			if (!top->map.own) {
				*ret = PRNE_YAML_PR_ERRNO;
			}
		}
		else {
			build_path_()

			if (ctx->opt->cb.scalar != NULL &&
				!ctx->opt->cb.scalar(
					ctx->opt->uctx,
					(const char*)event->data.scalar.value,
					&ctx->path))
			{
				*ret = PRNE_YAML_PR_CBHALT;
			}

			prne_free(top->map.name);
			top->map.name = NULL;
		}
	}
	else if (top->type == PRNE_YAML_ENT_SEQ) {
		build_path_()

		if (ctx->opt->cb.scalar != NULL &&
			!ctx->opt->cb.scalar(
				ctx->opt->uctx,
				(const char*)event->data.scalar.value,
				&ctx->path))
		{
			*ret = PRNE_YAML_PR_CBHALT;
		}

		top->seq.idx += 1;
	}
	else {
		abort();
	}
}

static void prne_yaml_handle_event_seq_start (
	prne_yaml_ctx_t *ctx,
	const yaml_event_t *event,
	prne_yaml_parse_ret_t *ret)
{
	handle_anchor_(event->data.sequence_start.anchor);

	if (!prne_yaml_pst_push(ctx, PRNE_YAML_ENT_SEQ)) {
		*ret = PRNE_YAML_PR_ERRNO;
	}
}

static void prne_yaml_handle_event_seq_end (
	prne_yaml_ctx_t *ctx,
	const yaml_event_t *event,
	prne_yaml_parse_ret_t *ret)
{
	prne_yaml_pst_pop(ctx);
	prne_yaml_pst_prep_last(ctx);
}

static void prne_yaml_handle_event_map_start (
	prne_yaml_ctx_t *ctx,
	const yaml_event_t *event,
	prne_yaml_parse_ret_t *ret)
{
	handle_anchor_(event->data.mapping_start.anchor);

	if (!prne_yaml_pst_push(ctx, PRNE_YAML_ENT_MAP)) {
		*ret = PRNE_YAML_PR_ERRNO;
	}
}

static void prne_yaml_handle_event_map_end (
	prne_yaml_ctx_t *ctx,
	const yaml_event_t *event,
	prne_yaml_parse_ret_t *ret)
{
	prne_yaml_pst_pop(ctx);
	prne_yaml_pst_prep_last(ctx);
}

#undef build_path_
#undef handle_anchor_

static void prne_yaml_handle_event (
	prne_yaml_ctx_t *ctx,
	const yaml_event_t *event,
	prne_yaml_parse_ret_t *ret)
{
	switch (event->type) {
	case YAML_DOCUMENT_START_EVENT:
		prne_yaml_handle_event_doc_start(ctx, event, ret);
		break;
	case YAML_DOCUMENT_END_EVENT:
		prne_yaml_handle_event_doc_end(ctx, event, ret);
		break;
	case YAML_ALIAS_EVENT:
		prne_yaml_handle_event_alias(ctx, event, ret);
		break;
	case YAML_SCALAR_EVENT:
		prne_yaml_handle_event_scalar(ctx, event, ret);
		break;
	case YAML_SEQUENCE_START_EVENT:
		prne_yaml_handle_event_seq_start(ctx, event, ret);
		break;
	case YAML_SEQUENCE_END_EVENT:
		prne_yaml_handle_event_seq_end(ctx, event, ret);
		break;
	case YAML_MAPPING_START_EVENT:
		prne_yaml_handle_event_map_start(ctx, event, ret);
		break;
	case YAML_MAPPING_END_EVENT:
		prne_yaml_handle_event_map_end(ctx, event, ret);
		break;
	default: abort();
	}
}

void prne_yaml_init_parse_opt (prne_yaml_parse_opt_t *p) {
	prne_memzero(p, sizeof(prne_yaml_parse_opt_t));
}

void prne_yaml_free_parse_opt (prne_yaml_parse_opt_t *p) {}

void prne_yaml_init_ctx (prne_yaml_ctx_t *ctx) {
	prne_memzero(ctx, sizeof(prne_yaml_ctx_t));
	prne_init_llist(&ctx->path_st);
	prne_yaml_init_path(&ctx->path);
}

void prne_yaml_free_ctx (prne_yaml_ctx_t *ctx) {
	if (ctx != NULL) {
		prne_yaml_path_st_clear(ctx);
		prne_free_llist(&ctx->path_st);
		prne_yaml_free_path(&ctx->path);
	}
}

prne_yaml_parse_ret_t prne_yaml_do_parse (
	yaml_parser_t *parser,
	prne_yaml_ctx_t *ctx,
	const prne_yaml_parse_opt_t *opt)
{
	prne_yaml_parse_ret_t ret = PRNE_YAML_PR_END;
	bool has_event = false;
	bool s_flag = false;
	yaml_event_t event;

	prne_yaml_free_ctx(ctx);
	prne_yaml_init_ctx(ctx);
	ctx->opt = opt;

	do {
		if (yaml_parser_parse(parser, &event) == 0) {
			ret = PRNE_YAML_PR_APIERR;
			goto END;
		}
		has_event = true;

		switch (event.type) {
		case YAML_STREAM_START_EVENT:
			s_flag = true;
			break;
		case YAML_STREAM_END_EVENT:
			s_flag = false;
			break;
		default:
			prne_yaml_handle_event(ctx, &event, &ret);
			if (ret <= PRNE_YAML_PR_CBHALT) {
				s_flag = false;
			}
		}

		yaml_event_delete(&event);
		has_event = false;
	} while (s_flag);

END:
	if (has_event) {
		yaml_event_delete(&event);
	}

	return ret;
}

const char *prne_yaml_pr_tostr (const prne_yaml_parse_ret_t x) {
	switch (x) {
	case PRNE_YAML_PR_ERRNO: return "errno set";
	case PRNE_YAML_PR_APIERR: return "libyaml error";
	case PRNE_YAML_PR_CBHALT: return "halted by callback";
	case PRNE_YAML_PR_END: return "end of stream";
	}
	return NULL;
}

void prne_yaml_init_path_entry (prne_yaml_path_entry_t *p) {
	prne_memzero(p, sizeof(prne_yaml_path_entry_t));
}

void prne_yaml_free_path_entry (prne_yaml_path_entry_t *p) {
	if (p == NULL) {
		return;
	}

	if (p->map.own) {
		switch (p->type) {
		case PRNE_YAML_ENT_MAP:
			prne_free(p->map.name);
			p->map.name = NULL;
			break;
		}
	}
}

void prne_yaml_init_path (prne_yaml_path_t *p) {
	prne_memzero(p, sizeof(prne_yaml_path_t));
}

void prne_yaml_free_path (prne_yaml_path_t *p) {
	if (p == NULL) {
		return;
	}

	if (p->own) {
		for (size_t i = 0; i < p->depth; i += 1) {
			prne_yaml_free_path_entry(p->entries + i);
		}
	}

	prne_free(p->entries);
	p->entries = NULL;
	p->depth = 0;
}

bool prne_yaml_alloc_path (prne_yaml_path_t *p, const size_t depth) {
	prne_yaml_path_entry_t *entries = NULL;

	entries = (prne_yaml_path_entry_t*)prne_realloc(
		p->entries,
		sizeof(prne_yaml_path_entry_t),
		depth);

	if (depth > 0 && entries == NULL) {
		return false;
	}

	p->depth = depth;
	p->entries = entries;

	return true;
}

bool prne_yaml_copy_path (const prne_yaml_path_t *src, prne_yaml_path_t *dst) {
	bool ret = false;
	prne_yaml_path_t ny;

	prne_yaml_init_path(&ny);
// TRY
	if (!prne_yaml_alloc_path(&ny, src->depth)) {
		goto END;
	}

	for (size_t i = 0; i < src->depth; i += 1) {
		prne_yaml_init_path_entry(ny.entries + i);
	}
	ny.own = true;

	ny.depth = src->depth;
	for (size_t i = 0; i < src->depth; i += 1) {
		prne_yaml_init_path_entry(dst->entries + i);

		dst->entries[i].type = src->entries[i].type;

		switch (src->entries[i].type) {
		case PRNE_YAML_ENT_MAP:
			dst->entries[i].map.name = prne_dup_str(src->entries[i].map.name);
			dst->entries[i].map.own = true;
			if (dst->entries[i].map.name == NULL) {
				goto END;
			}
			break;
		case PRNE_YAML_ENT_SEQ:
			dst->entries[i].seq.idx = src->entries[i].seq.idx;
			break;
		}
	}

	prne_yaml_move_path(&ny, dst);
	ret = true;

END: // FINALLY
	prne_yaml_free_path(&ny);
	return ret;
}

void prne_yaml_swap_path (prne_yaml_path_t *a, prne_yaml_path_t *b) {
	prne_yaml_path_t c;

	c = *b;
	*b = *a;
	*a = c;
}

void prne_yaml_move_path (prne_yaml_path_t *a, prne_yaml_path_t *b) {
	prne_yaml_free_path(b);
	*b = *a;
	prne_yaml_init_path(a);
}

int prne_yaml_cmp_path (const prne_yaml_path_t *a, const prne_yaml_path_t *b) {
	int rv;

	rv = prne_op_spaceship(a->depth, b->depth);
	if (rv != 0) {
		return rv;
	}

	for (size_t i = 0; i < a->depth; i += 1) {
		rv = prne_op_spaceship(a->entries[i].type, b->entries[i].type);
		if (rv != 0) {
			return rv * 2;
		}

		switch (a->entries[i].type) {
		case PRNE_YAML_ENT_MAP:
			rv = strcmp(a->entries[i].map.name, b->entries[i].map.name);
			break;
		case PRNE_YAML_ENT_SEQ:
			rv = prne_op_spaceship(
				a->entries[i].seq.idx,
				b->entries[i].seq.idx);
			break;
		}

		if (rv != 0) {
			return rv * 3;
		}
	}

	return 0;
}

char *prne_yaml_path_tostr (
	const prne_yaml_path_t *path,
	const char *path_sep,
	const bool ovr,
	char *old)
{
	static const char *FMT_MAP = "%s%s";
	static const char *FMT_SEQ = "[%zu]";
	char *ret = NULL;
	char **sb = NULL;
	const prne_yaml_path_entry_t *e;
	int l;

	if (path_sep == NULL || path_sep[0] == 0) {
		// *printf functions on various platform handle NULL differently
		errno = EINVAL;
		return NULL;
	}

	sb = prne_calloc(sizeof(char*), path->depth);
	if (path->depth > 0 && sb == NULL) {
		goto END;
	}

	for (size_t i = 0; i < path->depth; i += 1) {
		e = path->entries + i;

		switch (e->type) {
		case PRNE_YAML_ENT_MAP:
			if (!ovr && strstr(e->map.name, path_sep) != NULL) {
				errno = EILSEQ;
				goto END;
			}
			l = snprintf(NULL, 0, FMT_MAP, path_sep, e->map.name);
			break;
		case PRNE_YAML_ENT_SEQ:
			l = snprintf(NULL, 0, FMT_SEQ, e->seq.idx);
			break;
		}

		if (l < 0) {
			goto END;
		}
		sb[i] = prne_alloc_str(l);
		if (sb[i] == NULL) {
			goto END;
		}

		switch (e->type) {
		case PRNE_YAML_ENT_MAP:
			snprintf(sb[i], l + 1, FMT_MAP, path_sep, e->map.name);
			break;
		case PRNE_YAML_ENT_SEQ:
			snprintf(sb[i], l + 1, FMT_SEQ, e->seq.idx);
			break;
		}
	}

	ret = prne_rebuild_str(old, (const char**)sb, path->depth);

END:
	if (sb != NULL) {
		for (size_t i = 0; i < path->depth; i += 1) {
			prne_free(sb[i]);
		}
		prne_free(sb);
	}

	return ret;
}
