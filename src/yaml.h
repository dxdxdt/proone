/** \file
 * \brief The YAML helper. Only listen to terminating scalar events: the helper
 * removes the need to listen to mapping start and sequence start events in
 * between. The mapping and sequence start events are reformed as
 * \c prne_yaml_path_t which can be converted to a file-system-path-like string
 * using \c prne_yaml_path_tostr() The string can be matched against regexp or
 * simple string mapping to extract data from the document.
 */
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
#pragma once
#include <yaml.h>

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "util_ct.h"
#include "llist.h"


typedef enum {
	PRNE_YAML_PR_NALIAS = -3, // Alias encountered
	PRNE_YAML_PR_ERRNO, // errno set
	PRNE_YAML_PR_APIERR, // libyaml error
	PRNE_YAML_PR_CBHALT, // cb func returned false
	PRNE_YAML_PR_END // no more event
} prne_yaml_parse_ret_t;
prne_static_assert(PRNE_YAML_PR_CBHALT == 0, "PRNE_YAML_PR_CBHALT == 0");

typedef enum {
	PRNE_YAML_ENT_NONE,
	PRNE_YAML_ENT_MAP, // entry representing a mapping start
	PRNE_YAML_ENT_SEQ // entry representing a sequence start
} prne_yaml_ent_type_t;

/**
 * \brief Path entry object. One path entry corresponds to one mapping or
 * sequence start event.
 */
typedef struct {
	// Entry type: mapping or sequence
	prne_yaml_ent_type_t type;
	union {
		// Data for mapping entry
		struct {
			char *name; // The first scalar value of the mapping
			bool own; // True if the object has the ownership of \c name
		} map;
		// Data for sequence entry
		struct {
			size_t idx; // Index from the first occurrence in sequence
		} seq;
	};
} prne_yaml_path_entry_t;

/**
 * \brief Path object
 */
typedef struct {
	// The number of entries
	size_t depth;
	// The entries with the elements in the order of events occurrence.
	prne_yaml_path_entry_t *entries;
	// True if the object is responsible for freeing the path entries
	bool own;
} prne_yaml_path_t;

/**
 * \brief Callback function set object
 */
typedef struct {
	// YAML_DOCUMENT_START_EVENT
	bool(*doc_start)(void *ctx, const yaml_event_t *event);
	// YAML_DOCUMENT_END_EVENT
	bool(*doc_end)(void *ctx, const yaml_event_t *event);
	// Terminating YAML_SCALAR_EVENT
	bool(*scalar)(
		void *ctx,
		const char *value,
		const prne_yaml_path_t *path);
	/**
	 * \brief Anchor event
	 * \details This is a special event that is emitted prior to
	 * processing the event from libyaml. It can be used to support anchors and
	 * aliases in the document. The events that can have anchor are:
	 * - scalar
	 * - sequence start
	 * - mapping start
	 * The alias events can be processed in the separate callback function.
	 *
	 * Handling of anchors and aliases is expensive and impractical. The helper
	 * won't accept aliases unless requested.
	 *
	 * \see \c prne_yaml_parse_opt_t
	 * \see \c PRNE_YAML_PR_NALIAS
	 */
	bool(*anchor)(
		void *ctx,
		const char *anchor,
		const prne_yaml_path_t *path);
	// YAML_ALIAS_EVENT
	bool(*alias)(
		void *ctx,
		const char *anchor,
		const prne_yaml_path_t *path);
} prne_yaml_cbset_t;

/**
 * \brief Parsing Option Object
 */
typedef struct {
	void *uctx; // User context for callback functions
	prne_yaml_cbset_t cb; // Callback function set object
	/* Accept anchors and anliases. Not allowed by default - the parser will
	 * produce an error if the document contains an anchor or an alias.
	 */
	bool accept_alias;
} prne_yaml_parse_opt_t;

typedef struct {
	// A pointer to a parsing Option Object instnace
	const prne_yaml_parse_opt_t *opt;
	// Internal path stack
	prne_llist_t path_st;
	// Internal path object
	prne_yaml_path_t path;
} prne_yaml_ctx_t;


/**
 * \brief Initialisation function
 * \see [/doc/impl.md#Resource Allocation](/doc/impl.md#resource_allocation)
 */
void prne_yaml_init_parse_opt (prne_yaml_parse_opt_t *p);
/**
 * \brief Deinitialisation function
 * \see [/doc/impl.md#Resource Allocation](/doc/impl.md#resource_allocation)
 */
void prne_yaml_free_parse_opt (prne_yaml_parse_opt_t *p);

/**
 * \brief Initialisation function
 * \see [/doc/impl.md#Resource Allocation](/doc/impl.md#resource_allocation)
 */
void prne_yaml_init_ctx (prne_yaml_ctx_t *ctx);
/**
 * \brief Deinitialisation function
 * \see [/doc/impl.md#Resource Allocation](/doc/impl.md#resource_allocation)
 */
void prne_yaml_free_ctx (prne_yaml_ctx_t *ctx);
prne_yaml_parse_ret_t prne_yaml_do_parse (
	yaml_parser_t *parser,
	prne_yaml_ctx_t *ctx,
	const prne_yaml_parse_opt_t *opt);

const char *prne_yaml_pr_tostr (const prne_yaml_parse_ret_t x);

/**
 * \brief Initialisation function
 * \see [/doc/impl.md#Resource Allocation](/doc/impl.md#resource_allocation)
 */
void prne_yaml_init_path_entry (prne_yaml_path_entry_t *p);
/**
 * \brief Deinitialisation function
 * \see [/doc/impl.md#Resource Allocation](/doc/impl.md#resource_allocation)
 */
void prne_yaml_free_path_entry (prne_yaml_path_entry_t *p);

/**
 * \brief Initialisation function
 * \see [/doc/impl.md#Resource Allocation](/doc/impl.md#resource_allocation)
 */
void prne_yaml_init_path (prne_yaml_path_t *p);
/**
 * \brief Deinitialisation function
 * \see [/doc/impl.md#Resource Allocation](/doc/impl.md#resource_allocation)
 */
void prne_yaml_free_path (prne_yaml_path_t *p);
/**
 * \brief Allocate variable-length members of the Path Object
 * \param p The pointer to the object
 * \param depth The number of elements required
 * \return true if allocation was successful
 * \return false on failure and \c errno set to \c ENOMEM
 * \see [/doc/impl.md#Resource Allocation](/doc/impl.md#resource_allocation)
 */
bool prne_yaml_alloc_path (prne_yaml_path_t *p, const size_t depth);
/**
 * \brief Deep copy operator
 *
 * \param src The source object
 * \param dst The destination object. The original contents are be freed
 * \return true on successful operation
 * \return false on failure and \c errno set to \c ENOMEM
 */
bool prne_yaml_copy_path (const prne_yaml_path_t *src, prne_yaml_path_t *dst);
/**
 * \brief Swap operator
 */
void prne_yaml_swap_path (prne_yaml_path_t *a, prne_yaml_path_t *b);
/**
 * \brief Move opeator. Moves the contents of \p a into \p b The original
 * contents of \p b are freed
 */
void prne_yaml_move_path (prne_yaml_path_t *a, prne_yaml_path_t *b);
/**
 * \brief The comparison operator
 * \returns Negative value if \p a is less than \p b
 * \returns Positive value if \p a is greater than \p b
 * \retval 0 if \p a and \p b are identical
 */
int prne_yaml_cmp_path (const prne_yaml_path_t *a, const prne_yaml_path_t *b);
/**
 * \brief Fabricate string representation of the Path Object
 *
 * \param path The object
 * \param path_sep The path separator. Conventionally "/" or "."
 * \param ovr Set true to allow the path separator in path names
 * \param old The old pointer to the string for \c prne_rebuild_str()
 * \returns A pointer to the fabricated string
 * \retval NULL and \c errno set to \c ENOMEM on memory allocation error
 * \retval NULL and \c errno set to \c EINVAL if \p path_sep is NULL or a
 * pointer to an empty string
 * \retval NULL and \c errno set to \c EILSEQ if \p ovr is set and the path
 * separator was found in one of the path names
 */
char *prne_yaml_path_tostr (
	const prne_yaml_path_t *path,
	const char *path_sep,
	const bool ovr,
	char *old);
