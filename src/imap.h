#pragma once
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>


struct prne_imap;
struct prne_imap_tuple;
typedef uintptr_t prne_imap_key_type_t;
typedef struct prne_imap prne_imap_t;
typedef struct prne_imap_tuple prne_imap_tuple_t;

struct prne_imap {
	prne_imap_tuple_t *tbl;
	size_t size;
};

struct prne_imap_tuple {
	prne_imap_key_type_t key;
	void *val;
};


void prne_init_imap (prne_imap_t *im);
void prne_free_imap (prne_imap_t *im);

void prne_imap_clear (prne_imap_t *im);
const prne_imap_tuple_t *prne_imap_insert (prne_imap_t *im, const prne_imap_key_type_t key, void *val);
void prne_imap_erase (prne_imap_t *im, const prne_imap_key_type_t key);
const prne_imap_tuple_t *prne_imap_lookup (prne_imap_t *im, const prne_imap_key_type_t key);
