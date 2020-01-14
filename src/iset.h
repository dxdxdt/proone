#pragma once
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>


typedef struct prne_iset prne_iset_t;
typedef void* prne_iset_val_t;

struct prne_iset {
	prne_iset_val_t *arr;
	size_t size;
};


void prne_init_iset (prne_iset_t *s);
void prne_free_iset (prne_iset_t *s);

void prne_iset_clear (prne_iset_t *s);
bool prne_iset_insert (prne_iset_t *s, const prne_iset_val_t v);
void prne_iset_erase (prne_iset_t *s, const prne_iset_val_t v);
bool prne_iset_lookup (prne_iset_t *s, const prne_iset_val_t v);
