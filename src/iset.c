#include "iset.h"
#include "util_rt.h"

#include <stdlib.h>
#include <string.h>


static int iset_comp_func (const void *a, const void *b) {
	return
		*(const prne_iset_val_t*)a < *(const prne_iset_val_t*)b ? -1 :
		*(const prne_iset_val_t*)a > *(const prne_iset_val_t*)b ? 1 :
		0;
}


void prne_init_iset (prne_iset_t *s) {
	s->arr = NULL;
	s->size = 0;
}

void prne_free_iset (prne_iset_t *s) {
	prne_free(s->arr);
	s->arr = NULL;
	s->size = 0;
}

void prne_iset_clear (prne_iset_t *s) {
	prne_free(s->arr);
	s->arr = NULL;
	s->size = 0;
}

bool prne_iset_insert (prne_iset_t *s, const prne_iset_val_t v) {
	void *ny_mem;

	if (prne_iset_lookup(s, v)) {
		return true;
	}

	ny_mem = prne_realloc(s->arr, sizeof(prne_iset_val_t), s->size + 1);
	if (ny_mem == NULL) {
		return false;
	}
	s->arr = (prne_iset_val_t*)ny_mem;
	s->arr[s->size] = v;
	s->size += 1;
	qsort(s->arr, s->size, sizeof(prne_iset_val_t), iset_comp_func);

	return true;
}

void prne_iset_erase (prne_iset_t *s, const prne_iset_val_t v) {
	prne_iset_val_t *p;

	p = (prne_iset_val_t*)bsearch(
		&v,
		s->arr,
		s->size,
		sizeof(prne_iset_val_t),
		iset_comp_func);
	if (p == NULL) {
		return;
	}

	if (s->size == 1) {
		prne_free(s->arr);
		s->arr = NULL;
		s->size = 0;
	}
	else {
		void *ny_mem;

		memmove(
			p,
			p + 1,
			sizeof(prne_iset_val_t) * (s->size - 1 - (p - s->arr)));

		s->size -= 1;
		ny_mem = prne_realloc(s->arr, sizeof(prne_iset_val_t), s->size);
		if (ny_mem != NULL) {
			s->arr = (prne_iset_val_t*)ny_mem;
		}
	}
}

bool prne_iset_lookup (prne_iset_t *s, const prne_iset_val_t v) {
	return bsearch(
		&v,
		s->arr,
		s->size,
		sizeof(prne_iset_val_t),
		iset_comp_func) != NULL;
}
