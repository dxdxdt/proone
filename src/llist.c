#include "llist.h"
#include "util_rt.h"


void prne_init_llist (prne_llist_t *llist) {
	llist->head = NULL;
	llist->tail = NULL;
	llist->size = 0;
}

void prne_free_llist (prne_llist_t *llist) {
	prne_llist_clear(llist);
}

void prne_llist_clear (prne_llist_t *llist) {
	struct prne_llist_entry *cur = llist->head, *next;

	while (cur != NULL) {
		next = cur->next;
		prne_free(cur);
		cur = next;
	}

	llist->head = llist->tail = NULL;
	llist->size = 0;
}

prne_llist_entry_t *prne_llist_insert (prne_llist_t *llist, prne_llist_entry_t *entry, const prne_llist_element_t element) {
	prne_llist_entry_t *ny;

	if (entry == NULL) {
		return prne_llist_append(llist, element);
	}

	ny = (prne_llist_entry_t*)prne_malloc(sizeof(prne_llist_entry_t), 1);
	if (ny == NULL) {
		return NULL;
	}
	ny->prev = entry;
	ny->next = entry->next;
	ny->element = element;
	if (entry->next != NULL) {
		entry->next->prev = ny;
	}
	else {
		llist->tail = ny;
	}
	entry->next = ny;

	llist->size += 1;
	return ny;
}

prne_llist_entry_t *prne_llist_append (prne_llist_t *llist, const prne_llist_element_t element) {
	prne_llist_entry_t *ny = (prne_llist_entry_t*)prne_malloc(sizeof(prne_llist_entry_t), 1);

	if (ny == NULL) {
		return NULL;
	}
	ny->next = NULL;
	ny->element = element;

	if (llist->tail == NULL) {
		llist->head = llist->tail = ny;
		ny->prev = NULL;
	}
	else {
		llist->tail->next = ny;
		ny->prev = llist->tail;
		llist->tail = ny;
	}

	llist->size += 1;
	return ny;
}

prne_llist_entry_t *prne_llist_erase (prne_llist_t *llist, prne_llist_entry_t *entry) {
	prne_llist_entry_t *ret;

	if (entry == NULL) {
		return NULL;
	}

	if (entry == llist->head && entry == llist->tail) {
		llist->head = llist->tail = NULL;
		ret = NULL;
	}
	else if (entry == llist->head) {
		ret = llist->head = llist->head->next;
		llist->head->prev = NULL;
	}
	else if (entry == llist->tail) {
		ret = llist->tail = llist->tail->prev;
		llist->tail->next = NULL;
	}
	else {
		ret = entry->prev->next = entry->next;
		entry->next->prev = entry->prev;
	}

	prne_free(entry);
	llist->size -= 1;
	return ret;
}
