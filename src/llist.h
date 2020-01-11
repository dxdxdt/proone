#pragma once
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>


struct prne_llist;
struct prne_llist_entry;
typedef struct prne_llist prne_llist_t;
typedef struct prne_llist_entry prne_llist_entry_t;

struct prne_llist {
	prne_llist_entry_t *head, *tail;
	size_t size;
};

struct prne_llist_entry {
	prne_llist_entry_t *prev, *next;
	void *element;
};

void prne_init_llist (prne_llist_t *llist);
void prne_free_llist (prne_llist_t *llist);

void prne_llist_clear (prne_llist_t *llist);
prne_llist_entry_t *prne_llist_insert (prne_llist_t *llist, prne_llist_entry_t *entry, void *element);
prne_llist_entry_t *prne_llist_append (prne_llist_t *llist, void *element);
prne_llist_entry_t *prne_llist_erase (prne_llist_t *llist, prne_llist_entry_t *entry);
