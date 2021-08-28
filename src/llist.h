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
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>


struct prne_llist;
struct prne_llist_entry;
typedef struct prne_llist prne_llist_t;
typedef struct prne_llist_entry prne_llist_entry_t;
typedef uintptr_t prne_llist_element_t;

struct prne_llist {
	prne_llist_entry_t *head, *tail;
	size_t size;
};

struct prne_llist_entry {
	prne_llist_entry_t *prev, *next;
	prne_llist_element_t element;
};

void prne_init_llist (prne_llist_t *llist);
void prne_free_llist (prne_llist_t *llist);

void prne_llist_clear (prne_llist_t *llist);
prne_llist_entry_t *prne_llist_insert (
	prne_llist_t *llist,
	prne_llist_entry_t *entry,
	const prne_llist_element_t element);
prne_llist_entry_t *prne_llist_append (
	prne_llist_t *llist,
	const prne_llist_element_t element);
prne_llist_entry_t *prne_llist_erase (
	prne_llist_t *llist,
	prne_llist_entry_t *entry);
