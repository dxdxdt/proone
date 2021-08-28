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
#include "util_ct.h"
#include "data.h"

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>


typedef struct prne_dvault_mask_result prne_dvault_mask_result_t;
typedef struct prne_dvault prne_dvault_t;

typedef enum {
	PRNE_DATA_TYPE_NONE = -1,

	PRNE_DATA_TYPE_CSTR,
	PRNE_DATA_TYPE_BIN,

	NB_PRNE_DATA_TYPE
} prne_data_type_t;
PRNE_LIMIT_ENUM(prne_data_type_t, NB_PRNE_DATA_TYPE, 0xFF);

typedef enum {
	PRNE_DVAULT_MASK_OK,
	PRNE_DVAULT_MASK_MEM_ERR,
	PRNE_DVAULT_MASK_TOO_LARGE,
	PRNE_DVAULT_MASK_INVALID_TYPE
} prne_dvault_mask_result_code_t;

struct prne_dvault_mask_result {
	size_t size;
	uint8_t *data;
	prne_dvault_mask_result_code_t result;
};


const char *prne_data_type_tostr (const prne_data_type_t t);
prne_data_type_t prne_data_type_fstr (const char *str);
void prne_dvault_invert_mem (
	const size_t size,
	void *m,
	const uint8_t salt,
	const size_t salt_ofs,
	const uint8_t *mask);

void prne_init_dvault_mask_result (prne_dvault_mask_result_t *r);
void prne_free_dvault_mask_result (prne_dvault_mask_result_t *r);
prne_dvault_mask_result_t prne_dvault_mask (
	const prne_data_type_t type,
	const uint8_t salt,
	const uint8_t *mask,
	const size_t data_size,
	const uint8_t *data);
const char *prne_dvault_mask_result_tostr (
	const prne_dvault_mask_result_code_t code);

/* prne_init_dvault(const void *m)
*
* ARGS:
*	m: pointer to start of readable and writable a dvault made by
*		proone-mkdvault. This region of memory must be writable.
*/
void prne_init_dvault (const void *m);
/* prne_deinit_dvault (const void *m)
*
* Calls prne_dvault_reset(). Revert changes to the data vault memory.
*/
void prne_deinit_dvault (void);
// len: strlen()
const char *prne_dvault_get_cstr (const prne_data_key_t key, size_t *len);
const uint8_t *prne_dvault_get_bin (const prne_data_key_t key, size_t *len);
void prne_dvault_reset (void);
