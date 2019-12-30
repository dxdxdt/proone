#pragma once
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#include "proone_data.h"


typedef struct proone_dvault_mask_result proone_dvault_mask_result_t;

typedef enum {
    PROONE_DATA_TYPE_NONE = -1,
    PROONE_DATA_TYPE_CSTR,
    NB_PROONE_DATA_TYPE
} proone_data_type_t;

typedef enum {
    PROONE_DVAULT_MASK_OK,
    PROONE_DVAULT_MASK_MEM_ERR,
    PROONE_DVAULT_MASK_TOO_LARGE,
    PROONE_DVAULT_MASK_INVALID_TYPE
} proone_dvault_mask_result_code_t;

struct proone_dvault_mask_result {
    size_t str_len;
    char *str;
    proone_dvault_mask_result_code_t result;
};


extern const uint8_t PROONE_DVAULT_MASK[256];

const char *proone_data_type2str (const proone_data_type_t t);
proone_data_type_t proone_str2data_type (const char *str);
void proone_dvault_invert_mem (const size_t size, uint8_t *m, const uint8_t salt);

void proone_init_dvault_mask_result (proone_dvault_mask_result_t *r);
void proone_free_dvault_mask_result (proone_dvault_mask_result_t *r);
proone_dvault_mask_result_t proone_dvault_mask (const proone_data_type_t type, const uint8_t salt, const size_t data_size, const uint8_t *data);

void proone_init_dvault (void);
void proone_deinit_dvault (void);
proone_data_type_t proone_dvault_get_entry_data_type (const proone_data_key_t key);
size_t proone_dvault_get_entry_size (const proone_data_key_t key);
uint8_t proone_dvault_get_entry_salt (const proone_data_key_t key);
const char *proone_dvault_unmask_entry_cstr (const proone_data_key_t key);
void proone_dvault_reset_dict (void);
