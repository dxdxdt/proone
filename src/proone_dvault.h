#pragma once
#include "proone_data.h"

#include <stddef.h>


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

typedef struct {
    size_t str_len;
    char *str;
    proone_dvault_mask_result_code_t result;
} proone_dvault_mask_result_t;


const char *proone_data_type2str (const proone_data_type_t t);
proone_data_type_t proone_str2data_type (const char *str);

void proone_init_dvault_mask_result (proone_dvault_mask_result_t *r);
void proone_free_dvault_mask_result (proone_dvault_mask_result_t *r);
proone_dvault_mask_result_t proone_dvault_mask (const proone_data_type_t type, const uint8_t salt, const size_t data_size, const uint8_t *data);

const char *proone_dvault_unmask_entry_cstr (const proone_data_key_t key);
void proone_dvault_reset_dict (void);
