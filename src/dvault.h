#pragma once
#include "util_ct.h"
#include "data.h"

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>


typedef struct prne_dvault_mask_result prne_dvault_mask_result_t;

typedef enum {
    PRNE_DATA_TYPE_NONE = -1,
    PRNE_DATA_TYPE_CSTR,
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
    size_t str_len;
    char *str;
    prne_dvault_mask_result_code_t result;
};


extern const uint8_t PRNE_DVAULT_MASK[256];

const char *prne_data_type2str (const prne_data_type_t t);
prne_data_type_t prne_str2data_type (const char *str);
void prne_dvault_invert_mem (const size_t size, uint8_t *m, const uint8_t salt);

void prne_init_dvault_mask_result (prne_dvault_mask_result_t *r);
void prne_free_dvault_mask_result (prne_dvault_mask_result_t *r);
prne_dvault_mask_result_t prne_dvault_mask (const prne_data_type_t type, const uint8_t salt, const size_t data_size, const uint8_t *data);

void prne_init_dvault (void);
void prne_deinit_dvault (void);
prne_data_type_t prne_dvault_get_entry_data_type (const prne_data_key_t key);
size_t prne_dvault_get_entry_size (const prne_data_key_t key);
uint8_t prne_dvault_get_entry_salt (const prne_data_key_t key);
char *prne_dvault_unmask_entry_cstr (const prne_data_key_t key, size_t *len);
void prne_dvault_reset_dict (void);
