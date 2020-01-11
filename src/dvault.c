#include "dvault.h"
#include "util_rt.h"

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>


const uint8_t PRNE_DVAULT_MASK[] = {
    0xA2, 0x7A, 0x61, 0x65, 0x78, 0xBE, 0x95, 0x8A, 0xBF, 0x07, 
    0x52, 0x8F, 0x0E, 0x6F, 0x0B, 0xD8, 0x5B, 0xD4, 0x77, 0x9D, 
    0x39, 0x28, 0x72, 0xE2, 0x42, 0x5D, 0xE7, 0x92, 0xDD, 0xAF, 
    0xF7, 0x90, 0x8B, 0x2D, 0x1F, 0xB1, 0x18, 0x4B, 0x3C, 0x32, 
    0x58, 0xFC, 0x34, 0x94, 0xCA, 0x31, 0x43, 0xDB, 0x93, 0x55, 
    0xB5, 0xEF, 0x02, 0x8E, 0x84, 0x22, 0x88, 0x86, 0xEE, 0xC6, 
    0x44, 0xCB, 0xA3, 0xEC, 0x59, 0x8C, 0x8D, 0x7F, 0x6B, 0x0A, 
    0x3D, 0xA7, 0x6E, 0x9F, 0x2A, 0x7B, 0x12, 0x7D, 0xBD, 0xF8, 
    0x15, 0xAC, 0xF9, 0xD9, 0x3E, 0xF5, 0x38, 0xF4, 0x6D, 0xAB, 
    0xE9, 0x4C, 0x0D, 0x3F, 0x71, 0xDF, 0xC0, 0xB9, 0xD5, 0xA6, 
    0x53, 0xED, 0xE6, 0x82, 0x73, 0xC8, 0xA5, 0x08, 0x48, 0x1A, 
    0x79, 0x05, 0x10, 0x75, 0xF3, 0xE4, 0x85, 0xEB, 0xDC, 0x2C, 
    0x23, 0xCD, 0xBC, 0x1C, 0x45, 0x24, 0x5C, 0x26, 0x17, 0xB3, 
    0xA0, 0xBB, 0x03, 0xC9, 0xA1, 0x56, 0x2F, 0x91, 0xCF, 0xFE, 
    0xC2, 0xAE, 0x54, 0xE1, 0x00, 0x13, 0x9C, 0x5E, 0xAD, 0xB8, 
    0xB6, 0x63, 0x9E, 0x7C, 0x87, 0x60, 0x51, 0xFD, 0xF0, 0x76, 
    0x4E, 0x4A, 0x9B, 0x1D, 0xF1, 0x0F, 0x06, 0xD1, 0x68, 0x99, 
    0x20, 0x81, 0x3A, 0xE3, 0x25, 0xAA, 0x36, 0x98, 0x62, 0x96, 
    0xC4, 0x30, 0x37, 0x47, 0x2B, 0x3B, 0x80, 0x64, 0x21, 0x67, 
    0xB0, 0xB4, 0x01, 0x89, 0xC1, 0x0C, 0x41, 0xC3, 0x57, 0xB2, 
    0x9A, 0x35, 0xBA, 0xD7, 0x66, 0xE0, 0x19, 0xF2, 0x04, 0xFB, 
    0x70, 0xD6, 0xFF, 0x40, 0x83, 0xDE, 0xD0, 0xB7, 0xA8, 0xEA, 
    0x16, 0x49, 0xFA, 0xCC, 0x11, 0x46, 0xCE, 0xE8, 0x4F, 0xD2, 
    0x4D, 0xE5, 0x27, 0x50, 0x6A, 0x74, 0xDA, 0xC7, 0xA4, 0xA9, 
    0x5F, 0x97, 0x29, 0x14, 0x6C, 0x7E, 0x1E, 0xC5, 0x5A, 0x1B, 
    0x33, 0x69, 0x09, 0x2E, 0xD3, 0xF6
};

static uint8_t *unmasked_buf = NULL;
static size_t unmasked_buf_size = 0;
static bool unmasked = false;


static void invert_entry (const prne_data_key_t key, size_t *len) {
    const size_t entry_size = prne_dvault_get_entry_size(key);

    if (len != NULL) {
        *len = entry_size;
    }
    memcpy(unmasked_buf, PRNE_DATA_DICT[key] + 4, entry_size);
    prne_dvault_invert_mem(entry_size, unmasked_buf, prne_dvault_get_entry_salt(key));
    unmasked = true;
}

static void entry_check (const prne_data_key_t key, const prne_data_type_t type) {
    if (!(PRNE_DATA_KEY_NONE < key && key < NB_PRNE_DATA_KEY) ||
        !(PRNE_DATA_TYPE_NONE < type && type < NB_PRNE_DATA_TYPE) ||
        type != prne_dvault_get_entry_data_type(key)) {
        abort();
    }
}


const char *prne_data_type_tostr (const prne_data_type_t t) {
    switch (t) {
    case PRNE_DATA_TYPE_CSTR: return "cstr";
    case PRNE_DATA_TYPE_BIN: return "bin";
    }
    return NULL;
}

prne_data_type_t prne_data_type_fstr (const char *str) {
    if (strcmp(str, prne_data_type_tostr(PRNE_DATA_TYPE_CSTR)) == 0) {
        return PRNE_DATA_TYPE_CSTR;
    }
    if (strcmp(str, prne_data_type_tostr(PRNE_DATA_TYPE_BIN)) == 0) {
        return PRNE_DATA_TYPE_BIN;
    }
    
    return PRNE_DATA_TYPE_NONE;
}

void prne_dvault_invert_mem (const size_t size, uint8_t *m, const uint8_t salt) {
    size_t i;

    for (i = 0; i < size; i += 1) {
        m[i] ^= PRNE_DVAULT_MASK[(i + (size_t)salt) % 256];
    }
}

void prne_init_dvault_mask_result (prne_dvault_mask_result_t *r) {
    r->result = PRNE_DVAULT_MASK_OK;
    r->str = NULL;
    r->str_len = 0;
}

void prne_free_dvault_mask_result (prne_dvault_mask_result_t *r) {
    prne_free(r->str);
    r->str_len = 0;
    r->str = NULL;
    r->result = PRNE_DVAULT_MASK_OK;
}

prne_dvault_mask_result_t prne_dvault_mask (const prne_data_type_t type, const uint8_t salt, const size_t data_size, const uint8_t *data) {
    size_t i;
    prne_dvault_mask_result_t ret;

    prne_init_dvault_mask_result(&ret);

    if (data_size > 0xFFFF) {
        ret.result = PRNE_DVAULT_MASK_TOO_LARGE;
        return ret;        
    }
    if (!(PRNE_DATA_TYPE_NONE < type && type < NB_PRNE_DATA_TYPE)) {
        ret.result = PRNE_DVAULT_MASK_INVALID_TYPE;
        return ret;        
    }

    ret.str_len = 4 * 4 + 4 * data_size + 1;
    ret.str = prne_malloc(1, ret.str_len);
    if (ret.str == NULL) {
        ret.result = PRNE_DVAULT_MASK_MEM_ERR;
        ret.str_len = 0;
        return ret;
    }

    sprintf(ret.str, "\\x%02X\\x%02X\\x%02X\\x%02X",
        type,
        salt,
        (int)((0xFF00 & (uint_fast16_t)data_size) >> 8),
        (int)((0x00FF & (uint_fast16_t)data_size) >> 0));

    for (i = 0; i < data_size; i += 1) {
        sprintf(ret.str + 4 * 4 + 4 * i, "\\x%02X", data[i] ^ PRNE_DVAULT_MASK[(i + (size_t)salt) % 256]);
    }

    return ret;
}

void prne_init_dvault (void) {
    size_t max_size = 0;
    size_t entry_size;
    prne_data_key_t i;

    for (i = PRNE_DATA_KEY_NONE + 1; i < NB_PRNE_DATA_KEY; i += 1) {
        entry_size = prne_dvault_get_entry_size(i);
        switch (prne_dvault_get_entry_data_type(i)) {
        case PRNE_DATA_TYPE_CSTR:
            entry_size += 1;
            break;
        }

        if (entry_size > max_size) {
            max_size = entry_size;
        }
    }

    if (max_size == 0) {
        abort();
    }
    unmasked_buf = prne_calloc(1, max_size);
    unmasked_buf_size = max_size;
    if (unmasked_buf == NULL) {
        abort();
    }
    unmasked = false;
}

void prne_deinit_dvault (void) {
    prne_free(unmasked_buf);
    unmasked_buf = NULL;
    unmasked_buf_size = 0;
    unmasked = false;
}

prne_data_type_t prne_dvault_get_entry_data_type (const prne_data_key_t key) {
    return (prne_data_type_t)PRNE_DATA_DICT[key][0];
}

size_t prne_dvault_get_entry_size (const prne_data_key_t key) {
    return (size_t)PRNE_DATA_DICT[key][2] << 8 | (size_t)PRNE_DATA_DICT[key][3];
}

uint8_t prne_dvault_get_entry_salt (const prne_data_key_t key) {
    return PRNE_DATA_DICT[key][1];
}

char *prne_dvault_unmask_entry_cstr (const prne_data_key_t key, size_t *len) {
    prne_dvault_reset_dict();
    entry_check(key, PRNE_DATA_TYPE_CSTR);
    invert_entry(key, len);
    return (char*)unmasked_buf;
}

void prne_dvault_unmask_entry_bin (const prne_data_key_t key, const uint8_t **data, size_t *len) {
    prne_dvault_reset_dict();
    entry_check(key, PRNE_DATA_TYPE_BIN);
    invert_entry(key, len);
    *data = unmasked_buf;
}

void prne_dvault_reset_dict (void) {
    if (unmasked) {
        memset(unmasked_buf, 0, unmasked_buf_size);
        unmasked = false;
    }
}
