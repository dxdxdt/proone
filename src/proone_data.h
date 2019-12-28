#pragma once
#include <stdint.h>


typedef enum {
    PROONE_DATA_KEY_NONE = -1,
    PROONE_DATA_KEY_PROC_LIM_SHM,
    PROONE_DATA_KEY_SIGN_INIT_OK,
    NB_PROONE_DATA_KEY
} proone_data_key_t;


extern uint8_t *PROONE_DATA_DICT[];
