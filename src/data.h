#pragma once
#include <stdint.h>


typedef enum {
    PRNE_DATA_KEY_NONE = -1,
    PRNE_DATA_KEY_PROC_LIM_SHM,
    PRNE_DATA_KEY_SIGN_INIT_OK,
    NB_PRNE_DATA_KEY
} prne_data_key_t;


extern uint8_t *PRNE_DATA_DICT[NB_PRNE_DATA_KEY];
