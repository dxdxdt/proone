#pragma once
#include "util_ct.h"

#include <stddef.h>


typedef enum {
    PRNE_ARCH_NONE = -1,
    
    PRNE_ARCH_ARMV4T,
    PRNE_ARCH_ARMV7,
    PRNE_ARCH_I586,
    PRNE_ARCH_M68K,
    PRNE_ARCH_MIPS,
    PRNE_ARCH_MPSL,
    PRNE_ARCH_PPC,
    PRNE_ARCH_RV32,
    PRNE_ARCH_RV64,
    PRNE_ARCH_SH4,
    PRNE_ARCH_SPC,

    NB_PRNE_ARCH
} prne_arch_t;
PRNE_LIMIT_ENUM(prne_arch_t, NB_PRNE_ARCH, 0xFF);


const char *prne_arch2str (const prne_arch_t x);
prne_arch_t prne_str2arch (const char *str);
