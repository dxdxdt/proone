#pragma once
#include <stddef.h>


typedef enum {
    PROONE_ARCH_NONE = -1,
    
    PROONE_ARCH_ARMV4T,
    PROONE_ARCH_ARMV7,
    PROONE_ARCH_I586,
    PROONE_ARCH_M68K,
    PROONE_ARCH_MIPS,
    PROONE_ARCH_MPSL,
    PROONE_ARCH_PPC,
    PROONE_ARCH_RV32,
    PROONE_ARCH_RV64,
    PROONE_ARCH_SH4,
    PROONE_ARCH_SPC,

    NB_PROONE_ARCH
} proone_arch_t;


const char *proone_arch2str (const proone_arch_t x);
proone_arch_t proone_str2arch (const char *str);
