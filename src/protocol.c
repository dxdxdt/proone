#include "protocol.h"
#include <string.h>

const char *prne_arch2str (const prne_arch_t x) {
    switch (x){
    case PRNE_ARCH_ARMV4T:
        return "armv4t";
    case PRNE_ARCH_ARMV7:
        return "armv7";
    case PRNE_ARCH_I586:
        return "i586";
    case PRNE_ARCH_M68K:
        return "m68k";
    case PRNE_ARCH_MIPS:
        return "mips";
    case PRNE_ARCH_MPSL:
        return "mpsl";
    case PRNE_ARCH_PPC:
        return "ppc";
    case PRNE_ARCH_RV32:
        return "rv32";
    case PRNE_ARCH_RV64:
        return "rv64";
    case PRNE_ARCH_SH4:
        return "sh4";
    case PRNE_ARCH_SPC:
        return "spc";
    }
    
    return NULL;
}

prne_arch_t prne_str2arch (const char *str) {
    if (strcmp(str, "armv4t") == 0) {
        return PRNE_ARCH_ARMV4T;
    }
    else if (strcmp(str, "armv7") == 0) {
        return PRNE_ARCH_ARMV7;
    }
    else if (strcmp(str, "i586") == 0) {
        return PRNE_ARCH_I586;
    }
    else if (strcmp(str, "m68k") == 0) {
        return PRNE_ARCH_M68K;
    }
    else if (strcmp(str, "mips") == 0) {
        return PRNE_ARCH_MIPS;
    }
    else if (strcmp(str, "mpsl") == 0) {
        return PRNE_ARCH_MPSL;
    }
    else if (strcmp(str, "ppc") == 0) {
        return PRNE_ARCH_PPC;
    }
    else if (strcmp(str, "rv32") == 0) {
        return PRNE_ARCH_RV32;
    }
    else if (strcmp(str, "rv64") == 0) {
        return PRNE_ARCH_RV64;
    }
    else if (strcmp(str, "sh4") == 0) {
        return PRNE_ARCH_SH4;
    }
    else if (strcmp(str, "spc") == 0) {
        return PRNE_ARCH_SPC;
    }

    return PRNE_ARCH_NONE;
}
