#pragma once
#include <assert.h>
#include <stdint.h>

#define PRNE_LIMIT_ENUM(t,x,l) _Static_assert(x <= l,"enum overflow: "#t)

#define prne_op_min(a, b) (a < b ? a : b)
#define prne_op_max(a, b) (a > b ? a : b)
#define prne_op_spaceship(a, b) (a == b ? 0 : a < b ? -1 : 1)

#define prne_malign_to(x, align) ((x % align == 0) ? x : (x / align + 1) * align)

#if !defined(memzero)
#define memzero(addr, len) memset(addr, 0, len)
#endif

#ifdef PRNE_DEBUG
#define prne_dbgpf(...) fprintf(stderr, __VA_ARGS__)
#define prne_dbgperr(str) perror(str)
#else
#define prne_dbgpf(fmt, ...)
#define prne_dbgperr(str)
#endif
