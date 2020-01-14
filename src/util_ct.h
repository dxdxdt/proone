#pragma once
#include <assert.h>


#define PRNE_LIMIT_ENUM(t,x,l) _Static_assert(x<=l,"enum overflow: "#t)

#define prne_op_spaceship(a, b) (a == b ? 0 : a < b ? -1 : 1)

#if !defined(memzero)
#define memzero(addr, len) memset(addr, 0, len)
#endif
