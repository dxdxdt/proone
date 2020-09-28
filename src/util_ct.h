#pragma once
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#if PRNE_DEBUG
#include <stdio.h>
#include <errno.h>
#endif

#define PRNE_VL_FATAL	0
#define PRNE_VL_ERR		1
#define PRNE_VL_INFO	1
#define PRNE_VL_WARN	2
#define PRNE_VL_DBG0	3

#define PRNE_LIMIT_ENUM(t,x,l) _Static_assert((x) <= (l),"enum overflow: "#t)
#define prne_static_assert(expr, msg) _Static_assert((expr), msg)

#define prne_op_min(a, b) ((a) < (b) ? (a) : (b))
#define prne_op_max(a, b) ((a) > (b) ? (a) : (b))
#define prne_op_spaceship(a, b) ((a) == (b) ? 0 : (a) < (b) ? -1 : 1)

#define prne_salign_next(x, align) \
	(((x) % (align) == 0) ? (x) : ((x) / (align) + 1) * (align))
#define prne_salign_at(x, align) \
	(((x) % (align) == 0) ? (x) : ((x) / (align)) * (align))

#if PRNE_DEBUG
#define prne_dbgpf(...) fprintf(stderr, __VA_ARGS__)
#define prne_dbgperr(str) perror(str)
#define prne_assert(expr) assert(expr)
#define prne_massert(expr, ...)\
	if (!(expr)) {\
		fprintf(stderr, "*** ");\
		fprintf(stderr, __VA_ARGS__);\
		fprintf(stderr, "\n");\
		abort();\
	}
#define prne_dbgast(expr) prne_assert(expr)
#define prne_dbgmast(expr, ...) prne_massert(expr, __VA_ARGS__)
#define prne_dbgtrap(expr) prne_assert(expr)
#else
#define prne_dbgpf(...)
#define prne_dbgperr(str)
#define prne_assert(expr)\
	if (!(expr)) {\
		abort();\
	}
#define prne_massert(expr, ...) prne_assert(expr)
#define prne_dbgast(expr)
#define prne_dbgmast(expr, ...)
#define prne_dbgtrap(expr) (expr)
#endif

#define prne_chk_assign(l, r) \
	if ((l) != NULL) {\
		*(l) = (r);\
	}
