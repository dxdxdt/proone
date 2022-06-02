/** \file
 * \brief Compile-time utility and convenience functions
 * \note \c _Static_assert() instead of \c static_assert() is used because some
 * cross compilers do not support it. The use of \c _Static_assert() is
 * still standard compliant.
 * \note The expressions and values involved must be determinable during compile
 * time! Basically, write what can be written using constexpr in C++.
 */
/*
* Copyright (c) 2019-2021 David Timber <mieabby@gmail.com>
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*/
#pragma once
#ifndef CONFIG_GEN_H
#include "config_gen.h"
#define CONFIG_GEN_H
#endif
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#if PRNE_DEBUG
#include <stdio.h>
#include <errno.h>
#endif

/* Log levels
 * The default level is 1. Using the value 1(PRNE_VL_ERR or PRNE_VL_INFO) will
 * filter out all the log levels higher than 1 showing only info, err and fatal
 * errors only.
 * Generally, the native uint type is used. Note that minimum width of int for C
 * is 16-bit.
 */
/* Fatal error
 * The process cannot proceed further due to a serious error. The message
 * must be the last message the process prints before calling abort()
 */
#define PRNE_VL_FATAL	0
/* General error
 * An operation or a work unit failed due to an error
 */
#define PRNE_VL_ERR		1
/* Info
 * The message carries essential information. The value is the same as
 * PRNE_VL_ERR. This is intentional - this log level should only be used for
 * essential info messages.
 */
#define PRNE_VL_INFO	1
/* Warning
 * The message is about a warning that needs the user's attention.
 */
#define PRNE_VL_WARN	2
/* Debug Level 0
 * This level is the lowest possible debug log level. Use higher debug levels
 * for more detailed data like raw packet data and diagnostic info.
 */
#define PRNE_VL_DBG0	3

/**
 * \brief Limit the number of enums using static_assert()
 */
#define PRNE_LIMIT_ENUM(t,x,l) _Static_assert((x) <= (l),"enum overflow: "#t)
/**
 * \brief Do \c static_assert(). This is a workaround for the problem where some
 * compilers don't have static_assert() exposed.
 */
#define prne_static_assert(expr, msg) _Static_assert((expr), msg)

/**
 * \brief Pick the smallest expression
 */
#define prne_op_min(a, b) ((a) < (b) ? (a) : (b))
/**
 * \brief Pick the biggest expression
 */
#define prne_op_max(a, b) ((a) > (b) ? (a) : (b))
/**
 * \brief The spaceship operator - compare \p a and \p b and return -1 if \p b
 * is the biggest, return 1 if \p a is the biggest, return 0 if \p a and \p b
 * are equal.
 */
#define prne_op_spaceship(a, b) ((a) == (b) ? 0 : (a) < (b) ? -1 : 1)

/**
 * \brief Align the byte length \p x to the alignment \p align - calculate the
 * multiple of \p align required to store the \p x bytes of data (much like
 * ceiling function)
 * \note Consider using APIs like \c posix_memalign() where suits. This macro is
 * only for computation of byte size
 */
#define prne_salign_next(x, align) \
	(((x) % (align) == 0) ? (x) : ((x) / (align) + 1) * (align))

#if PRNE_DEBUG
/*
 * These macros have effect only on debug builds. The macros are disabled for
 * release builds to prevent info leak.
 */

/**
 * \brief The debug print function. Print the formatted message on the standard
 * error. Effective only in debug.
 */
#define prne_dbgpf(...) fprintf(stderr, __VA_ARGS__)
/**
 * \brief The \c perror() function only effective in debug.
 */
#define prne_dbgperr(str) perror(str)
/**
 * \brief \c assert() macro - use \c assert() directly in debug, use \c abort()
 * in release so the expression is not printed on the standard error.
 */
#define prne_assert(expr) assert(expr)
/**
 * \brief \c assert() macro, but instead of using the expression for the error
 * message, use the formatted message instead. The messages will not be built
 * into release builds.
 */
#define prne_massert(expr, ...)\
	if (!(expr)) {\
		fprintf(stderr, "*** ");\
		fprintf(stderr, __VA_ARGS__);\
		fprintf(stderr, "\n");\
		abort();\
	}
/**
 * \brief Do \c assert() only in debug. This macro has no effect in release
 * builds.
 */
#define prne_dbgast(expr) prne_assert(expr)
/**
 * \brief Do \c prne_massert() only in debug. This macro has no effect in
 * release builds.
 */
#define prne_dbgmast(expr, ...) prne_massert(expr, __VA_ARGS__)
/**
 * \brief The debug trap macro. In debug mode, this macro simply acts as
 * \c assert() In release mode, the expression is simply executed without its
 * result evaluated by \c assert(). The macro is for non-critical assertions.
 */
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

/**
 * \brief Convenience macro for assigning value to the optional parameter
 * pointer. Dereference the pointer \p l to assign the value \p r to it only if
 * the pointer is not NULL.
 */
#define prne_chk_assign(l, r) \
	if ((l) != NULL) {\
		*(l) = (r);\
	}

/**
 * \brief Test if the expression is one of the "non-blocking" errors. Include
 * <errno.h> to use this macro. The macro is a workaround for the issue where
 * some platforms define \c EAGAIN and \c EWOULDBLOCK as seperate values. On
 * platforms where they represent the same value, the compiler will optimise the
 * expression into a single equality comparison operation.
 */
#define prne_is_nberr(expr) ((expr) == EAGAIN || (expr) == EWOULDBLOCK)
