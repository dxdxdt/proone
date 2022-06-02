/** \file
 * \brief The convenience functions and abstraction for GNU Portable Threads
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
#include <stdbool.h>

#include <pthsem.h>


// The worker object (abstract)
struct prne_worker {
	void *ctx; // The opaque internal context
	void *(*entry)(void*); // The "run" function
	void (*fin)(void*); // The function that signals the thread to exit
	void (*free_ctx)(void*); // The function used to free the context object
	pth_t pth; // The PTH handle
	// The attribute of the PTH thread acquired at the point of creation
	pth_attr_t attr;
};
typedef struct prne_worker prne_worker_t;

// The PTH condition variable object (parametres required for notify())
struct prne_pth_cv {
	pth_mutex_t *lock; // The mutex
	pth_cond_t *cond; // The CV
	bool broadcast; // The broadcast flag (set to true to notify all threads)
};
typedef struct prne_pth_cv prne_pth_cv_t;


/**
 * \brief Initialisation function
 * \see [/doc/impl.md#Resource Allocation](/doc/impl.md#resource_allocation)
 */
void prne_init_worker (prne_worker_t *w);
/**
 * \brief Deinitialisation function
 * \see [/doc/impl.md#Resource Allocation](/doc/impl.md#resource_allocation)
 */
void prne_free_worker (prne_worker_t *w);
/**
 * \brief Signal the worker to exit
 */
void prne_fin_worker (prne_worker_t *w);

/**
 * \brief The workaround for the bug in \c pth_poll() implementation. Calling
 * 	pth_poll() with pollfd element whose fd is negative value results in
 * 	undefined behaviour as stated in POSIX(FD_SET() with invalid value is
 * 	undefined). GNU Pth uses FD_SET() with invalid values on purpose. This leads
 * 	to an undefined behaivour.
 * \see \c pth_poll()
 */
int prne_pth_poll (
	struct pollfd *pfd,
	const nfds_t nfs,
	const int timeout,
	pth_event_t ev);
/**
 * \brief Condition variable notify convenience function
 * \param lock The PTH mutex
 * \param cond The PTH condition variable
 * \param broadcast True to notify all PTH threads. False to notify one PTH
 * 	thread
 */
void prne_pth_cv_notify (pth_mutex_t *lock, pth_cond_t *cond, bool broadcast);
/**
 * \brief Convert the time spec structure to PTH time
 */
pth_time_t prne_pth_tstimeout (const struct timespec ts);
/**
 * \brief Free the PTH event handle and set up a new timeout event
 * \param[in,out] ev The pointer to the event handle pointer
 * \param ts The time spec structure
 */
void prne_pth_reset_timer (pth_event_t *ev, const struct timespec *ts);
