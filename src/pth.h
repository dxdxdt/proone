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


struct prne_worker {
	void *ctx;
	void *(*entry)(void*);
	void (*fin)(void*);
	void (*free_ctx)(void*);
	pth_t pth;
	pth_attr_t attr;
};
typedef struct prne_worker prne_worker_t;

struct prne_pth_cv {
	pth_mutex_t *lock;
	pth_cond_t *cond;
	bool broadcast;
};
typedef struct prne_pth_cv prne_pth_cv_t;


void prne_init_worker (prne_worker_t *w);
void prne_free_worker (prne_worker_t *w);
void prne_fin_worker (prne_worker_t *w);

/* Workaround for bug in GNU Pth
* Calling pth_poll() with pollfd element whose fd is negative value results in
* undefined behaviour as stated in POSIX(FD_SET() with invalid value is
* undefined). GNU Pth uses FD_SET() with invalid values on purpose to achieve
* something.
*/
int prne_pth_poll (
	struct pollfd *pfd,
	const nfds_t nfs,
	const int timeout,
	pth_event_t ev);
void prne_pth_cv_notify (pth_mutex_t *lock, pth_cond_t *cond, bool broadcast);
pth_time_t prne_pth_tstimeout (const struct timespec ts);
void prne_pth_reset_timer (pth_event_t *ev, const struct timespec *ts);
