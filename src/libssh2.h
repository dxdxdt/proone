#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include <libssh2.h>
#include <pthsem.h>


int prne_lssh2_handshake (LIBSSH2_SESSION *s, const int fd, pth_event_t ev);
int prne_lssh2_ua_pwd (
	LIBSSH2_SESSION *s,
	const int fd,
	const char *id,
	const char *pw,
	pth_event_t ev);
LIBSSH2_CHANNEL *prne_lssh2_open_ch (
	LIBSSH2_SESSION *s,
	const int fd,
	pth_event_t ev,
	int *err);
int prne_lssh2_ch_req_pty (
	LIBSSH2_SESSION *s,
	LIBSSH2_CHANNEL *c,
	const int fd,
	const char *term,
	pth_event_t ev);
int prne_lssh2_ch_sh (
	LIBSSH2_SESSION *s,
	LIBSSH2_CHANNEL *c,
	const int fd,
	pth_event_t ev);
int prne_lssh2_ch_read (
	LIBSSH2_SESSION *s,
	LIBSSH2_CHANNEL *c,
	const int fd,
	const bool s_err,
	void *buf,
	const size_t len,
	pth_event_t ev);
int prne_lssh2_ch_write (
	LIBSSH2_SESSION *s,
	LIBSSH2_CHANNEL *c,
	const int fd,
	const void *buf,
	const size_t len,
	pth_event_t ev);
int prne_lssh2_discon (
	LIBSSH2_SESSION *s,
	const int fd,
	const int reason,
	const char *desc,
	const char *lang,
	pth_event_t ev);
const char *prne_lssh2_ua_list (
	LIBSSH2_SESSION *s,
	const int fd,
	const char *username,
	pth_event_t ev,
	int *err);
int prne_lssh2_ua_authd (
	LIBSSH2_SESSION *s,
	const int fd,
	pth_event_t ev);

/* Workaround for the library's shitty design
*
* Cripples LIBSSH2_SESSION's ability to send() and recv() so that
* the library can't use the fd. This is used to guarantee that *_free()
* functions never return EAGAIN.
*/
void prne_lssh2_cripple_session (LIBSSH2_SESSION *s);
void prne_lssh2_free_session (LIBSSH2_SESSION *s);
