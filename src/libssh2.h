/** \file
 * \brief The libssh2 convenience functions.
 */
/*
* Copyright (c) 2019-2022 David Timber <dxdt@dev.snart.me>
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
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include <libssh2.h>
#include <pthsem.h>


/**
 * \brief libssh2_session_handshake() wrapper function.
 * \param s The libssh2 session object.
 * \param fd The open file descriptor for the session.
 * \param ev The pth event object to use on poll().
 * \retval 0 on success.
 * \retval Non-zero value returned from the library functions or poll() on
 *	failure.
 * \note This is a convenience function that wraps all the operation that
 *	involves polling and calling the function again.
 */
int prne_lssh2_handshake (LIBSSH2_SESSION *s, const int fd, pth_event_t ev);
/**
 * \brief libssh2_userauth_password_ex() wrapper function.
 * \param s The libssh2 session object.
 * \param fd The open file descriptor for the session.
 * \param id The user name.
 * \param pw The password.
 * \param ev The pth event object to use on poll().
 * \retval 0 on success.
 * \retval Non-zero value returned from the library functions or poll() on
 *	failure.
 * \note This is a convenience function that wraps all the operation that
 *	involves polling and calling the function again.
 */
int prne_lssh2_ua_pwd (
	LIBSSH2_SESSION *s,
	const int fd,
	const char *id,
	const char *pw,
	pth_event_t ev);
/**
 * \brief libssh2_channel_open_session() wrapper function.
 * \param s The libssh2 session object.
 * \param fd The open file descriptor for the session.
 * \param ev The pth event object to use on poll().
 * \param[out] err The pointer to int for an error code on failure.
 * \return The new libssh2 channel object on success.
 * \retval NULL on failure. The return value of libssh2_session_last_errno() is
 *	returned via \p err if used.
 * \note This is a convenience function that wraps all the operation that
 *	involves polling and calling the function again.
 */
LIBSSH2_CHANNEL *prne_lssh2_open_ch (
	LIBSSH2_SESSION *s,
	const int fd,
	pth_event_t ev,
	int *err);
/**
 * \brief libssh2_channel_close() wrapper function.
 * \param s The libssh2 session object.
 * \param c The libssh2 channel object.
 * \param fd The open file descriptor for the session.
 * \param ev The pth event object to use on poll().
 * \retval 0 on success.
 * \retval Non-zero value returned from the library functions or poll() on
 *	failure.
 * \note This is a convenience function that wraps all the operation that
 *	involves polling and calling the function again.
 */
int prne_lssh2_close_ch (
	LIBSSH2_SESSION *s,
	LIBSSH2_CHANNEL *c,
	const int fd,
	pth_event_t ev);
/**
 * \brief libssh2_channel_wait_closed() wrapper function.
 * \param s The libssh2 session object.
 * \param c The libssh2 channel object.
 * \param fd The open file descriptor for the session.
 * \param ev The pth event object to use on poll().
 * \retval 0 on success.
 * \retval Non-zero value returned from the library functions or poll() on
 *	failure.
 * \note This is a convenience function that wraps all the operation that
 *	involves polling and calling the function again.
 */
int prne_lssh2_ch_wait_closed (
	LIBSSH2_SESSION *s,
	LIBSSH2_CHANNEL *c,
	const int fd,
	pth_event_t ev);
/**
 * \brief libssh2_channel_request_pty() wrapper function.
 * \param s The libssh2 session object.
 * \param c The libssh2 channel object.
 * \param fd The open file descriptor for the session.
 * \param term
 * \param ev The pth event object to use on poll().
 * \retval 0 on success.
 * \retval Non-zero value returned from the library functions or poll() on
 *	failure.
 * \note This is a convenience function that wraps all the operation that
 *	involves polling and calling the function again.
 */
int prne_lssh2_ch_req_pty (
	LIBSSH2_SESSION *s,
	LIBSSH2_CHANNEL *c,
	const int fd,
	const char *term,
	pth_event_t ev);
/**
 * \brief libssh2_channel_shell() wrapper function.
 * \param s The libssh2 session object.
 * \param c The libssh2 channel object.
 * \param fd The open file descriptor for the session.
 * \param ev The pth event object to use on poll().
 * \retval 0 on success.
 * \retval Non-zero value returned from the library functions or poll() on
 *	failure.
 * \note This is a convenience function that wraps all the operation that
 *	involves polling and calling the function again.
 */
int prne_lssh2_ch_sh (
	LIBSSH2_SESSION *s,
	LIBSSH2_CHANNEL *c,
	const int fd,
	pth_event_t ev);
/**
 * \brief libssh2_channel_read() wrapper function.
 * \param s The libssh2 session object.
 * \param c The libssh2 channel object.
 * \param fd The open file descriptor for the session.
 * \param s_err The standard error flag. Returns data from the standard error
 *	stream instead of the standard output stream if pass as \c true .
 * \param[out] buf The output buffer.
 * \param[in] len The byte length of \p buf .
 * \param ev The pth event object to use on poll().
 * \return The actual number of bytes read from the stream and written to \p buf
 *	or a negative value returned from the library functions or poll() on
 *	failure.
 * \note This is a convenience function that wraps all the operation that
 *	involves polling and calling the function again.
 */
int prne_lssh2_ch_read (
	LIBSSH2_SESSION *s,
	LIBSSH2_CHANNEL *c,
	const int fd,
	const bool s_err,
	void *buf,
	const size_t len,
	pth_event_t ev);
/**
 * \brief libssh2_channel_write() wrapper function.
 * \param s The libssh2 session object.
 * \param c The libssh2 channel object.
 * \param fd The open file descriptor for the session.
 * \param buf The buffer containing data to write to the standard input stream.
 * \param len The byte length of data to write from \p buf .
 * \param ev The pth event object to use on poll().
 * \return The actual number of bytes written to the stream or a negative value
 *	returned from the library functions or poll() on failure.
 * \note This is a convenience function that wraps all the operation that
 *	involves polling and calling the function again.
 */
int prne_lssh2_ch_write (
	LIBSSH2_SESSION *s,
	LIBSSH2_CHANNEL *c,
	const int fd,
	const void *buf,
	const size_t len,
	pth_event_t ev);
/**
 * \brief libssh2_session_disconnect_ex() wrapper function.
 * \param s The libssh2 session object.
 * \param c The libssh2 channel object.
 * \param fd The open file descriptor for the session.
 * \param ev The pth event object to use on poll().
 * \retval 0 on success.
 * \retval Non-zero value returned from the library functions or poll() on
 *	failure.
 * \note This is a convenience function that wraps all the operation that
 *	involves polling and calling the function again.
 */
int prne_lssh2_discon (
	LIBSSH2_SESSION *s,
	const int fd,
	const int reason,
	const char *desc,
	const char *lang,
	pth_event_t ev);
/**
 * \brief libssh2_userauth_list() wrapper function.
 * \param s The libssh2 session object.
 * \param fd The open file descriptor for the session.
 * \param username The pointer to the null-terminated user name string.
 * \param ev The pth event object to use on poll().
 * \param[out] err The pointer to an \c int for returning an error occurred
 *	during the function call if any. The \c int will be set to zero if the
 *	the operation was successful (optional)
 * \return The pointer to the internal comma-separated and null-terminated
 *	string of the authentication methods available for the user.
 * \retval NULL if an error has occurred. The \c int at \p err is set to the
 *	\c errno
 * \note This is a convenience function that wraps all the operation that
 *	involves polling and calling the function again.
 */
const char *prne_lssh2_ua_list (
	LIBSSH2_SESSION *s,
	const int fd,
	const char *username,
	pth_event_t ev,
	int *err);
/**
 * \brief libssh2_userauth_authenticated() wrapper function.
 * \param s The libssh2 session object.
 * \param fd The open file descriptor for the session.
 * \param ev The pth event object to use on poll().
 * \retval 1 if the session has been authenticated.
 * \retval 0 if the session has not been authenticated.
 * \retval Negative value returned from the library functions or poll() on
 *	failure.
 * \note This is a convenience function that wraps all the operation that
 *	involves polling and calling the function again.
 */
int prne_lssh2_ua_authd (
	LIBSSH2_SESSION *s,
	const int fd,
	pth_event_t ev);

/**
 * \brief Free the libssh2 session object.
 * \param s The libssh2 session object.
 * \note This is a bullshit-free version of libssh2_session_free().
 * \note The function call has no effect if \p s is passed NULL.
 * \see prne_lssh2_cripple_session()
 */
void prne_lssh2_free_session (LIBSSH2_SESSION *s);

/* Workarounds */
/**
 * \brief Cripple the session's IO ability. Used to guarantee that
 *	\c libssh2_session_free() will never return \c EAGAIN .
 * \param s The libssh2 session object.
 * \warning This function renders the session unusuable. The function must be
 *	the last function to call before calling \c libssh2_session_free() to
 *	free the resources.
 * \note This function is used in \c prne_lssh2_free_session() . This function
 *	is exposed just to cover the cases where it's necessary to cripple the
 *	session manually.
 * \see prne_lssh2_free_session()
 * \see libssh2_session_free()
 */
void prne_lssh2_cripple_session (LIBSSH2_SESSION *s);
