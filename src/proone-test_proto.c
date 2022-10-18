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
#include "protocol.h"
#include "util_rt.h"
#include "config.h"
#include "dvault.h"
#include "pack.h"

#include <string.h>
#include <assert.h>
#include <errno.h>
#include <sys/random.h>


static uint8_t proto_buf[PRNE_HTBT_PROTO_MIN_BUF];
static size_t proto_buf_cnt_len;

static void test_ser (void);
static void test_enum (void);


int main (void) {
	test_ser();
	test_enum();

	return 0;
}

static void test_ser (void) {
	static size_t actual;
	static prne_htbt_msg_head_t mh_a, mh_b;
	static prne_htbt_status_t s_a, s_b;
	static prne_host_cred_t hc_a, hc_b;
	static prne_htbt_hover_t hv_a, hv_b;
	static uint8_t cred_data[255];
	static size_t cred_data_len = 0;
	static prne_htbt_host_info_t hi_a, hi_b;
	static prne_htbt_cmd_t cmd_a, cmd_b;
	static const char *test_args[] = {
		"sudo",
		"systemctl",
		"enable",
		"--now",
		"NetworkManager",
		NULL
	};
	static char test_args_mem[] =
		"\x00\x2Bsudo\0systemctl\0enable\0--now\0NetworkManager";
	static const char *empty_args[] = {
		NULL
	};
	static const char *long_args[] = {
		"", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
		"", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
		"", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
		"", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
		"", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
		"", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
		"", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
		"", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
		"", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
		"", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
		"", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
		"", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
		"", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
		"", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
		"", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
		"", "", "", "", "", "", "", "", "", "", "", "", "", "", "", NULL
	};
	static const char *too_long_args[] = {
		"", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
		"", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
		"", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
		"", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
		"", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
		"", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
		"", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
		"", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
		"", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
		"", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
		"", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
		"", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
		"", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
		"", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
		"", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
		"", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
		NULL
	};
	static const char *long_mem_args[] = {
		"123", "123", "123", "123", "123", "123", "123", "123",
		"123", "123", "123", "123", "123", "123", "123", "123",
		"123", "123", "123", "123", "123", "123", "123", "123",
		"123", "123", "123", "123", "123", "123", "123", "123",
		"123", "123", "123", "123", "123", "123", "123", "123",
		"123", "123", "123", "123", "123", "123", "123", "123",
		"123", "123", "123", "123", "123", "123", "123", "123",
		"123", "123", "123", "123", "123", "123", "123", "123",
		"123", "123", "123", "123", "123", "123", "123", "123",
		"123", "123", "123", "123", "123", "123", "123", "123",
		"123", "123", "123", "123", "123", "123", "123", "123",
		"123", "123", "123", "123", "123", "123", "123", "123",
		"123", "123", "123", "123", "123", "123", "123", "123",
		"123", "123", "123", "123", "123", "123", "123", "123",
		"123", "123", "123", "123", "123", "123", "123", "123",
		"123", "123", "123", "123", "123", "123", "123", "123",
		"123", "123", "123", "123", "123", "123", "123", "123",
		"123", "123", "123", "123", "123", "123", "123", "123",
		"123", "123", "123", "123", "123", "123", "123", "123",
		"123", "123", "123", "123", "123", "123", "123", "123",
		"123", "123", "123", "123", "123", "123", "123", "123",
		"123", "123", "123", "123", "123", "123", "123", "123",
		"123", "123", "123", "123", "123", "123", "123", "123",
		"123", "123", "123", "123", "123", "123", "123", "123",
		"123", "123", "123", "123", "123", "123", "123", "123",
		"123", "123", "123", "123", "123", "123", "123", "123",
		"123", "123", "123", "123", "123", "123", "123", "123",
		"123", "123", "123", "123", "123", "123", "123", "123",
		"123", "123", "123", "123", "123", "123", "123", "123",
		"123", "123", "123", "123", "123", "123", "123", "123",
		"123", "123", "123", "123", "123", "123", "123", "123",
		"123", "123", "123", "123", "123", "123", "123456", NULL
	};
	static const char *too_long_mem_args[] = {
		"123", "123", "123", "123", "123", "123", "123", "123",
		"123", "123", "123", "123", "123", "123", "123", "123",
		"123", "123", "123", "123", "123", "123", "123", "123",
		"123", "123", "123", "123", "123", "123", "123", "123",
		"123", "123", "123", "123", "123", "123", "123", "123",
		"123", "123", "123", "123", "123", "123", "123", "123",
		"123", "123", "123", "123", "123", "123", "123", "123",
		"123", "123", "123", "123", "123", "123", "123", "123",
		"123", "123", "123", "123", "123", "123", "123", "123",
		"123", "123", "123", "123", "123", "123", "123", "123",
		"123", "123", "123", "123", "123", "123", "123", "123",
		"123", "123", "123", "123", "123", "123", "123", "123",
		"123", "123", "123", "123", "123", "123", "123", "123",
		"123", "123", "123", "123", "123", "123", "123", "123",
		"123", "123", "123", "123", "123", "123", "123", "123",
		"123", "123", "123", "123", "123", "123", "123", "123",
		"123", "123", "123", "123", "123", "123", "123", "123",
		"123", "123", "123", "123", "123", "123", "123", "123",
		"123", "123", "123", "123", "123", "123", "123", "123",
		"123", "123", "123", "123", "123", "123", "123", "123",
		"123", "123", "123", "123", "123", "123", "123", "123",
		"123", "123", "123", "123", "123", "123", "123", "123",
		"123", "123", "123", "123", "123", "123", "123", "123",
		"123", "123", "123", "123", "123", "123", "123", "123",
		"123", "123", "123", "123", "123", "123", "123", "123",
		"123", "123", "123", "123", "123", "123", "123", "123",
		"123", "123", "123", "123", "123", "123", "123", "123",
		"123", "123", "123", "123", "123", "123", "123", "123",
		"123", "123", "123", "123", "123", "123", "123", "123",
		"123", "123", "123", "123", "123", "123", "123", "123",
		"123", "123", "123", "123", "123", "123", "123", "123",
		"123", "123", "123", "123", "123", "123", "1234567", NULL
	};
	static prne_htbt_bin_meta_t bm_a, bm_b;
	static const uint8_t prog_ver[] = PRNE_PROG_VER;
	static const char CRED_STR_NORM[] =
		"qwertyuiop[]asdfghjkl;'zxcvbnm,./`1234567890-=~!@#$%^&*()_+|\\";
	static const char CRED_STR_LONG[] =
		"012345678901234567890123456789012345678901234567890123456789"
		"012345678901234567890123456789012345678901234567890123456789"
		"012345678901234567890123456789012345678901234567890123456789";
	static uint8_t BF[] = { 0x55, 0xAA };

	// free functions should accept NULL
	prne_htbt_free_msg_head(NULL);
	prne_htbt_free_status(NULL);
	prne_free_host_cred(NULL);
	prne_htbt_free_host_info(NULL);
	prne_htbt_free_cmd(NULL);
	prne_htbt_free_bin_meta(NULL);

	// msg head
	prne_htbt_init_msg_head(&mh_a);
	prne_htbt_init_msg_head(&mh_b);
	// normal NOOP case
	// req
	assert(prne_htbt_ser_msg_head(
		proto_buf,
		PRNE_HTBT_PROTO_MIN_BUF,
		&proto_buf_cnt_len,
		&mh_a) == PRNE_HTBT_SER_RC_OK);
	assert(
		proto_buf_cnt_len == 3 &&
		memcmp("\x80\x00\x00", proto_buf, proto_buf_cnt_len) == 0);
	assert(prne_htbt_dser_msg_head(
		proto_buf,
		PRNE_HTBT_PROTO_MIN_BUF,
		&proto_buf_cnt_len,
		&mh_b) == PRNE_HTBT_SER_RC_OK);
	assert(prne_htbt_eq_msg_head(&mh_a, &mh_b));
	// rsp
	mh_a.is_rsp = true;
	assert(prne_htbt_ser_msg_head(
		proto_buf,
		PRNE_HTBT_PROTO_MIN_BUF,
		&proto_buf_cnt_len,
		&mh_a) == PRNE_HTBT_SER_RC_OK);
	assert(
		proto_buf_cnt_len == 3 &&
		memcmp("\x00\x00\x00", proto_buf, proto_buf_cnt_len) == 0);
	assert(prne_htbt_dser_msg_head(
		proto_buf,
		PRNE_HTBT_PROTO_MIN_BUF,
		&proto_buf_cnt_len,
		&mh_b) == PRNE_HTBT_SER_RC_OK);
	assert(prne_htbt_eq_msg_head(&mh_a, &mh_b));
	// error cases
	// using id other than 0 for NOOP should be an error
	mh_a.id = 1;
	mh_a.op = PRNE_HTBT_OP_NOOP;
	assert(prne_htbt_ser_msg_head(
		proto_buf,
		PRNE_HTBT_PROTO_MIN_BUF,
		&proto_buf_cnt_len,
		&mh_a) == PRNE_HTBT_SER_RC_FMT_ERR);
	// using id 0 for OP other than NOOP should be an error
	mh_a.id = 0;
	mh_a.op = PRNE_HTBT_OP_HOST_INFO;
	assert(prne_htbt_ser_msg_head(
		proto_buf,
		PRNE_HTBT_PROTO_MIN_BUF,
		&proto_buf_cnt_len,
		&mh_a) == PRNE_HTBT_SER_RC_FMT_ERR);
	// using id over 0x8000 should be an error
	mh_a.id = 0x8000;
	mh_a.op = PRNE_HTBT_OP_STATUS;
	assert(prne_htbt_ser_msg_head(
		proto_buf,
		PRNE_HTBT_PROTO_MIN_BUF,
		&proto_buf_cnt_len,
		&mh_a) == PRNE_HTBT_SER_RC_FMT_ERR);
	// normal cases
	mh_a.is_rsp = false;
	mh_a.id = 0x1234;
	mh_a.op = PRNE_HTBT_OP_STATUS;
	assert(prne_htbt_ser_msg_head(
		proto_buf,
		PRNE_HTBT_PROTO_MIN_BUF,
		&proto_buf_cnt_len,
		&mh_a) == PRNE_HTBT_SER_RC_OK);
	assert(
		proto_buf_cnt_len == 3 &&
		memcmp("\x92\x34\x01", proto_buf, proto_buf_cnt_len) == 0);
	assert(prne_htbt_dser_msg_head(
		proto_buf,
		PRNE_HTBT_PROTO_MIN_BUF,
		&proto_buf_cnt_len,
		&mh_b) == PRNE_HTBT_SER_RC_OK);
	assert(prne_htbt_eq_msg_head(&mh_a, &mh_b));
	mh_a.is_rsp = true;
	mh_a.id = 0x5678;
	mh_a.op = PRNE_HTBT_OP_STATUS;
	assert(prne_htbt_ser_msg_head(
		proto_buf,
		PRNE_HTBT_PROTO_MIN_BUF,
		&proto_buf_cnt_len,
		&mh_a) == PRNE_HTBT_SER_RC_OK);
	assert(
		proto_buf_cnt_len == 3 &&
		memcmp("\x56\x78\x01", proto_buf, proto_buf_cnt_len) == 0);
	assert(prne_htbt_dser_msg_head(
		proto_buf,
		PRNE_HTBT_PROTO_MIN_BUF,
		&proto_buf_cnt_len,
		&mh_b) == PRNE_HTBT_SER_RC_OK);
	assert(prne_htbt_eq_msg_head(&mh_a, &mh_b));
	// just testing (placeholder)
	prne_htbt_free_msg_head(&mh_a);
	prne_htbt_free_msg_head(&mh_b);

	// status
	prne_htbt_init_status(&s_a);
	prne_htbt_init_status(&s_b);
	s_a.code = PRNE_HTBT_STATUS_ERRNO;
	s_a.err = EHOSTUNREACH;
	assert(prne_htbt_ser_status(
		proto_buf,
		PRNE_HTBT_PROTO_MIN_BUF,
		&proto_buf_cnt_len,
		&s_a) == PRNE_HTBT_SER_RC_OK);
	assert(
		proto_buf_cnt_len == 5 &&
		memcmp("\x03\x00\x00\x00\x71", proto_buf, 5) == 0);
	assert(prne_htbt_dser_status(
		proto_buf,
		PRNE_HTBT_PROTO_MIN_BUF,
		&proto_buf_cnt_len,
		&s_b) == PRNE_HTBT_SER_RC_OK);
	assert(prne_htbt_eq_status(&s_a, &s_b));
	prne_htbt_free_status(&s_a);
	prne_htbt_free_status(&s_b);

	// empty cred
	// zero-len alloc
	prne_init_host_cred(&hc_a);
	prne_init_host_cred(&hc_b);
	assert(prne_alloc_host_cred(&hc_a, 0, 0));
	hc_a.id[0] = 0;
	hc_a.pw[0] = 0;
	assert(prne_enc_host_cred(
		proto_buf,
		PRNE_HTBT_PROTO_MIN_BUF,
		&proto_buf_cnt_len,
		&hc_a) == PRNE_HTBT_SER_RC_OK);
	assert(prne_dec_host_cred(
		proto_buf,
		proto_buf_cnt_len,
		&hc_b) == PRNE_HTBT_SER_RC_OK);
	assert(prne_eq_host_cred(&hc_a, &hc_b));
	assert(strlen(hc_b.id) == 0 && strlen(hc_b.pw) == 0);
	prne_free_host_cred(&hc_a);
	prne_free_host_cred(&hc_b);
	// no alloc (the functions should accept NULL pointers)
	prne_init_host_cred(&hc_a);
	prne_init_host_cred(&hc_b);
	assert(prne_enc_host_cred(
		proto_buf,
		PRNE_HTBT_PROTO_MIN_BUF,
		&proto_buf_cnt_len,
		&hc_a) == PRNE_HTBT_SER_RC_OK);
	assert(prne_dec_host_cred(
		proto_buf,
		proto_buf_cnt_len,
		&hc_b) == PRNE_HTBT_SER_RC_OK);
	assert(prne_eq_host_cred(&hc_a, &hc_b));
	prne_free_host_cred(&hc_a);
	prne_free_host_cred(&hc_b);
	// too long
	prne_init_host_cred(&hc_a);
	prne_init_host_cred(&hc_b);
	assert(prne_alloc_host_cred( // This should be ok
		&hc_a,
		strlen(CRED_STR_LONG),
		strlen(CRED_STR_LONG)));
	strcpy(hc_a.id, CRED_STR_LONG);
	strcpy(hc_a.pw, CRED_STR_LONG);
	assert(prne_enc_host_cred( // This is should fail
		proto_buf,
		PRNE_HTBT_PROTO_MIN_BUF,
		&proto_buf_cnt_len,
		&hc_a) == PRNE_HTBT_SER_RC_FMT_ERR);
	prne_free_host_cred(&hc_a);
	prne_free_host_cred(&hc_b);
	// normal case
	assert(prne_alloc_host_cred(
		&hc_a,
		strlen(CRED_STR_NORM),
		strlen(CRED_STR_NORM)));
	strcpy(hc_a.id, CRED_STR_NORM);
	strcpy(hc_a.pw, CRED_STR_NORM);
	assert(prne_enc_host_cred(
		cred_data,
		sizeof(cred_data),
		&cred_data_len,
		&hc_a) == PRNE_HTBT_SER_RC_OK);
	assert(cred_data_len == sizeof(CRED_STR_NORM) * 2);
	assert(prne_dec_host_cred(
		cred_data,
		cred_data_len,
		&hc_b) == PRNE_HTBT_SER_RC_OK);
	assert(
		strcmp(hc_b.id, CRED_STR_NORM) == 0 &&
		strcmp(hc_b.pw, CRED_STR_NORM) == 0);
	assert(prne_eq_host_cred(&hc_a, &hc_b));
	prne_free_host_cred(&hc_a);
	prne_free_host_cred(&hc_b);

	// host info
	prne_htbt_init_host_info(&hi_a);
	prne_htbt_init_host_info(&hi_b);
	// without ownership of host_cred
	hi_a.parent_uptime = 0xABBABABE;
	hi_a.child_uptime = 0xDEADBEEF;
	hi_a.crash_cnt = 0x11223344;
	hi_a.bne_cnt = 0x8899AABBCCDDEEFF;
	hi_a.infect_cnt = 0xABBAABBAABBAABBA;
	hi_a.parent_pid = 0xDEADBEEF;
	hi_a.child_pid = 0xBABEBABE;
	hi_a.host_cred = cred_data;
	hi_a.host_cred_len = cred_data_len;
	hi_a.bf = BF;
	hi_a.bf_len = sizeof(BF);
	memcpy(hi_a.prog_ver, prog_ver, sizeof(prog_ver));
	memcpy(
		hi_a.boot_id,
		"\x30\x1d\x25\x39\x90\x85\x42\xfd\x90\xb6\x20\x0b\x4a\x3b\x08\x55",
		16);
	memcpy(
		hi_a.instance_id,
		"\x25\xdc\x7e\xa2\x4a\xc6\x4a\x29\x9f\xac\xbe\x18\x42\x33\xc4\x85",
		16);
	memcpy(
		hi_a.org_id,
		"\xa3\x0f\xd3\x5e\xe7\xe7\xc3\xb6\x8f\x74\xdf\xf6\x07\x45\x77\xfa",
		16);
	hi_a.os = PRNE_HOST_OS;
	hi_a.arch = PRNE_HOST_ARCH;
	assert(prne_htbt_ser_host_info(
		proto_buf,
		PRNE_HTBT_PROTO_MIN_BUF,
		&proto_buf_cnt_len,
		&hi_a) == PRNE_HTBT_SER_RC_OK);
	assert(proto_buf_cnt_len == 104 + cred_data_len + sizeof(BF));
	assert(memcmp(proto_buf, prog_ver, 16) == 0);
	assert(memcmp(
			proto_buf + 16,
			// boot_id
			"\x30\x1d\x25\x39\x90\x85\x42\xfd\x90\xb6\x20\x0b\x4a\x3b\x08\x55"
			// instance_id
			"\x25\xdc\x7e\xa2\x4a\xc6\x4a\x29\x9f\xac\xbe\x18\x42\x33\xc4\x85"
			// org_id
			"\xa3\x0f\xd3\x5e\xe7\xe7\xc3\xb6\x8f\x74\xdf\xf6\x07\x45\x77\xfa"
			"\xAB\xBA\xBA\xBE" // parent_uptime
			"\xDE\xAD\xBE\xEF" // child_uptime
			"\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF" // bne_cnt
			"\xAB\xBA\xAB\xBA\xAB\xBA\xAB\xBA" // infect_cnt
			"\x11\x22\x33\x44" // crash_cnt
			"\xDE\xAD\xBE\xEF" // parent_pid
			"\xBA\xBE\xBA\xBE", // child_pid
			84) == 0);
	assert((size_t)proto_buf[16 + 84 + 0] == cred_data_len);
	assert(proto_buf[16 + 84 + 1] == (uint8_t)PRNE_HOST_ARCH);
	assert(proto_buf[16 + 84 + 2] == (uint8_t)PRNE_HOST_OS);
	assert(proto_buf[16 + 84 + 3] == sizeof(BF));
	assert(memcmp(proto_buf + 16 + 84 + 4, cred_data, cred_data_len) == 0);
	assert(memcmp(proto_buf + 16 + 84 + 4 + cred_data_len, BF, sizeof(BF)) == 0);
	assert(prne_htbt_dser_host_info(
		proto_buf,
		proto_buf_cnt_len,
		&actual,
		&hi_b) == PRNE_HTBT_SER_RC_OK);
	assert(prne_htbt_eq_host_info(&hi_a, &hi_b));
	hi_a.host_cred = NULL;
	hi_a.host_cred_len = 0;
	hi_a.bf = NULL;
	hi_a.bf_len = 0;
	// with ownership of buffers
	assert(prne_htbt_ser_host_info(
		proto_buf,
		PRNE_HTBT_PROTO_MIN_BUF,
		&proto_buf_cnt_len,
		&hi_a) == PRNE_HTBT_SER_RC_OK);
	assert(prne_htbt_dser_host_info(
		proto_buf,
		proto_buf_cnt_len,
		&actual,
		&hi_b) == PRNE_HTBT_SER_RC_OK);
	assert(prne_htbt_eq_host_info(&hi_a, &hi_b));
	prne_htbt_free_host_info(&hi_a);
	prne_htbt_free_host_info(&hi_b);

	prne_htbt_init_cmd(&cmd_a);
	assert(prne_htbt_set_cmd(&cmd_a, long_args));
	assert(!prne_htbt_set_cmd(&cmd_a, too_long_args));
	assert(prne_htbt_set_cmd(&cmd_a, long_mem_args));
	assert(!prne_htbt_set_cmd(&cmd_a, too_long_mem_args));
	// empty cmd
	assert(
		prne_htbt_set_cmd(&cmd_a, NULL) &&
		cmd_a.argc == 0 &&
		cmd_a.args == NULL &&
		cmd_a.mem == NULL &&
		cmd_a.mem_len == 0);
	assert(
		prne_htbt_set_cmd(&cmd_a, empty_args) &&
		cmd_a.argc == 0 &&
		cmd_a.args == NULL &&
		cmd_a.mem == NULL &&
		cmd_a.mem_len == 0);
	assert(prne_htbt_ser_cmd(
		proto_buf,
		PRNE_HTBT_PROTO_MIN_BUF,
		&proto_buf_cnt_len,
		&cmd_a) == PRNE_HTBT_SER_RC_OK);
	assert(proto_buf_cnt_len == 2 && memcmp(proto_buf, "\x00\x00", 2) == 0);
	prne_htbt_free_cmd(&cmd_a);
	// cmd
	prne_htbt_init_cmd(&cmd_a);
	prne_htbt_init_cmd(&cmd_b);
	assert(prne_htbt_set_cmd(&cmd_a, test_args));
	assert(prne_htbt_ser_cmd(
		proto_buf,
		PRNE_HTBT_PROTO_MIN_BUF,
		&proto_buf_cnt_len,
		&cmd_a) == PRNE_HTBT_SER_RC_OK);
	assert(
		proto_buf_cnt_len == sizeof(test_args_mem) &&
		memcmp(proto_buf, test_args_mem, sizeof(test_args_mem)) == 0);
	assert(prne_htbt_dser_cmd(
		proto_buf,
		proto_buf_cnt_len,
		&actual,
		&cmd_b) == PRNE_HTBT_SER_RC_OK);
	assert(prne_htbt_eq_cmd(&cmd_a, &cmd_b));
	prne_htbt_free_cmd(&cmd_a);
	prne_htbt_free_cmd(&cmd_b);

	// bin meta
	prne_htbt_init_bin_meta(&bm_a);
	prne_htbt_init_bin_meta(&bm_b);
	assert(prne_htbt_set_cmd(&bm_a.cmd, test_args));
	bm_a.alloc_len = 0xBBAAEE;
	assert(prne_htbt_ser_bin_meta(
		proto_buf,
		PRNE_HTBT_PROTO_MIN_BUF,
		&proto_buf_cnt_len,
		&bm_a) == PRNE_HTBT_SER_RC_OK);
	assert(
		proto_buf_cnt_len == sizeof(test_args_mem) + 3 &&
		memcmp(proto_buf, "\xBB\xAA\xEE", 3) == 0 &&
		memcmp(proto_buf + 3, test_args_mem, sizeof(test_args_mem)) == 0);
	assert(prne_htbt_dser_bin_meta(
		proto_buf,
		proto_buf_cnt_len,
		&actual,
		&bm_b) == PRNE_HTBT_SER_RC_OK);
	assert(prne_htbt_eq_bin_meta(&bm_a, &bm_b));

	bm_a.alloc_len = PRNE_HTBT_BIN_ALLOC_LEN_MAX + 1;
	assert(prne_htbt_ser_bin_meta(
		proto_buf,
		PRNE_HTBT_PROTO_MIN_BUF,
		&proto_buf_cnt_len,
		&bm_a) == PRNE_HTBT_SER_RC_FMT_ERR);

	prne_htbt_free_bin_meta(&bm_a);
	prne_htbt_free_bin_meta(&bm_b);

	// hover
	prne_htbt_init_hover(&hv_a);
	prne_htbt_init_hover(&hv_b);
	memcpy(hv_a.v4.addr, "\x1\x2\x3\x4", 4);
	memcpy(
		hv_a.v6.addr,
		"\x0\x1\x2\x3\x4\x5\x6\x7\x8\x9\xA\xB\xC\xD\xE\xF",
		16);
	hv_a.v4.port = 0xDEAD;
	hv_a.v6.port = 0xBEEF;
	assert(prne_htbt_ser_hover(
		proto_buf,
		PRNE_HTBT_PROTO_MIN_BUF,
		&proto_buf_cnt_len,
		&hv_a) == PRNE_HTBT_SER_RC_OK);
	assert(
		proto_buf_cnt_len == 24 &&
		memcmp(
			proto_buf,
			"\x1\x2\x3\x4"
			"\xDE\xAD"
			"\x0\x1\x2\x3\x4\x5\x6\x7\x8\x9\xA\xB\xC\xD\xE\xF"
			"\xBE\xEF",
			24) == 0);
	assert(prne_htbt_dser_hover(
		proto_buf,
		proto_buf_cnt_len,
		&actual,
		&hv_b) == PRNE_HTBT_SER_RC_OK);
	assert(prne_htbt_eq_hover(&hv_a, &hv_b));
	prne_htbt_free_hover(&hv_a);
	prne_htbt_free_hover(&hv_b);

	// TODO: test STDIO and RCB
}

static void test_enum (void) {
	for (prne_os_t i = PRNE_OS_NONE + 1; i < NB_PRNE_OS; i += 1) {
		assert(i == prne_os_fstr(prne_os_tostr(i)));
	}
	for (prne_os_t i = PRNE_OS_NONE + 1; i < NB_PRNE_OS; i += 1) {
		assert(prne_os_tostr(i) != NULL);
	}
	for (prne_arch_t i = PRNE_ARCH_NONE + 1; i < NB_PRNE_ARCH; i += 1) {
		assert(i == prne_arch_fstr(prne_arch_tostr(i)));
	}
	for (prne_arch_t i = PRNE_ARCH_NONE + 1; i < NB_PRNE_ARCH; i += 1) {
		assert(prne_arch_tostr(i) != NULL);
	}
	for (prne_iflag_t i = PRNE_IFLAG_NONE + 1; i < NB_PRNE_IFLAG; i += 1) {
		assert(i == prne_iflag_fstr(prne_iflag_tostr(i)));
	}
	for (prne_iflag_t i = PRNE_IFLAG_NONE + 1; i < NB_PRNE_IFLAG; i += 1) {
		assert(prne_iflag_tostr(i) != NULL);
	}

	for (prne_htbt_ser_rc_t i = 0; i < NB_PRNE_HTBT_SER_RC; i += 1) {
		assert(prne_htbt_serrc_tostr(i) != NULL);
	}
	for (prne_htbt_op_t i = 0; i < NB_PRNE_HTBT_OP; i += 1) {
		assert(prne_htbt_op_tostr(i) != NULL);
	}
	for (prne_pack_rc_t i = PRNE_PACK_RC_OK; i < NB_PRNE_PACK_RC; i += 1) {
		assert(prne_pack_rc_tostr(i) != NULL);
	}
}
