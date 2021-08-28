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
#include "util_ct.h"


typedef enum {
	PRNE_DATA_KEY_NONE = -1,

	PRNE_DATA_KEY_PROG_VER,
	PRNE_DATA_KEY_SHG_SALT,
	PRNE_DATA_KEY_X509_CA_CRT,
	PRNE_DATA_KEY_X509_DH,
	PRNE_DATA_KEY_X509_S_CRT,
	PRNE_DATA_KEY_X509_S_KEY,
	PRNE_DATA_KEY_X509_C_CRT,
	PRNE_DATA_KEY_X509_C_KEY,
	PRNE_DATA_KEY_RESOLV_NS_IPV4,
	PRNE_DATA_KEY_RESOLV_NS_IPV6,
	PRNE_DATA_KEY_CNC_TXT_REC,
	PRNE_DATA_KEY_RCN_PORTS,
	PRNE_DATA_KEY_RCN_T_IPV4,
	PRNE_DATA_KEY_RCN_BL_IPV4,
	PRNE_DATA_KEY_RCN_T_IPV6,
	PRNE_DATA_KEY_RCN_BL_IPV6,
	PRNE_DATA_KEY_CRED_DICT,
	PRNE_DATA_KEY_EXEC_NAME,
	PRNE_DATA_KEY_VER_MAT,
	PRNE_DATA_KEY_BNE_LOCK_NAME,

	NB_PRNE_DATA_KEY
} prne_data_key_t;
