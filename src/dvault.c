#include "dvault.h"
#include "util_rt.h"
#include "util_ct.h"
#include "endian.h"

#include <string.h>


static uint8_t *m_data;
static const uint8_t *m_mask;
static uint16_t *m_offsets;
static uint8_t *m_unmasked;
static size_t m_unmasked_size;
static uint8_t m_salt;


static void invert_entry (const prne_data_key_t key, prne_data_type_t *type, const uint8_t **data_start, size_t *len) {
	size_t entry_len;

	m_salt = m_data[m_offsets[key]];
	m_unmasked = m_data + m_offsets[key] + 1;
	prne_dvault_invert_mem(3, m_unmasked, m_salt, 0, m_mask);

	*type = (prne_data_type_t)m_unmasked[0];
	entry_len = ((size_t)m_unmasked[1] << 8) | ((size_t)m_unmasked[2] << 0);
	m_unmasked_size = 3 + entry_len;
	*data_start = m_unmasked + 3;

	prne_dvault_invert_mem(entry_len, m_unmasked + 3, m_salt, 3, m_mask);

	if (len != NULL) {
		*len = entry_len;
	}
}


const char *prne_data_type_tostr (const prne_data_type_t t) {
	switch (t) {
	case PRNE_DATA_TYPE_CSTR: return "cstr";
	case PRNE_DATA_TYPE_BIN: return "bin";
	}
	return NULL;
}

prne_data_type_t prne_data_type_fstr (const char *str) {
	if (prne_nstreq(str, prne_data_type_tostr(PRNE_DATA_TYPE_CSTR))) {
		return PRNE_DATA_TYPE_CSTR;
	}
	if (prne_nstreq(str, prne_data_type_tostr(PRNE_DATA_TYPE_BIN))) {
		return PRNE_DATA_TYPE_BIN;
	}

	return PRNE_DATA_TYPE_NONE;
}

void prne_dvault_invert_mem (const size_t size, void *m, const uint8_t salt, const size_t salt_ofs, const uint8_t *mask) {
	size_t i;

	for (i = 0; i < size; i += 1) {
		((uint8_t*)m)[i] ^= mask[(i + salt_ofs + (size_t)salt) % 256];
	}
}

void prne_init_dvault_mask_result (prne_dvault_mask_result_t *r) {
	r->result = PRNE_DVAULT_MASK_OK;
	r->data = NULL;
	r->size = 0;
}

void prne_free_dvault_mask_result (prne_dvault_mask_result_t *r) {
	prne_free(r->data);
	r->size = 0;
	r->data = NULL;
	r->result = PRNE_DVAULT_MASK_OK;
}

prne_dvault_mask_result_t prne_dvault_mask (const prne_data_type_t type, const uint8_t salt, const uint8_t *mask, const size_t data_size, const uint8_t *data) {
	prne_dvault_mask_result_t ret;

	prne_init_dvault_mask_result(&ret);

	if (data_size > 0xFFFF - 4) {
		ret.result = PRNE_DVAULT_MASK_TOO_LARGE;
		return ret;
	}
	ret.size = data_size + 4;

	ret.data = prne_malloc(1, ret.size);
	if (ret.data == NULL) {
		ret.result = PRNE_DVAULT_MASK_MEM_ERR;
		ret.size = 0;
		return ret;
	}

	ret.data[0] = salt;
	ret.data[1] = (uint8_t)type;
	ret.data[2] = (uint8_t)((0xFF00 & (uint_fast16_t)data_size) >> 8);
	ret.data[3] = (uint8_t)((0x00FF & (uint_fast16_t)data_size) >> 0);
	memcpy(ret.data + 4, data, data_size);

	prne_dvault_invert_mem(ret.size - 1, ret.data + 1, salt, 0, mask);

	return ret;
}

const char *prne_dvault_mask_result_tostr (const prne_dvault_mask_result_code_t code) {
	switch (code) {
	case PRNE_DVAULT_MASK_OK: return "ok";
	case PRNE_DVAULT_MASK_MEM_ERR: return "memory error";
	case PRNE_DVAULT_MASK_TOO_LARGE: return "data too large";
	case PRNE_DVAULT_MASK_INVALID_TYPE: return "invalid type";
	}
	return NULL;
}

void prne_init_dvault (const void *m) {
	prne_dbgast(m_mask == NULL && m_offsets == NULL && m_data == NULL && m_unmasked == NULL);

	m_data = (uint8_t*)m;
	m_mask = (uint8_t*)m + 0;
	m_offsets = (uint16_t*)((uint8_t*)m + 256);

	prne_dvault_invert_mem(NB_PRNE_DATA_KEY * 2, m_offsets, 0, 0, m_mask);
	for (prne_data_key_t i = 0; i < NB_PRNE_DATA_KEY; i += 1) {
		m_offsets[i] = prne_be16toh(m_offsets[i]);
	}
}

void prne_deinit_dvault (void) {
	prne_dbgast(m_mask != NULL && m_offsets != NULL && m_data != NULL);

	prne_dvault_reset();

	for (prne_data_key_t i = 0; i < NB_PRNE_DATA_KEY; i += 1) {
		m_offsets[i] = prne_be16toh(m_offsets[i]);
	}
	prne_dvault_invert_mem(NB_PRNE_DATA_KEY * 2, m_offsets, 0, 0, m_mask);

	m_mask = NULL;
	m_offsets = NULL;
	m_data = NULL;
}

static const uint8_t *dvault_get_bin (const prne_data_key_t key, const prne_data_type_t desired, size_t *len) {
	const uint8_t *data_start;
	prne_data_type_t type;

	prne_dvault_reset();
	invert_entry(key, &type, &data_start, len);
	prne_dbgast(type == desired);

	return data_start;
}

const char *prne_dvault_get_cstr (const prne_data_key_t key, size_t *len) {
	const char *ret = (const char*)dvault_get_bin(key, PRNE_DATA_TYPE_CSTR, len);

	if (len != NULL) {
		*len -= 1;
	}
	return ret;
}

const uint8_t *prne_dvault_get_bin (const prne_data_key_t key, size_t *len) {
	return dvault_get_bin(key, PRNE_DATA_TYPE_BIN, len);
}

void prne_dvault_reset (void) {
	if (m_unmasked != NULL) {
		prne_dvault_invert_mem(m_unmasked_size, m_unmasked, m_salt, 0, m_mask);
		m_unmasked = NULL;
		m_unmasked_size = 0;
	}
}
