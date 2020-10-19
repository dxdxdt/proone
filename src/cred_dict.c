#include "cred_dict.h"
#include "util_rt.h"
#include "endian.h"
#include "strmap.h"

#include <string.h>
#include <errno.h>


void prne_init_cred_dict (prne_cred_dict_t *p) {
	prne_memzero(p, sizeof(prne_cred_dict_t));
}

void prne_free_cred_dict (prne_cred_dict_t *p) {
	if (p == NULL) {
		return;
	}

	prne_free(p->arr);
	prne_memzero(p, sizeof(prne_cred_dict_t));
}

bool prne_build_cred_dict (
	const prne_cred_dict_raw_entry_t *arr,
	const size_t cnt,
	uint8_t **out_m,
	size_t *out_l)
{
	bool ret = false;
	prne_strmap_t map;
	uint8_t *m = NULL, *p;
	size_t l = 0, strsize, sum_str;
	uint16_t idx_id, idx_pw;

	if (cnt > UINT16_MAX) {
		errno = EOVERFLOW;
		return false;
	}

	prne_init_strmap(&map);

// TRY
	for (size_t i = 0; i < cnt; i += 1) {
		if (arr[i].id == NULL || arr[i].pw == NULL) {
			errno = EINVAL;
			goto END;
		}
		prne_strmap_insert(&map, arr[i].id, 0);
		prne_strmap_insert(&map, arr[i].pw, 0);
	}

	sum_str = 0;
	for (size_t i = 0; i < map.size; i += 1) {
		map.tbl[i].val = (prne_strmap_val_t)sum_str;
		sum_str += strlen(map.tbl[i].key) + 1;
	}
	l = 2/*head*/ + 5 * cnt/*entries*/ + sum_str;
	if (sum_str > UINT16_MAX || l > UINT16_MAX) {
		errno = EOVERFLOW;
		goto END;
	}

	p = m = (uint8_t*)prne_malloc(1, l);
	if (m == NULL) {
		goto END;
	}

	p[0] = prne_getmsb16(cnt, 0);
	p[1] = prne_getmsb16(cnt, 1);
	p += 2;
	for (size_t i = 0; i < cnt; i += 1) {
		idx_id = (uint16_t)(prne_strmap_lookup(&map, arr[i].id)->val);
		idx_pw = (uint16_t)(prne_strmap_lookup(&map, arr[i].pw)->val);
		p[0] = prne_getmsb16(idx_id, 0);
		p[1] = prne_getmsb16(idx_id, 1);
		p[2] = prne_getmsb16(idx_pw, 0);
		p[3] = prne_getmsb16(idx_pw, 1);
		p[4] = arr[i].weight;
		p += 5;
	}
	for (size_t i = 0; i < map.size; i += 1) {
		strsize = strlen(map.tbl[i].key) + 1;
		memcpy(p, map.tbl[i].key, strsize);
		p += strsize;
	}

	*out_m = m;
	*out_l = l;
	m = NULL;
	ret = true;
END: // CATCH
	prne_free(m);
	prne_free_strmap(&map);
	return ret;
}

bool prne_dser_cred_dict (
	prne_cred_dict_t *dict,
	const uint8_t *buf,
	const size_t len)
{
	prne_cred_dict_entry_t *arr = NULL;
	size_t cnt, head_size, m_size;
	const uint8_t *p = buf;
	bool ret = false;

	if (len < 2) {
		errno = EINVAL;
		return false;
	}
	cnt = prne_recmb_msb16(p[0], p[1]);
	head_size = 2 + 5 * cnt;
	if (head_size > len) {
		errno = EINVAL;
		return false;
	}
	if (cnt > 0 && buf[len - 1] != 0) {
		errno = EINVAL;
		return false;
	}
	p += 2;
	m_size = len - head_size;

// TRY
	arr = prne_malloc(sizeof(prne_cred_dict_entry_t), cnt);
	if (cnt > 0 && arr == NULL) {
		goto END;
	}

	for (size_t i = 0; i < cnt; i += 1) {
		arr[i].id = prne_recmb_msb16(p[0], p[1]);
		arr[i].pw = prne_recmb_msb16(p[2], p[3]);
		arr[i].weight = p[4];
		p += 5;

		if (arr[i].id >= m_size || arr[i].pw >= m_size) {
			errno = EINVAL;
			goto END;
		}
	}

	prne_free_cred_dict(dict);
	dict->arr = arr;
	dict->cnt = cnt;
	dict->m = (const char *)(buf + head_size);
	arr = NULL;
	ret = true;
END:
	prne_free(arr);
	return ret;
}
