/** \file
 * \brief The resolv worker
 * \note Open RFC 1035 now!
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
#include "protocol.h"
#include "pth.h"

#include <mbedtls/ctr_drbg.h>


/* Alias and forward declarations */
struct prne_resolv;
typedef struct prne_resolv prne_resolv_t; // The instance handle type (opaque)
typedef struct prne_resolv_ns_pool prne_resolv_ns_pool_t;

struct prne_resolv_prm;
struct prne_resolv_fut;
struct prne_resolv_rr;
typedef struct prne_resolv_prm prne_resolv_prm_t;
typedef struct prne_resolv_fut prne_resolv_fut_t;
typedef struct prne_resolv_rr prne_resolv_rr_t;
typedef uint16_t prne_resolv_rcode_t; // The type for DNS return codes

// The query operation result
typedef enum {
	PRNE_RESOLV_QR_NONE = -1, // Null value

	PRNE_RESOLV_QR_OK, // Operation successful
	PRNE_RESOLV_QR_ERR, // Error occurred (errno set)
	PRNE_RESOLV_QR_PRO_ERR, // Protocol error
	PRNE_RESOLV_QR_FIN, // prne_fin_worker() called whilst processing query
	PRNE_RESOLV_QR_IMPL, // Failed due to implementation's limitation
	PRNE_RESOLV_QR_TIMEOUT, // Query timed out
	PRNE_RESOLV_QR_STATUS, // RCODE other than zero returned

	NB_PRNE_RESOLV // Meta value: the number of enums excluding the null value
} prne_resolv_qr_t;

// The record type
typedef enum {
	PRNE_RESOLV_QT_NONE = -1, // Null value

	PRNE_RESOLV_QT_A, // A record
	PRNE_RESOLV_QT_AAAA, // AAAA record
	PRNE_RESOLV_QT_TXT, // TXT record

	// Meta value: the number of enums excluding the null value
	NB_PRNE_RESOLV_QT
} prne_resolv_query_type_t;

// The name server pool object
struct prne_resolv_ns_pool {
	prne_net_endpoint_t *arr; // The pointer to the array of name servers
	size_t cnt; // The number of elements in the array
	/*
	 * True if the object has the responsibility of freeing the dynamically
	 * allocated members
	 */
	bool ownership;
};

// The query operation promise object
struct prne_resolv_prm {
	void *ctx; // The opaque context
	prne_resolv_fut_t *fut; // The future object
};

/**
 * \brief The query operation future object
 * \note The life span of the future object is independent of the life span of
 * 	the promise object
 */
struct prne_resolv_fut {
	size_t rr_cnt; // The number of resource records
	prne_resolv_rr_t *rr; // The pointer to the array of resource records
	int err; // errno occurred whilst processing the query
	prne_resolv_qr_t qr; // The query result code
	prne_resolv_rcode_t status; // The returned query status code
};

// The query resource record
struct prne_resolv_rr {
	/*
	 * The name of the record, the lengths of the labels replaced with the
	 * character '.'. This means that the names will look like this:
	 * "www.example.com."
	 */
	char *name;
	uint16_t
		rr_class, // The resource record class (1, the internet)
		rr_type; // The resource type (not prne_resolv_query_type_t)
	uint32_t rr_ttl; // The TTL value of the record
	// The pointer to the binary data, including the preceeding length byte
	uint8_t *rd_data;
	uint16_t rd_len; // The byte length of the binary data
};

/* The IPv4 addresses of the popular public name servers for use in array
 * initialiser lists.
 * Note that the byte length of these addresses are 16 bytes so that they can be
 * used to initialise prne_ip_addr_t. You may to ignore the last 12 bytes by
 * explicitly declaring the size of the array.
 */
#define PRNE_RESOLV_NS_IPV4_GOOGLE_A \
	0x08, 0x08, 0x08, 0x08, 0x00, 0x00, 0x00, 0x00,\
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
#define PRNE_RESOLV_NS_IPV4_GOOGLE_B \
	0x08, 0x08, 0x04, 0x04, 0x00, 0x00, 0x00, 0x00,\
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
#define PRNE_RESOLV_NS_IPV4_CLOUDFLARE_A \
	0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,\
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
#define PRNE_RESOLV_NS_IPV4_CLOUDFLARE_B \
	0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,\
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
#define PRNE_RESOLV_NS_IPV4_QUAD9_A \
	0x09, 0x09, 0x09, 0x0a, 0x00, 0x00, 0x00, 0x00,\
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
#define PRNE_RESOLV_NS_IPV4_QUAD9_B \
	0x95, 0x70, 0x70, 0x0a, 0x00, 0x00, 0x00, 0x00,\
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
#define PRNE_RESOLV_NS_IPV4_CLEANBROWSING_A \
	0xb9, 0xe4, 0xa8, 0x09, 0x00, 0x00, 0x00, 0x00,\
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
#define PRNE_RESOLV_NS_IPV4_CLEANBROWSING_B \
	0xb9, 0xe4, 0xa9, 0x09, 0x00, 0x00, 0x00, 0x00,\
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
// The concatenated byte array of the name servers above
#define PRNE_RESOLV_NS_POOL_IPV4 {\
	PRNE_RESOLV_NS_IPV4_GOOGLE_A,\
	PRNE_RESOLV_NS_IPV4_GOOGLE_B,\
	PRNE_RESOLV_NS_IPV4_CLOUDFLARE_A,\
	PRNE_RESOLV_NS_IPV4_CLOUDFLARE_B,\
	PRNE_RESOLV_NS_IPV4_QUAD9_A,\
	PRNE_RESOLV_NS_IPV4_QUAD9_B,\
	PRNE_RESOLV_NS_IPV4_CLEANBROWSING_A,\
	PRNE_RESOLV_NS_IPV4_CLEANBROWSING_B\
}

/* The IPv6 addresses of the popular public name servers for use in array
 * initialiser lists.
 */
#define PRNE_RESOLV_NS_IPV6_GOOGLE_A \
	0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0x00, 0x00,\
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x88
#define PRNE_RESOLV_NS_IPV6_GOOGLE_B \
	0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0x00, 0x00,\
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x44
#define PRNE_RESOLV_NS_IPV6_CLOUDFLARE_A \
	0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0x00, 0x00,\
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x11
#define PRNE_RESOLV_NS_IPV6_CLOUDFLARE_B \
	0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0x00, 0x00,\
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x01
#define PRNE_RESOLV_NS_IPV6_QUAD9_A \
	0x26, 0x20, 0x00, 0xfe, 0x00, 0x00, 0x00, 0x00,\
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe
#define PRNE_RESOLV_NS_IPV6_QUAD9_B \
	0x26, 0x20, 0x00, 0xfe, 0x00, 0x00, 0x00, 0x00,\
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09
#define PRNE_RESOLV_NS_IPV6_CLEANBROWSING_A \
	0x2a, 0x0d, 0x2a, 0x00, 0x00, 0x01, 0x00, 0x00,\
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02
#define PRNE_RESOLV_NS_IPV6_CLEANBROWSING_B \
	0x2a, 0x0d, 0x2a, 0x00, 0x00, 0x02, 0x00, 0x00,\
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02
// The concatenated byte array of the name servers above
#define PRNE_RESOLV_NS_POOL_IPV6 {\
	PRNE_RESOLV_NS_IPV6_GOOGLE_A,\
	PRNE_RESOLV_NS_IPV6_GOOGLE_B,\
	PRNE_RESOLV_NS_IPV6_CLOUDFLARE_A,\
	PRNE_RESOLV_NS_IPV6_CLOUDFLARE_B,\
	PRNE_RESOLV_NS_IPV6_QUAD9_A,\
	PRNE_RESOLV_NS_IPV6_QUAD9_B,\
	PRNE_RESOLV_NS_IPV6_CLEANBROWSING_A,\
	PRNE_RESOLV_NS_IPV6_CLEANBROWSING_B\
}

/* The default name server pools
 * These are for testing purposes only. Referencing these variables will
 * increase the size of the binary significantly as IPv4 addresses are not
 * stored as a series of 4-byte-elements.
 */
extern const prne_resolv_ns_pool_t PRNE_RESOLV_DEF_IPV4_POOL;
extern const prne_resolv_ns_pool_t PRNE_RESOLV_DEF_IPV6_POOL;

/* The response codes as per RFC 1035 4.1.1
 * bind-utils' choice of words are honoured.
 */
#define PRNE_RESOLV_RCODE_NOERROR		0	// No error condition
#define PRNE_RESOLV_RCODE_FORMERR		1	// Format error
#define PRNE_RESOLV_RCODE_SERVFAIL		2	// Server failure
#define PRNE_RESOLV_RCODE_NXDOMAIN		3	// Name Error
#define PRNE_RESOLV_RCODE_NOTIMP		4	// Not Implemented
#define PRNE_RESOLV_RCODE_REFUSED		5	// Refused

// The DNS record types as per RFC 1035 3.2.2 and RFC 3596
#define PRNE_RESOLV_RTYPE_A				1	// A host address
#define PRNE_RESOLV_RTYPE_NS			2	// An authoritative name server
#define PRNE_RESOLV_RTYPE_CNAME			5	// The canonical name for an alias
// Marks the start of a zone of authority
#define PRNE_RESOLV_RTYPE_SOA			6
#define PRNE_RESOLV_RTYPE_PTR			12	// A domain name pointer
#define PRNE_RESOLV_RTYPE_MX			15	// Mail exchange
#define PRNE_RESOLV_RTYPE_TXT			16	// text strings
#define PRNE_RESOLV_RTYPE_AAAA			28	// A host address (IPv6)

/**
 * \brief Allocate resources and start an instance of the resolv worker
 * \param wkr The initialised worker object
 * \param ctr_drbg The CTR DRBG object for SSL connections. The object has to be
 *	valid until the worker is freed.
 * \param pool_v4 The IPv4 name server pool
 * \param pool_v6 The IPv6 name server pool
 * \return A handle to the instasnce
 * \retval NULL with \c errno set to \c EINVAL if \p wkr or \p ctr_drbg is
 * 	passed NULL, or one of the name server pools is empty
 * \retval NULL with \c errno set to \c ENOMEM on memory allocation error
 */
prne_resolv_t *prne_alloc_resolv (
	prne_worker_t *wkr,
	mbedtls_ctr_drbg_context *ctr_drbg,
	const prne_resolv_ns_pool_t pool_v4,
	const prne_resolv_ns_pool_t pool_v6);
/**
 * \brief Queue A or AAAA query
 * \param ctx The worker handle
 * \param name The domain name of the host
 * \param ipv The Internet Protocol version. \c PRNE_IPV_4 for A and
 * 	\c PRNE_IPV_6 for AAAA.
 * \param cv The condition variable for result notification. The objects must be
 * 	valid until \p out is freed (optional)
 * \param out The poiner to an instance of the query operation promise object
 * \retval true on success
 * \retval false with \c errno set to \c ECANCELED if the worker is finalising
 * \retval false with \c errno set to \c ENOMEM on memory allocation error
 * \note \p out is freed using \c prne_resolv_free_prm() before being set up by
 * 	the function. Therefore, the object has to be initialised using
 * 	\c prne_resolv_init_prm()
 */
bool prne_resolv_prm_gethostbyname (
	prne_resolv_t *ctx,
	const char *name,
	const prne_ipv_t ipv,
	prne_pth_cv_t *cv,
	prne_resolv_prm_t *out);
/**
 * \brief Queue TXT query
 * \param ctx The worker handle
 * \param name The domain name of the host
 * \param cv The condition variable for result notification. The objects must be
 * 	valid until \p out is freed (optional)
 * \param out The poiner to an instance of the query operation promise object
 * \retval true on success
 * \retval false with \c errno set to \c ECANCELED if the worker is finalising
 * \retval false with \c errno set to \c ENOMEM on memory allocation error
 * \note \p out is freed using \c prne_resolv_free_prm() before being set up by
 * 	the function. Therefore, the object has to be initialised using
 * 	\c prne_resolv_init_prm()
 */
bool prne_resolv_prm_gettxtrec (
	prne_resolv_t *ctx,
	const char *name,
	prne_pth_cv_t *cv,
	prne_resolv_prm_t *out);

/**
 * \brief Initialisation function
 * \see [/doc/impl.md#Resource Allocation](/doc/impl.md#resource_allocation)
 */
void prne_resolv_init_ns_pool (prne_resolv_ns_pool_t *pool);
/**
 * \brief Deinitialisation function
 * \see [/doc/impl.md#Resource Allocation](/doc/impl.md#resource_allocation)
 */
void prne_resolv_free_ns_pool (prne_resolv_ns_pool_t *pool);
/**
 * \brief Allocate memory for the name server pool object
 * \param pool The pointer to the object
 * \param cnt The new number of elements
 * \return true on successful allocation
 * \return false on failure and \c errno set to \c ENOMEM
 */
bool prne_resolv_alloc_ns_pool (prne_resolv_ns_pool_t *pool, const size_t cnt);
/**
 * \brief Make a shallow copy of the name server pool object with the specified
 * 	ownership flag. This is a convenience function for making shallow copy of
 * 	the object that is shared with the multiple instances of the resolv worker
 * \param pool The source object
 * \param ownership The ownership flag of the new copy
 * \return The new shallow copy
 */
prne_resolv_ns_pool_t prne_resolv_own_ns_pool(
	const prne_resolv_ns_pool_t *pool,
	const bool ownership);
/**
 * \brief Initialisation function
 * \see [/doc/impl.md#Resource Allocation](/doc/impl.md#resource_allocation)
 */
void prne_resolv_init_prm (prne_resolv_prm_t *prm);
/**
 * \brief Deinitialisation function
 * \see [/doc/impl.md#Resource Allocation](/doc/impl.md#resource_allocation)
 */
void prne_resolv_free_prm (prne_resolv_prm_t *prm);
/**
 * \brief Initialisation function
 * \see [/doc/impl.md#Resource Allocation](/doc/impl.md#resource_allocation)
 */
void prne_init_resolv_fut (prne_resolv_fut_t *fut);
/**
 * \brief Deinitialisation function
 * \see [/doc/impl.md#Resource Allocation](/doc/impl.md#resource_allocation)
 */
void prne_free_resolv_fut (prne_resolv_fut_t *fut);
/**
 * \brief Initialisation function
 * \see [/doc/impl.md#Resource Allocation](/doc/impl.md#resource_allocation)
 */
void prne_init_resolv_rr (prne_resolv_rr_t *rr);
/**
 * \brief Deinitialisation function
 * \see [/doc/impl.md#Resource Allocation](/doc/impl.md#resource_allocation)
 */
void prne_free_resolv_rr (prne_resolv_rr_t *rr);

/**
 * \brief Convert the enum value to a string
 * \return The pointer to the string from the read-only static string pool.
 * \retval NULL if \p qr is out of bounds and \c errno set to \c EINVAL
 */
const char *prne_resolv_qr_tostr (const prne_resolv_qr_t qr);
/**
 * \brief Convert the enum value to a string
 * \return The pointer to the string from the read-only static string pool.
 * \retval NULL if \p rc is out of bounds and \c errno set to \c EINVAL
 */
const char *prne_resolv_rcode_tostr (const prne_resolv_rcode_t rc);
/**
 * \brief Convert the enum value to a string
 * \return The pointer to the string from the read-only static string pool.
 * \retval NULL if \p rrt is out of bounds and \c errno set to \c EINVAL
 */
const char *prne_resolv_rrtype_tostr (const uint16_t rrt);
