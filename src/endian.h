/** \file
 * \brief Proone's own <endian.h>. Proone does not use <endian.h> present on
 *	many platforms simply because the header is not a standard. Proone does not
 *	use the traditional byte swap approach to solve the endianness problem for
 *	data communication so that all arches have the same disadvantage when
 *	communicating with other hosts.
 * \note The functions in the internet protocol headers are used if present to
 *	avoid confusion.
 * \see BYTEORDER(3)
 * \see <arpa/inet.h>
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

/** \def prne_getmsb \def prne_getmsb64 \def prne_getmsb32 \def prne_getmsb16
 * \brief Extract \p n th most significant byte of \p x
 * \param[in] x The integer
 * \param[in] n The byte place, in range of [0, 1] if \p x is 16-bit integer,
 *	[0, 3] if \p x is 32-bit integer, [0, 7] if \p x is 64-bit integer.
 * \param[in] w The data type to use in calculation. One of uint_fastN_t
 *	variants.
 * \param[in] s The number of bits to shift by.
 * \return The 8-bit integer extracted from the \p n th place of \p x in range
 *	[0, 255].
 * \see \c prne_recmb_msb64()
 * \see \c prne_recmb_msb32()
 * \see \c prne_recmb_msb16()
 */
#define prne_getmsb(x, n, w, s)\
	(uint8_t)(((w)(x) & (w)0xFF << (s - 8 * (n))) >> (s - 8 * (n)))
#define prne_getmsb64(x, n) prne_getmsb((x), (n), uint_fast64_t, 56)
#define prne_getmsb32(x, n) prne_getmsb((x), (n), uint_fast32_t, 24)
#define prne_getmsb16(x, n) prne_getmsb((x), (n), uint_fast16_t, 8)

/** \def prne_recmb_msb64 \def prne_recmb_msb32 \def prne_recmb_msb16
 * \brief Recombine bytes in big-endian order.
 * \param a The first byte.
 * \param b The second byte.
 * \param c The third byte.
 * \param d The fourth byte.
 * \param e The fifth byte.
 * \param f The sixth byte.
 * \param g The seventh byte.
 * \param h The eighth byte.
 * \return The recombined integer in the host's endian.
 * \see \c prne_getmsb()
 * \see \c prne_getmsb64()
 * \see \c prne_getmsb32()
 * \see \c prne_getmsb16()
 */
#define prne_recmb_msb64(a, b, c, d, e, f, g, h) (\
	((uint_fast64_t)(a) << 56) |\
	((uint_fast64_t)(b) << 48) |\
	((uint_fast64_t)(c) << 40) |\
	((uint_fast64_t)(d) << 32) |\
	((uint_fast64_t)(e) << 24) |\
	((uint_fast64_t)(f) << 16) |\
	((uint_fast64_t)(g) << 8) |\
	((uint_fast64_t)(h) << 0)\
)
#define prne_recmb_msb32(a, b, c, d) (\
	((uint_fast32_t)(a) << 24) |\
	((uint_fast32_t)(b) << 16) |\
	((uint_fast32_t)(c) << 8) |\
	((uint_fast32_t)(d) << 0)\
)
#define prne_recmb_msb16(a, b) (\
	((uint_fast16_t)(a) << 8) |\
	((uint_fast16_t)(b) << 0)\
)

/* Machine Characteristics
*/
/** \def PRNE_ENDIAN_LITTLE \def PRNE_ENDIAN_BIG
 * \brief The values that can be matched against \c PRNE_HOST_ENDIAN
 * \note The PDP endian is not defined because the ELF does not support it.
 */
#define PRNE_ENDIAN_LITTLE 1
#define PRNE_ENDIAN_BIG 2

/** \def PRNE_HOST_ENDIAN
 * \brief The host endian.
 * \see \c PRNE_ENDIAN_LITTLE
 * \see \c PRNE_ENDIAN_BIG
 */
#ifdef __GNUC__
	#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
		#define PRNE_HOST_ENDIAN PRNE_ENDIAN_BIG
	#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
		#define PRNE_HOST_ENDIAN PRNE_ENDIAN_LITTLE
	#else
		#error "FIXME!"
	#endif
#else
	// Expand this to support compilers other than GCC
	#error "FIXME!"
#endif

/**
 * \brief Swap bytes to invert the endianness of the 16-bit integer.
 * \param x The integer.
 * \returns The integer with its bytes swapped.
 */
#define prne_einv16(x) (((0xFF00 & x) >> 8) | ((0x00FF & x) << 8))

/** \def prne_htobe16 \def prne_be16toh \def prne_htole16 \def prne_le16toh
 * \brief Convert the endianness of the integer.
 * \param x The integer.
 * \return The integer converted.
 * \note Use the functions in <arpa/inet.h> where appropriate!
 */
#if PRNE_HOST_ENDIAN == PRNE_ENDIAN_BIG
#define prne_htobe16(x) (x)
#define prne_be16toh(x) (x)
#define prne_htole16(x) prne_einv16(x)
#define prne_le16toh(x) prne_einv16(x)
#elif PRNE_HOST_ENDIAN == PRNE_ENDIAN_LITTLE
#define prne_htobe16(x) prne_einv16(x)
#define prne_be16toh(x) prne_einv16(x)
#define prne_htole16(x) (x)
#define prne_le16toh(x) (x)
#else
#endif
