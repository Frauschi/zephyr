/*
 * Copyright (c) 2021 Daniel Hope (www.floorsense.nz)
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _CRYPTO_H_
#define _CRYPTO_H_

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

/*
 * BLAKE2S IMPLEMENTATION
 * Note: BLAKE2s is not available in PSA Crypto API, so we always use
 * the reference implementation.
 */
#include "refc/blake2s.h"

/* Endian / unaligned helper macros */
#define U8C(v)  (v##U)
#define U32C(v) (v##U)

#define U8V(v)  ((uint8_t)(v)&U8C(0xFF))
#define U32V(v) ((uint32_t)(v)&U32C(0xFFFFFFFF))

#define U8TO32_LITTLE(p)                                                                           \
	(((uint32_t)((p)[0])) | ((uint32_t)((p)[1]) << 8) | ((uint32_t)((p)[2]) << 16) |           \
	 ((uint32_t)((p)[3]) << 24))

#define U8TO64_LITTLE(p)                                                                           \
	(((uint64_t)((p)[0])) | ((uint64_t)((p)[1]) << 8) | ((uint64_t)((p)[2]) << 16) |           \
	 ((uint64_t)((p)[3]) << 24) | ((uint64_t)((p)[4]) << 32) | ((uint64_t)((p)[5]) << 40) |    \
	 ((uint64_t)((p)[6]) << 48) | ((uint64_t)((p)[7]) << 56))

#define U16TO8_BIG(p, v)                                                                           \
	do {                                                                                       \
		(p)[1] = U8V((v));                                                                 \
		(p)[0] = U8V((v) >> 8);                                                            \
	} while (0)

#define U32TO8_LITTLE(p, v)                                                                        \
	do {                                                                                       \
		(p)[0] = U8V((v));                                                                 \
		(p)[1] = U8V((v) >> 8);                                                            \
		(p)[2] = U8V((v) >> 16);                                                           \
		(p)[3] = U8V((v) >> 24);                                                           \
	} while (0)

#define U32TO8_BIG(p, v)                                                                           \
	do {                                                                                       \
		(p)[3] = U8V((v));                                                                 \
		(p)[2] = U8V((v) >> 8);                                                            \
		(p)[1] = U8V((v) >> 16);                                                           \
		(p)[0] = U8V((v) >> 24);                                                           \
	} while (0)

#define U64TO8_LITTLE(p, v)                                                                        \
	do {                                                                                       \
		(p)[0] = U8V((v));                                                                 \
		(p)[1] = U8V((v) >> 8);                                                            \
		(p)[2] = U8V((v) >> 16);                                                           \
		(p)[3] = U8V((v) >> 24);                                                           \
		(p)[4] = U8V((v) >> 32);                                                           \
		(p)[5] = U8V((v) >> 40);                                                           \
		(p)[6] = U8V((v) >> 48);                                                           \
		(p)[7] = U8V((v) >> 56);                                                           \
	} while (0)

#define U64TO8_BIG(p, v)                                                                           \
	do {                                                                                       \
		(p)[7] = U8V((v));                                                                 \
		(p)[6] = U8V((v) >> 8);                                                            \
		(p)[5] = U8V((v) >> 16);                                                           \
		(p)[4] = U8V((v) >> 24);                                                           \
		(p)[3] = U8V((v) >> 32);                                                           \
		(p)[2] = U8V((v) >> 40);                                                           \
		(p)[1] = U8V((v) >> 48);                                                           \
		(p)[0] = U8V((v) >> 56);                                                           \
	} while (0)

/*
 * Constant-time helpers, provided locally so WireGuard does not depend on
 * mbedTLS. crypto_equal MUST run in constant time - it compares message
 * authentication tags, where a data-dependent early exit would leak timing.
 * crypto_zero clears secrets through a volatile pointer so the stores are not
 * optimized away.
 */
static inline void crypto_zero(void *dest, size_t len)
{
	volatile uint8_t *p = (volatile uint8_t *)dest;

	while (len--) {
		*p++ = 0U;
	}
}

static inline bool crypto_equal(const void *a, const void *b, size_t n)
{
	const volatile uint8_t *pa = (const volatile uint8_t *)a;
	const volatile uint8_t *pb = (const volatile uint8_t *)b;
	uint8_t diff = 0U;

	while (n--) {
		diff |= (uint8_t)(*pa++ ^ *pb++);
	}

	return diff == 0U;
}

#endif /* _CRYPTO_H_ */
