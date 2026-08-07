/*
 * Copyright (c) 2026 wolfSSL Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/init.h>
#include <zephyr/kernel.h>
#include <zephyr/random/random.h>
#include <stdint.h>
#include <string.h>

#ifndef WOLFSSL_USER_SETTINGS
#include <user_settings.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/random.h>

static bool rng_initialised;
static K_MUTEX_DEFINE(rng_lock);

static WC_RNG rng_ctx;

static int wolfssl_rng_initialize(void)
{
	int ret;

	/* wc_InitRng_ex() seeds the DRBG through wc_GenerateSeed(), which on
	 * Zephyr draws from the hardware entropy driver (see
	 * wolfcrypt/src/random.c). A dead entropy source therefore surfaces here as
	 * a wolfCrypt failure.
	 *
	 * Supplying no nonce is deliberate: _InitRng() then requests MAX_SEED_SZ
	 * from the entropy source and derives the SP 800-90A nonce from it,
	 * instead of shortening the seed by SEED_SZ/2 to make room for a
	 * caller-provided one.
	 */
	ret = wc_InitRng_ex(&rng_ctx, NULL, 0);
	if (ret != 0) {
		(void)wc_FreeRng(&rng_ctx);
		return -EIO;
	}

	rng_initialised = true;
	return 0;
}

int z_impl_sys_csrand_get(void *dst, size_t outlen)
{
	int ret;

	k_mutex_lock(&rng_lock, K_FOREVER);

	if (unlikely(!rng_initialised)) {
		ret = wolfssl_rng_initialize();
		if (ret != 0) {
			/* Already a negative errno; preserve it. */
			goto end;
		}
	}

	/* wc_RNG_GenerateBlock() takes a word32. Truncating here would fill
	 * only part of the buffer and still report success.
	 */
	if (outlen > UINT32_MAX) {
		ret = -EINVAL;
		goto end;
	}

	ret = wc_RNG_GenerateBlock(&rng_ctx, (byte *)dst, (word32)outlen);
	if (ret != 0) {
		/* Do not leak wolfSSL error codes through the syscall
		 * contract (0 or negative errno).
		 */
		ret = -EIO;
	}

end:
	k_mutex_unlock(&rng_lock);

	return ret;
}
