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

	ret = wc_InitRng_ex(&rng_ctx, NULL, INVALID_DEVID);
	if (ret != 0) {
		(void)wc_FreeRng(&rng_ctx);
		return -EIO;
	}

	rng_initialised = true;
	return 0;
}

int z_impl_sys_csrand_get(void *dst, size_t outlen)
{
	uint8_t *out = dst;
	int ret = 0;

	k_mutex_lock(&rng_lock, K_FOREVER);

	if (unlikely(!rng_initialised)) {
		ret = wolfssl_rng_initialize();
		if (ret != 0) {
			goto end;
		}
	}

	/* The Hash-DRBG serves at most RNG_MAX_BLOCK_LEN bytes per request. */
	while (outlen > 0) {
		word32 len = (word32)MIN(outlen, (size_t)RNG_MAX_BLOCK_LEN);

		if (wc_RNG_GenerateBlock(&rng_ctx, out, len) != 0) {
			ret = -EIO;
			goto end;
		}

		out += len;
		outlen -= len;
	}

end:
	k_mutex_unlock(&rng_lock);

	return ret;
}
