/*
 * Copyright (c) 2026 wolfSSL Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/init.h>
#include <zephyr/device.h>
#include <zephyr/drivers/entropy.h>
#include <zephyr/kernel.h>
#include <string.h>

#ifndef WOLFSSL_USER_SETTINGS
#include <user_settings.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/random.h>

/*
 * entropy_dev is initialized at runtime to allow first time initialization
 * of the wolfSSL DRBG engine.
 */
static const struct device *entropy_dev;
static const unsigned char drbg_seed[] = CONFIG_WOLFSSL_CSPRNG_PERSONALIZATION;
static bool rng_initialised;
static K_MUTEX_DEFINE(rng_lock);

static WC_RNG rng_ctx;

static int wolfssl_rng_entropy_cb(OS_Seed *os, byte *seed, word32 sz)
{
	return entropy_get_entropy(entropy_dev, (void *)seed, (size_t)sz);
}

static int wolfssl_rng_initialize(void)
{
	int ret;

	entropy_dev = DEVICE_DT_GET(DT_CHOSEN(zephyr_entropy));

	if (!device_is_ready(entropy_dev)) {
		/* Recoverable error reported through the syscall return — not a
		 * fatal __ASSERT, so the failure semantics are the same in
		 * assert-enabled and assert-disabled builds.
		 */
		return -ENODEV;
	}

	ret = wc_SetSeed_Cb(wolfssl_rng_entropy_cb);
	if (ret != 0) {
		return -EIO;
	}

	/* sizeof() - 1 drops the string's NUL terminator so it is not fed into
	 * the DRBG as personalization data (and an empty string means none).
	 */
	ret = wc_InitRngNonce_ex(&rng_ctx, (byte *)drbg_seed, sizeof(drbg_seed) - 1,
				 NULL, 0);
	if (ret != 0) {
		(void)wc_FreeRng(&rng_ctx);
		return -EIO;
	}

	rng_initialised = true;
	return 0;
}

int z_impl_sys_csrand_get(void *dst, uint32_t outlen)
{
	int ret;

	k_mutex_lock(&rng_lock, K_FOREVER);

	if (unlikely(!rng_initialised)) {
		ret = wolfssl_rng_initialize();
		if (ret != 0) {
			/* Already a negative errno (-ENODEV / -EIO); preserve it
			 * rather than collapsing every init failure to -EIO.
			 */
			goto end;
		}
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
