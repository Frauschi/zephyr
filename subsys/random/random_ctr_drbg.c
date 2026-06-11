/*
 * Copyright (c) 2019, NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/init.h>
#include <zephyr/device.h>
#include <zephyr/drivers/entropy.h>
#include <zephyr/kernel.h>
#include <string.h>

#if defined(CONFIG_MBEDTLS)
#if !defined(CONFIG_MBEDTLS_CFG_FILE)
#include "mbedtls/config.h"
#else
#include CONFIG_MBEDTLS_CFG_FILE
#endif /* CONFIG_MBEDTLS_CFG_FILE */
#include <mbedtls/ctr_drbg.h>

#elif defined(CONFIG_WOLFSSL)
#ifndef WOLFSSL_USER_SETTINGS
#include <user_settings.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/random.h>

#endif /* CONFIG_MBEDTLS */

/*
 * entropy_dev is initialized at runtime to allow first time initialization
 * of the ctr_drbg engine.
 */
static const struct device *entropy_dev;
static const unsigned char drbg_seed[] = CONFIG_CS_CTR_DRBG_PERSONALIZATION;
static bool ctr_initialised;
static K_MUTEX_DEFINE(ctr_lock);

#if defined(CONFIG_MBEDTLS)
static mbedtls_ctr_drbg_context ctr_ctx;

static int ctr_drbg_entropy_func(void *ctx, unsigned char *buf, size_t len)
{
	return entropy_get_entropy(entropy_dev, (void *)buf, len);
}

#elif defined(CONFIG_WOLFSSL)

static WC_RNG ctr_ctx;

static int ctr_drbg_entropy_cb(OS_Seed* os, byte* seed, word32 sz)
{
	return entropy_get_entropy(entropy_dev, (void *)seed, (size_t)sz);
}

#endif /* CONFIG_MBEDTLS */

static int ctr_drbg_initialize(void)
{
	int ret;

	entropy_dev = DEVICE_DT_GET(DT_CHOSEN(zephyr_entropy));

	if (!device_is_ready(entropy_dev)) {
		__ASSERT(0, "Entropy device %s not ready", entropy_dev->name);
		return -ENODEV;
	}

#if defined(CONFIG_MBEDTLS)
	mbedtls_ctr_drbg_init(&ctr_ctx);

	ret = mbedtls_ctr_drbg_seed(&ctr_ctx,
				    ctr_drbg_entropy_func,
				    NULL,
				    drbg_seed,
				    sizeof(drbg_seed));

	if (ret != 0) {
		mbedtls_ctr_drbg_free(&ctr_ctx);
		return -EIO;
	}

#elif defined(CONFIG_WOLFSSL)
	ret = wc_SetSeed_Cb(ctr_drbg_entropy_cb);
	if (ret != 0) {
		return -EIO;
	}

	ret = wc_InitRngNonce_ex(&ctr_ctx, (byte *)drbg_seed, sizeof(drbg_seed), NULL, 0);
	if (ret != 0) {
		(void)wc_FreeRng(&ctr_ctx);
		return -EIO;
	}
#endif
	ctr_initialised = true;
	return 0;
}


int z_impl_sys_csrand_get(void *dst, uint32_t outlen)
{
	int ret;

	k_mutex_lock(&ctr_lock, K_FOREVER);

	if (unlikely(!ctr_initialised)) {
		ret = ctr_drbg_initialize();
		if (ret != 0) {
			ret = -EIO;
			goto end;
		}
	}

#if defined(CONFIG_MBEDTLS)
	ret = mbedtls_ctr_drbg_random(&ctr_ctx, (unsigned char *)dst, outlen);

#elif defined(CONFIG_WOLFSSL)

	ret = wc_RNG_GenerateBlock(&ctr_ctx, (byte *)dst, (word32)outlen);

#endif

end:
	k_mutex_unlock(&ctr_lock);

	return ret;
}
