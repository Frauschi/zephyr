/*
 * Copyright (c) 2026 wolfSSL Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

/** @file
 * @brief TLS_CERT_VERIFY_RESULT flags of the wolfSSL socket backend, with mbedTLS's values.
 */

#ifndef ZEPHYR_INCLUDE_NET_TLS_VERIFY_H_
#define ZEPHYR_INCLUDE_NET_TLS_VERIFY_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(CONFIG_WOLFSSL)

/* Values match mbedtls/x509.h, which may be included as well */
#ifndef MBEDTLS_X509_BADCERT_EXPIRED
#define MBEDTLS_X509_BADCERT_EXPIRED          0x01
#endif
#ifndef MBEDTLS_X509_BADCERT_REVOKED
#define MBEDTLS_X509_BADCERT_REVOKED          0x02
#endif
#ifndef MBEDTLS_X509_BADCERT_CN_MISMATCH
#define MBEDTLS_X509_BADCERT_CN_MISMATCH      0x04
#endif
#ifndef MBEDTLS_X509_BADCERT_NOT_TRUSTED
#define MBEDTLS_X509_BADCERT_NOT_TRUSTED      0x08
#endif
#ifndef MBEDTLS_X509_BADCRL_NOT_TRUSTED
#define MBEDTLS_X509_BADCRL_NOT_TRUSTED       0x10
#endif
#ifndef MBEDTLS_X509_BADCRL_EXPIRED
#define MBEDTLS_X509_BADCRL_EXPIRED           0x20
#endif
#ifndef MBEDTLS_X509_BADCERT_MISSING
#define MBEDTLS_X509_BADCERT_MISSING          0x40
#endif
#ifndef MBEDTLS_X509_BADCERT_SKIP_VERIFY
#define MBEDTLS_X509_BADCERT_SKIP_VERIFY      0x80
#endif
#ifndef MBEDTLS_X509_BADCERT_OTHER
#define MBEDTLS_X509_BADCERT_OTHER            0x0100
#endif
#ifndef MBEDTLS_X509_BADCERT_FUTURE
#define MBEDTLS_X509_BADCERT_FUTURE           0x0200
#endif
#ifndef MBEDTLS_X509_BADCRL_FUTURE
#define MBEDTLS_X509_BADCRL_FUTURE            0x0400
#endif
#ifndef MBEDTLS_X509_BADCERT_KEY_USAGE
#define MBEDTLS_X509_BADCERT_KEY_USAGE        0x0800
#endif
#ifndef MBEDTLS_X509_BADCERT_EXT_KEY_USAGE
#define MBEDTLS_X509_BADCERT_EXT_KEY_USAGE    0x1000
#endif
#ifndef MBEDTLS_X509_BADCERT_NS_CERT_TYPE
#define MBEDTLS_X509_BADCERT_NS_CERT_TYPE     0x2000
#endif
#ifndef MBEDTLS_X509_BADCERT_BAD_MD
#define MBEDTLS_X509_BADCERT_BAD_MD           0x4000
#endif
#ifndef MBEDTLS_X509_BADCERT_BAD_PK
#define MBEDTLS_X509_BADCERT_BAD_PK           0x8000
#endif
#ifndef MBEDTLS_X509_BADCERT_BAD_KEY
#define MBEDTLS_X509_BADCERT_BAD_KEY          0x010000
#endif
#ifndef MBEDTLS_X509_BADCRL_BAD_MD
#define MBEDTLS_X509_BADCRL_BAD_MD            0x020000
#endif
#ifndef MBEDTLS_X509_BADCRL_BAD_PK
#define MBEDTLS_X509_BADCRL_BAD_PK            0x040000
#endif
#ifndef MBEDTLS_X509_BADCRL_BAD_KEY
#define MBEDTLS_X509_BADCRL_BAD_KEY           0x080000
#endif

#ifndef MBEDTLS_ERR_X509_CERT_VERIFY_FAILED
/* Error code for verify failure (used in callback return values) */
#define MBEDTLS_ERR_X509_CERT_VERIFY_FAILED   -0x2700
#endif

/* Catches drift when mbedtls/x509.h is included too */
#if defined(__MBEDTLS_X509_H) || defined(MBEDTLS_X509_H)
#include <zephyr/sys/util.h>
BUILD_ASSERT(MBEDTLS_X509_BADCERT_EXPIRED       == 0x01,     "ABI drift vs mbedtls/x509.h");
BUILD_ASSERT(MBEDTLS_X509_BADCERT_REVOKED       == 0x02,     "ABI drift vs mbedtls/x509.h");
BUILD_ASSERT(MBEDTLS_X509_BADCERT_CN_MISMATCH   == 0x04,     "ABI drift vs mbedtls/x509.h");
BUILD_ASSERT(MBEDTLS_X509_BADCERT_NOT_TRUSTED   == 0x08,     "ABI drift vs mbedtls/x509.h");
BUILD_ASSERT(MBEDTLS_X509_BADCRL_NOT_TRUSTED    == 0x10,     "ABI drift vs mbedtls/x509.h");
BUILD_ASSERT(MBEDTLS_X509_BADCRL_EXPIRED        == 0x20,     "ABI drift vs mbedtls/x509.h");
BUILD_ASSERT(MBEDTLS_X509_BADCERT_MISSING       == 0x40,     "ABI drift vs mbedtls/x509.h");
BUILD_ASSERT(MBEDTLS_X509_BADCERT_SKIP_VERIFY   == 0x80,     "ABI drift vs mbedtls/x509.h");
BUILD_ASSERT(MBEDTLS_X509_BADCERT_OTHER         == 0x0100,   "ABI drift vs mbedtls/x509.h");
BUILD_ASSERT(MBEDTLS_X509_BADCERT_FUTURE        == 0x0200,   "ABI drift vs mbedtls/x509.h");
BUILD_ASSERT(MBEDTLS_X509_BADCRL_FUTURE         == 0x0400,   "ABI drift vs mbedtls/x509.h");
BUILD_ASSERT(MBEDTLS_X509_BADCERT_KEY_USAGE     == 0x0800,   "ABI drift vs mbedtls/x509.h");
BUILD_ASSERT(MBEDTLS_X509_BADCERT_EXT_KEY_USAGE == 0x1000,   "ABI drift vs mbedtls/x509.h");
BUILD_ASSERT(MBEDTLS_X509_BADCERT_NS_CERT_TYPE  == 0x2000,   "ABI drift vs mbedtls/x509.h");
BUILD_ASSERT(MBEDTLS_X509_BADCERT_BAD_MD        == 0x4000,   "ABI drift vs mbedtls/x509.h");
BUILD_ASSERT(MBEDTLS_X509_BADCERT_BAD_PK        == 0x8000,   "ABI drift vs mbedtls/x509.h");
BUILD_ASSERT(MBEDTLS_X509_BADCERT_BAD_KEY       == 0x010000, "ABI drift vs mbedtls/x509.h");
BUILD_ASSERT(MBEDTLS_X509_BADCRL_BAD_MD         == 0x020000, "ABI drift vs mbedtls/x509.h");
BUILD_ASSERT(MBEDTLS_X509_BADCRL_BAD_PK         == 0x040000, "ABI drift vs mbedtls/x509.h");
BUILD_ASSERT(MBEDTLS_X509_BADCRL_BAD_KEY        == 0x080000, "ABI drift vs mbedtls/x509.h");
#endif /* mbedtls/x509.h reachable */

#endif /* CONFIG_WOLFSSL */

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_INCLUDE_NET_TLS_VERIFY_H_ */
