/*
 * Copyright (c) 2026 Joakim Andersson
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/net/tls_credentials.h>
#include <zephyr/sys/timeutil.h>

#include "tls_internal.h"
#include "tls_credentials_info_raw.h"

#if defined(CONFIG_MBEDTLS_X509_CRT_PARSE_C)
#include <mbedtls/x509_crt.h>
#elif defined(CONFIG_WOLFSSL)
#include <string.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#endif

int credential_info_expiry_get(struct tls_credential *credential, time_t *expiry_out)
{
#if defined(CONFIG_MBEDTLS_X509_CRT_PARSE_C)
	mbedtls_x509_crt crt;
	int ret = 0, err;
	time_t expiry;
	struct tm tm_expiry;

	mbedtls_x509_crt_init(&crt);

	err = mbedtls_x509_crt_parse(&crt, credential->buf, credential->len);
	if (err != 0) {
		ret = -EINVAL;
		goto exit;
	}

	/* Convert mbedTLS time to time_t. */
	tm_expiry.tm_year = crt.valid_to.year - 1900;
	tm_expiry.tm_mon = crt.valid_to.mon - 1;
	tm_expiry.tm_mday = crt.valid_to.day;
	tm_expiry.tm_hour = crt.valid_to.hour;
	tm_expiry.tm_min = crt.valid_to.min;
	tm_expiry.tm_sec = crt.valid_to.sec;

	errno = 0;
	expiry = timeutil_timegm(&tm_expiry);
	/* Only if errno is set to non-zero is the conversion considered failed */
	if (expiry == -1 && errno != 0) {
		ret = -errno;
		goto exit;
	}

	*expiry_out = expiry;
exit:
	mbedtls_x509_crt_free(&crt);

	return ret;
#elif defined(CONFIG_WOLFSSL) && !defined(NO_ASN_TIME)
	const char *pem_header = "-----BEGIN CERTIFICATE-----";
	const byte *cert_buf = credential->buf;
	word32 cert_len = credential->len;
	struct DecodedCert *cert;
	struct tm tm_expiry;
	const byte *date;
	byte *der = NULL;
	time_t expiry;
	int date_len;
	byte format;
	int ret = -EINVAL;

	/* PEM must be NUL-terminated, as for mbedtls_x509_crt_parse() */
	if (cert_len > 0 && cert_buf[cert_len - 1] == '\0' &&
	    strstr((const char *)cert_buf, pem_header) != NULL) {
#if defined(WOLFSSL_PEM_TO_DER)
		int der_len;

		der = XMALLOC(cert_len, NULL, DYNAMIC_TYPE_TMP_BUFFER);
		if (der == NULL) {
			return -ENOMEM;
		}

		der_len = wc_CertPemToDer(cert_buf, (int)cert_len, der, (int)cert_len,
					  CERT_TYPE);
		if (der_len <= 0) {
			XFREE(der, NULL, DYNAMIC_TYPE_TMP_BUFFER);
			return -EINVAL;
		}

		cert_buf = der;
		cert_len = (word32)der_len;
#else
		return -ENOTSUP;
#endif /* WOLFSSL_PEM_TO_DER */
	}

	cert = XMALLOC(sizeof(*cert), NULL, DYNAMIC_TYPE_DCERT);
	if (cert == NULL) {
		XFREE(der, NULL, DYNAMIC_TYPE_TMP_BUFFER);
		return -ENOMEM;
	}

	wc_InitDecodedCert(cert, cert_buf, cert_len, NULL);

	if (wc_ParseCert(cert, CERT_TYPE, NO_VERIFY, NULL) != 0 ||
	    wc_GetDateInfo(cert->afterDate, cert->afterDateLen, &date, &format,
			   &date_len) != 0 ||
	    wc_GetDateAsCalendarTime(date, date_len, format, &tm_expiry) != 0) {
		goto exit;
	}

	errno = 0;
	expiry = timeutil_timegm(&tm_expiry);
	/* Only if errno is set to non-zero is the conversion considered failed */
	if (expiry == -1 && errno != 0) {
		ret = -errno;
		goto exit;
	}

	*expiry_out = expiry;
	ret = 0;
exit:
	wc_FreeDecodedCert(cert);
	XFREE(cert, NULL, DYNAMIC_TYPE_DCERT);
	XFREE(der, NULL, DYNAMIC_TYPE_TMP_BUFFER);

	return ret;
#else
	return -ENOTSUP;
#endif /* defined(CONFIG_MBEDTLS_X509_CRT_PARSE_C) */
}
