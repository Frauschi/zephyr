/*
 * Copyright (c) 2026 wolfSSL Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* Keeps <wolfssl/internal.h> and its unprefixed names out of main.c */

#if defined(CONFIG_WOLFSSL)

#ifndef WOLFSSL_USER_SETTINGS
#include <user_settings.h>
#endif
#include <wolfssl/internal.h>

void test_wolfssl_send_fatal_alert(WOLFSSL *ssl)
{
	(void)SendAlert(ssl, alert_fatal, wolfssl_alert_protocol_version);
}

void test_wolfssl_mark_close_notify_sent(WOLFSSL *ssl)
{
	ssl->options.sentNotify = 1;
}

static byte held_records[512];
static int held_len;
static CallbackIOSend held_send;

static int test_wolfssl_hold_send(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
	(void)ssl;
	(void)ctx;

	if (sz > (int)sizeof(held_records) - held_len) {
		return WOLFSSL_CBIO_ERR_GENERAL;
	}

	XMEMCPY(held_records + held_len, buf, sz);
	held_len += sz;

	return sz;
}

void test_wolfssl_hold_records(WOLFSSL *ssl)
{
	held_send = ssl->CBIOSend;
	held_len = 0;
	wolfSSL_SSLSetIOSend(ssl, test_wolfssl_hold_send);
}

int test_wolfssl_send_held_records(WOLFSSL *ssl)
{
	wolfSSL_SSLSetIOSend(ssl, held_send);

	return held_send(ssl, (char *)held_records, held_len, ssl->IOCB_WriteCtx);
}

#ifdef WOLFSSL_DTLS
int test_wolfssl_dtls_timeout_max(WOLFSSL *ssl)
{
	return ssl->dtls_timeout_max;
}
#endif /* WOLFSSL_DTLS */

#endif /* CONFIG_WOLFSSL */
