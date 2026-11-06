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

int test_wolfssl_max_psk_id_len(void)
{
	return MAX_PSK_ID_LEN;
}

#ifdef WOLFSSL_DTLS
int test_wolfssl_dtls_timeout_max(WOLFSSL *ssl)
{
	return ssl->dtls_timeout_max;
}
#endif /* WOLFSSL_DTLS */

#endif /* CONFIG_WOLFSSL */
