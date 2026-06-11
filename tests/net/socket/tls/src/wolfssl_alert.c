/*
 * Copyright (c) 2026 wolfSSL Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* Isolated translation unit for the wolfSSL-internal SendAlert() API used
 * by the pollerr tests. <wolfssl/internal.h> exposes a large number of
 * unprefixed identifiers (e.g. the TLS_* ciphersuite enums) that easily
 * collide with test-local names, so it is confined to this small file:
 * main.c only sees the test_wolfssl_send_fatal_alert() wrapper. Taking
 * the SendAlert() prototype from internal.h (instead of a hand-written
 * declaration) makes a wolfSSL signature change a build error rather
 * than a silent mismatch.
 */

#if defined(CONFIG_WOLFSSL)

#ifndef WOLFSSL_USER_SETTINGS
#include <user_settings.h>
#endif
#include <wolfssl/internal.h>

void test_wolfssl_send_fatal_alert(WOLFSSL *ssl)
{
	(void)SendAlert(ssl, alert_fatal, wolfssl_alert_protocol_version);
}

#endif /* CONFIG_WOLFSSL */
