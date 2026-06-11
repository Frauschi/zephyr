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

#endif /* CONFIG_WOLFSSL */
