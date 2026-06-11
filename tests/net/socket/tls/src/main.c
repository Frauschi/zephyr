/*
 * Copyright (c) 2021 Nordic Semiconductor
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(net_test, CONFIG_NET_SOCKETS_LOG_LEVEL);

#include <zephyr/ztest_assert.h>
#include <zephyr/net/loopback.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/tls_credentials.h>
/* IANA TLS ciphersuite IDs used by this file's set_ciphersuites tests.
 * Names match RFC 5487. Don't introduce a public Zephyr-wide header just
 * for these two — both backends accept IANA IDs verbatim via the byte-
 * list cipher API. (The RFC 4279 SHA-1 CBC suites used previously are no
 * longer selectable in the Zephyr 4.4 mbedTLS ciphersuite Kconfig.)
 */
#define TEST_TLS_PSK_WITH_AES_128_GCM_SHA256  0x00A8
#define TEST_TLS_PSK_WITH_AES_256_CBC_SHA384  0x00AF

#if defined(CONFIG_WOLFSSL)
#ifndef WOLFSSL_USER_SETTINGS
#include <user_settings.h>
#endif
#include <wolfssl/ssl.h>
WOLFSSL *ztls_get_wolfssl_context(int fd);
/* Fatal-alert injection for the pollerr tests; implemented in
 * wolfssl_alert.c, which confines <wolfssl/internal.h> (and its huge
 * unprefixed identifier surface) to a single translation unit.
 */
void test_wolfssl_send_fatal_alert(WOLFSSL *ssl);
#endif

#if defined(CONFIG_MBEDTLS)
#include <mbedtls/ssl.h>
mbedtls_ssl_context *ztls_get_mbedtls_ssl_context(int fd);
#endif

#include "../../socket_helpers.h"

uint32_t ztls_get_session_count(void);

/* Server-side allow-list. Only TLS_PSK_WITH_AES_256_CBC_SHA384 is enabled
 * in prj.conf for the mbedTLS scenarios — the GCM suite entry is never
 * negotiated, it only exercises list handling and the mismatch case. Keep
 * it that way: enabling extra suites globally in prj.conf would change the
 * default cipher negotiated by the other tests in this file, which size
 * SO_RCVBUF based on the default suite's record overhead.
 */
static const int cipher_list_psk[] = {
	TEST_TLS_PSK_WITH_AES_256_CBC_SHA384,
	TEST_TLS_PSK_WITH_AES_128_GCM_SHA256
};

/* Test test_set_ciphersuites() assumes [0] of this list is the
 * cipher that will be negotiated */
static const int cipher_list_psk2[] = {
	TEST_TLS_PSK_WITH_AES_256_CBC_SHA384,
};

static const int cipher_list_psk3[] = {
	TEST_TLS_PSK_WITH_AES_128_GCM_SHA256,
};

#define TEST_STR_SMALL "test"

#define MY_IPV4_ADDR "127.0.0.1"
#define MY_IPV6_ADDR "::1"

#ifndef MY_DEFLT_HOSTNAME
#define MY_DEFLT_HOSTNAME "localhost"
#endif

#define ANY_PORT 0
#define SERVER_PORT 4242
#define CLIENT_1_PORT 4243
#define CLIENT_2_PORT 4244
#define CLIENT_3_PORT 4245
/* Dedicated port for test_session_cache_client_resume: the client-side
 * session cache is keyed by peer address, so the test needs a fixed
 * port — but it must not collide with SERVER_PORT used by the DTLS
 * multi-client tests, to stay independent of suite ordering and
 * TIME_WAIT teardown.
 */
#define RESUME_SERVER_PORT 4246

#define PSK_TAG 1

#define MAX_CONNS 5

#define TCP_TEARDOWN_TIMEOUT K_MSEC(CONFIG_NET_TCP_TIME_WAIT_DELAY)

#define TLS_TEST_WORK_QUEUE_STACK_SIZE 3072

K_THREAD_STACK_DEFINE(tls_test_work_queue_stack, TLS_TEST_WORK_QUEUE_STACK_SIZE);
static struct k_work_q tls_test_work_queue;

int c_sock = -1, c_sock_2 = -1, s_sock = -1, new_sock = -1;

static void test_work_reschedule(struct k_work_delayable *dwork,
				 k_timeout_t delay)
{
	k_work_reschedule_for_queue(&tls_test_work_queue, dwork, delay);
}

static void test_work_wait(struct k_work_delayable *dwork)
{
	struct k_work_sync sync;

	k_work_cancel_delayable_sync(dwork, &sync);
}

static const unsigned char psk[] = {
	0x01, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};
static const char psk_id[] = "test_identity";

static void test_config_psk(int s_sock, int c_sock)
{
	sec_tag_t sec_tag_list[] = {
		PSK_TAG
	};

	(void)tls_credential_delete(PSK_TAG, TLS_CREDENTIAL_PSK);
	(void)tls_credential_delete(PSK_TAG, TLS_CREDENTIAL_PSK_ID);

	zassert_equal(tls_credential_add(PSK_TAG, TLS_CREDENTIAL_PSK,
					 psk, sizeof(psk)),
		      0, "Failed to register PSK");
	zassert_equal(tls_credential_add(PSK_TAG, TLS_CREDENTIAL_PSK_ID,
					 psk_id, strlen(psk_id)),
		      0, "Failed to register PSK ID");

	if (s_sock >= 0) {
		zassert_equal(zsock_setsockopt(s_sock, ZSOCK_SOL_TLS, ZSOCK_TLS_SEC_TAG_LIST,
					 sec_tag_list, sizeof(sec_tag_list)),
			      0, "Failed to set PSK on server socket");
	}

	if (c_sock >= 0) {
		zassert_equal(zsock_setsockopt(c_sock, ZSOCK_SOL_TLS, ZSOCK_TLS_SEC_TAG_LIST,
					 sec_tag_list, sizeof(sec_tag_list)),
			      0, "Failed to set PSK on client socket");
	}
}

static void test_fcntl(int sock, int cmd, int val)
{
	zassert_equal(zsock_fcntl(sock, cmd, val), 0, "fcntl failed");
}

static void test_bind(int sock, struct net_sockaddr *addr, net_socklen_t addrlen)
{
	zassert_equal(zsock_bind(sock, addr, addrlen),
		      0,
		      "bind failed");
}

static void test_listen(int sock)
{
	zassert_equal(zsock_listen(sock, MAX_CONNS),
		      0,
		      "listen failed");
}

static void test_connect(int sock, struct net_sockaddr *addr, net_socklen_t addrlen)
{
	k_yield();

	zassert_equal(zsock_connect(sock, addr, addrlen), 0, "zsock_connect() failed");

	if (IS_ENABLED(CONFIG_NET_TC_THREAD_PREEMPTIVE)) {
		/* Let the connection proceed */
		k_yield();
	}
}

static void test_connect_err(int sock, struct net_sockaddr *addr, net_socklen_t addrlen)
{
	k_yield();

	zassert_equal(zsock_connect(sock, addr, addrlen),
		      -1,
		      "connect expected to fail but succeeded");

	if (IS_ENABLED(CONFIG_NET_TC_THREAD_PREEMPTIVE)) {
		/* Let the connection proceed */
		k_yield();
	}
}

static void test_send(int sock, const void *buf, size_t len, int flags)
{
	zassert_equal(zsock_send(sock, buf, len, flags),
		      len,
		      "send failed");
}

static void test_sendto(int sock, const void *buf, size_t len, int flags,
			struct net_sockaddr *addr, net_socklen_t addrlen)
{
	zassert_equal(zsock_sendto(sock, buf, len, flags, addr, addrlen),
		      len,
		      "sendto failed");
}

static void test_sendmsg(int sock, const struct net_msghdr *msg, int flags)
{
	size_t total_len = 0;

	for (int i = 0; i < msg->msg_iovlen; i++) {
		struct net_iovec *vec = msg->msg_iov + i;

		total_len += vec->iov_len;
	}

	zassert_equal(zsock_sendmsg(sock, msg, flags), total_len, "zsock_sendmsg() failed");
}

static void test_accept(int sock, int *new_sock, struct net_sockaddr *addr,
			net_socklen_t *addrlen)
{
	zassert_not_null(new_sock, "null newsock");

	*new_sock = zsock_accept(sock, addr, addrlen);
	zassert_true(*new_sock >= 0, "zsock_accept() failed");
}

static void test_accept_err(int sock, int *new_sock, struct net_sockaddr *addr,
			    net_socklen_t *addrlen)
{
	zassert_not_null(new_sock, "null newsock");

	*new_sock = zsock_accept(sock, addr, addrlen);
	zassert_true(*new_sock < 0, "accept expected to fail but succeeded");
}

static void test_shutdown(int sock, int how)
{
	zassert_equal(zsock_shutdown(sock, how),
		      0,
		      "shutdown failed");
}

static void test_close(int sock)
{
	zassert_equal(zsock_close(sock),
		      0,
		      "close failed");
}

static void test_sockets_close(void)
{
	if (c_sock >= 0) {
		test_close(c_sock);
		c_sock = -1;
	}

	if (c_sock_2 >= 0) {
		test_close(c_sock_2);
		c_sock_2 = -1;
	}

	if (s_sock >= 0) {
		test_close(s_sock);
		s_sock = -1;
	}

	if (new_sock >= 0) {
		test_close(new_sock);
		new_sock = -1;
	}
}

static void test_eof(int sock)
{
	char rx_buf[1];
	ssize_t recved;

	/* Test that EOF properly detected. */
	recved = zsock_recv(sock, rx_buf, sizeof(rx_buf), 0);
	zassert_equal(recved, 0, "");

	/* Calling again should be OK. */
	recved = zsock_recv(sock, rx_buf, sizeof(rx_buf), ZSOCK_MSG_DONTWAIT);
	zassert_equal(recved, 0, "");

	/* Calling when TCP connection is fully torn down should be still OK. */
	k_sleep(TCP_TEARDOWN_TIMEOUT);
	recved = zsock_recv(sock, rx_buf, sizeof(rx_buf), ZSOCK_MSG_DONTWAIT);
	zassert_equal(recved, 0, "");
}

ZTEST(net_socket_tls, test_so_type)
{
	struct net_sockaddr_in bind_addr4;
	struct net_sockaddr_in6 bind_addr6;
	int sock1, sock2, rv;
	int optval;
	net_socklen_t optlen = sizeof(optval);

	prepare_sock_tls_v4(MY_IPV4_ADDR, ANY_PORT, &sock1, &bind_addr4, NET_IPPROTO_TLS_1_2);
	prepare_sock_tls_v6(MY_IPV6_ADDR, ANY_PORT, &sock2, &bind_addr6, NET_IPPROTO_TLS_1_2);

	rv = zsock_getsockopt(sock1, ZSOCK_SOL_SOCKET, ZSOCK_SO_TYPE, &optval, &optlen);
	zassert_equal(rv, 0, "zsock_getsockopt() failed (%d)", errno);
	zassert_equal(optval, NET_SOCK_STREAM, "zsock_getsockopt() got invalid type");
	zassert_equal(optlen, sizeof(optval), "zsock_getsockopt() got invalid size");

	rv = zsock_getsockopt(sock2, ZSOCK_SOL_SOCKET, ZSOCK_SO_TYPE, &optval, &optlen);
	zassert_equal(rv, 0, "zsock_getsockopt() failed (%d)", errno);
	zassert_equal(optval, NET_SOCK_STREAM, "zsock_getsockopt() got invalid type");
	zassert_equal(optlen, sizeof(optval), "zsock_getsockopt() got invalid size");

	test_close(sock1);
	test_close(sock2);
}

ZTEST(net_socket_tls, test_so_protocol)
{
	struct net_sockaddr_in bind_addr4;
	struct net_sockaddr_in6 bind_addr6;
	int sock1, sock2, rv;
	int optval;
	net_socklen_t optlen = sizeof(optval);

	prepare_sock_tls_v4(MY_IPV4_ADDR, ANY_PORT, &sock1, &bind_addr4, NET_IPPROTO_TLS_1_2);
	prepare_sock_tls_v6(MY_IPV6_ADDR, ANY_PORT, &sock2, &bind_addr6, NET_IPPROTO_TLS_1_1);

	rv = zsock_getsockopt(sock1, ZSOCK_SOL_SOCKET, ZSOCK_SO_PROTOCOL, &optval, &optlen);
	zassert_equal(rv, 0, "zsock_getsockopt() failed (%d)", errno);
	zassert_equal(optval, NET_IPPROTO_TLS_1_2, "zsock_getsockopt() got invalid protocol");
	zassert_equal(optlen, sizeof(optval), "zsock_getsockopt() got invalid size");

	rv = zsock_getsockopt(sock2, ZSOCK_SOL_SOCKET, ZSOCK_SO_PROTOCOL, &optval, &optlen);
	zassert_equal(rv, 0, "zsock_getsockopt() failed (%d)", errno);
	zassert_equal(optval, NET_IPPROTO_TLS_1_1, "zsock_getsockopt() got invalid protocol");
	zassert_equal(optlen, sizeof(optval), "zsock_getsockopt() got invalid size");

	test_close(sock1);
	test_close(sock2);
}

struct test_msg_waitall_data {
	struct k_work_delayable tx_work;
	int sock;
	const uint8_t *data;
	size_t offset;
	int retries;
};

static void test_msg_waitall_tx_work_handler(struct k_work *work)
{
	struct k_work_delayable *dwork = k_work_delayable_from_work(work);
	struct test_msg_waitall_data *test_data =
		CONTAINER_OF(dwork, struct test_msg_waitall_data, tx_work);

	if (test_data->retries > 0) {
		test_send(test_data->sock, test_data->data + test_data->offset, 1, 0);
		test_data->offset++;
		test_data->retries--;
		test_work_reschedule(&test_data->tx_work, K_MSEC(10));
	}
}

struct connect_data {
	struct k_work_delayable work;
	int sock;
	struct net_sockaddr *addr;
};

static void client_connect_work_handler(struct k_work *work)
{
	struct k_work_delayable *dwork = k_work_delayable_from_work(work);
	struct connect_data *data =
		CONTAINER_OF(dwork, struct connect_data, work);

	test_connect(data->sock, data->addr, data->addr->sa_family == NET_AF_INET ?
		     sizeof(struct net_sockaddr_in) : sizeof(struct net_sockaddr_in6));
}

static void client_connect_work_handler_err(struct k_work *work)
{
	struct k_work_delayable *dwork = k_work_delayable_from_work(work);
	struct connect_data *data =
		CONTAINER_OF(dwork, struct connect_data, work);

	test_connect_err(data->sock, data->addr, data->addr->sa_family == NET_AF_INET ?
			 sizeof(struct net_sockaddr_in) : sizeof(struct net_sockaddr_in6));
}

static void dtls_client_connect_send_work_handler(struct k_work *work)
{
	struct k_work_delayable *dwork = k_work_delayable_from_work(work);
	struct connect_data *data =
		CONTAINER_OF(dwork, struct connect_data, work);
	uint8_t tx_buf = 0;

	test_connect(data->sock, data->addr, data->addr->sa_family == NET_AF_INET ?
		     sizeof(struct net_sockaddr_in) : sizeof(struct net_sockaddr_in6));
	test_send(data->sock, &tx_buf, sizeof(tx_buf), 0);
}

static void test_prepare_tls_connection(net_sa_family_t family)
{
	struct net_sockaddr c_saddr;
	struct net_sockaddr s_saddr;
	net_socklen_t exp_addrlen = family == NET_AF_INET6 ?
				sizeof(struct net_sockaddr_in6) :
				sizeof(struct net_sockaddr_in);
	struct net_sockaddr addr;
	net_socklen_t addrlen = sizeof(addr);
	struct connect_data test_data;

	if (family == NET_AF_INET6) {
		prepare_sock_tls_v6(MY_IPV6_ADDR, ANY_PORT, &c_sock,
				    (struct net_sockaddr_in6 *)&c_saddr,
				    NET_IPPROTO_TLS_1_2);
		prepare_sock_tls_v6(MY_IPV6_ADDR, ANY_PORT, &s_sock,
				    (struct net_sockaddr_in6 *)&s_saddr,
				    NET_IPPROTO_TLS_1_2);
	} else {
		prepare_sock_tls_v4(MY_IPV4_ADDR, ANY_PORT, &c_sock,
				    (struct net_sockaddr_in *)&c_saddr,
				    NET_IPPROTO_TLS_1_2);
		prepare_sock_tls_v4(MY_IPV4_ADDR, ANY_PORT, &s_sock,
				    (struct net_sockaddr_in *)&s_saddr,
				    NET_IPPROTO_TLS_1_2);
	}

	test_config_psk(s_sock, c_sock);

	test_bind(s_sock, &s_saddr, exp_addrlen);
	test_listen(s_sock);

	/* Helper work for the connect operation - need to handle client/server
	 * in parallel due to handshake.
	 */
	test_data.sock = c_sock;
	test_data.addr = &s_saddr;
	k_work_init_delayable(&test_data.work, client_connect_work_handler);
	test_work_reschedule(&test_data.work, K_NO_WAIT);

	test_accept(s_sock, &new_sock, &addr, &addrlen);
	zassert_equal(addrlen, exp_addrlen, "Wrong addrlen");

	test_work_wait(&test_data.work);
}

static void test_prepare_dtls_connection(net_sa_family_t family)
{
	struct net_sockaddr c_saddr;
	struct net_sockaddr s_saddr;
	net_socklen_t exp_addrlen = family == NET_AF_INET6 ?
				sizeof(struct net_sockaddr_in6) :
				sizeof(struct net_sockaddr_in);
	struct connect_data test_data;
	int role = ZSOCK_TLS_DTLS_ROLE_SERVER;
	struct zsock_pollfd fds[1];
	uint8_t rx_buf;
	int ret;


	if (family == NET_AF_INET6) {
		prepare_sock_dtls_v6(MY_IPV6_ADDR, ANY_PORT, &c_sock,
				     (struct net_sockaddr_in6 *)&c_saddr,
				     NET_IPPROTO_DTLS_1_2);
		prepare_sock_dtls_v6(MY_IPV6_ADDR, ANY_PORT, &s_sock,
				     (struct net_sockaddr_in6 *)&s_saddr,
				     NET_IPPROTO_DTLS_1_2);
	} else {
		prepare_sock_dtls_v4(MY_IPV4_ADDR, ANY_PORT, &c_sock,
				     (struct net_sockaddr_in *)&c_saddr,
				     NET_IPPROTO_DTLS_1_2);
		prepare_sock_dtls_v4(MY_IPV4_ADDR, ANY_PORT, &s_sock,
				     (struct net_sockaddr_in *)&s_saddr,
				     NET_IPPROTO_DTLS_1_2);
	}

	test_config_psk(s_sock, c_sock);

	zassert_equal(zsock_setsockopt(s_sock, ZSOCK_SOL_TLS, ZSOCK_TLS_DTLS_ROLE,
				 &role, sizeof(role)),
		      0, "setsockopt() failed");

	test_bind(s_sock, &s_saddr, exp_addrlen);

	test_data.sock = c_sock;
	test_data.addr = &s_saddr;
	k_work_init_delayable(&test_data.work, dtls_client_connect_send_work_handler);
	test_work_reschedule(&test_data.work, K_NO_WAIT);

	/* DTLS has no separate call like accept() to know when the handshake
	 * is complete, therefore send a dummy byte once handshake is done to
	 * unblock poll().
	 */
	fds[0].fd = s_sock;
	fds[0].events = ZSOCK_POLLIN;
	ret = zsock_poll(fds, 1, 1000);
	zassert_equal(ret, 1, "poll() did not report data ready");

	/* Flush the dummy byte. */
	ret = zsock_recv(s_sock, &rx_buf, sizeof(rx_buf), 0);
	zassert_equal(ret, sizeof(rx_buf), "zsock_recv() failed");

	test_work_wait(&test_data.work);
}

/* Function pointer type for function to be called after socket creation but
 * before any bind/listen/connect operations */
typedef void (*tls_pre_cb)(void);
/* Function pointer type for function to be used to perform client work
 * instead of client_connect_work_handler() */
typedef void (*client_work_func)(struct k_work *work);

static void test_prepare_tls_connection_ex(net_sa_family_t family, bool accept_err,
					   tls_pre_cb cb, client_work_func cw)
{
	struct net_sockaddr c_saddr;
	struct net_sockaddr s_saddr;
	net_socklen_t exp_addrlen = family == NET_AF_INET6 ?
				sizeof(struct net_sockaddr_in6) :
				sizeof(struct net_sockaddr_in);
	struct net_sockaddr addr;
	net_socklen_t addrlen = sizeof(addr);
	struct connect_data test_data;

	if (family == NET_AF_INET6) {
		prepare_sock_tls_v6(MY_IPV6_ADDR, ANY_PORT, &c_sock,
				    (struct net_sockaddr_in6 *)&c_saddr,
				    NET_IPPROTO_TLS_1_2);
		prepare_sock_tls_v6(MY_IPV6_ADDR, ANY_PORT, &s_sock,
				    (struct net_sockaddr_in6 *)&s_saddr,
				    NET_IPPROTO_TLS_1_2);
	} else {
		prepare_sock_tls_v4(MY_IPV4_ADDR, ANY_PORT, &c_sock,
				    (struct net_sockaddr_in *)&c_saddr,
				    NET_IPPROTO_TLS_1_2);
		prepare_sock_tls_v4(MY_IPV4_ADDR, ANY_PORT, &s_sock,
				    (struct net_sockaddr_in *)&s_saddr,
				    NET_IPPROTO_TLS_1_2);
	}

	if (NULL != cb) {
		cb();
	}

	test_config_psk(s_sock, c_sock);

	test_bind(s_sock, &s_saddr, exp_addrlen);
	test_listen(s_sock);

	/* Helper work for the connect operation - need to handle client/server
	 * in parallel due to handshake.
	 */
	test_data.sock = c_sock;
	test_data.addr = &s_saddr;
	if (cw != NULL) {
		k_work_init_delayable(&test_data.work, cw);
	} else {
		k_work_init_delayable(&test_data.work, client_connect_work_handler);
	}
	test_work_reschedule(&test_data.work, K_NO_WAIT);

	if (accept_err == true) {
		test_accept_err(s_sock, &new_sock, &addr, &addrlen);
	} else {
		test_accept(s_sock, &new_sock, &addr, &addrlen);
		zassert_equal(addrlen, exp_addrlen, "Wrong addrlen");
	}
	test_work_wait(&test_data.work);
}

ZTEST(net_socket_tls, test_v4_msg_waitall)
{
	struct test_msg_waitall_data test_data = {
		.data = TEST_STR_SMALL,
	};
	int ret;
	uint8_t rx_buf[sizeof(TEST_STR_SMALL) - 1] = { 0 };
	struct timeval timeo_optval = {
		.tv_sec = 0,
		.tv_usec = 500000,
	};

	test_prepare_tls_connection(NET_AF_INET);

	/* Regular MSG_WAITALL - make sure recv returns only after
	 * requested amount is received.
	 */
	test_data.offset = 0;
	test_data.retries = sizeof(rx_buf);
	test_data.sock = c_sock;
	k_work_init_delayable(&test_data.tx_work,
			      test_msg_waitall_tx_work_handler);
	test_work_reschedule(&test_data.tx_work, K_MSEC(10));

	ret = zsock_recv(new_sock, rx_buf, sizeof(rx_buf), ZSOCK_MSG_WAITALL);
	zassert_equal(ret, sizeof(rx_buf), "Invalid length received");
	zassert_mem_equal(rx_buf, TEST_STR_SMALL, sizeof(rx_buf),
			  "Invalid data received");
	test_work_wait(&test_data.tx_work);

	/* MSG_WAITALL + SO_RCVTIMEO - make sure recv returns the amount of data
	 * received so far
	 */
	ret = zsock_setsockopt(new_sock, ZSOCK_SOL_SOCKET, ZSOCK_SO_RCVTIMEO, &timeo_optval,
			       sizeof(timeo_optval));
	zassert_equal(ret, 0, "zsock_setsockopt() failed (%d)", errno);

	memset(rx_buf, 0, sizeof(rx_buf));
	test_data.offset = 0;
	test_data.retries = sizeof(rx_buf) - 1;
	test_data.sock = c_sock;
	k_work_init_delayable(&test_data.tx_work,
			      test_msg_waitall_tx_work_handler);
	test_work_reschedule(&test_data.tx_work, K_MSEC(10));

	ret = zsock_recv(new_sock, rx_buf, sizeof(rx_buf) - 1, ZSOCK_MSG_WAITALL);
	zassert_equal(ret, sizeof(rx_buf) - 1, "Invalid length received");
	zassert_mem_equal(rx_buf, TEST_STR_SMALL, sizeof(rx_buf) - 1,
			  "Invalid data received");
	test_work_wait(&test_data.tx_work);

	test_sockets_close();

	k_sleep(TCP_TEARDOWN_TIMEOUT);
}

ZTEST(net_socket_tls, test_v6_msg_waitall)
{
	struct test_msg_waitall_data test_data = {
		.data = TEST_STR_SMALL,
	};
	int ret;
	uint8_t rx_buf[sizeof(TEST_STR_SMALL) - 1] = { 0 };
	struct timeval timeo_optval = {
		.tv_sec = 0,
		.tv_usec = 500000,
	};

	test_prepare_tls_connection(NET_AF_INET6);

	/* Regular MSG_WAITALL - make sure recv returns only after
	 * requested amount is received.
	 */
	test_data.offset = 0;
	test_data.retries = sizeof(rx_buf);
	test_data.sock = c_sock;
	k_work_init_delayable(&test_data.tx_work,
			      test_msg_waitall_tx_work_handler);
	test_work_reschedule(&test_data.tx_work, K_MSEC(10));

	ret = zsock_recv(new_sock, rx_buf, sizeof(rx_buf), ZSOCK_MSG_WAITALL);
	zassert_equal(ret, sizeof(rx_buf), "Invalid length received");
	zassert_mem_equal(rx_buf, TEST_STR_SMALL, sizeof(rx_buf),
			  "Invalid data received");
	test_work_wait(&test_data.tx_work);

	/* MSG_WAITALL + SO_RCVTIMEO - make sure recv returns the amount of data
	 * received so far
	 */
	ret = zsock_setsockopt(new_sock, ZSOCK_SOL_SOCKET, ZSOCK_SO_RCVTIMEO, &timeo_optval,
			       sizeof(timeo_optval));
	zassert_equal(ret, 0, "zsock_setsockopt() failed (%d)", errno);

	memset(rx_buf, 0, sizeof(rx_buf));
	test_data.offset = 0;
	test_data.retries = sizeof(rx_buf) - 1;
	test_data.sock = c_sock;
	k_work_init_delayable(&test_data.tx_work,
			      test_msg_waitall_tx_work_handler);
	test_work_reschedule(&test_data.tx_work, K_MSEC(10));

	ret = zsock_recv(new_sock, rx_buf, sizeof(rx_buf) - 1, ZSOCK_MSG_WAITALL);
	zassert_equal(ret, sizeof(rx_buf) - 1, "Invalid length received");
	zassert_mem_equal(rx_buf, TEST_STR_SMALL, sizeof(rx_buf) - 1,
			  "Invalid data received");
	test_work_wait(&test_data.tx_work);

	test_sockets_close();

	k_sleep(TCP_TEARDOWN_TIMEOUT);
}

struct send_data {
	struct k_work_delayable tx_work;
	int sock;
	const uint8_t *data;
	size_t datalen;
};

static void send_work_handler(struct k_work *work)
{
	struct k_work_delayable *dwork = k_work_delayable_from_work(work);
	struct send_data *test_data =
		CONTAINER_OF(dwork, struct send_data, tx_work);

	test_send(test_data->sock, test_data->data, test_data->datalen, 0);
}

void test_msg_trunc(net_sa_family_t family)
{
#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
	int rv;
	uint8_t rx_buf[sizeof(TEST_STR_SMALL) - 1];
	struct send_data test_data = {
		.data = TEST_STR_SMALL,
		.datalen = sizeof(TEST_STR_SMALL) - 1
	};

	test_prepare_dtls_connection(family);

	/* MSG_TRUNC */

	test_data.sock = c_sock;
	k_work_init_delayable(&test_data.tx_work, send_work_handler);
	test_work_reschedule(&test_data.tx_work, K_MSEC(10));

	memset(rx_buf, 0, sizeof(rx_buf));
	rv = zsock_recv(s_sock, rx_buf, 2, ZSOCK_MSG_TRUNC);
	zassert_equal(rv, sizeof(TEST_STR_SMALL) - 1, "MSG_TRUNC flag failed");
	zassert_mem_equal(rx_buf, TEST_STR_SMALL, 2, "invalid rx data");
	zassert_equal(rx_buf[2], 0, "received more than requested");

	/* The remaining data should've been discarded */
	rv = zsock_recv(s_sock, rx_buf, sizeof(rx_buf), ZSOCK_MSG_DONTWAIT);
	zassert_equal(rv, -1, "consecutive recv should've failed");
	zassert_equal(errno, EAGAIN, "incorrect errno value");

	/* MSG_PEEK not supported by DTLS socket */

	test_sockets_close();

	test_work_wait(&test_data.tx_work);

	/* Small delay for the final alert exchange */
	k_msleep(10);
#else
	ztest_test_skip();
#endif
}

ZTEST(net_socket_tls, test_v4_msg_trunc)
{
	test_msg_trunc(NET_AF_INET);
}

ZTEST(net_socket_tls, test_v6_msg_trunc)
{
	test_msg_trunc(NET_AF_INET6);
}

struct test_sendmsg_data {
	struct k_work_delayable tx_work;
	int sock;
	const struct net_msghdr *msg;
};

static void test_sendmsg_tx_work_handler(struct k_work *work)
{
	struct k_work_delayable *dwork = k_work_delayable_from_work(work);
	struct test_sendmsg_data *test_data =
		CONTAINER_OF(dwork, struct test_sendmsg_data, tx_work);

	test_sendmsg(test_data->sock, test_data->msg, 0);
}

static void test_dtls_sendmsg_no_buf(net_sa_family_t family)
{
	int rv;
	uint8_t rx_buf[sizeof(TEST_STR_SMALL) - 1];
	struct net_iovec iov[3] = {
		{},
		{
			.iov_base = TEST_STR_SMALL,
			.iov_len = sizeof(TEST_STR_SMALL) - 1,
		},
		{},
	};
	struct net_msghdr msg = {};
	struct test_sendmsg_data test_data = {
		.msg = &msg,
	};

	test_prepare_dtls_connection(family);

	test_data.sock = c_sock;
	k_work_init_delayable(&test_data.tx_work, test_sendmsg_tx_work_handler);

	/* sendmsg() with single fragment */

	msg.msg_iov = &iov[1];
	msg.msg_iovlen = 1,

	test_work_reschedule(&test_data.tx_work, K_MSEC(10));

	memset(rx_buf, 0, sizeof(rx_buf));
	rv = zsock_recv(s_sock, rx_buf, sizeof(rx_buf), 0);
	zassert_equal(rv, sizeof(TEST_STR_SMALL) - 1, "zsock_recv() failed");
	zassert_mem_equal(rx_buf, TEST_STR_SMALL, sizeof(TEST_STR_SMALL) - 1, "invalid rx data");

	test_work_wait(&test_data.tx_work);

	/* sendmsg() with single non-empty fragment */

	msg.msg_iov = iov;
	msg.msg_iovlen = ARRAY_SIZE(iov);

	test_work_reschedule(&test_data.tx_work, K_MSEC(10));

	memset(rx_buf, 0, sizeof(rx_buf));
	rv = zsock_recv(s_sock, rx_buf, sizeof(rx_buf), 0);
	zassert_equal(rv, sizeof(TEST_STR_SMALL) - 1, "zsock_recv() failed");
	zassert_mem_equal(rx_buf, TEST_STR_SMALL, sizeof(TEST_STR_SMALL) - 1, "invalid rx data");

	test_work_wait(&test_data.tx_work);

	/* sendmsg() with multiple non-empty fragments */

	iov[0].iov_base = TEST_STR_SMALL;
	iov[0].iov_len = sizeof(TEST_STR_SMALL) - 1;

	rv = zsock_sendmsg(c_sock, &msg, 0);
	zassert_equal(rv, -1, "zsock_sendmsg() succeeded");
	zassert_equal(errno, EMSGSIZE, "incorrect errno value");

	test_sockets_close();

	/* Small delay for the final alert exchange */
	k_msleep(10);
}

ZTEST(net_socket_tls, test_v4_dtls_sendmsg_no_buf)
{
#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
	if (CONFIG_NET_SOCKETS_DTLS_SENDMSG_BUF_SIZE > 0) {
		ztest_test_skip();
	}
#else
	ztest_test_skip();
#endif

	test_dtls_sendmsg_no_buf(NET_AF_INET);
}

ZTEST(net_socket_tls, test_v6_dtls_sendmsg_no_buf)
{
#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
	if (CONFIG_NET_SOCKETS_DTLS_SENDMSG_BUF_SIZE > 0) {
		ztest_test_skip();
	}
#else
	ztest_test_skip();
#endif

	test_dtls_sendmsg_no_buf(NET_AF_INET6);
}

static void test_dtls_sendmsg(net_sa_family_t family)
{
	int rv;
	uint8_t buf[128 + 1] = { 0 };
	static const char expected_str[] = "testtest";
	struct net_iovec iov[3] = {
		{
			.iov_base = TEST_STR_SMALL,
			.iov_len = sizeof(TEST_STR_SMALL) - 1,
		},
		{
			.iov_base = TEST_STR_SMALL,
			.iov_len = sizeof(TEST_STR_SMALL) - 1,
		},
		{},
	};
	struct net_msghdr msg = {};
	struct test_sendmsg_data test_data = {
		.msg = &msg,
	};

	test_prepare_dtls_connection(family);

	test_data.sock = c_sock;
	k_work_init_delayable(&test_data.tx_work, test_sendmsg_tx_work_handler);

	/* sendmsg() with multiple fragments */

	msg.msg_iov = iov;
	msg.msg_iovlen = 2,

	test_work_reschedule(&test_data.tx_work, K_NO_WAIT);

	memset(buf, 0, sizeof(buf));
	rv = zsock_recv(s_sock, buf, sizeof(buf), 0);
	zassert_equal(rv, sizeof(expected_str) - 1, "zsock_recv() failed");
	zassert_mem_equal(buf, expected_str, sizeof(expected_str) - 1, "invalid rx data");

	test_work_wait(&test_data.tx_work);

	/* sendmsg() with multiple fragments and empty fragment inbetween */

	iov[1].iov_base = NULL;
	iov[1].iov_len = 0;
	iov[2].iov_base = TEST_STR_SMALL;
	iov[2].iov_len = sizeof(TEST_STR_SMALL) - 1;
	msg.msg_iov = iov;
	msg.msg_iovlen = 3;

	test_work_reschedule(&test_data.tx_work, K_NO_WAIT);

	memset(buf, 0, sizeof(buf));
	rv = zsock_recv(s_sock, buf, sizeof(buf), 0);
	zassert_equal(rv, sizeof(expected_str) - 1, "zsock_recv() failed");
	zassert_mem_equal(buf, expected_str, sizeof(expected_str) - 1, "invalid rx data");

	test_work_wait(&test_data.tx_work);

	test_sockets_close();

	/* Small delay for the final alert exchange */
	k_msleep(10);
}

static void test_dtls_sendmsg_overflow(net_sa_family_t family)
{
	int rv;
	uint8_t buf[128 + 1] = { 0 };
	uint8_t dummy_byte = 0;
	struct net_iovec iov[3] = {
		{
			.iov_base = TEST_STR_SMALL,
			.iov_len = sizeof(TEST_STR_SMALL) - 1,
		},
		{
			.iov_base = TEST_STR_SMALL,
			.iov_len = sizeof(TEST_STR_SMALL) - 1,
		},
		{},
	};
	struct net_msghdr msg = {};
	struct test_sendmsg_data test_data = {
		.msg = &msg,
	};

	test_prepare_dtls_connection(family);

	test_data.sock = c_sock;
	k_work_init_delayable(&test_data.tx_work, test_sendmsg_tx_work_handler);

	/* sendmsg() with single fragment should still work even if larger than
	 * intermediate buffer size
	 */

	memset(buf, 'a', sizeof(buf));
	iov[0].iov_base = buf;
	iov[0].iov_len = sizeof(buf);
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

	test_work_reschedule(&test_data.tx_work, K_NO_WAIT);

	/* We reuse the buffer, so wait to make sure the message is sent. */
	k_msleep(10);

	memset(buf, 0, sizeof(buf));
	rv = zsock_recv(s_sock, buf, sizeof(buf), 0);
	zassert_equal(rv, sizeof(buf), "zsock_recv() failed");
	for (int i = 0; i < sizeof(buf); i++) {
		zassert_equal(buf[i], 'a', "invalid rx data");
	}

	test_work_wait(&test_data.tx_work);

	/* sendmsg() exceeding intermediate buf size */

	iov[0].iov_base = buf;
	iov[0].iov_len = sizeof(buf);
	iov[1].iov_base = &dummy_byte;
	iov[1].iov_len = sizeof(dummy_byte);
	msg.msg_iov = iov;
	msg.msg_iovlen = 2;

	rv = zsock_sendmsg(c_sock, &msg, 0);
	zassert_equal(rv, -1, "zsock_sendmsg() succeeded");
	zassert_equal(errno, EMSGSIZE, "incorrect errno value");

	test_sockets_close();

	/* Small delay for the final alert exchange */
	k_msleep(10);
}

ZTEST(net_socket_tls, test_v4_dtls_sendmsg)
{
#if !defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
	ztest_test_skip();
#elif CONFIG_NET_SOCKETS_DTLS_SENDMSG_BUF_SIZE <= 0
	ztest_test_skip();
#endif

	test_dtls_sendmsg(NET_AF_INET);
}

ZTEST(net_socket_tls, test_v6_dtls_sendmsg)
{
#if !defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
	ztest_test_skip();
#elif CONFIG_NET_SOCKETS_DTLS_SENDMSG_BUF_SIZE <= 0
	ztest_test_skip();
#endif

	test_dtls_sendmsg(NET_AF_INET6);
}

ZTEST(net_socket_tls, test_v4_dtls_sendmsg_overflow)
{
	if ((CONFIG_NET_SOCKETS_DTLS_SENDMSG_BUF_SIZE == 0) ||
	     IS_ENABLED(CONFIG_MBEDTLS_SSL_DTLS_CONNECTION_ID)) {
		ztest_test_skip();
	}

	test_dtls_sendmsg_overflow(NET_AF_INET);
}

ZTEST(net_socket_tls, test_v6_dtls_sendmsg_overflow)
{
	if ((CONFIG_NET_SOCKETS_DTLS_SENDMSG_BUF_SIZE == 0) ||
	     IS_ENABLED(CONFIG_MBEDTLS_SSL_DTLS_CONNECTION_ID)) {
		ztest_test_skip();
	}

	test_dtls_sendmsg_overflow(NET_AF_INET6);
}

struct close_data {
	struct k_work_delayable work;
	int *fd;
};

static void close_work(struct k_work *work)
{
	struct k_work_delayable *dwork = k_work_delayable_from_work(work);
	struct close_data *data = CONTAINER_OF(dwork, struct close_data, work);

	zsock_close(*data->fd);
	*data->fd = -1;
}

ZTEST(net_socket_tls, test_close_while_accept)
{
	struct net_sockaddr_in6 s_saddr;
	struct net_sockaddr addr;
	net_socklen_t addrlen = sizeof(addr);
	struct close_data close_work_data;

	prepare_sock_tls_v6(MY_IPV6_ADDR, ANY_PORT, &s_sock, &s_saddr, NET_IPPROTO_TLS_1_2);

	test_config_psk(s_sock, -1);

	test_bind(s_sock, (struct net_sockaddr *)&s_saddr, sizeof(s_saddr));
	test_listen(s_sock);

	/* Schedule close() from workqueue */
	k_work_init_delayable(&close_work_data.work, close_work);
	close_work_data.fd = &s_sock;
	test_work_reschedule(&close_work_data.work, K_MSEC(10));

	/* Start blocking accept(), which should be unblocked by close() from
	 * another thread and return an error.
	 */
	new_sock = zsock_accept(s_sock, &addr, &addrlen);
	zassert_equal(new_sock, -1, "zsock_accept() did not return error");
	zassert_equal(errno, EINTR, "Unexpected errno value: %d", errno);

	test_work_wait(&close_work_data.work);
	k_sleep(TCP_TEARDOWN_TIMEOUT);
}

ZTEST(net_socket_tls, test_close_while_recv)
{
	int ret;
	struct close_data close_work_data;
	uint8_t rx_buf;

	test_prepare_tls_connection(NET_AF_INET6);

	/* Schedule close() from workqueue */
	k_work_init_delayable(&close_work_data.work, close_work);
	close_work_data.fd = &new_sock;
	test_work_reschedule(&close_work_data.work, K_MSEC(10));

	ret = zsock_recv(new_sock, &rx_buf, sizeof(rx_buf), 0);
	zassert_equal(ret, -1, "zsock_recv() did not return error");
	zassert_equal(errno, EINTR, "Unexpected errno value: %d", errno);

	test_work_wait(&close_work_data.work);

	test_sockets_close();

	k_sleep(TCP_TEARDOWN_TIMEOUT);
}

ZTEST(net_socket_tls, test_connect_timeout)
{
	struct net_sockaddr_in6 c_saddr;
	struct net_sockaddr_in6 s_saddr;
	int ret;

	prepare_sock_tls_v6(MY_IPV6_ADDR, ANY_PORT, &c_sock, &c_saddr,
			    NET_IPPROTO_TLS_1_2);
	test_config_psk(-1, c_sock);

	s_saddr.sin6_family = NET_AF_INET6;
	s_saddr.sin6_port = net_htons(SERVER_PORT);
	ret = zsock_inet_pton(NET_AF_INET6, MY_IPV6_ADDR, &s_saddr.sin6_addr);
	zassert_equal(ret, 1, "zsock_inet_pton() failed");

	loopback_set_packet_drop_ratio(1.0f);

	zassert_equal(zsock_connect(c_sock, (struct net_sockaddr *)&s_saddr, sizeof(s_saddr)), -1,
		      "zsock_connect() succeed");
	zassert_equal(errno, ETIMEDOUT, "zsock_connect() should be timed out, got %d", errno);

	test_sockets_close();

	loopback_set_packet_drop_ratio(0.0f);
	k_sleep(TCP_TEARDOWN_TIMEOUT);
}

ZTEST(net_socket_tls, test_connect_closed_port)
{
	struct net_sockaddr_in6 c_saddr;
	struct net_sockaddr_in6 s_saddr;
	int ret;

	prepare_sock_tls_v6(MY_IPV6_ADDR, ANY_PORT, &c_sock, &c_saddr,
			    NET_IPPROTO_TLS_1_2);
	test_config_psk(-1, c_sock);

	s_saddr.sin6_family = NET_AF_INET6;
	s_saddr.sin6_port = net_htons(SERVER_PORT);
	ret = zsock_inet_pton(NET_AF_INET6, MY_IPV6_ADDR, &s_saddr.sin6_addr);
	zassert_equal(ret, 1, "zsock_inet_pton() failed");

	zassert_equal(zsock_connect(c_sock, (struct net_sockaddr *)&s_saddr, sizeof(s_saddr)), -1,
		      "zsock_connect() succeed");
	zassert_equal(errno, ECONNREFUSED, "zsock_connect() should fail, got %d", errno);

	test_sockets_close();
	k_sleep(TCP_TEARDOWN_TIMEOUT);
}

struct fake_tcp_server_data {
	struct k_work_delayable work;
	int sock;
	bool reply;
};

static void fake_tcp_server_work(struct k_work *work)
{
	struct k_work_delayable *dwork = k_work_delayable_from_work(work);
	struct fake_tcp_server_data *data =
		CONTAINER_OF(dwork, struct fake_tcp_server_data, work);

	test_accept(data->sock, &new_sock, NULL, 0);

	if (!data->reply) {
		/* Add small delay to avoid race between incoming data and
		 * sending FIN.
		 */
		k_msleep(10);
		goto out;
	}

	while (true) {
		int ret;
		char rx_buf[32];

		ret = zsock_recv(new_sock, rx_buf, sizeof(rx_buf), 0);
		if (ret <= 0) {
			break;
		}

		(void)zsock_send(new_sock, TEST_STR_SMALL, sizeof(TEST_STR_SMALL), 0);
	}

out:
	test_close(new_sock);
	new_sock = -1;
}

static void test_prepare_fake_tcp_server(struct fake_tcp_server_data *s_data,
					 net_sa_family_t family, int *s_sock,
					 struct net_sockaddr *s_saddr, bool reply)
{
	net_socklen_t exp_addrlen = family == NET_AF_INET6 ?
				sizeof(struct net_sockaddr_in6) :
				sizeof(struct net_sockaddr_in);

	if (family == NET_AF_INET6) {
		prepare_sock_tcp_v6(MY_IPV6_ADDR, SERVER_PORT, s_sock,
				    (struct net_sockaddr_in6 *)s_saddr);
	} else {
		prepare_sock_tcp_v4(MY_IPV4_ADDR, SERVER_PORT, s_sock,
				    (struct net_sockaddr_in *)s_saddr);
	}

	test_bind(*s_sock, s_saddr, exp_addrlen);
	test_listen(*s_sock);

	s_data->sock = *s_sock;
	s_data->reply = reply;
	k_work_init_delayable(&s_data->work, fake_tcp_server_work);
	test_work_reschedule(&s_data->work, K_NO_WAIT);
}

ZTEST(net_socket_tls, test_connect_invalid_handshake_data)
{
	struct fake_tcp_server_data server_data;
	struct net_sockaddr_in6 c_saddr;
	struct net_sockaddr_in6 s_saddr;

	prepare_sock_tls_v6(MY_IPV6_ADDR, ANY_PORT, &c_sock, &c_saddr,
			    NET_IPPROTO_TLS_1_2);
	test_config_psk(-1, c_sock);
	test_prepare_fake_tcp_server(&server_data, NET_AF_INET6, &s_sock,
				     (struct net_sockaddr *)&s_saddr, true);

	zassert_equal(zsock_connect(c_sock, (struct net_sockaddr *)&s_saddr, sizeof(s_saddr)), -1,
		      "zsock_connect() succeed");
	zassert_equal(errno, ECONNABORTED, "zsock_connect() should fail, got %d", errno);

	test_close(c_sock);
	c_sock = -1;

	test_work_wait(&server_data.work);
	test_sockets_close();

	k_sleep(TCP_TEARDOWN_TIMEOUT);
}

ZTEST(net_socket_tls, test_connect_no_handshake_data)
{
	struct fake_tcp_server_data server_data;
	struct net_sockaddr_in6 c_saddr;
	struct net_sockaddr s_saddr;

	prepare_sock_tls_v6(MY_IPV6_ADDR, ANY_PORT, &c_sock, &c_saddr,
			    NET_IPPROTO_TLS_1_2);
	test_config_psk(-1, c_sock);
	test_prepare_fake_tcp_server(&server_data, NET_AF_INET6, &s_sock,
				     (struct net_sockaddr *)&s_saddr, false);

	zassert_equal(zsock_connect(c_sock, (struct net_sockaddr *)&s_saddr, sizeof(s_saddr)), -1,
		      "zsock_connect() succeed");
	zassert_equal(errno, ECONNABORTED, "zsock_connect() should fail, got %d", errno);

	test_work_wait(&server_data.work);
	test_sockets_close();

	k_sleep(TCP_TEARDOWN_TIMEOUT);
}

ZTEST(net_socket_tls, test_accept_non_block)
{
	uint32_t timestamp;
	struct net_sockaddr_in6 s_saddr;

	prepare_sock_tls_v6(MY_IPV6_ADDR, SERVER_PORT, &s_sock, &s_saddr,
			    NET_IPPROTO_TLS_1_2);

	test_config_psk(s_sock, -1);
	test_fcntl(s_sock, ZVFS_F_SETFL, ZVFS_O_NONBLOCK);
	test_bind(s_sock, (struct net_sockaddr *)&s_saddr, sizeof(s_saddr));
	test_listen(s_sock);

	timestamp = k_uptime_get_32();
	new_sock = zsock_accept(s_sock, NULL, NULL);
	zassert_true(k_uptime_get_32() - timestamp <= 100, "");
	zassert_equal(new_sock, -1, "zsock_accept() did not return error");
	zassert_equal(errno, EAGAIN, "Unexpected errno value: %d", errno);

	test_sockets_close();
	k_sleep(TCP_TEARDOWN_TIMEOUT);
}

ZTEST(net_socket_tls, test_accept_invalid_handshake_data)
{
	struct net_sockaddr_in6 s_saddr;
	struct net_sockaddr_in6 c_saddr;

	prepare_sock_tls_v6(MY_IPV6_ADDR, ANY_PORT, &s_sock, &s_saddr,
			    NET_IPPROTO_TLS_1_2);
	prepare_sock_tcp_v6(MY_IPV6_ADDR, ANY_PORT, &c_sock, &c_saddr);

	test_config_psk(s_sock, -1);
	test_bind(s_sock, (struct net_sockaddr *)&s_saddr, sizeof(s_saddr));
	test_listen(s_sock);

	/* Connect at TCP level and send some unexpected data. */
	test_connect(c_sock, (struct net_sockaddr *)&s_saddr, sizeof(s_saddr));
	test_send(c_sock, TEST_STR_SMALL, sizeof(TEST_STR_SMALL), 0);

	new_sock = zsock_accept(s_sock, NULL, NULL);
	zassert_equal(new_sock, -1, "zsock_accept() did not return error");
	zassert_equal(errno, ECONNABORTED, "Unexpected errno value: %d", errno);

	test_sockets_close();
	k_sleep(TCP_TEARDOWN_TIMEOUT);
}

ZTEST(net_socket_tls, test_recv_non_block)
{
	int ret;
	uint8_t rx_buf[sizeof(TEST_STR_SMALL) - 1] = { 0 };

	test_prepare_tls_connection(NET_AF_INET6);

	/* Verify ZSOCK_MSG_DONTWAIT flag first */
	ret = zsock_recv(new_sock, rx_buf, sizeof(rx_buf), ZSOCK_MSG_DONTWAIT);
	zassert_equal(ret, -1, "zsock_recv() should've failed");
	zassert_equal(errno, EAGAIN, "Unexpected errno value: %d", errno);

	/* Verify zsock_fcntl() and ZVFS_O_NONBLOCK */
	test_fcntl(new_sock, ZVFS_F_SETFL, ZVFS_O_NONBLOCK);
	ret = zsock_recv(new_sock, rx_buf, sizeof(rx_buf), 0);
	zassert_equal(ret, -1, "zsock_recv() should've failed");
	zassert_equal(errno, EAGAIN, "Unexpected errno value: %d", errno);

	ret = zsock_send(c_sock, TEST_STR_SMALL, strlen(TEST_STR_SMALL), 0);
	zassert_equal(ret, strlen(TEST_STR_SMALL), "zsock_send() failed");

	/* Let the data got through. */
	k_sleep(K_MSEC(10));

	/* Should get data now */
	ret = zsock_recv(new_sock, rx_buf, sizeof(rx_buf), 0);
	zassert_equal(ret, strlen(TEST_STR_SMALL), "zsock_recv() failed");
	zassert_mem_equal(rx_buf, TEST_STR_SMALL, ret, "Invalid data received");

	/* And EAGAIN on consecutive read */
	ret = zsock_recv(new_sock, rx_buf, sizeof(rx_buf), 0);
	zassert_equal(ret, -1, "zsock_recv() should've failed");
	zassert_equal(errno, EAGAIN, "Unexpected errno value: %d", errno);

	test_sockets_close();

	k_sleep(TCP_TEARDOWN_TIMEOUT);
}

ZTEST(net_socket_tls, test_recv_block)
{
	int ret;
	uint8_t rx_buf[sizeof(TEST_STR_SMALL) - 1] = { 0 };
	struct send_data test_data = {
		.data = TEST_STR_SMALL,
		.datalen = sizeof(TEST_STR_SMALL) - 1
	};

	test_prepare_tls_connection(NET_AF_INET6);

	test_data.sock = c_sock;
	k_work_init_delayable(&test_data.tx_work, send_work_handler);
	test_work_reschedule(&test_data.tx_work, K_MSEC(10));

	/* recv() shall block until send work sends the data. */
	ret = zsock_recv(new_sock, rx_buf, sizeof(rx_buf), 0);
	zassert_equal(ret, sizeof(TEST_STR_SMALL) - 1, "zsock_recv() failed");
	zassert_mem_equal(rx_buf, TEST_STR_SMALL, ret, "Invalid data received");

	test_sockets_close();

	k_sleep(TCP_TEARDOWN_TIMEOUT);
}

ZTEST(net_socket_tls, test_recv_eof_on_close)
{
	test_prepare_tls_connection(NET_AF_INET6);

	test_close(c_sock);
	c_sock = -1;

	/* Verify recv() reports EOF */
	test_eof(new_sock);

	test_sockets_close();

	k_sleep(TCP_TEARDOWN_TIMEOUT);
}

/* Per-record framing overhead the test uses to right-size SO_RCVBUF for
 * exactly one TLS application record carrying TEST_STR_SMALL. Both numbers
 * are observed values for these suites' default ciphersuite (TLS 1.2 AES
 * GCM), measured by running the suite with an oversized buffer and printing
 * the inbound record length. Different values per backend reflect different
 * implementation choices for the record-layer framing (header layout, IV
 * placement, padding) — they are not part of any wire-format ABI. If a
 * test starts failing here after a backend or ciphersuite change, re-measure
 * with an oversized buffer and update.
 */
#if defined(CONFIG_WOLFSSL)
#define TLS_RECORD_OVERHEAD 29
#else
#define TLS_RECORD_OVERHEAD 81
#endif

ZTEST(net_socket_tls, test_send_non_block)
{
	int ret;
	uint8_t rx_buf[sizeof(TEST_STR_SMALL) - 1] = { 0 };
	int buf_optval = TLS_RECORD_OVERHEAD + sizeof(TEST_STR_SMALL) - 1;

	test_prepare_tls_connection(NET_AF_INET6);

	/* Simulate window full scenario with SO_RCVBUF option. */
	ret = zsock_setsockopt(new_sock, ZSOCK_SOL_SOCKET, ZSOCK_SO_RCVBUF, &buf_optval,
			       sizeof(buf_optval));
	zassert_equal(ret, 0, "zsock_setsockopt() failed (%d)", errno);

	/* Fill out the window */
	ret = zsock_send(c_sock, TEST_STR_SMALL, strlen(TEST_STR_SMALL), 0);
	zassert_equal(ret, strlen(TEST_STR_SMALL), "zsock_send() failed");

	/* Wait for ACK (empty window, min. 100 ms due to silly window
	 * protection).
	 */
	k_sleep(K_MSEC(150));

	/* Verify ZSOCK_MSG_DONTWAIT flag first */
	ret = zsock_send(c_sock, TEST_STR_SMALL, strlen(TEST_STR_SMALL),
			 ZSOCK_MSG_DONTWAIT);
	zassert_equal(ret, -1, "zsock_send() should've failed");
	zassert_equal(errno, EAGAIN, "Unexpected errno value: %d", errno);

	/* Verify zsock_fcntl() and ZVFS_O_NONBLOCK */
	test_fcntl(c_sock, ZVFS_F_SETFL, ZVFS_O_NONBLOCK);
	ret = zsock_send(c_sock, TEST_STR_SMALL, strlen(TEST_STR_SMALL), 0);
	zassert_equal(ret, -1, "zsock_send() should've failed");
	zassert_equal(errno, EAGAIN, "Unexpected errno value: %d", errno);

	ret = zsock_recv(new_sock, rx_buf, sizeof(rx_buf), 0);
	zassert_equal(ret, strlen(TEST_STR_SMALL), "zsock_recv() failed");
	zassert_mem_equal(rx_buf, TEST_STR_SMALL, ret, "Invalid data received");

	/* Wait for the window to update. */
	k_sleep(K_MSEC(10));

	/* Should succeed now. */
	ret = zsock_send(c_sock, TEST_STR_SMALL, strlen(TEST_STR_SMALL), 0);
	zassert_equal(ret, strlen(TEST_STR_SMALL), "zsock_send() failed");

	/* Flush the data */
	ret = zsock_recv(new_sock, rx_buf, sizeof(rx_buf), 0);
	zassert_equal(ret, strlen(TEST_STR_SMALL), "zsock_recv() failed");
	zassert_mem_equal(rx_buf, TEST_STR_SMALL, ret, "Invalid data received");

	/* And make sure there's no more data left. */
	ret = zsock_recv(new_sock, rx_buf, sizeof(rx_buf), ZSOCK_MSG_DONTWAIT);
	zassert_equal(ret, -1, "zsock_recv() should've failed");
	zassert_equal(errno, EAGAIN, "Unexpected errno value: %d", errno);

	test_sockets_close();

	k_sleep(TCP_TEARDOWN_TIMEOUT);
}

struct recv_data {
	struct k_work_delayable work;
	int sock;
	const uint8_t *data;
	size_t datalen;
};

static void recv_work_handler(struct k_work *work)
{
	struct k_work_delayable *dwork = k_work_delayable_from_work(work);
	struct recv_data *test_data = CONTAINER_OF(dwork, struct recv_data, work);
	char rx_buf[30] = { 0 };
	size_t off = 0;
	int ret;

	while (off < test_data->datalen) {
		size_t recvlen = MIN(sizeof(rx_buf), test_data->datalen - off);

		ret = zsock_recv(test_data->sock, rx_buf, recvlen, 0);
		zassert_true(ret > 0, "zsock_recv() error");
		zassert_mem_equal(rx_buf, test_data->data + off, ret,
				  "unexpected data");

		off += ret;
		zassert_true(off <= test_data->datalen,
			     "received more than expected");
	}
}

ZTEST(net_socket_tls, test_send_block)
{
	int ret;
	int buf_optval = TLS_RECORD_OVERHEAD + sizeof(TEST_STR_SMALL) - 1;
	uint8_t rx_buf[sizeof(TEST_STR_SMALL) - 1] = { 0 };
	struct recv_data test_data = {
		.data = TEST_STR_SMALL,
		.datalen = sizeof(TEST_STR_SMALL) - 1
	};

	test_prepare_tls_connection(NET_AF_INET6);

	/* Simulate window full scenario with SO_RCVBUF option. */
	ret = zsock_setsockopt(new_sock, ZSOCK_SOL_SOCKET, ZSOCK_SO_RCVBUF, &buf_optval,
			       sizeof(buf_optval));
	zassert_equal(ret, 0, "zsock_setsockopt() failed (%d)", errno);

	/* Fill out the window */
	ret = zsock_send(c_sock, TEST_STR_SMALL, strlen(TEST_STR_SMALL), 0);
	zassert_equal(ret, strlen(TEST_STR_SMALL), "zsock_send() failed");

	/* Wait for ACK (empty window, min. 100 ms due to silly window
	 * protection).
	 */
	k_sleep(K_MSEC(150));

	test_data.sock = new_sock;
	k_work_init_delayable(&test_data.work, recv_work_handler);
	test_work_reschedule(&test_data.work, K_MSEC(10));

	/* Should block and succeed. */
	ret = zsock_send(c_sock, TEST_STR_SMALL, strlen(TEST_STR_SMALL), 0);
	zassert_equal(ret, strlen(TEST_STR_SMALL), "zsock_send() failed");

	/* Flush the data */
	ret = zsock_recv(new_sock, rx_buf, sizeof(rx_buf), 0);
	zassert_equal(ret, strlen(TEST_STR_SMALL), "zsock_recv() failed");
	zassert_mem_equal(rx_buf, TEST_STR_SMALL, ret, "Invalid data received");

	/* And make sure there's no more data left. */
	ret = zsock_recv(new_sock, rx_buf, sizeof(rx_buf), ZSOCK_MSG_DONTWAIT);
	zassert_equal(ret, -1, "zsock_recv() should've failed");
	zassert_equal(errno, EAGAIN, "Unexpected errno value: %d", errno);

	test_sockets_close();

	k_sleep(TCP_TEARDOWN_TIMEOUT);
}

ZTEST(net_socket_tls, test_send_on_close)
{
	uint8_t rx_buf[sizeof(TEST_STR_SMALL) - 1] = { 0 };
	int ret;

	test_prepare_tls_connection(NET_AF_INET6);

	test_close(new_sock);
	new_sock = -1;

	/* Small delay for packets to propagate. */
	k_msleep(20);

	/* Verify send() reports an error after connection is closed. */
	ret = zsock_send(c_sock, TEST_STR_SMALL, strlen(TEST_STR_SMALL), 0);
	zassert_equal(ret, -1, "zsock_send() should've failed");
	zassert_equal(errno, ECONNABORTED, "Unexpected errno value: %d", errno);

	/* recv() on closed connection marked error on a socket. */
	ret = zsock_recv(c_sock, rx_buf, sizeof(rx_buf), 0);
	zassert_equal(ret, -1, "zsock_recv() should've failed");
	zassert_equal(errno, ECONNABORTED, "Unexpected errno value: %d", errno);

	test_sockets_close();

	/* And in reverse order */

	test_prepare_tls_connection(NET_AF_INET6);

	test_close(new_sock);
	new_sock = -1;

	/* Small delay for packets to propagate. */
	k_msleep(20);

	/* Graceful connection close should be reported first. */
	ret = zsock_recv(c_sock, rx_buf, sizeof(rx_buf), 0);
	zassert_equal(ret, 0, "zsock_recv() should've reported connection close");

	/* And consecutive send() should fail. */
	ret = zsock_send(c_sock, TEST_STR_SMALL, strlen(TEST_STR_SMALL), 0);
	zassert_equal(ret, -1, "zsock_send() should've failed");
	zassert_equal(errno, ECONNABORTED, "Unexpected errno value: %d", errno);

	test_sockets_close();

	k_sleep(TCP_TEARDOWN_TIMEOUT);
}

ZTEST(net_socket_tls, test_so_rcvtimeo)
{
	uint8_t rx_buf[sizeof(TEST_STR_SMALL) - 1];
	uint32_t start_time, time_diff;
	struct timeval optval = {
		.tv_sec = 0,
		.tv_usec = 500000,
	};
	struct send_data test_data = {
		.data = TEST_STR_SMALL,
		.datalen = sizeof(TEST_STR_SMALL) - 1
	};
	int ret;

	test_prepare_tls_connection(NET_AF_INET6);

	ret = zsock_setsockopt(c_sock, ZSOCK_SOL_SOCKET, ZSOCK_SO_RCVTIMEO, &optval,
			       sizeof(optval));
	zassert_equal(ret, 0, "zsock_setsockopt() failed (%d)", errno);

	start_time = k_uptime_get_32();
	ret = zsock_recv(c_sock, rx_buf, sizeof(rx_buf), 0);
	time_diff = k_uptime_get_32() - start_time;

	zassert_equal(ret, -1, "zsock_recv() should've failed");
	zassert_equal(errno, EAGAIN, "Unexpected errno value: %d", errno);
	zassert_true(time_diff >= 500, "Expected timeout after 500ms but "
		     "was %dms", time_diff);

	test_data.sock = c_sock;
	k_work_init_delayable(&test_data.tx_work, send_work_handler);
	test_work_reschedule(&test_data.tx_work, K_MSEC(10));

	/* recv() shall return as soon as it gets data, regardless of timeout. */
	ret = zsock_recv(new_sock, rx_buf, sizeof(rx_buf), 0);
	zassert_equal(ret, sizeof(TEST_STR_SMALL) - 1, "zsock_recv() failed");
	zassert_mem_equal(rx_buf, TEST_STR_SMALL, ret, "Invalid data received");

	test_sockets_close();

	k_sleep(TCP_TEARDOWN_TIMEOUT);
}

ZTEST(net_socket_tls, test_so_sndtimeo)
{
	int buf_optval = TLS_RECORD_OVERHEAD + sizeof(TEST_STR_SMALL) - 1;
	uint32_t start_time, time_diff;
	struct timeval timeo_optval = {
		.tv_sec = 0,
		.tv_usec = 500000,
	};
	struct recv_data test_data = {
		.data = TEST_STR_SMALL,
		.datalen = sizeof(TEST_STR_SMALL) - 1
	};
	int ret;

	test_prepare_tls_connection(NET_AF_INET6);

	ret = zsock_setsockopt(c_sock, ZSOCK_SOL_SOCKET, ZSOCK_SO_SNDTIMEO, &timeo_optval,
			       sizeof(timeo_optval));
	zassert_equal(ret, 0, "zsock_setsockopt() failed (%d)", errno);

	/* Simulate window full scenario with SO_RCVBUF option. */
	ret = zsock_setsockopt(new_sock, ZSOCK_SOL_SOCKET, ZSOCK_SO_RCVBUF, &buf_optval,
			       sizeof(buf_optval));
	zassert_equal(ret, 0, "zsock_setsockopt() failed (%d)", errno);

	ret = zsock_send(c_sock, TEST_STR_SMALL, sizeof(TEST_STR_SMALL) - 1, 0);
	zassert_equal(ret, sizeof(TEST_STR_SMALL) - 1, "zsock_send() failed");

	/* Wait for ACK (empty window). */
	k_msleep(150);

	/* Client should not be able to send now and time out after SO_SNDTIMEO */
	start_time = k_uptime_get_32();
	ret = zsock_send(c_sock, TEST_STR_SMALL, sizeof(TEST_STR_SMALL) - 1, 0);
	time_diff = k_uptime_get_32() - start_time;

	zassert_equal(ret, -1, "zsock_send() should've failed");
	zassert_equal(errno, EAGAIN, "Unexpected errno value: %d", errno);
	zassert_true(time_diff >= 500, "Expected timeout after 500ms but "
			"was %dms", time_diff);

	test_data.sock = new_sock;
	k_work_init_delayable(&test_data.work, recv_work_handler);
	test_work_reschedule(&test_data.work, K_MSEC(10));

	/* Should block and succeed. */
	ret = zsock_send(c_sock, TEST_STR_SMALL, strlen(TEST_STR_SMALL), 0);
	zassert_equal(ret, strlen(TEST_STR_SMALL), "zsock_send() failed");

	test_sockets_close();

	k_sleep(TCP_TEARDOWN_TIMEOUT);
}

ZTEST(net_socket_tls, test_shutdown_rd_synchronous)
{
	test_prepare_tls_connection(NET_AF_INET6);

	/* Shutdown reception */
	test_shutdown(c_sock, ZSOCK_SHUT_RD);

	/* EOF should be notified by recv() */
	test_eof(c_sock);

	test_sockets_close();

	k_sleep(TCP_TEARDOWN_TIMEOUT);
}

struct shutdown_data {
	struct k_work_delayable work;
	int sock;
	int how;
};

static void shutdown_work(struct k_work *work)
{
	struct k_work_delayable *dwork = k_work_delayable_from_work(work);
	struct shutdown_data *data = CONTAINER_OF(dwork, struct shutdown_data,
						  work);

	zsock_shutdown(data->sock, data->how);
}

ZTEST(net_socket_tls, test_shutdown_rd_while_recv)
{
	struct shutdown_data test_data = {
		.how = ZSOCK_SHUT_RD,
	};

	test_prepare_tls_connection(NET_AF_INET6);

	/* Schedule reception shutdown from workqueue. 50ms margin guards
	 * against slow CI runners where recv() hasn't reached its blocking
	 * point at the 10ms mark.
	 */
	k_work_init_delayable(&test_data.work, shutdown_work);
	test_data.sock = c_sock;
	test_work_reschedule(&test_data.work, K_MSEC(50));

	/* EOF should be notified by recv() */
	test_eof(c_sock);

	test_sockets_close();

	k_sleep(TCP_TEARDOWN_TIMEOUT);
}

#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS) && defined(CONFIG_WOLFSSL)
/* wolfSSL-only: exercises the recv_eof shortcut in
 * recvfrom_dtls_common_wolfssl that turns local SHUT_RD/SHUT_RDWR into
 * an EOF on the next recv(). The mbedTLS backend matches upstream
 * Zephyr behavior (no local-shutdown shortcut on DTLS), so this test
 * is gated to wolfSSL builds to preserve the upstream interface
 * contract for mbedTLS users.
 */
static void test_dtls_shutdown_synchronous_body(net_sa_family_t family, int how)
{
	test_prepare_dtls_connection(family);

	test_shutdown(c_sock, how);

	/* EOF should be notified by recv() */
	test_eof(c_sock);

	test_sockets_close();

	k_sleep(TCP_TEARDOWN_TIMEOUT);
}
#endif

ZTEST(net_socket_tls, test_dtls_shutdown_rd_synchronous_v6)
{
#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS) && defined(CONFIG_WOLFSSL)
	test_dtls_shutdown_synchronous_body(NET_AF_INET6, ZSOCK_SHUT_RD);
#else
	ztest_test_skip();
#endif
}

ZTEST(net_socket_tls, test_dtls_shutdown_rd_synchronous_v4)
{
#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS) && defined(CONFIG_WOLFSSL)
	test_dtls_shutdown_synchronous_body(NET_AF_INET, ZSOCK_SHUT_RD);
#else
	ztest_test_skip();
#endif
}

ZTEST(net_socket_tls, test_dtls_shutdown_rd_while_recv)
{
#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS) && defined(CONFIG_WOLFSSL)
	struct shutdown_data test_data = {
		.how = ZSOCK_SHUT_RD,
	};

	test_prepare_dtls_connection(NET_AF_INET6);

	/* Schedule reception shutdown from workqueue while recv() is blocked
	 * — exercises the recv_eof check inside the wolfSSL DTLS recv loop
	 * (recvfrom_dtls_common_wolfssl). The TCP/TLS variant lives in
	 * test_shutdown_rd_while_recv. 50ms margin guards against slow CI
	 * runners where recv() hasn't reached its blocking point yet at the
	 * 10ms mark — short enough to keep the test fast.
	 */
	k_work_init_delayable(&test_data.work, shutdown_work);
	test_data.sock = c_sock;
	test_work_reschedule(&test_data.work, K_MSEC(50));

	/* EOF should be notified by recv() */
	test_eof(c_sock);

	test_sockets_close();

	k_sleep(TCP_TEARDOWN_TIMEOUT);
#else
	ztest_test_skip();
#endif
}

ZTEST(net_socket_tls, test_send_while_recv)
{
	uint8_t rx_buf[sizeof(TEST_STR_SMALL) - 1];
	struct send_data test_data_c = {
		.data = TEST_STR_SMALL,
		.datalen = sizeof(TEST_STR_SMALL) - 1
	};
	struct send_data test_data_s = {
		.data = TEST_STR_SMALL,
		.datalen = sizeof(TEST_STR_SMALL) - 1
	};
	int ret;

	test_prepare_tls_connection(NET_AF_INET6);

	test_data_c.sock = c_sock;
	k_work_init_delayable(&test_data_c.tx_work, send_work_handler);
	test_work_reschedule(&test_data_c.tx_work, K_MSEC(10));

	test_data_s.sock = new_sock;
	k_work_init_delayable(&test_data_s.tx_work, send_work_handler);
	test_work_reschedule(&test_data_s.tx_work, K_MSEC(20));

	/* recv() shall block until the second work is executed. The second work
	 * will execute only if the first one won't block.
	 */
	ret = zsock_recv(c_sock, rx_buf, sizeof(rx_buf), 0);
	zassert_equal(ret, sizeof(TEST_STR_SMALL) - 1, "zsock_recv() failed");
	zassert_mem_equal(rx_buf, TEST_STR_SMALL, ret, "Invalid data received");

	/* Check if the server sock got its data. */
	ret = zsock_recv(new_sock, rx_buf, sizeof(rx_buf), 0);
	zassert_equal(ret, sizeof(TEST_STR_SMALL) - 1, "zsock_recv() failed");
	zassert_mem_equal(rx_buf, TEST_STR_SMALL, ret, "Invalid data received");

	test_sockets_close();

	k_sleep(TCP_TEARDOWN_TIMEOUT);
}

void tls_set_cs_cb(void)
{
	int ret = zsock_setsockopt(s_sock, ZSOCK_SOL_TLS, ZSOCK_TLS_CIPHERSUITE_LIST,
				   (void *)cipher_list_psk, sizeof(cipher_list_psk));
	zassert_equal(ret, 0, "Unable to set ciphersuites on server");
	ret = zsock_setsockopt(c_sock, ZSOCK_SOL_TLS, ZSOCK_TLS_CIPHERSUITE_LIST,
			       (void *)cipher_list_psk2, sizeof(cipher_list_psk2));
	zassert_equal(ret, 0, "Unable to set ciphersuites on client");
}

void tls_set_cs_mismatch_cb(void)
{
	/* Set mismatched ciphersuites, should not connect */
	int ret = zsock_setsockopt(c_sock, ZSOCK_SOL_TLS, ZSOCK_TLS_CIPHERSUITE_LIST,
				   (void *)cipher_list_psk2, sizeof(cipher_list_psk2));
	zassert_equal(ret, 0, "Unable to set ciphersuites on client");
	ret = zsock_setsockopt(s_sock, ZSOCK_SOL_TLS, ZSOCK_TLS_CIPHERSUITE_LIST,
			       (void *)cipher_list_psk3, sizeof(cipher_list_psk3));
	zassert_equal(ret, 0, "Unable to set ciphersuites on server");
}

ZTEST(net_socket_tls, test_set_ciphersuites)
{
#define TLS_CS_TEST_MAX_CS_NUM 3
	int ret;
	uint8_t rx_buf[sizeof(TEST_STR_SMALL) - 1] = { 0 };
	struct send_data test_data = {
		.data = TEST_STR_SMALL,
		.datalen = sizeof(TEST_STR_SMALL) - 1
	};
	int ciphersuites[TLS_CS_TEST_MAX_CS_NUM];
	int cs_len = sizeof(ciphersuites);
	int curr_cipher = 0;
	int cc_len = sizeof(int);
	int i;

	for (i = 0; i < TLS_CS_TEST_MAX_CS_NUM; i++) {
		ciphersuites[i] = 0;
	}

	test_prepare_tls_connection_ex(NET_AF_INET, false, tls_set_cs_cb, NULL);

	/* Verify the ciphersuite list is what we set for server */
	ret = zsock_getsockopt(s_sock, ZSOCK_SOL_TLS, ZSOCK_TLS_CIPHERSUITE_LIST,
			       (void *)ciphersuites, (net_socklen_t *)&cs_len);
	zassert_equal(ret, 0, "Unable to get ciphersuites for server");
	zassert_equal(cs_len, sizeof(cipher_list_psk), "Incorrect get ciphersuite len");

	for (i = 0; i < cs_len / sizeof(int); i++) {
		zassert_equal(ciphersuites[i], cipher_list_psk[i],
			      "Retrieved ciphersuite list element does not match set value");
	}

	/* Same for client */
	for (i = 0; i < TLS_CS_TEST_MAX_CS_NUM; i++) {
		ciphersuites[i] = 0;
	}

	cs_len = sizeof(ciphersuites);
	ret = zsock_getsockopt(c_sock, ZSOCK_SOL_TLS, ZSOCK_TLS_CIPHERSUITE_LIST,
			       (void *)ciphersuites, (net_socklen_t *)&cs_len);
	zassert_equal(ret, 0, "Unable to get ciphersuites for client");
	zassert_equal(cs_len, sizeof(cipher_list_psk2), "Incorrect get ciphersuite len");

	for (i = 0; i < cs_len / sizeof(int); i++) {
		zassert_equal(ciphersuites[i], cipher_list_psk2[i],
			      "Retrieved ciphersuite list element does not match set value");
	}

	/* Check that the actual negotiated cipher is correct for server */
	ret = zsock_getsockopt(new_sock, ZSOCK_SOL_TLS, ZSOCK_TLS_CIPHERSUITE_USED,
			       (void *)&curr_cipher, (net_socklen_t *)&cc_len);
	zassert_equal(ret, 0, "Unable to get current ciphersuite for server");
	zassert_equal(curr_cipher, cipher_list_psk2[0]);

	/* Same for the client */
	curr_cipher = 0;
	ret = zsock_getsockopt(c_sock, ZSOCK_SOL_TLS, ZSOCK_TLS_CIPHERSUITE_USED,
			       (void *)&curr_cipher, (net_socklen_t *)&cc_len);
	zassert_equal(ret, 0, "Unable to get current ciphersuite for client");
	zassert_equal(curr_cipher, cipher_list_psk2[0]);

	test_data.sock = c_sock;
	k_work_init_delayable(&test_data.tx_work, send_work_handler);
	test_work_reschedule(&test_data.tx_work, K_MSEC(10));

	/* recv() shall block until send work sends the data. */
	ret = zsock_recv(new_sock, rx_buf, sizeof(rx_buf), 0);
	zassert_equal(ret, sizeof(TEST_STR_SMALL) - 1, "recv() failed");
	zassert_mem_equal(rx_buf, TEST_STR_SMALL, ret, "Invalid data received");

	test_sockets_close();

	k_sleep(TCP_TEARDOWN_TIMEOUT);
}

ZTEST(net_socket_tls, test_set_ciphersuites_err)
{
	/* Expect failure to connect and accept due to mismatched ciphersuites */
	test_prepare_tls_connection_ex(NET_AF_INET, true,
		tls_set_cs_mismatch_cb, client_connect_work_handler_err);

	test_sockets_close();

	k_sleep(TCP_TEARDOWN_TIMEOUT);
}

void tls_set_hostname_cb(void)
{
	int ret = zsock_setsockopt(c_sock, ZSOCK_SOL_TLS, ZSOCK_TLS_HOSTNAME,
				   (void *)MY_DEFLT_HOSTNAME, strlen(MY_DEFLT_HOSTNAME));
	zassert_equal(ret, 0, "Unable to set hostname on client");
}

ZTEST(net_socket_tls, test_set_hostname)
{
	int ret;
	uint8_t rx_buf[sizeof(TEST_STR_SMALL) - 1] = { 0 };
	struct send_data test_data = {
		.data = TEST_STR_SMALL,
		.datalen = sizeof(TEST_STR_SMALL) - 1
	};

	test_prepare_tls_connection_ex(NET_AF_INET, false, tls_set_hostname_cb, NULL);

	test_data.sock = c_sock;
	k_work_init_delayable(&test_data.tx_work, send_work_handler);
	test_work_reschedule(&test_data.tx_work, K_MSEC(10));

	/* recv() shall block until send work sends the data. */
	ret = zsock_recv(new_sock, rx_buf, sizeof(rx_buf), 0);
	zassert_equal(ret, sizeof(TEST_STR_SMALL) - 1, "recv() failed");
	zassert_mem_equal(rx_buf, TEST_STR_SMALL, ret, "Invalid data received");

	test_sockets_close();

	k_sleep(TCP_TEARDOWN_TIMEOUT);
}

/* Verify that TLS options can still be set on an already-established
 * connection without failing the setsockopt call. On the wolfSSL backend
 * live changes are propagated to existing sessions best-effort (and apply
 * fully to future sessions); on mbedTLS they update the shared config.
 * Either way the call must succeed and the connection must stay usable.
 */
ZTEST(net_socket_tls, test_opt_set_after_connect)
{
	int ret;
	uint8_t rx_buf[sizeof(TEST_STR_SMALL) - 1] = { 0 };
	struct send_data test_data = {
		.data = TEST_STR_SMALL,
		.datalen = sizeof(TEST_STR_SMALL) - 1
	};
#if defined(CONFIG_WOLFSSL)
	static const int bad_cipher_list[] = { 0x1FFFF };
#endif

	test_prepare_tls_connection(NET_AF_INET);

	ret = zsock_setsockopt(c_sock, ZSOCK_SOL_TLS, ZSOCK_TLS_HOSTNAME,
			       (void *)MY_DEFLT_HOSTNAME,
			       strlen(MY_DEFLT_HOSTNAME));
	zassert_equal(ret, 0, "setting hostname after connect failed (%d)",
		      errno);

	ret = zsock_setsockopt(c_sock, ZSOCK_SOL_TLS, ZSOCK_TLS_CIPHERSUITE_LIST,
			       (void *)cipher_list_psk2, sizeof(cipher_list_psk2));
	zassert_equal(ret, 0, "setting ciphersuites after connect failed (%d)",
		      errno);

#if defined(CONFIG_WOLFSSL)
	/* Argument validation must happen before the option is stored,
	 * independent of the (best-effort) live application.
	 */
	ret = zsock_setsockopt(c_sock, ZSOCK_SOL_TLS, ZSOCK_TLS_CIPHERSUITE_LIST,
			       (void *)bad_cipher_list, sizeof(bad_cipher_list));
	zassert_equal(ret, -1, "invalid ciphersuite ID not rejected");
	zassert_equal(errno, EINVAL, "wrong errno value: %d", errno);
#endif

	/* Connection must still be usable. */
	test_data.sock = c_sock;
	k_work_init_delayable(&test_data.tx_work, send_work_handler);
	test_work_reschedule(&test_data.tx_work, K_MSEC(10));

	ret = zsock_recv(new_sock, rx_buf, sizeof(rx_buf), 0);
	zassert_equal(ret, sizeof(TEST_STR_SMALL) - 1, "recv() failed");
	zassert_mem_equal(rx_buf, TEST_STR_SMALL, ret, "Invalid data received");

	test_sockets_close();

	k_sleep(TCP_TEARDOWN_TIMEOUT);
}

#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS) && defined(CONFIG_WOLFSSL)
/* Defined further below with the DTLS multi-client tests. */
static void dtls_verify_address(struct net_sockaddr *addr, net_socklen_t addrlen,
				struct net_sockaddr *expected);
#endif

/* wolfSSL-only: an empty UDP datagram spoofed from the peer's address must
 * not tear down an established DTLS server session (it carries no TLS
 * record and source addresses are trivially forgeable). The mbedTLS
 * backend inherits upstream behavior here (a 0-byte BIO read is treated
 * as EOF), so the test is gated to the wolfSSL backend.
 */
ZTEST(net_socket_tls, test_dtls_server_empty_datagram)
{
#if !defined(CONFIG_NET_SOCKETS_ENABLE_DTLS) || !defined(CONFIG_WOLFSSL)
	ztest_test_skip();
#else
	struct net_sockaddr c_saddr;
	struct net_sockaddr s_saddr;
	struct net_sockaddr recv_addr;
	net_socklen_t recv_addrlen = sizeof(recv_addr);
	struct connect_data test_data;
	struct timeval timeo_optval = {
		.tv_sec = 1,
		.tv_usec = 0,
	};
	int role = ZSOCK_TLS_DTLS_ROLE_SERVER;
	int yes = 1;
	uint8_t rx_buf;
	uint8_t tx_buf = 0;
	int helper_sock;
	int ret;

	prepare_sock_dtls_v4(MY_IPV4_ADDR, CLIENT_1_PORT, &c_sock,
			     (struct net_sockaddr_in *)&c_saddr,
			     NET_IPPROTO_DTLS_1_2);
	prepare_sock_dtls_v4(MY_IPV4_ADDR, SERVER_PORT, &s_sock,
			     (struct net_sockaddr_in *)&s_saddr,
			     NET_IPPROTO_DTLS_1_2);

	test_config_psk(s_sock, c_sock);

	zassert_ok(zsock_setsockopt(s_sock, ZSOCK_SOL_TLS, ZSOCK_TLS_DTLS_ROLE,
				    &role, sizeof(role)),
		   "setsockopt failed (%d)", errno);
	zassert_ok(zsock_setsockopt(s_sock, ZSOCK_SOL_SOCKET, ZSOCK_SO_RCVTIMEO,
				    &timeo_optval, sizeof(timeo_optval)),
		   "setsockopt failed (%d)", errno);
	/* Allow the helper socket below to bind to the client's port. */
	zassert_ok(zsock_setsockopt(c_sock, ZSOCK_SOL_SOCKET, ZSOCK_SO_REUSEPORT,
				    &yes, sizeof(yes)),
		   "setsockopt failed (%d)", errno);

	test_bind(c_sock, &c_saddr, sizeof(struct net_sockaddr_in));
	test_bind(s_sock, &s_saddr, sizeof(struct net_sockaddr_in));

	/* Client handshake + initial data. */
	test_data.sock = c_sock;
	test_data.addr = &s_saddr;
	k_work_init_delayable(&test_data.work, dtls_client_connect_send_work_handler);
	test_work_reschedule(&test_data.work, K_NO_WAIT);

	ret = zsock_recvfrom(s_sock, &rx_buf, sizeof(rx_buf), 0,
			     &recv_addr, &recv_addrlen);
	zassert_equal(ret, sizeof(rx_buf), "recv() failed");
	test_work_wait(&test_data.work);

	/* Inject a 0-byte datagram with the client's exact source address. */
	helper_sock = zsock_socket(NET_AF_INET, NET_SOCK_DGRAM, NET_IPPROTO_UDP);
	zassert_true(helper_sock >= 0, "helper socket failed (%d)", errno);
	zassert_ok(zsock_setsockopt(helper_sock, ZSOCK_SOL_SOCKET,
				    ZSOCK_SO_REUSEPORT, &yes, sizeof(yes)),
		   "setsockopt failed (%d)", errno);
	zassert_ok(zsock_bind(helper_sock, &c_saddr,
			      sizeof(struct net_sockaddr_in)),
		   "helper bind failed (%d)", errno);
	ret = zsock_sendto(helper_sock, &tx_buf, 0, 0, &s_saddr,
			   sizeof(struct net_sockaddr_in));
	zassert_equal(ret, 0, "empty sendto() failed (%d)", errno);

	k_msleep(10);

	/* The empty datagram must be dropped: no EOF, no session teardown. */
	ret = zsock_recv(s_sock, &rx_buf, sizeof(rx_buf), ZSOCK_MSG_DONTWAIT);
	zassert_equal(ret, -1, "recv() should not have returned data/EOF");
	zassert_equal(errno, EAGAIN, "wrong errno value: %d", errno);

	/* The established session must still carry data. */
	test_send(c_sock, &tx_buf, sizeof(tx_buf), 0);

	recv_addrlen = sizeof(recv_addr);
	ret = zsock_recvfrom(s_sock, &rx_buf, sizeof(rx_buf), 0,
			     &recv_addr, &recv_addrlen);
	zassert_equal(ret, sizeof(rx_buf), "recv() after empty datagram failed");
	dtls_verify_address(&recv_addr, recv_addrlen, &c_saddr);

	(void)zsock_close(helper_sock);
	test_sockets_close();

	k_sleep(TCP_TEARDOWN_TIMEOUT);
#endif
}

void tls_set_session_cache_cb(void)
{
	int t = ZSOCK_TLS_SESSION_CACHE_ENABLED;
	int l = sizeof(int);

	int ret = zsock_setsockopt(s_sock, ZSOCK_SOL_TLS, ZSOCK_TLS_SESSION_CACHE,
				   (void *)&t, l);
	zassert_equal(ret, 0, "Unable to set session cache on server");
}

ZTEST(net_socket_tls, test_session_cache)
{
	int ret;
	int enabled = 0;
	int len = sizeof(int);
	uint8_t rx_buf[sizeof(TEST_STR_SMALL) - 1] = { 0 };
	struct send_data test_data = {
		.data = TEST_STR_SMALL,
		.datalen = sizeof(TEST_STR_SMALL) - 1
	};

	test_prepare_tls_connection_ex(NET_AF_INET, false, tls_set_session_cache_cb, NULL);

	/* Check that the session cache is enabled */
	ret = zsock_getsockopt(s_sock, ZSOCK_SOL_TLS, ZSOCK_TLS_SESSION_CACHE,
			       (void *)&enabled, (net_socklen_t *)&len);
	zassert_equal(ret, 0, "Unable to get session cache enabled status");
	zassert_equal(enabled, ZSOCK_TLS_SESSION_CACHE_ENABLED,
		      "Session cache value does not match what was set");

	test_data.sock = c_sock;
	k_work_init_delayable(&test_data.tx_work, send_work_handler);
	test_work_reschedule(&test_data.tx_work, K_MSEC(10));

	/* recv() shall block until send work sends the data. */
	ret = zsock_recv(new_sock, rx_buf, sizeof(rx_buf), 0);
	zassert_equal(ret, sizeof(TEST_STR_SMALL) - 1, "recv() failed");
	zassert_mem_equal(rx_buf, TEST_STR_SMALL, ret, "Invalid data received");

	test_sockets_close();

	k_sleep(TCP_TEARDOWN_TIMEOUT);
}

/* Helper enabling session cache on both client and server sockets. Used by
 * test_session_cache_client_resume to exercise the wolfSSL tls_session_store /
 * tls_session_restore marshalling code path.
 */
static void tls_set_session_cache_client_cb(void)
{
	int t = ZSOCK_TLS_SESSION_CACHE_ENABLED;
	int l = sizeof(int);
	int ret;

	ret = zsock_setsockopt(s_sock, ZSOCK_SOL_TLS, ZSOCK_TLS_SESSION_CACHE,
			       (void *)&t, l);
	zassert_equal(ret, 0, "Unable to set session cache on server");
	ret = zsock_setsockopt(c_sock, ZSOCK_SOL_TLS, ZSOCK_TLS_SESSION_CACHE,
			       (void *)&t, l);
	zassert_equal(ret, 0, "Unable to set session cache on client");
}

/* Sets up a TLS client/server connection on a FIXED server port so two
 * consecutive connections present the same peer address (which is the key
 * into client_cache). Used by test_session_cache_client_resume — the
 * main test_prepare_* helpers use ANY_PORT, which prevents resumption
 * lookup from matching across connections.
 */
static void prepare_tls_session_resume_connection(uint16_t server_port)
{
	struct net_sockaddr_in c_saddr;
	struct net_sockaddr_in s_saddr;
	struct net_sockaddr addr;
	net_socklen_t addrlen = sizeof(addr);
	struct connect_data test_data;
	int reuse = 1;
	int ret;

	prepare_sock_tls_v4(MY_IPV4_ADDR, ANY_PORT, &c_sock, &c_saddr,
			    NET_IPPROTO_TLS_1_2);
	prepare_sock_tls_v4(MY_IPV4_ADDR, server_port, &s_sock, &s_saddr,
			    NET_IPPROTO_TLS_1_2);

	tls_set_session_cache_client_cb();

	test_config_psk(s_sock, c_sock);

	/* Fixed server port + back-to-back binds in the same suite: ask the
	 * stack to allow rebind so the test isn't fragile if a previous
	 * teardown's TIME_WAIT entry is still around.
	 */
	ret = zsock_setsockopt(s_sock, ZSOCK_SOL_SOCKET, ZSOCK_SO_REUSEADDR,
			       &reuse, sizeof(reuse));
	zassert_equal(ret, 0, "ZSOCK_SO_REUSEADDR on server socket failed");

	test_bind(s_sock, (struct net_sockaddr *)&s_saddr, sizeof(s_saddr));
	test_listen(s_sock);

	test_data.sock = c_sock;
	test_data.addr = (struct net_sockaddr *)&s_saddr;
	k_work_init_delayable(&test_data.work, client_connect_work_handler);
	test_work_reschedule(&test_data.work, K_NO_WAIT);

	test_accept(s_sock, &new_sock, &addr, &addrlen);
	test_work_wait(&test_data.work);
}

/* Verifies that the second connect to the same peer actually resumes via the
 * client-side session marshalling (mbedTLS: tls_session_save/get; wolfSSL:
 * wolfSSL_i2d_SSL_SESSION / wolfSSL_d2i_SSL_SESSION in tls_session_store /
 * tls_session_restore). Purges first so state is isolated.
 */
ZTEST(net_socket_tls, test_session_cache_client_resume)
{
	uint8_t rx_buf[sizeof(TEST_STR_SMALL) - 1] = { 0 };
	struct send_data test_data = {
		.data = TEST_STR_SMALL,
		.datalen = sizeof(TEST_STR_SMALL) - 1,
	};
	int ret;

	/* Purge any sessions left by earlier tests so we can observe the
	 * transition from "no cached session" to "cached session".
	 */
	{
		int dummy = zsock_socket(NET_AF_INET, NET_SOCK_STREAM, NET_IPPROTO_TLS_1_2);

		zassert_true(dummy >= 0, "purge socket open failed");
		ret = zsock_setsockopt(dummy, ZSOCK_SOL_TLS, ZSOCK_TLS_SESSION_CACHE_PURGE,
				       NULL, 0);
		zassert_equal(ret, 0, "purge setsockopt failed");
		zsock_close(dummy);
	}

	/* First connection — should perform full handshake, then store. */
	prepare_tls_session_resume_connection(RESUME_SERVER_PORT);

#if defined(CONFIG_WOLFSSL)
	{
		WOLFSSL *ssl = ztls_get_wolfssl_context(c_sock);
		int reused;

		zassert_not_null(ssl, "Failed to get wolfSSL context");
		reused = wolfSSL_session_reused(ssl);
		zassert_equal(reused, 0,
			      "First connect should not be a resumption (got %d)",
			      reused);
	}
#endif

	test_data.sock = c_sock;
	k_work_init_delayable(&test_data.tx_work, send_work_handler);
	test_work_reschedule(&test_data.tx_work, K_MSEC(10));
	ret = zsock_recv(new_sock, rx_buf, sizeof(rx_buf), 0);
	zassert_equal(ret, sizeof(TEST_STR_SMALL) - 1, "recv() failed");

	test_sockets_close();
	k_sleep(TCP_TEARDOWN_TIMEOUT);

	/* Second connection to the SAME server port — should restore the
	 * stored session and resume.
	 */
	prepare_tls_session_resume_connection(RESUME_SERVER_PORT);

#if defined(CONFIG_WOLFSSL)
	{
		WOLFSSL *ssl = ztls_get_wolfssl_context(c_sock);
		int reused;

		zassert_not_null(ssl, "Failed to get wolfSSL context");
		reused = wolfSSL_session_reused(ssl);
		zassert_not_equal(reused, 0,
				  "Second connect did not reuse session");
	}
#endif

	memset(rx_buf, 0, sizeof(rx_buf));
	test_data.sock = c_sock;
	k_work_init_delayable(&test_data.tx_work, send_work_handler);
	test_work_reschedule(&test_data.tx_work, K_MSEC(10));
	ret = zsock_recv(new_sock, rx_buf, sizeof(rx_buf), 0);
	zassert_equal(ret, sizeof(TEST_STR_SMALL) - 1, "recv() failed");
	zassert_mem_equal(rx_buf, TEST_STR_SMALL, ret, "Invalid data received");

	test_sockets_close();
	k_sleep(TCP_TEARDOWN_TIMEOUT);
}

/* Smoke test for M01: verify that a TLS handshake completes when wolfSSL
 * secure renegotiation is enabled. With HAVE_SECURE_RENEGOTIATION the TLS
 * init path calls wolfSSL_UseSecureRenegotiation() on each new SSL object;
 * a failure there fails ztls_connect_ctx/ztls_accept_ctx. A successful
 * handshake proves the call is reachable and the API is wired up. A full
 * renegotiation round-trip would require additional hooks into the Zephyr
 * TLS socket API which are out of scope here.
 */
ZTEST(net_socket_tls, test_tls_renegotiation_smoke)
{
#if defined(CONFIG_WOLFSSL)
#if !defined(HAVE_SECURE_RENEGOTIATION)
	ztest_test_skip();
	return;
#endif
#elif !defined(CONFIG_MBEDTLS_SSL_RENEGOTIATION)
	ztest_test_skip();
	return;
#endif
	uint8_t rx_buf[sizeof(TEST_STR_SMALL) - 1] = { 0 };
	struct send_data test_data = {
		.data = TEST_STR_SMALL,
		.datalen = sizeof(TEST_STR_SMALL) - 1,
	};
	int ret;

	test_prepare_tls_connection(NET_AF_INET);

	test_data.sock = c_sock;
	k_work_init_delayable(&test_data.tx_work, send_work_handler);
	test_work_reschedule(&test_data.tx_work, K_MSEC(10));
	ret = zsock_recv(new_sock, rx_buf, sizeof(rx_buf), 0);
	zassert_equal(ret, sizeof(TEST_STR_SMALL) - 1, "recv() failed");
	zassert_mem_equal(rx_buf, TEST_STR_SMALL, ret, "Invalid data received");

	test_sockets_close();
	k_sleep(TCP_TEARDOWN_TIMEOUT);
}

const char *alpn_list[] = {
	"http/1.0",
	"http/1.1"
};

void tls_set_alpn_cb(void)
{
	net_socklen_t len = sizeof(alpn_list);
	int ret = zsock_setsockopt(s_sock, ZSOCK_SOL_TLS, ZSOCK_TLS_ALPN_LIST,
				   (void *)alpn_list, len);
	zassert_equal(ret, 0, "Unable to set alpn on server");
}

ZTEST(net_socket_tls, test_alpn)
{
#if CONFIG_NET_SOCKETS_TLS_MAX_APP_PROTOCOLS > 0
	int ret;
	uint8_t rx_buf[sizeof(TEST_STR_SMALL) - 1] = { 0 };
	struct send_data test_data = {
		.data = TEST_STR_SMALL,
		.datalen = sizeof(TEST_STR_SMALL) - 1
	};
	const char *alpn_buf[2];
	int alpn_len = sizeof(alpn_buf);

	alpn_buf[0] = NULL;
	alpn_buf[1] = NULL;

	test_prepare_tls_connection_ex(NET_AF_INET, false, tls_set_alpn_cb, NULL);

	/* Check that the ALPN list is the one we set */
	ret = zsock_getsockopt(s_sock, ZSOCK_SOL_TLS, ZSOCK_TLS_ALPN_LIST,
			       (void *)alpn_buf, (net_socklen_t *)&alpn_len);
	zassert_equal(ret, 0, "Unable to get alpn list");
	zassert_equal(alpn_len, sizeof(alpn_list), "Retrieved ALPN list length incorrect");
	zassert_equal(strlen(alpn_buf[0]), strlen(alpn_list[0]),
		      "Retrieved ALPN list element length incorrect");
	zassert_mem_equal(alpn_buf[0], alpn_list[0], strlen(alpn_list[0]),
			  "Retrieved ALPN element does not match what was set");
	zassert_equal(strlen(alpn_buf[1]), strlen(alpn_list[1]),
		      "Retrieved ALPN list element length incorrect");
	zassert_mem_equal(alpn_buf[1], alpn_list[1], strlen(alpn_list[1]),
			  "Retrieved ALPN element does not match what was set");

	test_data.sock = c_sock;
	k_work_init_delayable(&test_data.tx_work, send_work_handler);
	test_work_reschedule(&test_data.tx_work, K_MSEC(10));

	/* recv() shall block until send work sends the data. */
	ret = zsock_recv(new_sock, rx_buf, sizeof(rx_buf), 0);
	zassert_equal(ret, sizeof(TEST_STR_SMALL) - 1, "recv() failed");
	zassert_mem_equal(rx_buf, TEST_STR_SMALL, ret, "Invalid data received");

	test_sockets_close();

	k_sleep(TCP_TEARDOWN_TIMEOUT);
#else
	ztest_test_skip();
#endif
}

ZTEST(net_socket_tls, test_poll_tls_pollin)
{
	uint8_t rx_buf[sizeof(TEST_STR_SMALL) - 1];
	int ret;
	struct zsock_pollfd fds[1];

	test_prepare_tls_connection(NET_AF_INET6);

	fds[0].fd = new_sock;
	fds[0].events = ZSOCK_POLLIN;

	ret = zsock_poll(fds, 1, 0);
	zassert_equal(ret, 0, "Unexpected poll() event");

	ret = zsock_send(c_sock, TEST_STR_SMALL, sizeof(TEST_STR_SMALL) - 1, 0);
	zassert_equal(ret, strlen(TEST_STR_SMALL), "zsock_send() failed");

	ret = zsock_poll(fds, 1, 100);
	zassert_equal(ret, 1, "poll() should've report event");
	zassert_equal(fds[0].revents, ZSOCK_POLLIN, "No POLLIN event");

	/* Check that data is really available */
	ret = zsock_recv(new_sock, rx_buf, sizeof(rx_buf), ZSOCK_MSG_DONTWAIT);
	zassert_equal(ret, sizeof(TEST_STR_SMALL) - 1, "zsock_recv() failed");
	zassert_mem_equal(rx_buf, TEST_STR_SMALL, ret, "Invalid data received");

	test_sockets_close();

	k_sleep(TCP_TEARDOWN_TIMEOUT);
}

ZTEST(net_socket_tls, test_poll_dtls_pollin)
{
#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
	uint8_t rx_buf[sizeof(TEST_STR_SMALL) - 1];
	struct send_data test_data = {
		.data = TEST_STR_SMALL,
		.datalen = sizeof(TEST_STR_SMALL) - 1
	};
	int ret;
	struct zsock_pollfd fds[1];

	test_prepare_dtls_connection(NET_AF_INET6);

	fds[0].fd = s_sock;
	fds[0].events = ZSOCK_POLLIN;

	ret = zsock_poll(fds, 1, 0);
	zassert_equal(ret, 0, "Unexpected poll() event");

	test_data.sock = c_sock;
	k_work_init_delayable(&test_data.tx_work, send_work_handler);
	test_work_reschedule(&test_data.tx_work, K_NO_WAIT);

	ret = zsock_poll(fds, 1, 100);
	zassert_equal(ret, 1, "poll() should've report event");
	zassert_equal(fds[0].revents, ZSOCK_POLLIN, "No POLLIN event");

	/* Check that data is really available */
	ret = zsock_recv(s_sock, rx_buf, sizeof(rx_buf), ZSOCK_MSG_DONTWAIT);
	zassert_equal(ret, sizeof(TEST_STR_SMALL) - 1, "zsock_recv() failed");
	zassert_mem_equal(rx_buf, TEST_STR_SMALL, ret, "Invalid data received");

	test_sockets_close();

	/* Small delay for the final alert exchange */
	k_msleep(10);
#else
	ztest_test_skip();
#endif
}

ZTEST(net_socket_tls, test_poll_tls_pollout)
{
	int buf_optval = TLS_RECORD_OVERHEAD + sizeof(TEST_STR_SMALL) - 1;
	uint8_t rx_buf[sizeof(TEST_STR_SMALL) - 1];
	int ret;
	struct zsock_pollfd fds[1];

	test_prepare_tls_connection(NET_AF_INET6);

	fds[0].fd = c_sock;
	fds[0].events = ZSOCK_POLLOUT;

	ret = zsock_poll(fds, 1, 0);
	zassert_equal(ret, 1, "poll() should've report event");
	zassert_equal(fds[0].revents, ZSOCK_POLLOUT, "No POLLOUT event");

	/* Simulate window full scenario with SO_RCVBUF option. */
	ret = zsock_setsockopt(new_sock, ZSOCK_SOL_SOCKET, ZSOCK_SO_RCVBUF, &buf_optval,
			       sizeof(buf_optval));
	zassert_equal(ret, 0, "zsock_setsockopt() failed (%d)", errno);

	/* Fill out the window */
	ret = zsock_send(c_sock, TEST_STR_SMALL, strlen(TEST_STR_SMALL), 0);
	zassert_equal(ret, strlen(TEST_STR_SMALL), "zsock_send() failed");

	/* Wait for ACK (empty window, min. 100 ms due to silly window
	 * protection).
	 */
	k_sleep(K_MSEC(150));

	/* poll() shouldn't report POLLOUT now */
	ret = zsock_poll(fds, 1, 0);
	zassert_equal(ret, 0, "Unexpected poll() event");

	/* Consume the data, and check if the client sock is writeable again */
	ret = zsock_recv(new_sock, rx_buf, sizeof(rx_buf), ZSOCK_MSG_DONTWAIT);
	zassert_equal(ret, sizeof(TEST_STR_SMALL) - 1, "zsock_recv() failed");
	zassert_mem_equal(rx_buf, TEST_STR_SMALL, ret, "Invalid data received");

	ret = zsock_poll(fds, 1, 100);
	zassert_equal(ret, 1, "poll() should've report event");
	zassert_equal(fds[0].revents, ZSOCK_POLLOUT, "No POLLOUT event");

	test_sockets_close();

	k_sleep(TCP_TEARDOWN_TIMEOUT);
}

ZTEST(net_socket_tls, test_poll_dtls_pollout)
{
#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
	struct zsock_pollfd fds[1];
	int ret;

	test_prepare_dtls_connection(NET_AF_INET6);

	fds[0].fd = c_sock;
	fds[0].events = ZSOCK_POLLOUT;

	/* DTLS socket should always be writeable. */
	ret = zsock_poll(fds, 1, 0);
	zassert_equal(ret, 1, "poll() should've report event");
	zassert_equal(fds[0].revents, ZSOCK_POLLOUT, "No POLLOUT event");

	test_sockets_close();

	/* Small delay for the final alert exchange */
	k_msleep(10);
#else
	ztest_test_skip();
#endif
}

ZTEST(net_socket_tls, test_poll_tls_pollhup)
{
	struct zsock_pollfd fds[1];
	uint8_t rx_buf;
	int ret;

	test_prepare_tls_connection(NET_AF_INET6);

	fds[0].fd = new_sock;
	fds[0].events = ZSOCK_POLLIN;

	test_close(c_sock);
	c_sock = -1;

	ret = zsock_poll(fds, 1, 100);
	zassert_equal(ret, 1, "poll() should've report event");
	zassert_true(fds[0].revents & ZSOCK_POLLIN, "No POLLIN event");
	zassert_true(fds[0].revents & ZSOCK_POLLHUP, "No POLLHUP event");

	/* Check that connection was indeed closed */
	ret = zsock_recv(new_sock, &rx_buf, sizeof(rx_buf), ZSOCK_MSG_DONTWAIT);
	zassert_equal(ret, 0, "zsock_recv() did not report connection close");

	test_sockets_close();

	k_sleep(TCP_TEARDOWN_TIMEOUT);
}

ZTEST(net_socket_tls, test_poll_dtls_pollhup)
{
#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
	struct zsock_pollfd fds[1];
	uint8_t rx_buf;
	int ret;

	test_prepare_dtls_connection(NET_AF_INET6);

	fds[0].fd = s_sock;
	fds[0].events = ZSOCK_POLLIN;

	test_close(c_sock);
	c_sock = -1;

	ret = zsock_poll(fds, 1, 100);
	zassert_equal(ret, 1, "poll() should've report event");
	zassert_equal(fds[0].revents, ZSOCK_POLLHUP, "No POLLHUP event");

	/* Check that connection was indeed closed */
	ret = zsock_recv(s_sock, &rx_buf, sizeof(rx_buf), ZSOCK_MSG_DONTWAIT);
	zassert_equal(ret, -1, "zsock_recv() should report EAGAIN");
	zassert_equal(errno, EAGAIN, "Unexpected errno value: %d", errno);

	test_sockets_close();

	/* Small delay for the final alert exchange */
	k_msleep(10);
#else
	ztest_test_skip();
#endif
}

ZTEST(net_socket_tls, test_poll_tls_pollerr)
{
	uint8_t rx_buf;
	int ret;
	struct zsock_pollfd fds[1];
	int optval;
	net_socklen_t optlen = sizeof(optval);
#if defined(CONFIG_WOLFSSL)
	WOLFSSL *ssl_ctx;
#else
	mbedtls_ssl_context *ssl_ctx;
#endif

	test_prepare_tls_connection(NET_AF_INET6);

	fds[0].fd = new_sock;
	fds[0].events = ZSOCK_POLLIN;

	/* Get access to the underlying ssl context, and send alert. */
#if defined(CONFIG_WOLFSSL)
	ssl_ctx = ztls_get_wolfssl_context(c_sock);
	test_wolfssl_send_fatal_alert(ssl_ctx);
#else
	ssl_ctx = ztls_get_mbedtls_ssl_context(c_sock);
	mbedtls_ssl_send_alert_message(ssl_ctx, MBEDTLS_SSL_ALERT_LEVEL_FATAL,
				       MBEDTLS_SSL_ALERT_MSG_INTERNAL_ERROR);
#endif

	ret = zsock_poll(fds, 1, 100);
	zassert_equal(ret, 1, "poll() should've report event");
	zassert_true(fds[0].revents & ZSOCK_POLLERR, "No POLLERR event");

	ret = zsock_getsockopt(new_sock, ZSOCK_SOL_SOCKET, ZSOCK_SO_ERROR, &optval, &optlen);
	zassert_equal(ret, 0, "zsock_getsockopt() failed (%d)", errno);
	zassert_equal(optval, ECONNABORTED, "zsock_getsockopt() got invalid error %d", optval);

	ret = zsock_recv(new_sock, &rx_buf, sizeof(rx_buf), ZSOCK_MSG_DONTWAIT);
	zassert_equal(ret, -1, "zsock_recv() did not report error");
	zassert_equal(errno, ECONNABORTED, "Unexpected errno value: %d", errno);

	test_sockets_close();

	k_sleep(TCP_TEARDOWN_TIMEOUT);
}

ZTEST(net_socket_tls, test_poll_dtls_pollerr)
{
#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
	uint8_t rx_buf;
	int ret;
	struct zsock_pollfd fds[1];
	int optval;
	net_socklen_t optlen = sizeof(optval);
#if defined(CONFIG_WOLFSSL)
	WOLFSSL *ssl_ctx;
#else
	mbedtls_ssl_context *ssl_ctx;
#endif

	test_prepare_dtls_connection(NET_AF_INET6);

	fds[0].fd = s_sock;
	fds[0].events = ZSOCK_POLLIN;

	/* Get access to the underlying ssl context, and send alert. */
#if defined(CONFIG_WOLFSSL)
	ssl_ctx = ztls_get_wolfssl_context(c_sock);
	test_wolfssl_send_fatal_alert(ssl_ctx);
#else
	ssl_ctx = ztls_get_mbedtls_ssl_context(c_sock);
	mbedtls_ssl_send_alert_message(ssl_ctx, MBEDTLS_SSL_ALERT_LEVEL_FATAL,
				       MBEDTLS_SSL_ALERT_MSG_INTERNAL_ERROR);
#endif

	ret = zsock_poll(fds, 1, 100);
	zassert_equal(ret, 1, "poll() should've report event");
	zassert_true(fds[0].revents & ZSOCK_POLLERR, "No POLLERR event");

	ret = zsock_getsockopt(s_sock, ZSOCK_SOL_SOCKET, ZSOCK_SO_ERROR, &optval, &optlen);
	zassert_equal(ret, 0, "zsock_getsockopt() failed (%d)", errno);
	zassert_equal(optval, ECONNABORTED, "zsock_getsockopt() got invalid error %d", optval);

	/* DTLS server socket should recover and be ready to accept new session. */
	ret = zsock_recv(s_sock, &rx_buf, sizeof(rx_buf), ZSOCK_MSG_DONTWAIT);
	zassert_equal(ret, -1, "zsock_recv() did not report error");
	zassert_equal(errno, EAGAIN, "Unexpected errno value: %d", errno);

	test_sockets_close();

	/* Small delay for the final alert exchange */
	k_msleep(10);
#else
	ztest_test_skip();
#endif
}

#define BAD_CA_CERT_TAG 11
#define BAD_OWN_CERT_TAG 12
#define BAD_PRIV_KEY_TAG 13
#define BAD_PSK_TAG 14
#define BAD_NO_CRED_TAG 15

static void remove_bad_cred(void)
{
	(void)tls_credential_delete(BAD_CA_CERT_TAG, TLS_CREDENTIAL_CA_CERTIFICATE);
	(void)tls_credential_delete(BAD_OWN_CERT_TAG, TLS_CREDENTIAL_PUBLIC_CERTIFICATE);
	(void)tls_credential_delete(BAD_PRIV_KEY_TAG, TLS_CREDENTIAL_PRIVATE_KEY);
	(void)tls_credential_delete(BAD_PSK_TAG, TLS_CREDENTIAL_PSK);
	(void)tls_credential_delete(BAD_PSK_TAG, TLS_CREDENTIAL_PSK_ID);
}

static void test_bad_cred_common(bool test_dtls)
{
	static uint8_t bad_ca_cert[] = "bad ca cert";
	static uint8_t bad_own_cert[] = "bad own cert";
	static uint8_t bad_priv_key[] = "bad priv key";
	static uint8_t bad_psk[] = "bad psk"; /* PSK is not bad per se, but will
					       * try to use it without matching PSK ID.
					       */
	sec_tag_t bad_tags[] = {
		BAD_CA_CERT_TAG,
		BAD_OWN_CERT_TAG,
		BAD_PRIV_KEY_TAG,
		BAD_PSK_TAG,
		BAD_NO_CRED_TAG,
	};

	/* Preconfigure "bad" credentials */
	remove_bad_cred();

	zassert_ok(tls_credential_add(BAD_CA_CERT_TAG, TLS_CREDENTIAL_CA_CERTIFICATE,
				      bad_ca_cert, sizeof(bad_ca_cert)),
				      "Failed to add ca cert");
	zassert_ok(tls_credential_add(BAD_OWN_CERT_TAG, TLS_CREDENTIAL_PUBLIC_CERTIFICATE,
				      bad_own_cert, sizeof(bad_own_cert)),
				      "Failed to add own cert");
	zassert_ok(tls_credential_add(BAD_PRIV_KEY_TAG, TLS_CREDENTIAL_PRIVATE_KEY,
				      bad_priv_key, sizeof(bad_priv_key)),
				      "Failed to add priv key");
	zassert_ok(tls_credential_add(BAD_PSK_TAG, TLS_CREDENTIAL_PSK, bad_psk,
				      sizeof(bad_psk)), "Failed to add psk");

	if (test_dtls) {
		s_sock = zsock_socket(NET_AF_INET, NET_SOCK_DGRAM, NET_IPPROTO_DTLS_1_2);
	} else {
		s_sock = zsock_socket(NET_AF_INET, NET_SOCK_STREAM, NET_IPPROTO_TLS_1_2);
	}

	zassert_true(s_sock >= 0, "zsock_socket() failed");

	for (int i = 0; i < ARRAY_SIZE(bad_tags); i++) {
		sec_tag_t test_tag = bad_tags[i];
		int ret;

		ret = zsock_setsockopt(s_sock, ZSOCK_SOL_TLS, ZSOCK_TLS_SEC_TAG_LIST,
				       &test_tag, sizeof(test_tag));
		zassert_equal(ret, -1,
			      "zsock_setsockopt() should've failed with invalid credential");
		if (test_tag == BAD_NO_CRED_TAG) {
			zassert_equal(errno, ENOENT, "Unfound credential should fail with ENOENT");
		} else {
			zassert_equal(errno, EINVAL, "Bad credential should fail with EINVAL");
		}
	}

	test_sockets_close();
	remove_bad_cred();
}

ZTEST(net_socket_tls, test_tls_bad_cred)
{
	test_bad_cred_common(false);
}

ZTEST(net_socket_tls, test_dtls_bad_cred)
{
	test_bad_cred_common(true);
}

static void dtls_client_connect_send_no_assert_work_handler(struct k_work *work)
{
	struct k_work_delayable *dwork = k_work_delayable_from_work(work);
	struct connect_data *data =
		CONTAINER_OF(dwork, struct connect_data, work);
	uint8_t tx_buf = 0;
	int ret;

	ret = zsock_connect(data->sock, data->addr, data->addr->sa_family == NET_AF_INET ?
			    sizeof(struct net_sockaddr_in) : sizeof(struct net_sockaddr_in6));
	if (ret < 0) {
		return;
	}

	zsock_send(data->sock, &tx_buf, sizeof(tx_buf), 0);
}

static void dtls_verify_address(struct net_sockaddr *addr, net_socklen_t addrlen,
				struct net_sockaddr *expected)
{
	if (expected->sa_family == NET_AF_INET) {
		zassert_equal(addrlen, sizeof(struct net_sockaddr_in), "Address length mismatch");
		zassert_equal(net_sin(addr)->sin_family, NET_AF_INET, "Address family mismatch");
		zassert_equal(net_sin(addr)->sin_port, net_sin(expected)->sin_port,
			      "Address port mismatch");
		zassert_equal(net_sin(addr)->sin_addr.s_addr, net_sin(expected)->sin_addr.s_addr,
			      "Address mismatch");
	} else {
		zassert_equal(addrlen, sizeof(struct net_sockaddr_in6), "Address length mismatch");
		zassert_equal(net_sin6(addr)->sin6_family, NET_AF_INET6, "Address family mismatch");
		zassert_equal(net_sin6(addr)->sin6_port, net_sin6(expected)->sin6_port,
			      "Address port mismatch");
		zassert_mem_equal(net_sin6(addr)->sin6_addr.s6_addr,
				  net_sin6(expected)->sin6_addr.s6_addr,
				  NET_IPV6_ADDR_SIZE, "Address mismatch");
	}
}

static void test_dtls_server_multi_client_prepare_socks(net_sa_family_t family,
							struct net_sockaddr *s_saddr,
							struct net_sockaddr *c_saddr_1,
							struct net_sockaddr *c_saddr_2)
{
	net_socklen_t exp_addrlen = family == NET_AF_INET6 ?
				sizeof(struct net_sockaddr_in6) :
				sizeof(struct net_sockaddr_in);
	struct timeval timeo_optval = {
		.tv_sec = 1,
		.tv_usec = 0,
	};
	int role = ZSOCK_TLS_DTLS_ROLE_SERVER;

	if (family == NET_AF_INET6) {
		prepare_sock_dtls_v6(MY_IPV6_ADDR, CLIENT_1_PORT, &c_sock,
				     (struct net_sockaddr_in6 *)c_saddr_1,
				     NET_IPPROTO_DTLS_1_2);
		prepare_sock_dtls_v6(MY_IPV6_ADDR, CLIENT_2_PORT, &c_sock_2,
				     (struct net_sockaddr_in6 *)c_saddr_2,
				     NET_IPPROTO_DTLS_1_2);
		prepare_sock_dtls_v6(MY_IPV6_ADDR, SERVER_PORT, &s_sock,
				     (struct net_sockaddr_in6 *)s_saddr,
				     NET_IPPROTO_DTLS_1_2);
	} else {
		prepare_sock_dtls_v4(MY_IPV4_ADDR, CLIENT_1_PORT, &c_sock,
				     (struct net_sockaddr_in *)c_saddr_1,
				     NET_IPPROTO_DTLS_1_2);
		prepare_sock_dtls_v4(MY_IPV4_ADDR, CLIENT_2_PORT, &c_sock_2,
				     (struct net_sockaddr_in *)c_saddr_2,
				     NET_IPPROTO_DTLS_1_2);
		prepare_sock_dtls_v4(MY_IPV4_ADDR, SERVER_PORT, &s_sock,
				     (struct net_sockaddr_in *)s_saddr,
				     NET_IPPROTO_DTLS_1_2);
	}

	test_config_psk(s_sock, c_sock);
	test_config_psk(s_sock, c_sock_2);

	zassert_ok(zsock_setsockopt(s_sock, ZSOCK_SOL_TLS, ZSOCK_TLS_DTLS_ROLE,
				    &role, sizeof(role)),
		   "setsockopt failed (%d)", errno);
	zassert_ok(zsock_setsockopt(s_sock, ZSOCK_SOL_SOCKET, ZSOCK_SO_RCVTIMEO,
				    &timeo_optval, sizeof(timeo_optval)),
		   "setsockopt failed (%d)", errno);
	zassert_ok(zsock_setsockopt(c_sock, ZSOCK_SOL_SOCKET, ZSOCK_SO_RCVTIMEO,
				    &timeo_optval, sizeof(timeo_optval)),
		   "setsockopt failed (%d)", errno);
	zassert_ok(zsock_setsockopt(c_sock_2, ZSOCK_SOL_SOCKET, ZSOCK_SO_RCVTIMEO,
				    &timeo_optval, sizeof(timeo_optval)),
		   "setsockopt failed (%d)", errno);

	test_bind(c_sock, c_saddr_1, exp_addrlen);
	test_bind(c_sock_2, c_saddr_2, exp_addrlen);
	test_bind(s_sock, s_saddr, exp_addrlen);
}

static void test_dtls_server_multi_client_hs_in_poll(net_sa_family_t family)
{
	struct net_sockaddr c_saddr_1;
	struct net_sockaddr c_saddr_2;
	struct net_sockaddr s_saddr;
	struct net_sockaddr recv_addr;
	net_socklen_t recv_addrlen;
	struct connect_data test_data;
	struct zsock_pollfd fds[1];
	uint8_t tx_buf = 0;
	uint8_t rx_buf;
	int ret;

	test_dtls_server_multi_client_prepare_socks(family, &s_saddr, &c_saddr_1,
						    &c_saddr_2);
	zassert_equal(ztls_get_session_count(), 3, "Expected session count mismatch");

	/* Client 1 handshake */
	test_data.sock = c_sock;
	test_data.addr = &s_saddr;
	k_work_init_delayable(&test_data.work, dtls_client_connect_send_work_handler);
	test_work_reschedule(&test_data.work, K_NO_WAIT);

	/* DTLS has no separate call like accept() to know when the handshake
	 * is complete, therefore send a dummy byte once handshake is done to
	 * unblock poll().
	 */
	fds[0].fd = s_sock;
	fds[0].events = ZSOCK_POLLIN;
	ret = zsock_poll(fds, 1, 1000);
	zassert_equal(ret, 1, "poll() did not report data ready");
	zassert_equal(ztls_get_session_count(), 3,
		      "Server shouldn't have allocated extra session yet");

	/* Flush the dummy byte. */
	recv_addrlen = sizeof(recv_addr);
	ret = zsock_recvfrom(s_sock, &rx_buf, sizeof(rx_buf), 0,
			     &recv_addr, &recv_addrlen);
	zassert_equal(ret, sizeof(rx_buf), "recv() failed");
	dtls_verify_address(&recv_addr, recv_addrlen, &c_saddr_1);

	/* Client 2 handshake */
	test_data.sock = c_sock_2;
	test_data.addr = &s_saddr;
	k_work_init_delayable(&test_data.work, dtls_client_connect_send_no_assert_work_handler);
	test_work_reschedule(&test_data.work, K_NO_WAIT);

	/* DTLS has no separate call like accept() to know when the handshake
	 * is complete, therefore send a dummy byte once handshake is done to
	 * unblock poll().
	 */
	fds[0].fd = s_sock;
	fds[0].events = ZSOCK_POLLIN;
	ret = zsock_poll(fds, 1, 1000);
	zassert_equal(ret, 1, "poll() did not report data ready");
	zassert_equal(ztls_get_session_count(), 4, "Server should've allocated extra session");

	/* Flush the dummy byte. */
	recv_addrlen = sizeof(recv_addr);
	ret = zsock_recvfrom(s_sock, &rx_buf, sizeof(rx_buf), 0,
			     &recv_addr, &recv_addrlen);
	zassert_equal(ret, sizeof(rx_buf), "recv() failed");
	dtls_verify_address(&recv_addr, recv_addrlen, &c_saddr_2);

	/* Now as two sessions are established, send data from client 1 again. */
	test_send(c_sock, &tx_buf, sizeof(tx_buf), 0);

	/* And verify the server receives the data with correct address */
	fds[0].fd = s_sock;
	fds[0].events = ZSOCK_POLLIN;
	ret = zsock_poll(fds, 1, 1000);
	zassert_equal(ret, 1, "poll() did not report data ready");

	recv_addrlen = sizeof(recv_addr);
	ret = zsock_recvfrom(s_sock, &rx_buf, sizeof(rx_buf), 0,
			     &recv_addr, &recv_addrlen);
	zassert_equal(ret, sizeof(rx_buf), "recv() failed");
	dtls_verify_address(&recv_addr, recv_addrlen, &c_saddr_1);

	/* Repeat for client 2 again */
	test_send(c_sock_2, &tx_buf, sizeof(tx_buf), 0);

	/* And verify the server receives the data with correct address */
	fds[0].fd = s_sock;
	fds[0].events = ZSOCK_POLLIN;
	ret = zsock_poll(fds, 1, 1000);
	zassert_equal(ret, 1, "poll() did not report data ready");

	recv_addrlen = sizeof(recv_addr);
	ret = zsock_recvfrom(s_sock, &rx_buf, sizeof(rx_buf), 0,
			     &recv_addr, &recv_addrlen);
	zassert_equal(ret, sizeof(rx_buf), "recv() failed");
	dtls_verify_address(&recv_addr, recv_addrlen, &c_saddr_2);

	/* Close the first client session */
	test_close(c_sock);
	c_sock = -1;

	/* Let the server update sessions, poll should report POLLHUP. */
	fds[0].fd = s_sock;
	fds[0].events = ZSOCK_POLLIN;
	ret = zsock_poll(fds, 1, 10);
	zassert_equal(ret, 1, "poll() should report event");
	zassert_equal(fds[0].revents, ZSOCK_POLLHUP, "No POLLHUP event");

	/* Two sessions should've been released (one for client, one for server)
	 * and the server should still be able to receive data from the second client.
	 */
	zassert_equal(ztls_get_session_count(), 2, "Expected session count mismatch");

	test_send(c_sock_2, &tx_buf, sizeof(tx_buf), 0);

	fds[0].fd = s_sock;
	fds[0].events = ZSOCK_POLLIN;
	ret = zsock_poll(fds, 1, 1000);
	zassert_equal(ret, 1, "poll() did not report data ready");

	recv_addrlen = sizeof(recv_addr);
	ret = zsock_recvfrom(s_sock, &rx_buf, sizeof(rx_buf), 0,
			     &recv_addr, &recv_addrlen);
	zassert_equal(ret, sizeof(rx_buf), "recv() failed");
	dtls_verify_address(&recv_addr, recv_addrlen, &c_saddr_2);

	/* Close the second client session. */
	test_close(c_sock_2);
	c_sock_2 = -1;

	/* Let the server update sessions. */
	fds[0].fd = s_sock;
	fds[0].events = ZSOCK_POLLIN;
	ret = zsock_poll(fds, 1, 10);
	zassert_equal(ret, 1, "poll() should report event");
	zassert_equal(fds[0].revents, ZSOCK_POLLHUP, "No POLLHUP event");

	/* One session should be released (client), server socket needs at least
	 * one DTLS session to work with (even disconnected one).
	 */
	zassert_equal(ztls_get_session_count(), 1, "Expected session count mismatch");

	test_work_wait(&test_data.work);
}

ZTEST(net_socket_tls, test_v4_dtls_server_multi_client_hs_in_poll)
{
	test_dtls_server_multi_client_hs_in_poll(NET_AF_INET);
}

ZTEST(net_socket_tls, test_v6_dtls_server_multi_client_hs_in_poll)
{
	test_dtls_server_multi_client_hs_in_poll(NET_AF_INET6);
}

static void test_dtls_server_multi_client_hs_in_recvfrom(net_sa_family_t family)
{
	struct net_sockaddr c_saddr_1;
	struct net_sockaddr c_saddr_2;
	struct net_sockaddr s_saddr;
	struct net_sockaddr recv_addr;
	net_socklen_t recv_addrlen;
	struct connect_data test_data;
	uint8_t tx_buf = 0;
	uint8_t rx_buf;
	int ret;

	test_dtls_server_multi_client_prepare_socks(family, &s_saddr, &c_saddr_1,
						    &c_saddr_2);
	zassert_equal(ztls_get_session_count(), 3, "Expected session count mismatch");

	/* Client 1 handshake */
	test_data.sock = c_sock;
	test_data.addr = &s_saddr;
	k_work_init_delayable(&test_data.work, dtls_client_connect_send_work_handler);
	test_work_reschedule(&test_data.work, K_NO_WAIT);

	/* Block in recv for the handshake to complete. */
	recv_addrlen = sizeof(recv_addr);
	ret = zsock_recvfrom(s_sock, &rx_buf, sizeof(rx_buf), 0,
			     &recv_addr, &recv_addrlen);
	zassert_equal(ret, sizeof(rx_buf), "recv() failed");
	dtls_verify_address(&recv_addr, recv_addrlen, &c_saddr_1);
	zassert_equal(ztls_get_session_count(), 3,
		      "Server shouldn't have allocated extra session yet");

	/* Client 2 handshake */
	test_data.sock = c_sock_2;
	test_data.addr = &s_saddr;
	k_work_init_delayable(&test_data.work, dtls_client_connect_send_no_assert_work_handler);
	test_work_reschedule(&test_data.work, K_NO_WAIT);

	/* Block in recv for the second handshake to complete. */
	recv_addrlen = sizeof(recv_addr);
	ret = zsock_recvfrom(s_sock, &rx_buf, sizeof(rx_buf), 0,
			     &recv_addr, &recv_addrlen);
	zassert_equal(ret, sizeof(rx_buf), "recv() failed");
	dtls_verify_address(&recv_addr, recv_addrlen, &c_saddr_2);
	zassert_equal(ztls_get_session_count(), 4, "Server should've allocated extra session");

	/* Now as two sessions are established, send data from client 1 again. */
	test_send(c_sock, &tx_buf, sizeof(tx_buf), 0);

	/* And verify the server receives the data with correct address */
	recv_addrlen = sizeof(recv_addr);
	ret = zsock_recvfrom(s_sock, &rx_buf, sizeof(rx_buf), 0,
			     &recv_addr, &recv_addrlen);
	zassert_equal(ret, sizeof(rx_buf), "recv() failed");
	dtls_verify_address(&recv_addr, recv_addrlen, &c_saddr_1);

	/* Repeat for client 2 again */
	test_send(c_sock_2, &tx_buf, sizeof(tx_buf), 0);

	/* And verify the server receives the data with correct address */
	recv_addrlen = sizeof(recv_addr);
	ret = zsock_recvfrom(s_sock, &rx_buf, sizeof(rx_buf), 0,
			     &recv_addr, &recv_addrlen);
	zassert_equal(ret, sizeof(rx_buf), "recv() failed");
	dtls_verify_address(&recv_addr, recv_addrlen, &c_saddr_2);

	/* Close the second client session */
	test_close(c_sock_2);
	c_sock_2 = -1;

	/* Small delay for the alerts exchange */
	k_msleep(10);

	/* Let the server update sessions. */
	ret = zsock_recv(s_sock, &rx_buf, sizeof(rx_buf), ZSOCK_MSG_DONTWAIT);
	zassert_equal(ret, -1, "recv() should've reported EAGAIN");
	zassert_equal(errno, EAGAIN, "wrong errno value");

	/* Two sessions should've been released (one for client, one for server)
	 * and the server should still be able to receive data from the second client.
	 */
	zassert_equal(ztls_get_session_count(), 2, "Expected session count mismatch");

	test_send(c_sock, &tx_buf, sizeof(tx_buf), 0);

	recv_addrlen = sizeof(recv_addr);
	ret = zsock_recvfrom(s_sock, &rx_buf, sizeof(rx_buf), 0,
			     &recv_addr, &recv_addrlen);
	zassert_equal(ret, sizeof(rx_buf), "recv() failed");
	dtls_verify_address(&recv_addr, recv_addrlen, &c_saddr_1);

	/* Close the first client session. */
	test_close(c_sock);
	c_sock = -1;

	/* Small delay for the alerts exchange */
	k_msleep(10);

	/* Let the server update sessions. */
	ret = zsock_recv(s_sock, &rx_buf, sizeof(rx_buf), ZSOCK_MSG_DONTWAIT);
	zassert_equal(ret, -1, "recv() should've reported EAGAIN");
	zassert_equal(errno, EAGAIN, "wrong errno value");

	/* One session should be released (client), server socket needs at least
	 * one DTLS session to work with (even disconnected one).
	 */
	zassert_equal(ztls_get_session_count(), 1, "Expected session count mismatch");

	test_work_wait(&test_data.work);
}

ZTEST(net_socket_tls, test_v4_dtls_server_multi_client_hs_in_recvfrom)
{
	test_dtls_server_multi_client_hs_in_recvfrom(NET_AF_INET);
}

ZTEST(net_socket_tls, test_v6_dtls_server_multi_client_hs_in_recvfrom)
{
	test_dtls_server_multi_client_hs_in_recvfrom(NET_AF_INET6);
}

static void test_dtls_server_multi_client_prepare_two_connections(
	net_sa_family_t family, struct net_sockaddr *s_saddr,
	struct net_sockaddr *c_saddr_1, struct net_sockaddr *c_saddr_2,
	int32_t delay)
{
	struct connect_data test_data;
	uint8_t rx_buf;
	int ret;

	test_dtls_server_multi_client_prepare_socks(family, s_saddr, c_saddr_1,
						    c_saddr_2);
	/* Client 1 handshake */
	test_data.sock = c_sock;
	test_data.addr = s_saddr;
	k_work_init_delayable(&test_data.work, dtls_client_connect_send_work_handler);
	test_work_reschedule(&test_data.work, K_NO_WAIT);

	/* Block in recv for the handshake to complete. */
	ret = zsock_recvfrom(s_sock, &rx_buf, sizeof(rx_buf), 0, NULL, NULL);
	zassert_equal(ret, sizeof(rx_buf), "recv() failed");

	if (delay > 0) {
		k_msleep(delay);
	}

	/* Client 2 handshake */
	test_data.sock = c_sock_2;
	test_data.addr = s_saddr;
	k_work_init_delayable(&test_data.work, dtls_client_connect_send_no_assert_work_handler);
	test_work_reschedule(&test_data.work, K_NO_WAIT);

	/* Block in recv for the second handshake to complete. */
	ret = zsock_recvfrom(s_sock, &rx_buf, sizeof(rx_buf), 0, NULL, NULL);
	zassert_equal(ret, sizeof(rx_buf), "recv() failed");

	test_work_wait(&test_data.work);
}

static void test_dtls_server_multi_client_sendto(net_sa_family_t family)
{
	struct net_sockaddr c_saddr_1;
	struct net_sockaddr c_saddr_2;
	struct net_sockaddr s_saddr;
	net_socklen_t addrlen = family == NET_AF_INET6 ?
			    sizeof(struct net_sockaddr_in6) :
			    sizeof(struct net_sockaddr_in);
	uint8_t tx_buf = 0;
	uint8_t rx_buf;
	int ret;

	test_dtls_server_multi_client_prepare_two_connections(family, &s_saddr,
							      &c_saddr_1, &c_saddr_2, 0);
	zassert_equal(ztls_get_session_count(), 4, "Expected session count mismatch");

	/* As two sessions are established, send data from server to client 1. */
	test_sendto(s_sock, &tx_buf, sizeof(tx_buf), 0, &c_saddr_1, addrlen);
	ret = zsock_recv(c_sock, &rx_buf, sizeof(rx_buf), 0);
	zassert_equal(ret, sizeof(rx_buf), "recv() failed");

	/* Now to client 2. */
	test_sendto(s_sock, &tx_buf, sizeof(tx_buf), 0, &c_saddr_2, addrlen);
	ret = zsock_recv(c_sock_2, &rx_buf, sizeof(rx_buf), 0);
	zassert_equal(ret, sizeof(rx_buf), "recv() failed");

	/* And back to client 1 again. */
	test_sendto(s_sock, &tx_buf, sizeof(tx_buf), 0, &c_saddr_1, addrlen);
	ret = zsock_recv(c_sock, &rx_buf, sizeof(rx_buf), 0);
	zassert_equal(ret, sizeof(rx_buf), "recv() failed");

	/* Close the first client session */
	test_close(c_sock);
	c_sock = -1;

	/* Small delay for the alerts exchange */
	k_msleep(10);

	/* Let the server update sessions. */
	ret = zsock_recv(s_sock, &rx_buf, sizeof(rx_buf), ZSOCK_MSG_DONTWAIT);
	zassert_equal(ret, -1, "recv() should've reported EAGAIN");
	zassert_equal(errno, EAGAIN, "wrong errno value");

	/* Two sessions should've been released (one for client, one for server)
	 * and the server should still be able to receive data from the second client.
	 */
	zassert_equal(ztls_get_session_count(), 2, "Expected session count mismatch");

	/* Sending to second client should still work */
	test_sendto(s_sock, &tx_buf, sizeof(tx_buf), 0, &c_saddr_2, addrlen);
	ret = zsock_recv(c_sock_2, &rx_buf, sizeof(rx_buf), 0);
	zassert_equal(ret, sizeof(rx_buf), "recv() failed");

	/* Sending to the first client should fail though. */
	ret = zsock_sendto(s_sock, &tx_buf, sizeof(tx_buf), 0, &c_saddr_1, addrlen);
	zassert_equal(ret, -1, "zsock_sendto() should've failed");
	zassert_equal(errno, ENOTCONN, "wrong errno");

	/* Close the second client session. */
	test_close(c_sock_2);
	c_sock_2 = -1;

	/* Small delay for the alerts exchange */
	k_msleep(10);

	/* Let the server update sessions. */
	ret = zsock_recv(s_sock, &rx_buf, sizeof(rx_buf), ZSOCK_MSG_DONTWAIT);
	zassert_equal(ret, -1, "recv() should've reported EAGAIN");
	zassert_equal(errno, EAGAIN, "wrong errno value");

	/* One session should be released (client), server socket needs at least
	 * one DTLS session to work with (even disconnected one).
	 */
	zassert_equal(ztls_get_session_count(), 1, "Expected session count mismatch");

	/* But sending to the second client should fail now. */
	ret = zsock_sendto(s_sock, &tx_buf, sizeof(tx_buf), 0, &c_saddr_2, addrlen);
	zassert_equal(ret, -1, "zsock_sendto() should've failed");
	zassert_equal(errno, ENOTCONN, "wrong errno");
}

ZTEST(net_socket_tls, test_v4_dtls_server_multi_client_sendto)
{
	test_dtls_server_multi_client_sendto(NET_AF_INET);
}

ZTEST(net_socket_tls, test_v6_dtls_server_multi_client_sendto)
{
	test_dtls_server_multi_client_sendto(NET_AF_INET6);
}

static void test_dtls_server_cid_matching_on_addr_change(net_sa_family_t family)
{
	struct net_sockaddr c_saddr_1;
	struct net_sockaddr c_saddr_2;
	struct net_sockaddr c_saddr_1_backup;
	struct net_sockaddr s_saddr;
	struct net_sockaddr recv_addr;
	net_socklen_t recv_addrlen;
	net_socklen_t addrlen = family == NET_AF_INET6 ?
				sizeof(struct net_sockaddr_in6) :
				sizeof(struct net_sockaddr_in);
	struct connect_data test_data;
	uint8_t tx_buf = 0;
	uint8_t rx_buf;
	int cid, ret;

	if (!IS_ENABLED(CONFIG_MBEDTLS_SSL_DTLS_CONNECTION_ID)) {
		ztest_test_skip();
	}

	test_dtls_server_multi_client_prepare_socks(family, &s_saddr, &c_saddr_1,
						    &c_saddr_2);
	zassert_equal(ztls_get_session_count(), 3, "Expected session count mismatch");

	/* Enable DTLS CID for clients */
	cid = ZSOCK_TLS_DTLS_CID_ENABLED;
	zassert_ok(zsock_setsockopt(c_sock, ZSOCK_SOL_TLS, ZSOCK_TLS_DTLS_CID,
		   &cid, sizeof(cid)), "setsockopt failed (%d)", errno);
	zassert_ok(zsock_setsockopt(c_sock_2, ZSOCK_SOL_TLS, ZSOCK_TLS_DTLS_CID,
		   &cid, sizeof(cid)), "setsockopt failed (%d)", errno);

	/* And enable CID processing for server */
	cid = ZSOCK_TLS_DTLS_CID_SUPPORTED;
	zassert_ok(zsock_setsockopt(s_sock, ZSOCK_SOL_TLS, ZSOCK_TLS_DTLS_CID,
		   &cid, sizeof(cid)), "setsockopt failed (%d)", errno);

	/* Client 1 handshake */
	test_data.sock = c_sock;
	test_data.addr = &s_saddr;
	k_work_init_delayable(&test_data.work, dtls_client_connect_send_work_handler);
	test_work_reschedule(&test_data.work, K_NO_WAIT);

	/* Block in recv for the handshake to complete. */
	recv_addrlen = sizeof(recv_addr);
	ret = zsock_recvfrom(s_sock, &rx_buf, sizeof(rx_buf), 0,
			     &recv_addr, &recv_addrlen);
	zassert_equal(ret, sizeof(rx_buf), "recv() failed");
	dtls_verify_address(&recv_addr, recv_addrlen, &c_saddr_1);
	zassert_equal(ztls_get_session_count(), 3,
		      "Server shouldn't have allocated extra session");

	/* Rebind the client socket to a different port */
	c_saddr_1_backup = c_saddr_1;
	if (family == NET_AF_INET) {
		net_sin(&c_saddr_1)->sin_port = net_htons(CLIENT_3_PORT);
	} else {
		net_sin6(&c_saddr_1)->sin6_port = net_htons(CLIENT_3_PORT);
	}

	test_bind(c_sock, &c_saddr_1, addrlen);

	/* After rebinding, try to send some data to the server. */
	test_send(c_sock, &tx_buf, sizeof(tx_buf), 0);

	/* And verify the server receives the data with correct address */
	recv_addrlen = sizeof(recv_addr);
	ret = zsock_recvfrom(s_sock, &rx_buf, sizeof(rx_buf), 0,
			     &recv_addr, &recv_addrlen);
	zassert_equal(ret, sizeof(rx_buf), "recv() failed");
	dtls_verify_address(&recv_addr, recv_addrlen, &c_saddr_1);

	/* No new session should've been spawned */
	zassert_equal(ztls_get_session_count(), 3,
		      "Server shouldn't have allocated extra session");

	/* Sending back with the old address should fail */
	ret = zsock_sendto(s_sock, &tx_buf, sizeof(tx_buf), 0, &c_saddr_1_backup,
			   addrlen);
	zassert_equal(ret, -1, "zsock_sendto() should've failed");
	zassert_equal(errno, ENOTCONN, "wrong errno");

	/* Sending back with the new address should succeed */
	test_sendto(s_sock, &tx_buf, sizeof(tx_buf), 0, &c_saddr_1, addrlen);
	ret = zsock_recv(c_sock, &rx_buf, sizeof(rx_buf), 0);
	zassert_equal(ret, sizeof(tx_buf), "recv() failed");

	/* New client connecting with the "old" address but different CID */
	c_saddr_2 = c_saddr_1_backup;
	test_bind(c_sock_2, &c_saddr_2, addrlen);

	/* Client 2 handshake */
	test_data.sock = c_sock_2;
	test_data.addr = &s_saddr;
	k_work_init_delayable(&test_data.work, dtls_client_connect_send_work_handler);
	test_work_reschedule(&test_data.work, K_NO_WAIT);

	/* Block in recv for the handshake to complete. */
	recv_addrlen = sizeof(recv_addr);
	ret = zsock_recvfrom(s_sock, &rx_buf, sizeof(rx_buf), 0,
			     &recv_addr, &recv_addrlen);
	zassert_equal(ret, sizeof(rx_buf), "recv() failed");
	dtls_verify_address(&recv_addr, recv_addrlen, &c_saddr_2);
	/* New session should be spawned */
	zassert_equal(ztls_get_session_count(), 4,
		      "Server should have allocated new session");

	/* Rebind the second client socket to a different port */
	if (family == NET_AF_INET) {
		net_sin(&c_saddr_2)->sin_port = net_htons(CLIENT_2_PORT);
	} else {
		net_sin6(&c_saddr_2)->sin6_port = net_htons(CLIENT_2_PORT);
	}

	test_bind(c_sock_2, &c_saddr_2, addrlen);

	/* After rebinding, try to send some data to the server. */
	test_send(c_sock_2, &tx_buf, sizeof(tx_buf), 0);

	/* And verify the server receives the data with correct address */
	recv_addrlen = sizeof(recv_addr);
	ret = zsock_recvfrom(s_sock, &rx_buf, sizeof(rx_buf), 0,
			     &recv_addr, &recv_addrlen);
	zassert_equal(ret, sizeof(rx_buf), "recv() failed");
	dtls_verify_address(&recv_addr, recv_addrlen, &c_saddr_2);

	/* No new session should've been spawned */
	zassert_equal(ztls_get_session_count(), 4,
		      "Server shouldn't have allocated extra session");

	/* Close both clients and verify session count dropped. */
	test_close(c_sock);
	test_close(c_sock_2);
	c_sock = -1;
	c_sock_2 = -1;

	/* Small delay for the alerts exchange */
	k_msleep(10);

	/* Let the server update sessions. */
	ret = zsock_recv(s_sock, &rx_buf, sizeof(rx_buf), ZSOCK_MSG_DONTWAIT);
	zassert_equal(ret, -1, "recv() should've reported EAGAIN");
	zassert_equal(errno, EAGAIN, "wrong errno value");

	zassert_equal(ztls_get_session_count(), 1, "Leftover sessions!");

	test_work_wait(&test_data.work);
}

ZTEST(net_socket_tls, test_v4_dtls_server_cid_matching_on_addr_change)
{
	test_dtls_server_cid_matching_on_addr_change(NET_AF_INET);
}

ZTEST(net_socket_tls, test_v6_dtls_server_cid_matching_on_addr_change)
{
	test_dtls_server_cid_matching_on_addr_change(NET_AF_INET6);
}

/* Poll a non-blocking recv until the DTLS peer's close-notify has been
 * processed and the socket reports ENOTCONN, or a short bound elapses. On
 * native_sim loopback delivery is synchronous and the first recv already sees
 * the alert; on targets with asynchronous delivery (e.g. real hardware) this
 * waits for the in-flight alert instead of racing a fixed guess delay. A
 * genuinely missing close-notify is NOT masked: errno stays EAGAIN, the bound
 * expires, and the caller's ENOTCONN assertion fails.
 */
static int recv_await_peer_closed(int sock)
{
	uint8_t rx_buf;
	int ret = -1;

	for (int i = 0; i < 20; i++) {
		ret = zsock_recv(sock, &rx_buf, sizeof(rx_buf), ZSOCK_MSG_DONTWAIT);
		if (ret == -1 && errno == ENOTCONN) {
			break;
		}
		k_msleep(5);
	}

	return ret;
}

static void test_dtls_server_session_timeout_poll(net_sa_family_t family)
{
	struct net_sockaddr c_saddr_1;
	struct net_sockaddr c_saddr_2;
	struct net_sockaddr s_saddr;
	int32_t delay = CONFIG_NET_SOCKETS_DTLS_TIMEOUT / 2 + 100;
	struct zsock_pollfd fds[1];
	uint8_t rx_buf;
	int ret;

	test_dtls_server_multi_client_prepare_two_connections(
		family, &s_saddr, &c_saddr_1, &c_saddr_2, delay);
	zassert_equal(ztls_get_session_count(), 4, "Expected session count mismatch");

	/* First client session should time out */
	fds[0].fd = s_sock;
	fds[0].events = ZSOCK_POLLIN;
	ret = zsock_poll(fds, 1, delay);
	zassert_equal(ret, 1, "poll() did not report data ready");
	zassert_equal(fds[0].revents, ZSOCK_POLLHUP, "expected ZSOCK_POLLHUP");
	zassert_equal(ztls_get_session_count(), 3, "Expected session count mismatch");

	/* Verify client socket reports error (server closed the session). The
	 * close-notify may still be in flight on targets with asynchronous
	 * loopback delivery, so poll for it instead of racing a fixed delay.
	 */
	ret = recv_await_peer_closed(c_sock);
	zassert_equal(ret, -1, "recv() should've failed");
	zassert_equal(errno, ENOTCONN, "Wrong errno, expected ENOTCONN");

	/* Second client should still be operational */
	ret = zsock_recv(c_sock_2, &rx_buf, sizeof(rx_buf), ZSOCK_MSG_DONTWAIT);
	/* Not really an error (EAGAIN) */
	zassert_equal(ret, -1, "recv() should've failed");
	zassert_equal(errno, EAGAIN, "Wrong errno, expected EAGAIN");

	/* Second client session should time out */
	fds[0].fd = s_sock;
	fds[0].events = ZSOCK_POLLIN;
	ret = zsock_poll(fds, 1, delay);
	zassert_equal(ret, 1, "poll() did not report data ready");
	zassert_equal(fds[0].revents, ZSOCK_POLLHUP, "expected ZSOCK_POLLHUP");
	zassert_equal(ztls_get_session_count(), 3, "Expected session count mismatch");

	/* Verify second client socket reports error (server closed the session). */
	ret = recv_await_peer_closed(c_sock_2);
	zassert_equal(ret, -1, "recv() should've failed");
	zassert_equal(errno, ENOTCONN, "Wrong errno, expected ENOTCONN");
}

ZTEST(net_socket_tls, test_v4_dtls_server_session_timeout_poll)
{
	test_dtls_server_session_timeout_poll(NET_AF_INET);
}

ZTEST(net_socket_tls, test_v6_dtls_server_session_timeout_poll)
{
	test_dtls_server_session_timeout_poll(NET_AF_INET6);
}

static void test_dtls_server_session_timeout_recvfrom(net_sa_family_t family)
{
	struct net_sockaddr c_saddr_1;
	struct net_sockaddr c_saddr_2;
	struct net_sockaddr s_saddr;
	int32_t delay = CONFIG_NET_SOCKETS_DTLS_TIMEOUT / 2 + 100;
	struct timeval timeo_optval;
	uint8_t rx_buf;
	int ret;

	timeo_optval.tv_sec = 0;
	timeo_optval.tv_usec = delay * USEC_PER_MSEC;

	test_dtls_server_multi_client_prepare_two_connections(
		family, &s_saddr, &c_saddr_1, &c_saddr_2, delay);
	zassert_equal(ztls_get_session_count(), 4, "Expected session count mismatch");

	zassert_ok(zsock_setsockopt(s_sock, ZSOCK_SOL_SOCKET, ZSOCK_SO_RCVTIMEO,
				    &timeo_optval, sizeof(timeo_optval)),
		   "setsockopt failed (%d)", errno);

	/* Block in recv, it should timeout, and the first client should've timed
	 * out at this point.
	 */
	ret = zsock_recvfrom(s_sock, &rx_buf, sizeof(rx_buf), 0, NULL, NULL);
	zassert_equal(ret, -1, "recv() should've timed out");
	zassert_equal(errno, EAGAIN, "Wrong errno, expected EAGAIN");
	zassert_equal(ztls_get_session_count(), 3, "Expected session count mismatch");

	/* Verify client socket reports error (server closed the session). The
	 * close-notify may still be in flight on targets with asynchronous
	 * loopback delivery, so poll for it instead of racing a fixed delay.
	 */
	ret = recv_await_peer_closed(c_sock);
	zassert_equal(ret, -1, "recv() should've failed");
	zassert_equal(errno, ENOTCONN, "Wrong errno, expected ENOTCONN");

	/* Second client should still be operational */
	ret = zsock_recv(c_sock_2, &rx_buf, sizeof(rx_buf), ZSOCK_MSG_DONTWAIT);
	/* Not really an error (EAGAIN) */
	zassert_equal(ret, -1, "recv() should've failed");
	zassert_equal(errno, EAGAIN, "Wrong errno, expected EAGAIN");

	/* Second client session should time out */
	ret = zsock_recvfrom(s_sock, &rx_buf, sizeof(rx_buf), 0, NULL, NULL);
	zassert_equal(ret, -1, "recv() should've timed out");
	zassert_equal(errno, EAGAIN, "Wrong errno, expected EAGAIN");
	zassert_equal(ztls_get_session_count(), 3, "Expected session count mismatch");

	/* Verify second client socket reports error (server closed the session). */
	ret = recv_await_peer_closed(c_sock_2);
	zassert_equal(ret, -1, "recv() should've failed");
	zassert_equal(errno, ENOTCONN, "Wrong errno, expected ENOTCONN");
}

ZTEST(net_socket_tls, test_v4_dtls_server_session_timeout_recvfrom)
{
	test_dtls_server_session_timeout_recvfrom(NET_AF_INET);
}

ZTEST(net_socket_tls, test_v6_dtls_server_session_timeout_recvfrom)
{
	test_dtls_server_session_timeout_recvfrom(NET_AF_INET6);
}

ZTEST(net_socket_tls, test_tls13_psk_handshake)
{
#if !defined(WOLFSSL_TLS13) || !defined(CONFIG_WOLFSSL)
	ztest_test_skip();
	return;
#else
	struct net_sockaddr_in6 c_saddr, s_saddr;
	struct net_sockaddr addr;
	net_socklen_t addrlen = sizeof(addr);
	struct connect_data test_data;
	uint8_t tx_buf[] = TEST_STR_SMALL;
	uint8_t rx_buf[sizeof(tx_buf)];
	int ret;
	int optval;
	net_socklen_t optlen = sizeof(optval);

	prepare_sock_tls_v6(MY_IPV6_ADDR, ANY_PORT, &c_sock,
			    &c_saddr, NET_IPPROTO_TLS_1_3);
	prepare_sock_tls_v6(MY_IPV6_ADDR, ANY_PORT, &s_sock,
			    &s_saddr, NET_IPPROTO_TLS_1_3);

	test_config_psk(s_sock, c_sock);

	test_bind(s_sock, (struct net_sockaddr *)&s_saddr,
		  sizeof(struct net_sockaddr_in6));
	test_listen(s_sock);

	test_data.sock = c_sock;
	test_data.addr = (struct net_sockaddr *)&s_saddr;
	k_work_init_delayable(&test_data.work,
			      client_connect_work_handler);
	test_work_reschedule(&test_data.work, K_NO_WAIT);

	test_accept(s_sock, &new_sock, &addr, &addrlen);
	test_work_wait(&test_data.work);

	/* Verify protocol is TLS 1.3 via socket option */
	ret = zsock_getsockopt(new_sock, ZSOCK_SOL_SOCKET, ZSOCK_SO_PROTOCOL,
			       &optval, &optlen);
	zassert_equal(ret, 0, "getsockopt failed (%d)", errno);
	zassert_equal(optval, NET_IPPROTO_TLS_1_3,
		      "Expected TLS 1.3 protocol");

	/* Verify TLS 1.3 was actually negotiated, not just requested */
	{
		WOLFSSL *ssl = ztls_get_wolfssl_context(new_sock);

		zassert_not_null(ssl, "Failed to get wolfSSL context");
		zassert_equal(wolfSSL_GetVersion(ssl), WOLFSSL_TLSV1_3,
			      "Negotiated version is not TLS 1.3");
	}

	/* Send and receive */
	test_send(c_sock, tx_buf, sizeof(tx_buf), 0);
	ret = zsock_recv(new_sock, rx_buf, sizeof(rx_buf), 0);
	zassert_equal(ret, sizeof(tx_buf), "recv() failed");
	zassert_mem_equal(rx_buf, tx_buf, sizeof(tx_buf),
			  "Data mismatch");

	test_sockets_close();

	k_sleep(TCP_TEARDOWN_TIMEOUT);
#endif
}

static void *tls_tests_setup(void)
{
	k_work_queue_init(&tls_test_work_queue);
	k_work_queue_start(&tls_test_work_queue, tls_test_work_queue_stack,
			   K_THREAD_STACK_SIZEOF(tls_test_work_queue_stack),
			   K_LOWEST_APPLICATION_THREAD_PRIO, NULL);

	return NULL;
}

static void tls_tests_after(void *arg)
{
	ARG_UNUSED(arg);

	test_sockets_close();
}

ZTEST_SUITE(net_socket_tls, NULL, tls_tests_setup, NULL, tls_tests_after, NULL);
