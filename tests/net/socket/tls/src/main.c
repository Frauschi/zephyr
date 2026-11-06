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
/* IANA IDs (RFC 5487), which both backends accept */
#define TEST_TLS_PSK_WITH_AES_128_GCM_SHA256  0x00A8
#define TEST_TLS_PSK_WITH_AES_256_CBC_SHA384  0x00AF

#if defined(CONFIG_WOLFSSL)
#ifndef WOLFSSL_USER_SETTINGS
#include <user_settings.h>
#endif
#include <wolfssl/ssl.h>
#include <zephyr/net/tls_verify.h>
#include "tcp_internal.h"
WOLFSSL *ztls_get_wolfssl_context(int fd);
/* In wolfssl_alert.c, which keeps <wolfssl/internal.h> out of this file */
void test_wolfssl_send_fatal_alert(WOLFSSL *ssl);
void test_wolfssl_mark_close_notify_sent(WOLFSSL *ssl);
int test_wolfssl_max_psk_id_len(void);
/* Collect the records a session sends, and send them as one datagram */
void test_wolfssl_hold_records(WOLFSSL *ssl);
int test_wolfssl_send_held_records(WOLFSSL *ssl);
int test_wolfssl_dtls_timeout_max(WOLFSSL *ssl);
#endif

#if defined(CONFIG_MBEDTLS)
/* The BIO callbacks of a socket are needed to build a datagram that carries
 * two DTLS records.
 */
#if !defined(MBEDTLS_ALLOW_PRIVATE_ACCESS)
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#endif
#include <mbedtls/ssl.h>
mbedtls_ssl_context *ztls_get_mbedtls_ssl_context(int fd);
#endif

#include "../../socket_helpers.h"

#if defined(CONFIG_NET_SOCKETS_TLS_SESSION_CACHE_PERSISTENT)
#include <zephyr/settings/settings.h>
#endif

uint32_t ztls_get_session_count(void);

/* The SO_RCVBUF tests depend on the record overhead of this one mbedTLS suite */
static const int cipher_list_psk[] = {
	TEST_TLS_PSK_WITH_AES_256_CBC_SHA384,
	TEST_TLS_PSK_WITH_AES_128_GCM_SHA256
};

/* TLS_AES_128_GCM_SHA256, since test_config_psk() pins a TLS 1.2 suite */
static const int tls13_cipher_list[] = {
	0x1301,
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
/* The client cache is keyed by peer address, so resumption needs a fixed port of its own */
#define RESUME_SERVER_PORT 4246

#define PSK_TAG 1

#define MAX_CONNS 5

#define TCP_TEARDOWN_TIMEOUT K_MSEC(CONFIG_NET_TCP_TIME_WAIT_DELAY)

#define TLS_TEST_WORK_QUEUE_STACK_SIZE 4096

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
static const char *test_psk_id = psk_id;

static void test_config_tls13_suites(int s_sock, int c_sock)
{
	if (s_sock >= 0) {
		zassert_ok(zsock_setsockopt(s_sock, ZSOCK_SOL_TLS, ZSOCK_TLS_CIPHERSUITE_LIST,
					    tls13_cipher_list, sizeof(tls13_cipher_list)));
	}

	if (c_sock >= 0) {
		zassert_ok(zsock_setsockopt(c_sock, ZSOCK_SOL_TLS, ZSOCK_TLS_CIPHERSUITE_LIST,
					    tls13_cipher_list, sizeof(tls13_cipher_list)));
	}
}

static void test_config_psk(int s_sock, int c_sock)
{
	sec_tag_t sec_tag_list[] = {
		PSK_TAG
	};
	const int cipher_list[] = {
		TEST_TLS_PSK_WITH_AES_256_CBC_SHA384,
	};

	(void)tls_credential_delete(PSK_TAG, TLS_CREDENTIAL_PSK);
	(void)tls_credential_delete(PSK_TAG, TLS_CREDENTIAL_PSK_ID);

	zassert_equal(tls_credential_add(PSK_TAG, TLS_CREDENTIAL_PSK,
					 psk, sizeof(psk)),
		      0, "Failed to register PSK");
	zassert_equal(tls_credential_add(PSK_TAG, TLS_CREDENTIAL_PSK_ID,
					 test_psk_id, strlen(test_psk_id)),
		      0, "Failed to register PSK ID");

	if (s_sock >= 0) {
		zassert_equal(zsock_setsockopt(s_sock, ZSOCK_SOL_TLS, ZSOCK_TLS_SEC_TAG_LIST,
					 sec_tag_list, sizeof(sec_tag_list)),
			      0, "Failed to set PSK on server socket");
		zassert_equal(zsock_setsockopt(s_sock, ZSOCK_SOL_TLS, ZSOCK_TLS_CIPHERSUITE_LIST,
					 cipher_list, sizeof(cipher_list)),
			      0, "Failed to set ciphersuite list on server socket");
	}

	if (c_sock >= 0) {
		zassert_equal(zsock_setsockopt(c_sock, ZSOCK_SOL_TLS, ZSOCK_TLS_SEC_TAG_LIST,
					 sec_tag_list, sizeof(sec_tag_list)),
			      0, "Failed to set PSK on client socket");
		zassert_equal(zsock_setsockopt(c_sock, ZSOCK_SOL_TLS, ZSOCK_TLS_CIPHERSUITE_LIST,
					 cipher_list, sizeof(cipher_list)),
			      0, "Failed to set ciphersuite list on client socket");
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

static void close_and_invalidate(int *sock)
{
	(void)zsock_close(*sock);
	*sock = -1;
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
	int *peer_sock;
	const uint8_t *data;
	size_t offset;
	int retries;
};

static void test_msg_waitall_tx_work_handler(struct k_work *work)
{
	struct k_work_delayable *dwork = k_work_delayable_from_work(work);
	struct test_msg_waitall_data *test_data =
		CONTAINER_OF(dwork, struct test_msg_waitall_data, tx_work);
	int ret;

	while (test_data->retries > 0) {
		ret = zsock_send(test_data->sock, test_data->data + test_data->offset, 1, 0);
		if (ret < 0) {
			printk("zsock_send() failed (%d)\n", errno);
			close_and_invalidate(test_data->peer_sock);
			return;
		}
		if (ret != 1) {
			printk("zsock_send() sent %d instead of 1\n", ret);
			close_and_invalidate(test_data->peer_sock);
			return;
		}

		test_data->offset++;
		test_data->retries--;
		k_msleep(10);
	}
}

struct connect_data {
	struct k_work_delayable work;
	int sock;
	int *peer_sock;
	struct net_sockaddr *addr;
};

static void client_connect_work_handler(struct k_work *work)
{
	struct k_work_delayable *dwork = k_work_delayable_from_work(work);
	struct connect_data *data =
		CONTAINER_OF(dwork, struct connect_data, work);
	int ret;

	ret = zsock_connect(data->sock, data->addr, data->addr->sa_family == NET_AF_INET ?
			    sizeof(struct net_sockaddr_in) : sizeof(struct net_sockaddr_in6));
	if (ret < 0) {
		printk("zsock_connect() failed (%d)\n", errno);
		close_and_invalidate(data->peer_sock);
		return;
	}
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
	int ret;

	ret = zsock_connect(data->sock, data->addr, data->addr->sa_family == NET_AF_INET ?
			    sizeof(struct net_sockaddr_in) : sizeof(struct net_sockaddr_in6));
	if (ret < 0) {
		printk("zsock_connect() failed (%d)\n", errno);
		close_and_invalidate(data->peer_sock);
		return;
	}

	ret = zsock_send(data->sock, &tx_buf, sizeof(tx_buf), 0);
	if (ret < 0) {
		printk("zsock_send() failed (%d)\n", errno);
		close_and_invalidate(data->peer_sock);
		return;
	}
	if (ret != sizeof(tx_buf)) {
		printk("zsock_send() sent %d instead of %zu\n", ret, sizeof(tx_buf));
		close_and_invalidate(data->peer_sock);
		return;
	}
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
	test_data.peer_sock = &s_sock;
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
	test_data.peer_sock = &s_sock;
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

/* A handshake timeout near UINT32_MAX ms must not wrap when wolfSSL takes it in seconds */
ZTEST(net_socket_tls, test_dtls_handshake_timeout_max_large)
{
#if !defined(CONFIG_WOLFSSL) || !defined(WOLFSSL_DTLS)
	ztest_test_skip();
#else
	uint32_t timeout_max = UINT32_MAX;

	test_prepare_dtls_connection(NET_AF_INET);

	zassert_ok(zsock_setsockopt(c_sock, ZSOCK_SOL_TLS, ZSOCK_TLS_DTLS_HANDSHAKE_TIMEOUT_MAX,
				    &timeout_max, sizeof(timeout_max)));
	zassert_equal(test_wolfssl_dtls_timeout_max(ztls_get_wolfssl_context(c_sock)),
		      DIV_ROUND_UP((uint64_t)UINT32_MAX, MSEC_PER_SEC),
		      "wolfSSL got a wrapped DTLS timeout maximum");

	test_sockets_close();
#endif
}

void loopback_enable_address_swap(bool swap_addresses);

/* A wildcard-bound DTLS server answers from whichever address the client sent to */
ZTEST(net_socket_tls, test_dtls_server_replies_from_local_addr)
{
#if !defined(CONFIG_NET_CONTEXT_RECV_PKTINFO)
	ztest_test_skip();
#else
	static const char *const dst_addrs[] = { MY_IPV4_ADDR, "127.0.0.2" };
	const char *failed_addr = NULL;
	int unused_sock = -1;
	struct zsock_timeval rcv_timeout = { .tv_sec = 3 };
	struct net_if *iface = net_if_get_default();
	struct net_sockaddr_in c_saddr, s_saddr;
	struct net_in_addr second_addr;
	struct connect_data test_data;
	int role = ZSOCK_TLS_DTLS_ROLE_SERVER;
	int one = 1;
	uint8_t rx_buf;
	int ret;

	zassert_equal(zsock_inet_pton(NET_AF_INET, dst_addrs[1], &second_addr), 1);
	zassert_not_null(net_if_ipv4_addr_add(iface, &second_addr, NET_ADDR_MANUAL, 0),
			 "cannot add a second address");
	loopback_enable_address_swap(false);

	/* The stack picks one source address for both, so one reply needs PKTINFO */
	for (int i = 0; i < ARRAY_SIZE(dst_addrs); i++) {
		prepare_sock_dtls_v4(MY_IPV4_ADDR, ANY_PORT, &c_sock, &c_saddr,
				     NET_IPPROTO_DTLS_1_2);
		prepare_sock_dtls_v4("0.0.0.0", SERVER_PORT + i, &s_sock, &s_saddr,
				     NET_IPPROTO_DTLS_1_2);
		test_config_psk(s_sock, c_sock);
		zassert_ok(zsock_setsockopt(s_sock, ZSOCK_SOL_TLS, ZSOCK_TLS_DTLS_ROLE, &role,
					    sizeof(role)));
		zassert_ok(zsock_setsockopt(s_sock, NET_IPPROTO_IP, ZSOCK_IP_PKTINFO, &one,
					    sizeof(one)));
		zassert_ok(zsock_setsockopt(s_sock, ZSOCK_SOL_SOCKET, ZSOCK_SO_RCVTIMEO, &rcv_timeout,
					    sizeof(rcv_timeout)));
		test_bind(s_sock, (struct net_sockaddr *)&s_saddr, sizeof(s_saddr));

		zassert_equal(zsock_inet_pton(NET_AF_INET, dst_addrs[i], &s_saddr.sin_addr), 1);
		test_data.sock = c_sock;
		/* A failed handshake must not close the socket this thread polls */
		test_data.peer_sock = &unused_sock;
		test_data.addr = (struct net_sockaddr *)&s_saddr;
		k_work_init_delayable(&test_data.work, dtls_client_connect_send_work_handler);
		test_work_reschedule(&test_data.work, K_NO_WAIT);

		/* The handshake runs inside recv(), which gives up with the client */
		ret = zsock_recv(s_sock, &rx_buf, sizeof(rx_buf), 0);
		test_work_wait(&test_data.work);
		test_sockets_close();

		if (ret != sizeof(rx_buf)) {
			failed_addr = dst_addrs[i];
			break;
		}
	}

	/* Undo the setup before asserting, so a failure does not break later tests */
	loopback_enable_address_swap(true);
	zassert_true(net_if_ipv4_addr_rm(iface, &second_addr));
	zassert_is_null(failed_addr, "no DTLS handshake through %s", failed_addr);
#endif
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

	test_config_psk(s_sock, c_sock);

	if (NULL != cb) {
		cb();
	}

	test_bind(s_sock, &s_saddr, exp_addrlen);
	test_listen(s_sock);

	/* Helper work for the connect operation - need to handle client/server
	 * in parallel due to handshake.
	 */
	test_data.sock = c_sock;
	test_data.addr = &s_saddr;
	test_data.peer_sock = &s_sock;
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
	test_data.peer_sock = &new_sock;
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
	test_data.peer_sock = &new_sock;
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
	test_data.peer_sock = &new_sock;
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
	test_data.peer_sock = &new_sock;
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
	int *peer_sock;
	const uint8_t *data;
	size_t datalen;
};

static void send_work_handler(struct k_work *work)
{
	struct k_work_delayable *dwork = k_work_delayable_from_work(work);
	struct send_data *test_data =
		CONTAINER_OF(dwork, struct send_data, tx_work);
	int ret;

	ret = zsock_send(test_data->sock, test_data->data, test_data->datalen, 0);
	if (ret < 0) {
		printk("zsock_send() failed (%d)\n", errno);
		close_and_invalidate(test_data->peer_sock);
		return;
	}
	if (ret != test_data->datalen) {
		printk("zsock_send() sent %d instead of %zu\n", ret, test_data->datalen);
		close_and_invalidate(test_data->peer_sock);
		return;
	}
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
	test_data.peer_sock = &s_sock;
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
	int *peer_sock;
	const struct net_msghdr *msg;
};

static void test_sendmsg_tx_work_handler(struct k_work *work)
{
	struct k_work_delayable *dwork = k_work_delayable_from_work(work);
	struct test_sendmsg_data *test_data =
		CONTAINER_OF(dwork, struct test_sendmsg_data, tx_work);
	size_t total_len = 0;
	int ret;

	for (int i = 0; i < test_data->msg->msg_iovlen; i++) {
		struct net_iovec *vec = test_data->msg->msg_iov + i;

		total_len += vec->iov_len;
	}

	ret = zsock_sendmsg(test_data->sock, test_data->msg, 0);
	if (ret < 0) {
		printk("zsock_sendmsg() failed (%d)\n", errno);
		close_and_invalidate(test_data->peer_sock);
		return;
	}
	if (ret != total_len) {
		printk("zsock_sendmsg() sent %d instead of %zu\n", ret, total_len);
		close_and_invalidate(test_data->peer_sock);
		return;
	}
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
	test_data.peer_sock = &s_sock;
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
	test_data.peer_sock = &s_sock;
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
	test_data.peer_sock = &s_sock;
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
	int *peer_sock;
	bool reply;
};

static void fake_tcp_server_work(struct k_work *work)
{
	struct k_work_delayable *dwork = k_work_delayable_from_work(work);
	struct fake_tcp_server_data *data =
		CONTAINER_OF(dwork, struct fake_tcp_server_data, work);
	int ret;

	new_sock = zsock_accept(data->sock, NULL, 0);
	if (new_sock < 0) {
		printk("zsock_accept() failed (%d)\n", errno);
		close_and_invalidate(data->peer_sock);
		return;
	}

	if (!data->reply) {
		/* Add small delay to avoid race between incoming data and
		 * sending FIN.
		 */
		k_msleep(10);
		goto out;
	}

	while (true) {
		char rx_buf[32];

		ret = zsock_recv(new_sock, rx_buf, sizeof(rx_buf), 0);
		if (ret <= 0) {
			break;
		}

		ret = zsock_send(new_sock, TEST_STR_SMALL, sizeof(TEST_STR_SMALL), 0);
		if (ret < 0) {
			printk("zsock_send() failed (%d)\n", errno);
			close_and_invalidate(data->peer_sock);
			break;
		}
		if (ret != sizeof(TEST_STR_SMALL)) {
			printk("zsock_send() sent %d instead of %zu\n", ret,
			       sizeof(TEST_STR_SMALL));
			close_and_invalidate(data->peer_sock);
			break;
		}
	}

out:
	ret = zsock_close(new_sock);
	if (ret < 0) {
		printk("zsock_close() failed (%d)\n", errno);
	}

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
	s_data->peer_sock = &c_sock;
	s_data->reply = reply;
	k_work_init_delayable(&s_data->work, fake_tcp_server_work);
	test_work_reschedule(&s_data->work, K_NO_WAIT);
}

ZTEST(net_socket_tls, test_connect_invalid_handshake_data)
{
	net_socklen_t cipher_len = sizeof(int);
	struct fake_tcp_server_data server_data;
	int cipher;
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

	/* A failed handshake negotiated no suite */
	zassert_equal(zsock_getsockopt(c_sock, ZSOCK_SOL_TLS, ZSOCK_TLS_CIPHERSUITE_USED, &cipher,
				       &cipher_len), -1, "TLS_CIPHERSUITE_USED succeeded");
	zassert_equal(errno, ENOTCONN, "TLS_CIPHERSUITE_USED: errno %d, want ENOTCONN", errno);

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
	test_data.peer_sock = &new_sock;
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

#define TLS_RECORD_OVERHEAD 81

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
	int *peer_sock;
	const uint8_t *data;
	size_t datalen;
	bool failed;
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
		if (ret <= 0) {
			test_data->failed = true;
			printk("zsock_recv() failed (%d/%d)\n", ret, errno);
			close_and_invalidate(test_data->peer_sock);
			return;
		}

		if (memcmp(rx_buf, test_data->data + off, ret) != 0) {
			test_data->failed = true;
			printk("unexpected data at offset %zu\n", off);
			close_and_invalidate(test_data->peer_sock);
			return;
		}

		off += ret;
		if (off > test_data->datalen) {
			test_data->failed = true;
			printk("received more than expected\n");
			close_and_invalidate(test_data->peer_sock);
			return;
		}
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
	test_data.peer_sock = &c_sock;
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

	/* Check that the recv work received correct data */
	test_work_wait(&test_data.work);
	zassert_false(test_data.failed);

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
	test_data.peer_sock = &new_sock;
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
	test_data.peer_sock = &c_sock;
	k_work_init_delayable(&test_data.work, recv_work_handler);
	test_work_reschedule(&test_data.work, K_MSEC(10));

	/* Should block and succeed. */
	ret = zsock_send(c_sock, TEST_STR_SMALL, strlen(TEST_STR_SMALL), 0);
	zassert_equal(ret, strlen(TEST_STR_SMALL), "zsock_send() failed");

	/* Check that the recv work received correct data */
	test_work_wait(&test_data.work);
	zassert_false(test_data.failed);

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

	/* Shut down reception from the workqueue once recv() blocks, even on slow runners */
	k_work_init_delayable(&test_data.work, shutdown_work);
	test_data.sock = c_sock;
	test_work_reschedule(&test_data.work, K_MSEC(50));

	/* EOF should be notified by recv() */
	test_eof(c_sock);

	test_sockets_close();

	k_sleep(TCP_TEARDOWN_TIMEOUT);
}

#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS) && defined(CONFIG_WOLFSSL)
/* wolfSSL-only: a local read shutdown makes the next DTLS recv() return EOF */
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

	/* Shut down reception from the workqueue once recv() blocks, even on slow runners */
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
	test_data_c.peer_sock = &new_sock;
	k_work_init_delayable(&test_data_c.tx_work, send_work_handler);
	test_work_reschedule(&test_data_c.tx_work, K_MSEC(10));

	test_data_s.sock = new_sock;
	test_data_s.peer_sock = &c_sock;
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
	test_data.peer_sock = &new_sock;
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
	test_data.peer_sock = &new_sock;
	k_work_init_delayable(&test_data.tx_work, send_work_handler);
	test_work_reschedule(&test_data.tx_work, K_MSEC(10));

	/* recv() shall block until send work sends the data. */
	ret = zsock_recv(new_sock, rx_buf, sizeof(rx_buf), 0);
	zassert_equal(ret, sizeof(TEST_STR_SMALL) - 1, "recv() failed");
	zassert_mem_equal(rx_buf, TEST_STR_SMALL, ret, "Invalid data received");

	test_sockets_close();

	k_sleep(TCP_TEARDOWN_TIMEOUT);
}

/* Options set on an established connection succeed and leave it usable */
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
	/* The option is validated before it is stored, not when a live session applies it */
	ret = zsock_setsockopt(c_sock, ZSOCK_SOL_TLS, ZSOCK_TLS_CIPHERSUITE_LIST,
			       (void *)bad_cipher_list, sizeof(bad_cipher_list));
	zassert_equal(ret, -1, "invalid ciphersuite ID not rejected");
	zassert_equal(errno, EINVAL, "wrong errno value: %d", errno);
#endif

	/* Connection must still be usable. */
	test_data.sock = c_sock;
	test_data.peer_sock = &new_sock;
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

/* wolfSSL-only: a spoofed empty datagram does not end a DTLS server session; mbedTLS
 * keeps upstream's EOF behavior.
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
	test_data.peer_sock = &s_sock;
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
	test_data.peer_sock = &new_sock;
	k_work_init_delayable(&test_data.tx_work, send_work_handler);
	test_work_reschedule(&test_data.tx_work, K_MSEC(10));

	/* recv() shall block until send work sends the data. */
	ret = zsock_recv(new_sock, rx_buf, sizeof(rx_buf), 0);
	zassert_equal(ret, sizeof(TEST_STR_SMALL) - 1, "recv() failed");
	zassert_mem_equal(rx_buf, TEST_STR_SMALL, ret, "Invalid data received");

	test_sockets_close();

	k_sleep(TCP_TEARDOWN_TIMEOUT);
}

static void tls_set_session_cache_client_cb(bool server_cache)
{
	int t = ZSOCK_TLS_SESSION_CACHE_ENABLED;
	int l = sizeof(int);
	int ret;

	if (server_cache) {
		ret = zsock_setsockopt(s_sock, ZSOCK_SOL_TLS, ZSOCK_TLS_SESSION_CACHE,
				       (void *)&t, l);
		zassert_equal(ret, 0, "Unable to set session cache on server");
	}
	ret = zsock_setsockopt(c_sock, ZSOCK_SOL_TLS, ZSOCK_TLS_SESSION_CACHE,
			       (void *)&t, l);
	zassert_equal(ret, 0, "Unable to set session cache on client");
}

/* A fixed server port gives both connections the same peer address, the cache key */
static void prepare_tls_session_resume_ex(uint16_t server_port, int proto, bool server_cache)
{
	struct net_sockaddr_in c_saddr;
	struct net_sockaddr_in s_saddr;
	struct net_sockaddr addr;
	net_socklen_t addrlen = sizeof(addr);
	struct connect_data test_data;
	int reuse = 1;
	int ret;

	prepare_sock_tls_v4(MY_IPV4_ADDR, ANY_PORT, &c_sock, &c_saddr, proto);
	prepare_sock_tls_v4(MY_IPV4_ADDR, server_port, &s_sock, &s_saddr, proto);

	tls_set_session_cache_client_cb(server_cache);

	test_config_psk(s_sock, c_sock);
	if (proto == NET_IPPROTO_TLS_1_3) {
		test_config_tls13_suites(s_sock, c_sock);
	}

	/* Rebinding the fixed port must not fail on a TIME_WAIT entry */
	ret = zsock_setsockopt(s_sock, ZSOCK_SOL_SOCKET, ZSOCK_SO_REUSEADDR,
			       &reuse, sizeof(reuse));
	zassert_equal(ret, 0, "ZSOCK_SO_REUSEADDR on server socket failed");

	test_bind(s_sock, (struct net_sockaddr *)&s_saddr, sizeof(s_saddr));
	test_listen(s_sock);

	test_data.sock = c_sock;
	test_data.addr = (struct net_sockaddr *)&s_saddr;
	test_data.peer_sock = &s_sock;
	k_work_init_delayable(&test_data.work, client_connect_work_handler);
	test_work_reschedule(&test_data.work, K_NO_WAIT);

	test_accept(s_sock, &new_sock, &addr, &addrlen);
	test_work_wait(&test_data.work);
}

static void prepare_tls_session_resume_connection(uint16_t server_port, int proto)
{
	prepare_tls_session_resume_ex(server_port, proto, true);
}

static void check_verify_result(int sock, uint32_t expected)
{
	uint32_t result;
	net_socklen_t optlen = sizeof(result);

	zassert_ok(zsock_getsockopt(sock, ZSOCK_SOL_TLS, ZSOCK_TLS_CERT_VERIFY_RESULT, &result,
				    &optlen), "getsockopt(TLS_CERT_VERIFY_RESULT) failed (%d)", errno);
	zassert_equal(result, expected, "verify result 0x%x, expected 0x%x", result, expected);
}

static void tls_session_cache_purge(void)
{
	int sock = zsock_socket(NET_AF_INET, NET_SOCK_STREAM, NET_IPPROTO_TLS_1_2);

	zassert_true(sock >= 0, "purge socket open failed");
	zassert_ok(zsock_setsockopt(sock, ZSOCK_SOL_TLS, ZSOCK_TLS_SESSION_CACHE_PURGE, NULL, 0),
		   "purge setsockopt failed");
	zsock_close(sock);
}

#if defined(CONFIG_NET_SOCKETS_TLS_SESSION_CACHE_PERSISTENT)
#define TLS_CACHE_KEY(name) CONFIG_NET_SOCKETS_TLS_SESSION_CACHE_PERSISTENT_PREFIX "/0/" name

static struct {
	struct net_sockaddr_storage addr;
	uint8_t data[1024];
	size_t addr_len;
	size_t data_len;
} persisted;

static int persisted_session_cb(const char *key, size_t len, settings_read_cb read_cb,
				void *cb_arg, void *param)
{
	ARG_UNUSED(param);

	if (strcmp(key, "0/addr") == 0 && len == sizeof(persisted.addr)) {
		if (read_cb(cb_arg, &persisted.addr, len) == len) {
			persisted.addr_len = len;
		}
	} else if (strcmp(key, "0/data") == 0 && len <= sizeof(persisted.data)) {
		if (read_cb(cb_arg, persisted.data, len) == len) {
			persisted.data_len = len;
		}
	}

	return 0;
}

static void persisted_session_read(void)
{
	memset(&persisted, 0, sizeof(persisted));
	zassert_ok(settings_load_subtree_direct(
			   CONFIG_NET_SOCKETS_TLS_SESSION_CACHE_PERSISTENT_PREFIX,
			   persisted_session_cb, NULL));
}
#endif /* CONFIG_NET_SOCKETS_TLS_SESSION_CACHE_PERSISTENT */

/* The second connect to the same peer resumes the session */
ZTEST(net_socket_tls, test_session_cache_client_resume)
{
	uint8_t rx_buf[sizeof(TEST_STR_SMALL) - 1] = { 0 };
	struct send_data test_data = {
		.data = TEST_STR_SMALL,
		.datalen = sizeof(TEST_STR_SMALL) - 1,
	};
	int ret;

#if defined(CONFIG_WOLFSSL) && (!defined(HAVE_EXT_CACHE) || defined(NO_SESSION_CACHE))
	/* Same gate as ZTLS_WOLFSSL_EXT_CACHE: without it there is nothing to resume from. */
	ztest_test_skip();
#endif

	/* Start without a cached session */
	tls_session_cache_purge();

	/* First connection - should perform full handshake, then store. */
	prepare_tls_session_resume_connection(RESUME_SERVER_PORT, NET_IPPROTO_TLS_1_2);

	/* PSK verifies no certificate, and a resumption keeps that result */
	check_verify_result(c_sock, MBEDTLS_X509_BADCERT_SKIP_VERIFY);
	check_verify_result(new_sock, MBEDTLS_X509_BADCERT_SKIP_VERIFY);

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
	test_data.peer_sock = &new_sock;
	k_work_init_delayable(&test_data.tx_work, send_work_handler);
	test_work_reschedule(&test_data.tx_work, K_MSEC(10));
	ret = zsock_recv(new_sock, rx_buf, sizeof(rx_buf), 0);
	zassert_equal(ret, sizeof(TEST_STR_SMALL) - 1, "recv() failed");

	test_sockets_close();
	k_sleep(TCP_TEARDOWN_TIMEOUT);

	/* Second connection to the SAME server port - should restore the
	 * stored session and resume.
	 */
	prepare_tls_session_resume_connection(RESUME_SERVER_PORT, NET_IPPROTO_TLS_1_2);

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

	check_verify_result(c_sock, MBEDTLS_X509_BADCERT_SKIP_VERIFY);

	memset(rx_buf, 0, sizeof(rx_buf));
	test_data.sock = c_sock;
	test_data.peer_sock = &new_sock;
	k_work_init_delayable(&test_data.tx_work, send_work_handler);
	test_work_reschedule(&test_data.tx_work, K_MSEC(10));
	ret = zsock_recv(new_sock, rx_buf, sizeof(rx_buf), 0);
	zassert_equal(ret, sizeof(TEST_STR_SMALL) - 1, "recv() failed");
	zassert_mem_equal(rx_buf, TEST_STR_SMALL, ret, "Invalid data received");

	test_sockets_close();
	k_sleep(TCP_TEARDOWN_TIMEOUT);
}

/* The client stores the ticket that arrives after a TLS 1.3 handshake and offers it next time */
ZTEST(net_socket_tls, test_session_cache_tls13_ticket_offered)
{
#if !defined(CONFIG_WOLFSSL) || !defined(WOLFSSL_TLS13) || !defined(HAVE_SESSION_TICKET) || \
	!defined(HAVE_EXT_CACHE) || defined(NO_SESSION_CACHE)
	ztest_test_skip();
#else
	uint8_t rx_buf[sizeof(TEST_STR_SMALL) - 1];
	int ret;

	tls_session_cache_purge();

	for (int i = 0; i < 2; i++) {
		prepare_tls_session_resume_connection(RESUME_SERVER_PORT, NET_IPPROTO_TLS_1_3);
		/* The client reports the offer; a Zephyr server cannot redeem it and uses the PSK */
		zassert_equal(wolfSSL_session_reused(ztls_get_wolfssl_context(c_sock)), i,
			      "connection %d: ticket offered %d", i,
			      wolfSSL_session_reused(ztls_get_wolfssl_context(c_sock)));
		check_verify_result(c_sock, MBEDTLS_X509_BADCERT_SKIP_VERIFY);

		/* The client reads the ticket together with the data */
		test_send(new_sock, TEST_STR_SMALL, sizeof(TEST_STR_SMALL) - 1, 0);
		ret = zsock_recv(c_sock, rx_buf, sizeof(rx_buf), 0);
		zassert_equal(ret, sizeof(rx_buf), "recv() failed (%d)", errno);

		test_sockets_close();
		k_sleep(TCP_TEARDOWN_TIMEOUT);
	}
#endif
}

/* A server with TLS_SESSION_CACHE off issues no ticket, so the client offers none */
ZTEST(net_socket_tls, test_session_cache_server_disabled_no_ticket)
{
#if !defined(CONFIG_WOLFSSL) || !defined(HAVE_EXT_CACHE) || defined(NO_SESSION_CACHE)
	ztest_test_skip();
#else
	static const int protos[] = {
		NET_IPPROTO_TLS_1_2,
#if defined(WOLFSSL_TLS13)
		NET_IPPROTO_TLS_1_3,
#endif
	};
	uint8_t rx_buf[sizeof(TEST_STR_SMALL) - 1];
	int reused[ARRAY_SIZE(protos)][2];
	int ret;

	for (int p = 0; p < ARRAY_SIZE(protos); p++) {
		tls_session_cache_purge();

		for (int i = 0; i < 2; i++) {
			prepare_tls_session_resume_ex(RESUME_SERVER_PORT, protos[p], false);
			reused[p][i] = wolfSSL_session_reused(ztls_get_wolfssl_context(c_sock));

			/* A TLS 1.3 ticket arrives with the data */
			test_send(new_sock, TEST_STR_SMALL, sizeof(TEST_STR_SMALL) - 1, 0);
			ret = zsock_recv(c_sock, rx_buf, sizeof(rx_buf), 0);
			zassert_equal(ret, sizeof(rx_buf), "recv() failed (%d)", errno);

			test_sockets_close();
			k_sleep(TCP_TEARDOWN_TIMEOUT);
		}
	}

	for (int p = 0; p < ARRAY_SIZE(protos); p++) {
		zassert_equal(reused[p][0] + reused[p][1], 0,
			      "proto %d resumed with the server cache off", protos[p]);
	}
#endif
}

/* A TLS 1.2 socket sets the minimum version, so it runs TLS 1.3 with a TLS 1.3 peer */
ZTEST(net_socket_tls, test_tls_1_2_socket_runs_tls_1_3)
{
#if !defined(CONFIG_WOLFSSL) || !defined(WOLFSSL_TLS13)
	ztest_test_skip();
#else
	struct net_sockaddr c_saddr, s_saddr, addr;
	net_socklen_t addrlen = sizeof(addr);
	struct connect_data test_data;

	prepare_sock_tls_v4(MY_IPV4_ADDR, ANY_PORT, &c_sock, (struct net_sockaddr_in *)&c_saddr,
			    NET_IPPROTO_TLS_1_2);
	prepare_sock_tls_v4(MY_IPV4_ADDR, ANY_PORT, &s_sock, (struct net_sockaddr_in *)&s_saddr,
			    NET_IPPROTO_TLS_1_3);
	test_config_psk(s_sock, c_sock);
	test_config_tls13_suites(s_sock, c_sock);
	test_bind(s_sock, &s_saddr, sizeof(struct net_sockaddr_in));
	test_listen(s_sock);

	test_data.sock = c_sock;
	test_data.addr = &s_saddr;
	test_data.peer_sock = &s_sock;
	k_work_init_delayable(&test_data.work, client_connect_work_handler);
	test_work_reschedule(&test_data.work, K_NO_WAIT);

	test_accept(s_sock, &new_sock, &addr, &addrlen);
	test_work_wait(&test_data.work);

	zassert_equal(wolfSSL_GetVersion(ztls_get_wolfssl_context(c_sock)), WOLFSSL_TLSV1_3,
		      "TLS 1.2 socket did not negotiate TLS 1.3");

	test_sockets_close();
	k_sleep(TCP_TEARDOWN_TIMEOUT);
#endif
}

/* The client session cache is saved to and reloaded from the settings subsystem */
ZTEST(net_socket_tls, test_session_cache_persistent)
{
#if !defined(CONFIG_NET_SOCKETS_TLS_SESSION_CACHE_PERSISTENT) || \
	(defined(CONFIG_WOLFSSL) && (!defined(HAVE_EXT_CACHE) || defined(NO_SESSION_CACHE)))
	ztest_test_skip();
#else
	static uint8_t data[sizeof(persisted.data)];
	static const uint8_t junk[16];
	size_t data_len;

	tls_session_cache_purge();

	prepare_tls_session_resume_connection(RESUME_SERVER_PORT, NET_IPPROTO_TLS_1_2);
	test_sockets_close();
	k_sleep(TCP_TEARDOWN_TIMEOUT);

	persisted_session_read();
	zassert_equal(persisted.addr_len, sizeof(persisted.addr), "peer address not saved");
	zassert_true(persisted.data_len > 0, "session not saved");
	memcpy(data, persisted.data, persisted.data_len);
	data_len = persisted.data_len;

	/* Loading replaces the cached session, so a bad one costs the resumption */
	zassert_ok(settings_save_one(TLS_CACHE_KEY("data"), junk, sizeof(junk)));
	zassert_ok(settings_load_subtree(CONFIG_NET_SOCKETS_TLS_SESSION_CACHE_PERSISTENT_PREFIX));

	prepare_tls_session_resume_connection(RESUME_SERVER_PORT, NET_IPPROTO_TLS_1_2);
#if defined(CONFIG_WOLFSSL)
	zassert_equal(wolfSSL_session_reused(ztls_get_wolfssl_context(c_sock)), 0,
		      "resumed without a valid session");
#endif
	test_sockets_close();
	k_sleep(TCP_TEARDOWN_TIMEOUT);

	zassert_ok(settings_save_one(TLS_CACHE_KEY("data"), data, data_len));
	zassert_ok(settings_load_subtree(CONFIG_NET_SOCKETS_TLS_SESSION_CACHE_PERSISTENT_PREFIX));

	prepare_tls_session_resume_connection(RESUME_SERVER_PORT, NET_IPPROTO_TLS_1_2);
#if defined(CONFIG_WOLFSSL)
	zassert_not_equal(wolfSSL_session_reused(ztls_get_wolfssl_context(c_sock)), 0,
			  "reloaded session not resumed");
#endif
	test_sockets_close();
	k_sleep(TCP_TEARDOWN_TIMEOUT);

	tls_session_cache_purge();
	persisted_session_read();
	zassert_equal(persisted.addr_len + persisted.data_len, 0, "purge left the settings copy");
#endif
}

/* A handshake completes with secure renegotiation enabled */
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
	test_data.peer_sock = &new_sock;
	k_work_init_delayable(&test_data.tx_work, send_work_handler);
	test_work_reschedule(&test_data.tx_work, K_MSEC(10));
	ret = zsock_recv(new_sock, rx_buf, sizeof(rx_buf), 0);
	zassert_equal(ret, sizeof(TEST_STR_SMALL) - 1, "recv() failed");
	zassert_mem_equal(rx_buf, TEST_STR_SMALL, ret, "Invalid data received");

	test_sockets_close();
	k_sleep(TCP_TEARDOWN_TIMEOUT);
}

/* As with Mbed TLS, an ALPN list ends at its first NULL entry */
ZTEST(net_socket_tls, test_alpn_null_entry)
{
#if CONFIG_NET_SOCKETS_TLS_MAX_APP_PROTOCOLS > 2
	static const char * const list[] = { "http/1.1", NULL, "h2" };
	const char *read_list[ARRAY_SIZE(list)] = { NULL };
	net_socklen_t len = sizeof(read_list);
	struct net_sockaddr_in saddr;

	prepare_sock_tls_v4(MY_IPV4_ADDR, ANY_PORT, &c_sock, &saddr, NET_IPPROTO_TLS_1_2);
	zassert_ok(zsock_setsockopt(c_sock, ZSOCK_SOL_TLS, ZSOCK_TLS_ALPN_LIST, list,
				    sizeof(list)));
	zassert_ok(zsock_getsockopt(c_sock, ZSOCK_SOL_TLS, ZSOCK_TLS_ALPN_LIST, read_list,
				    &len));
	zassert_equal(len, sizeof(read_list[0]), "read back %d entries",
		      (int)(len / sizeof(read_list[0])));
	zassert_str_equal(read_list[0], "http/1.1");
	test_close(c_sock);
	c_sock = -1;
#else
	ztest_test_skip();
#endif
}

/* wolfSSL-only: wolfSSL takes the list joined by commas, so an entry must be a single name */
ZTEST(net_socket_tls, test_alpn_bad_entry)
{
#if defined(CONFIG_WOLFSSL) && CONFIG_NET_SOCKETS_TLS_MAX_APP_PROTOCOLS > 1
	static const char * const comma[] = { "h2,http/1.1" };
	static const char * const empty[] = { "http/1.1", "" };
	static const char * const good[] = { "http/1.1" };
	const char *read_list[2] = { NULL };
	net_socklen_t len = sizeof(read_list);
	struct net_sockaddr_in saddr;

	prepare_sock_tls_v4(MY_IPV4_ADDR, ANY_PORT, &c_sock, &saddr, NET_IPPROTO_TLS_1_2);
	zassert_ok(zsock_setsockopt(c_sock, ZSOCK_SOL_TLS, ZSOCK_TLS_ALPN_LIST, good,
				    sizeof(good)));
	zassert_equal(zsock_setsockopt(c_sock, ZSOCK_SOL_TLS, ZSOCK_TLS_ALPN_LIST, comma,
				       sizeof(comma)), -1);
	zassert_equal(errno, EINVAL);
	zassert_equal(zsock_setsockopt(c_sock, ZSOCK_SOL_TLS, ZSOCK_TLS_ALPN_LIST, empty,
				       sizeof(empty)), -1);
	zassert_equal(errno, EINVAL);

	/* A rejected list leaves the previous one */
	zassert_ok(zsock_getsockopt(c_sock, ZSOCK_SOL_TLS, ZSOCK_TLS_ALPN_LIST, read_list,
				    &len));
	zassert_equal(len, sizeof(read_list[0]));
	zassert_str_equal(read_list[0], "http/1.1");
	test_close(c_sock);
	c_sock = -1;
#else
	ztest_test_skip();
#endif
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
	test_data.peer_sock = &new_sock;
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

/* A zero-length read returns 0 once data is there, and leaves the data in place */
ZTEST(net_socket_tls, test_recv_zero_length)
{
	uint8_t rx_buf[sizeof(TEST_STR_SMALL) - 1];
	struct zsock_pollfd fds[1];
	int ret;

	test_prepare_tls_connection(NET_AF_INET6);

	test_send(c_sock, TEST_STR_SMALL, sizeof(TEST_STR_SMALL) - 1, 0);
	fds[0].fd = new_sock;
	fds[0].events = ZSOCK_POLLIN;
	zassert_equal(zsock_poll(fds, 1, 1000), 1, "poll() missed data");

	ret = zsock_recv(new_sock, NULL, 0, 0);
	zassert_equal(ret, 0, "zero-length recv() returned %d (%d)", ret, errno);

	ret = zsock_recv(new_sock, rx_buf, sizeof(rx_buf), ZSOCK_MSG_DONTWAIT);
	zassert_equal(ret, sizeof(rx_buf), "recv() after a zero-length read failed (%d)", errno);
	zassert_mem_equal(rx_buf, TEST_STR_SMALL, ret, "Invalid data received");

	test_sockets_close();
	k_sleep(TCP_TEARDOWN_TIMEOUT);
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
	test_data.peer_sock = &s_sock;
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

#if defined(CONFIG_MBEDTLS)
static uint8_t coalesce_buf[512];
static size_t coalesce_len;

/* Collect the ciphertext of a record instead of sending it. */
static int coalesce_send(void *ctx, const unsigned char *buf, size_t len)
{
	ARG_UNUSED(ctx);

	if (len > sizeof(coalesce_buf) - coalesce_len) {
		return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
	}

	memcpy(coalesce_buf + coalesce_len, buf, len);
	coalesce_len += len;

	return (int)len;
}
#endif /* CONFIG_MBEDTLS */

/* A datagram can carry more than one DTLS record. Mbed TLS reads the whole
 * datagram in and processes one record at a time, so once the application
 * has consumed the first record, the socket has no readiness left to report
 * while Mbed TLS still holds the second one. poll() has to report that
 * record instead of waiting for a datagram which never comes.
 */
ZTEST(net_socket_tls, test_poll_dtls_second_record_in_datagram)
{
	static const uint8_t rec_a = 'A';
	static const uint8_t rec_b = 'B';
#if defined(CONFIG_WOLFSSL)
	WOLFSSL *ssl;
#else
	mbedtls_ssl_context *ssl;
	mbedtls_ssl_send_t *orig_send;
	mbedtls_ssl_recv_t *orig_recv;
	void *p_bio;
#endif
	struct zsock_pollfd fds[1];
	uint8_t byte;
	int ret;

	test_prepare_dtls_connection(NET_AF_INET6);

#if defined(CONFIG_WOLFSSL)
	ssl = ztls_get_wolfssl_context(s_sock);
	zassert_not_null(ssl, "No wolfSSL session for the server socket");

	test_wolfssl_hold_records(ssl);

	ret = zsock_send(s_sock, &rec_a, sizeof(rec_a), 0);
	zassert_equal(ret, sizeof(rec_a), "Cannot write the first record");

	ret = zsock_send(s_sock, &rec_b, sizeof(rec_b), 0);
	zassert_equal(ret, sizeof(rec_b), "Cannot write the second record");

	ret = test_wolfssl_send_held_records(ssl);
	zassert_true(ret > 0, "Cannot send the records");
#else
	ssl = ztls_get_mbedtls_ssl_context(s_sock);
	zassert_not_null(ssl, "No Mbed TLS context for the server socket");

	orig_send = ssl->MBEDTLS_PRIVATE(f_send);
	orig_recv = ssl->MBEDTLS_PRIVATE(f_recv);
	p_bio = ssl->MBEDTLS_PRIVATE(p_bio);

	/* Hold both records back, so that they can be handed over in one
	 * datagram below.
	 */
	coalesce_len = 0;
	mbedtls_ssl_set_bio(ssl, p_bio, coalesce_send, orig_recv, NULL);

	ret = zsock_send(s_sock, &rec_a, sizeof(rec_a), 0);
	zassert_equal(ret, sizeof(rec_a), "Cannot write the first record");

	ret = zsock_send(s_sock, &rec_b, sizeof(rec_b), 0);
	zassert_equal(ret, sizeof(rec_b), "Cannot write the second record");

	mbedtls_ssl_set_bio(ssl, p_bio, orig_send, orig_recv, NULL);

	ret = orig_send(p_bio, coalesce_buf, coalesce_len);
	zassert_equal(ret, coalesce_len, "Cannot send the records");
#endif /* CONFIG_WOLFSSL */

	fds[0].fd = c_sock;
	fds[0].events = ZSOCK_POLLIN;

	ret = zsock_poll(fds, 1, 500);
	zassert_equal(ret, 1, "poll() did not report the datagram");

	ret = zsock_recv(c_sock, &byte, 1, 0);
	zassert_equal(ret, 1, "Cannot read the first record");
	zassert_equal(byte, rec_a, "Wrong first record");

	/* The datagram is gone from the socket at this point, the second
	 * record only exists inside Mbed TLS.
	 */
	ret = zsock_poll(fds, 1, 500);
	zassert_equal(ret, 1, "poll() did not report the second record");
	zassert_true(fds[0].revents & ZSOCK_POLLIN, "No POLLIN event");

	ret = zsock_recv(c_sock, &byte, 1, 0);
	zassert_equal(ret, 1, "Cannot read the second record");
	zassert_equal(byte, rec_b, "Wrong second record");

	test_sockets_close();

	/* Small delay for the final alert exchange */
	k_msleep(10);
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

#if defined(CONFIG_WOLFSSL)
#define CHAIN_CERT_TAG 16

/* wolfSSL-only: mbedTLS reads a single DER object from an own-cert credential. */
static const uint8_t chain_leaf_der[] = {
	0x30, 0x82, 0x01, 0x8e, 0x30, 0x82, 0x01, 0x34, 0xa0, 0x03, 0x02, 0x01,
	0x02, 0x02, 0x14, 0x0c, 0xf3, 0xc8, 0xd4, 0x66, 0x53, 0xed, 0x1f, 0x07,
	0xed, 0x3b, 0x3b, 0xfd, 0xe8, 0x6d, 0xc9, 0xd5, 0x2e, 0x55, 0x6d, 0x30,
	0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30,
	0x23, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x06,
	0x5a, 0x65, 0x70, 0x68, 0x79, 0x72, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03,
	0x55, 0x04, 0x03, 0x0c, 0x07, 0x54, 0x65, 0x73, 0x74, 0x20, 0x43, 0x41,
	0x30, 0x20, 0x17, 0x0d, 0x32, 0x36, 0x30, 0x39, 0x31, 0x37, 0x31, 0x34,
	0x32, 0x32, 0x34, 0x38, 0x5a, 0x18, 0x0f, 0x32, 0x31, 0x32, 0x36, 0x30,
	0x38, 0x32, 0x34, 0x31, 0x34, 0x32, 0x32, 0x34, 0x38, 0x5a, 0x30, 0x25,
	0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x06, 0x5a,
	0x65, 0x70, 0x68, 0x79, 0x72, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55,
	0x04, 0x03, 0x0c, 0x09, 0x54, 0x65, 0x73, 0x74, 0x20, 0x4c, 0x65, 0x61,
	0x66, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d,
	0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
	0x03, 0x42, 0x00, 0x04, 0x84, 0xd8, 0x25, 0xdd, 0xbd, 0xa5, 0xd0, 0x7f,
	0x98, 0x51, 0x63, 0x08, 0xd0, 0x6a, 0x81, 0x04, 0xa7, 0x57, 0x3e, 0x9d,
	0x7b, 0x92, 0xe5, 0x75, 0x6a, 0x9d, 0xdf, 0xaf, 0x44, 0x8d, 0xe8, 0x64,
	0x49, 0xdc, 0xf4, 0x2e, 0x5c, 0x26, 0x76, 0x7b, 0x72, 0x5f, 0x77, 0xed,
	0x05, 0xa0, 0x24, 0x46, 0x3b, 0xbb, 0x2d, 0x85, 0x0b, 0x34, 0xc8, 0x27,
	0x76, 0x95, 0x6f, 0x53, 0x9e, 0x17, 0xa8, 0xc8, 0xa3, 0x42, 0x30, 0x40,
	0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x9a,
	0xa7, 0xa3, 0x63, 0xc1, 0x1d, 0x90, 0x08, 0x1d, 0xdc, 0x55, 0x5f, 0x68,
	0x61, 0x42, 0x17, 0x6f, 0x6e, 0xe6, 0x64, 0x30, 0x1f, 0x06, 0x03, 0x55,
	0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0xa6, 0x58, 0x24, 0xe7,
	0xd9, 0x9e, 0x27, 0xb5, 0xd0, 0x4f, 0x56, 0x03, 0xc7, 0xf7, 0x32, 0xc0,
	0x3b, 0x5e, 0xe1, 0x25, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
	0x3d, 0x04, 0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x21, 0x00,
	0x96, 0x8d, 0xca, 0xc4, 0xa2, 0x9f, 0x2d, 0xbb, 0x71, 0x8a, 0x76, 0xf0,
	0x38, 0xd5, 0x06, 0x0e, 0x70, 0x86, 0x19, 0xd9, 0x24, 0x93, 0x60, 0x37,
	0xe3, 0x97, 0xb9, 0xb6, 0x4f, 0xd4, 0x5b, 0x51, 0x02, 0x20, 0x7b, 0x9d,
	0x3a, 0xd1, 0xce, 0xbb, 0xd5, 0xce, 0x00, 0x02, 0x46, 0xb2, 0xd5, 0x09,
	0x0f, 0xf8, 0x1d, 0x88, 0xfc, 0xa7, 0xf4, 0x46, 0x59, 0x89, 0x86, 0x6a,
	0x61, 0xe0, 0x0d, 0x63, 0xb7, 0x4e,
};

static const uint8_t chain_ca_der[] = {
	0x30, 0x82, 0x01, 0x9d, 0x30, 0x82, 0x01, 0x43, 0xa0, 0x03, 0x02, 0x01,
	0x02, 0x02, 0x14, 0x46, 0x83, 0x1a, 0x05, 0x77, 0x0c, 0xba, 0x80, 0x6a,
	0xec, 0x02, 0x41, 0xdd, 0xc7, 0x4f, 0x09, 0x02, 0x9d, 0xcd, 0x1f, 0x30,
	0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30,
	0x23, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x06,
	0x5a, 0x65, 0x70, 0x68, 0x79, 0x72, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03,
	0x55, 0x04, 0x03, 0x0c, 0x07, 0x54, 0x65, 0x73, 0x74, 0x20, 0x43, 0x41,
	0x30, 0x20, 0x17, 0x0d, 0x32, 0x36, 0x30, 0x39, 0x31, 0x37, 0x31, 0x34,
	0x32, 0x32, 0x34, 0x38, 0x5a, 0x18, 0x0f, 0x32, 0x31, 0x32, 0x36, 0x30,
	0x38, 0x32, 0x34, 0x31, 0x34, 0x32, 0x32, 0x34, 0x38, 0x5a, 0x30, 0x23,
	0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x06, 0x5a,
	0x65, 0x70, 0x68, 0x79, 0x72, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55,
	0x04, 0x03, 0x0c, 0x07, 0x54, 0x65, 0x73, 0x74, 0x20, 0x43, 0x41, 0x30,
	0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
	0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42,
	0x00, 0x04, 0xfd, 0xcb, 0x70, 0xce, 0x39, 0xda, 0xf3, 0x8e, 0x32, 0x44,
	0x17, 0x72, 0xf5, 0x87, 0x69, 0x1f, 0x27, 0x96, 0x18, 0xf0, 0x79, 0x8d,
	0x21, 0x95, 0x4b, 0x38, 0xba, 0xd8, 0x18, 0x6d, 0xf3, 0xd7, 0x32, 0x9c,
	0x1e, 0xd5, 0x69, 0xd1, 0x71, 0x08, 0xaf, 0x7e, 0x7f, 0x22, 0xee, 0xd1,
	0x2e, 0x21, 0x4e, 0x52, 0xb0, 0x12, 0x0e, 0x8d, 0xfa, 0x78, 0xdd, 0x81,
	0x92, 0x72, 0x45, 0xb5, 0x1b, 0xa6, 0xa3, 0x53, 0x30, 0x51, 0x30, 0x1d,
	0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0xa6, 0x58, 0x24,
	0xe7, 0xd9, 0x9e, 0x27, 0xb5, 0xd0, 0x4f, 0x56, 0x03, 0xc7, 0xf7, 0x32,
	0xc0, 0x3b, 0x5e, 0xe1, 0x25, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23,
	0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0xa6, 0x58, 0x24, 0xe7, 0xd9, 0x9e,
	0x27, 0xb5, 0xd0, 0x4f, 0x56, 0x03, 0xc7, 0xf7, 0x32, 0xc0, 0x3b, 0x5e,
	0xe1, 0x25, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff,
	0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x0a, 0x06, 0x08, 0x2a,
	0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45,
	0x02, 0x21, 0x00, 0x84, 0x31, 0xe4, 0xb3, 0x0d, 0x6e, 0xa0, 0xb3, 0xb3,
	0xcf, 0x87, 0xc0, 0xa4, 0x75, 0xb7, 0x5b, 0xa7, 0xc1, 0xde, 0x65, 0x9c,
	0x67, 0x89, 0xc6, 0xa9, 0x39, 0x3c, 0xb9, 0x4a, 0x59, 0x1e, 0xb3, 0x02,
	0x20, 0x16, 0x2a, 0xc1, 0xfb, 0xbc, 0x1e, 0xaa, 0x70, 0x01, 0x30, 0xaa,
	0x66, 0x3e, 0xad, 0x32, 0xba, 0xec, 0x4d, 0x88, 0xae, 0xe1, 0xab, 0xa6,
	0xa1, 0x53, 0x15, 0x72, 0xde, 0x05, 0xbf, 0x89, 0xab,
};

static const char chain_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIBjjCCATSgAwIBAgIUDPPI1GZT7R8H7Ts7/ehtydUuVW0wCgYIKoZIzj0EAwIw\n"
	"IzEPMA0GA1UECgwGWmVwaHlyMRAwDgYDVQQDDAdUZXN0IENBMCAXDTI2MDkxNzE0\n"
	"MjI0OFoYDzIxMjYwODI0MTQyMjQ4WjAlMQ8wDQYDVQQKDAZaZXBoeXIxEjAQBgNV\n"
	"BAMMCVRlc3QgTGVhZjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABITYJd29pdB/\n"
	"mFFjCNBqgQSnVz6de5LldWqd369EjehkSdz0LlwmdntyX3ftBaAkRju7LYULNMgn\n"
	"dpVvU54XqMijQjBAMB0GA1UdDgQWBBSap6NjwR2QCB3cVV9oYUIXb27mZDAfBgNV\n"
	"HSMEGDAWgBSmWCTn2Z4ntdBPVgPH9zLAO17hJTAKBggqhkjOPQQDAgNIADBFAiEA\n"
	"lo3KxKKfLbtxinbwONUGDnCGGdkkk2A345e5tk/UW1ECIHudOtHOu9XOAAJGstUJ\n"
	"D/gdiPyn9EZZiYZqYeANY7dO\n"
	"-----END CERTIFICATE-----\n"
	"-----BEGIN CERTIFICATE-----\n"
	"MIIBnTCCAUOgAwIBAgIURoMaBXcMuoBq7AJB3cdPCQKdzR8wCgYIKoZIzj0EAwIw\n"
	"IzEPMA0GA1UECgwGWmVwaHlyMRAwDgYDVQQDDAdUZXN0IENBMCAXDTI2MDkxNzE0\n"
	"MjI0OFoYDzIxMjYwODI0MTQyMjQ4WjAjMQ8wDQYDVQQKDAZaZXBoeXIxEDAOBgNV\n"
	"BAMMB1Rlc3QgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAT9y3DOOdrzjjJE\n"
	"F3L1h2kfJ5YY8HmNIZVLOLrYGG3z1zKcHtVp0XEIr35/Iu7RLiFOUrASDo36eN2B\n"
	"knJFtRumo1MwUTAdBgNVHQ4EFgQUplgk59meJ7XQT1YDx/cywDte4SUwHwYDVR0j\n"
	"BBgwFoAUplgk59meJ7XQT1YDx/cywDte4SUwDwYDVR0TAQH/BAUwAwEB/zAKBggq\n"
	"hkjOPQQDAgNIADBFAiEAhDHksw1uoLOzz4fApHW3W6fB3mWcZ4nGqTk8uUpZHrMC\n"
	"IBYqwfu8HqpwATCqZj6tMrrsTYiu4aumoVMVct4Fv4mr\n"
	"-----END CERTIFICATE-----\n";

/* Uses the file-scope s_sock so the suite's after-hook closes it if an assertion aborts. */
static void chain_cred_expect(const void *cred, size_t len, bool accept, const char *what)
{
	sec_tag_t tag = CHAIN_CERT_TAG;
	int ret, err;

	(void)tls_credential_delete(CHAIN_CERT_TAG, TLS_CREDENTIAL_PUBLIC_CERTIFICATE);
	zassert_ok(tls_credential_add(CHAIN_CERT_TAG, TLS_CREDENTIAL_PUBLIC_CERTIFICATE,
				      cred, len), "Failed to add %s", what);

	s_sock = zsock_socket(NET_AF_INET, NET_SOCK_STREAM, NET_IPPROTO_TLS_1_2);
	zassert_true(s_sock >= 0, "zsock_socket() failed");

	ret = zsock_setsockopt(s_sock, ZSOCK_SOL_TLS, ZSOCK_TLS_SEC_TAG_LIST,
			       &tag, sizeof(tag));
	err = errno;

	test_sockets_close();
	(void)tls_credential_delete(CHAIN_CERT_TAG, TLS_CREDENTIAL_PUBLIC_CERTIFICATE);

	if (accept) {
		zassert_ok(ret, "%s rejected, errno %d", what, err);
	} else {
		zassert_equal(ret, -1, "%s accepted", what);
		zassert_equal(err, EINVAL, "%s: errno %d, want EINVAL", what, err);
	}
}

ZTEST(net_socket_tls, test_tls_cert_chain_cred)
{
	static uint8_t chain[sizeof(chain_leaf_der) + sizeof(chain_ca_der)];

	memcpy(chain, chain_leaf_der, sizeof(chain_leaf_der));
	memcpy(chain + sizeof(chain_leaf_der), chain_ca_der, sizeof(chain_ca_der));

	chain_cred_expect(chain, sizeof(chain), true, "leaf+issuer DER chain");
	chain_cred_expect(chain_leaf_der, sizeof(chain_leaf_der), true, "single leaf DER");
	chain_cred_expect(chain_pem, sizeof(chain_pem), true, "leaf+issuer PEM chain");

	/* Padding after the last certificate is ignored, as mbedTLS does. */
	memcpy(chain, chain_leaf_der, sizeof(chain_leaf_der));
	memset(chain + sizeof(chain_leaf_der), 0xff, 4);
	chain_cred_expect(chain, sizeof(chain_leaf_der) + 4, true, "leaf DER with padding");
}

ZTEST(net_socket_tls, test_tls_cert_chain_cred_malformed)
{
	static uint8_t buf[sizeof(chain_leaf_der) + sizeof(chain_ca_der)];
	static char pem[sizeof(chain_pem)];

	/* Second certificate truncated mid-body. */
	memcpy(buf, chain_leaf_der, sizeof(chain_leaf_der));
	memcpy(buf + sizeof(chain_leaf_der), chain_ca_der, sizeof(chain_ca_der));
	chain_cred_expect(buf, sizeof(chain_leaf_der) + sizeof(chain_ca_der) / 2,
			  false, "truncated second certificate");

	/* Indefinite-length SEQUENCE, which DER forbids. */
	memcpy(buf, chain_leaf_der, sizeof(chain_leaf_der));
	buf[1] = 0x80;
	chain_cred_expect(buf, sizeof(chain_leaf_der), false, "indefinite length");

	/* Second PEM block corrupted. */
	memcpy(pem, chain_pem, sizeof(chain_pem));
	pem[sizeof(chain_pem) - 40] = '!';
	chain_cred_expect(pem, sizeof(pem), false, "corrupt second PEM block");
}
#endif /* CONFIG_WOLFSSL */

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
		printk("zsock_connect() failed (%d)\n", errno);
		close_and_invalidate(data->peer_sock);
		return;
	}

	ret = zsock_send(data->sock, &tx_buf, sizeof(tx_buf), 0);
	if (ret < 0) {
		printk("zsock_send() failed (%d)\n", errno);
		close_and_invalidate(data->peer_sock);
		return;
	}
	if (ret != sizeof(tx_buf)) {
		printk("zsock_send() sent %d instead of %zu\n", ret, sizeof(tx_buf));
		close_and_invalidate(data->peer_sock);
		return;
	}
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
	test_data.peer_sock = &s_sock;
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
	test_data.peer_sock = &s_sock;
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
	test_data.peer_sock = &s_sock;
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
	test_data.peer_sock = &s_sock;
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
	test_data.peer_sock = &s_sock;
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
	test_data.peer_sock = &s_sock;
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
	test_data.peer_sock = &s_sock;
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
	test_data.peer_sock = &s_sock;
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

/* Waits a bounded time for the peer's close_notify, which real targets deliver
 * asynchronously; a missing one still fails the caller's ENOTCONN check.
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

	/* The client sees the server's close_notify, which may still be in flight */
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

	/* The client sees the server's close_notify, which may still be in flight */
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

ZTEST(net_socket_tls, test_mfl_sockopt)
{
	int sock;
	int mfl;
	int ret;

	if (!IS_ENABLED(CONFIG_NET_SOCKETS_TLS_SET_MAX_FRAGMENT_LENGTH)) {
		ztest_test_skip();
	}

	sock = zsock_socket(NET_AF_INET, NET_SOCK_STREAM, NET_IPPROTO_TLS_1_2);
	zassert_not_equal(sock, -1, "socket() failed (%d)", errno);

	/* Valid values */
	mfl = ZSOCK_TLS_MFL_DEFAULT;
	ret = zsock_setsockopt(sock, ZSOCK_SOL_TLS, ZSOCK_TLS_MAX_FRAGMENT_LENGTH,
			      &mfl, sizeof(mfl));
	zassert_equal(ret, 0, "setsockopt(MFL_DEFAULT) failed (%d)", errno);

	mfl = ZSOCK_TLS_MFL_DISABLED;
	ret = zsock_setsockopt(sock, ZSOCK_SOL_TLS, ZSOCK_TLS_MAX_FRAGMENT_LENGTH,
			      &mfl, sizeof(mfl));
	zassert_equal(ret, 0, "setsockopt(MFL_DISABLED) failed (%d)", errno);

	mfl = ZSOCK_TLS_MFL_512;
	ret = zsock_setsockopt(sock, ZSOCK_SOL_TLS, ZSOCK_TLS_MAX_FRAGMENT_LENGTH,
			      &mfl, sizeof(mfl));
	zassert_equal(ret, 0, "setsockopt(MFL_512) failed (%d)", errno);

	mfl = ZSOCK_TLS_MFL_4096;
	ret = zsock_setsockopt(sock, ZSOCK_SOL_TLS, ZSOCK_TLS_MAX_FRAGMENT_LENGTH,
			      &mfl, sizeof(mfl));
	zassert_equal(ret, 0, "setsockopt(MFL_4096) failed (%d)", errno);

	/* Out-of-range code */
	mfl = ZSOCK_TLS_MFL_4096 + 1;
	ret = zsock_setsockopt(sock, ZSOCK_SOL_TLS, ZSOCK_TLS_MAX_FRAGMENT_LENGTH,
			      &mfl, sizeof(mfl));
	zassert_equal(ret, -1, "setsockopt(invalid) should have failed");
	zassert_equal(errno, EINVAL, "expected EINVAL, got %d", errno);

	mfl = ZSOCK_TLS_MFL_DEFAULT - 1;
	ret = zsock_setsockopt(sock, ZSOCK_SOL_TLS, ZSOCK_TLS_MAX_FRAGMENT_LENGTH,
			      &mfl, sizeof(mfl));
	zassert_equal(ret, -1, "setsockopt(below MFL_DEFAULT) should have failed");
	zassert_equal(errno, EINVAL, "expected EINVAL, got %d", errno);

	/* Wrong optlen */
	mfl = ZSOCK_TLS_MFL_512;
	ret = zsock_setsockopt(sock, ZSOCK_SOL_TLS, ZSOCK_TLS_MAX_FRAGMENT_LENGTH,
			      &mfl, sizeof(uint8_t));
	zassert_equal(ret, -1, "setsockopt(wrong len) should have failed");
	zassert_equal(errno, EINVAL, "expected EINVAL, got %d", errno);

	test_close(sock);
}

#if defined(CONFIG_MBEDTLS)
static void prepare_tls_client_with_sockopt_mfl(int *client_sock,
						struct net_sockaddr *s_saddr, int mfl_value)
{
	struct net_sockaddr c_saddr, addr;
	net_socklen_t addrlen = sizeof(addr);
	struct connect_data test_data;
	int accepted;
	int mfl = mfl_value;

	prepare_sock_tls_v4(MY_IPV4_ADDR, ANY_PORT, client_sock,
			    (struct net_sockaddr_in *)&c_saddr, NET_IPPROTO_TLS_1_2);
	test_config_psk(-1, *client_sock);
	zassert_ok(zsock_setsockopt(*client_sock, ZSOCK_SOL_TLS, ZSOCK_TLS_MAX_FRAGMENT_LENGTH,
				    &mfl, sizeof(mfl)), "setsockopt(MFL) failed (%d)", errno);

	test_data.sock = *client_sock;
	test_data.peer_sock = &s_sock;
	test_data.addr = s_saddr;
	k_work_init_delayable(&test_data.work, client_connect_work_handler);
	test_work_reschedule(&test_data.work, K_NO_WAIT);

	test_accept(s_sock, &accepted, &addr, &addrlen);
	test_work_wait(&test_data.work);
	test_close(accepted);
}
#endif /* CONFIG_MBEDTLS */

ZTEST(net_socket_tls, test_mfl_handshake)
{
#if !defined(CONFIG_MBEDTLS)
	ztest_test_skip();
#else
	struct net_sockaddr s_saddr;
	mbedtls_ssl_context *ssl;

	if (!IS_ENABLED(CONFIG_NET_SOCKETS_TLS_SET_MAX_FRAGMENT_LENGTH)) {
		ztest_test_skip();
	}

	prepare_sock_tls_v4(MY_IPV4_ADDR, ANY_PORT, &s_sock,
			    (struct net_sockaddr_in *)&s_saddr, NET_IPPROTO_TLS_1_2);
	test_config_psk(s_sock, -1);
	test_bind(s_sock, &s_saddr, sizeof(struct net_sockaddr_in));
	test_listen(s_sock);

	prepare_tls_client_with_sockopt_mfl(&c_sock, &s_saddr, ZSOCK_TLS_MFL_512);
	prepare_tls_client_with_sockopt_mfl(&c_sock_2, &s_saddr, ZSOCK_TLS_MFL_1024);

	ssl = ztls_get_mbedtls_ssl_context(c_sock);
	zassert_not_null(ssl, "Failed to get mbedTLS context for client 1");
	zassert_equal(mbedtls_ssl_get_max_out_record_payload(ssl), 512,
		      "MFL not negotiated to 512");

	ssl = ztls_get_mbedtls_ssl_context(c_sock_2);
	zassert_not_null(ssl, "Failed to get mbedTLS context for client 2");
	zassert_equal(mbedtls_ssl_get_max_out_record_payload(ssl), 1024,
		      "MFL not negotiated to 1024");
#endif
}

ZTEST(net_socket_tls, test_mfl_reset_to_default)
{
#if !defined(CONFIG_MBEDTLS)
	ztest_test_skip();
#else
	struct net_sockaddr s_saddr, c_saddr, addr;
	net_socklen_t addrlen = sizeof(addr);
	struct connect_data test_data;
	mbedtls_ssl_context *ssl;
	int accepted;
	int mfl;

	if (!IS_ENABLED(CONFIG_NET_SOCKETS_TLS_SET_MAX_FRAGMENT_LENGTH)) {
		ztest_test_skip();
	}

	prepare_sock_tls_v4(MY_IPV4_ADDR, ANY_PORT, &s_sock,
			    (struct net_sockaddr_in *)&s_saddr, NET_IPPROTO_TLS_1_2);
	test_config_psk(s_sock, -1);
	test_bind(s_sock, &s_saddr, sizeof(struct net_sockaddr_in));
	test_listen(s_sock);

	prepare_sock_tls_v4(MY_IPV4_ADDR, ANY_PORT, &c_sock,
			    (struct net_sockaddr_in *)&c_saddr, NET_IPPROTO_TLS_1_2);
	test_config_psk(-1, c_sock);

	/* Override to MFL_512, then reset back to the global default before
	 * connecting, the handshake should reflect the reset, not the
	 * earlier override.
	 */
	mfl = ZSOCK_TLS_MFL_512;
	zassert_ok(zsock_setsockopt(c_sock, ZSOCK_SOL_TLS, ZSOCK_TLS_MAX_FRAGMENT_LENGTH,
				    &mfl, sizeof(mfl)), "setsockopt(MFL_512) failed (%d)", errno);

	mfl = ZSOCK_TLS_MFL_DEFAULT;
	zassert_ok(zsock_setsockopt(c_sock, ZSOCK_SOL_TLS, ZSOCK_TLS_MAX_FRAGMENT_LENGTH,
				    &mfl, sizeof(mfl)),
		   "setsockopt(MFL_DEFAULT) failed (%d)", errno);

	test_data.sock = c_sock;
	test_data.peer_sock = &s_sock;
	test_data.addr = &s_saddr;
	k_work_init_delayable(&test_data.work, client_connect_work_handler);
	test_work_reschedule(&test_data.work, K_NO_WAIT);

	test_accept(s_sock, &accepted, &addr, &addrlen);
	test_work_wait(&test_data.work);
	test_close(accepted);

	/* CONFIG_MBEDTLS_SSL_IN_CONTENT_LEN and CONFIG_MBEDTLS_SSL_OUT_CONTENT_LEN
	 * default to 1500, which auto-derives to MFL_1024.
	 */
	ssl = ztls_get_mbedtls_ssl_context(c_sock);
	zassert_not_null(ssl, "Failed to get mbedTLS context");
	zassert_equal(mbedtls_ssl_get_max_out_record_payload(ssl), 1024,
		      "MFL not reset to global default (1024)");
#endif
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
	test_config_tls13_suites(s_sock, c_sock);

	test_bind(s_sock, (struct net_sockaddr *)&s_saddr,
		  sizeof(struct net_sockaddr_in6));
	test_listen(s_sock);

	test_data.sock = c_sock;
	test_data.addr = (struct net_sockaddr *)&s_saddr;
	test_data.peer_sock = &s_sock;
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

ZTEST(net_socket_tls, test_tls13_client_poll_after_ticket)
{
#if !defined(WOLFSSL_TLS13) || !defined(CONFIG_WOLFSSL)
	ztest_test_skip();
#else
	struct net_sockaddr_in6 c_saddr, s_saddr;
	struct net_sockaddr addr;
	net_socklen_t addrlen = sizeof(addr);
	struct connect_data test_data;
	uint8_t tx_buf[] = TEST_STR_SMALL;
	uint8_t rx_buf[sizeof(tx_buf)];
	struct zsock_pollfd fds[1];
	int ret;

	prepare_sock_tls_v6(MY_IPV6_ADDR, ANY_PORT, &c_sock, &c_saddr, NET_IPPROTO_TLS_1_3);
	prepare_sock_tls_v6(MY_IPV6_ADDR, ANY_PORT, &s_sock, &s_saddr, NET_IPPROTO_TLS_1_3);
	test_config_psk(s_sock, c_sock);
	test_config_tls13_suites(s_sock, c_sock);
	/* The server sends a ticket only with its session cache on */
	ret = ZSOCK_TLS_SESSION_CACHE_ENABLED;
	zassert_ok(zsock_setsockopt(s_sock, ZSOCK_SOL_TLS, ZSOCK_TLS_SESSION_CACHE, &ret,
				    sizeof(ret)), "server session cache (%d)", errno);
	test_bind(s_sock, (struct net_sockaddr *)&s_saddr, sizeof(struct net_sockaddr_in6));
	test_listen(s_sock);

	test_data.sock = c_sock;
	test_data.addr = (struct net_sockaddr *)&s_saddr;
	test_data.peer_sock = &s_sock;
	k_work_init_delayable(&test_data.work, client_connect_work_handler);
	test_work_reschedule(&test_data.work, K_NO_WAIT);
	test_accept(s_sock, &new_sock, &addr, &addrlen);
	test_work_wait(&test_data.work);

	k_sleep(K_MSEC(100));
	fds[0].fd = c_sock;
	fds[0].events = ZSOCK_POLLIN;
	ret = zsock_poll(fds, 1, 100);
	zassert_equal(ret, 0, "poll() after ticket: ret %d revents 0x%x", ret, fds[0].revents);

	test_send(new_sock, tx_buf, sizeof(tx_buf), 0);
	ret = zsock_poll(fds, 1, 500);
	zassert_equal(ret, 1, "poll() missed data");
	zassert_equal(fds[0].revents, ZSOCK_POLLIN, "revents 0x%x", fds[0].revents);
	ret = zsock_recv(c_sock, rx_buf, sizeof(rx_buf), 0);
	zassert_equal(ret, sizeof(tx_buf), "recv() failed %d", errno);

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

	test_psk_id = psk_id;
	test_sockets_close();
}

/* Neither backend builds TLS 1.0 or 1.1, so a TLS_1_0 socket runs TLS 1.2. */
ZTEST(net_socket_tls, test_tls_1_0_socket_runs_tls_1_2)
{
	struct net_sockaddr c_saddr, s_saddr, addr;
	net_socklen_t addrlen = sizeof(addr);
	struct connect_data test_data;

	prepare_sock_tls_v4(MY_IPV4_ADDR, ANY_PORT, &c_sock, (struct net_sockaddr_in *)&c_saddr,
			    NET_IPPROTO_TLS_1_0);
	prepare_sock_tls_v4(MY_IPV4_ADDR, ANY_PORT, &s_sock, (struct net_sockaddr_in *)&s_saddr,
			    NET_IPPROTO_TLS_1_2);
	test_config_psk(s_sock, c_sock);
	test_bind(s_sock, &s_saddr, sizeof(struct net_sockaddr_in));
	test_listen(s_sock);

	test_data.sock = c_sock;
	test_data.addr = &s_saddr;
	test_data.peer_sock = &s_sock;
	k_work_init_delayable(&test_data.work, client_connect_work_handler);
	test_work_reschedule(&test_data.work, K_NO_WAIT);

	test_accept(s_sock, &new_sock, &addr, &addrlen);
	test_work_wait(&test_data.work);
}

/* wolfSSL-only: a second connect() handshakes with the new peer, where mbedTLS refuses it. */
ZTEST(net_socket_tls, test_dtls_client_reconnect_new_peer)
{
#if !defined(CONFIG_NET_SOCKETS_ENABLE_DTLS) || !defined(CONFIG_WOLFSSL)
	ztest_test_skip();
#else
	struct net_sockaddr c_saddr, s_saddr, s2_saddr;
	struct connect_data test_data;
	int role = ZSOCK_TLS_DTLS_ROLE_SERVER;
	struct zsock_pollfd fds[1];
	uint8_t rx_buf;
	int ret;

	prepare_sock_dtls_v4(MY_IPV4_ADDR, CLIENT_1_PORT, &c_sock,
			     (struct net_sockaddr_in *)&c_saddr, NET_IPPROTO_DTLS_1_2);
	prepare_sock_dtls_v4(MY_IPV4_ADDR, SERVER_PORT, &s_sock,
			     (struct net_sockaddr_in *)&s_saddr, NET_IPPROTO_DTLS_1_2);
	/* c_sock_2 serves as the second server */
	prepare_sock_dtls_v4(MY_IPV4_ADDR, CLIENT_2_PORT, &c_sock_2,
			     (struct net_sockaddr_in *)&s2_saddr, NET_IPPROTO_DTLS_1_2);
	test_config_psk(s_sock, c_sock);
	test_config_psk(c_sock_2, -1);
	zassert_ok(zsock_setsockopt(s_sock, ZSOCK_SOL_TLS, ZSOCK_TLS_DTLS_ROLE, &role,
				    sizeof(role)));
	zassert_ok(zsock_setsockopt(c_sock_2, ZSOCK_SOL_TLS, ZSOCK_TLS_DTLS_ROLE, &role,
				    sizeof(role)));
	test_bind(c_sock, &c_saddr, sizeof(struct net_sockaddr_in));
	test_bind(s_sock, &s_saddr, sizeof(struct net_sockaddr_in));
	test_bind(c_sock_2, &s2_saddr, sizeof(struct net_sockaddr_in));

	for (int i = 0; i < 2; i++) {
		int srv = i == 0 ? s_sock : c_sock_2;

		test_data.sock = c_sock;
		test_data.addr = i == 0 ? &s_saddr : &s2_saddr;
		test_data.peer_sock = i == 0 ? &s_sock : &c_sock_2;
		k_work_init_delayable(&test_data.work, dtls_client_connect_send_work_handler);
		test_work_reschedule(&test_data.work, K_NO_WAIT);

		fds[0].fd = srv;
		fds[0].events = ZSOCK_POLLIN;
		ret = zsock_poll(fds, 1, 2000);
		zassert_equal(ret, 1, "server %d got no data after connect()", i + 1);
		ret = zsock_recv(srv, &rx_buf, sizeof(rx_buf), 0);
		zassert_equal(ret, sizeof(rx_buf), "server %d recv() failed", i + 1);
		test_work_wait(&test_data.work);
	}
#endif
}

/* wolfSSL-only: a reconnect does not inherit the error the last session latched. */
ZTEST(net_socket_tls, test_dtls_client_reconnect_clears_error)
{
#if !defined(CONFIG_NET_SOCKETS_ENABLE_DTLS) || !defined(CONFIG_WOLFSSL)
	ztest_test_skip();
#else
	struct net_sockaddr c_saddr, s_saddr, s2_saddr;
	struct connect_data test_data;
	struct timeval timeo_optval = { .tv_sec = 2 };
	int role = ZSOCK_TLS_DTLS_ROLE_SERVER;
	uint8_t rx_buf;
	int ret;

	prepare_sock_dtls_v4(MY_IPV4_ADDR, CLIENT_1_PORT, &c_sock,
			     (struct net_sockaddr_in *)&c_saddr, NET_IPPROTO_DTLS_1_2);
	prepare_sock_dtls_v4(MY_IPV4_ADDR, SERVER_PORT, &s_sock,
			     (struct net_sockaddr_in *)&s_saddr, NET_IPPROTO_DTLS_1_2);
	/* c_sock_2 serves as the second server */
	prepare_sock_dtls_v4(MY_IPV4_ADDR, CLIENT_2_PORT, &c_sock_2,
			     (struct net_sockaddr_in *)&s2_saddr, NET_IPPROTO_DTLS_1_2);
	test_config_psk(s_sock, c_sock);
	test_config_psk(c_sock_2, -1);
	zassert_ok(zsock_setsockopt(s_sock, ZSOCK_SOL_TLS, ZSOCK_TLS_DTLS_ROLE, &role,
				    sizeof(role)));
	zassert_ok(zsock_setsockopt(c_sock_2, ZSOCK_SOL_TLS, ZSOCK_TLS_DTLS_ROLE, &role,
				    sizeof(role)));
	zassert_ok(zsock_setsockopt(c_sock, ZSOCK_SOL_SOCKET, ZSOCK_SO_RCVTIMEO, &timeo_optval,
				    sizeof(timeo_optval)));
	test_bind(c_sock, &c_saddr, sizeof(struct net_sockaddr_in));
	test_bind(s_sock, &s_saddr, sizeof(struct net_sockaddr_in));
	test_bind(c_sock_2, &s2_saddr, sizeof(struct net_sockaddr_in));

	test_data.sock = c_sock;
	test_data.addr = &s_saddr;
	test_data.peer_sock = &s_sock;
	k_work_init_delayable(&test_data.work, dtls_client_connect_send_work_handler);
	test_work_reschedule(&test_data.work, K_NO_WAIT);
	ret = zsock_recv(s_sock, &rx_buf, sizeof(rx_buf), 0);
	zassert_equal(ret, sizeof(rx_buf), "server 1 recv() failed");
	test_work_wait(&test_data.work);

	/* The first server's close_notify latches ENOTCONN on the client */
	test_close(s_sock);
	s_sock = -1;
	ret = zsock_recv(c_sock, &rx_buf, sizeof(rx_buf), 0);
	zassert_equal(ret, -1, "recv() after close_notify returned %d", ret);
	zassert_equal(errno, ENOTCONN, "unexpected errno %d", errno);

	test_data.addr = &s2_saddr;
	test_data.peer_sock = &c_sock_2;
	k_work_init_delayable(&test_data.work, dtls_client_connect_send_work_handler);
	test_work_reschedule(&test_data.work, K_NO_WAIT);
	ret = zsock_recv(c_sock_2, &rx_buf, sizeof(rx_buf), 0);
	zassert_equal(ret, sizeof(rx_buf), "server 2 recv() failed");
	test_work_wait(&test_data.work);

	test_sockets_close();
#endif
}

#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS) && defined(CONFIG_WOLFSSL)
static void *test_wolfssl_null_malloc(size_t size)
{
	ARG_UNUSED(size);

	return NULL;
}
#endif

/* wolfSSL-only: a DTLS server that cannot rebuild its session reports ENOMEM, then recovers. */
ZTEST(net_socket_tls, test_dtls_server_reset_out_of_memory)
{
#if !defined(CONFIG_NET_SOCKETS_ENABLE_DTLS) || !defined(CONFIG_WOLFSSL)
	ztest_test_skip();
#else
	struct net_sockaddr c_saddr, s_saddr;
	struct connect_data test_data;
	struct timeval timeo_optval = { .tv_sec = 1 };
	int role = ZSOCK_TLS_DTLS_ROLE_SERVER;
	uint8_t junk[64] = { 0 };
	uint8_t rx_buf;
	int helper_sock;
	int ret;

	prepare_sock_dtls_v4(MY_IPV4_ADDR, CLIENT_1_PORT, &c_sock,
			     (struct net_sockaddr_in *)&c_saddr, NET_IPPROTO_DTLS_1_2);
	prepare_sock_dtls_v4(MY_IPV4_ADDR, SERVER_PORT, &s_sock,
			     (struct net_sockaddr_in *)&s_saddr, NET_IPPROTO_DTLS_1_2);
	test_config_psk(s_sock, c_sock);
	zassert_ok(zsock_setsockopt(s_sock, ZSOCK_SOL_TLS, ZSOCK_TLS_DTLS_ROLE, &role,
				    sizeof(role)));
	zassert_ok(zsock_setsockopt(s_sock, ZSOCK_SOL_SOCKET, ZSOCK_SO_RCVTIMEO, &timeo_optval,
				    sizeof(timeo_optval)));
	test_bind(c_sock, &c_saddr, sizeof(struct net_sockaddr_in));
	test_bind(s_sock, &s_saddr, sizeof(struct net_sockaddr_in));

	ret = zsock_recv(s_sock, &rx_buf, sizeof(rx_buf), ZSOCK_MSG_DONTWAIT);
	zassert_true(ret == -1 && errno == EAGAIN, "first recv() returned %d (%d)", ret, errno);

	/* A datagram the server must buffer while every wolfSSL allocation fails */
	helper_sock = zsock_socket(NET_AF_INET, NET_SOCK_DGRAM, NET_IPPROTO_UDP);
	zassert_true(helper_sock >= 0, "helper socket failed (%d)", errno);
	ret = zsock_sendto(helper_sock, junk, sizeof(junk), 0, &s_saddr,
			   sizeof(struct net_sockaddr_in));
	zassert_equal(ret, sizeof(junk), "helper sendto() failed (%d)", errno);
	(void)zsock_close(helper_sock);
	k_msleep(10);

	zassert_ok(wolfSSL_SetAllocators(test_wolfssl_null_malloc, NULL, NULL));
	ret = zsock_recv(s_sock, &rx_buf, sizeof(rx_buf), 0);
	zassert_ok(wolfSSL_SetAllocators(NULL, NULL, NULL));
	zassert_equal(ret, -1, "recv() without memory returned %d", ret);
	zassert_equal(errno, ENOMEM, "unexpected errno %d", errno);

	test_data.sock = c_sock;
	test_data.addr = &s_saddr;
	test_data.peer_sock = &s_sock;
	k_work_init_delayable(&test_data.work, dtls_client_connect_send_work_handler);
	test_work_reschedule(&test_data.work, K_NO_WAIT);
	ret = zsock_recv(s_sock, &rx_buf, sizeof(rx_buf), 0);
	zassert_equal(ret, sizeof(rx_buf), "recv() after recovery failed (%d)", errno);
	test_work_wait(&test_data.work);

	test_sockets_close();
#endif
}

/* wolfSSL-only: a DTLS handshake that runs out of retransmissions latches ETIMEDOUT. */
ZTEST(net_socket_tls, test_dtls_client_handshake_timeout_latches)
{
#if !defined(CONFIG_NET_SOCKETS_ENABLE_DTLS) || !defined(CONFIG_WOLFSSL)
	ztest_test_skip();
#else
	struct net_sockaddr c_saddr, s_saddr;
	uint32_t timeout_min = 1000;
	uint32_t timeout_max = 2000;
	int no = 0;
	int so_error = 0;
	net_socklen_t optlen = sizeof(so_error);
	uint8_t tx_buf = 0;
	int ret;

	prepare_sock_dtls_v4(MY_IPV4_ADDR, CLIENT_1_PORT, &c_sock,
			     (struct net_sockaddr_in *)&c_saddr, NET_IPPROTO_DTLS_1_2);
	test_config_psk(-1, c_sock);
	zassert_ok(zsock_setsockopt(c_sock, ZSOCK_SOL_TLS, ZSOCK_TLS_DTLS_HANDSHAKE_TIMEOUT_MIN,
				    &timeout_min, sizeof(timeout_min)));
	zassert_ok(zsock_setsockopt(c_sock, ZSOCK_SOL_TLS, ZSOCK_TLS_DTLS_HANDSHAKE_TIMEOUT_MAX,
				    &timeout_max, sizeof(timeout_max)));
	zassert_ok(zsock_setsockopt(c_sock, ZSOCK_SOL_TLS, ZSOCK_TLS_DTLS_HANDSHAKE_ON_CONNECT, &no,
				    sizeof(no)));
	test_bind(c_sock, &c_saddr, sizeof(struct net_sockaddr_in));

	/* A plain UDP peer that never answers the handshake */
	prepare_sock_udp_v4(MY_IPV4_ADDR, SERVER_PORT, &s_sock, (struct net_sockaddr_in *)&s_saddr);
	test_bind(s_sock, &s_saddr, sizeof(struct net_sockaddr_in));

	test_connect(c_sock, &s_saddr, sizeof(struct net_sockaddr_in));
	ret = zsock_send(c_sock, &tx_buf, sizeof(tx_buf), 0);
	zassert_equal(ret, -1, "send() to a silent peer returned %d", ret);
	zassert_equal(errno, ETIMEDOUT, "unexpected errno %d", errno);

	zassert_ok(zsock_getsockopt(c_sock, ZSOCK_SOL_SOCKET, ZSOCK_SO_ERROR, &so_error, &optlen));
	zassert_equal(so_error, ETIMEDOUT, "SO_ERROR is %d after a handshake timeout", so_error);

	test_sockets_close();
#endif
}

#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS) && defined(CONFIG_WOLFSSL)
static int unpin_connect_errno;
static int unpin_send_errno;

static void dtls_client_unpin_work_handler(struct k_work *work)
{
	struct k_work_delayable *dwork = k_work_delayable_from_work(work);
	struct connect_data *data = CONTAINER_OF(dwork, struct connect_data, work);
	uint8_t tx_buf = 0;

	unpin_connect_errno = zsock_connect(data->sock, data->addr,
					    sizeof(struct net_sockaddr_in)) < 0 ? errno : 0;
	unpin_send_errno = zsock_send(data->sock, &tx_buf, sizeof(tx_buf), 0) < 0 ? errno : 0;
}
#endif

/* wolfSSL-only: a server driven without blocking lets go of a peer that went silent. */
ZTEST(net_socket_tls, test_dtls_server_unpins_silent_peer)
{
#if !defined(CONFIG_NET_SOCKETS_ENABLE_DTLS) || !defined(CONFIG_WOLFSSL)
	ztest_test_skip();
#else
	struct net_sockaddr c_saddr, s_saddr, h_saddr;
	struct connect_data test_data;
	int no_peer = -1;
	struct timeval timeo_optval = { .tv_sec = 2 };
	uint32_t timeout_min = 1000;
	uint32_t timeout_max = 2000;
	int role = ZSOCK_TLS_DTLS_ROLE_SERVER;
	int no = 0;
	uint8_t hello[512];
	uint8_t rx_buf;
	int hello_len;
	int ret = -1;

	/* Capture a ClientHello on a plain UDP socket */
	prepare_sock_dtls_v4(MY_IPV4_ADDR, CLIENT_1_PORT, &c_sock,
			     (struct net_sockaddr_in *)&c_saddr, NET_IPPROTO_DTLS_1_2);
	test_config_psk(-1, c_sock);
	test_bind(c_sock, &c_saddr, sizeof(struct net_sockaddr_in));
	prepare_sock_udp_v4(MY_IPV4_ADDR, SERVER_PORT, &s_sock, (struct net_sockaddr_in *)&s_saddr);
	test_bind(s_sock, &s_saddr, sizeof(struct net_sockaddr_in));
	zassert_ok(zsock_setsockopt(s_sock, ZSOCK_SOL_SOCKET, ZSOCK_SO_RCVTIMEO, &timeo_optval,
				    sizeof(timeo_optval)));

	test_data.sock = c_sock;
	test_data.addr = &s_saddr;
	test_data.peer_sock = &no_peer;
	k_work_init_delayable(&test_data.work, dtls_client_connect_send_no_assert_work_handler);
	test_work_reschedule(&test_data.work, K_NO_WAIT);
	hello_len = zsock_recv(s_sock, hello, sizeof(hello), 0);
	zassert_true(hello_len > 0, "no ClientHello captured (%d)", errno);
	test_work_wait(&test_data.work);
	test_sockets_close();

	/* The server answers a replayed ClientHello from a peer that never replies */
	prepare_sock_dtls_v4(MY_IPV4_ADDR, SERVER_PORT, &s_sock,
			     (struct net_sockaddr_in *)&s_saddr, NET_IPPROTO_DTLS_1_2);
	test_config_psk(s_sock, -1);
	zassert_ok(zsock_setsockopt(s_sock, ZSOCK_SOL_TLS, ZSOCK_TLS_DTLS_ROLE, &role,
				    sizeof(role)));
	zassert_ok(zsock_setsockopt(s_sock, ZSOCK_SOL_TLS, ZSOCK_TLS_DTLS_HANDSHAKE_TIMEOUT_MIN,
				    &timeout_min, sizeof(timeout_min)));
	zassert_ok(zsock_setsockopt(s_sock, ZSOCK_SOL_TLS, ZSOCK_TLS_DTLS_HANDSHAKE_TIMEOUT_MAX,
				    &timeout_max, sizeof(timeout_max)));
	test_bind(s_sock, &s_saddr, sizeof(struct net_sockaddr_in));
	(void)zsock_recv(s_sock, &rx_buf, sizeof(rx_buf), ZSOCK_MSG_DONTWAIT);

	prepare_sock_udp_v4(MY_IPV4_ADDR, CLIENT_2_PORT, &c_sock_2,
			    (struct net_sockaddr_in *)&h_saddr);
	test_bind(c_sock_2, &h_saddr, sizeof(struct net_sockaddr_in));
	ret = zsock_sendto(c_sock_2, hello, hello_len, 0, &s_saddr, sizeof(struct net_sockaddr_in));
	zassert_equal(ret, hello_len, "replay failed (%d)", errno);
	k_msleep(10);
	(void)zsock_recv(s_sock, &rx_buf, sizeof(rx_buf), ZSOCK_MSG_DONTWAIT);

	/* A real client keeps retrying while the server is only polled */
	prepare_sock_dtls_v4(MY_IPV4_ADDR, CLIENT_1_PORT, &c_sock,
			     (struct net_sockaddr_in *)&c_saddr, NET_IPPROTO_DTLS_1_2);
	test_config_psk(-1, c_sock);
	zassert_ok(zsock_setsockopt(c_sock, ZSOCK_SOL_TLS, ZSOCK_TLS_DTLS_HANDSHAKE_ON_CONNECT, &no,
				    sizeof(no)));
	test_bind(c_sock, &c_saddr, sizeof(struct net_sockaddr_in));
	test_data.sock = c_sock;
	k_work_init_delayable(&test_data.work, dtls_client_unpin_work_handler);
	test_work_reschedule(&test_data.work, K_NO_WAIT);

	for (int i = 0; i < 150; i++) {
		ret = zsock_recv(s_sock, &rx_buf, sizeof(rx_buf), ZSOCK_MSG_DONTWAIT);
		if (ret == sizeof(rx_buf)) {
			break;
		}
		k_msleep(100);
	}
	zassert_equal(ret, sizeof(rx_buf), "server stayed pinned to the silent peer (%d %d)",
		      unpin_connect_errno, unpin_send_errno);
	test_work_wait(&test_data.work);
	zassert_equal(unpin_connect_errno, 0, "connect() failed (%d)", unpin_connect_errno);
	zassert_equal(unpin_send_errno, 0, "send() failed (%d)", unpin_send_errno);

	test_sockets_close();
#endif
}

/* wolfSSL-only: replayed ClientHellos from many peers do not lock a real client out. */
ZTEST(net_socket_tls, test_dtls_server_survives_hello_storm)
{
#if !defined(CONFIG_NET_SOCKETS_ENABLE_DTLS) || !defined(CONFIG_WOLFSSL)
	ztest_test_skip();
#else
	struct net_sockaddr c_saddr, s_saddr, h_saddr;
	struct connect_data test_data;
	int no_peer = -1;
	struct timeval timeo_optval = { .tv_sec = 2 };
	int role = ZSOCK_TLS_DTLS_ROLE_SERVER;
	int no = 0;
	int storm[3];
	uint8_t hello[512];
	uint8_t rx_buf;
	int hello_len;
	int ret = -1;

	/* Capture a ClientHello on a plain UDP socket */
	prepare_sock_dtls_v4(MY_IPV4_ADDR, CLIENT_1_PORT, &c_sock,
			     (struct net_sockaddr_in *)&c_saddr, NET_IPPROTO_DTLS_1_2);
	test_config_psk(-1, c_sock);
	test_bind(c_sock, &c_saddr, sizeof(struct net_sockaddr_in));
	prepare_sock_udp_v4(MY_IPV4_ADDR, SERVER_PORT, &s_sock,
			    (struct net_sockaddr_in *)&s_saddr);
	test_bind(s_sock, &s_saddr, sizeof(struct net_sockaddr_in));
	zassert_ok(zsock_setsockopt(s_sock, ZSOCK_SOL_SOCKET, ZSOCK_SO_RCVTIMEO, &timeo_optval,
				    sizeof(timeo_optval)));

	test_data.sock = c_sock;
	test_data.addr = &s_saddr;
	test_data.peer_sock = &no_peer;
	k_work_init_delayable(&test_data.work, dtls_client_connect_send_no_assert_work_handler);
	test_work_reschedule(&test_data.work, K_NO_WAIT);
	hello_len = zsock_recv(s_sock, hello, sizeof(hello), 0);
	zassert_true(hello_len > 0, "no ClientHello captured (%d)", errno);
	test_work_wait(&test_data.work);
	test_sockets_close();

	prepare_sock_dtls_v4(MY_IPV4_ADDR, SERVER_PORT, &s_sock,
			     (struct net_sockaddr_in *)&s_saddr, NET_IPPROTO_DTLS_1_2);
	test_config_psk(s_sock, -1);
	zassert_ok(zsock_setsockopt(s_sock, ZSOCK_SOL_TLS, ZSOCK_TLS_DTLS_ROLE, &role,
				    sizeof(role)));
	test_bind(s_sock, &s_saddr, sizeof(struct net_sockaddr_in));

	for (int i = 0; i < ARRAY_SIZE(storm); i++) {
		prepare_sock_udp_v4(MY_IPV4_ADDR, 4250 + i, &storm[i],
				    (struct net_sockaddr_in *)&h_saddr);
		test_bind(storm[i], &h_saddr, sizeof(struct net_sockaddr_in));
	}

	prepare_sock_dtls_v4(MY_IPV4_ADDR, CLIENT_1_PORT, &c_sock,
			     (struct net_sockaddr_in *)&c_saddr, NET_IPPROTO_DTLS_1_2);
	test_config_psk(-1, c_sock);
	zassert_ok(zsock_setsockopt(c_sock, ZSOCK_SOL_TLS, ZSOCK_TLS_DTLS_HANDSHAKE_ON_CONNECT,
				    &no, sizeof(no)));
	test_bind(c_sock, &c_saddr, sizeof(struct net_sockaddr_in));
	test_data.sock = c_sock;
	k_work_init_delayable(&test_data.work, dtls_client_unpin_work_handler);
	test_work_reschedule(&test_data.work, K_NO_WAIT);

	/* Each storm peer repeats its ClientHello faster than a session expires */
	for (int i = 0; i < 40; i++) {
		for (int j = 0; j < ARRAY_SIZE(storm); j++) {
			(void)zsock_sendto(storm[j], hello, hello_len, 0, &s_saddr,
					   sizeof(struct net_sockaddr_in));
		}

		ret = zsock_recv(s_sock, &rx_buf, sizeof(rx_buf), ZSOCK_MSG_DONTWAIT);
		if (ret == sizeof(rx_buf)) {
			break;
		}
		k_msleep(100);
	}

	for (int i = 0; i < ARRAY_SIZE(storm); i++) {
		(void)zsock_close(storm[i]);
	}

	zassert_equal(ret, sizeof(rx_buf), "a real client was locked out (%d %d)",
		      unpin_connect_errno, unpin_send_errno);
	test_work_wait(&test_data.work);

	test_sockets_close();
#endif
}

/* wolfSSL-only: a server driven without blocking gives up on a peer that vanished
 * mid-handshake, once wolfSSL has committed to it.
 */
ZTEST(net_socket_tls, test_dtls_server_times_out_vanished_peer)
{
#if !defined(CONFIG_NET_SOCKETS_ENABLE_DTLS) || !defined(CONFIG_WOLFSSL)
	ztest_test_skip();
#else
	static const unsigned char wrong_psk[sizeof(psk)] = { 0x5a };
	sec_tag_t wrong_tag = 17;
	struct net_sockaddr c_saddr, s_saddr, c2_saddr;
	struct connect_data test_data, bad_data;
	int no_peer = -1;
	uint32_t timeout_min = 1000;
	uint32_t timeout_max = 2000;
	int role = ZSOCK_TLS_DTLS_ROLE_SERVER;
	int no = 0;
	uint8_t rx_buf;
	int ret = -1;

	prepare_sock_dtls_v4(MY_IPV4_ADDR, SERVER_PORT, &s_sock,
			     (struct net_sockaddr_in *)&s_saddr, NET_IPPROTO_DTLS_1_2);
	test_config_psk(s_sock, -1);
	zassert_ok(zsock_setsockopt(s_sock, ZSOCK_SOL_TLS, ZSOCK_TLS_DTLS_ROLE, &role,
				    sizeof(role)));
	zassert_ok(zsock_setsockopt(s_sock, ZSOCK_SOL_TLS, ZSOCK_TLS_DTLS_HANDSHAKE_TIMEOUT_MIN,
				    &timeout_min, sizeof(timeout_min)));
	zassert_ok(zsock_setsockopt(s_sock, ZSOCK_SOL_TLS, ZSOCK_TLS_DTLS_HANDSHAKE_TIMEOUT_MAX,
				    &timeout_max, sizeof(timeout_max)));
	test_bind(s_sock, &s_saddr, sizeof(struct net_sockaddr_in));

	/* The right identity with the wrong key: the server commits, then never sees a
	 * Finished it can decrypt
	 */
	(void)tls_credential_delete(wrong_tag, TLS_CREDENTIAL_PSK);
	(void)tls_credential_delete(wrong_tag, TLS_CREDENTIAL_PSK_ID);
	zassert_ok(tls_credential_add(wrong_tag, TLS_CREDENTIAL_PSK, wrong_psk,
				      sizeof(wrong_psk)));
	zassert_ok(tls_credential_add(wrong_tag, TLS_CREDENTIAL_PSK_ID, psk_id, strlen(psk_id)));
	prepare_sock_dtls_v4(MY_IPV4_ADDR, CLIENT_2_PORT, &c_sock_2,
			     (struct net_sockaddr_in *)&c2_saddr, NET_IPPROTO_DTLS_1_2);
	zassert_ok(zsock_setsockopt(c_sock_2, ZSOCK_SOL_TLS, ZSOCK_TLS_SEC_TAG_LIST, &wrong_tag,
				    sizeof(wrong_tag)));
	test_bind(c_sock_2, &c2_saddr, sizeof(struct net_sockaddr_in));
	bad_data.sock = c_sock_2;
	bad_data.addr = &s_saddr;
	bad_data.peer_sock = &no_peer;
	k_work_init_delayable(&bad_data.work, dtls_client_connect_send_no_assert_work_handler);
	test_work_reschedule(&bad_data.work, K_NO_WAIT);

	for (int i = 0; i < 10; i++) {
		(void)zsock_recv(s_sock, &rx_buf, sizeof(rx_buf), ZSOCK_MSG_DONTWAIT);
		k_msleep(50);
	}

	test_work_wait(&bad_data.work);
	test_close(c_sock_2);
	c_sock_2 = -1;

	/* A good client gets through once the server lets the vanished peer go */
	prepare_sock_dtls_v4(MY_IPV4_ADDR, CLIENT_1_PORT, &c_sock,
			     (struct net_sockaddr_in *)&c_saddr, NET_IPPROTO_DTLS_1_2);
	test_config_psk(-1, c_sock);
	zassert_ok(zsock_setsockopt(c_sock, ZSOCK_SOL_TLS, ZSOCK_TLS_DTLS_HANDSHAKE_ON_CONNECT, &no,
				    sizeof(no)));
	test_bind(c_sock, &c_saddr, sizeof(struct net_sockaddr_in));
	test_data.sock = c_sock;
	test_data.addr = &s_saddr;
	k_work_init_delayable(&test_data.work, dtls_client_unpin_work_handler);
	test_work_reschedule(&test_data.work, K_NO_WAIT);

	for (int i = 0; i < 150; i++) {
		ret = zsock_recv(s_sock, &rx_buf, sizeof(rx_buf), ZSOCK_MSG_DONTWAIT);
		if (ret == sizeof(rx_buf)) {
			break;
		}
		k_msleep(100);
	}
	zassert_equal(ret, sizeof(rx_buf), "server never gave up on the vanished peer (%d %d)",
		      unpin_connect_errno, unpin_send_errno);
	test_work_wait(&test_data.work);
	zassert_equal(unpin_connect_errno, 0, "connect() failed (%d)", unpin_connect_errno);
	zassert_equal(unpin_send_errno, 0, "send() failed (%d)", unpin_send_errno);

	(void)tls_credential_delete(wrong_tag, TLS_CREDENTIAL_PSK);
	(void)tls_credential_delete(wrong_tag, TLS_CREDENTIAL_PSK_ID);
	test_sockets_close();
#endif
}

/* wolfSSL-only: a DTLS server whose read side is shut down reads EOF. */
ZTEST(net_socket_tls, test_dtls_server_shut_rd_reads_eof)
{
#if !defined(CONFIG_NET_SOCKETS_ENABLE_DTLS) || !defined(CONFIG_WOLFSSL)
	ztest_test_skip();
#else
	struct net_sockaddr s_saddr;
	struct timeval timeo_optval = { .tv_sec = 1 };
	int role = ZSOCK_TLS_DTLS_ROLE_SERVER;
	uint8_t rx_buf;
	int ret;

	prepare_sock_dtls_v4(MY_IPV4_ADDR, SERVER_PORT, &s_sock,
			     (struct net_sockaddr_in *)&s_saddr, NET_IPPROTO_DTLS_1_2);
	test_config_psk(s_sock, -1);
	zassert_ok(zsock_setsockopt(s_sock, ZSOCK_SOL_TLS, ZSOCK_TLS_DTLS_ROLE, &role,
				    sizeof(role)));
	zassert_ok(zsock_setsockopt(s_sock, ZSOCK_SOL_SOCKET, ZSOCK_SO_RCVTIMEO, &timeo_optval,
				    sizeof(timeo_optval)));
	test_bind(s_sock, &s_saddr, sizeof(struct net_sockaddr_in));

	zassert_ok(zsock_shutdown(s_sock, ZSOCK_SHUT_RD), "shutdown() failed (%d)", errno);

	ret = zsock_recv(s_sock, &rx_buf, sizeof(rx_buf), 0);
	zassert_equal(ret, 0, "recv() after SHUT_RD returned %d (%d)", ret, errno);

	test_sockets_close();
#endif
}

/* wolfSSL-only: datagrams that bring no handshake progress do not hold off a retransmission. */
ZTEST(net_socket_tls, test_dtls_client_retransmit_under_traffic)
{
#if !defined(CONFIG_NET_SOCKETS_ENABLE_DTLS) || !defined(CONFIG_WOLFSSL)
	ztest_test_skip();
#else
	struct net_sockaddr c_saddr, s_saddr;
	struct connect_data test_data;
	int no_peer = -1;
	uint8_t junk = 0, rx_buf[512];
	int flights = 0;

	prepare_sock_dtls_v4(MY_IPV4_ADDR, CLIENT_1_PORT, &c_sock,
			     (struct net_sockaddr_in *)&c_saddr, NET_IPPROTO_DTLS_1_2);
	test_config_psk(-1, c_sock);
	test_bind(c_sock, &c_saddr, sizeof(struct net_sockaddr_in));

	/* A plain UDP peer that never answers the handshake */
	prepare_sock_udp_v4(MY_IPV4_ADDR, SERVER_PORT, &s_sock, (struct net_sockaddr_in *)&s_saddr);
	test_bind(s_sock, &s_saddr, sizeof(struct net_sockaddr_in));

	test_data.sock = c_sock;
	test_data.addr = &s_saddr;
	test_data.peer_sock = &no_peer;
	k_work_init_delayable(&test_data.work, dtls_client_connect_send_no_assert_work_handler);
	test_work_reschedule(&test_data.work, K_NO_WAIT);

	/* Junk every 200 ms, past the 1 s DTLS timer and within the connect timeout */
	for (int i = 0; i < 9; i++) {
		k_msleep(200);
		while (zsock_recv(s_sock, rx_buf, sizeof(rx_buf), ZSOCK_MSG_DONTWAIT) > 0) {
			flights++;
		}
		(void)zsock_sendto(s_sock, &junk, sizeof(junk), 0, &c_saddr,
				   sizeof(struct net_sockaddr_in));
	}

	test_work_wait(&test_data.work);
	zassert_true(flights >= 2, "client sent %d ClientHello flight(s), no retransmission",
		     flights);
#endif
}

/* wolfSSL-only: a TCP FIN without a close_notify is a recv error, as on mbedTLS. */
ZTEST(net_socket_tls, test_tls_peer_fin_is_error)
{
#if !defined(CONFIG_WOLFSSL)
	ztest_test_skip();
#else
	struct timeval rcv_timeo = { .tv_sec = 2 };
	uint8_t rx_buf[sizeof(TEST_STR_SMALL)];
	int ret;

	test_prepare_tls_connection(NET_AF_INET);

	/* Closing the server then sends a FIN but no close_notify */
	test_wolfssl_mark_close_notify_sent(ztls_get_wolfssl_context(new_sock));
	test_close(new_sock);
	new_sock = -1;

	ret = zsock_setsockopt(c_sock, ZSOCK_SOL_SOCKET, ZSOCK_SO_RCVTIMEO, &rcv_timeo,
			       sizeof(rcv_timeo));
	zassert_ok(ret, "failed to set ZSOCK_SO_RCVTIMEO (%d)", errno);

	ret = zsock_recv(c_sock, rx_buf, sizeof(rx_buf), 0);
	zassert_equal(ret, -1, "a FIN without close_notify read as %d", ret);
	zassert_equal(errno, EIO, "unexpected errno %d", errno);

	test_sockets_close();

	k_sleep(TCP_TEARDOWN_TIMEOUT);
#endif
}

/* wolfSSL-only: a TCP reset is a recv error, not a clean EOF. */
ZTEST(net_socket_tls, test_tls_peer_rst_is_error)
{
#if !defined(CONFIG_WOLFSSL)
	ztest_test_skip();
#else
	struct timeval rcv_timeo = { .tv_sec = 2 };
	struct net_context *srv_ctx;
	uint8_t rx_buf[sizeof(TEST_STR_SMALL)];
	int ret;

	test_prepare_tls_connection(NET_AF_INET);

	/* Drop the server connection with neither close_notify nor FIN, so the next
	 * client segment draws a RST from the listener.
	 */
	srv_ctx = zsock_get_context_object(wolfSSL_get_fd(ztls_get_wolfssl_context(new_sock)));
	zassert_not_null(srv_ctx, "no server TCP context");
	test_wolfssl_mark_close_notify_sent(ztls_get_wolfssl_context(new_sock));
	zassert_ok(net_tcp_put(srv_ctx, true), "failed to drop the server connection");
	test_close(new_sock);
	new_sock = -1;

	test_send(c_sock, TEST_STR_SMALL, sizeof(TEST_STR_SMALL) - 1, 0);
	/* Let the RST land first, so wolfSSL reads it rather than poll() */
	k_sleep(K_MSEC(100));

	ret = zsock_setsockopt(c_sock, ZSOCK_SOL_SOCKET, ZSOCK_SO_RCVTIMEO, &rcv_timeo,
			       sizeof(rcv_timeo));
	zassert_ok(ret, "failed to set ZSOCK_SO_RCVTIMEO (%d)", errno);

	ret = zsock_recv(c_sock, rx_buf, sizeof(rx_buf), 0);
	zassert_equal(ret, -1, "a TCP reset read as %d", ret);
	zassert_true(errno == EIO || errno == ECONNRESET, "unexpected errno %d", errno);

	test_sockets_close();

	k_sleep(TCP_TEARDOWN_TIMEOUT);
#endif
}

/* A datagram bigger than one DTLS record fails, as mbedTLS refuses it */
ZTEST(net_socket_tls, test_dtls_send_oversized_datagram)
{
	static uint8_t big[4000];
	ssize_t ret;

	test_prepare_dtls_connection(NET_AF_INET);

	ret = zsock_send(c_sock, big, sizeof(big), 0);
	zassert_equal(ret, -1, "an oversized datagram sent %d bytes", (int)ret);
	zassert_equal(errno, ECONNABORTED, "unexpected errno %d", errno);

	test_sockets_close();
}

/* wolfSSL's PSK callback buffer holds MAX_PSK_ID_LEN bytes plus the terminator */
ZTEST(net_socket_tls, test_tls_psk_identity_max_len)
{
	static char long_id[2048];
	uint8_t rx_buf[sizeof(TEST_STR_SMALL) - 1];
	int id_len = 128;
	int ret;

#if defined(CONFIG_WOLFSSL)
	id_len = test_wolfssl_max_psk_id_len();
#endif
	zassert_true(id_len < sizeof(long_id), "identity of %d bytes does not fit", id_len);
	memset(long_id, 'i', id_len);
	test_psk_id = long_id;
	test_prepare_tls_connection(NET_AF_INET);

	test_send(c_sock, TEST_STR_SMALL, sizeof(rx_buf), 0);
	ret = zsock_recv(new_sock, rx_buf, sizeof(rx_buf), ZSOCK_MSG_WAITALL);
	zassert_equal(ret, sizeof(rx_buf), "recv() returned %d (%d)", ret, errno);
	zassert_mem_equal(rx_buf, TEST_STR_SMALL, sizeof(rx_buf));

	test_sockets_close();
	k_sleep(TCP_TEARDOWN_TIMEOUT);
}

ZTEST_SUITE(net_socket_tls, NULL, tls_tests_setup, NULL, tls_tests_after, NULL);
