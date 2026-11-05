/*
 * Copyright (c) 2021 Nordic Semiconductor
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(net_test, CONFIG_NET_SOCKETS_LOG_LEVEL);

#include <zephyr/ztest_assert.h>
#include <zephyr/posix/fcntl.h>
#include <zephyr/net/loopback.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/tls_credentials.h>
/* IANA IDs (RFC 4279), which both backends accept */
#define TLS_PSK_WITH_AES_128_CBC_SHA  0x008C
#define TLS_PSK_WITH_AES_256_CBC_SHA  0x008D

#if defined(CONFIG_WOLFSSL)
#ifndef WOLFSSL_USER_SETTINGS
#include <user_settings.h>
#endif
#include <wolfssl/ssl.h>
#include "tcp_internal.h"
WOLFSSL *ztls_get_wolfssl_context(int fd);
/* In wolfssl_alert.c, which keeps <wolfssl/internal.h> out of this file */
void test_wolfssl_send_fatal_alert(WOLFSSL *ssl);
void test_wolfssl_mark_close_notify_sent(WOLFSSL *ssl);
#endif

#if defined(CONFIG_MBEDTLS)
#include <mbedtls/ssl.h>
mbedtls_ssl_context *ztls_get_mbedtls_ssl_context(int fd);
#endif

#include "../../socket_helpers.h"

static const int cipher_list_psk[] = {
	TLS_PSK_WITH_AES_128_CBC_SHA,
	TLS_PSK_WITH_AES_256_CBC_SHA
};

/* Test test_set_ciphersuites() assumes [0] of this list is the
 * cipher that will be negotiated */
static const int cipher_list_psk2[] = {
	TLS_PSK_WITH_AES_128_CBC_SHA,
};

static const int cipher_list_psk3[] = {
	TLS_PSK_WITH_AES_256_CBC_SHA,
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
		zassert_equal(zsock_setsockopt(s_sock, SOL_TLS, TLS_SEC_TAG_LIST,
					 sec_tag_list, sizeof(sec_tag_list)),
			      0, "Failed to set PSK on server socket");
	}

	if (c_sock >= 0) {
		zassert_equal(zsock_setsockopt(c_sock, SOL_TLS, TLS_SEC_TAG_LIST,
					 sec_tag_list, sizeof(sec_tag_list)),
			      0, "Failed to set PSK on client socket");
	}
}

static void test_fcntl(int sock, int cmd, int val)
{
	zassert_equal(zsock_fcntl(sock, cmd, val), 0, "fcntl failed");
}

static void test_bind(int sock, struct sockaddr *addr, socklen_t addrlen)
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

static void test_connect(int sock, struct sockaddr *addr, socklen_t addrlen)
{
	k_yield();

	zassert_equal(zsock_connect(sock, addr, addrlen),
		      0,
		      "connect failed");

	if (IS_ENABLED(CONFIG_NET_TC_THREAD_PREEMPTIVE)) {
		/* Let the connection proceed */
		k_yield();
	}
}

static void test_connect_err(int sock, struct sockaddr *addr, socklen_t addrlen)
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

static void test_sendmsg(int sock, const struct msghdr *msg, int flags)
{
	size_t total_len = 0;

	for (int i = 0; i < msg->msg_iovlen; i++) {
		struct iovec *vec = msg->msg_iov + i;

		total_len += vec->iov_len;
	}

	zassert_equal(zsock_sendmsg(sock, msg, flags),
		      total_len,
		      "sendmsg failed");
}

static void test_accept(int sock, int *new_sock, struct sockaddr *addr,
			socklen_t *addrlen)
{
	zassert_not_null(new_sock, "null newsock");

	*new_sock = zsock_accept(sock, addr, addrlen);
	zassert_true(*new_sock >= 0, "accept failed");
}

static void test_accept_err(int sock, int *new_sock, struct sockaddr *addr,
			    socklen_t *addrlen)
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
	struct sockaddr_in bind_addr4;
	struct sockaddr_in6 bind_addr6;
	int sock1, sock2, rv;
	int optval;
	socklen_t optlen = sizeof(optval);

	prepare_sock_tls_v4(MY_IPV4_ADDR, ANY_PORT, &sock1, &bind_addr4, IPPROTO_TLS_1_2);
	prepare_sock_tls_v6(MY_IPV6_ADDR, ANY_PORT, &sock2, &bind_addr6, IPPROTO_TLS_1_2);

	rv = zsock_getsockopt(sock1, SOL_SOCKET, SO_TYPE, &optval, &optlen);
	zassert_equal(rv, 0, "getsockopt failed (%d)", errno);
	zassert_equal(optval, SOCK_STREAM, "getsockopt got invalid type");
	zassert_equal(optlen, sizeof(optval), "getsockopt got invalid size");

	rv = zsock_getsockopt(sock2, SOL_SOCKET, SO_TYPE, &optval, &optlen);
	zassert_equal(rv, 0, "getsockopt failed (%d)", errno);
	zassert_equal(optval, SOCK_STREAM, "getsockopt got invalid type");
	zassert_equal(optlen, sizeof(optval), "getsockopt got invalid size");

	test_close(sock1);
	test_close(sock2);
}

ZTEST(net_socket_tls, test_so_protocol)
{
	struct sockaddr_in bind_addr4;
	struct sockaddr_in6 bind_addr6;
	int sock1, sock2, rv;
	int optval;
	socklen_t optlen = sizeof(optval);

	prepare_sock_tls_v4(MY_IPV4_ADDR, ANY_PORT, &sock1, &bind_addr4, IPPROTO_TLS_1_2);
	prepare_sock_tls_v6(MY_IPV6_ADDR, ANY_PORT, &sock2, &bind_addr6, IPPROTO_TLS_1_1);

	rv = zsock_getsockopt(sock1, SOL_SOCKET, SO_PROTOCOL, &optval, &optlen);
	zassert_equal(rv, 0, "getsockopt failed (%d)", errno);
	zassert_equal(optval, IPPROTO_TLS_1_2,
		      "getsockopt got invalid protocol");
	zassert_equal(optlen, sizeof(optval), "getsockopt got invalid size");

	rv = zsock_getsockopt(sock2, SOL_SOCKET, SO_PROTOCOL, &optval, &optlen);
	zassert_equal(rv, 0, "getsockopt failed (%d)", errno);
	zassert_equal(optval, IPPROTO_TLS_1_1,
		      "getsockopt got invalid protocol");
	zassert_equal(optlen, sizeof(optval), "getsockopt got invalid size");

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
	struct sockaddr *addr;
};

static void client_connect_work_handler(struct k_work *work)
{
	struct k_work_delayable *dwork = k_work_delayable_from_work(work);
	struct connect_data *data =
		CONTAINER_OF(dwork, struct connect_data, work);

	test_connect(data->sock, data->addr, data->addr->sa_family == AF_INET ?
		     sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
}

static void client_connect_work_handler_err(struct k_work *work)
{
	struct k_work_delayable *dwork = k_work_delayable_from_work(work);
	struct connect_data *data =
		CONTAINER_OF(dwork, struct connect_data, work);

	test_connect_err(data->sock, data->addr, data->addr->sa_family == AF_INET ?
			 sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
}

static void dtls_client_connect_send_work_handler(struct k_work *work)
{
	struct k_work_delayable *dwork = k_work_delayable_from_work(work);
	struct connect_data *data =
		CONTAINER_OF(dwork, struct connect_data, work);
	uint8_t tx_buf = 0;

	test_connect(data->sock, data->addr, data->addr->sa_family == AF_INET ?
		     sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
	test_send(data->sock, &tx_buf, sizeof(tx_buf), 0);
}

static void test_prepare_tls_connection(sa_family_t family)
{
	struct sockaddr c_saddr;
	struct sockaddr s_saddr;
	socklen_t exp_addrlen = family == AF_INET6 ?
				sizeof(struct sockaddr_in6) :
				sizeof(struct sockaddr_in);
	struct sockaddr addr;
	socklen_t addrlen = sizeof(addr);
	struct connect_data test_data;

	if (family == AF_INET6) {
		prepare_sock_tls_v6(MY_IPV6_ADDR, ANY_PORT, &c_sock,
				    (struct sockaddr_in6 *)&c_saddr,
				    IPPROTO_TLS_1_2);
		prepare_sock_tls_v6(MY_IPV6_ADDR, ANY_PORT, &s_sock,
				    (struct sockaddr_in6 *)&s_saddr,
				    IPPROTO_TLS_1_2);
	} else {
		prepare_sock_tls_v4(MY_IPV4_ADDR, ANY_PORT, &c_sock,
				    (struct sockaddr_in *)&c_saddr,
				    IPPROTO_TLS_1_2);
		prepare_sock_tls_v4(MY_IPV4_ADDR, ANY_PORT, &s_sock,
				    (struct sockaddr_in *)&s_saddr,
				    IPPROTO_TLS_1_2);
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

static void test_prepare_dtls_connection(sa_family_t family)
{
	struct sockaddr c_saddr;
	struct sockaddr s_saddr;
	socklen_t exp_addrlen = family == AF_INET6 ?
				sizeof(struct sockaddr_in6) :
				sizeof(struct sockaddr_in);
	struct connect_data test_data;
	int role = TLS_DTLS_ROLE_SERVER;
	struct zsock_pollfd fds[1];
	uint8_t rx_buf;
	int ret;


	if (family == AF_INET6) {
		prepare_sock_dtls_v6(MY_IPV6_ADDR, ANY_PORT, &c_sock,
				     (struct sockaddr_in6 *)&c_saddr,
				     IPPROTO_DTLS_1_2);
		prepare_sock_dtls_v6(MY_IPV6_ADDR, ANY_PORT, &s_sock,
				     (struct sockaddr_in6 *)&s_saddr,
				     IPPROTO_DTLS_1_2);
	} else {
		prepare_sock_dtls_v4(MY_IPV4_ADDR, ANY_PORT, &c_sock,
				     (struct sockaddr_in *)&c_saddr,
				     IPPROTO_DTLS_1_2);
		prepare_sock_dtls_v4(MY_IPV4_ADDR, ANY_PORT, &s_sock,
				     (struct sockaddr_in *)&s_saddr,
				     IPPROTO_DTLS_1_2);
	}

	test_config_psk(s_sock, c_sock);

	zassert_equal(zsock_setsockopt(s_sock, SOL_TLS, TLS_DTLS_ROLE,
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
	zassert_equal(ret, sizeof(rx_buf), "recv() failed");

	test_work_wait(&test_data.work);
}

/* Function pointer type for function to be called after socket creation but
 * before any bind/listen/connect operations */
typedef void (*tls_pre_cb)(void);
/* Function pointer type for function to be used to perform client work
 * instead of client_connect_work_handler() */
typedef void (*client_work_func)(struct k_work *work);

static void test_prepare_tls_connection_ex(sa_family_t family, bool accept_err,
					   tls_pre_cb cb, client_work_func cw)
{
	struct sockaddr c_saddr;
	struct sockaddr s_saddr;
	socklen_t exp_addrlen = family == AF_INET6 ?
				sizeof(struct sockaddr_in6) :
				sizeof(struct sockaddr_in);
	struct sockaddr addr;
	socklen_t addrlen = sizeof(addr);
	struct connect_data test_data;

	if (family == AF_INET6) {
		prepare_sock_tls_v6(MY_IPV6_ADDR, ANY_PORT, &c_sock,
				    (struct sockaddr_in6 *)&c_saddr,
				    IPPROTO_TLS_1_2);
		prepare_sock_tls_v6(MY_IPV6_ADDR, ANY_PORT, &s_sock,
				    (struct sockaddr_in6 *)&s_saddr,
				    IPPROTO_TLS_1_2);
	} else {
		prepare_sock_tls_v4(MY_IPV4_ADDR, ANY_PORT, &c_sock,
				    (struct sockaddr_in *)&c_saddr,
				    IPPROTO_TLS_1_2);
		prepare_sock_tls_v4(MY_IPV4_ADDR, ANY_PORT, &s_sock,
				    (struct sockaddr_in *)&s_saddr,
				    IPPROTO_TLS_1_2);
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

	test_prepare_tls_connection(AF_INET);

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
	ret = zsock_setsockopt(new_sock, SOL_SOCKET, SO_RCVTIMEO, &timeo_optval,
			       sizeof(timeo_optval));
	zassert_equal(ret, 0, "setsockopt failed (%d)", errno);

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

	test_prepare_tls_connection(AF_INET6);

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
	ret = zsock_setsockopt(new_sock, SOL_SOCKET, SO_RCVTIMEO, &timeo_optval,
			       sizeof(timeo_optval));
	zassert_equal(ret, 0, "setsockopt failed (%d)", errno);

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

void test_msg_trunc(sa_family_t family)
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
	test_msg_trunc(AF_INET);
}

ZTEST(net_socket_tls, test_v6_msg_trunc)
{
	test_msg_trunc(AF_INET6);
}

struct test_sendmsg_data {
	struct k_work_delayable tx_work;
	int sock;
	const struct msghdr *msg;
};

static void test_sendmsg_tx_work_handler(struct k_work *work)
{
	struct k_work_delayable *dwork = k_work_delayable_from_work(work);
	struct test_sendmsg_data *test_data =
		CONTAINER_OF(dwork, struct test_sendmsg_data, tx_work);

	test_sendmsg(test_data->sock, test_data->msg, 0);
}

static void test_dtls_sendmsg_no_buf(sa_family_t family)
{
	int rv;
	uint8_t rx_buf[sizeof(TEST_STR_SMALL) - 1];
	struct iovec iov[3] = {
		{},
		{
			.iov_base = TEST_STR_SMALL,
			.iov_len = sizeof(TEST_STR_SMALL) - 1,
		},
		{},
	};
	struct msghdr msg = {};
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
	zassert_equal(rv, sizeof(TEST_STR_SMALL) - 1, "recv failed");
	zassert_mem_equal(rx_buf, TEST_STR_SMALL, sizeof(TEST_STR_SMALL) - 1, "invalid rx data");

	test_work_wait(&test_data.tx_work);

	/* sendmsg() with single non-empty fragment */

	msg.msg_iov = iov;
	msg.msg_iovlen = ARRAY_SIZE(iov);

	test_work_reschedule(&test_data.tx_work, K_MSEC(10));

	memset(rx_buf, 0, sizeof(rx_buf));
	rv = zsock_recv(s_sock, rx_buf, sizeof(rx_buf), 0);
	zassert_equal(rv, sizeof(TEST_STR_SMALL) - 1, "recv failed");
	zassert_mem_equal(rx_buf, TEST_STR_SMALL, sizeof(TEST_STR_SMALL) - 1, "invalid rx data");

	test_work_wait(&test_data.tx_work);

	/* sendmsg() with multiple non-empty fragments */

	iov[0].iov_base = TEST_STR_SMALL;
	iov[0].iov_len = sizeof(TEST_STR_SMALL) - 1;

	rv = zsock_sendmsg(c_sock, &msg, 0);
	zassert_equal(rv, -1, "sendmsg succeeded");
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

	test_dtls_sendmsg_no_buf(AF_INET);
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

	test_dtls_sendmsg_no_buf(AF_INET6);
}

static void test_dtls_sendmsg(sa_family_t family)
{
	int rv;
	uint8_t buf[128 + 1] = { 0 };
	uint8_t dummy_byte = 0;
	static const char expected_str[] = "testtest";
	struct iovec iov[3] = {
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
	struct msghdr msg = {};
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
	zassert_equal(rv, sizeof(expected_str) - 1, "recv failed");
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
	zassert_equal(rv, sizeof(expected_str) - 1, "recv failed");
	zassert_mem_equal(buf, expected_str, sizeof(expected_str) - 1, "invalid rx data");

	test_work_wait(&test_data.tx_work);

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
	zassert_equal(rv, sizeof(buf), "recv failed");
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
	zassert_equal(rv, -1, "sendmsg succeeded");
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

	test_dtls_sendmsg(AF_INET);
}

ZTEST(net_socket_tls, test_v6_dtls_sendmsg)
{
#if !defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
	ztest_test_skip();
#elif CONFIG_NET_SOCKETS_DTLS_SENDMSG_BUF_SIZE <= 0
	ztest_test_skip();
#endif

	test_dtls_sendmsg(AF_INET6);
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
	struct sockaddr_in6 s_saddr;
	struct sockaddr addr;
	socklen_t addrlen = sizeof(addr);
	struct close_data close_work_data;

	prepare_sock_tls_v6(MY_IPV6_ADDR, ANY_PORT, &s_sock, &s_saddr, IPPROTO_TLS_1_2);

	test_config_psk(s_sock, -1);

	test_bind(s_sock, (struct sockaddr *)&s_saddr, sizeof(s_saddr));
	test_listen(s_sock);

	/* Schedule close() from workqueue */
	k_work_init_delayable(&close_work_data.work, close_work);
	close_work_data.fd = &s_sock;
	test_work_reschedule(&close_work_data.work, K_MSEC(10));

	/* Start blocking accept(), which should be unblocked by close() from
	 * another thread and return an error.
	 */
	new_sock = zsock_accept(s_sock, &addr, &addrlen);
	zassert_equal(new_sock, -1, "accept did not return error");
	zassert_equal(errno, EINTR, "Unexpected errno value: %d", errno);

	test_work_wait(&close_work_data.work);
	k_sleep(TCP_TEARDOWN_TIMEOUT);
}

ZTEST(net_socket_tls, test_close_while_recv)
{
	int ret;
	struct close_data close_work_data;
	uint8_t rx_buf;

	test_prepare_tls_connection(AF_INET6);

	/* Schedule close() from workqueue */
	k_work_init_delayable(&close_work_data.work, close_work);
	close_work_data.fd = &new_sock;
	test_work_reschedule(&close_work_data.work, K_MSEC(10));

	ret = zsock_recv(new_sock, &rx_buf, sizeof(rx_buf), 0);
	zassert_equal(ret, -1, "recv did not return error");
	zassert_equal(errno, EINTR, "Unexpected errno value: %d", errno);

	test_work_wait(&close_work_data.work);

	test_sockets_close();

	k_sleep(TCP_TEARDOWN_TIMEOUT);
}

ZTEST(net_socket_tls, test_connect_timeout)
{
	struct sockaddr_in6 c_saddr;
	struct sockaddr_in6 s_saddr;
	int ret;

	prepare_sock_tls_v6(MY_IPV6_ADDR, ANY_PORT, &c_sock, &c_saddr,
			    IPPROTO_TLS_1_2);
	test_config_psk(-1, c_sock);

	s_saddr.sin6_family = AF_INET6;
	s_saddr.sin6_port = htons(SERVER_PORT);
	ret = zsock_inet_pton(AF_INET6, MY_IPV6_ADDR, &s_saddr.sin6_addr);
	zassert_equal(ret, 1, "inet_pton failed");

	loopback_set_packet_drop_ratio(1.0f);

	zassert_equal(zsock_connect(c_sock, (struct sockaddr *)&s_saddr,
				    sizeof(s_saddr)),
		      -1, "connect succeed");
	zassert_equal(errno, ETIMEDOUT,
		      "connect should be timed out, got %d", errno);

	test_sockets_close();

	loopback_set_packet_drop_ratio(0.0f);
	k_sleep(TCP_TEARDOWN_TIMEOUT);
}

ZTEST(net_socket_tls, test_connect_closed_port)
{
	struct sockaddr_in6 c_saddr;
	struct sockaddr_in6 s_saddr;
	int ret;

	prepare_sock_tls_v6(MY_IPV6_ADDR, ANY_PORT, &c_sock, &c_saddr,
			    IPPROTO_TLS_1_2);
	test_config_psk(-1, c_sock);

	s_saddr.sin6_family = AF_INET6;
	s_saddr.sin6_port = htons(SERVER_PORT);
	ret = zsock_inet_pton(AF_INET6, MY_IPV6_ADDR, &s_saddr.sin6_addr);
	zassert_equal(ret, 1, "inet_pton failed");

	zassert_equal(zsock_connect(c_sock, (struct sockaddr *)&s_saddr,
				    sizeof(s_saddr)),
		      -1, "connect succeed");
	zassert_equal(errno, ECONNREFUSED,
		      "connect should fail, got %d", errno);

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
					 sa_family_t family, int *s_sock,
					 struct sockaddr *s_saddr, bool reply)
{
	socklen_t exp_addrlen = family == AF_INET6 ?
				sizeof(struct sockaddr_in6) :
				sizeof(struct sockaddr_in);

	if (family == AF_INET6) {
		prepare_sock_tcp_v6(MY_IPV6_ADDR, SERVER_PORT, s_sock,
				    (struct sockaddr_in6 *)s_saddr);
	} else {
		prepare_sock_tcp_v4(MY_IPV4_ADDR, SERVER_PORT, s_sock,
				    (struct sockaddr_in *)s_saddr);
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
	struct sockaddr_in6 c_saddr;
	struct sockaddr_in6 s_saddr;

	prepare_sock_tls_v6(MY_IPV6_ADDR, ANY_PORT, &c_sock, &c_saddr,
			    IPPROTO_TLS_1_2);
	test_config_psk(-1, c_sock);
	test_prepare_fake_tcp_server(&server_data, AF_INET6, &s_sock,
				     (struct sockaddr *)&s_saddr, true);

	zassert_equal(zsock_connect(c_sock, (struct sockaddr *)&s_saddr,
				    sizeof(s_saddr)),
		      -1, "connect succeed");
	zassert_equal(errno, ECONNABORTED,
		      "connect should fail, got %d", errno);

	test_close(c_sock);
	c_sock = -1;

	test_work_wait(&server_data.work);
	test_sockets_close();

	k_sleep(TCP_TEARDOWN_TIMEOUT);
}

ZTEST(net_socket_tls, test_connect_no_handshake_data)
{
	struct fake_tcp_server_data server_data;
	struct sockaddr_in6 c_saddr;
	struct sockaddr s_saddr;

	prepare_sock_tls_v6(MY_IPV6_ADDR, ANY_PORT, &c_sock, &c_saddr,
			    IPPROTO_TLS_1_2);
	test_config_psk(-1, c_sock);
	test_prepare_fake_tcp_server(&server_data, AF_INET6, &s_sock,
				     (struct sockaddr *)&s_saddr, false);

	zassert_equal(zsock_connect(c_sock, (struct sockaddr *)&s_saddr,
				    sizeof(s_saddr)),
		      -1, "connect succeed");
	zassert_equal(errno, ECONNABORTED,
		      "connect should fail, got %d", errno);

	test_work_wait(&server_data.work);
	test_sockets_close();

	k_sleep(TCP_TEARDOWN_TIMEOUT);
}

ZTEST(net_socket_tls, test_accept_non_block)
{
	uint32_t timestamp;
	struct sockaddr_in6 s_saddr;

	prepare_sock_tls_v6(MY_IPV6_ADDR, SERVER_PORT, &s_sock, &s_saddr,
			    IPPROTO_TLS_1_2);

	test_config_psk(s_sock, -1);
	test_fcntl(s_sock, F_SETFL, O_NONBLOCK);
	test_bind(s_sock, (struct sockaddr *)&s_saddr, sizeof(s_saddr));
	test_listen(s_sock);

	timestamp = k_uptime_get_32();
	new_sock = zsock_accept(s_sock, NULL, NULL);
	zassert_true(k_uptime_get_32() - timestamp <= 100, "");
	zassert_equal(new_sock, -1, "accept did not return error");
	zassert_equal(errno, EAGAIN, "Unexpected errno value: %d", errno);

	test_sockets_close();
	k_sleep(TCP_TEARDOWN_TIMEOUT);
}

ZTEST(net_socket_tls, test_accept_invalid_handshake_data)
{
	struct sockaddr_in6 s_saddr;
	struct sockaddr_in6 c_saddr;

	prepare_sock_tls_v6(MY_IPV6_ADDR, ANY_PORT, &s_sock, &s_saddr,
			    IPPROTO_TLS_1_2);
	prepare_sock_tcp_v6(MY_IPV6_ADDR, ANY_PORT, &c_sock, &c_saddr);

	test_config_psk(s_sock, -1);
	test_bind(s_sock, (struct sockaddr *)&s_saddr, sizeof(s_saddr));
	test_listen(s_sock);

	/* Connect at TCP level and send some unexpected data. */
	test_connect(c_sock, (struct sockaddr *)&s_saddr, sizeof(s_saddr));
	test_send(c_sock, TEST_STR_SMALL, sizeof(TEST_STR_SMALL), 0);

	new_sock = zsock_accept(s_sock, NULL, NULL);
	zassert_equal(new_sock, -1, "accept did not return error");
	zassert_equal(errno, ECONNABORTED, "Unexpected errno value: %d", errno);

	test_sockets_close();
	k_sleep(TCP_TEARDOWN_TIMEOUT);
}

ZTEST(net_socket_tls, test_recv_non_block)
{
	int ret;
	uint8_t rx_buf[sizeof(TEST_STR_SMALL) - 1] = { 0 };

	test_prepare_tls_connection(AF_INET6);

	/* Verify ZSOCK_MSG_DONTWAIT flag first */
	ret = zsock_recv(new_sock, rx_buf, sizeof(rx_buf), ZSOCK_MSG_DONTWAIT);
	zassert_equal(ret, -1, "recv()) should've failed");
	zassert_equal(errno, EAGAIN, "Unexpected errno value: %d", errno);

	/* Verify fcntl and O_NONBLOCK */
	test_fcntl(new_sock, F_SETFL, O_NONBLOCK);
	ret = zsock_recv(new_sock, rx_buf, sizeof(rx_buf), 0);
	zassert_equal(ret, -1, "recv() should've failed");
	zassert_equal(errno, EAGAIN, "Unexpected errno value: %d", errno);

	ret = zsock_send(c_sock, TEST_STR_SMALL, strlen(TEST_STR_SMALL), 0);
	zassert_equal(ret, strlen(TEST_STR_SMALL), "send() failed");

	/* Let the data got through. */
	k_sleep(K_MSEC(10));

	/* Should get data now */
	ret = zsock_recv(new_sock, rx_buf, sizeof(rx_buf), 0);
	zassert_equal(ret, strlen(TEST_STR_SMALL), "recv() failed");
	zassert_mem_equal(rx_buf, TEST_STR_SMALL, ret, "Invalid data received");

	/* And EAGAIN on consecutive read */
	ret = zsock_recv(new_sock, rx_buf, sizeof(rx_buf), 0);
	zassert_equal(ret, -1, "recv() should've failed");
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

	test_prepare_tls_connection(AF_INET6);

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

ZTEST(net_socket_tls, test_recv_eof_on_close)
{
	test_prepare_tls_connection(AF_INET6);

	test_close(c_sock);
	c_sock = -1;

	/* Verify recv() reports EOF */
	test_eof(new_sock);

	test_sockets_close();

	k_sleep(TCP_TEARDOWN_TIMEOUT);
}

/* Measured record overhead of the default TLS 1.2 AES-GCM suite per backend; re-measure
 * with an oversized buffer after a backend or suite change.
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

	test_prepare_tls_connection(AF_INET6);

	/* Simulate window full scenario with SO_RCVBUF option. */
	ret = zsock_setsockopt(new_sock, SOL_SOCKET, SO_RCVBUF, &buf_optval,
			       sizeof(buf_optval));
	zassert_equal(ret, 0, "setsockopt failed (%d)", errno);

	/* Fill out the window */
	ret = zsock_send(c_sock, TEST_STR_SMALL, strlen(TEST_STR_SMALL), 0);
	zassert_equal(ret, strlen(TEST_STR_SMALL), "send() failed");

	/* Wait for ACK (empty window, min. 100 ms due to silly window
	 * protection).
	 */
	k_sleep(K_MSEC(150));

	/* Verify ZSOCK_MSG_DONTWAIT flag first */
	ret = zsock_send(c_sock, TEST_STR_SMALL, strlen(TEST_STR_SMALL),
			 ZSOCK_MSG_DONTWAIT);
	zassert_equal(ret, -1, "send() should've failed");
	zassert_equal(errno, EAGAIN, "Unexpected errno value: %d", errno);

	/* Verify fcntl and O_NONBLOCK */
	test_fcntl(c_sock, F_SETFL, O_NONBLOCK);
	ret = zsock_send(c_sock, TEST_STR_SMALL, strlen(TEST_STR_SMALL), 0);
	zassert_equal(ret, -1, "send() should've failed");
	zassert_equal(errno, EAGAIN, "Unexpected errno value: %d", errno);

	ret = zsock_recv(new_sock, rx_buf, sizeof(rx_buf), 0);
	zassert_equal(ret, strlen(TEST_STR_SMALL), "recv() failed");
	zassert_mem_equal(rx_buf, TEST_STR_SMALL, ret, "Invalid data received");

	/* Wait for the window to update. */
	k_sleep(K_MSEC(10));

	/* Should succeed now. */
	ret = zsock_send(c_sock, TEST_STR_SMALL, strlen(TEST_STR_SMALL), 0);
	zassert_equal(ret, strlen(TEST_STR_SMALL), "send() failed");

	/* Flush the data */
	ret = zsock_recv(new_sock, rx_buf, sizeof(rx_buf), 0);
	zassert_equal(ret, strlen(TEST_STR_SMALL), "recv() failed");
	zassert_mem_equal(rx_buf, TEST_STR_SMALL, ret, "Invalid data received");

	/* And make sure there's no more data left. */
	ret = zsock_recv(new_sock, rx_buf, sizeof(rx_buf), ZSOCK_MSG_DONTWAIT);
	zassert_equal(ret, -1, "recv() should've failed");
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
		zassert_true(ret > 0, "recv() error");
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

	test_prepare_tls_connection(AF_INET6);

	/* Simulate window full scenario with SO_RCVBUF option. */
	ret = zsock_setsockopt(new_sock, SOL_SOCKET, SO_RCVBUF, &buf_optval,
			       sizeof(buf_optval));
	zassert_equal(ret, 0, "setsockopt failed (%d)", errno);

	/* Fill out the window */
	ret = zsock_send(c_sock, TEST_STR_SMALL, strlen(TEST_STR_SMALL), 0);
	zassert_equal(ret, strlen(TEST_STR_SMALL), "send() failed");

	/* Wait for ACK (empty window, min. 100 ms due to silly window
	 * protection).
	 */
	k_sleep(K_MSEC(150));

	test_data.sock = new_sock;
	k_work_init_delayable(&test_data.work, recv_work_handler);
	test_work_reschedule(&test_data.work, K_MSEC(10));

	/* Should block and succeed. */
	ret = zsock_send(c_sock, TEST_STR_SMALL, strlen(TEST_STR_SMALL), 0);
	zassert_equal(ret, strlen(TEST_STR_SMALL), "send() failed");

	/* Flush the data */
	ret = zsock_recv(new_sock, rx_buf, sizeof(rx_buf), 0);
	zassert_equal(ret, strlen(TEST_STR_SMALL), "recv() failed");
	zassert_mem_equal(rx_buf, TEST_STR_SMALL, ret, "Invalid data received");

	/* And make sure there's no more data left. */
	ret = zsock_recv(new_sock, rx_buf, sizeof(rx_buf), ZSOCK_MSG_DONTWAIT);
	zassert_equal(ret, -1, "recv() should've failed");
	zassert_equal(errno, EAGAIN, "Unexpected errno value: %d", errno);

	test_sockets_close();

	k_sleep(TCP_TEARDOWN_TIMEOUT);
}

ZTEST(net_socket_tls, test_send_on_close)
{
	uint8_t rx_buf[sizeof(TEST_STR_SMALL) - 1] = { 0 };
	int ret;

	test_prepare_tls_connection(AF_INET6);

	test_close(new_sock);
	new_sock = -1;

	/* Small delay for packets to propagate. */
	k_msleep(20);

	/* Verify send() reports an error after connection is closed. */
	ret = zsock_send(c_sock, TEST_STR_SMALL, strlen(TEST_STR_SMALL), 0);
	zassert_equal(ret, -1, "send() should've failed");
	zassert_equal(errno, ECONNABORTED, "Unexpected errno value: %d", errno);

	/* recv() on closed connection marked error on a socket. */
	ret = zsock_recv(c_sock, rx_buf, sizeof(rx_buf), 0);
	zassert_equal(ret, -1, "recv() should've failed");
	zassert_equal(errno, ECONNABORTED, "Unexpected errno value: %d", errno);

	test_sockets_close();

	/* And in reverse order */

	test_prepare_tls_connection(AF_INET6);

	test_close(new_sock);
	new_sock = -1;

	/* Small delay for packets to propagate. */
	k_msleep(20);

	/* Graceful connection close should be reported first. */
	ret = zsock_recv(c_sock, rx_buf, sizeof(rx_buf), 0);
	zassert_equal(ret, 0, "recv() should've reported connection close");

	/* And consecutive send() should fail. */
	ret = zsock_send(c_sock, TEST_STR_SMALL, strlen(TEST_STR_SMALL), 0);
	zassert_equal(ret, -1, "send() should've failed");
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

	test_prepare_tls_connection(AF_INET6);

	ret = zsock_setsockopt(c_sock, SOL_SOCKET, SO_RCVTIMEO, &optval,
			       sizeof(optval));
	zassert_equal(ret, 0, "setsockopt failed (%d)", errno);

	start_time = k_uptime_get_32();
	ret = zsock_recv(c_sock, rx_buf, sizeof(rx_buf), 0);
	time_diff = k_uptime_get_32() - start_time;

	zassert_equal(ret, -1, "recv() should've failed");
	zassert_equal(errno, EAGAIN, "Unexpected errno value: %d", errno);
	zassert_true(time_diff >= 500, "Expected timeout after 500ms but "
		     "was %dms", time_diff);

	test_data.sock = c_sock;
	k_work_init_delayable(&test_data.tx_work, send_work_handler);
	test_work_reschedule(&test_data.tx_work, K_MSEC(10));

	/* recv() shall return as soon as it gets data, regardless of timeout. */
	ret = zsock_recv(new_sock, rx_buf, sizeof(rx_buf), 0);
	zassert_equal(ret, sizeof(TEST_STR_SMALL) - 1, "recv() failed");
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

	test_prepare_tls_connection(AF_INET6);

	ret = zsock_setsockopt(c_sock, SOL_SOCKET, SO_SNDTIMEO, &timeo_optval,
			       sizeof(timeo_optval));
	zassert_equal(ret, 0, "setsockopt failed (%d)", errno);

	/* Simulate window full scenario with SO_RCVBUF option. */
	ret = zsock_setsockopt(new_sock, SOL_SOCKET, SO_RCVBUF, &buf_optval,
			       sizeof(buf_optval));
	zassert_equal(ret, 0, "setsockopt failed (%d)", errno);

	ret = zsock_send(c_sock, TEST_STR_SMALL, sizeof(TEST_STR_SMALL) - 1, 0);
	zassert_equal(ret, sizeof(TEST_STR_SMALL) - 1, "send() failed");

	/* Wait for ACK (empty window). */
	k_msleep(150);

	/* Client should not be able to send now and time out after SO_SNDTIMEO */
	start_time = k_uptime_get_32();
	ret = zsock_send(c_sock, TEST_STR_SMALL, sizeof(TEST_STR_SMALL) - 1, 0);
	time_diff = k_uptime_get_32() - start_time;

	zassert_equal(ret, -1, "send() should've failed");
	zassert_equal(errno, EAGAIN, "Unexpected errno value: %d", errno);
	zassert_true(time_diff >= 500, "Expected timeout after 500ms but "
			"was %dms", time_diff);

	test_data.sock = new_sock;
	k_work_init_delayable(&test_data.work, recv_work_handler);
	test_work_reschedule(&test_data.work, K_MSEC(10));

	/* Should block and succeed. */
	ret = zsock_send(c_sock, TEST_STR_SMALL, strlen(TEST_STR_SMALL), 0);
	zassert_equal(ret, strlen(TEST_STR_SMALL), "send() failed");

	test_sockets_close();

	k_sleep(TCP_TEARDOWN_TIMEOUT);
}

ZTEST(net_socket_tls, test_shutdown_rd_synchronous)
{
	test_prepare_tls_connection(AF_INET6);

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

	test_prepare_tls_connection(AF_INET6);

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
static void test_dtls_shutdown_synchronous_body(sa_family_t family, int how)
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
	test_dtls_shutdown_synchronous_body(AF_INET6, ZSOCK_SHUT_RD);
#else
	ztest_test_skip();
#endif
}

ZTEST(net_socket_tls, test_dtls_shutdown_rd_synchronous_v4)
{
#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS) && defined(CONFIG_WOLFSSL)
	test_dtls_shutdown_synchronous_body(AF_INET, ZSOCK_SHUT_RD);
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

	test_prepare_dtls_connection(AF_INET6);

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

	test_prepare_tls_connection(AF_INET6);

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
	zassert_equal(ret, sizeof(TEST_STR_SMALL) - 1, "recv() failed");
	zassert_mem_equal(rx_buf, TEST_STR_SMALL, ret, "Invalid data received");

	/* Check if the server sock got its data. */
	ret = zsock_recv(new_sock, rx_buf, sizeof(rx_buf), 0);
	zassert_equal(ret, sizeof(TEST_STR_SMALL) - 1, "recv() failed");
	zassert_mem_equal(rx_buf, TEST_STR_SMALL, ret, "Invalid data received");

	test_sockets_close();

	k_sleep(TCP_TEARDOWN_TIMEOUT);
}

void tls_set_cs_cb(void)
{
	int ret = zsock_setsockopt(s_sock, SOL_TLS, TLS_CIPHERSUITE_LIST,
				   (void *)cipher_list_psk, sizeof(cipher_list_psk));
	zassert_equal(ret, 0, "Unable to set ciphersuites on server");
	ret = zsock_setsockopt(c_sock, SOL_TLS, TLS_CIPHERSUITE_LIST,
			       (void *)cipher_list_psk2, sizeof(cipher_list_psk2));
	zassert_equal(ret, 0, "Unable to set ciphersuites on client");
}

void tls_set_cs_mismatch_cb(void)
{
	/* Set mismatched ciphersuites, should not connect */
	int ret = zsock_setsockopt(c_sock, SOL_TLS, TLS_CIPHERSUITE_LIST,
				   (void *)cipher_list_psk2, sizeof(cipher_list_psk2));
	zassert_equal(ret, 0, "Unable to set ciphersuites on client");
	ret = zsock_setsockopt(s_sock, SOL_TLS, TLS_CIPHERSUITE_LIST,
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

	test_prepare_tls_connection_ex(AF_INET, false, tls_set_cs_cb, NULL);

	/* Verify the ciphersuite list is what we set for server */
	ret = zsock_getsockopt(s_sock, SOL_TLS, TLS_CIPHERSUITE_LIST,
			       (void *)ciphersuites, (socklen_t *)&cs_len);
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
	ret = zsock_getsockopt(c_sock, SOL_TLS, TLS_CIPHERSUITE_LIST,
			       (void *)ciphersuites, (socklen_t *)&cs_len);
	zassert_equal(ret, 0, "Unable to get ciphersuites for client");
	zassert_equal(cs_len, sizeof(cipher_list_psk2), "Incorrect get ciphersuite len");

	for (i = 0; i < cs_len / sizeof(int); i++) {
		zassert_equal(ciphersuites[i], cipher_list_psk2[i],
			      "Retrieved ciphersuite list element does not match set value");
	}

	/* Check that the actual negotiated cipher is correct for server */
	ret = zsock_getsockopt(new_sock, SOL_TLS, TLS_CIPHERSUITE_USED,
			       (void *)&curr_cipher, (socklen_t *)&cc_len);
	zassert_equal(ret, 0, "Unable to get current ciphersuite for server");
	zassert_equal(curr_cipher, cipher_list_psk2[0]);

	/* Same for the client */
	curr_cipher = 0;
	ret = zsock_getsockopt(c_sock, SOL_TLS, TLS_CIPHERSUITE_USED,
			       (void *)&curr_cipher, (socklen_t *)&cc_len);
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
	test_prepare_tls_connection_ex(AF_INET, true,
		tls_set_cs_mismatch_cb, client_connect_work_handler_err);

	test_sockets_close();

	k_sleep(TCP_TEARDOWN_TIMEOUT);
}

void tls_set_hostname_cb(void)
{
	int ret = zsock_setsockopt(c_sock, SOL_TLS, TLS_HOSTNAME,
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

	test_prepare_tls_connection_ex(AF_INET, false, tls_set_hostname_cb, NULL);

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

void tls_set_session_cache_cb(void)
{
	int t = TLS_SESSION_CACHE_ENABLED;
	int l = sizeof(int);

	int ret = zsock_setsockopt(s_sock, SOL_TLS, TLS_SESSION_CACHE,
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

	test_prepare_tls_connection_ex(AF_INET, false, tls_set_session_cache_cb, NULL);

	/* Check that the session cache is enabled */
	ret = zsock_getsockopt(s_sock, SOL_TLS, TLS_SESSION_CACHE,
			       (void *)&enabled, (socklen_t *)&len);
	zassert_equal(ret, 0, "Unable to get session cache enabled status");
	zassert_equal(enabled, TLS_SESSION_CACHE_ENABLED,
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

static void tls_set_session_cache_client_cb(void)
{
	int t = TLS_SESSION_CACHE_ENABLED;
	int l = sizeof(int);
	int ret;

	ret = zsock_setsockopt(s_sock, SOL_TLS, TLS_SESSION_CACHE,
			       (void *)&t, l);
	zassert_equal(ret, 0, "Unable to set session cache on server");
	ret = zsock_setsockopt(c_sock, SOL_TLS, TLS_SESSION_CACHE,
			       (void *)&t, l);
	zassert_equal(ret, 0, "Unable to set session cache on client");
}

/* A fixed server port gives both connections the same peer address, the cache key */
static void prepare_tls_session_resume_connection(uint16_t server_port)
{
	struct sockaddr_in c_saddr;
	struct sockaddr_in s_saddr;
	struct sockaddr addr;
	socklen_t addrlen = sizeof(addr);
	struct connect_data test_data;
	int reuse = 1;
	int ret;

	prepare_sock_tls_v4(MY_IPV4_ADDR, ANY_PORT, &c_sock, &c_saddr,
			    IPPROTO_TLS_1_2);
	prepare_sock_tls_v4(MY_IPV4_ADDR, server_port, &s_sock, &s_saddr,
			    IPPROTO_TLS_1_2);

	tls_set_session_cache_client_cb();

	test_config_psk(s_sock, c_sock);

	/* Rebinding the fixed port must not fail on a TIME_WAIT entry */
	ret = zsock_setsockopt(s_sock, SOL_SOCKET, SO_REUSEADDR,
			       &reuse, sizeof(reuse));
	zassert_equal(ret, 0, "SO_REUSEADDR on server socket failed");

	test_bind(s_sock, (struct sockaddr *)&s_saddr, sizeof(s_saddr));
	test_listen(s_sock);

	test_data.sock = c_sock;
	test_data.addr = (struct sockaddr *)&s_saddr;
	k_work_init_delayable(&test_data.work, client_connect_work_handler);
	test_work_reschedule(&test_data.work, K_NO_WAIT);

	test_accept(s_sock, &new_sock, &addr, &addrlen);
	test_work_wait(&test_data.work);
}

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

	/* Purge any sessions left by earlier tests so we can observe the
	 * transition from "no cached session" to "cached session".
	 */
	{
		int dummy = zsock_socket(AF_INET, SOCK_STREAM, IPPROTO_TLS_1_2);

		zassert_true(dummy >= 0, "purge socket open failed");
		ret = zsock_setsockopt(dummy, SOL_TLS, TLS_SESSION_CACHE_PURGE,
				       NULL, 0);
		zassert_equal(ret, 0, "purge setsockopt failed");
		zsock_close(dummy);
	}

	/* First connection - should perform full handshake, then store. */
	prepare_tls_session_resume_connection(SERVER_PORT);

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

	/* Second connection to the SAME server port - should restore the
	 * stored session and resume.
	 */
	prepare_tls_session_resume_connection(SERVER_PORT);

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

	test_prepare_tls_connection(AF_INET);

	test_data.sock = c_sock;
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
	socklen_t len = sizeof(read_list);
	struct sockaddr_in saddr;

	prepare_sock_tls_v4(MY_IPV4_ADDR, ANY_PORT, &c_sock, &saddr, IPPROTO_TLS_1_2);
	zassert_ok(zsock_setsockopt(c_sock, SOL_TLS, TLS_ALPN_LIST, list,
				    sizeof(list)));
	zassert_ok(zsock_getsockopt(c_sock, SOL_TLS, TLS_ALPN_LIST, read_list,
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
	socklen_t len = sizeof(read_list);
	struct sockaddr_in saddr;

	prepare_sock_tls_v4(MY_IPV4_ADDR, ANY_PORT, &c_sock, &saddr, IPPROTO_TLS_1_2);
	zassert_ok(zsock_setsockopt(c_sock, SOL_TLS, TLS_ALPN_LIST, good,
				    sizeof(good)));
	zassert_equal(zsock_setsockopt(c_sock, SOL_TLS, TLS_ALPN_LIST, comma,
				       sizeof(comma)), -1);
	zassert_equal(errno, EINVAL);
	zassert_equal(zsock_setsockopt(c_sock, SOL_TLS, TLS_ALPN_LIST, empty,
				       sizeof(empty)), -1);
	zassert_equal(errno, EINVAL);

	/* A rejected list leaves the previous one */
	zassert_ok(zsock_getsockopt(c_sock, SOL_TLS, TLS_ALPN_LIST, read_list,
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
	socklen_t len = sizeof(alpn_list);
	int ret = zsock_setsockopt(s_sock, SOL_TLS, TLS_ALPN_LIST,
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

	test_prepare_tls_connection_ex(AF_INET, false, tls_set_alpn_cb, NULL);

	/* Check that the ALPN list is the one we set */
	ret = zsock_getsockopt(s_sock, SOL_TLS, TLS_ALPN_LIST,
			       (void *)alpn_buf, (socklen_t *)&alpn_len);
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

	test_prepare_tls_connection(AF_INET6);

	fds[0].fd = new_sock;
	fds[0].events = ZSOCK_POLLIN;

	ret = zsock_poll(fds, 1, 0);
	zassert_equal(ret, 0, "Unexpected poll() event");

	ret = zsock_send(c_sock, TEST_STR_SMALL, sizeof(TEST_STR_SMALL) - 1, 0);
	zassert_equal(ret, strlen(TEST_STR_SMALL), "send() failed");

	ret = zsock_poll(fds, 1, 100);
	zassert_equal(ret, 1, "poll() should've report event");
	zassert_equal(fds[0].revents, ZSOCK_POLLIN, "No POLLIN event");

	/* Check that data is really available */
	ret = zsock_recv(new_sock, rx_buf, sizeof(rx_buf), ZSOCK_MSG_DONTWAIT);
	zassert_equal(ret, sizeof(TEST_STR_SMALL) - 1, "recv() failed");
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

	test_prepare_dtls_connection(AF_INET6);

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
	zassert_equal(ret, sizeof(TEST_STR_SMALL) - 1, "recv() failed");
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

	test_prepare_tls_connection(AF_INET6);

	fds[0].fd = c_sock;
	fds[0].events = ZSOCK_POLLOUT;

	ret = zsock_poll(fds, 1, 0);
	zassert_equal(ret, 1, "poll() should've report event");
	zassert_equal(fds[0].revents, ZSOCK_POLLOUT, "No POLLOUT event");

	/* Simulate window full scenario with SO_RCVBUF option. */
	ret = zsock_setsockopt(new_sock, SOL_SOCKET, SO_RCVBUF, &buf_optval,
			       sizeof(buf_optval));
	zassert_equal(ret, 0, "setsockopt failed (%d)", errno);

	/* Fill out the window */
	ret = zsock_send(c_sock, TEST_STR_SMALL, strlen(TEST_STR_SMALL), 0);
	zassert_equal(ret, strlen(TEST_STR_SMALL), "send() failed");

	/* Wait for ACK (empty window, min. 100 ms due to silly window
	 * protection).
	 */
	k_sleep(K_MSEC(150));

	/* poll() shouldn't report POLLOUT now */
	ret = zsock_poll(fds, 1, 0);
	zassert_equal(ret, 0, "Unexpected poll() event");

	/* Consume the data, and check if the client sock is writeable again */
	ret = zsock_recv(new_sock, rx_buf, sizeof(rx_buf), ZSOCK_MSG_DONTWAIT);
	zassert_equal(ret, sizeof(TEST_STR_SMALL) - 1, "recv() failed");
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

	test_prepare_dtls_connection(AF_INET6);

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

	test_prepare_tls_connection(AF_INET6);

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
	zassert_equal(ret, 0, "recv() did not report connection close");

	test_sockets_close();

	k_sleep(TCP_TEARDOWN_TIMEOUT);
}

ZTEST(net_socket_tls, test_poll_dtls_pollhup)
{
#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
	struct zsock_pollfd fds[1];
	uint8_t rx_buf;
	int ret;

	test_prepare_dtls_connection(AF_INET6);

	fds[0].fd = s_sock;
	fds[0].events = ZSOCK_POLLIN;

	test_close(c_sock);
	c_sock = -1;

	ret = zsock_poll(fds, 1, 100);
	zassert_equal(ret, 1, "poll() should've report event");
	zassert_equal(fds[0].revents, ZSOCK_POLLHUP, "No POLLHUP event");

	/* Check that connection was indeed closed */
	ret = zsock_recv(s_sock, &rx_buf, sizeof(rx_buf), ZSOCK_MSG_DONTWAIT);
	zassert_equal(ret, -1, "recv() should report EAGAIN");
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
	socklen_t optlen = sizeof(optval);
#if defined(CONFIG_WOLFSSL)
	WOLFSSL *ssl_ctx;
#else
	mbedtls_ssl_context *ssl_ctx;
#endif

	test_prepare_tls_connection(AF_INET6);

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

	ret = zsock_getsockopt(new_sock, SOL_SOCKET, SO_ERROR, &optval, &optlen);
	zassert_equal(ret, 0, "getsockopt failed (%d)", errno);
	zassert_equal(optval, ECONNABORTED, "getsockopt got invalid error %d",
		      optval);

	ret = zsock_recv(new_sock, &rx_buf, sizeof(rx_buf), ZSOCK_MSG_DONTWAIT);
	zassert_equal(ret, -1, "recv() did not report error");
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
	socklen_t optlen = sizeof(optval);
#if defined(CONFIG_WOLFSSL)
	WOLFSSL *ssl_ctx;
#else
	mbedtls_ssl_context *ssl_ctx;
#endif

	test_prepare_dtls_connection(AF_INET6);

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

	ret = zsock_getsockopt(s_sock, SOL_SOCKET, SO_ERROR, &optval, &optlen);
	zassert_equal(ret, 0, "getsockopt failed (%d)", errno);
	zassert_equal(optval, ECONNABORTED, "getsockopt got invalid error %d",
		      optval);

	/* DTLS server socket should recover and be ready to accept new session. */
	ret = zsock_recv(s_sock, &rx_buf, sizeof(rx_buf), ZSOCK_MSG_DONTWAIT);
	zassert_equal(ret, -1, "recv() did not report error");
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
		s_sock = zsock_socket(AF_INET, SOCK_DGRAM, IPPROTO_DTLS_1_2);
	} else {
		s_sock = zsock_socket(AF_INET, SOCK_STREAM, IPPROTO_TLS_1_2);
	}

	zassert_true(s_sock >= 0, "socket open failed");

	for (int i = 0; i < ARRAY_SIZE(bad_tags); i++) {
		sec_tag_t test_tag = bad_tags[i];
		int ret;

		ret = zsock_setsockopt(s_sock, SOL_TLS, TLS_SEC_TAG_LIST,
				       &test_tag, sizeof(test_tag));
		zassert_equal(ret, -1, "zsock_setsockopt should've failed with invalid credential");
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

ZTEST(net_socket_tls, test_tls13_psk_handshake)
{
#if !defined(WOLFSSL_TLS13) || !defined(CONFIG_WOLFSSL)
	ztest_test_skip();
	return;
#else
	struct sockaddr_in6 c_saddr, s_saddr;
	struct sockaddr addr;
	socklen_t addrlen = sizeof(addr);
	struct connect_data test_data;
	uint8_t tx_buf[] = TEST_STR_SMALL;
	uint8_t rx_buf[sizeof(tx_buf)];
	int ret;
	int optval;
	socklen_t optlen = sizeof(optval);

	prepare_sock_tls_v6(MY_IPV6_ADDR, ANY_PORT, &c_sock,
			    &c_saddr, IPPROTO_TLS_1_3);
	prepare_sock_tls_v6(MY_IPV6_ADDR, ANY_PORT, &s_sock,
			    &s_saddr, IPPROTO_TLS_1_3);

	test_config_psk(s_sock, c_sock);

	test_bind(s_sock, (struct sockaddr *)&s_saddr,
		  sizeof(struct sockaddr_in6));
	test_listen(s_sock);

	test_data.sock = c_sock;
	test_data.addr = (struct sockaddr *)&s_saddr;
	k_work_init_delayable(&test_data.work,
			      client_connect_work_handler);
	test_work_reschedule(&test_data.work, K_NO_WAIT);

	test_accept(s_sock, &new_sock, &addr, &addrlen);
	test_work_wait(&test_data.work);

	/* Verify protocol is TLS 1.3 via socket option */
	ret = zsock_getsockopt(new_sock, SOL_SOCKET, SO_PROTOCOL,
			       &optval, &optlen);
	zassert_equal(ret, 0, "getsockopt failed (%d)", errno);
	zassert_equal(optval, IPPROTO_TLS_1_3,
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

ZTEST(net_socket_tls, test_tls13_client_poll_after_ticket)
{
#if !defined(WOLFSSL_TLS13) || !defined(CONFIG_WOLFSSL)
	ztest_test_skip();
#else
	struct sockaddr_in6 c_saddr, s_saddr;
	struct sockaddr addr;
	socklen_t addrlen = sizeof(addr);
	struct connect_data test_data;
	uint8_t tx_buf[] = TEST_STR_SMALL;
	uint8_t rx_buf[sizeof(tx_buf)];
	struct zsock_pollfd fds[1];
	int ret;

	prepare_sock_tls_v6(MY_IPV6_ADDR, ANY_PORT, &c_sock, &c_saddr, IPPROTO_TLS_1_3);
	prepare_sock_tls_v6(MY_IPV6_ADDR, ANY_PORT, &s_sock, &s_saddr, IPPROTO_TLS_1_3);
	test_config_psk(s_sock, c_sock);
	test_bind(s_sock, (struct sockaddr *)&s_saddr, sizeof(struct sockaddr_in6));
	test_listen(s_sock);

	test_data.sock = c_sock;
	test_data.addr = (struct sockaddr *)&s_saddr;
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

	test_sockets_close();
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

	s_sock = zsock_socket(AF_INET, SOCK_STREAM, IPPROTO_TLS_1_2);
	zassert_true(s_sock >= 0, "zsock_socket() failed");

	ret = zsock_setsockopt(s_sock, SOL_TLS, TLS_SEC_TAG_LIST,
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

#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS) && defined(CONFIG_WOLFSSL)
static void dtls_client_connect_send_no_assert_work_handler(struct k_work *work)
{
	struct k_work_delayable *dwork = k_work_delayable_from_work(work);
	struct connect_data *data =
		CONTAINER_OF(dwork, struct connect_data, work);
	uint8_t tx_buf = 0;
	int ret;

	ret = zsock_connect(data->sock, data->addr, data->addr->sa_family == AF_INET ?
			    sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
	if (ret < 0) {
		return;
	}

	zsock_send(data->sock, &tx_buf, sizeof(tx_buf), 0);
}
#endif

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

	test_prepare_tls_connection(AF_INET);

	ret = zsock_setsockopt(c_sock, SOL_TLS, TLS_HOSTNAME,
			       (void *)MY_DEFLT_HOSTNAME,
			       strlen(MY_DEFLT_HOSTNAME));
	zassert_equal(ret, 0, "setting hostname after connect failed (%d)",
		      errno);

	ret = zsock_setsockopt(c_sock, SOL_TLS, TLS_CIPHERSUITE_LIST,
			       (void *)cipher_list_psk2, sizeof(cipher_list_psk2));
	zassert_equal(ret, 0, "setting ciphersuites after connect failed (%d)",
		      errno);

#if defined(CONFIG_WOLFSSL)
	/* The option is validated before it is stored, not when a live session applies it */
	ret = zsock_setsockopt(c_sock, SOL_TLS, TLS_CIPHERSUITE_LIST,
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
static void dtls_verify_address(struct sockaddr *addr, socklen_t addrlen,
				struct sockaddr *expected)
{
	if (expected->sa_family == AF_INET) {
		zassert_equal(addrlen, sizeof(struct sockaddr_in), "Address length mismatch");
		zassert_equal(net_sin(addr)->sin_family, AF_INET, "Address family mismatch");
		zassert_equal(net_sin(addr)->sin_port, net_sin(expected)->sin_port,
			      "Address port mismatch");
		zassert_equal(net_sin(addr)->sin_addr.s_addr, net_sin(expected)->sin_addr.s_addr,
			      "Address mismatch");
	} else {
		zassert_equal(addrlen, sizeof(struct sockaddr_in6), "Address length mismatch");
		zassert_equal(net_sin6(addr)->sin6_family, AF_INET6, "Address family mismatch");
		zassert_equal(net_sin6(addr)->sin6_port, net_sin6(expected)->sin6_port,
			      "Address port mismatch");
		zassert_mem_equal(net_sin6(addr)->sin6_addr.s6_addr,
				  net_sin6(expected)->sin6_addr.s6_addr,
				  NET_IPV6_ADDR_SIZE, "Address mismatch");
	}
}
#endif

/* wolfSSL-only: a spoofed empty datagram does not end a DTLS server session; mbedTLS
 * keeps upstream's EOF behavior.
 */
ZTEST(net_socket_tls, test_dtls_server_empty_datagram)
{
#if !defined(CONFIG_NET_SOCKETS_ENABLE_DTLS) || !defined(CONFIG_WOLFSSL)
	ztest_test_skip();
#else
	struct sockaddr c_saddr;
	struct sockaddr s_saddr;
	struct sockaddr recv_addr;
	socklen_t recv_addrlen = sizeof(recv_addr);
	struct connect_data test_data;
	struct timeval timeo_optval = {
		.tv_sec = 1,
		.tv_usec = 0,
	};
	int role = TLS_DTLS_ROLE_SERVER;
	int yes = 1;
	uint8_t rx_buf;
	uint8_t tx_buf = 0;
	int helper_sock;
	int ret;

	prepare_sock_dtls_v4(MY_IPV4_ADDR, CLIENT_1_PORT, &c_sock,
			     (struct sockaddr_in *)&c_saddr,
			     IPPROTO_DTLS_1_2);
	prepare_sock_dtls_v4(MY_IPV4_ADDR, SERVER_PORT, &s_sock,
			     (struct sockaddr_in *)&s_saddr,
			     IPPROTO_DTLS_1_2);

	test_config_psk(s_sock, c_sock);

	zassert_ok(zsock_setsockopt(s_sock, SOL_TLS, TLS_DTLS_ROLE,
				    &role, sizeof(role)),
		   "setsockopt failed (%d)", errno);
	zassert_ok(zsock_setsockopt(s_sock, SOL_SOCKET, SO_RCVTIMEO,
				    &timeo_optval, sizeof(timeo_optval)),
		   "setsockopt failed (%d)", errno);
	/* Allow the helper socket below to bind to the client's port. */
	zassert_ok(zsock_setsockopt(c_sock, SOL_SOCKET, SO_REUSEPORT,
				    &yes, sizeof(yes)),
		   "setsockopt failed (%d)", errno);

	test_bind(c_sock, &c_saddr, sizeof(struct sockaddr_in));
	test_bind(s_sock, &s_saddr, sizeof(struct sockaddr_in));

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
	helper_sock = zsock_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	zassert_true(helper_sock >= 0, "helper socket failed (%d)", errno);
	zassert_ok(zsock_setsockopt(helper_sock, SOL_SOCKET,
				    SO_REUSEPORT, &yes, sizeof(yes)),
		   "setsockopt failed (%d)", errno);
	zassert_ok(zsock_bind(helper_sock, &c_saddr,
			      sizeof(struct sockaddr_in)),
		   "helper bind failed (%d)", errno);
	ret = zsock_sendto(helper_sock, &tx_buf, 0, 0, &s_saddr,
			   sizeof(struct sockaddr_in));
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

/* Neither backend builds TLS 1.0 or 1.1, so a TLS_1_0 socket runs TLS 1.2. */
ZTEST(net_socket_tls, test_tls_1_0_socket_runs_tls_1_2)
{
	struct sockaddr c_saddr, s_saddr, addr;
	socklen_t addrlen = sizeof(addr);
	struct connect_data test_data;

	prepare_sock_tls_v4(MY_IPV4_ADDR, ANY_PORT, &c_sock, (struct sockaddr_in *)&c_saddr,
			    IPPROTO_TLS_1_0);
	prepare_sock_tls_v4(MY_IPV4_ADDR, ANY_PORT, &s_sock, (struct sockaddr_in *)&s_saddr,
			    IPPROTO_TLS_1_2);
	test_config_psk(s_sock, c_sock);
	test_bind(s_sock, &s_saddr, sizeof(struct sockaddr_in));
	test_listen(s_sock);

	test_data.sock = c_sock;
	test_data.addr = &s_saddr;
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
	struct sockaddr c_saddr, s_saddr, s2_saddr;
	struct connect_data test_data;
	int role = TLS_DTLS_ROLE_SERVER;
	struct zsock_pollfd fds[1];
	uint8_t rx_buf;
	int ret;

	prepare_sock_dtls_v4(MY_IPV4_ADDR, CLIENT_1_PORT, &c_sock,
			     (struct sockaddr_in *)&c_saddr, IPPROTO_DTLS_1_2);
	prepare_sock_dtls_v4(MY_IPV4_ADDR, SERVER_PORT, &s_sock,
			     (struct sockaddr_in *)&s_saddr, IPPROTO_DTLS_1_2);
	/* c_sock_2 serves as the second server */
	prepare_sock_dtls_v4(MY_IPV4_ADDR, CLIENT_2_PORT, &c_sock_2,
			     (struct sockaddr_in *)&s2_saddr, IPPROTO_DTLS_1_2);
	test_config_psk(s_sock, c_sock);
	test_config_psk(c_sock_2, -1);
	zassert_ok(zsock_setsockopt(s_sock, SOL_TLS, TLS_DTLS_ROLE, &role,
				    sizeof(role)));
	zassert_ok(zsock_setsockopt(c_sock_2, SOL_TLS, TLS_DTLS_ROLE, &role,
				    sizeof(role)));
	test_bind(c_sock, &c_saddr, sizeof(struct sockaddr_in));
	test_bind(s_sock, &s_saddr, sizeof(struct sockaddr_in));
	test_bind(c_sock_2, &s2_saddr, sizeof(struct sockaddr_in));

	for (int i = 0; i < 2; i++) {
		int srv = i == 0 ? s_sock : c_sock_2;

		test_data.sock = c_sock;
		test_data.addr = i == 0 ? &s_saddr : &s2_saddr;
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
	struct sockaddr c_saddr, s_saddr, s2_saddr;
	struct connect_data test_data;
	struct timeval timeo_optval = { .tv_sec = 2 };
	int role = TLS_DTLS_ROLE_SERVER;
	uint8_t rx_buf;
	int ret;

	prepare_sock_dtls_v4(MY_IPV4_ADDR, CLIENT_1_PORT, &c_sock,
			     (struct sockaddr_in *)&c_saddr, IPPROTO_DTLS_1_2);
	prepare_sock_dtls_v4(MY_IPV4_ADDR, SERVER_PORT, &s_sock,
			     (struct sockaddr_in *)&s_saddr, IPPROTO_DTLS_1_2);
	/* c_sock_2 serves as the second server */
	prepare_sock_dtls_v4(MY_IPV4_ADDR, CLIENT_2_PORT, &c_sock_2,
			     (struct sockaddr_in *)&s2_saddr, IPPROTO_DTLS_1_2);
	test_config_psk(s_sock, c_sock);
	test_config_psk(c_sock_2, -1);
	zassert_ok(zsock_setsockopt(s_sock, SOL_TLS, TLS_DTLS_ROLE, &role, sizeof(role)));
	zassert_ok(zsock_setsockopt(c_sock_2, SOL_TLS, TLS_DTLS_ROLE, &role, sizeof(role)));
	zassert_ok(zsock_setsockopt(c_sock, SOL_SOCKET, SO_RCVTIMEO, &timeo_optval,
				    sizeof(timeo_optval)));
	test_bind(c_sock, &c_saddr, sizeof(struct sockaddr_in));
	test_bind(s_sock, &s_saddr, sizeof(struct sockaddr_in));
	test_bind(c_sock_2, &s2_saddr, sizeof(struct sockaddr_in));

	test_data.sock = c_sock;
	test_data.addr = &s_saddr;
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
	struct sockaddr c_saddr, s_saddr;
	struct connect_data test_data;
	struct timeval timeo_optval = { .tv_sec = 1 };
	int role = TLS_DTLS_ROLE_SERVER;
	uint8_t junk[64] = { 0 };
	uint8_t rx_buf;
	int helper_sock;
	int ret;

	prepare_sock_dtls_v4(MY_IPV4_ADDR, CLIENT_1_PORT, &c_sock,
			     (struct sockaddr_in *)&c_saddr, IPPROTO_DTLS_1_2);
	prepare_sock_dtls_v4(MY_IPV4_ADDR, SERVER_PORT, &s_sock,
			     (struct sockaddr_in *)&s_saddr, IPPROTO_DTLS_1_2);
	test_config_psk(s_sock, c_sock);
	zassert_ok(zsock_setsockopt(s_sock, SOL_TLS, TLS_DTLS_ROLE, &role, sizeof(role)));
	zassert_ok(zsock_setsockopt(s_sock, SOL_SOCKET, SO_RCVTIMEO, &timeo_optval,
				    sizeof(timeo_optval)));
	test_bind(c_sock, &c_saddr, sizeof(struct sockaddr_in));
	test_bind(s_sock, &s_saddr, sizeof(struct sockaddr_in));

	ret = zsock_recv(s_sock, &rx_buf, sizeof(rx_buf), ZSOCK_MSG_DONTWAIT);
	zassert_true(ret == -1 && errno == EAGAIN, "first recv() returned %d (%d)", ret, errno);

	/* A datagram the server must buffer while every wolfSSL allocation fails */
	helper_sock = zsock_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	zassert_true(helper_sock >= 0, "helper socket failed (%d)", errno);
	ret = zsock_sendto(helper_sock, junk, sizeof(junk), 0, &s_saddr,
			   sizeof(struct sockaddr_in));
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
	struct sockaddr c_saddr, s_saddr;
	uint32_t timeout_min = 1000;
	uint32_t timeout_max = 2000;
	int no = 0;
	int so_error = 0;
	socklen_t optlen = sizeof(so_error);
	uint8_t tx_buf = 0;
	int ret;

	prepare_sock_dtls_v4(MY_IPV4_ADDR, CLIENT_1_PORT, &c_sock,
			     (struct sockaddr_in *)&c_saddr, IPPROTO_DTLS_1_2);
	test_config_psk(-1, c_sock);
	zassert_ok(zsock_setsockopt(c_sock, SOL_TLS, TLS_DTLS_HANDSHAKE_TIMEOUT_MIN,
				    &timeout_min, sizeof(timeout_min)));
	zassert_ok(zsock_setsockopt(c_sock, SOL_TLS, TLS_DTLS_HANDSHAKE_TIMEOUT_MAX,
				    &timeout_max, sizeof(timeout_max)));
	zassert_ok(zsock_setsockopt(c_sock, SOL_TLS, TLS_DTLS_HANDSHAKE_ON_CONNECT, &no,
				    sizeof(no)));
	test_bind(c_sock, &c_saddr, sizeof(struct sockaddr_in));

	/* A plain UDP peer that never answers the handshake */
	prepare_sock_udp_v4(MY_IPV4_ADDR, SERVER_PORT, &s_sock, (struct sockaddr_in *)&s_saddr);
	test_bind(s_sock, &s_saddr, sizeof(struct sockaddr_in));

	test_connect(c_sock, &s_saddr, sizeof(struct sockaddr_in));
	ret = zsock_send(c_sock, &tx_buf, sizeof(tx_buf), 0);
	zassert_equal(ret, -1, "send() to a silent peer returned %d", ret);
	zassert_equal(errno, ETIMEDOUT, "unexpected errno %d", errno);

	zassert_ok(zsock_getsockopt(c_sock, SOL_SOCKET, SO_ERROR, &so_error, &optlen));
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
					    sizeof(struct sockaddr_in)) < 0 ? errno : 0;
	unpin_send_errno = zsock_send(data->sock, &tx_buf, sizeof(tx_buf), 0) < 0 ? errno : 0;
}
#endif

/* wolfSSL-only: a server driven without blocking lets go of a peer that went silent. */
ZTEST(net_socket_tls, test_dtls_server_unpins_silent_peer)
{
#if !defined(CONFIG_NET_SOCKETS_ENABLE_DTLS) || !defined(CONFIG_WOLFSSL)
	ztest_test_skip();
#else
	struct sockaddr c_saddr, s_saddr, h_saddr;
	struct connect_data test_data;
	struct timeval timeo_optval = { .tv_sec = 2 };
	uint32_t timeout_min = 1000;
	uint32_t timeout_max = 2000;
	int role = TLS_DTLS_ROLE_SERVER;
	int no = 0;
	uint8_t hello[512];
	uint8_t rx_buf;
	int hello_len;
	int ret = -1;

	/* Capture a ClientHello on a plain UDP socket */
	prepare_sock_dtls_v4(MY_IPV4_ADDR, CLIENT_1_PORT, &c_sock,
			     (struct sockaddr_in *)&c_saddr, IPPROTO_DTLS_1_2);
	test_config_psk(-1, c_sock);
	test_bind(c_sock, &c_saddr, sizeof(struct sockaddr_in));
	prepare_sock_udp_v4(MY_IPV4_ADDR, SERVER_PORT, &s_sock, (struct sockaddr_in *)&s_saddr);
	test_bind(s_sock, &s_saddr, sizeof(struct sockaddr_in));
	zassert_ok(zsock_setsockopt(s_sock, SOL_SOCKET, SO_RCVTIMEO, &timeo_optval,
				    sizeof(timeo_optval)));

	test_data.sock = c_sock;
	test_data.addr = &s_saddr;
	k_work_init_delayable(&test_data.work, dtls_client_connect_send_no_assert_work_handler);
	test_work_reschedule(&test_data.work, K_NO_WAIT);
	hello_len = zsock_recv(s_sock, hello, sizeof(hello), 0);
	zassert_true(hello_len > 0, "no ClientHello captured (%d)", errno);
	test_work_wait(&test_data.work);
	test_sockets_close();

	/* The server answers a replayed ClientHello from a peer that never replies */
	prepare_sock_dtls_v4(MY_IPV4_ADDR, SERVER_PORT, &s_sock,
			     (struct sockaddr_in *)&s_saddr, IPPROTO_DTLS_1_2);
	test_config_psk(s_sock, -1);
	zassert_ok(zsock_setsockopt(s_sock, SOL_TLS, TLS_DTLS_ROLE, &role, sizeof(role)));
	zassert_ok(zsock_setsockopt(s_sock, SOL_TLS, TLS_DTLS_HANDSHAKE_TIMEOUT_MIN,
				    &timeout_min, sizeof(timeout_min)));
	zassert_ok(zsock_setsockopt(s_sock, SOL_TLS, TLS_DTLS_HANDSHAKE_TIMEOUT_MAX,
				    &timeout_max, sizeof(timeout_max)));
	test_bind(s_sock, &s_saddr, sizeof(struct sockaddr_in));
	(void)zsock_recv(s_sock, &rx_buf, sizeof(rx_buf), ZSOCK_MSG_DONTWAIT);

	prepare_sock_udp_v4(MY_IPV4_ADDR, CLIENT_2_PORT, &c_sock_2,
			    (struct sockaddr_in *)&h_saddr);
	test_bind(c_sock_2, &h_saddr, sizeof(struct sockaddr_in));
	ret = zsock_sendto(c_sock_2, hello, hello_len, 0, &s_saddr, sizeof(struct sockaddr_in));
	zassert_equal(ret, hello_len, "replay failed (%d)", errno);
	k_msleep(10);
	(void)zsock_recv(s_sock, &rx_buf, sizeof(rx_buf), ZSOCK_MSG_DONTWAIT);

	/* A real client keeps retrying while the server is only polled */
	prepare_sock_dtls_v4(MY_IPV4_ADDR, CLIENT_1_PORT, &c_sock,
			     (struct sockaddr_in *)&c_saddr, IPPROTO_DTLS_1_2);
	test_config_psk(-1, c_sock);
	zassert_ok(zsock_setsockopt(c_sock, SOL_TLS, TLS_DTLS_HANDSHAKE_ON_CONNECT, &no,
				    sizeof(no)));
	test_bind(c_sock, &c_saddr, sizeof(struct sockaddr_in));
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
	struct sockaddr c_saddr, s_saddr, h_saddr;
	struct connect_data test_data;
	struct timeval timeo_optval = { .tv_sec = 2 };
	int role = TLS_DTLS_ROLE_SERVER;
	int no = 0;
	int storm[3];
	uint8_t hello[512];
	uint8_t rx_buf;
	int hello_len;
	int ret = -1;

	/* Capture a ClientHello on a plain UDP socket */
	prepare_sock_dtls_v4(MY_IPV4_ADDR, CLIENT_1_PORT, &c_sock,
			     (struct sockaddr_in *)&c_saddr, IPPROTO_DTLS_1_2);
	test_config_psk(-1, c_sock);
	test_bind(c_sock, &c_saddr, sizeof(struct sockaddr_in));
	prepare_sock_udp_v4(MY_IPV4_ADDR, SERVER_PORT, &s_sock,
			    (struct sockaddr_in *)&s_saddr);
	test_bind(s_sock, &s_saddr, sizeof(struct sockaddr_in));
	zassert_ok(zsock_setsockopt(s_sock, SOL_SOCKET, SO_RCVTIMEO, &timeo_optval,
				    sizeof(timeo_optval)));

	test_data.sock = c_sock;
	test_data.addr = &s_saddr;
	k_work_init_delayable(&test_data.work, dtls_client_connect_send_no_assert_work_handler);
	test_work_reschedule(&test_data.work, K_NO_WAIT);
	hello_len = zsock_recv(s_sock, hello, sizeof(hello), 0);
	zassert_true(hello_len > 0, "no ClientHello captured (%d)", errno);
	test_work_wait(&test_data.work);
	test_sockets_close();

	prepare_sock_dtls_v4(MY_IPV4_ADDR, SERVER_PORT, &s_sock,
			     (struct sockaddr_in *)&s_saddr, IPPROTO_DTLS_1_2);
	test_config_psk(s_sock, -1);
	zassert_ok(zsock_setsockopt(s_sock, SOL_TLS, TLS_DTLS_ROLE, &role,
				    sizeof(role)));
	test_bind(s_sock, &s_saddr, sizeof(struct sockaddr_in));

	for (int i = 0; i < ARRAY_SIZE(storm); i++) {
		prepare_sock_udp_v4(MY_IPV4_ADDR, 4250 + i, &storm[i],
				    (struct sockaddr_in *)&h_saddr);
		test_bind(storm[i], &h_saddr, sizeof(struct sockaddr_in));
	}

	prepare_sock_dtls_v4(MY_IPV4_ADDR, CLIENT_1_PORT, &c_sock,
			     (struct sockaddr_in *)&c_saddr, IPPROTO_DTLS_1_2);
	test_config_psk(-1, c_sock);
	zassert_ok(zsock_setsockopt(c_sock, SOL_TLS, TLS_DTLS_HANDSHAKE_ON_CONNECT,
				    &no, sizeof(no)));
	test_bind(c_sock, &c_saddr, sizeof(struct sockaddr_in));
	test_data.sock = c_sock;
	k_work_init_delayable(&test_data.work, dtls_client_unpin_work_handler);
	test_work_reschedule(&test_data.work, K_NO_WAIT);

	/* Each storm peer repeats its ClientHello faster than a session expires */
	for (int i = 0; i < 40; i++) {
		for (int j = 0; j < ARRAY_SIZE(storm); j++) {
			(void)zsock_sendto(storm[j], hello, hello_len, 0, &s_saddr,
					   sizeof(struct sockaddr_in));
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
	struct sockaddr c_saddr, s_saddr, c2_saddr;
	struct connect_data test_data, bad_data;
	uint32_t timeout_min = 1000;
	uint32_t timeout_max = 2000;
	int role = TLS_DTLS_ROLE_SERVER;
	int no = 0;
	uint8_t rx_buf;
	int ret = -1;

	prepare_sock_dtls_v4(MY_IPV4_ADDR, SERVER_PORT, &s_sock,
			     (struct sockaddr_in *)&s_saddr, IPPROTO_DTLS_1_2);
	test_config_psk(s_sock, -1);
	zassert_ok(zsock_setsockopt(s_sock, SOL_TLS, TLS_DTLS_ROLE, &role, sizeof(role)));
	zassert_ok(zsock_setsockopt(s_sock, SOL_TLS, TLS_DTLS_HANDSHAKE_TIMEOUT_MIN,
				    &timeout_min, sizeof(timeout_min)));
	zassert_ok(zsock_setsockopt(s_sock, SOL_TLS, TLS_DTLS_HANDSHAKE_TIMEOUT_MAX,
				    &timeout_max, sizeof(timeout_max)));
	test_bind(s_sock, &s_saddr, sizeof(struct sockaddr_in));

	/* The right identity with the wrong key: the server commits, then never sees a
	 * Finished it can decrypt
	 */
	(void)tls_credential_delete(wrong_tag, TLS_CREDENTIAL_PSK);
	(void)tls_credential_delete(wrong_tag, TLS_CREDENTIAL_PSK_ID);
	zassert_ok(tls_credential_add(wrong_tag, TLS_CREDENTIAL_PSK, wrong_psk,
				      sizeof(wrong_psk)));
	zassert_ok(tls_credential_add(wrong_tag, TLS_CREDENTIAL_PSK_ID, psk_id, strlen(psk_id)));
	prepare_sock_dtls_v4(MY_IPV4_ADDR, CLIENT_2_PORT, &c_sock_2,
			     (struct sockaddr_in *)&c2_saddr, IPPROTO_DTLS_1_2);
	zassert_ok(zsock_setsockopt(c_sock_2, SOL_TLS, TLS_SEC_TAG_LIST, &wrong_tag,
				    sizeof(wrong_tag)));
	test_bind(c_sock_2, &c2_saddr, sizeof(struct sockaddr_in));
	bad_data.sock = c_sock_2;
	bad_data.addr = &s_saddr;
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
			     (struct sockaddr_in *)&c_saddr, IPPROTO_DTLS_1_2);
	test_config_psk(-1, c_sock);
	zassert_ok(zsock_setsockopt(c_sock, SOL_TLS, TLS_DTLS_HANDSHAKE_ON_CONNECT, &no,
				    sizeof(no)));
	test_bind(c_sock, &c_saddr, sizeof(struct sockaddr_in));
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
	struct sockaddr s_saddr;
	struct timeval timeo_optval = { .tv_sec = 1 };
	int role = TLS_DTLS_ROLE_SERVER;
	uint8_t rx_buf;
	int ret;

	prepare_sock_dtls_v4(MY_IPV4_ADDR, SERVER_PORT, &s_sock,
			     (struct sockaddr_in *)&s_saddr, IPPROTO_DTLS_1_2);
	test_config_psk(s_sock, -1);
	zassert_ok(zsock_setsockopt(s_sock, SOL_TLS, TLS_DTLS_ROLE, &role, sizeof(role)));
	zassert_ok(zsock_setsockopt(s_sock, SOL_SOCKET, SO_RCVTIMEO, &timeo_optval,
				    sizeof(timeo_optval)));
	test_bind(s_sock, &s_saddr, sizeof(struct sockaddr_in));

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
	struct sockaddr c_saddr, s_saddr;
	struct connect_data test_data;
	uint8_t junk = 0, rx_buf[512];
	int flights = 0;

	prepare_sock_dtls_v4(MY_IPV4_ADDR, CLIENT_1_PORT, &c_sock,
			     (struct sockaddr_in *)&c_saddr, IPPROTO_DTLS_1_2);
	test_config_psk(-1, c_sock);
	test_bind(c_sock, &c_saddr, sizeof(struct sockaddr_in));

	/* A plain UDP peer that never answers the handshake */
	prepare_sock_udp_v4(MY_IPV4_ADDR, SERVER_PORT, &s_sock, (struct sockaddr_in *)&s_saddr);
	test_bind(s_sock, &s_saddr, sizeof(struct sockaddr_in));

	test_data.sock = c_sock;
	test_data.addr = &s_saddr;
	k_work_init_delayable(&test_data.work, dtls_client_connect_send_no_assert_work_handler);
	test_work_reschedule(&test_data.work, K_NO_WAIT);

	/* Junk every 200 ms, past the 1 s DTLS timer and within the connect timeout */
	for (int i = 0; i < 9; i++) {
		k_msleep(200);
		while (zsock_recv(s_sock, rx_buf, sizeof(rx_buf), ZSOCK_MSG_DONTWAIT) > 0) {
			flights++;
		}
		(void)zsock_sendto(s_sock, &junk, sizeof(junk), 0, &c_saddr,
				   sizeof(struct sockaddr_in));
	}

	test_work_wait(&test_data.work);
	zassert_true(flights >= 2, "client sent %d ClientHello flight(s), no retransmission",
		     flights);
#endif
}

/* wolfSSL-only: a TCP FIN without a close_notify reads as EOF, OPENSSL_EXTRA or not. */
ZTEST(net_socket_tls, test_tls_peer_fin_reads_eof)
{
#if !defined(CONFIG_WOLFSSL)
	ztest_test_skip();
#else
	test_prepare_tls_connection(AF_INET);

	/* Closing the server then sends a FIN but no close_notify */
	test_wolfssl_mark_close_notify_sent(ztls_get_wolfssl_context(new_sock));
	test_close(new_sock);
	new_sock = -1;

	test_eof(c_sock);

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

	test_prepare_tls_connection(AF_INET);

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

	ret = zsock_setsockopt(c_sock, SOL_SOCKET, SO_RCVTIMEO, &rcv_timeo, sizeof(rcv_timeo));
	zassert_ok(ret, "failed to set SO_RCVTIMEO (%d)", errno);

	ret = zsock_recv(c_sock, rx_buf, sizeof(rx_buf), 0);
	zassert_equal(ret, -1, "a TCP reset read as %d", ret);
	zassert_true(errno == EIO || errno == ECONNRESET, "unexpected errno %d", errno);

	test_sockets_close();

	k_sleep(TCP_TEARDOWN_TIMEOUT);
#endif
}

ZTEST_SUITE(net_socket_tls, NULL, tls_tests_setup, NULL, tls_tests_after, NULL);
