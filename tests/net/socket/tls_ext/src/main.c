/*
 * Copyright (c) 2020 Friedt Professional Engineering Services, Inc
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/logging/log.h>
#include <zephyr/net/net_core.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/tls_credentials.h>
#include <zephyr/posix/unistd.h>
#include <zephyr/sys/util.h>
#include <zephyr/ztest.h>

#if defined(CONFIG_WOLFSSL)
#include <time.h>
#include <wolfssl/ssl.h>
#include <zephyr/net/tls_verify.h>

struct WOLFSSL *ztls_get_wolfssl_context(int fd);
#else
#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>
#endif

LOG_MODULE_REGISTER(tls_test, CONFIG_NET_SOCKETS_LOG_LEVEL);

/**
 * @brief An encrypted message to pass between server and client.
 *
 * The answer to life, the universe, and everything.
 *
 * See also <a href="https://en.wikipedia.org/wiki/42_(number)#The_Hitchhiker's_Guide_to_the_Galaxy">42</a>.
 */
#define SECRET "forty-two"

/**
 * @brief Size of the encrypted message passed between server and client.
 */
#define SECRET_SIZE (sizeof(SECRET) - 1)

/** @brief Stack size for the server thread */
#define STACK_SIZE 8192

#define MY_IPV4_ADDR "127.0.0.1"

/** @brief TCP port for the server thread */
#define PORT 4242

/** @brief arbitrary timeout value in ms */
#define TIMEOUT 1000

/**
 * @brief Application-dependent TLS credential identifiers
 *
 * Since both the server and client exist in the same test
 * application in this case, both the server and client credentials
 * are loaded together.
 *
 * The server would normally need
 * - SERVER_CERTIFICATE_TAG (for both public and private keys)
 * - CA_CERTIFICATE_TAG (only when client authentication is required)
 *
 * The client would normally load
 * - CA_CERTIFICATE_TAG (always required, to verify the server)
 * - CLIENT_CERTIFICATE_TAG (for both public and private keys, only when
 *   client authentication is required)
 */
enum tls_tag {
	/** The Certificate Authority public key */
	CA_CERTIFICATE_TAG,
	/** Used for both the public and private server keys */
	SERVER_CERTIFICATE_TAG,
	/** Used for both the public and private client keys */
	CLIENT_CERTIFICATE_TAG,
	/** The CA of the OCSP stapling tests */
	OCSP_CA_TAG,
	/** The CA and server of the IP address SAN test */
	IP_SAN_CA_TAG,
	IP_SAN_SERVER_TAG,
	/** The client of the untrusted client certificate resumption test */
	CLIENT_AUTH_TAG,
	/** The PSK of the REQUIRED client resumption test */
	EXT_PSK_TAG,
	/** The clients of the untrusted chain CA tests and their shared key */
	CHAIN_A_TAG,
	CHAIN_B_TAG,
	CHAIN_KEY_TAG,
	/** Client A's CA, trusted by the controls of the untrusted chain CA tests */
	CHAIN_CA_TAG,
};

/** @brief synchronization object for server & client threads */
static struct k_sem server_sem;

/** @brief The server thread stack */
static K_THREAD_STACK_DEFINE(server_stack, STACK_SIZE);
/** @brief the server thread object */
static struct k_thread server_thread;

#ifdef CONFIG_TLS_CREDENTIALS
/**
 * @brief The Certificate Authority (CA) Certificate
 *
 * The client needs the CA cert to verify the server public key. TLS client
 * sockets are always required to verify the server public key.
 *
 * Additionally, when the peer verification mode is
 * @ref TLS_PEER_VERIFY_OPTIONAL or @ref TLS_PEER_VERIFY_REQUIRED, then
 * the server also needs the CA cert in order to verify the client. This
 * type of configuration is often referred to as *mutual authentication*.
 */
static const unsigned char ca[] = {
#include "ca.inc"
};

/**
 * @brief The Server Certificate
 *
 * This is the public key of the server.
 */
static const unsigned char server[] = {
#include "server.inc"
};

/**
 * @brief The Server Private Key
 *
 * This is the private key of the server.
 */
static const unsigned char server_privkey[] = {
#include "server_privkey.inc"
};

/**
 * @brief The Client Certificate
 *
 * This is the public key of the client.
 */
static const unsigned char client[] = {
#include "client.inc"
};

/**
 * @brief The Client Private Key
 *
 * This is the private key of the client.
 */
static const unsigned char client_privkey[] = {
#include "client_privkey.inc"
};

#if defined(CONFIG_NET_SOCKETS_TLS_WOLFSSL_OCSP_STAPLING)
static const unsigned char ocsp_ca[] = {
#include "ocsp_ca.inc"
};

static const unsigned char ocsp_server[] = {
#include "ocsp_server.inc"
};

static const unsigned char ocsp_server_key[] = {
#include "ocsp_server_key.inc"
};

static const unsigned char ocsp_good[] = {
#include "ocsp_good.inc"
};
#endif

#if defined(CONFIG_WOLFSSL)
/* Client A's leaf and the untrusted self-signed CA that issued it */
static const unsigned char chain_client_a[] = {
#include "client_a_chain.inc"
};

/* Client B's leaf, issued by the same untrusted CA */
static const unsigned char chain_client_b[] = {
#include "client_b.inc"
};

static const unsigned char chain_client_key[] = {
#include "client_key.inc"
};
#endif /* CONFIG_WOLFSSL */
#else /* CONFIG_TLS_CREDENTIALS */
#define ca NULL
#define server NULL
#define server_privkey NULL
#define client NULL
#define client_privkey NULL
#endif /* CONFIG_TLS_CREDENTIALS */

/**
 * @brief The server thread function
 *
 * This function simply accepts a client connection and
 * echoes the first @ref SECRET_SIZE bytes of the first
 * packet. After that, the server is closed and connections
 * are no longer accepted.
 *
 * @param arg0 a pointer to the int representing the server file descriptor
 * @param arg1 ignored
 * @param arg2 ignored
 */
static void server_thread_fn(void *arg0, void *arg1, void *arg2)
{
	const int server_fd = POINTER_TO_INT(arg0);
	const int echo = POINTER_TO_INT(arg1);
	const int expect_failure = POINTER_TO_INT(arg2);

	int r;
	int client_fd;
	socklen_t addrlen;
	char addrstr[INET_ADDRSTRLEN];
	struct sockaddr_in sa;
	char *addrstrp;

	k_thread_name_set(k_current_get(), "server");

	NET_DBG("Server thread running");

	memset(&sa, 0, sizeof(sa));
	addrlen = sizeof(sa);

	NET_DBG("Accepting client connection..");
	k_sem_give(&server_sem);
	r = accept(server_fd, (struct sockaddr *)&sa, &addrlen);
	if (expect_failure) {
		zassert_equal(r, -1, "accept() should've failed");
		return;
	}
	zassert_not_equal(r, -1, "accept() failed (%d)", r);
	client_fd = r;

	memset(addrstr, '\0', sizeof(addrstr));
	addrstrp = (char *)inet_ntop(AF_INET, &sa.sin_addr,
				     addrstr, sizeof(addrstr));
	zassert_not_equal(addrstrp, NULL, "inet_ntop() failed (%d)", errno);

	NET_DBG("accepted connection from [%s]:%d as fd %d",
		addrstr, ntohs(sa.sin_port), client_fd);

	if (echo) {
		NET_DBG("calling recv()");
		r = recv(client_fd, addrstr, sizeof(addrstr), 0);
		zassert_not_equal(r, -1, "recv() failed (%d)", errno);
		zassert_equal(r, SECRET_SIZE, "expected: %zu actual: %d",
			      SECRET_SIZE, r);

		NET_DBG("calling send()");
		r = send(client_fd, SECRET, SECRET_SIZE, 0);
		zassert_not_equal(r, -1, "send() failed (%d)", errno);
		zassert_equal(r, SECRET_SIZE, "expected: %zu actual: %d",
			      SECRET_SIZE, r);
	}

	NET_DBG("closing client fd");
	r = close(client_fd);
	zassert_not_equal(r, -1, "close() failed on the server fd (%d)", errno);
}

static int tls_proto = IPPROTO_TLS_1_2;

static int test_configure_server_ex(k_tid_t *server_thread_id, int peer_verify,
				    int echo, int expect_failure, const sec_tag_t *tags,
				    size_t tags_size, bool cache, k_thread_entry_t entry)
{
	static const sec_tag_t server_tag_list_verify_none[] = {
		SERVER_CERTIFICATE_TAG,
	};

	static const sec_tag_t server_tag_list_verify[] = {
		CA_CERTIFICATE_TAG,
		SERVER_CERTIFICATE_TAG,
	};

	char addrstr[INET_ADDRSTRLEN];
	const sec_tag_t *sec_tag_list;
	size_t sec_tag_list_size;
	struct sockaddr_in sa;
	const int yes = true;
	char *addrstrp;
	int server_fd;
	int r;

	k_sem_init(&server_sem, 0, 1);

	NET_DBG("Creating server socket");
	r = socket(AF_INET, SOCK_STREAM, tls_proto);
	zassert_not_equal(r, -1, "failed to create server socket (%d)", errno);
	server_fd = r;

	r = setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
	zassert_not_equal(r, -1, "failed to set SO_REUSEADDR (%d)", errno);

	switch (peer_verify) {
	case TLS_PEER_VERIFY_NONE:
		sec_tag_list = server_tag_list_verify_none;
		sec_tag_list_size = sizeof(server_tag_list_verify_none);
		break;
	case TLS_PEER_VERIFY_OPTIONAL:
	case TLS_PEER_VERIFY_REQUIRED:
		sec_tag_list = server_tag_list_verify;
		sec_tag_list_size = sizeof(server_tag_list_verify);

		r = setsockopt(server_fd, SOL_TLS, TLS_PEER_VERIFY,
			       &peer_verify, sizeof(peer_verify));
		zassert_not_equal(r, -1, "failed to set TLS_PEER_VERIFY (%d)",
				  errno);
		break;
	default:
		zassert_true(false, "unrecognized TLS peer verify type %d",
			     peer_verify);
		return -1;
	}

	if (tags != NULL) {
		sec_tag_list = tags;
		sec_tag_list_size = tags_size;
	}

	r = setsockopt(server_fd, SOL_TLS, TLS_SEC_TAG_LIST,
		       sec_tag_list, sec_tag_list_size);
	zassert_not_equal(r, -1, "failed to set TLS_SEC_TAG_LIST (%d)", errno);

	if (cache) {
		const int cache_on = TLS_SESSION_CACHE_ENABLED;

		r = setsockopt(server_fd, SOL_TLS, TLS_SESSION_CACHE, &cache_on, sizeof(cache_on));
		zassert_not_equal(r, -1, "failed to set TLS_SESSION_CACHE (%d)", errno);
	}

	r = setsockopt(server_fd, SOL_TLS, TLS_HOSTNAME, "localhost",
		       sizeof("localhost"));
	zassert_not_equal(r, -1, "failed to set TLS_HOSTNAME (%d)", errno);

	memset(&sa, 0, sizeof(sa));
	/* The server listens on all network interfaces */
	sa.sin_addr.s_addr = INADDR_ANY;
	sa.sin_family = AF_INET;
	sa.sin_port = htons(PORT);

	r = bind(server_fd, (struct sockaddr *)&sa, sizeof(sa));
	zassert_not_equal(r, -1, "failed to bind (%d)", errno);

	r = listen(server_fd, 1);
	zassert_not_equal(r, -1, "failed to listen (%d)", errno);

	memset(addrstr, '\0', sizeof(addrstr));
	addrstrp = (char *)inet_ntop(AF_INET, &sa.sin_addr,
				     addrstr, sizeof(addrstr));
	zassert_not_equal(addrstrp, NULL, "inet_ntop() failed (%d)", errno);

	NET_DBG("listening on [%s]:%d as fd %d",
		addrstr, ntohs(sa.sin_port), server_fd);

	NET_DBG("Creating server thread");
	*server_thread_id = k_thread_create(&server_thread, server_stack,
					    STACK_SIZE, entry,
					    INT_TO_POINTER(server_fd),
					    INT_TO_POINTER(echo),
					    INT_TO_POINTER(expect_failure),
					    K_PRIO_PREEMPT(8), 0, K_NO_WAIT);

	r = k_sem_take(&server_sem, K_MSEC(TIMEOUT));
	zassert_equal(0, r, "failed to synchronize with server thread (%d)", r);

	return server_fd;
}

static int test_configure_server(k_tid_t *server_thread_id, int peer_verify,
				 int echo, int expect_failure)
{
	return test_configure_server_ex(server_thread_id, peer_verify, echo, expect_failure,
					NULL, 0, false, server_thread_fn);
}

static int test_configure_client(struct sockaddr_in *sa, bool own_cert,
				 const char *hostname)
{
	static const sec_tag_t client_tag_list_verify_none[] = {
		CA_CERTIFICATE_TAG,
	};

	static const sec_tag_t client_tag_list_verify[] = {
		CA_CERTIFICATE_TAG,
		CLIENT_CERTIFICATE_TAG,
	};

	char addrstr[INET_ADDRSTRLEN];
	const sec_tag_t *sec_tag_list;
	size_t sec_tag_list_size;
	char *addrstrp;
	int client_fd;
	int r;

	k_thread_name_set(k_current_get(), "client");

	NET_DBG("Creating client socket");
	r = socket(AF_INET, SOCK_STREAM, tls_proto);
	zassert_not_equal(r, -1, "failed to create client socket (%d)", errno);
	client_fd = r;

	if (own_cert) {
		sec_tag_list = client_tag_list_verify;
		sec_tag_list_size = sizeof(client_tag_list_verify);
	} else {
		sec_tag_list = client_tag_list_verify_none;
		sec_tag_list_size = sizeof(client_tag_list_verify_none);
	}

	r = setsockopt(client_fd, SOL_TLS, TLS_SEC_TAG_LIST,
		       sec_tag_list, sec_tag_list_size);
	zassert_not_equal(r, -1, "failed to set TLS_SEC_TAG_LIST (%d)", errno);

	/* A NULL hostname leaves TLS_HOSTNAME unset, which both backends treat
	 * as a peer identity that cannot be verified.
	 */
	if (hostname != NULL) {
		r = zsock_setsockopt(client_fd, SOL_TLS, TLS_HOSTNAME, hostname,
				     strlen(hostname) + 1);
		zassert_not_equal(r, -1, "failed to set TLS_HOSTNAME (%d)", errno);
	}

	sa->sin_family = AF_INET;
	sa->sin_port = htons(PORT);
	r = inet_pton(AF_INET, MY_IPV4_ADDR, &sa->sin_addr.s_addr);
	zassert_not_equal(-1, r, "inet_pton() failed (%d)", errno);
	zassert_not_equal(0, r, "%s is not a valid IPv4 address", MY_IPV4_ADDR);
	zassert_equal(1, r, "inet_pton() failed to convert %s", MY_IPV4_ADDR);

	memset(addrstr, '\0', sizeof(addrstr));
	addrstrp = (char *)inet_ntop(AF_INET, &sa->sin_addr,
				     addrstr, sizeof(addrstr));
	zassert_not_equal(addrstrp, NULL, "inet_ntop() failed (%d)", errno);

	NET_DBG("connecting to [%s]:%d with fd %d",
		addrstr, ntohs(sa->sin_port), client_fd);

	return client_fd;
}
static void test_shutdown(int client_fd, int server_fd, k_tid_t server_thread_id)
{
	int r;

	NET_DBG("closing client fd");
	r = close(client_fd);
	zassert_not_equal(-1, r, "close() failed on the client fd (%d)", errno);

	NET_DBG("closing server fd");
	r = close(server_fd);
	zassert_not_equal(-1, r, "close() failed on the server fd (%d)", errno);

	r = k_thread_join(&server_thread, K_FOREVER);
	zassert_equal(0, r, "k_thread_join() failed (%d)", r);

	k_yield();
}

static void test_common(int peer_verify)
{
	k_tid_t server_thread_id;
	struct sockaddr_in sa;
	uint8_t rx_buf[16];
	int server_fd;
	int client_fd;
	int r;

	/*
	 * Server socket setup
	 */
	server_fd = test_configure_server(&server_thread_id, peer_verify, true,
					  false);

	/*
	 * Client socket setup
	 */
	client_fd = test_configure_client(&sa, peer_verify != TLS_PEER_VERIFY_NONE,
					  "localhost");

	/*
	 * The main part of the test
	 */

	r = connect(client_fd, (struct sockaddr *)&sa, sizeof(sa));
	zassert_not_equal(r, -1, "failed to connect (%d)", errno);

	NET_DBG("Calling send()");
	r = send(client_fd, SECRET, SECRET_SIZE, 0);
	zassert_not_equal(r, -1, "send() failed (%d)", errno);
	zassert_equal(SECRET_SIZE, r, "expected: %zu actual: %d", SECRET_SIZE, r);

	NET_DBG("Calling recv()");
	memset(rx_buf, 0, sizeof(rx_buf));
	r = recv(client_fd, rx_buf, sizeof(rx_buf), 0);
	zassert_not_equal(r, -1, "recv() failed (%d)", errno);
	zassert_equal(SECRET_SIZE, r, "expected: %zu actual: %d", SECRET_SIZE, r);
	zassert_mem_equal(SECRET, rx_buf, SECRET_SIZE,
			  "expected: %s actual: %s", SECRET, rx_buf);

	/*
	 * Cleanup resources
	 */
	 test_shutdown(client_fd, server_fd, server_thread_id);
}

ZTEST(net_socket_tls_api_extension, test_tls_peer_verify_none)
{
	test_common(TLS_PEER_VERIFY_NONE);
}

ZTEST(net_socket_tls_api_extension, test_tls_own_cert_padded_der)
{
	static uint8_t padded[sizeof(server) + 4];
	int r;

	memcpy(padded, server, sizeof(server));
	memset(padded + sizeof(server), 0xff, 4);

	(void)tls_credential_delete(SERVER_CERTIFICATE_TAG, TLS_CREDENTIAL_PUBLIC_CERTIFICATE);
	r = tls_credential_add(SERVER_CERTIFICATE_TAG, TLS_CREDENTIAL_PUBLIC_CERTIFICATE,
			       padded, sizeof(padded));
	zassert_ok(r, "failed to add padded server certificate (%d)", r);

	test_common(TLS_PEER_VERIFY_OPTIONAL);

	(void)tls_credential_delete(SERVER_CERTIFICATE_TAG, TLS_CREDENTIAL_PUBLIC_CERTIFICATE);
	r = tls_credential_add(SERVER_CERTIFICATE_TAG, TLS_CREDENTIAL_PUBLIC_CERTIFICATE,
			       server, sizeof(server));
	zassert_ok(r, "failed to restore server certificate (%d)", r);
}

ZTEST(net_socket_tls_api_extension, test_tls_peer_verify_optional)
{
	test_common(TLS_PEER_VERIFY_OPTIONAL);
}

ZTEST(net_socket_tls_api_extension, test_tls_peer_verify_required)
{
#if defined(CONFIG_WOLFSSL)
	/* wolfSSL rejects v1 peer certificates (test uses v1 server.der as
	 * client cert). This is a wolfSSL policy, not a bug. */
	ztest_test_skip();
#else
	test_common(TLS_PEER_VERIFY_REQUIRED);
#endif
}

/* --- Unified cert verify result tests (both backends) --- */

static void test_tls_cert_verify_result_common(int peer_verify, uint32_t expect)
{
	int server_fd, client_fd, ret;
	k_tid_t server_thread_id;
	struct sockaddr_in sa;
	uint32_t optval;
	socklen_t optlen = sizeof(optval);
	const char *hostname = "localhost";

	if (expect == MBEDTLS_X509_BADCERT_CN_MISMATCH) {
		hostname = "dummy";
	}

	server_fd = test_configure_server(&server_thread_id, TLS_PEER_VERIFY_NONE,
					  false, false);
	client_fd = test_configure_client(&sa, false, hostname);

	ret = zsock_setsockopt(client_fd, SOL_TLS, TLS_PEER_VERIFY,
			       &peer_verify, sizeof(peer_verify));
	zassert_ok(ret, "failed to set TLS_PEER_VERIFY (%d)", errno);

	ret = zsock_connect(client_fd, (struct sockaddr *)&sa, sizeof(sa));
	zassert_not_equal(ret, -1, "failed to connect (%d)", errno);

	ret = zsock_getsockopt(client_fd, SOL_TLS, TLS_CERT_VERIFY_RESULT,
			       &optval, &optlen);
	zassert_equal(ret, 0, "getsockopt failed (%d)", errno);
	zassert_equal(optval, expect, "getsockopt got invalid verify result %d",
		      optval);

	test_shutdown(client_fd, server_fd, server_thread_id);
}

ZTEST(net_socket_tls_api_extension, test_tls_cert_verify_result_opt_ok)
{
	test_tls_cert_verify_result_common(TLS_PEER_VERIFY_OPTIONAL, 0);
}

ZTEST(net_socket_tls_api_extension, test_tls_cert_verify_result_opt_bad_cn)
{
	test_tls_cert_verify_result_common(TLS_PEER_VERIFY_OPTIONAL,
					   MBEDTLS_X509_BADCERT_CN_MISMATCH);
}

ZTEST(net_socket_tls_api_extension, test_tls_cert_verify_result_none)
{
	test_tls_cert_verify_result_common(TLS_PEER_VERIFY_NONE, 0);
}

/* wolfSSL keeps the verify result of a failed handshake; mbedTLS has none after its reset */
ZTEST(net_socket_tls_api_extension, test_tls_cert_verify_result_required_bad_cn)
{
	const int required = TLS_PEER_VERIFY_REQUIRED;
	int server_fd, client_fd, ret;
	k_tid_t server_thread_id;
	struct sockaddr_in sa;
	uint32_t optval;
	socklen_t optlen = sizeof(optval);

	server_fd = test_configure_server(&server_thread_id, TLS_PEER_VERIFY_NONE,
					  false, true);
	client_fd = test_configure_client(&sa, false, "dummy");

	ret = zsock_setsockopt(client_fd, SOL_TLS, TLS_PEER_VERIFY, &required,
			       sizeof(required));
	zassert_ok(ret, "failed to set TLS_PEER_VERIFY (%d)", errno);

	ret = zsock_connect(client_fd, (struct sockaddr *)&sa, sizeof(sa));
	zassert_equal(ret, -1, "connect() should've failed");

	ret = zsock_getsockopt(client_fd, SOL_TLS, TLS_CERT_VERIFY_RESULT,
			       &optval, &optlen);
	zassert_ok(ret, "getsockopt failed (%d)", errno);
#if defined(CONFIG_WOLFSSL)
	zassert_equal(optval, MBEDTLS_X509_BADCERT_CN_MISMATCH, "verify result 0x%x", optval);
#else
	zassert_equal(optval, UINT32_MAX, "verify result 0x%x", optval);
#endif

	test_shutdown(client_fd, server_fd, server_thread_id);
}

static uint32_t resumed_verify_result[2];

/* arg1 is the number of connections to accept */
static void server_thread_resume_fn(void *arg0, void *arg1, void *arg2)
{
	const int server_fd = POINTER_TO_INT(arg0);
	socklen_t optlen;
	char buf[16];
	int client_fd;
	int r;

	ARG_UNUSED(arg2);

	k_sem_give(&server_sem);

	for (int i = 0; i < POINTER_TO_INT(arg1); i++) {
		client_fd = zsock_accept(server_fd, NULL, NULL);
		zassert_not_equal(client_fd, -1, "accept() failed (%d)", errno);

		optlen = sizeof(resumed_verify_result[i]);
		r = zsock_getsockopt(client_fd, SOL_TLS, TLS_CERT_VERIFY_RESULT,
				     &resumed_verify_result[i], &optlen);
		zassert_ok(r, "getsockopt failed (%d)", errno);

		r = zsock_recv(client_fd, buf, sizeof(buf), 0);
		zassert_equal(r, SECRET_SIZE, "recv() failed (%d)", errno);
		r = zsock_send(client_fd, SECRET, SECRET_SIZE, 0);
		zassert_equal(r, SECRET_SIZE, "send() failed (%d)", errno);
		(void)zsock_close(client_fd);
	}
}

/* A server that resumed a session checked no client certificate, so it never reports 0 */
ZTEST(net_socket_tls_api_extension, test_tls_cert_verify_result_server_resumed)
{
	const int cache_on = TLS_SESSION_CACHE_ENABLED;
	k_tid_t server_thread_id;
	struct sockaddr_in sa;
	uint8_t rx_buf[16];
	int server_fd, client_fd, r;

#if defined(CONFIG_WOLFSSL) && defined(HAVE_SECURE_RENEGOTIATION) && !defined(WOLFSSL_NO_TLS12)
	/* The children of an OPTIONAL listener have their own CTX, so its tickets do not resume */
	ztest_test_skip();
#endif

	server_fd = test_configure_server_ex(&server_thread_id, TLS_PEER_VERIFY_OPTIONAL,
					     2, false, NULL, 0, true,
					     server_thread_resume_fn);
#if defined(CONFIG_WOLFSSL)
	/* A TLS 1.2 suite, since only the session cache resumes on a wolfSSL server */
	const int tls12_suite = 0xC02F;

	r = zsock_setsockopt(server_fd, SOL_TLS, TLS_CIPHERSUITE_LIST, &tls12_suite,
			     sizeof(tls12_suite));
	zassert_ok(r, "failed to set TLS_CIPHERSUITE_LIST (%d)", errno);
#endif

	for (int i = 0; i < 2; i++) {
		client_fd = test_configure_client(&sa, false, "localhost");
		r = zsock_setsockopt(client_fd, SOL_TLS, TLS_SESSION_CACHE,
				     &cache_on, sizeof(cache_on));
		zassert_ok(r, "failed to set TLS_SESSION_CACHE (%d)", errno);

		r = zsock_connect(client_fd, (struct sockaddr *)&sa, sizeof(sa));
		zassert_not_equal(r, -1, "failed to connect (%d)", errno);
		r = zsock_send(client_fd, SECRET, SECRET_SIZE, 0);
		zassert_equal(r, SECRET_SIZE, "send() failed (%d)", errno);
		r = zsock_recv(client_fd, rx_buf, sizeof(rx_buf), 0);
		zassert_equal(r, SECRET_SIZE, "recv() failed (%d)", errno);

		if (i + 1 < 2) {
			zassert_ok(zsock_close(client_fd), "close() failed (%d)", errno);
		}
	}

	test_shutdown(client_fd, server_fd, server_thread_id);

	zassert_equal(resumed_verify_result[0], MBEDTLS_X509_BADCERT_MISSING,
		      "full handshake: verify result 0x%x, resumption 0x%x",
		      resumed_verify_result[0], resumed_verify_result[1]);
	zassert_not_equal(resumed_verify_result[1], 0, "resumption reported a verified client");
#if defined(CONFIG_WOLFSSL)
	zassert_equal(resumed_verify_result[1], MBEDTLS_X509_BADCERT_SKIP_VERIFY,
		      "resumption: verify result 0x%x", resumed_verify_result[1]);
#endif
}

/* wolfSSL-only: a resumed server session reports SKIP_VERIFY, also after a switch to REQUIRED */
ZTEST(net_socket_tls_api_extension, test_tls_server_resumed_untrusted_cert)
{
#if !defined(CONFIG_WOLFSSL)
	ztest_test_skip();
#else
	/* A client certificate with the clientAuth EKU that the server's CA did not sign */
	static const uint8_t client_auth_cert_der[] = {
		0x30, 0x82, 0x01, 0xbc, 0x30, 0x82, 0x01, 0x61, 0xa0, 0x03, 0x02, 0x01,
		0x02, 0x02, 0x02, 0x20, 0x01, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48,
		0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x40, 0x31, 0x20, 0x30, 0x1e, 0x06,
		0x03, 0x55, 0x04, 0x0a, 0x0c, 0x17, 0x5a, 0x65, 0x70, 0x68, 0x79, 0x72,
		0x20, 0x54, 0x4c, 0x53, 0x20, 0x73, 0x6f, 0x63, 0x6b, 0x65, 0x74, 0x20,
		0x74, 0x65, 0x73, 0x74, 0x73, 0x31, 0x1c, 0x30, 0x1a, 0x06, 0x03, 0x55,
		0x04, 0x03, 0x0c, 0x13, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x20, 0x61,
		0x75, 0x74, 0x68, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x43, 0x41, 0x30,
		0x20, 0x17, 0x0d, 0x32, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30,
		0x30, 0x30, 0x30, 0x5a, 0x18, 0x0f, 0x32, 0x31, 0x31, 0x39, 0x31, 0x32,
		0x33, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x30, 0x33, 0x31,
		0x20, 0x30, 0x1e, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x17, 0x5a, 0x65,
		0x70, 0x68, 0x79, 0x72, 0x20, 0x54, 0x4c, 0x53, 0x20, 0x73, 0x6f, 0x63,
		0x6b, 0x65, 0x74, 0x20, 0x74, 0x65, 0x73, 0x74, 0x73, 0x31, 0x0f, 0x30,
		0x0d, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x06, 0x63, 0x6c, 0x69, 0x65,
		0x6e, 0x74, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce,
		0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01,
		0x07, 0x03, 0x42, 0x00, 0x04, 0xd1, 0xa7, 0xce, 0xd1, 0x51, 0x1f, 0xa1,
		0x16, 0x2c, 0xe9, 0x84, 0x47, 0x04, 0x54, 0xd8, 0xd8, 0x56, 0x6d, 0x50,
		0x95, 0x0a, 0x81, 0x88, 0x99, 0x9c, 0x22, 0x0e, 0x6d, 0xf9, 0xd9, 0xe4,
		0x25, 0x76, 0x0f, 0x3a, 0xe0, 0x82, 0xe9, 0xb7, 0x80, 0x79, 0xe2, 0x8b,
		0xb4, 0x9d, 0x1f, 0x2c, 0x7b, 0x8d, 0x5a, 0x27, 0x3b, 0x25, 0x77, 0x30,
		0x60, 0xc6, 0x5a, 0x82, 0x56, 0x01, 0xa7, 0x4f, 0x1b, 0xa3, 0x56, 0x30,
		0x54, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04,
		0x02, 0x30, 0x00, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01,
		0xff, 0x04, 0x04, 0x03, 0x02, 0x07, 0x80, 0x30, 0x13, 0x06, 0x03, 0x55,
		0x1d, 0x25, 0x04, 0x0c, 0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05,
		0x05, 0x07, 0x03, 0x02, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04,
		0x18, 0x30, 0x16, 0x80, 0x14, 0x85, 0x72, 0x4e, 0x70, 0x90, 0xb7, 0xf0,
		0x6e, 0x6f, 0xca, 0x0c, 0x80, 0xed, 0xe8, 0xdd, 0x44, 0x19, 0xa3, 0xd3,
		0x3d, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03,
		0x02, 0x03, 0x49, 0x00, 0x30, 0x46, 0x02, 0x21, 0x00, 0xd6, 0x72, 0x2b,
		0x3c, 0xad, 0x3b, 0x9b, 0xa2, 0x22, 0xd7, 0x69, 0x40, 0xd8, 0x0a, 0x57,
		0xaa, 0x2c, 0xc7, 0xa2, 0x01, 0x45, 0x8e, 0x96, 0x3a, 0x93, 0x88, 0x16,
		0x2e, 0x33, 0x94, 0x0e, 0xde, 0x02, 0x21, 0x00, 0x93, 0xbc, 0x72, 0x06,
		0xb3, 0x94, 0xc1, 0x8b, 0x4d, 0xab, 0xea, 0xad, 0xd6, 0xe4, 0xc4, 0x0b,
		0x43, 0xc0, 0x84, 0x48, 0x02, 0x67, 0xd2, 0xc6, 0x59, 0x37, 0x2c, 0x0c,
		0xe9, 0x3b, 0x1c, 0xc5,
	};

	static const uint8_t client_auth_key_der[] = {
		0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20, 0x83, 0xca, 0x2a, 0x4b, 0x9d,
		0xfc, 0x87, 0xc0, 0x80, 0x2d, 0xcc, 0x9b, 0x9c, 0x5f, 0xf5, 0x1a, 0x11,
		0xac, 0x31, 0x11, 0x9d, 0x67, 0xbf, 0xc4, 0xdf, 0xb4, 0x67, 0x3d, 0x39,
		0xd4, 0x86, 0x8e, 0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
		0x03, 0x01, 0x07, 0xa1, 0x44, 0x03, 0x42, 0x00, 0x04, 0xd1, 0xa7, 0xce,
		0xd1, 0x51, 0x1f, 0xa1, 0x16, 0x2c, 0xe9, 0x84, 0x47, 0x04, 0x54, 0xd8,
		0xd8, 0x56, 0x6d, 0x50, 0x95, 0x0a, 0x81, 0x88, 0x99, 0x9c, 0x22, 0x0e,
		0x6d, 0xf9, 0xd9, 0xe4, 0x25, 0x76, 0x0f, 0x3a, 0xe0, 0x82, 0xe9, 0xb7,
		0x80, 0x79, 0xe2, 0x8b, 0xb4, 0x9d, 0x1f, 0x2c, 0x7b, 0x8d, 0x5a, 0x27,
		0x3b, 0x25, 0x77, 0x30, 0x60, 0xc6, 0x5a, 0x82, 0x56, 0x01, 0xa7, 0x4f,
		0x1b,
	};

	static const sec_tag_t client_tags[] = { CA_CERTIFICATE_TAG, CLIENT_AUTH_TAG };
	const int cache_on = TLS_SESSION_CACHE_ENABLED;
	const int required = TLS_PEER_VERIFY_REQUIRED;
	/* A TLS 1.2 suite, whose sessions every listener CTX can resume */
	const int tls12_suite = 0xC02F;
	k_tid_t server_thread_id;
	struct sockaddr_in sa;
	uint8_t rx_buf[16];
	int reused[ARRAY_SIZE(resumed_verify_result)];
	int server_fd, client_fd = -1, r;

	zassert_ok(tls_credential_add(CLIENT_AUTH_TAG, TLS_CREDENTIAL_PUBLIC_CERTIFICATE,
				      client_auth_cert_der, sizeof(client_auth_cert_der)));
	zassert_ok(tls_credential_add(CLIENT_AUTH_TAG, TLS_CREDENTIAL_PRIVATE_KEY,
				      client_auth_key_der, sizeof(client_auth_key_der)));

	server_fd = test_configure_server_ex(&server_thread_id, TLS_PEER_VERIFY_OPTIONAL,
					     ARRAY_SIZE(resumed_verify_result), false, NULL, 0,
					     true, server_thread_resume_fn);
	r = zsock_setsockopt(server_fd, SOL_TLS, TLS_CIPHERSUITE_LIST, &tls12_suite,
			     sizeof(tls12_suite));
	zassert_ok(r, "failed to set TLS_CIPHERSUITE_LIST (%d)", errno);

	/* OPTIONAL accepts the certificate, then the listener switches to REQUIRED */
	for (int i = 0; i < ARRAY_SIZE(resumed_verify_result); i++) {
		if (client_fd >= 0) {
			zassert_ok(zsock_close(client_fd), "close() failed (%d)", errno);
		}

		client_fd = test_configure_client(&sa, false, "localhost");
		r = zsock_setsockopt(client_fd, SOL_TLS, TLS_SEC_TAG_LIST, client_tags,
				     sizeof(client_tags));
		zassert_ok(r, "failed to set TLS_SEC_TAG_LIST (%d)", errno);
		r = zsock_setsockopt(client_fd, SOL_TLS, TLS_SESSION_CACHE,
				     &cache_on, sizeof(cache_on));
		zassert_ok(r, "failed to set TLS_SESSION_CACHE (%d)", errno);
		if (i == 0) {
			/* An earlier test may have left a session for this server */
			r = zsock_setsockopt(client_fd, SOL_TLS,
					     TLS_SESSION_CACHE_PURGE, NULL, 0);
			zassert_ok(r, "failed to purge the session cache (%d)", errno);
		} else {
			r = zsock_setsockopt(server_fd, SOL_TLS, TLS_PEER_VERIFY,
					     &required, sizeof(required));
			zassert_ok(r, "failed to set TLS_PEER_VERIFY (%d)", errno);
		}

		r = zsock_connect(client_fd, (struct sockaddr *)&sa, sizeof(sa));
		zassert_not_equal(r, -1, "failed to connect (%d)", errno);
		reused[i] = wolfSSL_session_reused(ztls_get_wolfssl_context(client_fd));
		r = zsock_send(client_fd, SECRET, SECRET_SIZE, 0);
		zassert_equal(r, SECRET_SIZE, "send() failed (%d)", errno);
		r = zsock_recv(client_fd, rx_buf, sizeof(rx_buf), 0);
		zassert_equal(r, SECRET_SIZE, "recv() failed (%d)", errno);
	}

	test_shutdown(client_fd, server_fd, server_thread_id);

	zassert_not_equal(resumed_verify_result[0], 0, "untrusted certificate read as verified");
	zassert_equal(reused[1], 1, "the session was not resumed");
	zassert_equal(resumed_verify_result[1], MBEDTLS_X509_BADCERT_SKIP_VERIFY,
		      "REQUIRED resumption: 0x%x", resumed_verify_result[1]);
#endif
}

#if defined(CONFIG_WOLFSSL)
static void server_thread_echo_twice_fn(void *arg0, void *arg1, void *arg2)
{
	const int server_fd = POINTER_TO_INT(arg0);
	char buf[16];
	int client_fd;

	ARG_UNUSED(arg1);
	ARG_UNUSED(arg2);

	k_sem_give(&server_sem);

	/* The second handshake may fail, which is what the test checks */
	for (int i = 0; i < 2; i++) {
		client_fd = zsock_accept(server_fd, NULL, NULL);
		if (client_fd < 0) {
			continue;
		}

		if (zsock_recv(client_fd, buf, sizeof(buf), 0) > 0) {
			(void)zsock_send(client_fd, SECRET, SECRET_SIZE, 0);
		}
		(void)zsock_close(client_fd);
	}
}
#endif /* CONFIG_WOLFSSL */

/* wolfSSL-only: a REQUIRED client does not resume a session whose server failed the check */
ZTEST(net_socket_tls_api_extension, test_tls_required_skips_unverified_session)
{
#if !defined(CONFIG_WOLFSSL)
	ztest_test_skip();
#else
	const int cache_on = TLS_SESSION_CACHE_ENABLED;
	const int levels[] = { TLS_PEER_VERIFY_OPTIONAL, TLS_PEER_VERIFY_REQUIRED };
	const int tls12_suite = 0xC02F;
	k_tid_t server_thread_id;
	struct sockaddr_in sa;
	uint8_t rx_buf[16];
	int server_fd, client_fd = -1, r;

	server_fd = test_configure_server_ex(&server_thread_id, TLS_PEER_VERIFY_NONE,
					     false, false, NULL, 0, true,
					     server_thread_echo_twice_fn);
	/* A TLS 1.2 suite, since only the session cache resumes on a wolfSSL server */
	r = zsock_setsockopt(server_fd, SOL_TLS, TLS_CIPHERSUITE_LIST, &tls12_suite,
			     sizeof(tls12_suite));
	zassert_ok(r, "failed to set TLS_CIPHERSUITE_LIST (%d)", errno);

	for (int i = 0; i < ARRAY_SIZE(levels); i++) {
		client_fd = test_configure_client(&sa, false, "dummy");
		if (i == 0) {
			r = zsock_setsockopt(client_fd, SOL_TLS,
					     TLS_SESSION_CACHE_PURGE, NULL, 0);
			zassert_ok(r, "failed to purge the session cache (%d)", errno);
		}
		r = zsock_setsockopt(client_fd, SOL_TLS, TLS_SESSION_CACHE,
				     &cache_on, sizeof(cache_on));
		zassert_ok(r, "failed to set TLS_SESSION_CACHE (%d)", errno);
		r = zsock_setsockopt(client_fd, SOL_TLS, TLS_PEER_VERIFY,
				     &levels[i], sizeof(levels[i]));
		zassert_ok(r, "failed to set TLS_PEER_VERIFY (%d)", errno);

		r = zsock_connect(client_fd, (struct sockaddr *)&sa, sizeof(sa));
		if (i == 0) {
			zassert_not_equal(r, -1, "failed to connect (%d)", errno);
			r = zsock_send(client_fd, SECRET, SECRET_SIZE, 0);
			zassert_equal(r, SECRET_SIZE, "send() failed (%d)", errno);
			r = zsock_recv(client_fd, rx_buf, sizeof(rx_buf), 0);
			zassert_equal(r, SECRET_SIZE, "recv() failed (%d)", errno);
			zassert_ok(zsock_close(client_fd), "close() failed (%d)", errno);
		} else {
			zassert_equal(r, -1, "REQUIRED resumed a session with a name mismatch");
		}
	}

	test_shutdown(client_fd, server_fd, server_thread_id);
#endif
}

/* wolfSSL-only: a PSK on a REQUIRED client does not resume a session nobody verified */
ZTEST(net_socket_tls_api_extension, test_tls_required_psk_skips_unverified_session)
{
#if !defined(CONFIG_WOLFSSL) || defined(NO_PSK)
	ztest_test_skip();
#else
	static const uint8_t psk[] = {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	};
	static const char psk_id[] = "tls_ext_psk";
	static const sec_tag_t client_tags[] = { CA_CERTIFICATE_TAG, EXT_PSK_TAG };
	const int cache_on = TLS_SESSION_CACHE_ENABLED;
	const int levels[] = { TLS_PEER_VERIFY_NONE, TLS_PEER_VERIFY_REQUIRED };
	const int tls12_suite = 0xC02F;
	k_tid_t server_thread_id;
	struct sockaddr_in sa;
	uint8_t rx_buf[16];
	int server_fd, client_fd = -1, r;

	zassert_ok(tls_credential_add(EXT_PSK_TAG, TLS_CREDENTIAL_PSK, psk, sizeof(psk)));
	zassert_ok(tls_credential_add(EXT_PSK_TAG, TLS_CREDENTIAL_PSK_ID, psk_id,
				      strlen(psk_id)));

	server_fd = test_configure_server_ex(&server_thread_id, TLS_PEER_VERIFY_NONE,
					     false, false, NULL, 0, true,
					     server_thread_echo_twice_fn);
	r = zsock_setsockopt(server_fd, SOL_TLS, TLS_CIPHERSUITE_LIST, &tls12_suite,
			     sizeof(tls12_suite));
	zassert_ok(r, "failed to set TLS_CIPHERSUITE_LIST (%d)", errno);

	for (int i = 0; i < ARRAY_SIZE(levels); i++) {
		client_fd = test_configure_client(&sa, false, "dummy");
		if (i == 0) {
			r = zsock_setsockopt(client_fd, SOL_TLS,
					     TLS_SESSION_CACHE_PURGE, NULL, 0);
			zassert_ok(r, "failed to purge the session cache (%d)", errno);
		} else {
			r = zsock_setsockopt(client_fd, SOL_TLS, TLS_SEC_TAG_LIST,
					     client_tags, sizeof(client_tags));
			zassert_ok(r, "failed to set TLS_SEC_TAG_LIST (%d)", errno);
		}
		r = zsock_setsockopt(client_fd, SOL_TLS, TLS_SESSION_CACHE,
				     &cache_on, sizeof(cache_on));
		zassert_ok(r, "failed to set TLS_SESSION_CACHE (%d)", errno);
		r = zsock_setsockopt(client_fd, SOL_TLS, TLS_PEER_VERIFY,
				     &levels[i], sizeof(levels[i]));
		zassert_ok(r, "failed to set TLS_PEER_VERIFY (%d)", errno);

		r = zsock_connect(client_fd, (struct sockaddr *)&sa, sizeof(sa));
		if (i == 0) {
			zassert_not_equal(r, -1, "failed to connect (%d)", errno);
			r = zsock_send(client_fd, SECRET, SECRET_SIZE, 0);
			zassert_equal(r, SECRET_SIZE, "send() failed (%d)", errno);
			r = zsock_recv(client_fd, rx_buf, sizeof(rx_buf), 0);
			zassert_equal(r, SECRET_SIZE, "recv() failed (%d)", errno);
			zassert_ok(zsock_close(client_fd), "close() failed (%d)", errno);
		} else {
			zassert_equal(r, -1, "REQUIRED resumed an unverified session through its PSK");
		}
	}

	test_shutdown(client_fd, server_fd, server_thread_id);
#endif
}

#if defined(CONFIG_WOLFSSL) && !defined(SINGLE_THREADED)
static int accepted_connect_ret;
static int accepted_connect_errno;

static void server_thread_connect_fn(void *arg0, void *arg1, void *arg2)
{
	const int server_fd = POINTER_TO_INT(arg0);
	struct sockaddr_in sa = {
		.sin_family = AF_INET,
		.sin_port = htons(PORT),
	};
	char buf[16];
	int client_fd;
	int r;

	ARG_UNUSED(arg1);
	ARG_UNUSED(arg2);

	k_sem_give(&server_sem);

	client_fd = zsock_accept(server_fd, NULL, NULL);
	zassert_not_equal(client_fd, -1, "accept() failed (%d)", errno);

	(void)zsock_inet_pton(AF_INET, MY_IPV4_ADDR, &sa.sin_addr);
	accepted_connect_ret = zsock_connect(client_fd, (struct sockaddr *)&sa, sizeof(sa));
	accepted_connect_errno = errno;

	r = zsock_recv(client_fd, buf, sizeof(buf), 0);
	zassert_equal(r, SECRET_SIZE, "recv() failed (%d)", errno);
	r = zsock_send(client_fd, SECRET, SECRET_SIZE, 0);
	zassert_equal(r, SECRET_SIZE, "send() failed (%d)", errno);
	(void)zsock_close(client_fd);
}
#endif /* CONFIG_WOLFSSL && !SINGLE_THREADED */

/* wolfSSL-only: connect() on an accepted socket fails and leaves its session working */
ZTEST(net_socket_tls_api_extension, test_tls_connect_on_accepted_socket)
{
#if !defined(CONFIG_WOLFSSL) || defined(SINGLE_THREADED)
	ztest_test_skip();
#else
	k_tid_t server_thread_id;
	struct sockaddr_in sa;
	uint8_t rx_buf[16];
	int server_fd, client_fd, r;

	accepted_connect_ret = 0;
	accepted_connect_errno = 0;

	server_fd = test_configure_server_ex(&server_thread_id, TLS_PEER_VERIFY_NONE,
					     false, false, NULL, 0, false,
					     server_thread_connect_fn);
	client_fd = test_configure_client(&sa, false, "localhost");

	r = zsock_connect(client_fd, (struct sockaddr *)&sa, sizeof(sa));
	zassert_not_equal(r, -1, "failed to connect (%d)", errno);
	r = zsock_send(client_fd, SECRET, SECRET_SIZE, 0);
	zassert_equal(r, SECRET_SIZE, "send() failed (%d)", errno);
	r = zsock_recv(client_fd, rx_buf, sizeof(rx_buf), 0);
	zassert_equal(r, SECRET_SIZE, "recv() failed (%d)", errno);

	test_shutdown(client_fd, server_fd, server_thread_id);

	zassert_equal(accepted_connect_ret, -1, "connect() on an accepted socket succeeded");
	zassert_equal(accepted_connect_errno, EISCONN, "errno %d", accepted_connect_errno);
#endif
}

#if defined(CONFIG_WOLFSSL) && defined(CONFIG_TLS_CREDENTIALS)
static const sec_tag_t chain_ca_client_tags[][3] = {
	{ CA_CERTIFICATE_TAG, CHAIN_A_TAG, CHAIN_KEY_TAG },
	{ CA_CERTIFICATE_TAG, CHAIN_B_TAG, CHAIN_KEY_TAG },
};

static void chain_ca_add_credentials(void)
{
	zassert_ok(tls_credential_add(CHAIN_A_TAG, TLS_CREDENTIAL_PUBLIC_CERTIFICATE,
				      chain_client_a, sizeof(chain_client_a)));
	zassert_ok(tls_credential_add(CHAIN_B_TAG, TLS_CREDENTIAL_PUBLIC_CERTIFICATE,
				      chain_client_b, sizeof(chain_client_b)));
	zassert_ok(tls_credential_add(CHAIN_KEY_TAG, TLS_CREDENTIAL_PRIVATE_KEY,
				      chain_client_key, sizeof(chain_client_key)));
}

/* Client A's chain is its leaf, with a two-byte DER length, followed by the CA */
static void chain_ca_add_trusted_ca(void)
{
	size_t leaf_len = 4 + ((chain_client_a[2] << 8) | chain_client_a[3]);

	zassert_equal(chain_client_a[1], 0x82, "unexpected leaf length encoding");
	zassert_ok(tls_credential_add(CHAIN_CA_TAG, TLS_CREDENTIAL_CA_CERTIFICATE,
				      chain_client_a + leaf_len,
				      sizeof(chain_client_a) - leaf_len));
}

#if defined(HAVE_SECURE_RENEGOTIATION)
/* Like server_thread_resume_fn, but lets a renegotiation fail the first recv() */
static void server_thread_reneg_fn(void *arg0, void *arg1, void *arg2)
{
	const int server_fd = POINTER_TO_INT(arg0);
	socklen_t optlen;
	char buf[16];
	int client_fd;
	int r;

	ARG_UNUSED(arg2);

	k_sem_give(&server_sem);

	for (int i = 0; i < POINTER_TO_INT(arg1); i++) {
		client_fd = zsock_accept(server_fd, NULL, NULL);
		zassert_not_equal(client_fd, -1, "accept() failed (%d)", errno);

		optlen = sizeof(resumed_verify_result[i]);
		r = zsock_getsockopt(client_fd, SOL_TLS, TLS_CERT_VERIFY_RESULT,
				     &resumed_verify_result[i], &optlen);
		zassert_ok(r, "getsockopt failed (%d)", errno);

		r = zsock_recv(client_fd, buf, sizeof(buf), 0);
		if (r == SECRET_SIZE) {
			r = zsock_send(client_fd, SECRET, SECRET_SIZE, 0);
			zassert_equal(r, SECRET_SIZE, "send() failed (%d)", errno);
		}
		(void)zsock_close(client_fd);
	}
}

/* Returns whether the client's renegotiation completed */
static bool chain_ca_renegotiate(int client_fd)
{
	WOLFSSL *ssl = ztls_get_wolfssl_context(client_fd);
	int ret = wolfSSL_Rehandshake(ssl);
	int err;

	for (int i = 0; ret != WOLFSSL_SUCCESS && i < 100; i++) {
		err = wolfSSL_get_error(ssl, ret);
		if (err != WOLFSSL_ERROR_WANT_READ && err != WOLFSSL_ERROR_WANT_WRITE) {
			break;
		}

		k_msleep(10);
		ret = wolfSSL_negotiate(ssl);
	}

	return ret == WOLFSSL_SUCCESS;
}
#endif /* HAVE_SECURE_RENEGOTIATION */

/* Client A sends its CA, also in a renegotiation if asked; client B's leaf is signed by it.
 * With trusted set, the server trusts that CA.
 */
static void chain_ca_tcp_common(int peer_verify, const void *cb, size_t cb_len,
				bool renegotiate, bool trusted)
{
	static const sec_tag_t trusted_tags[] = {
		CA_CERTIFICATE_TAG, SERVER_CERTIFICATE_TAG, CHAIN_CA_TAG
	};
	k_thread_entry_t entry = server_thread_resume_fn;
	k_tid_t server_thread_id;
	struct sockaddr_in sa;
	uint8_t rx_buf[16];
	bool reneg_done = false;
	int server_fd, client_fd = -1, r;

	chain_ca_add_credentials();
	if (trusted) {
		chain_ca_add_trusted_ca();
	}

#if defined(HAVE_SECURE_RENEGOTIATION)
	if (renegotiate) {
		entry = server_thread_reneg_fn;
	}
#endif /* HAVE_SECURE_RENEGOTIATION */

	server_fd = test_configure_server_ex(&server_thread_id, peer_verify,
					     ARRAY_SIZE(resumed_verify_result), false,
					     trusted ? trusted_tags : NULL,
					     trusted ? sizeof(trusted_tags) : 0, false, entry);
	if (renegotiate) {
		/* TLS 1.3 has no renegotiation */
		const int tls12_suite = 0xC02F;

		r = zsock_setsockopt(server_fd, SOL_TLS, TLS_CIPHERSUITE_LIST, &tls12_suite,
				     sizeof(tls12_suite));
		zassert_ok(r, "failed to set TLS_CIPHERSUITE_LIST (%d)", errno);
	}
	if (cb != NULL) {
		r = zsock_setsockopt(server_fd, SOL_TLS, TLS_CERT_VERIFY_CALLBACK_WOLFSSL, cb,
				     cb_len);
		zassert_ok(r, "failed to set the verify callback (%d)", errno);
	}

	for (int i = 0; i < ARRAY_SIZE(chain_ca_client_tags); i++) {
		if (client_fd >= 0) {
			zassert_ok(zsock_close(client_fd), "close() failed (%d)", errno);
		}

		client_fd = test_configure_client(&sa, false, "localhost");
		r = zsock_setsockopt(client_fd, SOL_TLS, TLS_SEC_TAG_LIST,
				     chain_ca_client_tags[i], sizeof(chain_ca_client_tags[i]));
		zassert_ok(r, "failed to set TLS_SEC_TAG_LIST (%d)", errno);

		r = zsock_connect(client_fd, (struct sockaddr *)&sa, sizeof(sa));
		zassert_not_equal(r, -1, "failed to connect (%d)", errno);
#if defined(HAVE_SECURE_RENEGOTIATION)
		if (i == 0 && renegotiate) {
			reneg_done = chain_ca_renegotiate(client_fd);
			if (!reneg_done) {
				continue;
			}
		}
#endif /* HAVE_SECURE_RENEGOTIATION */
		r = zsock_send(client_fd, SECRET, SECRET_SIZE, 0);
		zassert_equal(r, SECRET_SIZE, "send() failed (%d)", errno);
		r = zsock_recv(client_fd, rx_buf, sizeof(rx_buf), 0);
		zassert_equal(r, SECRET_SIZE, "recv() failed (%d)", errno);
	}

	test_shutdown(client_fd, server_fd, server_thread_id);

	if (trusted) {
		zassert_equal(reneg_done, renegotiate, "the trusted renegotiation failed");
		zassert_equal(resumed_verify_result[0], 0, "client A: verify result 0x%x",
			      resumed_verify_result[0]);
		zassert_equal(resumed_verify_result[1], 0, "client B: verify result 0x%x",
			      resumed_verify_result[1]);
		return;
	}

	zassert_false(reneg_done, "the server renegotiated with a failed chain CA");
	zassert_equal(resumed_verify_result[0], MBEDTLS_X509_BADCERT_NOT_TRUSTED,
		      "client A: verify result 0x%x", resumed_verify_result[0]);
	zassert_equal(resumed_verify_result[1], MBEDTLS_X509_BADCERT_NOT_TRUSTED,
		      "client B: verify result 0x%x", resumed_verify_result[1]);
}
#endif /* CONFIG_WOLFSSL && CONFIG_TLS_CREDENTIALS */

/* wolfSSL-only: a CA that failed verification under OPTIONAL is not trusted afterwards */
ZTEST(net_socket_tls_api_extension, test_tls_optional_chain_ca_not_learned)
{
#if !defined(CONFIG_WOLFSSL) || !defined(CONFIG_TLS_CREDENTIALS)
	ztest_test_skip();
#else
	chain_ca_tcp_common(TLS_PEER_VERIFY_OPTIONAL, NULL, 0, false, false);
#endif
}

/* wolfSSL-only: a renegotiation does not let a failed chain CA into the listener's CTX */
ZTEST(net_socket_tls_api_extension, test_tls_optional_reneg_chain_ca_not_learned)
{
#if !defined(CONFIG_WOLFSSL) || !defined(CONFIG_TLS_CREDENTIALS) || \
	!defined(HAVE_SECURE_RENEGOTIATION) || defined(WOLFSSL_NO_TLS12)
	ztest_test_skip();
#else
	chain_ca_tcp_common(TLS_PEER_VERIFY_OPTIONAL, NULL, 0, true, false);
#endif
}

/* wolfSSL-only: the control for the test above, with client A's CA trusted */
ZTEST(net_socket_tls_api_extension, test_tls_optional_reneg_trusted_chain)
{
#if !defined(CONFIG_WOLFSSL) || !defined(CONFIG_TLS_CREDENTIALS) || \
	!defined(HAVE_SECURE_RENEGOTIATION) || defined(WOLFSSL_NO_TLS12)
	ztest_test_skip();
#else
	chain_ca_tcp_common(TLS_PEER_VERIFY_OPTIONAL, NULL, 0, true, true);
#endif
}

#if defined(CONFIG_WOLFSSL) && !defined(SINGLE_THREADED)
static int accepted_ctx_shared;

/* Compares the CTX of two accepted children; a reference keeps the first one's address unused */
static void server_thread_two_children_fn(void *arg0, void *arg1, void *arg2)
{
	const int server_fd = POINTER_TO_INT(arg0);
	WOLFSSL_CTX *first = NULL;
	WOLFSSL_CTX *ctx;
	char buf[16];
	int child_fd;
	int r;

	ARG_UNUSED(arg1);
	ARG_UNUSED(arg2);

	k_sem_give(&server_sem);

	for (int i = 0; i < 2; i++) {
		child_fd = zsock_accept(server_fd, NULL, NULL);
		zassert_not_equal(child_fd, -1, "accept() failed (%d)", errno);

		ctx = wolfSSL_get_SSL_CTX(ztls_get_wolfssl_context(child_fd));
		if (first == NULL) {
			first = ctx;
			zassert_equal(wolfSSL_CTX_up_ref(first), WOLFSSL_SUCCESS);
		} else {
			accepted_ctx_shared = ctx == first;
		}

		r = zsock_recv(child_fd, buf, sizeof(buf), 0);
		zassert_equal(r, SECRET_SIZE, "recv() failed (%d)", errno);
		r = zsock_send(child_fd, SECRET, SECRET_SIZE, 0);
		zassert_equal(r, SECRET_SIZE, "send() failed (%d)", errno);
		(void)zsock_close(child_fd);
	}

	wolfSSL_CTX_free(first);
}

/* Returns whether two children of a listener set up this way shared its CTX */
static bool listener_ctx_shared(int peer_verify, const void *cb, size_t cb_len, bool own_cert)
{
	k_tid_t server_thread_id;
	struct sockaddr_in sa;
	uint8_t rx_buf[16];
	int server_fd, client_fd = -1, r;

	accepted_ctx_shared = -1;
	server_fd = test_configure_server_ex(&server_thread_id, peer_verify, false, false, NULL,
					     0, false, server_thread_two_children_fn);
	if (cb != NULL) {
		r = zsock_setsockopt(server_fd, SOL_TLS, TLS_CERT_VERIFY_CALLBACK_WOLFSSL, cb,
				     cb_len);
		zassert_ok(r, "failed to set the verify callback (%d)", errno);
	}

	for (int i = 0; i < 2; i++) {
		if (client_fd >= 0) {
			zassert_ok(zsock_close(client_fd), "close() failed (%d)", errno);
		}

		client_fd = test_configure_client(&sa, own_cert, "localhost");
		r = zsock_connect(client_fd, (struct sockaddr *)&sa, sizeof(sa));
		zassert_not_equal(r, -1, "failed to connect (%d)", errno);
		r = zsock_send(client_fd, SECRET, SECRET_SIZE, 0);
		zassert_equal(r, SECRET_SIZE, "send() failed (%d)", errno);
		r = zsock_recv(client_fd, rx_buf, sizeof(rx_buf), 0);
		zassert_equal(r, SECRET_SIZE, "recv() failed (%d)", errno);
	}

	test_shutdown(client_fd, server_fd, server_thread_id);
	zassert_not_equal(accepted_ctx_shared, -1, "the server never accepted a second child");

	return accepted_ctx_shared == 1;
}

#if defined(HAVE_SECURE_RENEGOTIATION) && !defined(WOLFSSL_NO_TLS12)
#define RENEGOTIATION_UNSHARES true
#else
#define RENEGOTIATION_UNSHARES false
#endif
#endif /* CONFIG_WOLFSSL && !SINGLE_THREADED */

/* wolfSSL-only: children of an OPTIONAL listener share its CTX only without renegotiation */
ZTEST(net_socket_tls_api_extension, test_tls_optional_listener_ctx_sharing)
{
#if !defined(CONFIG_WOLFSSL) || defined(SINGLE_THREADED)
	ztest_test_skip();
#else
	zassert_equal(listener_ctx_shared(TLS_PEER_VERIFY_OPTIONAL, NULL, 0, false),
		      !RENEGOTIATION_UNSHARES, "unexpected CTX sharing");
#endif
}

/* wolfSSL-only: a TLS 1.3 listener cannot renegotiate, so its children always share */
ZTEST(net_socket_tls_api_extension, test_tls_optional_tls13_listener_ctx_shared)
{
#if !defined(CONFIG_WOLFSSL) || defined(SINGLE_THREADED) || !defined(WOLFSSL_TLS13)
	ztest_test_skip();
#else
	tls_proto = IPPROTO_TLS_1_3;
	zassert_true(listener_ctx_shared(TLS_PEER_VERIFY_OPTIONAL, NULL, 0, false),
		     "the children of a TLS 1.3 listener do not share its CTX");
#endif
}

#if defined(CONFIG_WOLFSSL) && defined(CONFIG_TLS_CREDENTIALS) && \
	defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
/* Reads the verify result after the first record of each client */
static void server_thread_dtls_verify_fn(void *arg0, void *arg1, void *arg2)
{
	const int server_fd = POINTER_TO_INT(arg0);
	socklen_t optlen;
	char buf[16];
	int r;

	ARG_UNUSED(arg1);
	ARG_UNUSED(arg2);

	k_sem_give(&server_sem);

	for (int i = 0; i < ARRAY_SIZE(resumed_verify_result); i++) {
		r = zsock_recv(server_fd, buf, sizeof(buf), 0);
		zassert_equal(r, SECRET_SIZE, "recv() failed (%d)", errno);

		optlen = sizeof(resumed_verify_result[i]);
		r = zsock_getsockopt(server_fd, SOL_TLS, TLS_CERT_VERIFY_RESULT,
				     &resumed_verify_result[i], &optlen);
		zassert_ok(r, "getsockopt failed (%d)", errno);
	}
}
#endif

/* wolfSSL-only: a DTLS server keeps its CTX for the next peer, which must not trust A's CA */
ZTEST(net_socket_tls_api_extension, test_dtls_optional_chain_ca_not_learned)
{
#if !defined(CONFIG_WOLFSSL) || !defined(CONFIG_TLS_CREDENTIALS) || \
	!defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
	ztest_test_skip();
#else
	static const sec_tag_t server_tags[] = { CA_CERTIFICATE_TAG, SERVER_CERTIFICATE_TAG };
	const int peer_verify = TLS_PEER_VERIFY_OPTIONAL;
	const int role = TLS_DTLS_ROLE_SERVER;
	const struct timeval timeo = { .tv_sec = 5 };
	struct sockaddr_in sa;
	int server_fd, client_fd, r;

	chain_ca_add_credentials();
	k_sem_init(&server_sem, 0, 1);

	server_fd = zsock_socket(AF_INET, SOCK_DGRAM, IPPROTO_DTLS_1_2);
	zassert_not_equal(server_fd, -1, "failed to create server socket (%d)", errno);
	zassert_ok(zsock_setsockopt(server_fd, SOL_TLS, TLS_DTLS_ROLE, &role, sizeof(role)));
	zassert_ok(zsock_setsockopt(server_fd, SOL_TLS, TLS_PEER_VERIFY, &peer_verify,
				    sizeof(peer_verify)));
	zassert_ok(zsock_setsockopt(server_fd, SOL_TLS, TLS_SEC_TAG_LIST, server_tags,
				    sizeof(server_tags)));
	zassert_ok(zsock_setsockopt(server_fd, SOL_SOCKET, SO_RCVTIMEO, &timeo, sizeof(timeo)));

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(PORT);
	zassert_equal(zsock_inet_pton(AF_INET, MY_IPV4_ADDR, &sa.sin_addr), 1);
	zassert_ok(zsock_bind(server_fd, (struct sockaddr *)&sa, sizeof(sa)),
		   "failed to bind (%d)", errno);

	k_thread_create(&server_thread, server_stack, STACK_SIZE, server_thread_dtls_verify_fn,
			INT_TO_POINTER(server_fd), NULL, NULL, K_PRIO_PREEMPT(8), 0, K_NO_WAIT);
	zassert_ok(k_sem_take(&server_sem, K_MSEC(TIMEOUT)));

	/* The server serves one peer at a time, so A's close_notify lets B in */
	for (int i = 0; i < ARRAY_SIZE(chain_ca_client_tags); i++) {
		client_fd = zsock_socket(AF_INET, SOCK_DGRAM, IPPROTO_DTLS_1_2);
		zassert_not_equal(client_fd, -1, "failed to create client socket (%d)", errno);
		zassert_ok(zsock_setsockopt(client_fd, SOL_TLS, TLS_SEC_TAG_LIST,
					    chain_ca_client_tags[i],
					    sizeof(chain_ca_client_tags[i])));
		zassert_ok(zsock_setsockopt(client_fd, SOL_TLS, TLS_HOSTNAME, "localhost",
					    sizeof("localhost")));

		r = zsock_connect(client_fd, (struct sockaddr *)&sa, sizeof(sa));
		zassert_ok(r, "failed to connect (%d)", errno);
		r = zsock_send(client_fd, SECRET, SECRET_SIZE, 0);
		zassert_equal(r, SECRET_SIZE, "send() failed (%d)", errno);
		zassert_ok(zsock_close(client_fd), "close() failed (%d)", errno);
	}

	zassert_ok(k_thread_join(&server_thread, K_FOREVER));
	zassert_ok(zsock_close(server_fd), "close() failed (%d)", errno);

	zassert_equal(resumed_verify_result[0], MBEDTLS_X509_BADCERT_NOT_TRUSTED,
		      "client A: verify result 0x%x", resumed_verify_result[0]);
	zassert_equal(resumed_verify_result[1], MBEDTLS_X509_BADCERT_NOT_TRUSTED,
		      "client B: verify result 0x%x", resumed_verify_result[1]);
#endif
}

#if defined(CONFIG_TLS_CREDENTIALS)
/* A leaf for 127.0.0.1 with only an iPAddress SAN, and its CA */
static const uint8_t ip_san_ca_der[] = {
	0x30, 0x82, 0x03, 0x26, 0x30, 0x82, 0x02, 0x0e, 0xa0, 0x03, 0x02, 0x01,
	0x02, 0x02, 0x14, 0x6e, 0x2e, 0x75, 0xa1, 0x93, 0xc8, 0xe2, 0x78, 0x94,
	0x6f, 0x83, 0x81, 0xfd, 0x7d, 0xba, 0x33, 0xb1, 0x6c, 0xe6, 0xfe, 0x30,
	0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
	0x05, 0x00, 0x30, 0x2a, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04,
	0x0a, 0x0c, 0x06, 0x5a, 0x65, 0x70, 0x68, 0x79, 0x72, 0x31, 0x17, 0x30,
	0x15, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0e, 0x49, 0x50, 0x20, 0x53,
	0x41, 0x4e, 0x20, 0x54, 0x65, 0x73, 0x74, 0x20, 0x43, 0x41, 0x30, 0x20,
	0x17, 0x0d, 0x32, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30,
	0x30, 0x30, 0x5a, 0x18, 0x0f, 0x32, 0x31, 0x31, 0x39, 0x31, 0x32, 0x33,
	0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x30, 0x2a, 0x31, 0x0f,
	0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x06, 0x5a, 0x65, 0x70,
	0x68, 0x79, 0x72, 0x31, 0x17, 0x30, 0x15, 0x06, 0x03, 0x55, 0x04, 0x03,
	0x0c, 0x0e, 0x49, 0x50, 0x20, 0x53, 0x41, 0x4e, 0x20, 0x54, 0x65, 0x73,
	0x74, 0x20, 0x43, 0x41, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09,
	0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03,
	0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01,
	0x00, 0xc4, 0x5c, 0x42, 0xff, 0x90, 0x7b, 0x07, 0x04, 0x34, 0xce, 0x35,
	0x75, 0x11, 0x32, 0x06, 0xeb, 0x7b, 0xdb, 0xb8, 0xa5, 0x15, 0xe1, 0xe2,
	0xea, 0x1c, 0x84, 0x08, 0x97, 0x4b, 0xe4, 0x79, 0x42, 0x36, 0x13, 0xd5,
	0xda, 0x40, 0xe6, 0x21, 0xbb, 0xd3, 0x33, 0xdb, 0x13, 0x52, 0x4f, 0xcb,
	0x7c, 0x05, 0x76, 0xf8, 0x20, 0x57, 0xc8, 0xe0, 0x2d, 0x71, 0x04, 0x6a,
	0xe0, 0x46, 0xc9, 0x1d, 0x15, 0x1c, 0x34, 0x53, 0xf5, 0x1d, 0x6a, 0x69,
	0x9a, 0x3b, 0x4c, 0xcc, 0x3b, 0x9b, 0x50, 0xfc, 0x3e, 0x89, 0x6d, 0xcd,
	0x66, 0x8a, 0x05, 0x03, 0x4a, 0x7d, 0x87, 0x5e, 0x7e, 0x70, 0x2c, 0x6f,
	0x65, 0x05, 0x71, 0x2e, 0x81, 0xcf, 0x2b, 0xb8, 0xd8, 0x9e, 0xc9, 0xfc,
	0xa9, 0x08, 0x16, 0xed, 0x1b, 0xd1, 0x27, 0x75, 0x0b, 0x7a, 0xc7, 0xde,
	0xe7, 0x70, 0xfd, 0x95, 0xf1, 0xdd, 0xec, 0x45, 0x5f, 0xb7, 0x3a, 0x0c,
	0x98, 0x81, 0x7e, 0x65, 0x63, 0x95, 0x82, 0x4e, 0x28, 0xf4, 0xc8, 0x66,
	0xab, 0xfa, 0xd8, 0x6a, 0xb3, 0x5a, 0xee, 0x8b, 0x1b, 0xca, 0x4d, 0xd6,
	0x14, 0xef, 0x81, 0x57, 0xd1, 0x21, 0xa2, 0x15, 0x2b, 0xc7, 0x2a, 0xa1,
	0xb3, 0x13, 0xa1, 0x97, 0x13, 0x69, 0xf9, 0x8d, 0x65, 0x4e, 0x03, 0xd8,
	0x1a, 0xd6, 0x94, 0x94, 0x4f, 0x12, 0xff, 0x29, 0x7b, 0xc6, 0x9d, 0xf4,
	0xd6, 0x93, 0x1c, 0x89, 0x1d, 0x5b, 0xb0, 0xa8, 0x66, 0x0f, 0xd1, 0x9b,
	0xed, 0x14, 0x47, 0xa7, 0x4c, 0xb0, 0x00, 0x2f, 0xef, 0xaf, 0x74, 0xac,
	0x11, 0x4c, 0xf4, 0x9a, 0xb5, 0x4a, 0xa1, 0xa5, 0x6c, 0x2d, 0x64, 0xdc,
	0x5c, 0x45, 0x7b, 0x11, 0x88, 0x1f, 0x5c, 0xd2, 0xa0, 0x46, 0x2c, 0x81,
	0xa5, 0x1f, 0xde, 0xb7, 0xa8, 0x48, 0xb2, 0x08, 0x76, 0x29, 0x0d, 0xdb,
	0xf9, 0x2c, 0xb9, 0x2e, 0x09, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x42,
	0x30, 0x40, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff,
	0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x0e, 0x06, 0x03, 0x55,
	0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x01, 0x06, 0x30,
	0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0xc9, 0xe5,
	0x35, 0x0a, 0x4c, 0xe7, 0x39, 0x59, 0x51, 0xe2, 0x63, 0xec, 0xbb, 0xa0,
	0xdc, 0x7a, 0xab, 0x52, 0x1e, 0x60, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86,
	0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82, 0x01,
	0x01, 0x00, 0x60, 0xd9, 0xa0, 0xa5, 0x2f, 0xaf, 0xae, 0x25, 0x8f, 0xfe,
	0xf9, 0x0f, 0x71, 0x5e, 0xd2, 0xf8, 0xf5, 0x3f, 0x89, 0x68, 0x0d, 0xf8,
	0x72, 0xad, 0x74, 0xa3, 0xc4, 0xe5, 0xa7, 0x20, 0xea, 0x75, 0x0e, 0xe1,
	0x77, 0xa8, 0xd0, 0xee, 0x09, 0xfd, 0x2d, 0x5a, 0x43, 0x43, 0x19, 0x71,
	0x60, 0xcc, 0x12, 0x6e, 0xda, 0xca, 0x6a, 0x93, 0x85, 0x61, 0xeb, 0x10,
	0xfa, 0x97, 0x14, 0xcd, 0xf1, 0xc9, 0x05, 0xda, 0x7e, 0xb8, 0xb4, 0x25,
	0xe8, 0x6c, 0x5c, 0xdb, 0x5b, 0x87, 0x5a, 0xf0, 0x58, 0x9b, 0x8e, 0x42,
	0x64, 0x70, 0x29, 0xfd, 0x97, 0x1b, 0x10, 0x52, 0x35, 0x64, 0x73, 0xf1,
	0xcc, 0xb3, 0x01, 0xff, 0xea, 0xe7, 0xa7, 0x77, 0x70, 0x96, 0xc8, 0x9f,
	0x23, 0xff, 0xd5, 0x35, 0x33, 0x1c, 0x7b, 0x25, 0x32, 0xd0, 0x2f, 0xc2,
	0x36, 0x20, 0xb2, 0x2a, 0xaa, 0x92, 0x21, 0xe2, 0xba, 0xdf, 0xcf, 0xb0,
	0x69, 0x7f, 0x44, 0xfb, 0x5e, 0x87, 0x89, 0xad, 0x32, 0x94, 0x02, 0x2a,
	0xc1, 0xfc, 0x1b, 0x1c, 0x6c, 0x75, 0x5c, 0x74, 0xfc, 0x9e, 0x66, 0xb9,
	0x66, 0x73, 0x57, 0x9e, 0x06, 0x6e, 0x17, 0xbb, 0x31, 0x7b, 0x6e, 0x17,
	0x33, 0x6d, 0x93, 0xb3, 0xa2, 0x75, 0x9d, 0x26, 0x71, 0x70, 0x11, 0x58,
	0x39, 0x73, 0xa1, 0x0a, 0x35, 0x7b, 0xde, 0x1a, 0x06, 0x05, 0xea, 0x6a,
	0x57, 0x78, 0x44, 0x5c, 0xed, 0xd2, 0x84, 0x7a, 0xe3, 0xef, 0x60, 0x2f,
	0x21, 0xb1, 0x07, 0xc2, 0x40, 0xca, 0xee, 0xa9, 0x4e, 0xf1, 0x18, 0xbd,
	0x45, 0xe3, 0xc4, 0x29, 0xcf, 0x68, 0x70, 0xe7, 0x94, 0x66, 0xa7, 0xf2,
	0xf1, 0xf5, 0xb8, 0x4a, 0xfd, 0xc5, 0x31, 0x7c, 0x8f, 0x16, 0x6d, 0xe7,
	0x94, 0x1a, 0xb3, 0x4f, 0x65, 0x8d, 0x67, 0x56, 0x7f, 0xf5, 0x83, 0x7d,
	0x5d, 0x16, 0x12, 0x13, 0x89, 0xd1,
};

static const uint8_t ip_san_server_der[] = {
	0x30, 0x82, 0x03, 0x23, 0x30, 0x82, 0x02, 0x0b, 0xa0, 0x03, 0x02, 0x01,
	0x02, 0x02, 0x14, 0x59, 0x21, 0x1b, 0x5b, 0x19, 0x43, 0xf6, 0x36, 0x9f,
	0x8c, 0x5b, 0x6e, 0x0e, 0x59, 0xed, 0x92, 0xea, 0xd1, 0x9a, 0xbd, 0x30,
	0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
	0x05, 0x00, 0x30, 0x2a, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04,
	0x0a, 0x0c, 0x06, 0x5a, 0x65, 0x70, 0x68, 0x79, 0x72, 0x31, 0x17, 0x30,
	0x15, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0e, 0x49, 0x50, 0x20, 0x53,
	0x41, 0x4e, 0x20, 0x54, 0x65, 0x73, 0x74, 0x20, 0x43, 0x41, 0x30, 0x20,
	0x17, 0x0d, 0x32, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30,
	0x30, 0x30, 0x5a, 0x18, 0x0f, 0x32, 0x31, 0x31, 0x39, 0x31, 0x32, 0x33,
	0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x30, 0x27, 0x31, 0x0f,
	0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x06, 0x5a, 0x65, 0x70,
	0x68, 0x79, 0x72, 0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x03,
	0x0c, 0x0b, 0x69, 0x70, 0x2d, 0x73, 0x61, 0x6e, 0x2d, 0x74, 0x65, 0x73,
	0x74, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48,
	0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f,
	0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xed, 0xe2,
	0xd8, 0x35, 0xaf, 0xf4, 0x6f, 0x91, 0x80, 0x25, 0x11, 0xb8, 0x31, 0x4d,
	0x60, 0x09, 0xda, 0xa6, 0xf8, 0xf3, 0x4e, 0x67, 0xb0, 0xc3, 0x73, 0x8d,
	0xc7, 0x97, 0x17, 0x33, 0xa1, 0xda, 0x3a, 0x6b, 0x4b, 0x59, 0x02, 0xae,
	0x0f, 0xbb, 0x86, 0x22, 0x97, 0xf9, 0xe9, 0x43, 0xf0, 0x54, 0xdf, 0xdb,
	0xcc, 0x8b, 0xa2, 0x7f, 0x5a, 0x7f, 0x20, 0xc0, 0xd9, 0xe8, 0x52, 0x3e,
	0x0d, 0x72, 0x8a, 0x3c, 0x6b, 0xb8, 0x32, 0x5d, 0x0f, 0x52, 0x81, 0xf7,
	0xdd, 0xdf, 0xd9, 0xe5, 0x72, 0x5e, 0x4c, 0x69, 0x48, 0x5e, 0x27, 0x12,
	0xed, 0x53, 0x09, 0x20, 0x92, 0xef, 0xe0, 0xa2, 0x62, 0x1d, 0x81, 0x7a,
	0x46, 0xce, 0x7d, 0x46, 0x7e, 0x19, 0xe2, 0x0f, 0x71, 0x77, 0xf7, 0xe3,
	0x92, 0x55, 0x92, 0x1e, 0x47, 0x6a, 0x6a, 0xab, 0x2b, 0xb7, 0xc5, 0x56,
	0x59, 0x17, 0x8f, 0xc9, 0x38, 0xea, 0x26, 0xcd, 0x9d, 0x69, 0xaa, 0x8f,
	0x36, 0x16, 0x84, 0x04, 0x37, 0xf4, 0x54, 0x3a, 0x4e, 0x12, 0x95, 0x07,
	0x2c, 0x66, 0x69, 0xca, 0x47, 0xa8, 0xff, 0x1d, 0x66, 0x7b, 0xa0, 0x20,
	0xbf, 0xee, 0x1f, 0x10, 0xd6, 0xf3, 0xeb, 0xfe, 0x16, 0x15, 0xef, 0x33,
	0x04, 0x84, 0xa4, 0xdd, 0x23, 0xb8, 0xd0, 0x3a, 0x35, 0x9c, 0xa7, 0x8c,
	0x2a, 0x26, 0xb9, 0x02, 0x52, 0x99, 0xb3, 0x76, 0xff, 0x17, 0x1d, 0xbf,
	0xf8, 0x04, 0xe8, 0xbe, 0xab, 0x6c, 0xcd, 0xd5, 0xfb, 0x90, 0x3d, 0x20,
	0x94, 0x46, 0x85, 0x7d, 0x0c, 0x66, 0x56, 0x7f, 0xaa, 0xf2, 0x56, 0x7b,
	0x1a, 0xf9, 0x0d, 0x57, 0x8a, 0x83, 0x7d, 0xa3, 0xbd, 0x28, 0xea, 0xa3,
	0x50, 0x6e, 0xd8, 0xb2, 0xc1, 0xbc, 0xc8, 0xd0, 0xb9, 0x31, 0x41, 0x01,
	0x60, 0x69, 0x28, 0xf0, 0xa1, 0xb1, 0x69, 0x37, 0xf3, 0x2f, 0xe2, 0xd4,
	0xb4, 0xe5, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x42, 0x30, 0x40, 0x30,
	0x0f, 0x06, 0x03, 0x55, 0x1d, 0x11, 0x04, 0x08, 0x30, 0x06, 0x87, 0x04,
	0x7f, 0x00, 0x00, 0x01, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01,
	0x01, 0xff, 0x04, 0x02, 0x30, 0x00, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d,
	0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0xc9, 0xe5, 0x35, 0x0a, 0x4c,
	0xe7, 0x39, 0x59, 0x51, 0xe2, 0x63, 0xec, 0xbb, 0xa0, 0xdc, 0x7a, 0xab,
	0x52, 0x1e, 0x60, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
	0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x49,
	0x2e, 0xb7, 0xb0, 0xec, 0xd4, 0x4f, 0x8d, 0xd7, 0x1b, 0x56, 0xfd, 0x21,
	0x40, 0x25, 0x8b, 0x15, 0x01, 0xfb, 0xca, 0x97, 0x1a, 0x70, 0x0c, 0x07,
	0x66, 0xfe, 0x50, 0xfa, 0x5f, 0x13, 0x05, 0xe4, 0xa5, 0x18, 0x71, 0x90,
	0x3d, 0x2f, 0x9e, 0xd1, 0xe0, 0xcf, 0x75, 0x67, 0xe4, 0x85, 0x06, 0x3b,
	0xae, 0xc1, 0x39, 0xd0, 0x90, 0x8b, 0x48, 0x17, 0x94, 0xa3, 0x1a, 0xa4,
	0xff, 0xfb, 0x2b, 0xfa, 0x2d, 0x59, 0x34, 0x78, 0xf9, 0x3d, 0xde, 0xe9,
	0x58, 0xd0, 0xec, 0x62, 0x84, 0x2d, 0xe2, 0x49, 0xc3, 0x9f, 0x15, 0xd0,
	0xe7, 0x3d, 0xdf, 0x0c, 0x82, 0xf5, 0xf7, 0x49, 0x25, 0x92, 0xb2, 0xd2,
	0x20, 0xf4, 0x23, 0x37, 0xed, 0x25, 0x52, 0x5c, 0x6c, 0x39, 0xf8, 0xca,
	0x9a, 0xea, 0x21, 0xdd, 0x4b, 0x49, 0x46, 0xf4, 0x3f, 0x87, 0x80, 0xae,
	0x35, 0xcb, 0x82, 0xec, 0x2a, 0x40, 0x1b, 0x60, 0x0d, 0xd6, 0x9e, 0x3b,
	0x2d, 0x50, 0x6d, 0x12, 0x93, 0xa3, 0x7d, 0xdc, 0x07, 0x42, 0xe4, 0x90,
	0xeb, 0xaa, 0x50, 0x64, 0x07, 0x31, 0x16, 0x8a, 0xe3, 0xfa, 0xe5, 0x79,
	0x60, 0xdf, 0xbd, 0xe0, 0x3f, 0xc7, 0x03, 0xda, 0xaf, 0x84, 0xa3, 0x8d,
	0x68, 0xff, 0x79, 0x18, 0x1d, 0xeb, 0xe1, 0xe0, 0x7e, 0x0f, 0x4b, 0xdd,
	0x1e, 0xf1, 0x22, 0xd7, 0x83, 0xb3, 0x09, 0x93, 0x6b, 0x44, 0x4c, 0x06,
	0x68, 0xb9, 0x53, 0x2a, 0xd6, 0x64, 0x0d, 0x2d, 0x06, 0x91, 0x69, 0x74,
	0x65, 0x34, 0xb7, 0xa9, 0xea, 0xaa, 0x59, 0x27, 0xde, 0x3e, 0xa1, 0x57,
	0x16, 0xd1, 0x5c, 0xdc, 0x7e, 0xc7, 0x1e, 0xc1, 0x1c, 0xee, 0x45, 0x88,
	0xed, 0x99, 0xd0, 0xc1, 0xe5, 0x9b, 0xbb, 0xb0, 0xdd, 0x08, 0xaa, 0xf9,
	0x99, 0xca, 0x8d, 0x05, 0x99, 0xa5, 0x36, 0x66, 0x5d, 0xc3, 0x20, 0x59,
	0xf5, 0xb2, 0xea,
};

static const uint8_t ip_san_server_key_der[] = {
	0x30, 0x82, 0x04, 0xbc, 0x02, 0x01, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x2a,
	0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x04, 0x82,
	0x04, 0xa6, 0x30, 0x82, 0x04, 0xa2, 0x02, 0x01, 0x00, 0x02, 0x82, 0x01,
	0x01, 0x00, 0xed, 0xe2, 0xd8, 0x35, 0xaf, 0xf4, 0x6f, 0x91, 0x80, 0x25,
	0x11, 0xb8, 0x31, 0x4d, 0x60, 0x09, 0xda, 0xa6, 0xf8, 0xf3, 0x4e, 0x67,
	0xb0, 0xc3, 0x73, 0x8d, 0xc7, 0x97, 0x17, 0x33, 0xa1, 0xda, 0x3a, 0x6b,
	0x4b, 0x59, 0x02, 0xae, 0x0f, 0xbb, 0x86, 0x22, 0x97, 0xf9, 0xe9, 0x43,
	0xf0, 0x54, 0xdf, 0xdb, 0xcc, 0x8b, 0xa2, 0x7f, 0x5a, 0x7f, 0x20, 0xc0,
	0xd9, 0xe8, 0x52, 0x3e, 0x0d, 0x72, 0x8a, 0x3c, 0x6b, 0xb8, 0x32, 0x5d,
	0x0f, 0x52, 0x81, 0xf7, 0xdd, 0xdf, 0xd9, 0xe5, 0x72, 0x5e, 0x4c, 0x69,
	0x48, 0x5e, 0x27, 0x12, 0xed, 0x53, 0x09, 0x20, 0x92, 0xef, 0xe0, 0xa2,
	0x62, 0x1d, 0x81, 0x7a, 0x46, 0xce, 0x7d, 0x46, 0x7e, 0x19, 0xe2, 0x0f,
	0x71, 0x77, 0xf7, 0xe3, 0x92, 0x55, 0x92, 0x1e, 0x47, 0x6a, 0x6a, 0xab,
	0x2b, 0xb7, 0xc5, 0x56, 0x59, 0x17, 0x8f, 0xc9, 0x38, 0xea, 0x26, 0xcd,
	0x9d, 0x69, 0xaa, 0x8f, 0x36, 0x16, 0x84, 0x04, 0x37, 0xf4, 0x54, 0x3a,
	0x4e, 0x12, 0x95, 0x07, 0x2c, 0x66, 0x69, 0xca, 0x47, 0xa8, 0xff, 0x1d,
	0x66, 0x7b, 0xa0, 0x20, 0xbf, 0xee, 0x1f, 0x10, 0xd6, 0xf3, 0xeb, 0xfe,
	0x16, 0x15, 0xef, 0x33, 0x04, 0x84, 0xa4, 0xdd, 0x23, 0xb8, 0xd0, 0x3a,
	0x35, 0x9c, 0xa7, 0x8c, 0x2a, 0x26, 0xb9, 0x02, 0x52, 0x99, 0xb3, 0x76,
	0xff, 0x17, 0x1d, 0xbf, 0xf8, 0x04, 0xe8, 0xbe, 0xab, 0x6c, 0xcd, 0xd5,
	0xfb, 0x90, 0x3d, 0x20, 0x94, 0x46, 0x85, 0x7d, 0x0c, 0x66, 0x56, 0x7f,
	0xaa, 0xf2, 0x56, 0x7b, 0x1a, 0xf9, 0x0d, 0x57, 0x8a, 0x83, 0x7d, 0xa3,
	0xbd, 0x28, 0xea, 0xa3, 0x50, 0x6e, 0xd8, 0xb2, 0xc1, 0xbc, 0xc8, 0xd0,
	0xb9, 0x31, 0x41, 0x01, 0x60, 0x69, 0x28, 0xf0, 0xa1, 0xb1, 0x69, 0x37,
	0xf3, 0x2f, 0xe2, 0xd4, 0xb4, 0xe5, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02,
	0x82, 0x01, 0x00, 0x27, 0x44, 0x3d, 0x0a, 0x80, 0xf7, 0x59, 0x07, 0xe1,
	0x93, 0xa7, 0x87, 0x9f, 0x17, 0xc0, 0x65, 0x10, 0x03, 0x0f, 0x6f, 0xe0,
	0xa9, 0x76, 0xab, 0x8f, 0x37, 0x95, 0x7d, 0x08, 0x01, 0x92, 0xa8, 0xaf,
	0x8b, 0x9b, 0x68, 0x8a, 0x16, 0x8a, 0x41, 0x45, 0x79, 0xbb, 0x5a, 0xaf,
	0x59, 0x9d, 0x62, 0x47, 0xd6, 0x03, 0xbe, 0xfe, 0xd2, 0x85, 0x1b, 0xc6,
	0x9f, 0xc9, 0x63, 0x08, 0x59, 0xa1, 0x7a, 0xf3, 0xd2, 0x2d, 0x0e, 0x69,
	0x68, 0x79, 0x5e, 0xd6, 0x00, 0xeb, 0x4e, 0x5d, 0x2c, 0xd0, 0x6d, 0x3c,
	0x06, 0xb0, 0x41, 0x33, 0xb3, 0x9e, 0x44, 0xb3, 0xbf, 0xd2, 0x91, 0x51,
	0xa3, 0xec, 0x37, 0x26, 0x48, 0x0a, 0x9d, 0x0b, 0x5f, 0xbc, 0x9b, 0xf0,
	0x22, 0x90, 0x1e, 0x77, 0x3c, 0x1e, 0x21, 0x0d, 0x83, 0xfd, 0xa7, 0x80,
	0x0b, 0xae, 0x25, 0x36, 0x52, 0x88, 0xff, 0xe8, 0x7b, 0x94, 0xc4, 0x51,
	0xab, 0x6f, 0xc1, 0x57, 0xb6, 0x55, 0x41, 0x76, 0x5d, 0xb5, 0xe9, 0xbc,
	0xe9, 0x74, 0x0a, 0xee, 0xe9, 0x55, 0x96, 0xb4, 0x79, 0x61, 0xf8, 0xd6,
	0x5b, 0xf2, 0x0e, 0xd8, 0x22, 0xaf, 0x73, 0x27, 0x94, 0x4a, 0x10, 0x7a,
	0xfa, 0x0c, 0x99, 0x53, 0x0b, 0x40, 0x40, 0x0a, 0x10, 0x52, 0x5a, 0xac,
	0x6d, 0x9f, 0xc2, 0x95, 0x6c, 0x1f, 0x67, 0x67, 0xd3, 0x6a, 0x30, 0x96,
	0x3f, 0xcd, 0x27, 0x60, 0x5c, 0x5e, 0x4f, 0x06, 0x6f, 0x3f, 0xca, 0x56,
	0x24, 0x01, 0xfd, 0xad, 0xd0, 0xa3, 0x3e, 0xb5, 0xb1, 0x1d, 0x42, 0x17,
	0x9c, 0x49, 0xf2, 0x8c, 0x75, 0x51, 0x9c, 0xff, 0x45, 0xde, 0x24, 0x1e,
	0x04, 0xb3, 0x48, 0x60, 0xc8, 0x4b, 0xdf, 0x0f, 0x14, 0xcf, 0xef, 0x7d,
	0xa1, 0xd4, 0xd5, 0x8e, 0x25, 0xea, 0xfe, 0x3d, 0xdc, 0x37, 0x74, 0xb7,
	0x1c, 0x90, 0x6d, 0x43, 0xf5, 0x73, 0x87, 0x02, 0x81, 0x81, 0x00, 0xfa,
	0x4f, 0x2c, 0xe8, 0x49, 0x4e, 0x8f, 0xcf, 0x5c, 0x4d, 0x48, 0xda, 0x7d,
	0x84, 0xdc, 0x36, 0x19, 0x2f, 0xc8, 0x1d, 0x7f, 0xde, 0xda, 0xa9, 0xf6,
	0xa7, 0x07, 0xc1, 0x74, 0x97, 0x17, 0x1a, 0xc9, 0x19, 0x9f, 0x8a, 0xc4,
	0xfe, 0x2a, 0x27, 0xef, 0xce, 0xb1, 0xc4, 0x76, 0x30, 0x5c, 0xab, 0x19,
	0x3a, 0xd1, 0x52, 0x08, 0xab, 0x81, 0x84, 0x43, 0x22, 0x24, 0x04, 0x12,
	0x2c, 0x64, 0x90, 0x4d, 0x2d, 0x59, 0x95, 0x5c, 0x98, 0x23, 0x3d, 0x11,
	0x05, 0xbd, 0x61, 0xec, 0x6c, 0xd2, 0x07, 0xae, 0x99, 0x55, 0x8f, 0x23,
	0xe8, 0xb5, 0xa8, 0xa2, 0xf2, 0x34, 0x34, 0x0d, 0x14, 0x4c, 0x78, 0x25,
	0x3a, 0xcd, 0xd0, 0x13, 0x90, 0x3b, 0xb1, 0x53, 0xc9, 0x35, 0xe9, 0xfe,
	0x6e, 0x0c, 0xd7, 0x44, 0x5c, 0x18, 0x82, 0x4f, 0x1b, 0x71, 0x4a, 0xd5,
	0x89, 0x4d, 0x99, 0xb4, 0xe0, 0x20, 0x83, 0x02, 0x81, 0x81, 0x00, 0xf3,
	0x4b, 0x5d, 0x76, 0xeb, 0xbf, 0xe3, 0x18, 0xd1, 0x21, 0x27, 0x69, 0x81,
	0x80, 0xf2, 0x24, 0x5a, 0xb4, 0x5e, 0x3a, 0xcc, 0xdd, 0x83, 0x22, 0x1a,
	0xa5, 0x59, 0xa7, 0xf8, 0xa9, 0x7a, 0x7e, 0x75, 0x3e, 0x67, 0x75, 0x97,
	0x50, 0xb4, 0xf7, 0xb6, 0x67, 0x89, 0xe2, 0xe9, 0x1e, 0xb6, 0x7d, 0x0a,
	0xd6, 0x9a, 0xf2, 0xaa, 0xad, 0x69, 0xc3, 0xd1, 0x75, 0x47, 0xd4, 0xa6,
	0x80, 0x12, 0x7b, 0x7b, 0xa4, 0x79, 0x49, 0xea, 0x3a, 0x08, 0xc1, 0x1e,
	0x6f, 0x08, 0x8b, 0x68, 0x99, 0x93, 0x8e, 0x08, 0xda, 0x88, 0x95, 0x4d,
	0x78, 0xb8, 0xa5, 0xae, 0x18, 0x54, 0xc0, 0x55, 0x7a, 0x6e, 0x28, 0xa7,
	0x77, 0x45, 0xc4, 0xb5, 0xb9, 0x16, 0xb4, 0x36, 0x54, 0x3c, 0xdd, 0xf9,
	0x75, 0x66, 0x91, 0x34, 0x6c, 0x7d, 0x84, 0xa1, 0x61, 0xbc, 0xd6, 0x0a,
	0x25, 0x09, 0x3e, 0x0f, 0x20, 0x88, 0x77, 0x02, 0x81, 0x80, 0x7f, 0x74,
	0xaf, 0x7e, 0x3c, 0x4d, 0xb7, 0xa6, 0xb3, 0xee, 0x5a, 0x89, 0x7e, 0xde,
	0x97, 0x2f, 0x28, 0xd6, 0x0e, 0xc5, 0x0e, 0xa6, 0x90, 0x9b, 0x79, 0x10,
	0x06, 0x3f, 0xf8, 0xb9, 0x32, 0xb7, 0x9d, 0xec, 0xe1, 0x33, 0x4d, 0x29,
	0xca, 0x97, 0x79, 0x61, 0xbb, 0x5d, 0x39, 0x7d, 0x58, 0xc2, 0x7a, 0xdf,
	0x5b, 0x54, 0xb5, 0x3b, 0x77, 0x80, 0xbc, 0x9a, 0x76, 0xd2, 0x67, 0xda,
	0x98, 0xfe, 0x6d, 0x7e, 0x09, 0x1e, 0xa7, 0xfe, 0x83, 0xfb, 0x05, 0x5e,
	0xf1, 0xd7, 0x1a, 0x07, 0x33, 0x4f, 0x5c, 0x15, 0x91, 0xde, 0x88, 0x3f,
	0x67, 0xb8, 0xcd, 0xf8, 0x1c, 0xa2, 0xe0, 0x82, 0x14, 0x8a, 0x1d, 0x12,
	0xfb, 0x57, 0xd7, 0x8e, 0x5b, 0x06, 0xe9, 0x8e, 0x0c, 0x58, 0xf1, 0x08,
	0x62, 0x9b, 0x7e, 0xa0, 0x92, 0x8e, 0x4f, 0xef, 0xbe, 0x59, 0x87, 0xb0,
	0x19, 0x86, 0x89, 0xf6, 0x92, 0x37, 0x02, 0x81, 0x80, 0x33, 0x7c, 0x76,
	0x7a, 0x0d, 0x27, 0xdd, 0x7a, 0x49, 0xff, 0x77, 0x24, 0xb7, 0xb8, 0x3f,
	0x05, 0xfc, 0x80, 0x01, 0x14, 0xf6, 0x77, 0xc6, 0x21, 0x78, 0x7c, 0x17,
	0x7e, 0x19, 0x7c, 0x5c, 0x24, 0xd8, 0xd0, 0xec, 0xfa, 0x10, 0x9c, 0x8e,
	0xbf, 0x81, 0x45, 0x66, 0x03, 0xb4, 0x0b, 0xc0, 0xd8, 0xb3, 0x6b, 0x78,
	0xfc, 0xf3, 0xab, 0xa1, 0x1f, 0x44, 0x7b, 0x4a, 0x49, 0x31, 0x37, 0x17,
	0x32, 0x34, 0x97, 0x38, 0xe7, 0xb0, 0x7e, 0xb9, 0x8d, 0x8c, 0xd0, 0x38,
	0x81, 0xb0, 0x10, 0x18, 0x0e, 0xcd, 0xc6, 0xd9, 0x72, 0xa7, 0x23, 0x6e,
	0x07, 0xf9, 0xd0, 0xc2, 0x56, 0xb5, 0x80, 0x24, 0x41, 0xcc, 0x36, 0xcc,
	0x77, 0xf5, 0x71, 0x06, 0xe1, 0xfa, 0x41, 0x57, 0x64, 0x2e, 0x3f, 0x6f,
	0x06, 0x39, 0x8e, 0xdf, 0xfd, 0x2a, 0x5d, 0xd1, 0xa5, 0x86, 0x1e, 0x12,
	0x57, 0xa4, 0xc1, 0xe0, 0xbf, 0x02, 0x81, 0x80, 0x66, 0xd0, 0x07, 0x09,
	0x52, 0x50, 0x3d, 0x98, 0x08, 0xd9, 0x1b, 0x5c, 0xb0, 0xb4, 0x6f, 0xcd,
	0x14, 0x15, 0x33, 0x2a, 0x66, 0x91, 0x49, 0xe9, 0xd9, 0x6a, 0xdb, 0x3a,
	0x74, 0xb3, 0x22, 0xbc, 0x98, 0xbd, 0xa9, 0x14, 0x5f, 0x56, 0x60, 0x88,
	0xdc, 0xa8, 0xf6, 0x1d, 0x3d, 0xa7, 0xc7, 0x7f, 0x84, 0xbb, 0xff, 0x96,
	0x41, 0x4b, 0x16, 0x12, 0x72, 0xd7, 0x30, 0x5a, 0x79, 0x96, 0x19, 0x86,
	0x74, 0x87, 0x3b, 0x5d, 0x22, 0x42, 0x1d, 0xc9, 0xe4, 0x66, 0x88, 0xd8,
	0x3f, 0xb9, 0x81, 0xd3, 0xb1, 0xee, 0xd3, 0xb2, 0x52, 0x8f, 0xb0, 0x63,
	0x69, 0x8b, 0x18, 0x88, 0xf3, 0xee, 0x4e, 0xb3, 0x37, 0x1b, 0x6d, 0xa4,
	0xf4, 0xd3, 0x7f, 0x16, 0x98, 0x6d, 0xd9, 0xf7, 0xd1, 0xd0, 0x7a, 0x92,
	0x9c, 0x18, 0xdc, 0xb2, 0x18, 0xe0, 0xd6, 0xe5, 0x56, 0x73, 0xcc, 0x99,
	0xf7, 0xaa, 0x49, 0xe6,
};

/* TLS_HOSTNAME holding an IP address matches an iPAddress SAN, as on mbedTLS */
ZTEST(net_socket_tls_api_extension, test_tls_hostname_ip_san)
{
	static const sec_tag_t server_tags[] = { IP_SAN_SERVER_TAG };
	static const sec_tag_t client_tags[] = { IP_SAN_CA_TAG };
	k_tid_t server_thread_id;
	struct sockaddr_in sa = {
		.sin_family = AF_INET,
		.sin_port = htons(PORT),
	};
	uint8_t rx_buf[16];
	int server_fd, client_fd, r;

	zassert_ok(tls_credential_add(IP_SAN_CA_TAG, TLS_CREDENTIAL_CA_CERTIFICATE,
				      ip_san_ca_der, sizeof(ip_san_ca_der)));
	zassert_ok(tls_credential_add(IP_SAN_SERVER_TAG, TLS_CREDENTIAL_PUBLIC_CERTIFICATE,
				      ip_san_server_der, sizeof(ip_san_server_der)));
	zassert_ok(tls_credential_add(IP_SAN_SERVER_TAG, TLS_CREDENTIAL_PRIVATE_KEY,
				      ip_san_server_key_der, sizeof(ip_san_server_key_der)));

	server_fd = test_configure_server_ex(&server_thread_id, TLS_PEER_VERIFY_NONE,
					     true, false, server_tags, sizeof(server_tags),
					     false, server_thread_fn);

	client_fd = zsock_socket(AF_INET, SOCK_STREAM, IPPROTO_TLS_1_2);
	zassert_not_equal(client_fd, -1, "failed to create client socket (%d)", errno);
	r = zsock_setsockopt(client_fd, SOL_TLS, TLS_SEC_TAG_LIST, client_tags,
			     sizeof(client_tags));
	zassert_ok(r, "failed to set TLS_SEC_TAG_LIST (%d)", errno);
	r = zsock_setsockopt(client_fd, SOL_TLS, TLS_HOSTNAME, MY_IPV4_ADDR,
			     sizeof(MY_IPV4_ADDR));
	zassert_ok(r, "failed to set TLS_HOSTNAME (%d)", errno);
	zassert_equal(zsock_inet_pton(AF_INET, MY_IPV4_ADDR, &sa.sin_addr), 1);

	r = zsock_connect(client_fd, (struct sockaddr *)&sa, sizeof(sa));
	zassert_not_equal(r, -1, "failed to connect (%d)", errno);
	r = zsock_send(client_fd, SECRET, SECRET_SIZE, 0);
	zassert_equal(r, SECRET_SIZE, "send() failed (%d)", errno);
	r = zsock_recv(client_fd, rx_buf, sizeof(rx_buf), 0);
	zassert_equal(r, SECRET_SIZE, "recv() failed (%d)", errno);

	test_shutdown(client_fd, server_fd, server_thread_id);

	(void)tls_credential_delete(IP_SAN_CA_TAG, TLS_CREDENTIAL_CA_CERTIFICATE);
	(void)tls_credential_delete(IP_SAN_SERVER_TAG, TLS_CREDENTIAL_PUBLIC_CERTIFICATE);
	(void)tls_credential_delete(IP_SAN_SERVER_TAG, TLS_CREDENTIAL_PRIVATE_KEY);
}

#if defined(CONFIG_WOLFSSL) && defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
/* Runs the handshake of each DTLS server until its first record or its timeout */
static void server_thread_dtls_recv_each_fn(void *arg0, void *arg1, void *arg2)
{
	char buf[16];

	ARG_UNUSED(arg2);

	k_sem_give(&server_sem);
	(void)zsock_recv(POINTER_TO_INT(arg0), buf, sizeof(buf), 0);
	(void)zsock_recv(POINTER_TO_INT(arg1), buf, sizeof(buf), 0);
}

static int dtls_server_socket_tags(uint16_t port, const sec_tag_t *server_tags,
				   size_t server_tags_size)
{
	const int role = TLS_DTLS_ROLE_SERVER;
	const struct timeval timeo = { .tv_sec = 1 };
	struct sockaddr_in sa = {
		.sin_family = AF_INET,
		.sin_port = htons(port),
	};
	int fd;

	fd = zsock_socket(AF_INET, SOCK_DGRAM, IPPROTO_DTLS_1_2);
	zassert_not_equal(fd, -1, "failed to create server socket (%d)", errno);
	zassert_ok(zsock_setsockopt(fd, SOL_TLS, TLS_DTLS_ROLE, &role, sizeof(role)));
	zassert_ok(zsock_setsockopt(fd, SOL_TLS, TLS_SEC_TAG_LIST, server_tags,
				    server_tags_size));
	zassert_ok(zsock_setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeo, sizeof(timeo)));
	zassert_equal(zsock_inet_pton(AF_INET, MY_IPV4_ADDR, &sa.sin_addr), 1);
	zassert_ok(zsock_bind(fd, (struct sockaddr *)&sa, sizeof(sa)),
		   "failed to bind (%d)", errno);

	return fd;
}

static int dtls_server_socket(uint16_t port)
{
	static const sec_tag_t server_tags[] = { SERVER_CERTIFICATE_TAG };

	return dtls_server_socket_tags(port, server_tags, sizeof(server_tags));
}

/* Connects a DTLS client that trusts the CA on ca_tag and expects hostname */
static int dtls_client_connect(int *fd, sec_tag_t ca_tag, const char *hostname)
{
	const sec_tag_t tags[] = { ca_tag };
	struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(PORT) };
	const int timeout_max = 1000;

	*fd = zsock_socket(AF_INET, SOCK_DGRAM, IPPROTO_DTLS_1_2);
	zassert_not_equal(*fd, -1, "failed to create client socket (%d)", errno);
	zassert_ok(zsock_setsockopt(*fd, SOL_TLS, TLS_HOSTNAME, hostname, strlen(hostname) + 1));
	zassert_ok(zsock_setsockopt(*fd, SOL_TLS, TLS_SEC_TAG_LIST, tags, sizeof(tags)));
	zassert_ok(zsock_setsockopt(*fd, SOL_TLS, TLS_DTLS_HANDSHAKE_TIMEOUT_MAX, &timeout_max,
				    sizeof(timeout_max)));
	zassert_equal(zsock_inet_pton(AF_INET, MY_IPV4_ADDR, &sa.sin_addr), 1);

	return zsock_connect(*fd, (struct sockaddr *)&sa, sizeof(sa));
}

static bool dtls_later_peer_served;

/* Receives until a later peer's record arrives, failed handshakes in between included */
static void dtls_serve_later_peer(int server_fd)
{
	int64_t end = k_uptime_get() + 10 * MSEC_PER_SEC;
	char buf[16];

	while (!dtls_later_peer_served && k_uptime_get() < end) {
		dtls_later_peer_served = zsock_recv(server_fd, buf, sizeof(buf), 0) == SECRET_SIZE;
		if (!dtls_later_peer_served) {
			/* recv() fails at once while the server cannot set up */
			k_msleep(50);
		}
	}
}
#endif /* CONFIG_WOLFSSL && CONFIG_NET_SOCKETS_ENABLE_DTLS */

/* wolfSSL-only: a DTLS client that changes TLS_SEC_TAG_LIST stops trusting the old CA */
ZTEST(net_socket_tls_api_extension, test_dtls_client_sec_tag_change)
{
#if !defined(CONFIG_WOLFSSL) || !defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
	ztest_test_skip();
#else
	static const sec_tag_t client_tags[][1] = { { CA_CERTIFICATE_TAG }, { IP_SAN_CA_TAG } };
	int server_fd[ARRAY_SIZE(client_tags)];
	struct sockaddr_in sa = { .sin_family = AF_INET };
	int client_fd, r;

	/* Added first, so that only the sec tag change can rebuild the client's CTX */
	zassert_ok(tls_credential_add(IP_SAN_CA_TAG, TLS_CREDENTIAL_CA_CERTIFICATE,
				      ip_san_ca_der, sizeof(ip_san_ca_der)));
	k_sem_init(&server_sem, 0, 1);

	for (int i = 0; i < ARRAY_SIZE(server_fd); i++) {
		server_fd[i] = dtls_server_socket(PORT + i);
	}

	k_thread_create(&server_thread, server_stack, STACK_SIZE,
			server_thread_dtls_recv_each_fn, INT_TO_POINTER(server_fd[0]),
			INT_TO_POINTER(server_fd[1]), NULL, K_PRIO_PREEMPT(8), 0, K_NO_WAIT);
	zassert_ok(k_sem_take(&server_sem, K_MSEC(TIMEOUT)));

	client_fd = zsock_socket(AF_INET, SOCK_DGRAM, IPPROTO_DTLS_1_2);
	zassert_not_equal(client_fd, -1, "failed to create client socket (%d)", errno);
	zassert_ok(zsock_setsockopt(client_fd, SOL_TLS, TLS_HOSTNAME, "localhost",
				    sizeof("localhost")));
	zassert_equal(zsock_inet_pton(AF_INET, MY_IPV4_ADDR, &sa.sin_addr), 1);

	for (int i = 0; i < ARRAY_SIZE(client_tags); i++) {
		zassert_ok(zsock_setsockopt(client_fd, SOL_TLS, TLS_SEC_TAG_LIST,
					    client_tags[i], sizeof(client_tags[i])));
		sa.sin_port = htons(PORT + i);

		r = zsock_connect(client_fd, (struct sockaddr *)&sa, sizeof(sa));
		if (i == 0) {
			zassert_ok(r, "failed to connect (%d)", errno);
			r = zsock_send(client_fd, SECRET, SECRET_SIZE, 0);
			zassert_equal(r, SECRET_SIZE, "send() failed (%d)", errno);
		} else {
			zassert_equal(r, -1, "the old sec tag list's CA verified the server");
		}
	}

	zassert_ok(k_thread_join(&server_thread, K_FOREVER));
	zassert_ok(zsock_close(client_fd), "close() failed (%d)", errno);
	for (int i = 0; i < ARRAY_SIZE(server_fd); i++) {
		zassert_ok(zsock_close(server_fd[i]), "close() failed (%d)", errno);
	}
#endif
}

#if defined(CONFIG_WOLFSSL) && defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
/* Serves the first peer and switches to the IP SAN certificate before that peer leaves */
static void server_thread_dtls_tag_change_fn(void *arg0, void *arg1, void *arg2)
{
	static const sec_tag_t new_tags[] = { IP_SAN_SERVER_TAG };
	const int server_fd = POINTER_TO_INT(arg0);
	char buf[16];
	int r;

	ARG_UNUSED(arg1);
	ARG_UNUSED(arg2);

	k_sem_give(&server_sem);
	r = zsock_recv(server_fd, buf, sizeof(buf), 0);
	zassert_equal(r, SECRET_SIZE, "recv() failed (%d)", errno);

	zassert_ok(zsock_setsockopt(server_fd, SOL_TLS, TLS_SEC_TAG_LIST, new_tags,
				    sizeof(new_tags)));
	k_sem_give(&server_sem);
	dtls_serve_later_peer(server_fd);
}
#endif /* CONFIG_WOLFSSL && CONFIG_NET_SOCKETS_ENABLE_DTLS */

/* wolfSSL-only: a DTLS server that changes TLS_SEC_TAG_LIST presents the new certificate */
ZTEST(net_socket_tls_api_extension, test_dtls_server_sec_tag_change)
{
#if !defined(CONFIG_WOLFSSL) || !defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
	ztest_test_skip();
#else
	int client_fd, server_fd, r;

	/* Added first, so that only the sec tag change can rebuild the server's CTX */
	zassert_ok(tls_credential_add(IP_SAN_CA_TAG, TLS_CREDENTIAL_CA_CERTIFICATE,
				      ip_san_ca_der, sizeof(ip_san_ca_der)));
	zassert_ok(tls_credential_add(IP_SAN_SERVER_TAG, TLS_CREDENTIAL_PUBLIC_CERTIFICATE,
				      ip_san_server_der, sizeof(ip_san_server_der)));
	zassert_ok(tls_credential_add(IP_SAN_SERVER_TAG, TLS_CREDENTIAL_PRIVATE_KEY,
				      ip_san_server_key_der, sizeof(ip_san_server_key_der)));
	k_sem_init(&server_sem, 0, 1);
	dtls_later_peer_served = false;

	server_fd = dtls_server_socket(PORT);
	k_thread_create(&server_thread, server_stack, STACK_SIZE,
			server_thread_dtls_tag_change_fn, INT_TO_POINTER(server_fd), NULL, NULL,
			K_PRIO_PREEMPT(8), 0, K_NO_WAIT);
	zassert_ok(k_sem_take(&server_sem, K_MSEC(TIMEOUT)));

	r = dtls_client_connect(&client_fd, CA_CERTIFICATE_TAG, "localhost");
	zassert_ok(r, "failed to connect (%d)", errno);
	r = zsock_send(client_fd, SECRET, SECRET_SIZE, 0);
	zassert_equal(r, SECRET_SIZE, "send() failed (%d)", errno);
	zassert_ok(k_sem_take(&server_sem, K_MSEC(TIMEOUT)));

	/* The server serves one peer at a time, so the first client leaves first */
	zassert_ok(zsock_close(client_fd), "close() failed (%d)", errno);
	k_msleep(300);

	r = dtls_client_connect(&client_fd, CA_CERTIFICATE_TAG, "localhost");
	zassert_equal(r, -1, "the server presented its old certificate");
	zassert_ok(zsock_close(client_fd), "close() failed (%d)", errno);
	k_msleep(300);

	r = dtls_client_connect(&client_fd, IP_SAN_CA_TAG, MY_IPV4_ADDR);
	zassert_ok(r, "the server did not present its new certificate (%d)", errno);
	r = zsock_send(client_fd, SECRET, SECRET_SIZE, 0);
	zassert_equal(r, SECRET_SIZE, "send() failed (%d)", errno);

	zassert_ok(k_thread_join(&server_thread, K_FOREVER));
	zassert_true(dtls_later_peer_served, "the server did not serve the new client");
	zassert_ok(zsock_close(client_fd), "close() failed (%d)", errno);
	zassert_ok(zsock_close(server_fd), "close() failed (%d)", errno);
#endif
}

#if defined(CONFIG_WOLFSSL) && defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
static void server_thread_dtls_rebuild_fail_fn(void *arg0, void *arg1, void *arg2)
{
	const int server_fd = POINTER_TO_INT(arg0);
	char buf[16];
	int r;

	ARG_UNUSED(arg1);
	ARG_UNUSED(arg2);

	k_sem_give(&server_sem);
	r = zsock_recv(server_fd, buf, sizeof(buf), 0);
	zassert_equal(r, SECRET_SIZE, "recv() failed (%d)", errno);
	k_sem_give(&server_sem);
	dtls_serve_later_peer(server_fd);
}

static void server_thread_dtls_recv_one_fn(void *arg0, void *arg1, void *arg2)
{
	char buf[16];
	int r;

	ARG_UNUSED(arg1);
	ARG_UNUSED(arg2);

	k_sem_give(&server_sem);
	r = zsock_recv(POINTER_TO_INT(arg0), buf, sizeof(buf), 0);
	zassert_equal(r, SECRET_SIZE, "recv() failed (%d)", errno);
}
#endif /* CONFIG_WOLFSSL && CONFIG_NET_SOCKETS_ENABLE_DTLS */

/* wolfSSL-only: a DTLS server whose credentials vanish and come back serves the next client */
ZTEST(net_socket_tls_api_extension, test_dtls_server_ctx_rebuild_failure)
{
#if !defined(CONFIG_WOLFSSL) || !defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
	ztest_test_skip();
#else
	static const sec_tag_t server_tags[] = { IP_SAN_SERVER_TAG };
	int client_fd, server_fd, r;

	zassert_ok(tls_credential_add(IP_SAN_CA_TAG, TLS_CREDENTIAL_CA_CERTIFICATE,
				      ip_san_ca_der, sizeof(ip_san_ca_der)));
	zassert_ok(tls_credential_add(IP_SAN_SERVER_TAG, TLS_CREDENTIAL_PUBLIC_CERTIFICATE,
				      ip_san_server_der, sizeof(ip_san_server_der)));
	zassert_ok(tls_credential_add(IP_SAN_SERVER_TAG, TLS_CREDENTIAL_PRIVATE_KEY,
				      ip_san_server_key_der, sizeof(ip_san_server_key_der)));
	k_sem_init(&server_sem, 0, 1);
	dtls_later_peer_served = false;

	server_fd = dtls_server_socket_tags(PORT, server_tags, sizeof(server_tags));
	k_thread_create(&server_thread, server_stack, STACK_SIZE,
			server_thread_dtls_rebuild_fail_fn, INT_TO_POINTER(server_fd), NULL, NULL,
			K_PRIO_PREEMPT(8), 0, K_NO_WAIT);
	zassert_ok(k_sem_take(&server_sem, K_MSEC(TIMEOUT)));

	r = dtls_client_connect(&client_fd, IP_SAN_CA_TAG, MY_IPV4_ADDR);
	zassert_ok(r, "failed to connect (%d)", errno);
	r = zsock_send(client_fd, SECRET, SECRET_SIZE, 0);
	zassert_equal(r, SECRET_SIZE, "send() failed (%d)", errno);
	zassert_ok(k_sem_take(&server_sem, K_MSEC(TIMEOUT)));

	/* The session ends while the server's tag is empty, so the CTX cannot be rebuilt */
	zassert_ok(tls_credential_delete(IP_SAN_SERVER_TAG, TLS_CREDENTIAL_PUBLIC_CERTIFICATE));
	zassert_ok(tls_credential_delete(IP_SAN_SERVER_TAG, TLS_CREDENTIAL_PRIVATE_KEY));
	zassert_ok(zsock_close(client_fd), "close() failed (%d)", errno);
	k_msleep(300);

	zassert_ok(tls_credential_add(IP_SAN_SERVER_TAG, TLS_CREDENTIAL_PUBLIC_CERTIFICATE,
				      ip_san_server_der, sizeof(ip_san_server_der)));
	zassert_ok(tls_credential_add(IP_SAN_SERVER_TAG, TLS_CREDENTIAL_PRIVATE_KEY,
				      ip_san_server_key_der, sizeof(ip_san_server_key_der)));
	r = dtls_client_connect(&client_fd, IP_SAN_CA_TAG, MY_IPV4_ADDR);
	zassert_ok(r, "failed to connect once the credentials were back (%d)", errno);
	r = zsock_send(client_fd, SECRET, SECRET_SIZE, 0);
	zassert_equal(r, SECRET_SIZE, "send() failed (%d)", errno);

	zassert_ok(k_thread_join(&server_thread, K_FOREVER));
	zassert_true(dtls_later_peer_served, "the server did not serve the new client");
	zassert_ok(zsock_close(client_fd), "close() failed (%d)", errno);
	zassert_ok(zsock_close(server_fd), "close() failed (%d)", errno);
#endif
}

/* wolfSSL-only: a DTLS server serving a peer refuses connect() and keeps serving it */
ZTEST(net_socket_tls_api_extension, test_dtls_server_connect_while_serving)
{
#if !defined(CONFIG_WOLFSSL) || !defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
	ztest_test_skip();
#else
	struct sockaddr_in other = { .sin_family = AF_INET, .sin_port = htons(PORT + 1) };
	const int no_handshake = 0;
	char buf[16];
	int client_fd, server_fd, r;

	k_sem_init(&server_sem, 0, 1);
	server_fd = dtls_server_socket(PORT);
	k_thread_create(&server_thread, server_stack, STACK_SIZE, server_thread_dtls_recv_one_fn,
			INT_TO_POINTER(server_fd), NULL, NULL, K_PRIO_PREEMPT(8), 0, K_NO_WAIT);
	zassert_ok(k_sem_take(&server_sem, K_MSEC(TIMEOUT)));

	r = dtls_client_connect(&client_fd, CA_CERTIFICATE_TAG, "localhost");
	zassert_ok(r, "failed to connect (%d)", errno);
	r = zsock_send(client_fd, SECRET, SECRET_SIZE, 0);
	zassert_equal(r, SECRET_SIZE, "send() failed (%d)", errno);
	zassert_ok(k_thread_join(&server_thread, K_FOREVER));

	zassert_equal(zsock_inet_pton(AF_INET, MY_IPV4_ADDR, &other.sin_addr), 1);
	r = zsock_connect(server_fd, (struct sockaddr *)&other, sizeof(other));
	zassert_equal(r, -1, "a DTLS server serving a peer connected elsewhere");
	zassert_equal(errno, EISCONN, "unexpected errno %d", errno);

	zassert_ok(zsock_setsockopt(server_fd, SOL_TLS, TLS_DTLS_HANDSHAKE_ON_CONNECT,
				    &no_handshake, sizeof(no_handshake)));
	r = zsock_connect(server_fd, (struct sockaddr *)&other, sizeof(other));
	zassert_equal(r, -1, "connect() without a handshake moved the peer's session");
	zassert_equal(errno, EISCONN, "unexpected errno %d", errno);

	r = zsock_send(client_fd, SECRET, SECRET_SIZE, 0);
	zassert_equal(r, SECRET_SIZE, "send() failed (%d)", errno);
	r = zsock_recv(server_fd, buf, sizeof(buf), 0);
	zassert_equal(r, SECRET_SIZE, "the server stopped serving its peer (%d)", errno);

	zassert_ok(zsock_close(client_fd), "close() failed (%d)", errno);
	zassert_ok(zsock_close(server_fd), "close() failed (%d)", errno);
#endif
}

/* wolfSSL-only: a DTLS server that only pinned a peer with connect() can connect() again */
ZTEST(net_socket_tls_api_extension, test_dtls_server_connect_after_pin)
{
#if !defined(CONFIG_WOLFSSL) || !defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
	ztest_test_skip();
#else
	struct sockaddr_in peer = { .sin_family = AF_INET };
	const int no_handshake = 0;
	int server_fd;

	server_fd = dtls_server_socket(PORT);
	zassert_ok(zsock_setsockopt(server_fd, SOL_TLS, TLS_DTLS_HANDSHAKE_ON_CONNECT,
				    &no_handshake, sizeof(no_handshake)));
	zassert_equal(zsock_inet_pton(AF_INET, MY_IPV4_ADDR, &peer.sin_addr), 1);

	for (int i = 1; i <= 2; i++) {
		peer.sin_port = htons(PORT + i);
		zassert_ok(zsock_connect(server_fd, (struct sockaddr *)&peer, sizeof(peer)),
			   "connect() %d failed (%d)", i, errno);
	}

	zassert_ok(zsock_close(server_fd), "close() failed (%d)", errno);
#endif
}

/* wolfSSL-only: a DTLS client whose reset cannot rebuild the CTX reports why and recovers */
ZTEST(net_socket_tls_api_extension, test_dtls_client_ctx_rebuild_failure)
{
#if !defined(CONFIG_WOLFSSL) || !defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
	ztest_test_skip();
#else
	static const sec_tag_t server_tags[] = { IP_SAN_SERVER_TAG };
	const struct timeval timeo = { .tv_sec = 2 };
	struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(PORT) };
	char buf[16];
	int client_fd, server_fd, r;

	zassert_ok(tls_credential_add(IP_SAN_CA_TAG, TLS_CREDENTIAL_CA_CERTIFICATE,
				      ip_san_ca_der, sizeof(ip_san_ca_der)));
	zassert_ok(tls_credential_add(IP_SAN_SERVER_TAG, TLS_CREDENTIAL_PUBLIC_CERTIFICATE,
				      ip_san_server_der, sizeof(ip_san_server_der)));
	zassert_ok(tls_credential_add(IP_SAN_SERVER_TAG, TLS_CREDENTIAL_PRIVATE_KEY,
				      ip_san_server_key_der, sizeof(ip_san_server_key_der)));
	k_sem_init(&server_sem, 0, 1);

	server_fd = dtls_server_socket_tags(PORT, server_tags, sizeof(server_tags));
	k_thread_create(&server_thread, server_stack, STACK_SIZE, server_thread_dtls_recv_one_fn,
			INT_TO_POINTER(server_fd), NULL, NULL, K_PRIO_PREEMPT(8), 0, K_NO_WAIT);
	zassert_ok(k_sem_take(&server_sem, K_MSEC(TIMEOUT)));

	r = dtls_client_connect(&client_fd, IP_SAN_CA_TAG, MY_IPV4_ADDR);
	zassert_ok(r, "failed to connect (%d)", errno);
	zassert_ok(zsock_setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &timeo, sizeof(timeo)));
	r = zsock_send(client_fd, SECRET, SECRET_SIZE, 0);
	zassert_equal(r, SECRET_SIZE, "send() failed (%d)", errno);
	zassert_ok(k_thread_join(&server_thread, K_FOREVER));

	/* With the client's tag empty, the reset after the server's close_notify cannot rebuild */
	zassert_ok(tls_credential_delete(IP_SAN_CA_TAG, TLS_CREDENTIAL_CA_CERTIFICATE));
	zassert_ok(zsock_close(server_fd), "close() failed (%d)", errno);
	r = zsock_recv(client_fd, buf, sizeof(buf), 0);
	zassert_equal(r, -1, "recv() succeeded after the server closed");
	zassert_equal(errno, ENOENT, "unexpected errno %d", errno);

	zassert_ok(tls_credential_add(IP_SAN_CA_TAG, TLS_CREDENTIAL_CA_CERTIFICATE,
				      ip_san_ca_der, sizeof(ip_san_ca_der)));
	server_fd = dtls_server_socket_tags(PORT, server_tags, sizeof(server_tags));
	k_thread_create(&server_thread, server_stack, STACK_SIZE, server_thread_dtls_recv_one_fn,
			INT_TO_POINTER(server_fd), NULL, NULL, K_PRIO_PREEMPT(8), 0, K_NO_WAIT);
	zassert_ok(k_sem_take(&server_sem, K_MSEC(TIMEOUT)));

	/* The reset forgot the peer, so sendto() names it and sets the client up again */
	zassert_equal(zsock_inet_pton(AF_INET, MY_IPV4_ADDR, &sa.sin_addr), 1);
	r = zsock_sendto(client_fd, SECRET, SECRET_SIZE, 0, (struct sockaddr *)&sa, sizeof(sa));
	zassert_equal(r, SECRET_SIZE, "sendto() failed once the CA was back (%d)", errno);
	zassert_ok(k_thread_join(&server_thread, K_FOREVER));

	zassert_ok(zsock_close(client_fd), "close() failed (%d)", errno);
	zassert_ok(zsock_close(server_fd), "close() failed (%d)", errno);
#endif
}
#endif /* CONFIG_TLS_CREDENTIALS */

/* Without TLS_HOSTNAME, REQUIRED has no name to check, so the handshake fails */
ZTEST(net_socket_tls_api_extension, test_tls_no_hostname_required_rejected)
{
	int server_fd, client_fd, ret;
	k_tid_t server_thread_id;
	struct sockaddr_in sa;
	int peer_verify = TLS_PEER_VERIFY_REQUIRED;

	server_fd = test_configure_server(&server_thread_id, TLS_PEER_VERIFY_NONE,
					  false, true);
	client_fd = test_configure_client(&sa, false, NULL);

	ret = zsock_setsockopt(client_fd, SOL_TLS, TLS_PEER_VERIFY,
			       &peer_verify, sizeof(peer_verify));
	zassert_ok(ret, "failed to set TLS_PEER_VERIFY (%d)", errno);

	ret = zsock_connect(client_fd, (struct sockaddr *)&sa, sizeof(sa));
	zassert_equal(ret, -1, "connect succeeded without a hostname to verify");

	test_shutdown(client_fd, server_fd, server_thread_id);
}

/* A NULL TLS_HOSTNAME turns the name check off, so a mismatched name passes REQUIRED */
ZTEST(net_socket_tls_api_extension, test_tls_null_hostname_skips_name_check)
{
	int server_fd, client_fd, ret;
	k_tid_t server_thread_id;
	struct sockaddr_in sa;
	int peer_verify = TLS_PEER_VERIFY_REQUIRED;
	uint32_t verify_result = UINT32_MAX;
	socklen_t optlen = sizeof(verify_result);

	server_fd = test_configure_server(&server_thread_id, TLS_PEER_VERIFY_NONE,
					  false, false);
	client_fd = test_configure_client(&sa, false, "dummy");

	ret = zsock_setsockopt(client_fd, SOL_TLS, TLS_HOSTNAME, NULL, 0);
	zassert_ok(ret, "failed to clear TLS_HOSTNAME (%d)", errno);
	ret = zsock_setsockopt(client_fd, SOL_TLS, TLS_PEER_VERIFY,
			       &peer_verify, sizeof(peer_verify));
	zassert_ok(ret, "failed to set TLS_PEER_VERIFY (%d)", errno);

	ret = zsock_connect(client_fd, (struct sockaddr *)&sa, sizeof(sa));
	zassert_not_equal(ret, -1, "connect failed with the name check off (%d)", errno);

	ret = zsock_getsockopt(client_fd, SOL_TLS, TLS_CERT_VERIFY_RESULT,
			       &verify_result, &optlen);
	zassert_ok(ret, "failed to get TLS_CERT_VERIFY_RESULT (%d)", errno);
	zassert_equal(verify_result, 0, "verify result 0x%x", verify_result);

	test_shutdown(client_fd, server_fd, server_thread_id);
}

/* NONE skips the name check, so it is never stricter than OPTIONAL */
ZTEST(net_socket_tls_api_extension, test_tls_verify_none_ignores_hostname)
{
	int server_fd, client_fd, ret;
	k_tid_t server_thread_id;
	struct sockaddr_in sa;
	int peer_verify = TLS_PEER_VERIFY_NONE;

	server_fd = test_configure_server(&server_thread_id, TLS_PEER_VERIFY_NONE,
					  false, false);
	client_fd = test_configure_client(&sa, false, "dummy");

	ret = zsock_setsockopt(client_fd, SOL_TLS, TLS_PEER_VERIFY,
			       &peer_verify, sizeof(peer_verify));
	zassert_ok(ret, "failed to set TLS_PEER_VERIFY (%d)", errno);

	ret = zsock_connect(client_fd, (struct sockaddr *)&sa, sizeof(sa));
	zassert_not_equal(ret, -1, "TLS_PEER_VERIFY_NONE rejected a hostname mismatch (%d)",
			  errno);

	test_shutdown(client_fd, server_fd, server_thread_id);
}

/* optlen often counts the terminating NUL, which both backends accept */
ZTEST(net_socket_tls_api_extension, test_tls_hostname_trailing_nul)
{
	int server_fd, client_fd, ret;
	k_tid_t server_thread_id;
	struct sockaddr_in sa;
	uint32_t optval;
	socklen_t optlen = sizeof(optval);
	int peer_verify = TLS_PEER_VERIFY_OPTIONAL;

	server_fd = test_configure_server(&server_thread_id,
					  TLS_PEER_VERIFY_NONE,
					  false, false);
	client_fd = test_configure_client(&sa, false, "localhost");

	/* Override the hostname with optlen including the terminating NUL. */
	ret = zsock_setsockopt(client_fd, SOL_TLS, TLS_HOSTNAME,
			       "localhost", sizeof("localhost"));
	zassert_ok(ret, "failed to set TLS_HOSTNAME (%d)", errno);

	ret = zsock_setsockopt(client_fd, SOL_TLS, TLS_PEER_VERIFY,
			       &peer_verify, sizeof(peer_verify));
	zassert_ok(ret, "failed to set TLS_PEER_VERIFY (%d)", errno);

	ret = zsock_connect(client_fd, (struct sockaddr *)&sa, sizeof(sa));
	zassert_not_equal(ret, -1, "failed to connect (%d)", errno);

	/* The CN must have matched despite the NUL-terminated optval. */
	ret = zsock_getsockopt(client_fd, SOL_TLS,
			       TLS_CERT_VERIFY_RESULT, &optval, &optlen);
	zassert_equal(ret, 0, "getsockopt failed (%d)", errno);
	zassert_equal(optval, 0,
		      "unexpected verify result 0x%x (hostname mismatch?)",
		      optval);

	test_shutdown(client_fd, server_fd, server_thread_id);
}

/* --- Unified cert verify callback tests (mbedTLS backend only) --- */

#if defined(CONFIG_NET_SOCKETS_TLS_CERT_VERIFY_CALLBACK) && !defined(CONFIG_WOLFSSL)

struct test_cert_verify_ctx {
	bool cb_called;
	int result;
};

static int cert_verify_cb(void *ctx, mbedtls_x509_crt *crt, int depth,
			  uint32_t *flags)
{
	struct test_cert_verify_ctx *test_ctx = (struct test_cert_verify_ctx *)ctx;

	test_ctx->cb_called = true;

	if (test_ctx->result == 0) {
		*flags = 0;
	} else {
		*flags |= MBEDTLS_X509_BADCERT_NOT_TRUSTED;
	}

	return test_ctx->result;
}

static void test_tls_cert_verify_cb_opt_common(int result)
{
	int server_fd, client_fd, ret;
	k_tid_t server_thread_id;
	struct sockaddr_in sa;
	struct test_cert_verify_ctx ctx = {
		.cb_called = false,
		.result = result,
	};
	struct tls_cert_verify_cb cb = {
		.cb = cert_verify_cb,
		.ctx = &ctx,
	};

	server_fd = test_configure_server(&server_thread_id, TLS_PEER_VERIFY_NONE,
					  false, result == 0 ? false : true);
	client_fd = test_configure_client(&sa, false, "localhost");

	ret = zsock_setsockopt(client_fd, SOL_TLS, TLS_CERT_VERIFY_CALLBACK,
			       &cb, sizeof(cb));
	zassert_ok(ret, "failed to set TLS_CERT_VERIFY_CALLBACK (%d)", errno);

	ret = zsock_connect(client_fd, (struct sockaddr *)&sa, sizeof(sa));
	zassert_true(ctx.cb_called, "callback not called");
	if (result == 0) {
		zassert_equal(ret, 0, "failed to connect (%d)", errno);
	} else {
		zassert_equal(ret, -1, "connect() should fail");
		zassert_equal(errno, ECONNABORTED, "invalid errno");
	}

	test_shutdown(client_fd, server_fd, server_thread_id);
}

ZTEST(net_socket_tls_api_extension, test_tls_cert_verify_cb_opt_ok)
{
	test_tls_cert_verify_cb_opt_common(0);
}

ZTEST(net_socket_tls_api_extension, test_tls_cert_verify_cb_opt_bad_cert)
{
	test_tls_cert_verify_cb_opt_common(MBEDTLS_ERR_X509_CERT_VERIFY_FAILED);
}

#endif /* CONFIG_NET_SOCKETS_TLS_CERT_VERIFY_CALLBACK */

#if defined(CONFIG_WOLFSSL)
/* Option 20 is the mbedTLS-style callback and returns -ENOTSUP on wolfSSL */
ZTEST(net_socket_tls_api_extension, test_tls_cert_verify_cb_opt20_enotsup_on_wolfssl)
{
	int client_fd;
	int ret;
	struct tls_cert_verify_cb dummy = { .cb = NULL, .ctx = NULL };

	client_fd = zsock_socket(AF_INET, SOCK_STREAM, IPPROTO_TLS_1_2);
	zassert_true(client_fd >= 0, "socket() failed: %d", errno);

	ret = zsock_setsockopt(client_fd, SOL_TLS, TLS_CERT_VERIFY_CALLBACK,
			       &dummy, sizeof(dummy));
	zassert_equal(ret, -1, "setsockopt() should fail under wolfSSL");
	zassert_equal(errno, ENOTSUP,
		      "expected -ENOTSUP, got errno=%d", errno);

	(void)zsock_close(client_fd);
}
#endif /* CONFIG_WOLFSSL */

#if defined(CONFIG_WOLFSSL) && defined(CONFIG_WOLFSSL_MAX_FRAGMENT) && \
	defined(CONFIG_NET_SOCKETS_TLS_SET_MAX_FRAGMENT_LENGTH)
/* One socket for all cases: the net_context pool is small and reclaimed lazily. */
ZTEST(net_socket_tls_api_extension, test_tls_mfl_opt_values)
{
	static const int accept[] = {
		TLS_MFL_DEFAULT, TLS_MFL_DISABLED, TLS_MFL_512,
		TLS_MFL_1024, TLS_MFL_2048, TLS_MFL_4096,
	};
	/* 5 and 6 are wolfSSL's non-RFC-6066 8192 and 256 codes. */
	static const int reject[] = { -2, 5, 6, 255 };
	int accept_r[ARRAY_SIZE(accept)];
	int reject_r[ARRAY_SIZE(reject)];
	int reject_e[ARRAY_SIZE(reject)];
	int short_r, short_e, null_r, null_e;
	int fd, val;

	fd = zsock_socket(AF_INET, SOCK_STREAM, IPPROTO_TLS_1_2);
	zassert_true(fd >= 0, "socket() failed (%d)", errno);

	/* Collect results first, so the socket is closed even if an assertion aborts. */
	for (int i = 0; i < ARRAY_SIZE(accept); i++) {
		val = accept[i];
		accept_r[i] = zsock_setsockopt(fd, SOL_TLS,
					       TLS_MAX_FRAGMENT_LENGTH,
					       &val, sizeof(val));
	}

	for (int i = 0; i < ARRAY_SIZE(reject); i++) {
		val = reject[i];
		reject_r[i] = zsock_setsockopt(fd, SOL_TLS,
					       TLS_MAX_FRAGMENT_LENGTH,
					       &val, sizeof(val));
		reject_e[i] = errno;
	}

	val = TLS_MFL_512;
	short_r = zsock_setsockopt(fd, SOL_TLS, TLS_MAX_FRAGMENT_LENGTH,
				   &val, sizeof(val) - 1);
	short_e = errno;

	null_r = zsock_setsockopt(fd, SOL_TLS, TLS_MAX_FRAGMENT_LENGTH,
				  NULL, sizeof(val));
	null_e = errno;

	(void)zsock_close(fd);

	for (int i = 0; i < ARRAY_SIZE(accept); i++) {
		zassert_ok(accept_r[i], "MFL %d rejected", accept[i]);
	}

	for (int i = 0; i < ARRAY_SIZE(reject); i++) {
		zassert_equal(reject_r[i], -1, "MFL %d accepted", reject[i]);
		zassert_equal(reject_e[i], EINVAL, "MFL %d: errno %d, want EINVAL",
			      reject[i], reject_e[i]);
	}

	zassert_equal(short_r, -1, "short optlen accepted");
	zassert_equal(short_e, EINVAL, "short optlen: errno %d, want EINVAL", short_e);
	zassert_equal(null_r, -1, "NULL optval accepted");
	zassert_equal(null_e, EINVAL, "NULL optval: errno %d, want EINVAL", null_e);
}

ZTEST(net_socket_tls_api_extension, test_tls_mfl_handshake)
{
	k_tid_t server_thread_id;
	struct sockaddr_in sa;
	uint8_t rx_buf[16];
	int mfl = TLS_MFL_512;
	int server_fd;
	int client_fd;
	int r;

	server_fd = test_configure_server(&server_thread_id,
					  TLS_PEER_VERIFY_NONE, true, false);
	client_fd = test_configure_client(&sa, false, "localhost");

	r = zsock_setsockopt(client_fd, SOL_TLS, TLS_MAX_FRAGMENT_LENGTH,
			     &mfl, sizeof(mfl));
	zassert_ok(r, "failed to set TLS_MAX_FRAGMENT_LENGTH (%d)", errno);

	r = zsock_connect(client_fd, (struct sockaddr *)&sa, sizeof(sa));
	zassert_not_equal(r, -1, "failed to connect (%d)", errno);

	r = zsock_send(client_fd, SECRET, SECRET_SIZE, 0);
	zassert_equal(SECRET_SIZE, r, "send() failed (%d)", errno);

	memset(rx_buf, 0, sizeof(rx_buf));
	r = zsock_recv(client_fd, rx_buf, sizeof(rx_buf), 0);
	zassert_equal(SECRET_SIZE, r, "recv() failed (%d)", errno);
	zassert_mem_equal(SECRET, rx_buf, SECRET_SIZE, "payload mismatch");

	test_shutdown(client_fd, server_fd, server_thread_id);
}

/* send() writes one record per call, so it returns a short count, as on mbedTLS */
ZTEST(net_socket_tls_api_extension, test_tls_send_one_record)
{
	static uint8_t big[1000];
	k_tid_t server_thread_id;
	uint8_t rx_buf[16];
	struct sockaddr_in sa;
	int mfl = TLS_MFL_512;
	int server_fd;
	int client_fd;
	int r;

	server_fd = test_configure_server(&server_thread_id,
					  TLS_PEER_VERIFY_NONE, true, false);
	client_fd = test_configure_client(&sa, false, "localhost");

	r = zsock_setsockopt(client_fd, SOL_TLS, TLS_MAX_FRAGMENT_LENGTH,
			     &mfl, sizeof(mfl));
	zassert_ok(r, "failed to set TLS_MAX_FRAGMENT_LENGTH (%d)", errno);

	r = zsock_connect(client_fd, (struct sockaddr *)&sa, sizeof(sa));
	zassert_not_equal(r, -1, "failed to connect (%d)", errno);

	r = zsock_send(client_fd, SECRET, SECRET_SIZE, 0);
	zassert_equal(SECRET_SIZE, r, "send() failed (%d)", errno);

	r = zsock_send(client_fd, big, sizeof(big), 0);
	zassert_true(r > 0 && r <= 512, "send() of %zu bytes returned %d", sizeof(big), r);

	r = zsock_recv(client_fd, rx_buf, sizeof(rx_buf), 0);
	zassert_equal(SECRET_SIZE, r, "recv() failed (%d)", errno);

	test_shutdown(client_fd, server_fd, server_thread_id);
}
#endif /* CONFIG_WOLFSSL && CONFIG_WOLFSSL_MAX_FRAGMENT &&
	* CONFIG_NET_SOCKETS_TLS_SET_MAX_FRAGMENT_LENGTH
	*/

static void *setup(void)
{
	int r;

	/*
	 * Load both client & server credentials
	 *
	 * Normally, this would be split into separate applications but
	 * for testing purposes, we just use separate threads.
	 *
	 * Also, it has to be done before tests are run, otherwise
	 * there are errors due to attempts to load too many certificates.
	 *
	 * The server would normally load
	 * - server public key
	 * - server private key
	 * - ca cert (only when client authentication is required)
	 *
	 * The client would normally load
	 * - ca cert (to verify the server)
	 * - client public key (only when client authentication is required)
	 * - client private key (only when client authentication is required)
	 */
	if (IS_ENABLED(CONFIG_TLS_CREDENTIALS)) {
		NET_DBG("Loading credentials");
		r = tls_credential_add(CA_CERTIFICATE_TAG,
				       TLS_CREDENTIAL_CA_CERTIFICATE,
				       ca, sizeof(ca));
		zassert_equal(r, 0, "failed to add CA Certificate (%d)", r);

		r = tls_credential_add(SERVER_CERTIFICATE_TAG,
				       TLS_CREDENTIAL_PUBLIC_CERTIFICATE,
				       server, sizeof(server));
		zassert_equal(r, 0, "failed to add Server Certificate (%d)", r);

		r = tls_credential_add(SERVER_CERTIFICATE_TAG,
				       TLS_CREDENTIAL_PRIVATE_KEY,
				       server_privkey, sizeof(server_privkey));
		zassert_equal(r, 0, "failed to add Server Private Key (%d)", r);

		r = tls_credential_add(CLIENT_CERTIFICATE_TAG,
				       TLS_CREDENTIAL_PUBLIC_CERTIFICATE,
				       client, sizeof(client));
		zassert_equal(r, 0, "failed to add Client Certificate (%d)", r);

		r = tls_credential_add(CLIENT_CERTIFICATE_TAG,
				       TLS_CREDENTIAL_PRIVATE_KEY,
				       client_privkey, sizeof(client_privkey));
		zassert_equal(r, 0, "failed to add Client Private Key (%d)", r);
	}
	return NULL;
}

/* --- wolfSSL-style verify callback tests --- */

#if defined(CONFIG_WOLFSSL_VERIFY_CALLBACK)

struct wolfssl_verify_ctx {
	bool cb_called;
	int depth_seen;
	int error_seen;
	int decision;  /* 1 = accept, 0 = reject */
};

static int wolfssl_verify_cb(int preverify_ok, void *store_ctx)
{
	WOLFSSL_X509_STORE_CTX *store = store_ctx;
	struct wolfssl_verify_ctx *ctx;

	if (store == NULL || store->userCtx == NULL) {
		return preverify_ok;
	}

	ctx = (struct wolfssl_verify_ctx *)store->userCtx;
	ctx->cb_called = true;
	ctx->depth_seen = store->error_depth;
	ctx->error_seen = store->error;

	return ctx->decision;
}

struct wolfssl_verify_inspect_ctx {
	bool cb_called;
	int error_depth;
	int total_certs;
	bool has_certs_buffer;
	bool domain_is_localhost;
};

static int wolfssl_verify_inspect_cb(int preverify_ok, void *store_ctx)
{
	WOLFSSL_X509_STORE_CTX *store = store_ctx;
	struct wolfssl_verify_inspect_ctx *ctx;

	if (store == NULL || store->userCtx == NULL) {
		return preverify_ok;
	}

	ctx = (struct wolfssl_verify_inspect_ctx *)store->userCtx;
	ctx->cb_called = true;
	ctx->error_depth = store->error_depth;
	ctx->total_certs = store->totalCerts;
	ctx->has_certs_buffer = (store->certs != NULL &&
				 store->certs[store->error_depth].length > 0);

	if (store->domain != NULL &&
	    strcmp(store->domain, "localhost") == 0) {
		ctx->domain_is_localhost = true;
	}

	return 1; /* accept */
}

ZTEST(net_socket_tls_api_extension, test_wolfssl_verify_cb_accept)
{
	int server_fd, client_fd, ret;
	k_tid_t server_thread_id;
	struct sockaddr_in sa;

	struct wolfssl_verify_ctx ctx = {
		.cb_called = false,
		.decision = 1, /* accept */
	};
	struct tls_cert_verify_cb_wolfssl cb = {
		.cb = wolfssl_verify_cb,
		.ctx = &ctx,
	};

	server_fd = test_configure_server(&server_thread_id,
					  TLS_PEER_VERIFY_NONE, false, false);
	client_fd = test_configure_client(&sa, false, "localhost");

	ret = zsock_setsockopt(client_fd, SOL_TLS, TLS_CERT_VERIFY_CALLBACK_WOLFSSL,
			       &cb, sizeof(cb));
	zassert_ok(ret, "failed to set TLS_CERT_VERIFY_CALLBACK_WOLFSSL (%d)", errno);

	ret = zsock_connect(client_fd, (struct sockaddr *)&sa, sizeof(sa));
	zassert_equal(ret, 0, "failed to connect (%d)", errno);
	zassert_true(ctx.cb_called, "wolfSSL-style verify callback was not called");

	test_shutdown(client_fd, server_fd, server_thread_id);
}

ZTEST(net_socket_tls_api_extension, test_wolfssl_verify_cb_reject)
{
	int server_fd, client_fd, ret;
	k_tid_t server_thread_id;
	struct sockaddr_in sa;

	struct wolfssl_verify_ctx ctx = {
		.cb_called = false,
		.decision = 0, /* reject */
	};
	struct tls_cert_verify_cb_wolfssl cb = {
		.cb = wolfssl_verify_cb,
		.ctx = &ctx,
	};

	server_fd = test_configure_server(&server_thread_id,
					  TLS_PEER_VERIFY_NONE, false, true);
	client_fd = test_configure_client(&sa, false, "localhost");

	ret = zsock_setsockopt(client_fd, SOL_TLS, TLS_CERT_VERIFY_CALLBACK_WOLFSSL,
			       &cb, sizeof(cb));
	zassert_ok(ret, "failed to set TLS_CERT_VERIFY_CALLBACK_WOLFSSL (%d)", errno);

	ret = zsock_connect(client_fd, (struct sockaddr *)&sa, sizeof(sa));
	zassert_true(ctx.cb_called, "wolfSSL-style verify callback was not called");
	zassert_equal(ret, -1, "connect() should fail");
	zassert_equal(errno, ECONNABORTED, "invalid errno");

	test_shutdown(client_fd, server_fd, server_thread_id);
}

ZTEST(net_socket_tls_api_extension, test_wolfssl_verify_cb_inspect_fields)
{
	int server_fd, client_fd, ret;
	k_tid_t server_thread_id;
	struct sockaddr_in sa;

	struct wolfssl_verify_inspect_ctx ctx = {0};
	struct tls_cert_verify_cb_wolfssl cb = {
		.cb = wolfssl_verify_inspect_cb,
		.ctx = &ctx,
	};

	server_fd = test_configure_server(&server_thread_id,
					  TLS_PEER_VERIFY_NONE, false, false);
	client_fd = test_configure_client(&sa, false, "localhost");

	ret = zsock_setsockopt(client_fd, SOL_TLS, TLS_CERT_VERIFY_CALLBACK_WOLFSSL,
			       &cb, sizeof(cb));
	zassert_ok(ret, "failed to set TLS_CERT_VERIFY_CALLBACK_WOLFSSL (%d)", errno);

	ret = zsock_connect(client_fd, (struct sockaddr *)&sa, sizeof(sa));
	zassert_equal(ret, 0, "failed to connect (%d)", errno);

	zassert_true(ctx.cb_called, "wolfSSL-style verify callback was not called");
	zassert_true(ctx.total_certs > 0, "totalCerts should be > 0");
	zassert_true(ctx.has_certs_buffer,
		     "certs buffer should contain DER data");
	zassert_true(ctx.domain_is_localhost,
		     "domain should be 'localhost'");

	test_shutdown(client_fd, server_fd, server_thread_id);
}

static int wolfssl_verify_null_ctx_cb(int preverify_ok, void *store_ctx)
{
	WOLFSSL_X509_STORE_CTX *store = store_ctx;

	/* When ctx is NULL, wolfSSL's default userCtx resolution applies.
	 * store->userCtx should be NULL (ssl->verifyCbCtx is NULL by default).
	 */
	if (store != NULL && store->userCtx == NULL) {
		/* This is the expected path -- userCtx is NULL because we
		 * did not call wolfSSL_SetCertCbCtx. Accept the cert.
		 */
		return 1;
	}

	/* Unexpected: userCtx is non-NULL. Reject to signal test failure. */
	return 0;
}

ZTEST(net_socket_tls_api_extension, test_wolfssl_verify_cb_null_ctx)
{
	int server_fd, client_fd, ret;
	k_tid_t server_thread_id;
	struct sockaddr_in sa;

	/* With a NULL ctx, store->userCtx in the callback is NULL */
	struct tls_cert_verify_cb_wolfssl cb = {
		.cb = wolfssl_verify_null_ctx_cb,
		.ctx = NULL,
	};

	server_fd = test_configure_server(&server_thread_id,
					  TLS_PEER_VERIFY_NONE, false, false);
	client_fd = test_configure_client(&sa, false, "localhost");

	ret = zsock_setsockopt(client_fd, SOL_TLS, TLS_CERT_VERIFY_CALLBACK_WOLFSSL,
			       &cb, sizeof(cb));
	zassert_ok(ret, "failed to set TLS_CERT_VERIFY_CALLBACK_WOLFSSL (%d)", errno);

	ret = zsock_connect(client_fd, (struct sockaddr *)&sa, sizeof(sa));
	zassert_equal(ret, 0,
		      "connect failed -- userCtx may not be NULL (%d)", errno);

	test_shutdown(client_fd, server_fd, server_thread_id);
}

/* --- Server-side wolfSSL-style verify callback test --- */

static struct wolfssl_verify_ctx server_wolfssl_verify_ctx;

static void server_thread_wolfssl_verify_fn(void *arg0, void *arg1, void *arg2)
{
	const int server_fd = POINTER_TO_INT(arg0);
	int r;
	int client_fd;
	socklen_t addrlen;
	struct sockaddr_in sa;

	k_thread_name_set(k_current_get(), "server");

	memset(&sa, 0, sizeof(sa));
	addrlen = sizeof(sa);

	k_sem_give(&server_sem);
	r = zsock_accept(server_fd, (struct sockaddr *)&sa, &addrlen);
	zassert_not_equal(r, -1, "zsock_accept() failed (%d)", errno);
	client_fd = r;

	r = zsock_close(client_fd);
	zassert_not_equal(r, -1, "zsock_close() failed on the server fd (%d)", errno);
}

ZTEST(net_socket_tls_api_extension, test_wolfssl_verify_cb_server_accept)
{
	static const sec_tag_t server_tag_list[] = {
		CA_CERTIFICATE_TAG,
		SERVER_CERTIFICATE_TAG,
	};
	int server_fd, client_fd, ret;
	k_tid_t tid;
	struct sockaddr_in sa;
	/* Only REQUIRED makes a server demand a client certificate and run the callback */
	int peer_verify = TLS_PEER_VERIFY_REQUIRED;

	memset(&server_wolfssl_verify_ctx, 0, sizeof(server_wolfssl_verify_ctx));
	server_wolfssl_verify_ctx.decision = 1; /* accept */

	struct tls_cert_verify_cb_wolfssl cb = {
		.cb = wolfssl_verify_cb,
		.ctx = &server_wolfssl_verify_ctx,
	};

	k_sem_init(&server_sem, 0, 1);

	/* Create server socket */
	ret = zsock_socket(AF_INET, SOCK_STREAM, IPPROTO_TLS_1_2);
	zassert_not_equal(ret, -1, "failed to create server socket (%d)", errno);
	server_fd = ret;

	int yes = true;

	ret = zsock_setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
	zassert_not_equal(ret, -1, "failed to set SO_REUSEADDR (%d)", errno);

	ret = zsock_setsockopt(server_fd, SOL_TLS, TLS_SEC_TAG_LIST,
			 server_tag_list, sizeof(server_tag_list));
	zassert_not_equal(ret, -1, "failed to set TLS_SEC_TAG_LIST (%d)", errno);

	ret = zsock_setsockopt(server_fd, SOL_TLS, TLS_HOSTNAME, "localhost",
			 sizeof("localhost"));
	zassert_not_equal(ret, -1, "failed to set TLS_HOSTNAME (%d)", errno);

	ret = zsock_setsockopt(server_fd, SOL_TLS, TLS_PEER_VERIFY,
			 &peer_verify, sizeof(peer_verify));
	zassert_not_equal(ret, -1, "failed to set TLS_PEER_VERIFY (%d)", errno);

	ret = zsock_setsockopt(server_fd, SOL_TLS, TLS_CERT_VERIFY_CALLBACK_WOLFSSL,
			 &cb, sizeof(cb));
	zassert_ok(ret, "failed to set TLS_CERT_VERIFY_CALLBACK_WOLFSSL (%d)", errno);

	memset(&sa, 0, sizeof(sa));
	sa.sin_addr.s_addr = INADDR_ANY;
	sa.sin_family = AF_INET;
	sa.sin_port = htons(PORT);

	ret = zsock_bind(server_fd, (struct sockaddr *)&sa, sizeof(sa));
	zassert_not_equal(ret, -1, "failed to bind (%d)", errno);

	ret = zsock_listen(server_fd, 1);
	zassert_not_equal(ret, -1, "failed to listen (%d)", errno);

	tid = k_thread_create(&server_thread, server_stack, STACK_SIZE,
			      server_thread_wolfssl_verify_fn,
			      INT_TO_POINTER(server_fd), NULL, NULL,
			      K_PRIO_PREEMPT(8), 0, K_NO_WAIT);

	ret = k_sem_take(&server_sem, K_MSEC(TIMEOUT));
	zassert_equal(0, ret, "failed to synchronize with server thread (%d)", ret);

	/* Client presents its cert */
	client_fd = test_configure_client(&sa, true, "localhost");

	ret = zsock_connect(client_fd, (struct sockaddr *)&sa, sizeof(sa));
	zassert_equal(ret, 0, "failed to connect (%d)", errno);

	/* The server's wolfSSL-style verify callback should have been invoked
	 * during zsock_accept() on the cloned child context.
	 */
	zassert_true(server_wolfssl_verify_ctx.cb_called,
		     "server wolfSSL-style verify callback was not called");

	ret = zsock_close(client_fd);
	zassert_not_equal(-1, ret, "zsock_close() failed on client fd (%d)", errno);
	ret = zsock_close(server_fd);
	zassert_not_equal(-1, ret, "zsock_close() failed on server fd (%d)", errno);
	ret = k_thread_join(&server_thread, K_FOREVER);
	zassert_equal(0, ret, "k_thread_join() failed (%d)", ret);
	k_yield();
}

/* A verify callback that accepts a failed chain CA does not make it trusted afterwards */
ZTEST(net_socket_tls_api_extension, test_wolfssl_verify_cb_chain_ca_not_learned)
{
#if !defined(CONFIG_TLS_CREDENTIALS)
	ztest_test_skip();
#else
	static struct wolfssl_verify_ctx accept_ctx = { .decision = 1 };
	const struct tls_cert_verify_cb_wolfssl cb = {
		.cb = wolfssl_verify_cb,
		.ctx = &accept_ctx,
	};

	chain_ca_tcp_common(TLS_PEER_VERIFY_REQUIRED, &cb, sizeof(cb), false, false);
#endif
}

/* A verify callback cannot accept a failed chain CA in a renegotiation */
ZTEST(net_socket_tls_api_extension, test_wolfssl_verify_cb_reneg_chain_ca_not_learned)
{
#if !defined(CONFIG_TLS_CREDENTIALS) || !defined(HAVE_SECURE_RENEGOTIATION) || \
	defined(WOLFSSL_NO_TLS12)
	ztest_test_skip();
#else
	static struct wolfssl_verify_ctx accept_ctx = { .decision = 1 };
	const struct tls_cert_verify_cb_wolfssl cb = {
		.cb = wolfssl_verify_cb,
		.ctx = &accept_ctx,
	};

	chain_ca_tcp_common(TLS_PEER_VERIFY_REQUIRED, &cb, sizeof(cb), true, false);
#endif
}

/* Children of a listener with a verify callback share its CTX only without renegotiation */
ZTEST(net_socket_tls_api_extension, test_wolfssl_verify_cb_listener_ctx_sharing)
{
#if defined(SINGLE_THREADED)
	ztest_test_skip();
#else
	static struct wolfssl_verify_ctx accept_ctx = { .decision = 1 };
	const struct tls_cert_verify_cb_wolfssl cb = {
		.cb = wolfssl_verify_cb,
		.ctx = &accept_ctx,
	};

	zassert_equal(listener_ctx_shared(TLS_PEER_VERIFY_REQUIRED, &cb, sizeof(cb), true),
		      !RENEGOTIATION_UNSHARES, "unexpected CTX sharing");
#endif
}

/* The control for the test above, with client A's CA trusted */
ZTEST(net_socket_tls_api_extension, test_wolfssl_verify_cb_reneg_trusted_chain)
{
#if !defined(CONFIG_TLS_CREDENTIALS) || !defined(HAVE_SECURE_RENEGOTIATION) || \
	defined(WOLFSSL_NO_TLS12)
	ztest_test_skip();
#else
	static struct wolfssl_verify_ctx accept_ctx = { .decision = 1 };
	const struct tls_cert_verify_cb_wolfssl cb = {
		.cb = wolfssl_verify_cb,
		.ctx = &accept_ctx,
	};

	chain_ca_tcp_common(TLS_PEER_VERIFY_REQUIRED, &cb, sizeof(cb), true, true);
#endif
}

#endif /* CONFIG_WOLFSSL_VERIFY_CALLBACK */

#if defined(CONFIG_WOLFSSL)
/* 2025-06-01, inside the 2020..2119 validity of the test certificates */
#define WOLFSSL_CERT_VALID_TIME 1748736000

static void set_cert_validity_clock(void *fixture)
{
	const struct timespec ts = {
		.tv_sec = WOLFSSL_CERT_VALID_TIME,
		.tv_nsec = 0,
	};
	int ret;

	ARG_UNUSED(fixture);

	/* ztest resets the realtime clock to 1970 after each test, so set it before each one */
	ret = clock_settime(CLOCK_REALTIME, &ts);
	zassert_ok(ret, "failed to set CLOCK_REALTIME (%d)", ret);
}
#define TLS_EXT_BEFORE set_cert_validity_clock
#else
#define TLS_EXT_BEFORE NULL
#endif /* CONFIG_WOLFSSL */

#if defined(CONFIG_NET_SOCKETS_TLS_WOLFSSL_OCSP_STAPLING)
#define OCSP_PORT 4243
#define OCSP_STACK_SIZE 16384

static K_THREAD_STACK_DEFINE(ocsp_server_stack, OCSP_STACK_SIZE);

static int ocsp_io_cb(void *ctx, const char *url, int url_len, unsigned char *req,
		      int req_len, unsigned char **resp)
{
	ARG_UNUSED(ctx);
	ARG_UNUSED(url);
	ARG_UNUSED(url_len);
	ARG_UNUSED(req);
	ARG_UNUSED(req_len);

	*resp = (unsigned char *)ocsp_good;
	return sizeof(ocsp_good);
}

static void ocsp_resp_free_cb(void *ctx, unsigned char *resp)
{
	ARG_UNUSED(ctx);
	ARG_UNUSED(resp);
}

/* A Zephyr TLS server socket cannot staple, so the peer is plain wolfSSL. */
static void ocsp_server_fn(void *p1, void *p2, void *p3)
{
	int listen_fd = POINTER_TO_INT(p1);
	bool staple = POINTER_TO_INT(p2);
	WOLFSSL_CTX *ctx;
	WOLFSSL *ssl = NULL;
	int fd = -1;

	ARG_UNUSED(p3);

	ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method());
	if (ctx == NULL ||
	    wolfSSL_CTX_use_certificate_buffer(ctx, ocsp_server, sizeof(ocsp_server),
					       WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS ||
	    wolfSSL_CTX_use_PrivateKey_buffer(ctx, ocsp_server_key, sizeof(ocsp_server_key),
					      WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
		goto out;
	}

	if (staple &&
	    (wolfSSL_CTX_load_verify_buffer(ctx, ocsp_ca, sizeof(ocsp_ca),
					    WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS ||
	     wolfSSL_CTX_EnableOCSP(ctx, WOLFSSL_OCSP_URL_OVERRIDE | WOLFSSL_OCSP_NO_NONCE) !=
	     WOLFSSL_SUCCESS ||
	     wolfSSL_CTX_SetOCSP_OverrideURL(ctx, "http://127.0.0.1/") != WOLFSSL_SUCCESS ||
	     wolfSSL_CTX_EnableOCSPStapling(ctx) != WOLFSSL_SUCCESS ||
	     /* After EnableOCSPStapling(), which installs the default lookup. */
	     wolfSSL_CTX_SetOCSP_Cb(ctx, ocsp_io_cb, ocsp_resp_free_cb, NULL) !=
	     WOLFSSL_SUCCESS)) {
		goto out;
	}

	fd = zsock_accept(listen_fd, NULL, NULL);
	if (fd < 0) {
		goto out;
	}

	ssl = wolfSSL_new(ctx);
	if (ssl != NULL && wolfSSL_set_fd(ssl, fd) == WOLFSSL_SUCCESS &&
	    wolfSSL_accept(ssl) == WOLFSSL_SUCCESS) {
		(void)wolfSSL_shutdown(ssl);
	}

out:
	wolfSSL_free(ssl);
	if (fd >= 0) {
		zsock_close(fd);
	}
	wolfSSL_CTX_free(ctx);
}

/* Returns 0 or the errno of a failed connect(), and the verify result. */
static int ocsp_connect(int peer_verify, bool staple, uint32_t *verify_result)
{
	static const sec_tag_t tags[] = { OCSP_CA_TAG };
	struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(OCSP_PORT) };
	socklen_t optlen = sizeof(*verify_result);
	int listen_fd, client_fd, yes = 1, ret, err = 0;

	zassert_equal(zsock_inet_pton(AF_INET, MY_IPV4_ADDR, &sa.sin_addr), 1);

	listen_fd = zsock_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	zassert_true(listen_fd >= 0, "socket() failed (%d)", errno);
	zassert_ok(zsock_setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes,
				    sizeof(yes)));
	zassert_ok(zsock_bind(listen_fd, (struct sockaddr *)&sa, sizeof(sa)));
	zassert_ok(zsock_listen(listen_fd, 1));

	(void)k_thread_create(&server_thread, ocsp_server_stack, OCSP_STACK_SIZE, ocsp_server_fn,
			      INT_TO_POINTER(listen_fd), INT_TO_POINTER(staple), NULL,
			      K_PRIO_PREEMPT(8), 0, K_NO_WAIT);

	client_fd = zsock_socket(AF_INET, SOCK_STREAM, IPPROTO_TLS_1_2);
	zassert_true(client_fd >= 0, "TLS socket() failed (%d)", errno);
	zassert_ok(zsock_setsockopt(client_fd, SOL_TLS, TLS_SEC_TAG_LIST, tags,
				    sizeof(tags)));
	zassert_ok(zsock_setsockopt(client_fd, SOL_TLS, TLS_HOSTNAME, "localhost",
				    sizeof("localhost")));
	zassert_ok(zsock_setsockopt(client_fd, SOL_TLS, TLS_PEER_VERIFY, &peer_verify,
				    sizeof(peer_verify)));

	ret = zsock_connect(client_fd, (struct sockaddr *)&sa, sizeof(sa));
	if (ret != 0) {
		err = errno;
	} else {
		*verify_result = UINT32_MAX;
		zassert_ok(zsock_getsockopt(client_fd, SOL_TLS, TLS_CERT_VERIFY_RESULT,
					    verify_result, &optlen));
	}

	zsock_close(client_fd);
	zassert_ok(k_thread_join(&server_thread, K_FOREVER));
	zsock_close(listen_fd);

	return err;
}

static void ocsp_expect(int peer_verify, bool staple, int want_err)
{
	uint32_t result = 0;
	int err = ocsp_connect(peer_verify, staple, &result);

	zassert_equal(err, want_err, "verify %d, staple %d: errno %d, want %d", peer_verify,
		      staple, err, want_err);
	if (err == 0) {
		zassert_equal(result, 0, "verify %d, staple %d: verify result 0x%x", peer_verify,
			      staple, result);
	}
}

ZTEST(net_socket_tls_ocsp, test_tls_ocsp_staple_required)
{
	ocsp_expect(TLS_PEER_VERIFY_REQUIRED, true, 0);
}

ZTEST(net_socket_tls_ocsp, test_tls_ocsp_staple_optional)
{
	ocsp_expect(TLS_PEER_VERIFY_OPTIONAL, true, 0);
}

ZTEST(net_socket_tls_ocsp, test_tls_ocsp_staple_none)
{
	ocsp_expect(TLS_PEER_VERIFY_NONE, true, 0);
}

ZTEST(net_socket_tls_ocsp, test_tls_ocsp_no_staple_required)
{
	ocsp_expect(TLS_PEER_VERIFY_REQUIRED, false,
		    IS_ENABLED(CONFIG_NET_SOCKETS_TLS_WOLFSSL_OCSP_MUST_STAPLE) ? ECONNABORTED : 0);
}

ZTEST(net_socket_tls_ocsp, test_tls_ocsp_no_staple_optional)
{
	ocsp_expect(TLS_PEER_VERIFY_OPTIONAL, false, 0);
}

ZTEST(net_socket_tls_ocsp, test_tls_ocsp_no_staple_none)
{
	ocsp_expect(TLS_PEER_VERIFY_NONE, false, 0);
}

static void *ocsp_setup(void)
{
	zassert_ok(tls_credential_add(OCSP_CA_TAG, TLS_CREDENTIAL_CA_CERTIFICATE, ocsp_ca,
				      sizeof(ocsp_ca)));
	return NULL;
}
#endif /* CONFIG_NET_SOCKETS_TLS_WOLFSSL_OCSP_STAPLING */

/* The suite's own TLS server cannot staple, so must-staple fails its handshakes. */
static bool tls_ext_predicate(const void *state)
{
	ARG_UNUSED(state);

	return !IS_ENABLED(CONFIG_NET_SOCKETS_TLS_WOLFSSL_OCSP_MUST_STAPLE);
}

/* Runs also after a failed test, which leaves its credentials behind */
static void tls_ext_after(void *fixture)
{
	ARG_UNUSED(fixture);

	tls_proto = IPPROTO_TLS_1_2;
	(void)tls_credential_delete(CLIENT_AUTH_TAG, TLS_CREDENTIAL_PUBLIC_CERTIFICATE);
	(void)tls_credential_delete(CLIENT_AUTH_TAG, TLS_CREDENTIAL_PRIVATE_KEY);
	(void)tls_credential_delete(EXT_PSK_TAG, TLS_CREDENTIAL_PSK);
	(void)tls_credential_delete(EXT_PSK_TAG, TLS_CREDENTIAL_PSK_ID);
	(void)tls_credential_delete(CHAIN_A_TAG, TLS_CREDENTIAL_PUBLIC_CERTIFICATE);
	(void)tls_credential_delete(CHAIN_B_TAG, TLS_CREDENTIAL_PUBLIC_CERTIFICATE);
	(void)tls_credential_delete(CHAIN_KEY_TAG, TLS_CREDENTIAL_PRIVATE_KEY);
	(void)tls_credential_delete(CHAIN_CA_TAG, TLS_CREDENTIAL_CA_CERTIFICATE);
	(void)tls_credential_delete(IP_SAN_CA_TAG, TLS_CREDENTIAL_CA_CERTIFICATE);
	(void)tls_credential_delete(IP_SAN_SERVER_TAG, TLS_CREDENTIAL_PUBLIC_CERTIFICATE);
	(void)tls_credential_delete(IP_SAN_SERVER_TAG, TLS_CREDENTIAL_PRIVATE_KEY);
}

ZTEST_SUITE(net_socket_tls_api_extension, tls_ext_predicate, setup, TLS_EXT_BEFORE,
	    tls_ext_after, NULL);

#if defined(CONFIG_NET_SOCKETS_TLS_WOLFSSL_OCSP_STAPLING)
ZTEST_SUITE(net_socket_tls_ocsp, NULL, ocsp_setup, TLS_EXT_BEFORE, NULL, NULL);
#endif
