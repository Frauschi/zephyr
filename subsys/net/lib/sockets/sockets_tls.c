/*
 * Copyright (c) 2018 Intel Corporation
 * Copyright (c) 2018 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdbool.h>
#include <stdlib.h>

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(net_sock_tls, CONFIG_NET_SOCKETS_LOG_LEVEL);

#include <zephyr/init.h>
#include <zephyr/sys/util.h>
#include <zephyr/net/net_log.h>
#include <zephyr/net/socket.h>
#include <zephyr/random/random.h>
#include <zephyr/internal/syscall_handler.h>
#include <zephyr/sys/fdtable.h>

/* TODO: Remove all direct access to private fields.
 * According with Mbed TLS migration guide:
 *
 * Direct access to fields of structures
 * (`struct` types) declared in public headers is no longer
 * supported. In Mbed TLS 3, the layout of structures is not
 * considered part of the stable API, and minor versions (3.1, 3.2,
 * etc.) may add, remove, rename, reorder or change the type of
 * structure fields.
 */
#if !defined(MBEDTLS_ALLOW_PRIVATE_ACCESS)
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#endif

#if defined(CONFIG_MBEDTLS)
#include <mbedtls/net_sockets.h>
#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/ssl.h>
#include <mbedtls/ssl_cookie.h>
#include <mbedtls/error.h>
#include <mbedtls/platform.h>
#include <mbedtls/ssl_cache.h>
#include <mbedtls/pk.h>
#if defined(MBEDTLS_PSA_CRYPTO_C) || defined(MBEDTLS_PSA_CRYPTO_CLIENT)
#include <psa/crypto.h>
/* Support for referencing a private key resident in PSA (TLS_CREDENTIAL_PRIVATE_KEY_PSA),
 * so that the key material never has to be exported into the credential store.
 */
#define TLS_PRIV_KEY_PSA_ENABLED 1
#endif

#define ZTLS_IS_CLIENT         MBEDTLS_SSL_IS_CLIENT
#define ZTLS_IS_SERVER         MBEDTLS_SSL_IS_SERVER
#define ZTLS_ERROR_WANT_READ   MBEDTLS_ERR_SSL_WANT_READ
#define ZTLS_ERROR_WANT_WRITE  MBEDTLS_ERR_SSL_WANT_WRITE

#endif /* CONFIG_MBEDTLS */

#include "sockets_internal.h"
#include "tls_internal.h"
#include "../../ip/net_private.h"

#if defined(CONFIG_NET_SOCKETS_TLS_SESSION_CACHE_PERSISTENT)
#include <zephyr/settings/settings.h>
#endif

#if defined(CONFIG_MBEDTLS_DEBUG)
#include <zephyr_mbedtls_priv.h>
#endif

#if defined(CONFIG_WOLFSSL) && defined(CONFIG_MBEDTLS)
#error "wolfSSL and mbedTLS TLS-socket backends are mutually exclusive; " \
       "enable exactly one of CONFIG_WOLFSSL / CONFIG_MBEDTLS."
#endif

#if defined(CONFIG_WOLFSSL)
/* wolfSSL's settings.h maps these names to zsock_*, which would rename the vtable members below */
#undef socket
#undef bind
#undef connect
#undef listen
#undef accept
#undef send
#undef recv
#undef sendto
#undef recvfrom
#undef setsockopt
#undef getsockopt
#undef shutdown
#undef getpeername
#undef getsockname

#ifndef WOLFSSL_USER_SETTINGS
#include <user_settings.h>
#endif /* !WOLFSSL_USER_SETTINGS */
#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/memory.h>
#include <zephyr/net/tls_verify.h>

#undef socket
#undef bind
#undef connect
#undef listen
#undef accept
#undef send
#undef recv
#undef sendto
#undef recvfrom
#undef setsockopt
#undef getsockopt
#undef shutdown
#undef getpeername
#undef getsockname

/* Without it a valid chain never reaches the verify callback and skips the CN/SAN match. */
#if !defined(WOLFSSL_ALWAYS_VERIFY_CB)
#error "Zephyr TLS sockets with wolfSSL require WOLFSSL_ALWAYS_VERIFY_CB: " \
       "define it in CONFIG_WOLFSSL_SETTINGS_FILE, or leave that unset and " \
       "enable CONFIG_WOLFSSL_ALWAYS_VERIFY_CB"
#endif /* !WOLFSSL_ALWAYS_VERIFY_CB */

#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS) && !defined(WOLFSSL_DTLS)
#error "DTLS sockets need wolfSSL WOLFSSL_DTLS: define it in " \
       "CONFIG_WOLFSSL_SETTINGS_FILE, or leave that unset and enable " \
       "CONFIG_WOLFSSL_DTLS"
#endif /* CONFIG_NET_SOCKETS_ENABLE_DTLS && !WOLFSSL_DTLS */

/* WOLFCRYPT_ONLY compiles the wolfSSL TLS layer out, so nothing below would link */
#if defined(WOLFCRYPT_ONLY)
#error "Zephyr TLS sockets need the wolfSSL TLS layer: drop WOLFCRYPT_ONLY " \
       "from CONFIG_WOLFSSL_SETTINGS_FILE, or leave that unset and disable " \
       "CONFIG_WOLFSSL_CRYPTO_ONLY"
#endif /* WOLFCRYPT_ONLY */

#if defined(CONFIG_NET_SOCKETS_TLS_WOLFSSL_OCSP_STAPLING) && \
    (!defined(HAVE_OCSP) || !defined(HAVE_CERTIFICATE_STATUS_REQUEST))
#error "OCSP stapling on TLS sockets needs HAVE_OCSP and " \
       "HAVE_CERTIFICATE_STATUS_REQUEST: define them in " \
       "CONFIG_WOLFSSL_SETTINGS_FILE, or leave that unset and enable " \
       "CONFIG_WOLFSSL_OCSP and CONFIG_WOLFSSL_OCSP_STAPLING"
#endif /* CONFIG_NET_SOCKETS_TLS_WOLFSSL_OCSP_STAPLING */

#if defined(CONFIG_NET_SOCKETS_TLS_WOLFSSL_OCSP_STAPLING) && defined(NO_WOLFSSL_CLIENT)
#error "OCSP stapling on TLS sockets is client-only, but wolfSSL defines NO_WOLFSSL_CLIENT"
#endif

/* wolfSSL drops its session API under NO_SESSION_CACHE, and serialisation without EXT_CACHE. */
#if defined(HAVE_EXT_CACHE) && !defined(NO_SESSION_CACHE)
#define ZTLS_WOLFSSL_EXT_CACHE
#endif

#if defined(HAVE_MAX_FRAGMENT) && !defined(NO_WOLFSSL_CLIENT) && \
	defined(CONFIG_NET_SOCKETS_TLS_SET_MAX_FRAGMENT_LENGTH)
#define ZTLS_WOLFSSL_MAX_FRAGMENT
#endif

#define ZTLS_IS_CLIENT        0
#define ZTLS_IS_SERVER        1
#define ZTLS_ERROR_WANT_READ  WOLFSSL_ERROR_WANT_READ
#define ZTLS_ERROR_WANT_WRITE WOLFSSL_ERROR_WANT_WRITE

/* DTLS default timeout values, copied from mbedtls to replicate existing default behavior */
/*
 * Default range for DTLS retransmission timer value, in milliseconds.
 * RFC 6347 4.2.4.1 says from 1 second to 60 seconds.
 */
#define DTLS_TIMEOUT_DFL_MIN    1000
#define DTLS_TIMEOUT_DFL_MAX   60000
#endif /* CONFIG_WOLFSSL */

#define LOG_ADDR_PORT_HELPER(addr)                                \
	(addr)->sa_family == NET_AF_INET ?                        \
		net_sprint_ipv4_addr(&net_sin(addr)->sin_addr) :  \
		net_sprint_ipv6_addr(&net_sin6(addr)->sin6_addr), \
	(addr)->sa_family == NET_AF_INET ?                        \
		net_ntohs(net_sin(addr)->sin_port) :              \
		net_ntohs(net_sin6(addr)->sin6_port)

#if defined(CONFIG_NET_SOCKETS_TLS_MAX_APP_PROTOCOLS)
#define ALPN_MAX_PROTOCOLS (CONFIG_NET_SOCKETS_TLS_MAX_APP_PROTOCOLS + 1)
#else
#define ALPN_MAX_PROTOCOLS 0
#endif /* CONFIG_NET_SOCKETS_TLS_MAX_APP_PROTOCOLS */

#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
#define DTLS_SENDMSG_BUF_SIZE (CONFIG_NET_SOCKETS_DTLS_SENDMSG_BUF_SIZE)

#if defined(CONFIG_MBEDTLS_SSL_DTLS_CONNECTION_ID)
#define DTLS_CID_CHECK_BUF_SIZE (MBEDTLS_SSL_IN_CONTENT_LEN)
#else
#define DTLS_CID_CHECK_BUF_SIZE 0
#endif /* CONFIG_MBEDTLS_SSL_DTLS_CONNECTION_ID */

#else
#define DTLS_SENDMSG_BUF_SIZE 0
#define DTLS_CID_CHECK_BUF_SIZE 0
#endif /* CONFIG_NET_SOCKETS_ENABLE_DTLS */

static const struct socket_op_vtable tls_sock_fd_op_vtable;

#ifndef MBEDTLS_ERR_SSL_PEER_VERIFY_FAILED
#define MBEDTLS_ERR_SSL_PEER_VERIFY_FAILED MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE
#endif

/** A list of secure tags that TLS context should use. */
struct sec_tag_list {
	/** An array of secure tags referencing TLS credentials. */
	sec_tag_t sec_tags[CONFIG_NET_SOCKETS_TLS_MAX_CREDENTIALS];

	/** Number of configured secure tags. */
	int sec_tag_count;
};

/** Timer context for DTLS. */
struct dtls_timing_context {
	/** Current time, stored during timer set. */
	uint32_t snapshot;

	/** Intermediate delay value. For details, refer to Mbed TLS API
	 *  documentation (mbedtls_ssl_set_timer_t).
	 */
	uint32_t int_ms;

	/** Final delay value. For details, refer to Mbed TLS API documentation
	 *  (mbedtls_ssl_set_timer_t).
	 */
	uint32_t fin_ms;
};

/** TLS peer address/session ID mapping. */
struct tls_session_cache {
	/** Creation time. */
	int64_t timestamp;

	/** Peer address. */
	struct net_sockaddr_storage peer_addr;

	/** Session buffer. */
	uint8_t *session;

	/** Session length. */
	size_t session_len;
};

#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS) && defined(CONFIG_MBEDTLS)
struct tls_dtls_cid {
	bool enabled;
	unsigned char cid[MAX(MBEDTLS_SSL_CID_OUT_LEN_MAX,
			      MBEDTLS_SSL_CID_IN_LEN_MAX)];
	size_t cid_len;
};
#endif /* CONFIG_NET_SOCKETS_ENABLE_DTLS && CONFIG_MBEDTLS */

struct tls_session_context {
	sys_snode_t node;

	/* Handshake completion time. */
	int64_t handshake_timestamp;

	/* Information whether TLS handshake is currently in progress. */
	bool handshake_in_progress : 1;

	/* Session ended at the TLS/DTLS level. */
	bool session_closed : 1;

	/* Information whether TLS handshake is complete or not. */
	struct k_sem tls_established;

#if defined(CONFIG_MBEDTLS)
	/* Mbed TLS context. */
	mbedtls_ssl_context ssl;
#endif /* CONFIG_MBEDTLS */

#if defined(CONFIG_WOLFSSL)
	/* Created on session init, since it needs the per-socket WOLFSSL_CTX */
	WOLFSSL *wssl;

	/* Lets a verify callback reach the context of the session it verifies */
	struct tls_context *tls_ctx;

	/* Accumulated mbedTLS-compatible verify result flags for the
	 * handshake performed on this session.
	 */
	uint32_t verify_result_flags;
#endif /* CONFIG_WOLFSSL */

#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
#if defined(CONFIG_MBEDTLS)
	/* Context information for DTLS timing. */
	struct dtls_timing_context dtls_timing;
#endif /* CONFIG_MBEDTLS */

	/* DTLS peer address. */
	struct net_sockaddr_storage dtls_peer_addr;

	/* DTLS peer address length. */
	net_socklen_t dtls_peer_addrlen;

	/* The local address this session's data came in on (server side only). */
	struct net_sockaddr_storage dtls_local_addr;

	/* DTLS session expiry time (server only). */
	k_timepoint_t session_expiry;
#endif /* CONFIG_NET_SOCKETS_ENABLE_DTLS */
};

/** TLS context information. */
__net_socket struct tls_context {
	/** Underlying TCP/UDP socket. */
	int sock;

	/** Information whether TLS context is used. */
	bool is_used : 1;

	/** Information whether TLS context was initialized. */
	bool is_initialized : 1;

	/** Information whether underlying socket is listening. */
	bool is_listening : 1;

#if defined(CONFIG_WOLFSSL)
	/** The read side was shut down; unlike session_closed, send() still works. */
	bool recv_eof : 1;

	/* TLS_HOSTNAME on a server socket warns once per socket */
	bool server_hostname_warned : 1;

	/* Set when the application chose TLS_DTLS_ROLE; tls_wolfssl_init() derives it otherwise */
	bool role_set : 1;
#endif /* CONFIG_WOLFSSL */

	/* TLS sessions associated with this socket. In most cases there will
	 * be one session allocated per TLS context. DTLS server is an exception,
	 * which can have multiple TLS sessions allocated at the same time.
	 */
	sys_slist_t sessions;

	/* Currently active TLS session. For a TLS context in use, this should
	 * always point to a valid session instance.
	 */
	struct tls_session_context *active_session;

	/** Socket type. */
	enum net_sock_type type;

	/** Secure protocol version running on TLS context. */
	enum net_ip_protocol_secure tls_version;

	/** Socket flags passed to a socket call. */
	int flags;

	/* Indicates whether socket is in error state at TLS/DTLS level. */
	int error;

	/* TLS socket mutex lock. */
	struct k_mutex *lock;

	/** TLS specific option values. */
	struct {
		/** Select which credentials to use with TLS. */
		struct sec_tag_list sec_tag_list;

		/** 0-terminated list of allowed ciphersuites (Mbed TLS format).
		 */
		int ciphersuites[CONFIG_NET_SOCKETS_TLS_MAX_CIPHERSUITES + 1];

		/** Information if hostname was explicitly set on a socket. */
		bool is_hostname_set;

		/** Peer verification level. */
		int8_t verify_level;

		/** Indicating on whether DER certificates should not be copied
		 * to the heap.
		 */
		int8_t cert_nocopy;

		/** DTLS role, client by default. */
		int8_t role;

		/** Per-socket MFL override for ZSOCK_TLS_MAX_FRAGMENT_LENGTH.
		 *  -1: use global Kconfig-derived value (default), also
		 *      settable via ZSOCK_TLS_MFL_DEFAULT to reset an
		 *      already overridden socket back to the global value.
		 *   0: disable MFL extension (ZSOCK_TLS_MFL_DISABLED).
		 *  1-4: ZSOCK_TLS_MFL_512 through ZSOCK_TLS_MFL_4096.
		 */
		int8_t mfl_code;

		/** NULL-terminated list of allowed application layer
		 * protocols.
		 */
		const char *alpn_list[ALPN_MAX_PROTOCOLS];

		/** Session cache enabled on a socket. */
		bool cache_enabled;

		/** Socket TX timeout */
		k_timeout_t timeout_tx;

		/** Socket RX timeout */
		k_timeout_t timeout_rx;

#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
		/* DTLS handshake timeout */
		uint32_t dtls_handshake_timeout_min;
		uint32_t dtls_handshake_timeout_max;

#if defined(CONFIG_MBEDTLS)
		struct tls_dtls_cid dtls_cid;
#endif

		bool dtls_handshake_on_connect;
#endif /* CONFIG_NET_SOCKETS_ENABLE_DTLS */

#if defined(CONFIG_NET_SOCKETS_TLS_CERT_VERIFY_CALLBACK) && \
	!defined(CONFIG_WOLFSSL)
		struct zsock_tls_cert_verify_cb cert_verify;
#endif /* CONFIG_NET_SOCKETS_TLS_CERT_VERIFY_CALLBACK && !CONFIG_WOLFSSL */
#if defined(CONFIG_NET_SOCKETS_TLS_WOLFSSL_VERIFY_CALLBACK)
		struct zsock_tls_cert_verify_cb_wolfssl cert_verify_wolfssl;
#endif /* CONFIG_NET_SOCKETS_TLS_WOLFSSL_VERIFY_CALLBACK */
	} options;

#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS) && defined(CONFIG_MBEDTLS)
	/** Mbed TLS cookie context for DTLS */
	mbedtls_ssl_cookie_ctx cookie;
#endif /* CONFIG_NET_SOCKETS_ENABLE_DTLS && CONFIG_MBEDTLS */

#if defined(CONFIG_WOLFSSL)
	/** The wolfSSL context */
	WOLFSSL_CTX *ctx;

	/** The hostname to use as the SNI */
	byte *host_name;

	/* Length in bytes of the host_name */
	word32 host_len;

#if defined(HAVE_ALPN)
	/* TLS_ALPN_LIST as the comma separated list wolfSSL_UseALPN() takes */
	char *alpn_joined;
#endif /* HAVE_ALPN */

#ifndef NO_PSK
	/* The Pre Shared Key to be used */
	byte *psk;

	/* Length in bytes of the Pre Shared Key data */
	word32 psk_len;

	/* The Identity associated with the value in psk */
	byte *psk_id;

	/* The Length in bytes of the psk identity */
	word32 psk_id_len;
#endif /* !NO_PSK */
#endif /* CONFIG_WOLFSSL */

#if defined(CONFIG_MBEDTLS)
	/** Mbed TLS configuration. */
	mbedtls_ssl_config config;

#if defined(CONFIG_MBEDTLS_X509_CRT_PARSE_C)
	/** Mbed TLS structure for CA chain. */
	mbedtls_x509_crt ca_chain;

	/** Mbed TLS structure for own certificate. */
	mbedtls_x509_crt own_cert;

	/** Mbed TLS structure for own private key. */
	mbedtls_pk_context priv_key;
#endif /* CONFIG_MBEDTLS_X509_CRT_PARSE_C */
#endif /* CONFIG_MBEDTLS */
};

#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
#define DTLS_HELPER_BUF_SIZE MAX(DTLS_SENDMSG_BUF_SIZE, DTLS_CID_CHECK_BUF_SIZE)
static uint8_t dtls_helper_buf[DTLS_HELPER_BUF_SIZE];
static K_MUTEX_DEFINE(dtls_helper_buf_lock);
#endif

/* A global pool of TLS contexts. */
static struct tls_context tls_contexts[CONFIG_NET_SOCKETS_TLS_MAX_CONTEXTS];
K_MEM_SLAB_DEFINE_STATIC_TYPE(tls_session_contexts, struct tls_session_context,
			      CONFIG_NET_SOCKETS_TLS_MAX_SESSION_CONTEXTS);

BUILD_ASSERT(CONFIG_NET_SOCKETS_TLS_MAX_SESSION_CONTEXTS >= CONFIG_NET_SOCKETS_TLS_MAX_CONTEXTS,
	     "CONFIG_NET_SOCKETS_TLS_MAX_SESSION_CONTEXTS cannot be smaller than "
	     "CONFIG_NET_SOCKETS_TLS_MAX_CONTEXTS");

/* wolfSSL can fill the client cache only through session export. */
#if defined(CONFIG_MBEDTLS) || \
    (defined(CONFIG_WOLFSSL) && defined(ZTLS_WOLFSSL_EXT_CACHE))
#define TLS_SESSION_CACHE_PRESENT 1
#else
#define TLS_SESSION_CACHE_PRESENT 0
#endif

#if TLS_SESSION_CACHE_PRESENT
static struct tls_session_cache client_cache[CONFIG_NET_SOCKETS_TLS_MAX_CLIENT_SESSION_COUNT];
#endif

/* A mutex for protecting access to the client session cache. */
static K_MUTEX_DEFINE(session_cache_lock);

#if defined(MBEDTLS_SSL_CACHE_C)
static mbedtls_ssl_cache_context server_cache;
#endif

#if defined(CONFIG_NET_SOCKETS_TLS_SESSION_CACHE_PERSISTENT)

#define TLS_SETTINGS_PREFIX CONFIG_NET_SOCKETS_TLS_SESSION_CACHE_PERSISTENT_PREFIX

static int tls_session_cache_settings_set(const char *key, size_t len, settings_read_cb read_cb,
					  void *cb_arg)
{
	const char *next;
	size_t name_len;
	long idx;
	ssize_t rc;
	char *end;

	name_len = settings_name_next(key, &next);
	if (next == NULL) {
		return -ENOENT;
	}

	idx = strtol(key, &end, 10);
	if (end != key + name_len || idx < 0 ||
	    idx >= CONFIG_NET_SOCKETS_TLS_MAX_CLIENT_SESSION_COUNT) {
		return -ENOENT;
	}

	k_mutex_lock(&session_cache_lock, K_FOREVER);

	if (strcmp(next, "addr") == 0) {
		if (len != sizeof(struct net_sockaddr_storage)) {
			rc = -EINVAL;
			goto out;
		}
		rc = read_cb(cb_arg, &client_cache[idx].peer_addr, len);
		if (rc < 0) {
			goto out;
		}
		client_cache[idx].timestamp = k_uptime_get();
	} else if (strcmp(next, "data") == 0) {
		uint8_t *buf = mbedtls_calloc(1, len);

		if (buf == NULL) {
			NET_ERR("TLS session alloc failed for slot %ld", idx);
			rc = -ENOMEM;
			goto out;
		}
		rc = read_cb(cb_arg, buf, len);
		if (rc < 0) {
			mbedtls_free(buf);
			goto out;
		}
		if (client_cache[idx].session != NULL) {
			mbedtls_free(client_cache[idx].session);
		}
		client_cache[idx].session = buf;
		client_cache[idx].session_len = len;
		NET_DBG("TLS session %ld restored from settings", idx);
	} else {
		rc = -ENOENT;
		goto out;
	}

	rc = 0;

out:
	k_mutex_unlock(&session_cache_lock);

	return rc;
}

SETTINGS_STATIC_HANDLER_DEFINE(tls_session_cache, TLS_SETTINGS_PREFIX, NULL,
			       tls_session_cache_settings_set, NULL, NULL);

/* Must be called with session_cache_lock held. */
static void tls_session_cache_settings_save(int idx)
{
	char key[32];

	if (client_cache[idx].session == NULL) {
		return;
	}

	snprintk(key, sizeof(key), TLS_SETTINGS_PREFIX "/%d/addr", idx);
	settings_save_one(key, &client_cache[idx].peer_addr, sizeof(client_cache[idx].peer_addr));

	snprintk(key, sizeof(key), TLS_SETTINGS_PREFIX "/%d/data", idx);
	settings_save_one(key, client_cache[idx].session, client_cache[idx].session_len);

	NET_DBG("TLS session %d saved to settings", idx);
}

static void tls_session_cache_settings_load(void)
{
	int rc;

	rc = settings_subsys_init();
	if (rc) {
		NET_ERR("TLS session cache: settings_subsys_init failed (%d)", rc);
		return;
	}

	rc = settings_load_subtree(TLS_SETTINGS_PREFIX);
	if (rc) {
		NET_ERR("TLS session cache: settings_load_subtree failed (%d)", rc);
	}
}

static void tls_session_cache_settings_clear(void)
{
	char key[32];

	for (int i = 0; i < CONFIG_NET_SOCKETS_TLS_MAX_CLIENT_SESSION_COUNT; i++) {
		snprintk(key, sizeof(key), TLS_SETTINGS_PREFIX "/%d/addr", i);
		settings_delete(key);
		snprintk(key, sizeof(key), TLS_SETTINGS_PREFIX "/%d/data", i);
		settings_delete(key);
	}
}

#endif /* CONFIG_NET_SOCKETS_TLS_SESSION_CACHE_PERSISTENT */

/* A mutex for protecting TLS context allocation. */
static K_MUTEX_DEFINE(context_lock);

/* Arbitrary delay value to wait if Mbed TLS reports it cannot proceed for
 * reasons other than TX/RX block.
 */
#define TLS_WAIT_MS 100

static int tls_release(struct tls_context *tls);
#if defined(CONFIG_MBEDTLS)
static int tls_mbedtls_reset_session(struct tls_context *context);
#endif
#if defined(CONFIG_WOLFSSL)
static int tls_wolfssl_reset_session(struct tls_context *context);
#endif

#if defined(CONFIG_MBEDTLS)
static void tls_session_cache_reset(void)
{
	k_mutex_lock(&session_cache_lock, K_FOREVER);

	for (int i = 0; i < ARRAY_SIZE(client_cache); i++) {
		if (client_cache[i].session != NULL) {
			mbedtls_free(client_cache[i].session);
		}
	}

	(void)memset(client_cache, 0, sizeof(client_cache));

	k_mutex_unlock(&session_cache_lock);
}
#elif defined(CONFIG_WOLFSSL) && defined(ZTLS_WOLFSSL_EXT_CACHE)
static void tls_session_cache_reset(void)
{
	k_mutex_lock(&session_cache_lock, K_FOREVER);
	for (int i = 0; i < ARRAY_SIZE(client_cache); i++) {
		if (client_cache[i].session != NULL) {
			/* The serialized session holds the resumption secret */
			wc_ForceZero(client_cache[i].session,
				     client_cache[i].session_len);
			XFREE(client_cache[i].session, NULL,
			      DYNAMIC_TYPE_TMP_BUFFER);
		}
	}

	(void)memset(client_cache, 0, sizeof(client_cache));
	k_mutex_unlock(&session_cache_lock);
}
#endif

#if defined(CONFIG_WOLFSSL) && defined(WOLFSSL_TLS13) && !defined(NO_PSK)
/* TLS 1.3 binds a PSK to one hash, so every PSK handshake uses this suite */
static const char tls13_psk_default_ciphersuite[] =
	CONFIG_NET_SOCKETS_TLS_WOLFSSL_PSK_TLS13_CIPHERSUITE;
#endif /* CONFIG_WOLFSSL && WOLFSSL_TLS13 && !NO_PSK */

bool net_socket_is_tls(void *obj)
{
	return PART_OF_ARRAY(tls_contexts, (struct tls_context *)obj);
}

#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
#if defined(CONFIG_MBEDTLS)
/* Mbed TLS-defined function for setting timer. */
static void dtls_timing_set_delay(void *data, uint32_t int_ms, uint32_t fin_ms)
{
	struct dtls_timing_context *ctx = data;

	ctx->int_ms = int_ms;
	ctx->fin_ms = fin_ms;

	if (fin_ms != 0U) {
		ctx->snapshot = k_uptime_get_32();
	}
}

/* Mbed TLS-defined function for getting timer status.
 * The return values are specified by Mbed TLS. The callback must return:
 *   -1 if cancelled (fin_ms == 0),
 *    0 if none of the delays have passed,
 *    1 if only the intermediate delay has passed,
 *    2 if the final delay has passed.
 */
static int dtls_timing_get_delay(void *data)
{
	struct dtls_timing_context *timing = data;
	unsigned long elapsed_ms;

	NET_ASSERT(timing);

	if (timing->fin_ms == 0U) {
		return -1;
	}

	elapsed_ms = k_uptime_get_32() - timing->snapshot;

	if (elapsed_ms >= timing->fin_ms) {
		return 2;
	}

	if (elapsed_ms >= timing->int_ms) {
		return 1;
	}

	return 0;
}

static int dtls_get_remaining_timeout(struct tls_session_context *session_ctx)
{
	struct dtls_timing_context *timing = &session_ctx->dtls_timing;
	uint32_t elapsed_ms;

	elapsed_ms = k_uptime_get_32() - timing->snapshot;

	if (timing->fin_ms == 0U) {
		return SYS_FOREVER_MS;
	}

	if (elapsed_ms >= timing->fin_ms) {
		return 0;
	}

	return timing->fin_ms - elapsed_ms;
}
#endif /* CONFIG_MBEDTLS */

static void dtls_server_init_session_timeout(struct tls_session_context *session_ctx)
{
	session_ctx->session_expiry = sys_timepoint_calc(K_FOREVER);
}

static void dtls_server_refresh_session_timeout(struct tls_session_context *session_ctx)
{
	session_ctx->session_expiry =
		sys_timepoint_calc(K_MSEC(CONFIG_NET_SOCKETS_DTLS_TIMEOUT));
}
#endif /* CONFIG_NET_SOCKETS_ENABLE_DTLS */

/* Initialize TLS internals. */
static int tls_init(void)
{

#if !defined(CONFIG_ENTROPY_HAS_DRIVER)
	NET_WARN("No entropy device on the system, "
		 "TLS communication is insecure!");
#endif

	(void)memset(tls_contexts, 0, sizeof(tls_contexts));
#if TLS_SESSION_CACHE_PRESENT
	(void)memset(client_cache, 0, sizeof(client_cache));
#endif

#if defined(MBEDTLS_SSL_CACHE_C)
	mbedtls_ssl_cache_init(&server_cache);
#endif

#if defined(CONFIG_NET_SOCKETS_TLS_SESSION_CACHE_PERSISTENT)
	tls_session_cache_settings_load();
#endif
#if defined(CONFIG_WOLFSSL) && defined(WOLFSSL_TLS13) && !defined(NO_PSK)
	/* SYS_INIT ignores the return value, so only the assert stops a bad ciphersuite at boot */
	{
		byte cs0, cs1;
		int  cs_flags = 0;
		int  cs_ret = wolfSSL_get_cipher_suite_from_name(
				tls13_psk_default_ciphersuite,
				&cs0, &cs1, &cs_flags);

		__ASSERT(cs_ret == 0,
			 "CONFIG_NET_SOCKETS_TLS_WOLFSSL_PSK_TLS13_CIPHERSUITE "
			 "is not a wolfSSL-recognized TLS 1.3 suite: \"%s\"",
			 tls13_psk_default_ciphersuite);
		if (cs_ret != 0) {
			NET_ERR("CONFIG_NET_SOCKETS_TLS_WOLFSSL_PSK_TLS13_CIPHERSUITE "
				"is not a wolfSSL-recognized TLS 1.3 suite: \"%s\"",
				tls13_psk_default_ciphersuite);
			return -EINVAL;
		}
	}
#endif /* CONFIG_WOLFSSL && WOLFSSL_TLS13 && !NO_PSK */

	return 0;
}

SYS_INIT(tls_init, APPLICATION, CONFIG_KERNEL_INIT_PRIORITY_DEFAULT);

static inline bool is_handshake_complete(struct tls_session_context *session_ctx)
{
	return k_sem_count_get(&session_ctx->tls_established) != 0;
}

/*
 * Copied from include/mbedtls/ssl_internal.h
 *
 * Maximum length we can advertise as our max content length for
 * RFC 6066 max_fragment_length extension negotiation purposes
 * (the lesser of both sizes, if they are unequal.)
 */
#define MBEDTLS_TLS_EXT_ADV_CONTENT_LEN (                            \
	(MBEDTLS_SSL_IN_CONTENT_LEN > MBEDTLS_SSL_OUT_CONTENT_LEN)   \
	? (MBEDTLS_SSL_OUT_CONTENT_LEN)				     \
	: (MBEDTLS_SSL_IN_CONTENT_LEN)				     \
	)

#if defined(CONFIG_NET_SOCKETS_TLS_SET_MAX_FRAGMENT_LENGTH) &&	\
	defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)

BUILD_ASSERT(MBEDTLS_TLS_EXT_ADV_CONTENT_LEN >= 512,
	     "Too small content length!");

static inline unsigned char tls_mfl_code_from_content_len(size_t len)
{
	if (len >= 4096) {
		return MBEDTLS_SSL_MAX_FRAG_LEN_4096;
	} else if (len >= 2048) {
		return MBEDTLS_SSL_MAX_FRAG_LEN_2048;
	} else if (len >= 1024) {
		return MBEDTLS_SSL_MAX_FRAG_LEN_1024;
	} else if (len >= 512) {
		return MBEDTLS_SSL_MAX_FRAG_LEN_512;
	} else {
		return MBEDTLS_SSL_MAX_FRAG_LEN_INVALID;
	}
}

static inline void tls_set_max_frag_len(struct tls_context *context, enum net_sock_type type)
{
	unsigned char mfl_code;
	size_t len;

	if (context->options.mfl_code > ZSOCK_TLS_MFL_DISABLED) {
		/* Per-socket override: codes 1-4 map directly to mbedTLS codes. */
		mbedtls_ssl_conf_max_frag_len(&context->config,
					      (unsigned char)context->options.mfl_code);
		return;
	} else if (context->options.mfl_code == ZSOCK_TLS_MFL_DISABLED) {
		/* Explicitly disabled: leave conf->mfl_code at its default NONE,
		 * which suppresses the extension in ClientHello.
		 */
		return;
	}

	/* mfl_code == -1: fall back to global Kconfig-derived value. */
	len = MBEDTLS_TLS_EXT_ADV_CONTENT_LEN;

#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
	if (type == NET_SOCK_DGRAM && len > CONFIG_NET_SOCKETS_DTLS_MAX_FRAGMENT_LENGTH) {
		len = CONFIG_NET_SOCKETS_DTLS_MAX_FRAGMENT_LENGTH;
	}
#endif
	mfl_code = tls_mfl_code_from_content_len(len);

	mbedtls_ssl_conf_max_frag_len(&context->config, mfl_code);
}
#else
#if defined(CONFIG_MBEDTLS)
static inline void tls_set_max_frag_len(struct tls_context *context, enum net_sock_type type) {}
#endif
#endif

static struct tls_session_context *tls_session_alloc(void)
{
	struct tls_session_context *session_ctx = NULL;

	if (k_mem_slab_alloc(&tls_session_contexts, (void **)&session_ctx,
			     K_NO_WAIT) != 0) {
		NET_WARN("Failed to allocate TLS session context");
		return NULL;
	}

	(void)memset(session_ctx, 0, sizeof(*session_ctx));
	(void)k_sem_init(&session_ctx->tls_established, 0, 1);
#if defined(CONFIG_MBEDTLS)
	mbedtls_ssl_init(&session_ctx->ssl);
#endif
	/* wssl is created in tls_wolfssl_session_init, once the WOLFSSL_CTX exists */

	return session_ctx;
}

static void tls_session_free(struct tls_session_context *session_ctx)
{
#if defined(CONFIG_MBEDTLS)
	mbedtls_ssl_free(&session_ctx->ssl);
#endif
#if defined(CONFIG_WOLFSSL)
	if (session_ctx->wssl != NULL) {
		/* wolfSSL_shutdown before the handshake completes can corrupt global state */
		if (wolfSSL_is_init_finished(session_ctx->wssl) &&
		    !(wolfSSL_get_shutdown(session_ctx->wssl) & WOLFSSL_SENT_SHUTDOWN)) {
			(void)wolfSSL_shutdown(session_ctx->wssl);
		}
		wolfSSL_free(session_ctx->wssl);
		session_ctx->wssl = NULL;
	}
#endif /* CONFIG_WOLFSSL */
	k_mem_slab_free(&tls_session_contexts, (void *)session_ctx);
}

/* Allocate TLS context. */
static struct tls_context *tls_alloc(void)
{
	int i;
	struct tls_context *tls = NULL;

	k_mutex_lock(&context_lock, K_FOREVER);

	for (i = 0; i < ARRAY_SIZE(tls_contexts); i++) {
		if (!tls_contexts[i].is_used) {
			tls = &tls_contexts[i];

			(void)memset(tls, 0, sizeof(*tls));

			/* Allocate initial (and in most cases the only) session context */
			tls->active_session = tls_session_alloc();
			if (tls->active_session == NULL) {
				tls = NULL;
				break;
			}

			tls->is_used = true;
			tls->options.verify_level = -1;
			tls->options.mfl_code = -1;
			tls->options.timeout_tx = K_FOREVER;
			tls->options.timeout_rx = K_FOREVER;
			tls->sock = -1;

			sys_slist_init(&tls->sessions);
			sys_slist_append(&tls->sessions, &tls->active_session->node);

			NET_DBG("Allocated TLS context, %p", tls);
			break;
		}
	}

	k_mutex_unlock(&context_lock);

	if (tls) {
#if defined(CONFIG_WOLFSSL)
#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
		tls->options.dtls_handshake_timeout_min =
			DTLS_TIMEOUT_DFL_MIN;
		tls->options.dtls_handshake_timeout_max =
			DTLS_TIMEOUT_DFL_MAX;
		tls->options.dtls_handshake_on_connect = true;
#endif /* CONFIG_NET_SOCKETS_ENABLE_DTLS */
#else
		mbedtls_ssl_config_init(&tls->config);
#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
		mbedtls_ssl_cookie_init(&tls->cookie);
		tls->options.dtls_handshake_timeout_min =
			MBEDTLS_SSL_DTLS_TIMEOUT_DFL_MIN;
		tls->options.dtls_handshake_timeout_max =
			MBEDTLS_SSL_DTLS_TIMEOUT_DFL_MAX;
		tls->options.dtls_cid.cid_len = 0;
		tls->options.dtls_cid.enabled = false;
		tls->options.dtls_handshake_on_connect = true;
#endif
#if defined(CONFIG_MBEDTLS_X509_CRT_PARSE_C)
		mbedtls_x509_crt_init(&tls->ca_chain);
		mbedtls_x509_crt_init(&tls->own_cert);
		mbedtls_pk_init(&tls->priv_key);
#endif

#if defined(CONFIG_MBEDTLS_DEBUG)
		mbedtls_ssl_conf_dbg(&tls->config, zephyr_mbedtls_debug, NULL);
#endif
#endif /* CONFIG_WOLFSSL */
	} else {
		NET_WARN("Failed to allocate TLS context");
	}

	return tls;
}

/* Allocate new TLS context and copy the content from the source context. */
static struct tls_context *tls_clone(struct tls_context *source_tls)
{
	struct tls_context *target_tls;

	target_tls = tls_alloc();
	if (!target_tls) {
		return NULL;
	}

	target_tls->tls_version = source_tls->tls_version;
	target_tls->type = source_tls->type;

	memcpy(&target_tls->options, &source_tls->options,
	       sizeof(target_tls->options));

#if defined(CONFIG_WOLFSSL)
	if (target_tls->options.is_hostname_set && source_tls->host_name) {
		target_tls->host_name = XMALLOC(source_tls->host_len + 1,
						NULL, DYNAMIC_TYPE_TMP_BUFFER);
		if (target_tls->host_name == NULL) {
			tls_release(target_tls);
			return NULL;
		}

		XMEMCPY(target_tls->host_name, source_tls->host_name,
			 source_tls->host_len + 1);
		target_tls->host_len = source_tls->host_len;
	}

#if defined(HAVE_ALPN)
	if (source_tls->alpn_joined != NULL) {
		size_t len = XSTRLEN(source_tls->alpn_joined) + 1;

		target_tls->alpn_joined = XMALLOC(len, NULL, DYNAMIC_TYPE_TMP_BUFFER);
		if (target_tls->alpn_joined == NULL) {
			tls_release(target_tls);
			return NULL;
		}

		XMEMCPY(target_tls->alpn_joined, source_tls->alpn_joined, len);
	}
#endif /* HAVE_ALPN */
#elif defined(CONFIG_MBEDTLS_X509_CRT_PARSE_C)
	if (target_tls->options.is_hostname_set) {
		mbedtls_ssl_set_hostname(&target_tls->active_session->ssl,
					 source_tls->active_session->ssl.hostname);
	}
#endif /* CONFIG_WOLFSSL */

	return target_tls;
}

/* Release TLS context. */
static int tls_release(struct tls_context *tls)
{
	sys_snode_t *node;

	if (!PART_OF_ARRAY(tls_contexts, tls)) {
		NET_ERR("Invalid TLS context");
		return -EBADF;
	}

	if (!tls->is_used) {
		NET_ERR("Deallocating unused TLS context");
		return -EBADF;
	}

#if defined(CONFIG_WOLFSSL)
	if (NULL != tls->host_name) {
		XFREE(tls->host_name, NULL, DYNAMIC_TYPE_TMP_BUFFER);
		tls->host_name = NULL;
	}
#if defined(HAVE_ALPN)
	XFREE(tls->alpn_joined, NULL, DYNAMIC_TYPE_TMP_BUFFER);
	tls->alpn_joined = NULL;
#endif /* HAVE_ALPN */
#ifndef NO_PSK
	if (NULL != tls->psk) {
		wc_ForceZero(tls->psk, tls->psk_len);
		XFREE(tls->psk, NULL, DYNAMIC_TYPE_TMP_BUFFER);
		tls->psk = NULL;
		tls->psk_len = 0;
	}
	if (NULL != tls->psk_id) {
		XFREE(tls->psk_id, NULL, DYNAMIC_TYPE_TMP_BUFFER);
		tls->psk_id = NULL;
		tls->psk_id_len = 0;
	}
#endif /* !NO_PSK */
#else
#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
	mbedtls_ssl_cookie_free(&tls->cookie);
#endif
	mbedtls_ssl_config_free(&tls->config);
#if defined(CONFIG_MBEDTLS_X509_CRT_PARSE_C)
	mbedtls_x509_crt_free(&tls->ca_chain);
	mbedtls_x509_crt_free(&tls->own_cert);
	mbedtls_pk_free(&tls->priv_key);
#endif
#endif /* CONFIG_WOLFSSL */

	while ((node = sys_slist_get(&tls->sessions)) != NULL) {
		struct tls_session_context *session_ctx =
			SYS_SLIST_CONTAINER(node, session_ctx, node);

		/* The close_notify reaches dtls_wolf_tx(), which uses active_session */
		tls->active_session = session_ctx;

		tls_session_free(session_ctx);
	}

	tls->active_session = NULL;

#if defined(CONFIG_WOLFSSL)
	/* Free the CTX after its sessions */
	{
		WOLFSSL_CTX *wolf_ctx;

		k_mutex_lock(&context_lock, K_FOREVER);
		wolf_ctx = tls->ctx;
		tls->ctx = NULL;
		k_mutex_unlock(&context_lock);

		if (wolf_ctx != NULL) {
			wolfSSL_CTX_free(wolf_ctx);
		}
	}
#endif /* CONFIG_WOLFSSL */

	tls->is_used = false;

	return 0;
}

#if TLS_SESSION_CACHE_PRESENT || defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
static bool peer_addr_cmp(const struct net_sockaddr *addr,
			  const struct net_sockaddr *peer_addr)
{
	if (addr->sa_family != peer_addr->sa_family) {
		return false;
	}

	if (IS_ENABLED(CONFIG_NET_IPV6) && peer_addr->sa_family == NET_AF_INET6) {
		struct net_sockaddr_in6 *addr1 = net_sin6(peer_addr);
		struct net_sockaddr_in6 *addr2 = net_sin6(addr);

		return (addr1->sin6_port == addr2->sin6_port) &&
			net_ipv6_addr_cmp(&addr1->sin6_addr, &addr2->sin6_addr);
	} else if (IS_ENABLED(CONFIG_NET_IPV4) && peer_addr->sa_family == NET_AF_INET) {
		struct net_sockaddr_in *addr1 = net_sin(peer_addr);
		struct net_sockaddr_in *addr2 = net_sin(addr);

		return (addr1->sin_port == addr2->sin_port) &&
			net_ipv4_addr_cmp(&addr1->sin_addr, &addr2->sin_addr);
	}

	return false;
}
#endif /* TLS_SESSION_CACHE_PRESENT || CONFIG_NET_SOCKETS_ENABLE_DTLS */

#if defined(CONFIG_MBEDTLS)
static int tls_session_save(const struct net_sockaddr *peer_addr,
			    mbedtls_ssl_session *session)
{
	struct tls_session_cache *entry = NULL;
	size_t session_len;
	int ret = 0;

	k_mutex_lock(&session_cache_lock, K_FOREVER);

	for (int i = 0; i < ARRAY_SIZE(client_cache); i++) {
		if (client_cache[i].session == NULL) {
			/* New entry. */
			if (entry == NULL || entry->session != NULL) {
				entry = &client_cache[i];
			}
		} else {
			if (peer_addr_cmp(net_sad(&client_cache[i].peer_addr), peer_addr)) {
				/* Reuse old entry for given address. */
				entry = &client_cache[i];
				break;
			}

			/* Remember the oldest entry and reuse if needed. */
			if (entry == NULL ||
			    (entry->session != NULL &&
			     entry->timestamp < client_cache[i].timestamp)) {
				entry = &client_cache[i];
			}
		}
	}

	/* Allocate session and save */

	if (entry->session != NULL) {
		mbedtls_free(entry->session);
		entry->session = NULL;
	}

	(void)mbedtls_ssl_session_save(session, NULL, 0, &session_len);

	entry->session = mbedtls_calloc(1, session_len);
	if (entry->session == NULL) {
		NET_ERR("Failed to allocate session buffer.");
		ret = -ENOMEM;
		goto out;
	}

	ret = mbedtls_ssl_session_save(session, entry->session, session_len,
				       &session_len);
	if (ret < 0) {
		NET_ERR("Failed to serialize session, err: -0x%x.", -ret);
		mbedtls_free(entry->session);
		entry->session = NULL;
		ret = -ENOMEM;
		goto out;
	}

	entry->session_len = session_len;
	entry->timestamp = k_uptime_get();
	memcpy(&entry->peer_addr, peer_addr, sizeof(*peer_addr));

#if defined(CONFIG_NET_SOCKETS_TLS_SESSION_CACHE_PERSISTENT)
	tls_session_cache_settings_save(entry - client_cache);
#endif

	ret = 0;

out:
	k_mutex_unlock(&session_cache_lock);

	return ret;
}

static int tls_session_get(const struct net_sockaddr *peer_addr,
			   mbedtls_ssl_session *session)
{
	struct tls_session_cache *entry = NULL;
	int ret = 0;

	k_mutex_lock(&session_cache_lock, K_FOREVER);

	for (int i = 0; i < ARRAY_SIZE(client_cache); i++) {
		if (client_cache[i].session != NULL &&
		    peer_addr_cmp(net_sad(&client_cache[i].peer_addr), peer_addr)) {
			entry = &client_cache[i];
			break;
		}
	}

	if (entry == NULL) {
		ret = -ENOENT;
		goto out;
	}

	ret = mbedtls_ssl_session_load(session, entry->session,
				       entry->session_len);
	if (ret < 0) {
		/* Discard corrupted session data. */
		mbedtls_free(entry->session);
		entry->session = NULL;
		NET_ERR("Failed to load TLS session %d", ret);
		ret = -EIO;
		goto out;
	}

	ret = 0;

out:
	k_mutex_unlock(&session_cache_lock);

	return ret;
}

static void tls_session_store(struct tls_context *context,
			      const struct net_sockaddr *addr,
			      net_socklen_t addrlen)
{
	mbedtls_ssl_session session;
	struct net_sockaddr_storage peer_addr = { 0 };
	int ret;

	if (!context->options.cache_enabled) {
		return;
	}

	if (addrlen > sizeof(peer_addr)) {
		return;
	}

	memcpy(&peer_addr, addr, addrlen);
	mbedtls_ssl_session_init(&session);

	ret = mbedtls_ssl_get_session(&context->active_session->ssl, &session);
	if (ret < 0) {
		NET_ERR("Failed to obtain session for %p", context);
		goto exit;
	}

	ret = tls_session_save(net_sad(&peer_addr), &session);
	if (ret < 0) {
		NET_ERR("Failed to save session for %p", context);
	}

exit:
	mbedtls_ssl_session_free(&session);
}

static void tls_session_store_current(struct tls_context *context)
{
	struct net_sockaddr_storage peer_addr = { 0 };
	net_socklen_t peer_addrlen = sizeof(peer_addr);

	if (!context->options.cache_enabled) {
		return;
	}

	if (zsock_getpeername(context->sock, net_sad(&peer_addr), &peer_addrlen) < 0) {
		return;
	}

	tls_session_store(context, net_sad(&peer_addr), peer_addrlen);
}

static void tls_session_restore(struct tls_context *context,
				const struct net_sockaddr *addr,
				net_socklen_t addrlen)
{
	mbedtls_ssl_session session;
	struct net_sockaddr_storage peer_addr = { 0 };
	int ret;

	if (!context->options.cache_enabled) {
		return;
	}

	if (addrlen > sizeof(peer_addr)) {
		return;
	}

	memcpy(&peer_addr, addr, addrlen);
	mbedtls_ssl_session_init(&session);

	ret = tls_session_get(net_sad(&peer_addr), &session);
	if (ret < 0) {
		NET_DBG("Session not found for %p", context);
		goto exit;
	}

	ret = mbedtls_ssl_set_session(&context->active_session->ssl, &session);
	if (ret < 0) {
		NET_ERR("Failed to set session for %p", context);
	} else {
		NET_DBG("Cached session found for %p, attempting resumption", context);
	}

exit:
	mbedtls_ssl_session_free(&session);
}

static void tls_session_purge(void)
{
	tls_session_cache_reset();

#if defined(CONFIG_NET_SOCKETS_TLS_SESSION_CACHE_PERSISTENT)
	tls_session_cache_settings_clear();
#endif

#if defined(MBEDTLS_SSL_CACHE_C)
	mbedtls_ssl_cache_free(&server_cache);
	mbedtls_ssl_cache_init(&server_cache);
#endif
}
#endif /* CONFIG_MBEDTLS */

#if defined(CONFIG_WOLFSSL)
#if defined(ZTLS_WOLFSSL_EXT_CACHE)
/* Caller holds session_cache_lock. */
static struct tls_session_cache *tls_wolfssl_session_entry_reserve(
	const struct net_sockaddr *peer_addr)
{
	struct tls_session_cache *entry = NULL;

	for (int i = 0; i < ARRAY_SIZE(client_cache); i++) {
		if (client_cache[i].session == NULL) {
			if (entry == NULL || entry->session != NULL) {
				entry = &client_cache[i];
			}
		} else {
			if (peer_addr_cmp(net_sad(&client_cache[i].peer_addr), peer_addr)) {
				entry = &client_cache[i];
				break;
			}

			/* Otherwise evict the least recently used slot */
			if (entry == NULL ||
			    (entry->session != NULL &&
			     entry->timestamp > client_cache[i].timestamp)) {
				entry = &client_cache[i];
			}
		}
	}

	if (entry == NULL) {
		return NULL;
	}

	if (entry->session != NULL) {
		/* Evicted blob holds session secret material; scrub it. */
		wc_ForceZero(entry->session, entry->session_len);
		XFREE(entry->session, NULL, DYNAMIC_TYPE_TMP_BUFFER);
		entry->session = NULL;
		entry->session_len = 0;
	}

	return entry;
}
#endif /* ZTLS_WOLFSSL_EXT_CACHE */

static void tls_session_store(struct tls_context *context,
			      const struct net_sockaddr *addr,
			      net_socklen_t addrlen)
{
#if !defined(ZTLS_WOLFSSL_EXT_CACHE)
	ARG_UNUSED(context);
	ARG_UNUSED(addr);
	ARG_UNUSED(addrlen);
#else
	WOLFSSL_SESSION *session = NULL;
	struct tls_session_cache *entry;
	struct net_sockaddr_storage peer_addr = { 0 };
	unsigned char *serialized = NULL;
	size_t alloc_len = 0;
	int size;

	if (!context->options.cache_enabled ||
	    context->active_session->wssl == NULL) {
		return;
	}

	if (addrlen > sizeof(peer_addr)) {
		return;
	}

	memcpy(&peer_addr, addr, addrlen);

	session = wolfSSL_get1_session(context->active_session->wssl);
	if (session == NULL) {
		NET_DBG("No session to save for %p", context);
		return;
	}

	/* Query required buffer size. */
	size = wolfSSL_i2d_SSL_SESSION(session, NULL);
	if (size <= 0) {
		NET_ERR("Failed to size session for %p", context);
		goto exit;
	}

	alloc_len = (size_t)size;

	serialized = XMALLOC(alloc_len, NULL, DYNAMIC_TYPE_TMP_BUFFER);
	if (serialized == NULL) {
		NET_ERR("Failed to allocate session buffer.");
		goto exit;
	}

	{
		unsigned char *p = serialized;

		size = wolfSSL_i2d_SSL_SESSION(session, &p);
	}
	if (size <= 0) {
		NET_ERR("Failed to serialize session for %p", context);
		goto exit;
	}

	k_mutex_lock(&session_cache_lock, K_FOREVER);
	entry = tls_wolfssl_session_entry_reserve(net_sad(&peer_addr));
	if (entry == NULL) {
		k_mutex_unlock(&session_cache_lock);
		NET_ERR("No cache slot for %p", context);
		goto exit;
	}

	entry->session = serialized;
	entry->session_len = (size_t)size;
	entry->timestamp = k_uptime_get();
	memcpy(&entry->peer_addr, &peer_addr, sizeof(peer_addr));
	serialized = NULL;
	k_mutex_unlock(&session_cache_lock);

exit:
	if (serialized != NULL) {
		/* Also covers a partial serialization when i2d failed */
		wc_ForceZero(serialized, alloc_len);
		XFREE(serialized, NULL, DYNAMIC_TYPE_TMP_BUFFER);
	}
	wolfSSL_SESSION_free(session);
#endif /* ZTLS_WOLFSSL_EXT_CACHE */
}

static void tls_session_restore(struct tls_context *context,
				const struct net_sockaddr *addr,
				net_socklen_t addrlen)
{
#if !defined(ZTLS_WOLFSSL_EXT_CACHE)
	ARG_UNUSED(context);
	ARG_UNUSED(addr);
	ARG_UNUSED(addrlen);
#else
	struct tls_session_cache *entry = NULL;
	WOLFSSL_SESSION *session = NULL;
	struct net_sockaddr_storage peer_addr = { 0 };
	unsigned char *serialized_copy = NULL;
	size_t serialized_len = 0;
	const uint8_t *stale;
	int64_t stale_ts;
	const unsigned char *p;

	if (!context->options.cache_enabled ||
	    context->active_session->wssl == NULL) {
		return;
	}

	if (addrlen > sizeof(peer_addr)) {
		return;
	}

	memcpy(&peer_addr, addr, addrlen);

	k_mutex_lock(&session_cache_lock, K_FOREVER);

	for (int i = 0; i < ARRAY_SIZE(client_cache); i++) {
		if (client_cache[i].session != NULL &&
		    peer_addr_cmp(net_sad(&client_cache[i].peer_addr),
				  net_sad(&peer_addr))) {
			entry = &client_cache[i];
			break;
		}
	}

	if (entry == NULL) {
		k_mutex_unlock(&session_cache_lock);
		NET_DBG("Session not found for %p", context);
		return;
	}

	/* Copy under lock so deserialization runs without blocking others. */
	serialized_copy = XMALLOC(entry->session_len, NULL,
				  DYNAMIC_TYPE_TMP_BUFFER);
	if (serialized_copy == NULL) {
		k_mutex_unlock(&session_cache_lock);
		NET_ERR("Failed to allocate session copy");
		return;
	}
	memcpy(serialized_copy, entry->session, entry->session_len);
	serialized_len = entry->session_len;
	stale = entry->session;
	stale_ts = entry->timestamp;
	k_mutex_unlock(&session_cache_lock);

	p = serialized_copy;
	session = wolfSSL_d2i_SSL_SESSION(NULL, &p, (long)serialized_len);
	if (session == NULL) {
		NET_ERR("Failed to load TLS session");
		/* Evict the entry only if no other socket replaced it meanwhile. */
		k_mutex_lock(&session_cache_lock, K_FOREVER);
		for (int i = 0; i < ARRAY_SIZE(client_cache); i++) {
			if (client_cache[i].session == stale &&
			    client_cache[i].timestamp == stale_ts) {
				wc_ForceZero(client_cache[i].session,
					     client_cache[i].session_len);
				XFREE(client_cache[i].session, NULL,
				      DYNAMIC_TYPE_TMP_BUFFER);
				client_cache[i].session = NULL;
				client_cache[i].session_len = 0;
				break;
			}
		}
		k_mutex_unlock(&session_cache_lock);
		wc_ForceZero(serialized_copy, serialized_len);
		XFREE(serialized_copy, NULL, DYNAMIC_TYPE_TMP_BUFFER);
		return;
	}

	if (wolfSSL_set_session(context->active_session->wssl, session) !=
	    WOLFSSL_SUCCESS) {
		NET_DBG("Failed to set session for %p", context);
	}

	wolfSSL_SESSION_free(session);
	wc_ForceZero(serialized_copy, serialized_len);
	XFREE(serialized_copy, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif /* ZTLS_WOLFSSL_EXT_CACHE */
}

static void tls_session_purge(void)
{
#if TLS_SESSION_CACHE_PRESENT
	tls_session_cache_reset();
#endif
}
#endif /* CONFIG_WOLFSSL */

static inline int time_left(uint32_t start, uint32_t timeout)
{
	uint32_t elapsed = k_uptime_get_32() - start;

	return timeout - elapsed;
}

static int wait(int sock, int timeout, int event)
{
	struct zsock_pollfd fds = {
		.fd = sock,
		.events = event,
	};
	int ret;

	ret = zsock_poll(&fds, 1, timeout);
	if (ret < 0) {
		return ret;
	}

	if (ret == 1) {
		if (fds.revents & ZSOCK_POLLNVAL) {
			return -EBADF;
		}

		if (fds.revents & ZSOCK_POLLERR) {
			int optval;
			net_socklen_t optlen = sizeof(optval);

			if (zsock_getsockopt(fds.fd, ZSOCK_SOL_SOCKET, ZSOCK_SO_ERROR,
					     &optval, &optlen) == 0) {
				NET_ERR("TLS underlying socket poll error %d",
					-optval);
				return -optval;
			}

			return -EIO;
		}
	}

	return 0;
}

static int wait_for_reason(int sock, int timeout, int reason)
{
	if (reason == ZTLS_ERROR_WANT_READ) {
		return wait(sock, timeout, ZSOCK_POLLIN);
	}

	if (reason == ZTLS_ERROR_WANT_WRITE) {
		return wait(sock, timeout, ZSOCK_POLLOUT);
	}

	/* Any other reason - no way to monitor, just wait for some time. */
	k_msleep(TLS_WAIT_MS);

	return 0;
}

static bool is_blocking(int sock, int flags)
{
	int sock_flags = zsock_fcntl(sock, ZVFS_F_GETFL, 0);

	if (sock_flags == -1) {
		return false;
	}

	return !((flags & ZSOCK_MSG_DONTWAIT) || (sock_flags & ZVFS_O_NONBLOCK));
}

static int timeout_to_ms(k_timeout_t *timeout)
{
	if (K_TIMEOUT_EQ(*timeout, K_NO_WAIT)) {
		return 0;
	} else if (K_TIMEOUT_EQ(*timeout, K_FOREVER)) {
		return SYS_FOREVER_MS;
	} else {
		return k_ticks_to_ms_ceil32(timeout->ticks);
	}
}

static void ctx_set_lock(struct tls_context *ctx, struct k_mutex *lock)
{
	ctx->lock = lock;
}

#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
static bool dtls_is_peer_addr_valid(struct tls_session_context *session_ctx,
				    const struct net_sockaddr *peer_addr,
				    net_socklen_t addrlen)
{
	if (session_ctx->dtls_peer_addrlen != addrlen) {
		return false;
	}

	return peer_addr_cmp(net_sad(&session_ctx->dtls_peer_addr), peer_addr);
}

static void dtls_peer_address_set(struct tls_session_context *session_ctx,
				  const struct net_sockaddr *peer_addr,
				  net_socklen_t addrlen)
{
	if (addrlen <= sizeof(session_ctx->dtls_peer_addr)) {
		memcpy(&session_ctx->dtls_peer_addr, peer_addr, addrlen);
		session_ctx->dtls_peer_addrlen = addrlen;
	}
}

static void dtls_peer_address_get(struct tls_session_context *session_ctx,
				  struct net_sockaddr *peer_addr,
				  net_socklen_t *addrlen)
{
	net_socklen_t len = MIN(session_ctx->dtls_peer_addrlen, *addrlen);

	memcpy(peer_addr, &session_ctx->dtls_peer_addr, len);
	*addrlen = len;
}

#if defined(CONFIG_WOLFSSL)
static int dtls_wolf_tx(WOLFSSL *ssl, char *buf, int len, void *ctx)
{
	struct tls_context *tls_ctx = ctx;
	ssize_t sent;

	if (tls_ctx->options.role == ZTLS_IS_SERVER) {
		dtls_server_refresh_session_timeout(tls_ctx->active_session);
	}

	sent = zsock_sendto(tls_ctx->sock, buf, len, ZSOCK_MSG_DONTWAIT,
			    net_sad(&tls_ctx->active_session->dtls_peer_addr),
			    tls_ctx->active_session->dtls_peer_addrlen);
	if (sent < 0) {
		if (errno == EAGAIN) {
			return WOLFSSL_CBIO_ERR_WANT_WRITE;
		}

		return WOLFSSL_CBIO_ERR_GENERAL;
	}

	return sent;
}

static int dtls_wolf_server_rx(WOLFSSL *ssl, char *buf, int len, void *ctx)
{
	struct tls_context *tls_ctx = ctx;
	net_socklen_t addrlen = sizeof(struct net_sockaddr);
	struct net_sockaddr_storage addr = { 0 };
	ssize_t received;
	uint8_t tmp_buf;

	/* Peek the packet first to check the peer address. */
	received = zsock_recvfrom(tls_ctx->sock, &tmp_buf, sizeof(tmp_buf),
				  ZSOCK_MSG_DONTWAIT | ZSOCK_MSG_PEEK,
				  net_sad(&addr), &addrlen);
	if (received < 0) {
		if (errno == EAGAIN) {
			return WOLFSSL_CBIO_ERR_WANT_READ;
		}

		NET_ERR("DTLS server RX: failure %d", errno);
		return WOLFSSL_CBIO_ERR_GENERAL;
	}

	if (received == 0) {
		/* An empty datagram is consumed before the peer check without refreshing a timeout.
		 * It means EOF after a local read shutdown and is dropped otherwise.
		 */
		(void)zsock_recvfrom(tls_ctx->sock, &tmp_buf, sizeof(tmp_buf),
				     ZSOCK_MSG_DONTWAIT, net_sad(&addr), &addrlen);
		return tls_ctx->recv_eof ? WOLFSSL_CBIO_ERR_CONN_CLOSE
					 : WOLFSSL_CBIO_ERR_WANT_READ;
	}

	/* Check if the peer address matches the current session. */
	if (tls_ctx->active_session->dtls_peer_addrlen != 0 &&
	    !dtls_is_peer_addr_valid(tls_ctx->active_session, net_sad(&addr), addrlen)) {
		/* Peer address does not match the current session, exit now
		 * and try to find the appropriate session or allocate a new one.
		 */
		return WOLFSSL_CBIO_ERR_WANT_READ;
	}

	/* If the session matches, read the actual packet. */
	received = zsock_recvfrom(tls_ctx->sock, buf, len,
				  ZSOCK_MSG_DONTWAIT, net_sad(&addr), &addrlen);
	if (received < 0) {
		NET_ERR("DTLS server RX: failure %d", errno);
		return WOLFSSL_CBIO_ERR_GENERAL;
	}

	if (received == 0) {
		/* An empty datagram can arrive between the peek and this read */
		return tls_ctx->recv_eof ? WOLFSSL_CBIO_ERR_CONN_CLOSE
					 : WOLFSSL_CBIO_ERR_WANT_READ;
	}

	dtls_server_refresh_session_timeout(tls_ctx->active_session);

	/* Only allow to store peer address for DTLS servers. */
	if (tls_ctx->active_session->dtls_peer_addrlen == 0) {
		dtls_peer_address_set(tls_ctx->active_session, net_sad(&addr), addrlen);

		if (wolfSSL_dtls_set_peer(ssl, (void *)&addr,
				(unsigned int)addrlen) != WOLFSSL_SUCCESS) {
			/* Roll back stored peer so retry doesn't
			 * falsely match.
			 */
			tls_ctx->active_session->dtls_peer_addrlen = 0;
			return WOLFSSL_CBIO_ERR_GENERAL;
		}
	}

	return received;
}

static int dtls_wolf_client_rx(WOLFSSL *ssl, char *buf, int len, void *ctx)
{
	struct tls_context *tls_ctx = ctx;
	net_socklen_t addrlen = sizeof(struct net_sockaddr);
	struct net_sockaddr_storage addr = { 0 };
	ssize_t received;

	received = zsock_recvfrom(tls_ctx->sock, buf, len,
				  ZSOCK_MSG_DONTWAIT, net_sad(&addr), &addrlen);
	if (received < 0) {
		if (errno == EAGAIN) {
			return WOLFSSL_CBIO_ERR_WANT_READ;
		}

		return WOLFSSL_CBIO_ERR_GENERAL;
	}

	if (received == 0) {
		/* EOF after a local read shutdown; an empty datagram from the network is dropped */
		return tls_ctx->recv_eof ? WOLFSSL_CBIO_ERR_CONN_CLOSE
					 : WOLFSSL_CBIO_ERR_WANT_READ;
	}

	if (tls_ctx->active_session->dtls_peer_addrlen == 0) {
		/* For clients it's incorrect to receive when
		 * no peer has been set up.
		 */
		return WOLFSSL_CBIO_ERR_GENERAL;
	}

	if (!dtls_is_peer_addr_valid(tls_ctx->active_session, net_sad(&addr), addrlen)) {
		/* Received packet from a different peer, drop and retry. */
		return WOLFSSL_CBIO_ERR_WANT_READ;
	}

	return received;
}
#endif /* CONFIG_WOLFSSL */

#if defined(CONFIG_MBEDTLS)
static int dtls_tx(void *ctx, const unsigned char *buf, size_t len)
{
	struct tls_context *tls_ctx = ctx;
	struct net_sockaddr_storage *local_addr = NULL;
	ssize_t sent;

	if (tls_ctx->options.role == MBEDTLS_SSL_IS_SERVER) {
		dtls_server_refresh_session_timeout(tls_ctx->active_session);

		if (tls_ctx->active_session->dtls_local_addr.ss_family != NET_AF_UNSPEC) {
			local_addr = &tls_ctx->active_session->dtls_local_addr;
		}
	}

	if (local_addr != NULL) {
		/* A union keeps this properly aligned for net_cmsghdr, not just a byte array. */
		union {
			struct net_cmsghdr hdr;
			uint8_t buf[NET_CMSG_SPACE(sizeof(struct net_in6_pktinfo))];
		} cmsg_storage = { 0 };
		uint8_t *cmsg_buf = cmsg_storage.buf;
		struct net_cmsghdr *cmsg = &cmsg_storage.hdr;
		struct net_iovec io_vec = { .iov_base = (void *)buf, .iov_len = len };
		struct net_msghdr msg = {
			.msg_name = net_sad(&tls_ctx->active_session->dtls_peer_addr),
			.msg_namelen = tls_ctx->active_session->dtls_peer_addrlen,
			.msg_iov = &io_vec,
			.msg_iovlen = 1,
			.msg_control = cmsg_buf,
			.msg_controllen = sizeof(cmsg_storage.buf),
		};

		if (IS_ENABLED(CONFIG_NET_IPV6) && local_addr->ss_family == NET_AF_INET6) {
			struct net_in6_pktinfo info = {
				.ipi6_addr = ((struct net_sockaddr_in6 *)local_addr)->sin6_addr,
			};

			cmsg->cmsg_level = NET_IPPROTO_IPV6;
			cmsg->cmsg_type = ZSOCK_IPV6_PKTINFO;
			cmsg->cmsg_len = NET_CMSG_LEN(sizeof(info));
			memcpy(NET_CMSG_DATA(cmsg), &info, sizeof(info));
			msg.msg_controllen = NET_CMSG_SPACE(sizeof(info));
		} else if (IS_ENABLED(CONFIG_NET_IPV4) && local_addr->ss_family == NET_AF_INET) {
			struct net_in_pktinfo info = {
				.ipi_spec_dst = ((struct net_sockaddr_in *)local_addr)->sin_addr,
			};

			cmsg->cmsg_level = NET_IPPROTO_IP;
			cmsg->cmsg_type = ZSOCK_IP_PKTINFO;
			cmsg->cmsg_len = NET_CMSG_LEN(sizeof(info));
			memcpy(NET_CMSG_DATA(cmsg), &info, sizeof(info));
			msg.msg_controllen = NET_CMSG_SPACE(sizeof(info));
		}

		sent = zsock_sendmsg(tls_ctx->sock, &msg, ZSOCK_MSG_DONTWAIT);
	} else {
		sent = zsock_sendto(tls_ctx->sock, buf, len, ZSOCK_MSG_DONTWAIT,
				    net_sad(&tls_ctx->active_session->dtls_peer_addr),
				    tls_ctx->active_session->dtls_peer_addrlen);
	}

	if (sent < 0) {
		if (errno == EAGAIN) {
			return MBEDTLS_ERR_SSL_WANT_WRITE;
		}

		return MBEDTLS_ERR_NET_SEND_FAILED;
	}

	return sent;
}

/* Get the local address a DTLS packet came in on, from IPV6_PKTINFO/IP_PKTINFO.
 * If that address turns out to be multicast, we leave it unset instead of
 * storing it. That way the reply just goes out through plain sendto(), and
 * the OS picks a normal address to send it from - replying "from" a
 * multicast address wouldn't make sense.
 */
static void dtls_server_local_addr_from_cmsg(struct net_msghdr *msg,
					     struct net_sockaddr_storage *local_addr)
{
	struct net_cmsghdr *cmsg;

	local_addr->ss_family = NET_AF_UNSPEC;

	for (cmsg = NET_CMSG_FIRSTHDR(msg); cmsg != NULL; cmsg = NET_CMSG_NXTHDR(msg, cmsg)) {
		if (IS_ENABLED(CONFIG_NET_IPV6) && cmsg->cmsg_level == NET_IPPROTO_IPV6 &&
		    cmsg->cmsg_type == ZSOCK_IPV6_PKTINFO &&
		    cmsg->cmsg_len == NET_CMSG_LEN(sizeof(struct net_in6_pktinfo))) {
			struct net_in6_pktinfo *info =
				(struct net_in6_pktinfo *)NET_CMSG_DATA(cmsg);
			struct net_sockaddr_in6 *addr6 = (struct net_sockaddr_in6 *)local_addr;

			if (!net_ipv6_is_addr_mcast(&info->ipi6_addr)) {
				addr6->sin6_family = NET_AF_INET6;
				addr6->sin6_addr = info->ipi6_addr;
			}
			return;
		}

		if (IS_ENABLED(CONFIG_NET_IPV4) && cmsg->cmsg_level == NET_IPPROTO_IP &&
		    cmsg->cmsg_type == ZSOCK_IP_PKTINFO &&
		    cmsg->cmsg_len == NET_CMSG_LEN(sizeof(struct net_in_pktinfo))) {
			struct net_in_pktinfo *info = (struct net_in_pktinfo *)NET_CMSG_DATA(cmsg);
			struct net_sockaddr_in *addr4 = (struct net_sockaddr_in *)local_addr;

			if (!net_ipv4_is_addr_mcast(&info->ipi_addr)) {
				addr4->sin_family = NET_AF_INET;
				addr4->sin_addr = info->ipi_addr;
			}
			return;
		}
	}
}

static int dtls_server_rx(void *ctx, unsigned char *buf, size_t len)
{
	struct tls_context *tls_ctx = ctx;
	net_socklen_t addrlen = sizeof(struct net_sockaddr_storage);
	struct net_sockaddr_storage addr = { 0 };
	struct net_sockaddr_storage local_addr = { 0 };
	union {
		struct net_cmsghdr hdr;
		uint8_t buf[NET_CMSG_SPACE(sizeof(struct net_in6_pktinfo))];
	} cmsg_storage = { 0 };
	uint8_t *cmsg_buf = cmsg_storage.buf;
	struct net_iovec io_vec;
	struct net_msghdr msg;
	int err;
	ssize_t received;
	uint8_t tmp_buf;

	/* Peek the packet first to check the peer address. */
	received = zsock_recvfrom(tls_ctx->sock, &tmp_buf, sizeof(tmp_buf),
				  ZSOCK_MSG_DONTWAIT | ZSOCK_MSG_PEEK,
				  net_sad(&addr), &addrlen);
	if (received < 0) {
		if (errno == EAGAIN) {
			return MBEDTLS_ERR_SSL_WANT_READ;
		}

		NET_ERR("DTLS server RX: failure %d", errno);
		return MBEDTLS_ERR_NET_RECV_FAILED;
	}

	/* Check if the peer address matches the current session. */
	if (tls_ctx->active_session->dtls_peer_addrlen != 0 &&
	    !dtls_is_peer_addr_valid(tls_ctx->active_session, net_sad(&addr), addrlen)) {
		/* Peer address does not match the current session, exit now
		 * and try to find the appropriate session or allocate a new one.
		 */
		return MBEDTLS_ERR_SSL_WANT_READ;
	}

	/* If the session matches, use recvmsg() to read the packet and its local address. */
	memset(cmsg_buf, 0, sizeof(cmsg_storage.buf));

	io_vec.iov_base = buf;
	io_vec.iov_len = len;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = net_sad(&addr);
	msg.msg_namelen = sizeof(addr);
	msg.msg_iov = &io_vec;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsg_buf;
	msg.msg_controllen = sizeof(cmsg_storage.buf);

	received = zsock_recvmsg(tls_ctx->sock, &msg, ZSOCK_MSG_DONTWAIT);
	if (received < 0) {
		NET_ERR("DTLS server RX: failure %d", errno);
		return MBEDTLS_ERR_NET_RECV_FAILED;
	}

	addrlen = msg.msg_namelen;
	dtls_server_local_addr_from_cmsg(&msg, &local_addr);
	tls_ctx->active_session->dtls_local_addr = local_addr;

	dtls_server_refresh_session_timeout(tls_ctx->active_session);

	/* Only allow to store peer address for DTLS servers. */
	if (tls_ctx->active_session->dtls_peer_addrlen == 0) {
		dtls_peer_address_set(tls_ctx->active_session, net_sad(&addr), addrlen);

		err = mbedtls_ssl_set_client_transport_id(&tls_ctx->active_session->ssl,
							 (const unsigned char *)&addr,
							 addrlen);
		if (err < 0) {
			return err;
		}
	}

	return received;
}

static int dtls_client_rx(void *ctx, unsigned char *buf, size_t len)
{
	struct tls_context *tls_ctx = ctx;
	net_socklen_t addrlen = sizeof(struct net_sockaddr_storage);
	struct net_sockaddr_storage addr = { 0 };
	ssize_t received;

	received = zsock_recvfrom(tls_ctx->sock, buf, len,
				  ZSOCK_MSG_DONTWAIT, net_sad(&addr), &addrlen);
	if (received < 0) {
		if (errno == EAGAIN) {
			return MBEDTLS_ERR_SSL_WANT_READ;
		}

		return MBEDTLS_ERR_NET_RECV_FAILED;
	}

	if (tls_ctx->active_session->dtls_peer_addrlen == 0) {
		/* For clients it's incorrect to receive when
		 * no peer has been set up.
		 */
		return MBEDTLS_ERR_SSL_PEER_VERIFY_FAILED;
	}

	if (!dtls_is_peer_addr_valid(tls_ctx->active_session, net_sad(&addr), addrlen)) {
		/* Received packet from a different peer, drop and retry. */
		return MBEDTLS_ERR_SSL_WANT_READ;
	}

	return received;
}
#endif /* CONFIG_MBEDTLS */

#if defined(CONFIG_MBEDTLS)
static int tls_mbedtls_session_init(struct tls_session_context *session_ctx,
				    struct tls_context *tls_ctx, bool is_server);
#endif
#if defined(CONFIG_WOLFSSL)
static int tls_wolfssl_session_init(struct tls_session_context *session_ctx,
				    struct tls_context *tls_ctx, bool is_server);
#endif

/* Returns
 * - 0 when session was switched,
 * - 1 if session was already valid,
 * - negative error code otherwise
 */
static int dtls_server_switch_active_session(struct tls_context *tls_ctx,
					     const struct net_sockaddr *addr,
					     net_socklen_t addrlen)
{
	struct tls_session_context *session_ctx = NULL;

	if (tls_ctx->active_session->dtls_peer_addrlen == 0 ||
	    dtls_is_peer_addr_valid(tls_ctx->active_session, addr, addrlen)) {
		return 1;
	}

	NET_DBG("Need to swap session for [%s]:%d (current [%s]:%d)",
		LOG_ADDR_PORT_HELPER(addr),
		LOG_ADDR_PORT_HELPER(net_sad(&tls_ctx->active_session->dtls_peer_addr)));

	SYS_SLIST_FOR_EACH_CONTAINER(&tls_ctx->sessions, session_ctx, node) {
		if (dtls_is_peer_addr_valid(session_ctx, addr, addrlen)) {
			NET_DBG("Found matching session (address)");
			tls_ctx->active_session = session_ctx;
			return 0;
		}
	}

	return -ENOENT;
}

static int dtls_server_new_active_session(struct tls_context *tls_ctx,
					  const struct net_sockaddr *addr,
					  net_socklen_t addrlen)
{
	struct tls_session_context *session_ctx = NULL;
	int ret;

	session_ctx = tls_session_alloc();
	if (session_ctx == NULL) {
		return -ENOMEM;
	}

#if defined(CONFIG_WOLFSSL)
	ret = tls_wolfssl_session_init(session_ctx, tls_ctx, true);
	if (ret < 0) {
		tls_session_free(session_ctx);
		return ret;
	}

	dtls_peer_address_set(session_ctx, addr, addrlen);

	if (wolfSSL_dtls_set_peer(session_ctx->wssl, (void *)addr,
				  (unsigned int)addrlen) != WOLFSSL_SUCCESS) {
		tls_session_free(session_ctx);
		return -ENOMEM;
	}
#else
	ret = tls_mbedtls_session_init(session_ctx, tls_ctx, true);
	if (ret < 0) {
		tls_session_free(session_ctx);
		return ret;
	}

	dtls_peer_address_set(session_ctx, addr, addrlen);

	ret = mbedtls_ssl_set_client_transport_id(&session_ctx->ssl,
						  (const unsigned char *)addr,
						  addrlen);
	if (ret < 0) {
		tls_session_free(session_ctx);
		return -ENOMEM;
	}

#if defined(CONFIG_MBEDTLS_X509_CRT_PARSE_C)
	if (tls_ctx->options.is_hostname_set) {
		mbedtls_ssl_set_hostname(&session_ctx->ssl,
					 tls_ctx->active_session->ssl.hostname);
	}
#endif
#endif /* CONFIG_WOLFSSL */

	sys_slist_append(&tls_ctx->sessions, &session_ctx->node);
	tls_ctx->active_session = session_ctx;

	dtls_server_refresh_session_timeout(session_ctx);

	return 0;
}

#if defined(CONFIG_MBEDTLS_SSL_DTLS_CONNECTION_ID)
static int dtls_server_switch_active_session_by_cid(struct tls_context *tls_ctx)
{
	struct tls_session_context *session_ctx = NULL;
	int result = -ENOENT;

	if (!tls_ctx->options.dtls_cid.enabled) {
		return -ENOTSUP;
	}

	k_mutex_lock(&dtls_helper_buf_lock, K_FOREVER);

	SYS_SLIST_FOR_EACH_CONTAINER(&tls_ctx->sessions, session_ctx, node) {
		struct net_sockaddr_storage addr;
		net_socklen_t addrlen;
		int cid_enabled;
		ssize_t len;
		int ret;

		ret = mbedtls_ssl_get_peer_cid(&session_ctx->ssl, &cid_enabled,
					       NULL, NULL);
		if (ret != 0 || cid_enabled != MBEDTLS_SSL_CID_ENABLED) {
			continue;
		}

		/* This deserves some additional context. The only way I found to
		 * check if the datagram matches current session based on DTLS CID
		 * is mbedtls_ssl_check_record() function (which according to the
		 * API documentation serves exactly the purpose). Because of this,
		 * we need to:
		 * - peek the full datagram from the socket this time, not just
		 *   a dummy byte,
		 * - and as the function may modify the provided datagram, we
		 *   need to repeat this for each checked client session.
		 *
		 * As the DTLS records can take up to 16kB in size depending on
		 * the configuration, it's been decided to dedicate a single
		 * static buffer for the purpose, and protect it with a mutex to
		 * avoid races in case multiple DTLS server sockets run in parallel.
		 */
		addrlen = sizeof(struct net_sockaddr_storage);
		len = zsock_recvfrom(tls_ctx->sock, &dtls_helper_buf, sizeof(dtls_helper_buf),
				     ZSOCK_MSG_DONTWAIT | ZSOCK_MSG_PEEK,
				     net_sad(&addr), &addrlen);
		if (len < 0) {
			result = -errno;
			break;
		}

		ret = mbedtls_ssl_check_record(&session_ctx->ssl, dtls_helper_buf, len);
		if (ret == 0) {
			NET_DBG("Found matching session (CID) for [%s]:%d (was [%s]:%d)",
				LOG_ADDR_PORT_HELPER(net_sad(&addr)),
				LOG_ADDR_PORT_HELPER(net_sad(&session_ctx->dtls_peer_addr)));

			/* Need to update peer address as CID matched */
			dtls_peer_address_set(session_ctx, net_sad(&addr), addrlen);
			tls_ctx->active_session = session_ctx;
			result = 0;
			break;
		}
	}

	k_mutex_unlock(&dtls_helper_buf_lock);

	return result;
}
#else
#define dtls_server_switch_active_session_by_cid(...) (-ENOTSUP)
#endif /* defined(CONFIG_MBEDTLS_SSL_DTLS_CONNECTION_ID) */

/* Returns
 * - 0 when session was switched or updated,
 * - 1 if session was already valid,
 * - negative error code otherwise
 */
static int dtls_server_switch_session_on_rx(struct tls_context *tls_ctx)
{
	net_socklen_t addrlen = sizeof(struct net_sockaddr_storage);
	struct net_sockaddr_storage addr = { 0 };
	uint8_t tmp_buf;
	int ret;

	/* Peek a dummy byte first to get peer address. */
	ret = zsock_recvfrom(tls_ctx->sock, &tmp_buf, sizeof(tmp_buf),
			     ZSOCK_MSG_DONTWAIT | ZSOCK_MSG_PEEK,
			     net_sad(&addr), &addrlen);
	if (ret < 0) {
		return -errno;
	}

	/* Try to match existing session by peer address. */
	ret = dtls_server_switch_active_session(tls_ctx, net_sad(&addr), addrlen);
	if (ret == 0 || ret == 1) {
		return ret;
	}

	/* Not found, try to match existing session by CID */
	ret = dtls_server_switch_active_session_by_cid(tls_ctx);
	if (ret == 0) {
		return 0;
	}

	/* No session found, try to allocate one. */

	NET_DBG("No session found (RX), allocating new");

	ret = dtls_server_new_active_session(tls_ctx, net_sad(&addr), addrlen);
	if (ret < 0) {
		NET_ERR("Failed to allocate new session for DTLS server, "
			"dropping packet (err: %d)", ret);

		(void)zsock_recv(tls_ctx->sock, &tmp_buf, sizeof(tmp_buf),
				 ZSOCK_MSG_DONTWAIT);
	}

	return ret;
}

static int dtls_server_free_active_session(struct tls_context *tls_ctx)
{
	int ret = 0;

	dtls_server_init_session_timeout(tls_ctx->active_session);

	if (sys_slist_len(&tls_ctx->sessions) > 1) {
		struct tls_session_context *session_ctx;

		/* Free the session and set the active session to any other. */
		sys_slist_find_and_remove(&tls_ctx->sessions,
					  &tls_ctx->active_session->node);
		tls_session_free(tls_ctx->active_session);
		tls_ctx->active_session =
			SYS_SLIST_PEEK_HEAD_CONTAINER(&tls_ctx->sessions,
						      session_ctx, node);
	} else {
		/* Last session, just reset it. */
#if defined(CONFIG_WOLFSSL)
		ret = tls_wolfssl_reset_session(tls_ctx);
#else
		ret = tls_mbedtls_reset_session(tls_ctx);
#endif
	}

	tls_ctx->error = 0;

	return ret;
}

static bool dtls_server_check_expired_sessions(struct tls_context *tls_ctx)
{
	struct tls_session_context *session_ctx, *next;
	bool expired = false;

	SYS_SLIST_FOR_EACH_CONTAINER_SAFE(&tls_ctx->sessions, session_ctx, next, node) {
		if (sys_timepoint_expired(session_ctx->session_expiry)) {
			tls_ctx->active_session = session_ctx;
#if defined(CONFIG_WOLFSSL)
			if (tls_ctx->active_session->wssl != NULL &&
			    wolfSSL_is_init_finished(tls_ctx->active_session->wssl)) {
				(void)wolfSSL_shutdown(tls_ctx->active_session->wssl);
			}
#else
			(void)mbedtls_ssl_close_notify(&tls_ctx->active_session->ssl);
#endif
			(void)dtls_server_free_active_session(tls_ctx);
			expired = true;
		}
	}

	return expired;
}
#endif /* CONFIG_NET_SOCKETS_ENABLE_DTLS */

#if defined(CONFIG_MBEDTLS)
static int tls_tx(void *ctx, const unsigned char *buf, size_t len)
{
	struct tls_context *tls_ctx = ctx;
	ssize_t sent;

	sent = zsock_sendto(tls_ctx->sock, buf, len,
			    ZSOCK_MSG_DONTWAIT, NULL, 0);
	if (sent < 0) {
		if (errno == EAGAIN) {
			return MBEDTLS_ERR_SSL_WANT_WRITE;
		}

		return MBEDTLS_ERR_NET_SEND_FAILED;
	}

	return sent;
}

static int tls_rx(void *ctx, unsigned char *buf, size_t len)
{
	struct tls_context *tls_ctx = ctx;
	ssize_t received;

	received = zsock_recvfrom(tls_ctx->sock, buf, len,
				  ZSOCK_MSG_DONTWAIT, NULL, 0);
	if (received < 0) {
		if (errno == EAGAIN) {
			return MBEDTLS_ERR_SSL_WANT_READ;
		}

		return MBEDTLS_ERR_NET_RECV_FAILED;
	}

	return received;
}
#endif /* CONFIG_MBEDTLS */

#if defined(CONFIG_WOLFSSL)
static int tls_wolf_tx(WOLFSSL *ssl, char *buf, int len, void *ctx)
{
	struct tls_context *tls_ctx = ctx;
	ssize_t sent;

	sent = zsock_sendto(tls_ctx->sock, buf, len,
			    ZSOCK_MSG_DONTWAIT, NULL, 0);

	if (sent < 0) {
		switch (errno) {
		case EAGAIN:
			return WOLFSSL_CBIO_ERR_WANT_WRITE;
		case ECONNRESET:
			return WOLFSSL_CBIO_ERR_CONN_RST;
		case EINTR:
			return WOLFSSL_CBIO_ERR_ISR;
		case EPIPE:
			return WOLFSSL_CBIO_ERR_CONN_CLOSE;
		default:
			return WOLFSSL_CBIO_ERR_GENERAL;
		}
	}

	return sent;
}

static int tls_wolf_rx(WOLFSSL *ssl, char *buf, int len, void *ctx)
{
	struct tls_context *tls_ctx = ctx;
	ssize_t received;

	received = zsock_recvfrom(tls_ctx->sock, buf, len,
				  ZSOCK_MSG_DONTWAIT, NULL, 0);

	if (received < 0) {
		switch (errno) {
		case EAGAIN:
			return WOLFSSL_CBIO_ERR_WANT_READ;
		case ECONNRESET:
			return WOLFSSL_CBIO_ERR_CONN_RST;
		case EINTR:
			return WOLFSSL_CBIO_ERR_ISR;
		case ECONNREFUSED:
			return WOLFSSL_CBIO_ERR_WANT_READ;
		case ECONNABORTED:
			return WOLFSSL_CBIO_ERR_CONN_CLOSE;
		default:
			return WOLFSSL_CBIO_ERR_GENERAL;
		}
	} else if (received == 0) {
		return WOLFSSL_CBIO_ERR_CONN_CLOSE;
	}

	return received;
}

static bool crt_is_pem(const unsigned char *buf, size_t buflen)
{
	return (buflen != 0 && buf[buflen - 1] == '\0' &&
		strstr((const char *)buf, "-----BEGIN CERTIFICATE-----") != NULL);
}

/* "PRIVATE KEY-----" also matches the RSA, EC and ENCRYPTED variants */
static bool key_is_pem(const unsigned char *buf, size_t buflen)
{
	return (buflen != 0 && buf[buflen - 1] == '\0' &&
		strstr((const char *)buf, "PRIVATE KEY-----") != NULL);
}
#endif /* CONFIG_WOLFSSL */

#if defined(CONFIG_MBEDTLS_X509_CRT_PARSE_C)
static bool crt_is_pem(const unsigned char *buf, size_t buflen)
{
	return (buflen != 0 && buf[buflen - 1] == '\0' &&
		strstr((const char *)buf, "-----BEGIN CERTIFICATE-----") != NULL);
}
#endif

static int tls_add_ca_certificate(struct tls_context *tls,
				  struct tls_credential *ca_cert)
{
#if defined(CONFIG_WOLFSSL)
	int ret;
	int format = WOLFSSL_FILETYPE_ASN1;

	if (crt_is_pem(ca_cert->buf, ca_cert->len)) {
		format = WOLFSSL_FILETYPE_PEM;
	}
	ret = wolfSSL_CTX_load_verify_buffer(tls->ctx, ca_cert->buf,
					     ca_cert->len, format);

	if (ret != WOLFSSL_SUCCESS) {
		NET_ERR("Failed to install CA certificate into wolfSSL CTX "
			"(wolfSSL_CTX_load_verify_buffer=%d)", ret);
		return -EINVAL;
	}

	return 0;
#elif defined(CONFIG_MBEDTLS_X509_CRT_PARSE_C)
	int err;

	if (tls->options.cert_nocopy == ZSOCK_TLS_CERT_NOCOPY_NONE ||
	    crt_is_pem(ca_cert->buf, ca_cert->len)) {
		err = mbedtls_x509_crt_parse(&tls->ca_chain, ca_cert->buf,
					     ca_cert->len);
	} else {
		err = mbedtls_x509_crt_parse_der_nocopy(&tls->ca_chain,
							ca_cert->buf,
							ca_cert->len);
	}

	if (err != 0) {
		NET_ERR("Failed to parse CA certificate, err: -0x%x", -err);
		return -EINVAL;
	}

	return 0;
#endif /* CONFIG_MBEDTLS_X509_CRT_PARSE_C */

	return -ENOTSUP;
}

#if defined(CONFIG_MBEDTLS)
static void tls_set_ca_chain(struct tls_context *tls)
{
#if defined(CONFIG_MBEDTLS_X509_CRT_PARSE_C)
	mbedtls_ssl_conf_ca_chain(&tls->config, &tls->ca_chain, NULL);
	mbedtls_ssl_conf_cert_profile(&tls->config,
				      &mbedtls_x509_crt_profile_default);
#endif /* CONFIG_MBEDTLS_X509_CRT_PARSE_C */
}
#endif /* CONFIG_MBEDTLS */

static int tls_add_own_cert(struct tls_context *tls,
			    struct tls_credential *own_cert)
{
#if defined(CONFIG_WOLFSSL)
	int ret = 0;
	int format = WOLFSSL_FILETYPE_ASN1;

	if (crt_is_pem(own_cert->buf, own_cert->len)) {
		format = WOLFSSL_FILETYPE_PEM;
	}
	/* Chain variant, not the single-certificate one: applications ship the
	 * leaf and its intermediates as one concatenated credential, and
	 * mbedtls_x509_crt_parse() on the other backend loads all of them.
	 * Loading only the leaf sends an incomplete chain to the peer.
	 */
	ret = wolfSSL_CTX_use_certificate_chain_buffer_format(tls->ctx,
							      own_cert->buf,
							      own_cert->len,
							      format);
	if (ret != WOLFSSL_SUCCESS) {
		NET_ERR("Failed to parse certificate");
		return -EINVAL;
	}

	return 0;
#elif defined(CONFIG_MBEDTLS_X509_CRT_PARSE_C)
	int err;

	if (tls->options.cert_nocopy == ZSOCK_TLS_CERT_NOCOPY_NONE ||
	    crt_is_pem(own_cert->buf, own_cert->len)) {
		err = mbedtls_x509_crt_parse(&tls->own_cert,
					     own_cert->buf, own_cert->len);
	} else {
		err = mbedtls_x509_crt_parse_der_nocopy(&tls->own_cert,
							own_cert->buf,
							own_cert->len);
	}

	if (err != 0) {
		return -EINVAL;
	}

	return 0;
#endif /* CONFIG_MBEDTLS_X509_CRT_PARSE_C */

	return -ENOTSUP;
}

#if defined(CONFIG_MBEDTLS)
static int tls_set_own_cert(struct tls_context *tls)
{
#if defined(CONFIG_MBEDTLS_X509_CRT_PARSE_C)
	int err = mbedtls_ssl_conf_own_cert(&tls->config, &tls->own_cert,
					    &tls->priv_key);
	if (err != 0) {
		err = -ENOMEM;
	}

	return err;
#endif /* CONFIG_MBEDTLS_X509_CRT_PARSE_C */

	return -ENOTSUP;
}
#endif /* CONFIG_MBEDTLS */

static int tls_set_private_key(struct tls_context *tls,
			       struct tls_credential *priv_key)
{
#if defined(CONFIG_WOLFSSL)
	int ret = 0;
	int format = WOLFSSL_FILETYPE_ASN1;

	if (key_is_pem(priv_key->buf, priv_key->len)) {
		format = WOLFSSL_FILETYPE_PEM;
	}
	ret = wolfSSL_CTX_use_PrivateKey_buffer(tls->ctx, priv_key->buf,
						priv_key->len, format);
	if (ret != WOLFSSL_SUCCESS) {
		NET_ERR("Failed to parse private key");
		return -EINVAL;
	}

	return 0;
#elif defined(CONFIG_MBEDTLS_X509_CRT_PARSE_C)
	int err;

	err = mbedtls_pk_parse_key(&tls->priv_key, priv_key->buf,
				   priv_key->len, NULL, 0);
	if (err != 0) {
		return -EINVAL;
	}

	return 0;
#endif /* CONFIG_MBEDTLS_X509_CRT_PARSE_C */

	return -ENOTSUP;
}

static int tls_set_private_key_psa(struct tls_context *tls,
				   struct tls_credential *priv_key)
{
#if defined(CONFIG_MBEDTLS_X509_CRT_PARSE_C) && defined(TLS_PRIV_KEY_PSA_ENABLED)
	psa_key_id_t key_id;
	mbedtls_svc_key_id_t svc_key_id;
	int err;

	if (priv_key->len != sizeof(key_id)) {
		return -EINVAL;
	}

	memcpy(&key_id, priv_key->buf, sizeof(key_id));

	/* The private key lives in PSA and is never exported - we only hold its
	 * key id. Wrap that id into an opaque PK context (mbedtls_pk_wrap_psa)
	 * so mbedTLS delegates every signature back to PSA instead of needing
	 * the raw key. mbedtls_pk_wrap_psa() takes an mbedtls_svc_key_id_t, so
	 * build one from the key id with owner 0 (the local/default owner).
	 */
	svc_key_id = mbedtls_svc_key_id_make(0, key_id);

	err = mbedtls_pk_wrap_psa(&tls->priv_key, svc_key_id);
	if (err != 0) {
		return -EINVAL;
	}

	return 0;
#else
	return -ENOTSUP;
#endif /* CONFIG_MBEDTLS_X509_CRT_PARSE_C && TLS_PRIV_KEY_PSA_ENABLED */
}

static int tls_set_psk(struct tls_context *tls,
		       struct tls_credential *psk,
		       struct tls_credential *psk_id)
{
#if defined(CONFIG_WOLFSSL)
#ifndef NO_PSK
	if (NULL != tls->psk) {
		wc_ForceZero(tls->psk, tls->psk_len);
		XFREE(tls->psk, NULL, DYNAMIC_TYPE_TMP_BUFFER);
		tls->psk = NULL;
		tls->psk_len = 0;
	}
	tls->psk = (byte *)XMALLOC(
			psk->len, NULL, DYNAMIC_TYPE_TMP_BUFFER);
	if (tls->psk == NULL) {
		return -ENOMEM;
	}

	XMEMCPY(tls->psk, psk->buf, psk->len);
	tls->psk_len = psk->len;

	if (NULL != tls->psk_id) {
		XFREE(tls->psk_id, NULL, DYNAMIC_TYPE_TMP_BUFFER);
		tls->psk_id = NULL;
		tls->psk_id_len = 0;
	}
	tls->psk_id = (byte *)XMALLOC(
			psk_id->len + 1, NULL, DYNAMIC_TYPE_TMP_BUFFER);
	if (tls->psk_id == NULL) {
		wc_ForceZero(tls->psk, tls->psk_len);
		XFREE(tls->psk, NULL, DYNAMIC_TYPE_TMP_BUFFER);
		tls->psk = NULL;
		tls->psk_len = 0;
		return -ENOMEM;
	}

	XMEMCPY(tls->psk_id, psk_id->buf, psk_id->len);
	tls->psk_id[psk_id->len] = '\0';
	tls->psk_id_len = psk_id->len;

	return 0;
#else
	return -ENOTSUP;
#endif /* !NO_PSK */
#else
#if defined(MBEDTLS_SSL_HANDSHAKE_WITH_PSK_ENABLED)
	int err = mbedtls_ssl_conf_psk(&tls->config,
				       psk->buf, psk->len,
				       (const unsigned char *)psk_id->buf,
				       psk_id->len);
	if (err != 0) {
		return -EINVAL;
	}

	return 0;
#endif
#endif /* CONFIG_WOLFSSL */

	return -ENOTSUP;
}

static int tls_set_credential(struct tls_context *tls,
			      struct tls_credential *cred)
{
	switch (cred->type) {
	case TLS_CREDENTIAL_CA_CERTIFICATE:
		return tls_add_ca_certificate(tls, cred);

	case TLS_CREDENTIAL_PUBLIC_CERTIFICATE:
		return tls_add_own_cert(tls, cred);

	case TLS_CREDENTIAL_PRIVATE_KEY:
		return tls_set_private_key(tls, cred);
	break;

	case TLS_CREDENTIAL_PRIVATE_KEY_PSA:
		return tls_set_private_key_psa(tls, cred);
	break;

	case TLS_CREDENTIAL_PSK:
	{
		struct tls_credential *psk_id =
			credential_get(cred->tag, TLS_CREDENTIAL_PSK_ID);
		if (!psk_id) {
			return -ENOENT;
		}

		return tls_set_psk(tls, cred, psk_id);
	}

	case TLS_CREDENTIAL_PSK_ID:
		/* Ignore PSK ID - it will be used together
		 * with PSK
		 */
		break;

	default:
		return -EINVAL;
	}

	return 0;
}

#if defined(CONFIG_MBEDTLS)
static int tls_mbedtls_set_credentials(struct tls_context *tls)
{
	struct tls_credential *cred;
	sec_tag_t tag;
	int i, err = 0;
	bool tag_found, ca_cert_present = false, own_cert_present = false;

	credentials_lock();

	for (i = 0; i < tls->options.sec_tag_list.sec_tag_count; i++) {
		tag = tls->options.sec_tag_list.sec_tags[i];
		cred = NULL;
		tag_found = false;

		while ((cred = credential_next_get(tag, cred)) != NULL) {
			tag_found = true;

			err = tls_set_credential(tls, cred);
			if (err != 0) {
				goto exit;
			}

			if (cred->type == TLS_CREDENTIAL_CA_CERTIFICATE) {
				ca_cert_present = true;
			} else if (cred->type == TLS_CREDENTIAL_PUBLIC_CERTIFICATE) {
				own_cert_present = true;
			}
		}

		if (!tag_found) {
			err = -ENOENT;
			goto exit;
		}
	}

exit:
	credentials_unlock();

	if (err == 0) {
		if (ca_cert_present) {
			tls_set_ca_chain(tls);
		}
		if (own_cert_present) {
			err = tls_set_own_cert(tls);
		}
	}

	return err;
}

static int tls_mbedtls_reset_session(struct tls_context *context)
{
	int ret;

	ret = mbedtls_ssl_session_reset(&context->active_session->ssl);
	if (ret != 0) {
		return ret;
	}

	context->active_session->handshake_timestamp = 0;

	k_sem_reset(&context->active_session->tls_established);

#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
	/* Server role: reset the address so that a new
	 *              client can connect w/o a need to reopen a socket
	 * Client role: keep peer addr so socket can continue to be used
	 *              even on handshake timeout
	 */
	if (context->options.role == MBEDTLS_SSL_IS_SERVER) {
		(void)memset(&context->active_session->dtls_peer_addr, 0,
			     sizeof(context->active_session->dtls_peer_addr));
		context->active_session->dtls_peer_addrlen = 0;
	}
#endif

	return 0;
}

static int tls_mbedtls_handshake(struct tls_context *context,
				 k_timeout_t timeout)
{
	k_timepoint_t end;
	int ret;

	context->active_session->handshake_in_progress = true;

	end = sys_timepoint_calc(timeout);

	while ((ret = mbedtls_ssl_handshake(&context->active_session->ssl)) != 0) {
		if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
		    ret == MBEDTLS_ERR_SSL_WANT_WRITE ||
		    ret == MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS ||
		    ret == MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS) {
			int timeout_ms;

			/* Blocking timeout. */
			timeout = sys_timepoint_timeout(end);
			if (K_TIMEOUT_EQ(timeout, K_NO_WAIT)) {
				ret = -EAGAIN;
				break;
			}

			/* Block. */
			timeout_ms = timeout_to_ms(&timeout);

#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
			if (context->type == NET_SOCK_DGRAM) {
				if (context->options.role == MBEDTLS_SSL_IS_SERVER) {
					/* DTLS server may need to switch session. */
					int err = dtls_server_switch_session_on_rx(context);

					if (err == 0) {
						/* Switched the session, repeat the loop. */
						context->active_session->handshake_in_progress =
							true;
						continue;
					}
				}

				int timeout_dtls =
					dtls_get_remaining_timeout(context->active_session);

				if (timeout_dtls != SYS_FOREVER_MS) {
					if (timeout_ms == SYS_FOREVER_MS) {
						timeout_ms = timeout_dtls;
					} else {
						timeout_ms = MIN(timeout_dtls,
								 timeout_ms);
					}
				}
			}
#endif /* CONFIG_NET_SOCKETS_ENABLE_DTLS */

			ret = wait_for_reason(context->sock, timeout_ms, ret);
			if (ret != 0) {
				break;
			}

			continue;
		} else if (ret == MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED) {
			ret = tls_mbedtls_reset_session(context);
			if (ret == 0) {
				if (!K_TIMEOUT_EQ(timeout, K_NO_WAIT)) {
					continue;
				}

				ret = -EAGAIN;
				break;
			}
		} else if (ret == MBEDTLS_ERR_SSL_TIMEOUT) {
			/* MbedTLS API documentation requires session to
			 * be reset in this case
			 */
			ret = tls_mbedtls_reset_session(context);
			if (ret == 0) {
				NET_ERR("TLS handshake timeout");
				context->error = ETIMEDOUT;
				ret = -ETIMEDOUT;
				break;
			}
		} else {
			/* MbedTLS API documentation requires session to
			 * be reset in other error cases
			 */
			NET_ERR("TLS handshake error: -0x%x", -ret);
			ret = tls_mbedtls_reset_session(context);
			if (ret == 0) {
				context->error = ECONNABORTED;
				ret = -ECONNABORTED;
				break;
			}
		}

		/* Avoid constant loop if tls_mbedtls_reset_session fails */
		NET_ERR("TLS reset error: -0x%x", -ret);
		context->error = ECONNABORTED;
		ret = -ECONNABORTED;
		break;
	}

	if (ret == 0) {
		context->active_session->handshake_timestamp = k_uptime_get();
		k_sem_give(&context->active_session->tls_established);
	}

	context->active_session->handshake_in_progress = false;

	return ret;
}

static int tls_mbedtls_session_init(struct tls_session_context *session_ctx,
				    struct tls_context *tls_ctx, bool is_server)
{
	int ret;

#if defined(CONFIG_MBEDTLS_X509_CRT_PARSE_C)
	/* For TLS clients, set hostname to empty string to enforce it's
	 * verification - only if hostname option was not set. Otherwise
	 * depend on user configuration.
	 */
	if (!is_server && !tls_ctx->options.is_hostname_set) {
		ret = mbedtls_ssl_set_hostname(&session_ctx->ssl, "");
		if (ret != 0) {
			return -ENOMEM;
		}
	}
#endif

	ret = mbedtls_ssl_setup(&session_ctx->ssl, &tls_ctx->config);
	if (ret != 0) {
		/* According to Mbed TLS API documentation,
		 * mbedtls_ssl_setup can fail due to memory allocation failure
		 */
		return -ENOMEM;
	}

	if (tls_ctx->type == NET_SOCK_STREAM) {
		mbedtls_ssl_set_bio(&session_ctx->ssl, tls_ctx,
				    tls_tx, tls_rx, NULL);
	} else {
#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
		mbedtls_ssl_set_bio(&session_ctx->ssl, tls_ctx, dtls_tx,
				    is_server ? dtls_server_rx : dtls_client_rx,
				    NULL);

		/* DTLS requires timer callbacks to operate */
		mbedtls_ssl_set_timer_cb(&session_ctx->ssl,
					 &session_ctx->dtls_timing,
					 dtls_timing_set_delay,
					 dtls_timing_get_delay);

		dtls_server_init_session_timeout(session_ctx);

#if defined(CONFIG_MBEDTLS_SSL_DTLS_CONNECTION_ID)
		if (tls_ctx->options.dtls_cid.enabled) {
			ret = mbedtls_ssl_set_cid(&session_ctx->ssl, MBEDTLS_SSL_CID_ENABLED,
						  tls_ctx->options.dtls_cid.cid,
						  tls_ctx->options.dtls_cid.cid_len);
			if (ret != 0) {
				return -EINVAL;
			}
		}
#endif /* CONFIG_MBEDTLS_SSL_DTLS_CONNECTION_ID */
#else /* CONFIG_NET_SOCKETS_ENABLE_DTLS */
		return -ENOTSUP;
#endif /* CONFIG_NET_SOCKETS_ENABLE_DTLS */
	}

	return 0;
}

static int tls_mbedtls_init(struct tls_context *context, bool is_server)
{
	int role, type, ret;

	role = is_server ? MBEDTLS_SSL_IS_SERVER : MBEDTLS_SSL_IS_CLIENT;

	type = (context->type == NET_SOCK_STREAM) ?
		MBEDTLS_SSL_TRANSPORT_STREAM :
		MBEDTLS_SSL_TRANSPORT_DATAGRAM;

	ret = mbedtls_ssl_config_defaults(&context->config, role, type,
					  MBEDTLS_SSL_PRESET_DEFAULT);
	if (ret != 0) {
		/* According to Mbed TLS API documentation,
		 * mbedtls_ssl_config_defaults can fail due to memory
		 * allocation failure
		 */
		return -ENOMEM;
	}
	tls_set_max_frag_len(context, context->type);

	switch (context->tls_version) {
	case NET_IPPROTO_TLS_1_3:
		mbedtls_ssl_conf_min_tls_version(&context->config, MBEDTLS_SSL_VERSION_TLS1_3);
		break;
	case NET_IPPROTO_TLS_1_2:
	case NET_IPPROTO_DTLS_1_2:
		mbedtls_ssl_conf_min_tls_version(&context->config, MBEDTLS_SSL_VERSION_TLS1_2);
		break;
	case NET_IPPROTO_TLS_1_0:
	case NET_IPPROTO_TLS_1_1:
	case NET_IPPROTO_DTLS_1_0:
		/* Nothing to do */
		break;
	default:
		NET_ASSERT(false, "Unknown (D)TLS version, cannot specify minimum requirement");
		break;
	}

#if defined(MBEDTLS_SSL_RENEGOTIATION)
	mbedtls_ssl_conf_legacy_renegotiation(&context->config,
					   MBEDTLS_SSL_LEGACY_BREAK_HANDSHAKE);
	mbedtls_ssl_conf_renegotiation(&context->config,
				       MBEDTLS_SSL_RENEGOTIATION_ENABLED);
#endif

#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
	if (type == MBEDTLS_SSL_TRANSPORT_DATAGRAM) {
		mbedtls_ssl_conf_handshake_timeout(&context->config,
				context->options.dtls_handshake_timeout_min,
				context->options.dtls_handshake_timeout_max);

#if defined(CONFIG_MBEDTLS_SSL_DTLS_CONNECTION_ID)
		if (context->options.dtls_cid.enabled) {
			ret = mbedtls_ssl_conf_cid(
					&context->config,
					context->options.dtls_cid.cid_len,
					MBEDTLS_SSL_UNEXPECTED_CID_IGNORE);
			if (ret != 0) {
				return -EINVAL;
			}
		}
#endif /* CONFIG_MBEDTLS_SSL_DTLS_CONNECTION_ID */

		/* Configure cookie for DTLS server */
		if (role == MBEDTLS_SSL_IS_SERVER) {
			ret = mbedtls_ssl_cookie_setup(&context->cookie);
			if (ret != 0) {
				return -ENOMEM;
			}

			mbedtls_ssl_conf_dtls_cookies(&context->config,
						      mbedtls_ssl_cookie_write,
						      mbedtls_ssl_cookie_check,
						      &context->cookie);

			mbedtls_ssl_conf_read_timeout(
					&context->config,
					CONFIG_NET_SOCKETS_DTLS_TIMEOUT);
		}
	}
#endif /* CONFIG_NET_SOCKETS_ENABLE_DTLS */

	/* If verification level was specified explicitly, set it. Otherwise,
	 * use Mbed TLS default values (required for client, none for server)
	 */
	if (context->options.verify_level != -1) {
		mbedtls_ssl_conf_authmode(&context->config,
					  context->options.verify_level);
	}

	ret = tls_mbedtls_set_credentials(context);
	if (ret != 0) {
		return ret;
	}

	if (context->options.ciphersuites[0] != 0) {
		/* Specific ciphersuites configured, so use them */
		NET_DBG("Using user-specified ciphersuites");
		mbedtls_ssl_conf_ciphersuites(&context->config,
					      context->options.ciphersuites);
	}

#if defined(CONFIG_MBEDTLS_SSL_ALPN)
	if (ALPN_MAX_PROTOCOLS && context->options.alpn_list[0] != NULL) {
		ret = mbedtls_ssl_conf_alpn_protocols(&context->config,
				context->options.alpn_list);
		if (ret != 0) {
			return -EINVAL;
		}
	}
#endif /* CONFIG_MBEDTLS_SSL_ALPN */

#if defined(MBEDTLS_SSL_CACHE_C)
	if (is_server && context->options.cache_enabled) {
		mbedtls_ssl_conf_session_cache(&context->config, &server_cache,
					       mbedtls_ssl_cache_get,
					       mbedtls_ssl_cache_set);
	}
#endif

#if defined(MBEDTLS_SSL_EARLY_DATA)
	mbedtls_ssl_conf_early_data(&context->config, MBEDTLS_SSL_EARLY_DATA_ENABLED);
#endif

#if defined(CONFIG_NET_SOCKETS_TLS_CERT_VERIFY_CALLBACK)
	if (context->options.cert_verify.cb != NULL) {
		mbedtls_ssl_conf_verify(&context->config,
					context->options.cert_verify.cb,
					context->options.cert_verify.ctx);
	}
#endif /* CONFIG_NET_SOCKETS_TLS_CERT_VERIFY_CALLBACK */

	ret = tls_mbedtls_session_init(context->active_session, context, is_server);
	if (ret < 0) {
		return ret;
	}

	context->is_initialized = true;

	return 0;
}
#endif /* CONFIG_MBEDTLS */

#if defined(CONFIG_WOLFSSL)
#ifndef NO_PSK
static unsigned int tls_psk_server_cb(WOLFSSL *ssl, const char *identity,
				      unsigned char *key,
				      unsigned int key_max_len)
{
	struct tls_context *context = NULL;

	context = (struct tls_context *)wolfSSL_get_psk_callback_ctx(ssl);
	if (context == NULL) {
		return 0;
	}

	if (context->psk == NULL || context->psk_id == NULL) {
		return 0;
	}

	if (context->psk_len == 0 || context->psk_len > key_max_len) {
		return 0;
	}

	/* The PSK ID is length-delimited, so a prefix of it must not match */
	if (XSTRLEN(identity) != context->psk_id_len ||
	    XMEMCMP(identity, context->psk_id, context->psk_id_len) != 0) {
		return 0;
	}

	XMEMCPY(key, context->psk, context->psk_len);

	return context->psk_len;
}

static unsigned int tls_psk_client_cb(WOLFSSL *ssl, const char *hint,
				      char *identity,
				      unsigned int id_max_len,
				      unsigned char *key,
				      unsigned int key_max_len)
{
	struct tls_context *context = NULL;

	context = (struct tls_context *)wolfSSL_get_psk_callback_ctx(ssl);
	if (context == NULL) {
		return 0;
	}

	if (context->psk == NULL || context->psk_id == NULL) {
		return 0;
	}

	if (context->psk_len == 0 || context->psk_len > key_max_len ||
	    context->psk_id_len == 0 ||
	    context->psk_id_len + 1 > id_max_len) {
		return 0;
	}

	XMEMCPY(identity, context->psk_id, context->psk_id_len);
	identity[context->psk_id_len] = '\0';
	XMEMCPY(key, context->psk, context->psk_len);

	return context->psk_len;
}

#ifdef WOLFSSL_TLS13
/* TLS 1.3 PSK callbacks */
static unsigned int tls_psk_server_tls13_cb(WOLFSSL *ssl, const char *identity,
					    unsigned char *key,
					    unsigned int key_max_len,
					    const char **ciphersuite)
{
	unsigned int key_len = tls_psk_server_cb(ssl, identity, key, key_max_len);

	if (key_len == 0) {
		return 0;
	}

	*ciphersuite = tls13_psk_default_ciphersuite;
	return key_len;
}

static unsigned int tls_psk_client_tls13_cb(WOLFSSL *ssl, const char *hint,
					    char *identity,
					    unsigned int id_max_len,
					    unsigned char *key,
					    unsigned int key_max_len,
					    const char **ciphersuite)
{
	unsigned int key_len = tls_psk_client_cb(ssl, hint, identity,
						 id_max_len, key, key_max_len);

	if (key_len == 0) {
		return 0;
	}

	*ciphersuite = tls13_psk_default_ciphersuite;
	return key_len;
}
#endif /* WOLFSSL_TLS13 */
#endif /* !NO_PSK */

static int tls_wolfssl_set_credentials(struct tls_context *tls)
{
	struct tls_credential *cred;
	sec_tag_t tag;
	int i, err = 0;
	bool tag_found;

	credentials_lock();

	for (i = 0; i < tls->options.sec_tag_list.sec_tag_count; i++) {
		tag = tls->options.sec_tag_list.sec_tags[i];
		cred = NULL;
		tag_found = false;

		while ((cred = credential_next_get(tag, cred)) != NULL) {
			tag_found = true;

			err = tls_set_credential(tls, cred);
			if (err != 0) {
				goto exit;
			}
		}

		if (!tag_found) {
			err = -ENOENT;
			goto exit;
		}
	}

exit:
	credentials_unlock();

	return err;
}

static int tls_wolfssl_set_session_cache_mode(struct tls_context *context)
{
#if !defined(NO_SESSION_CACHE)
	if ((context->options.role == ZTLS_IS_SERVER) &&
	    (0 == context->options.cache_enabled)) {
		if (wolfSSL_CTX_set_session_cache_mode(context->ctx,
				SSL_SESS_CACHE_OFF) != WOLFSSL_SUCCESS) {
			return -EINVAL;
		}
	}
#else
	/* Nothing caches a session, so TLS_SESSION_CACHE is already off. */
	ARG_UNUSED(context);
#endif /* !NO_SESSION_CACHE */

	return 0;
}

static int tls_wolfssl_set_hostname(struct tls_context *context,
				    struct tls_session_context *session_ctx)
{
	if (context->options.role != ZTLS_IS_CLIENT) {
		if (context->options.is_hostname_set &&
		    !context->server_hostname_warned) {
			/* TLS_HOSTNAME has no effect on a server, as on mbedTLS */
			context->server_hostname_warned = true;
			NET_WARN("TLS_HOSTNAME set on a server socket is "
				 "ignored; no CN/SAN match is performed "
				 "against client certs.");
		}
		return 0;
	}

#if defined(HAVE_SNI)
	if (context->options.is_hostname_set) {
		if (wolfSSL_UseSNI(session_ctx->wssl, WOLFSSL_SNI_HOST_NAME,
				   (const char *)context->host_name,
				   context->host_len) != WOLFSSL_SUCCESS) {
			return -EINVAL;
		}
	}
#endif /* HAVE_SNI */

	/* Without HAVE_SNI the name still drives the CN/SAN match. */

#if !defined(OPENSSL_EXTRA) && !defined(OPENSSL_EXTRA_X509_SMALL)
	/* No current_cert without the compat layer, so wolfSSL matches the name itself. */
	if (context->options.is_hostname_set &&
	    context->options.verify_level != ZSOCK_TLS_PEER_VERIFY_NONE &&
	    wolfSSL_check_domain_name(session_ctx->wssl,
				      (const char *)context->host_name) !=
	    WOLFSSL_SUCCESS) {
		if (context->options.verify_level != ZSOCK_TLS_PEER_VERIFY_OPTIONAL) {
			return -EINVAL;
		}
		session_ctx->verify_result_flags |= MBEDTLS_X509_BADCERT_CN_MISMATCH;
	}
#endif /* !OPENSSL_EXTRA && !OPENSSL_EXTRA_X509_SMALL */

	return 0;
}

#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
/* True when the leaf cert's CN/SAN matches the client's TLS_HOSTNAME */
static bool tls_wolfssl_leaf_hostname_matches(struct tls_context *context,
					      WOLFSSL_X509 *cert)
{
	int ret;

	if (cert == NULL) {
		return false;
	}

	ret = wolfSSL_X509_check_host(cert,
				      (const char *)context->host_name,
				      context->host_len, 0, NULL);
	return ret == WOLFSSL_SUCCESS;
}
#endif /* OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL */

/* Flags BADCERT_CN_MISMATCH and clears *effective_ok when the leaf misses TLS_HOSTNAME */
static void tls_wolfssl_apply_leaf_hostname_check(struct tls_context *context,
						  struct tls_session_context *session_ctx,
						  WOLFSSL_X509_STORE_CTX *store,
						  int *effective_ok)
{
	if (store->error_depth != 0) {
		return;
	}
	if (context->options.role != ZTLS_IS_CLIENT) {
		return;
	}
	/* Keeps NONE from being stricter than OPTIONAL */
	if (context->options.verify_level == ZSOCK_TLS_PEER_VERIFY_NONE) {
		return;
	}
	/* No name set matches no certificate, like the empty name mbedTLS sets */
	if (!context->options.is_hostname_set || context->host_len == 0) {
		session_ctx->verify_result_flags |= MBEDTLS_X509_BADCERT_CN_MISMATCH;
		*effective_ok = 0;
		return;
	}
#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
	if (tls_wolfssl_leaf_hostname_matches(context, store->current_cert)) {
		return;
	}

	session_ctx->verify_result_flags |= MBEDTLS_X509_BADCERT_CN_MISMATCH;
	*effective_ok = 0;
#else
	/* tls_wolfssl_set_hostname() armed wolfSSL's match; a mismatch arrives in store->error. */
#endif /* OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL */
}

/* Map wolfSSL verify error to mbedTLS flag bits. */
static uint32_t tls_wolfssl_error_to_mbedtls_flags(int error)
{
	switch (error) {
	case 0:
		return 0;
	case ASN_AFTER_DATE_E:
		return MBEDTLS_X509_BADCERT_EXPIRED;
	case ASN_BEFORE_DATE_E:
		return MBEDTLS_X509_BADCERT_FUTURE;
	case ASN_NO_SIGNER_E:
	case ASN_SELF_SIGNED_E:
		return MBEDTLS_X509_BADCERT_NOT_TRUSTED;
	case CRL_CERT_REVOKED:
	case OCSP_CERT_REVOKED:
		return MBEDTLS_X509_BADCERT_REVOKED;
	case DOMAIN_NAME_MISMATCH:
		return MBEDTLS_X509_BADCERT_CN_MISMATCH;
	case ASN_SIG_CONFIRM_E:
	case ASN_SIG_HASH_E:
	case ASN_SIG_KEY_E:
		return MBEDTLS_X509_BADCERT_NOT_TRUSTED;
	case EXT_NOT_ALLOWED:
	case KEYUSAGE_E:
		return MBEDTLS_X509_BADCERT_KEY_USAGE;
	case EXTKEYUSAGE_E:
		return MBEDTLS_X509_BADCERT_EXT_KEY_USAGE;
	case CRL_CERT_DATE_ERR:
		return MBEDTLS_X509_BADCRL_EXPIRED;
	case ASN_CRL_NO_SIGNER_E:
		return MBEDTLS_X509_BADCRL_NOT_TRUSTED;
	case ASN_PATHLEN_SIZE_E:
	case ASN_PATHLEN_INV_E:
	case MAX_CHAIN_ERROR:
	case NOT_CA_ERROR:
		return MBEDTLS_X509_BADCERT_NOT_TRUSTED;
	case ASN_NO_PEM_HEADER:
		return MBEDTLS_X509_BADCERT_MISSING;
	default:
		return MBEDTLS_X509_BADCERT_OTHER;
	}
}

static int tls_wolfssl_verify_accumulate_cb(int preverify_ok,
					     WOLFSSL_X509_STORE_CTX *store)
{
	struct tls_session_context *session_ctx;
	struct tls_context *context;
	int effective_ok;

	if (store == NULL || store->userCtx == NULL) {
		return preverify_ok;
	}

	session_ctx = (struct tls_session_context *)store->userCtx;
	context = session_ctx->tls_ctx;
	effective_ok = preverify_ok;

	if (!preverify_ok && store->error != 0) {
		session_ctx->verify_result_flags |=
			tls_wolfssl_error_to_mbedtls_flags(store->error);
	}

	tls_wolfssl_apply_leaf_hostname_check(context, session_ctx, store, &effective_ok);

	/* OPTIONAL continues; warn, since an unread TLS_CERT_VERIFY_RESULT hides a bad chain */
	if (context->options.verify_level == ZSOCK_TLS_PEER_VERIFY_OPTIONAL) {
		/* The leaf comes last, so this warns once per handshake */
		if (store->error_depth == 0 && session_ctx->verify_result_flags != 0) {
			NET_WARN("TLS_PEER_VERIFY_OPTIONAL: accepting chain with "
				 "verify_result_flags=0x%x; application should "
				 "read TLS_CERT_VERIFY_RESULT before trusting the peer",
				 session_ctx->verify_result_flags);
		}
		return 1;
	}

	return effective_ok;
}

#if defined(CONFIG_NET_SOCKETS_TLS_WOLFSSL_VERIFY_CALLBACK)
static int tls_wolfssl_verify_cb_wrapper(int preverify_ok,
					 WOLFSSL_X509_STORE_CTX *store)
{
	struct tls_session_context *session_ctx;
	struct tls_context *context;
	zsock_tls_wolfssl_verify_cb_t user_cb;
	void *user_ctx;
	int effective_ok;
	int ret;

	if (store == NULL || store->userCtx == NULL) {
		return preverify_ok;
	}

	session_ctx = (struct tls_session_context *)store->userCtx;
	context = session_ctx->tls_ctx;
	effective_ok = preverify_ok;

	if (!preverify_ok && store->error != 0) {
		session_ctx->verify_result_flags |=
			tls_wolfssl_error_to_mbedtls_flags(store->error);
	}

	/* The application callback sees the same preverify_ok as the default one */
	tls_wolfssl_apply_leaf_hostname_check(context, session_ctx, store, &effective_ok);

	user_cb = context->options.cert_verify_wolfssl.cb;
	user_ctx = context->options.cert_verify_wolfssl.ctx;
	__ASSERT(user_cb != NULL,
		 "verify wrapper installed without a user callback");

	/* The application's ctx travels in store->userCtx for this synchronous call only */
	store->userCtx = user_ctx;
	ret = user_cb(effective_ok, store);
	store->userCtx = session_ctx;

	return ret;
}
#endif /* CONFIG_NET_SOCKETS_TLS_WOLFSSL_VERIFY_CALLBACK */

static int tls_wolfssl_set_verify(struct tls_context *context,
				  struct tls_session_context *session_ctx)
{
	int verifyLevel = -1;
	VerifyCallback cb = NULL;

	if (context->options.verify_level != -1) {
		switch (context->options.verify_level) {
		case ZSOCK_TLS_PEER_VERIFY_NONE:
			verifyLevel = WOLFSSL_VERIFY_NONE;
			break;
		case ZSOCK_TLS_PEER_VERIFY_OPTIONAL:
			verifyLevel = WOLFSSL_VERIFY_PEER;
			break;
		case ZSOCK_TLS_PEER_VERIFY_REQUIRED:
			if (context->options.role == ZTLS_IS_SERVER) {
				verifyLevel = WOLFSSL_VERIFY_PEER |
					      WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT |
					      WOLFSSL_VERIFY_FAIL_EXCEPT_PSK;
			} else {
				verifyLevel = WOLFSSL_VERIFY_PEER;
			}
			break;
		default:
			return -EINVAL;
		}
	}

	wolfSSL_SetCertCbCtx(session_ctx->wssl, session_ctx);

#if defined(CONFIG_NET_SOCKETS_TLS_WOLFSSL_VERIFY_CALLBACK)
	if (context->options.cert_verify_wolfssl.cb != NULL) {
		cb = tls_wolfssl_verify_cb_wrapper;
	} else {
		cb = tls_wolfssl_verify_accumulate_cb;
	}
#else
	cb = tls_wolfssl_verify_accumulate_cb;
#endif /* CONFIG_NET_SOCKETS_TLS_WOLFSSL_VERIFY_CALLBACK */

	if (verifyLevel == -1) {
		/* Match mbedTLS defaults: required for clients, none for servers. */
		if (context->options.role == ZTLS_IS_SERVER) {
			verifyLevel = WOLFSSL_VERIFY_NONE;
		} else {
			verifyLevel = WOLFSSL_VERIFY_PEER;
		}
	}
	wolfSSL_set_verify(session_ctx->wssl, verifyLevel, cb);

	return 0;
}

static int tls_wolfssl_set_ciphersuites(struct tls_context *context,
					struct tls_session_context *session_ctx)
{
	/* mbedTLS-style suite IDs are ints; wolfSSL takes big-endian byte pairs */
	byte cs_bytes[CONFIG_NET_SOCKETS_TLS_MAX_CIPHERSUITES * 2];
	int cipher_cnt = 0;

	/* Nothing to set */
	if (context->options.ciphersuites[0] == 0) {
		return 0;
	}

	for (int i = 0; context->options.ciphersuites[i] != 0; i++) {
		int id = context->options.ciphersuites[i];

		if (cipher_cnt >= CONFIG_NET_SOCKETS_TLS_MAX_CIPHERSUITES) {
			return -EINVAL;
		}

		/* All ciphersuite IDs fit in 16 bits */
		if (id < 0 || id > 0xFFFF) {
			return -EINVAL;
		}

		sys_put_be16((uint16_t)id, &cs_bytes[cipher_cnt * 2]);
		cipher_cnt++;
	}

	if (wolfSSL_set_cipher_list_bytes(session_ctx->wssl, cs_bytes,
					  cipher_cnt * 2) != WOLFSSL_SUCCESS) {
		return -EINVAL;
	}

	return 0;
}

#ifdef HAVE_ALPN
static int tls_wolfssl_set_alpn(struct tls_context *context,
				struct tls_session_context *session_ctx)
{
	if (context->alpn_joined != NULL &&
	    wolfSSL_UseALPN(session_ctx->wssl, context->alpn_joined,
			    XSTRLEN(context->alpn_joined),
			    WOLFSSL_ALPN_FAILED_ON_MISMATCH) != WOLFSSL_SUCCESS) {
		return -EINVAL;
	}

	return 0;
}

/* Joins a TLS_ALPN_LIST into the comma separated form wolfSSL_UseALPN() takes */
static int tls_wolfssl_alpn_join(const char * const *list, int cnt, char **joined)
{
	size_t len = 0;
	char *iter;
	int i;

	*joined = NULL;

	/* Like Mbed TLS, the list ends at the first NULL */
	for (i = 0; i < cnt && list[i] != NULL; i++) {
		if (list[i][0] == '\0' || strchr(list[i], ',') != NULL) {
			return -EINVAL;
		}

		len += XSTRLEN(list[i]) + 1;
	}

	if (len == 0) {
		return 0;
	}

	*joined = XMALLOC(len, NULL, DYNAMIC_TYPE_TMP_BUFFER);
	if (*joined == NULL) {
		return -ENOMEM;
	}

	iter = *joined;
	for (i = 0; i < cnt && list[i] != NULL; i++) {
		size_t proto_len = XSTRLEN(list[i]);

		XMEMCPY(iter, list[i], proto_len);
		iter += proto_len;
		*iter++ = ',';
	}

	/* The last comma becomes the terminator */
	*(iter - 1) = '\0';

	return 0;
}
#endif /* HAVE_ALPN */

#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
static int tls_wolfssl_set_dtls_timeouts(struct tls_context *context,
					 struct tls_session_context *session_ctx)
{
	if (context->type == NET_SOCK_DGRAM) {
		int init_s;
		int max_s;

		/* wolfSSL takes whole seconds; round up so a sub-second value does not become 0. */
		init_s = (int)((context->options.dtls_handshake_timeout_min +
				MSEC_PER_SEC - 1) / MSEC_PER_SEC);
		if (init_s < 1) {
			init_s = 1;
		}
		max_s = (int)((context->options.dtls_handshake_timeout_max +
			       MSEC_PER_SEC - 1) / MSEC_PER_SEC);
		if (max_s < init_s) {
			max_s = init_s;
		}

		/* Lower init first: wolfSSL rejects a max below the current init. */
		if (wolfSSL_dtls_set_timeout_init(session_ctx->wssl, 1) != WOLFSSL_SUCCESS ||
		    wolfSSL_dtls_set_timeout_max(session_ctx->wssl, max_s) != WOLFSSL_SUCCESS ||
		    wolfSSL_dtls_set_timeout_init(session_ctx->wssl, init_s) != WOLFSSL_SUCCESS) {
			return -EINVAL;
		}

		/* Underlying socket always acts like non-blocking due to IO callback overrides */
		wolfSSL_dtls_set_using_nonblock(session_ctx->wssl, 1);
	}

	return 0;
}
#endif

/* Pushes a stored option into live sessions; one that refuses it does not fail setsockopt */
static int tls_wolfssl_apply_all_sessions(
	struct tls_context *context,
	int (*setter)(struct tls_context *context,
		      struct tls_session_context *session_ctx))
{
	struct tls_session_context *session_ctx;
	int ret;

	SYS_SLIST_FOR_EACH_CONTAINER(&context->sessions, session_ctx, node) {
		if (session_ctx->wssl == NULL) {
			continue;
		}

		ret = setter(context, session_ctx);
		if (ret != 0) {
			NET_WARN("Failed to apply TLS option to live session "
				 "%p (%d); new sessions will use it",
				 session_ctx, ret);
		}
	}

	return 0;
}

/* Apply all per-SSL-object settings. Runs both on first session init and
 * again after wolfSSL_clear() in tls_wolfssl_reset_session - wolfSSL_clear
 * drops per-SSL state configured after wolfSSL_new().
 */
static int tls_wolfssl_session_setup(struct tls_session_context *session_ctx,
				     struct tls_context *tls_ctx, bool is_server)
{
	int ret;

	/* The verify callbacks reach the session through this */
	session_ctx->tls_ctx = tls_ctx;

	if (wolfSSL_set_fd(session_ctx->wssl, tls_ctx->sock) != WOLFSSL_SUCCESS) {
		return -EINVAL;
	}

	if (tls_ctx->type == NET_SOCK_STREAM) {
		wolfSSL_SSLSetIORecv(session_ctx->wssl, tls_wolf_rx);
		wolfSSL_SSLSetIOSend(session_ctx->wssl, tls_wolf_tx);
	}
#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
	else if (tls_ctx->type == NET_SOCK_DGRAM) {
		wolfSSL_SSLSetIORecv(session_ctx->wssl,
				     is_server ? dtls_wolf_server_rx :
						 dtls_wolf_client_rx);
		wolfSSL_SSLSetIOSend(session_ctx->wssl, dtls_wolf_tx);
	}
#endif /* CONFIG_NET_SOCKETS_ENABLE_DTLS */
	else {
		return -EINVAL;
	}

	/* Set our TLS context as the read/write context since it contains the socket */
	wolfSSL_SetIOReadCtx(session_ctx->wssl, (void *)tls_ctx);
	wolfSSL_SetIOWriteCtx(session_ctx->wssl, (void *)tls_ctx);

#ifndef NO_PSK
	if (NULL != tls_ctx->psk) {
		wolfSSL_set_psk_callback_ctx(session_ctx->wssl, (void *)tls_ctx);
	}
#endif /* !NO_PSK */

	session_ctx->verify_result_flags = 0;

	ret = tls_wolfssl_set_verify(tls_ctx, session_ctx);
	if (ret != 0) {
		return ret;
	}

	ret = tls_wolfssl_set_hostname(tls_ctx, session_ctx);
	if (ret != 0) {
		return ret;
	}

	ret = tls_wolfssl_set_ciphersuites(tls_ctx, session_ctx);
	if (ret != 0) {
		return ret;
	}

#ifdef HAVE_ALPN
	ret = tls_wolfssl_set_alpn(tls_ctx, session_ctx);
	if (ret != 0) {
		return ret;
	}
#endif /* HAVE_ALPN */

#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
	ret = tls_wolfssl_set_dtls_timeouts(tls_ctx, session_ctx);
	if (ret != 0) {
		return ret;
	}

	dtls_server_init_session_timeout(session_ctx);
#endif /* CONFIG_NET_SOCKETS_ENABLE_DTLS */

	return 0;
}

static int tls_wolfssl_session_init(struct tls_session_context *session_ctx,
				    struct tls_context *tls_ctx, bool is_server)
{
	int ret;

	if (session_ctx->wssl == NULL) {
		session_ctx->wssl = wolfSSL_new(tls_ctx->ctx);
		if (session_ctx->wssl == NULL) {
			return -ENOMEM;
		}
	}

#if defined(HAVE_SECURE_RENEGOTIATION)
	if (wolfSSL_UseSecureRenegotiation(session_ctx->wssl) != WOLFSSL_SUCCESS) {
		ret = -EINVAL;
		goto err_cleanup;
	}
#endif /* HAVE_SECURE_RENEGOTIATION */

	ret = tls_wolfssl_session_setup(session_ctx, tls_ctx, is_server);
	if (ret != 0) {
		goto err_cleanup;
	}

	return 0;

err_cleanup:
	wolfSSL_free(session_ctx->wssl);
	session_ctx->wssl = NULL;

	return ret;
}

static int tls_wolfssl_reset_session(struct tls_context *context)
{
	struct tls_session_context *session_ctx = context->active_session;

	if (session_ctx->wssl != NULL) {
		bool is_server = context->options.role == ZTLS_IS_SERVER;
		int ret;

		/* Bring the SSL object back to a reusable post-init state so
		 * the next handshake on this session starts a fresh handshake
		 * (parity with mbedtls_ssl_session_reset).
		 */
		if (wolfSSL_clear(session_ctx->wssl) != WOLFSSL_SUCCESS) {
			return -EIO;
		}

		/* wolfSSL_clear drops per-SSL settings configured after
		 * wolfSSL_new - re-apply them.
		 */
		ret = tls_wolfssl_session_setup(session_ctx, context, is_server);
		if (ret != 0) {
			return ret;
		}
	}

	session_ctx->handshake_timestamp = 0;
	session_ctx->verify_result_flags = 0;

	k_sem_reset(&session_ctx->tls_established);

#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
	/* Server role: reset the address so that a new
	 *              client can connect w/o a need to reopen a socket
	 * Client role: keep peer addr so socket can continue to be used
	 *              even on handshake timeout
	 */
	if (context->options.role == ZTLS_IS_SERVER) {
		(void)memset(&session_ctx->dtls_peer_addr, 0,
			     sizeof(session_ctx->dtls_peer_addr));
		session_ctx->dtls_peer_addrlen = 0;
	}
#endif

	return 0;
}

static int tls_wolfssl_handshake(struct tls_context *context,
				 k_timeout_t timeout)
{
	k_timepoint_t end;
	int ret;
	int err;

	context->active_session->handshake_in_progress = true;

	end = sys_timepoint_calc(timeout);

	while ((ret = wolfSSL_negotiate(context->active_session->wssl)) !=
	       WOLFSSL_SUCCESS) {
		err = wolfSSL_get_error(context->active_session->wssl, ret);
		if (err == WOLFSSL_ERROR_WANT_READ ||
		    err == WOLFSSL_ERROR_WANT_WRITE) {
			int timeout_ms;
#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
			int timeout_dtls = SYS_FOREVER_MS;
			uint32_t wait_start = 0U;
#endif

			/* Blocking timeout. */
			timeout = sys_timepoint_timeout(end);
			if (K_TIMEOUT_EQ(timeout, K_NO_WAIT)) {
				ret = -EAGAIN;
				break;
			}

			/* Block. */
			timeout_ms = timeout_to_ms(&timeout);

#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
			if (context->type == NET_SOCK_DGRAM) {
				if (context->options.role == ZTLS_IS_SERVER) {
					/* DTLS server may need to switch session. */
					int err2 = dtls_server_switch_session_on_rx(context);

					if (err2 == 0) {
						/* Switched the session, repeat the loop. */
						context->active_session->handshake_in_progress =
							true;
						continue;
					}
				}

				/* wolfSSL reports the DTLS retransmission
				 * timeout in seconds.
				 */
				timeout_dtls =
					wolfSSL_dtls_get_current_timeout(
						context->active_session->wssl) *
					MSEC_PER_SEC;

				if (timeout_ms == SYS_FOREVER_MS) {
					timeout_ms = timeout_dtls;
				} else {
					timeout_ms = MIN(timeout_dtls,
							 timeout_ms);
				}
			}

			wait_start = k_uptime_get_32();
#endif /* CONFIG_NET_SOCKETS_ENABLE_DTLS */

			ret = wait_for_reason(context->sock, timeout_ms, err);
			if (ret < 0) {
				break;
			}

#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
			/* wait_for_reason() returns 0 both when the socket
			 * became ready and when the poll timed out. Only
			 * report a timeout to wolfSSL when the DTLS
			 * retransmission timer elapsed - calling
			 * wolfSSL_dtls_got_timeout() on an early data-ready
			 * wakeup would needlessly retransmit the flight and
			 * double wolfSSL's internal timer. Residual: if data
			 * arrives at/after timer expiry, one retransmission
			 * still precedes reading it; that is indistinguishable
			 * here without an extra poll and is harmless (the
			 * peer discards duplicate flights).
			 */
			if (context->type == NET_SOCK_DGRAM && ret == 0 &&
			    timeout_dtls != SYS_FOREVER_MS &&
			    (k_uptime_get_32() - wait_start) >=
			    (uint32_t)timeout_dtls) {
				ret = wolfSSL_dtls_got_timeout(
					context->active_session->wssl);
				if (ret != WOLFSSL_SUCCESS) {
					err = wolfSSL_get_error(
						context->active_session->wssl, ret);
					if (err != WOLFSSL_ERROR_WANT_READ &&
					    err != WOLFSSL_ERROR_WANT_WRITE) {
						NET_ERR("DTLS handshake timeout");
						if (tls_wolfssl_reset_session(context) == 0) {
							context->error = ETIMEDOUT;
							ret = -ETIMEDOUT;
						} else {
							context->error = ECONNABORTED;
							ret = -ECONNABORTED;
						}
						break;
					}
				}
			}
#endif

			continue;
		} else {
			NET_ERR("TLS handshake error: %d", err);
			ret = tls_wolfssl_reset_session(context);
			if (ret == 0) {
				context->error = ECONNABORTED;
				ret = -ECONNABORTED;
				break;
			}

			/* Avoid constant loop if tls_wolfssl_reset_session fails */
			NET_ERR("TLS reset error: %d", ret);
			context->error = ECONNABORTED;
			ret = -ECONNABORTED;
			break;
		}
	}

	if (ret == WOLFSSL_SUCCESS) {
		ret = 0;
		context->active_session->handshake_timestamp = k_uptime_get();
		k_sem_give(&context->active_session->tls_established);
	}

	context->active_session->handshake_in_progress = false;

	return ret;
}

#if defined(ZTLS_WOLFSSL_MAX_FRAGMENT)
/* Round down to an RFC 6066 length; a full record needs no extension. */
static inline int tls_wolfssl_mfl_code(struct tls_context *context)
{
	enum net_sock_type type = context->type;
	size_t len;

	/* ZSOCK_TLS_MFL_* and WOLFSSL_MFL_* both hold the RFC 6066 codes. */
	if (context->options.mfl_code != ZSOCK_TLS_MFL_DEFAULT) {
		return context->options.mfl_code;
	}

	len = CONFIG_NET_SOCKETS_TLS_WOLFSSL_MAX_FRAGMENT_LENGTH;

#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
	if (type == NET_SOCK_DGRAM &&
	    len > CONFIG_NET_SOCKETS_DTLS_MAX_FRAGMENT_LENGTH) {
		len = CONFIG_NET_SOCKETS_DTLS_MAX_FRAGMENT_LENGTH;
	}
#else
	ARG_UNUSED(type);
#endif

	if (len >= 16384) {
		return WOLFSSL_MFL_DISABLED;
	} else if (len >= 4096) {
		return WOLFSSL_MFL_2_12;
	} else if (len >= 2048) {
		return WOLFSSL_MFL_2_11;
	} else if (len >= 1024) {
		return WOLFSSL_MFL_2_10;
	}

	return WOLFSSL_MFL_2_9;
}
#endif /* ZTLS_WOLFSSL_MAX_FRAGMENT */

static WOLFSSL_METHOD *tls_wolfssl_get_method(struct tls_context *context,
					      bool is_server)
{
	if (context->type == NET_SOCK_STREAM) {
		switch (context->tls_version) {
#ifdef WOLFSSL_TLS13
		case NET_IPPROTO_TLS_1_3:
			return is_server ? wolfTLSv1_3_server_method()
					 : wolfTLSv1_3_client_method();
#endif /* WOLFSSL_TLS13 */
#ifndef WOLFSSL_NO_TLS12
		case NET_IPPROTO_TLS_1_2:
			return is_server ? wolfTLSv1_2_server_method()
					 : wolfTLSv1_2_client_method();
#endif /* !WOLFSSL_NO_TLS12 */
		case NET_IPPROTO_TLS_1_1:
		case NET_IPPROTO_TLS_1_0:
			/* user_settings.h defines NO_OLD_TLS. */
			return NULL;
		default:
			return NULL;
		}
	}
#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS) && defined(WOLFSSL_DTLS)
	else if (context->type == NET_SOCK_DGRAM) {
		switch (context->tls_version) {
#ifndef WOLFSSL_NO_TLS12
		case NET_IPPROTO_DTLS_1_2:
			return is_server ? wolfDTLSv1_2_server_method()
					 : wolfDTLSv1_2_client_method();
#endif /* !WOLFSSL_NO_TLS12 */
		default:
			/* DTLS 1.0 and 1.3 are not currently wired up on the
			 * wolfSSL backend; refuse rather than silently
			 * substituting a different version.
			 */
			return NULL;
		}
	}
#endif /* CONFIG_NET_SOCKETS_ENABLE_DTLS && WOLFSSL_DTLS */
	return NULL;
}

static int tls_wolfssl_init(struct tls_context *context, bool is_server)
{
	WOLFSSL_METHOD *method;
	int ret;
#if defined(ZTLS_WOLFSSL_MAX_FRAGMENT)
	int mfl;
#endif

	/* connect() must not demote a socket configured as a DTLS server */
	if (!context->role_set) {
		context->options.role = is_server ? ZTLS_IS_SERVER : ZTLS_IS_CLIENT;
	}

#if defined(CONFIG_WOLFSSL_DEBUG)
	wolfSSL_Debugging_ON();
#endif /* CONFIG_WOLFSSL_DEBUG */

	method = tls_wolfssl_get_method(context, is_server);

	if (method == NULL) {
		return -ENOTSUP;
	}

	/* Only wolfSSL_CTX_new() takes ownership of the method */
	if (context->ctx != NULL) {
		XFREE(method, NULL, DYNAMIC_TYPE_METHOD);
		method = NULL;
	}

	if (context->ctx == NULL) {
		context->ctx = wolfSSL_CTX_new(method);
		if (context->ctx == NULL) {
			return -ENOMEM;
		}
	}

	ret = tls_wolfssl_set_credentials(context);
	if (ret != 0) {
		goto err_cleanup;
	}

#ifndef NO_PSK
	if (NULL != context->psk) {
		if (is_server) {
			wolfSSL_CTX_set_psk_server_callback(context->ctx,
							    tls_psk_server_cb);
#ifdef WOLFSSL_TLS13
			wolfSSL_CTX_set_psk_server_tls13_callback(
				context->ctx, tls_psk_server_tls13_cb);
#endif /* WOLFSSL_TLS13 */
		} else {
			wolfSSL_CTX_set_psk_client_callback(context->ctx,
							    tls_psk_client_cb);
#ifdef WOLFSSL_TLS13
			wolfSSL_CTX_set_psk_client_tls13_callback(
				context->ctx, tls_psk_client_tls13_cb);
#endif /* WOLFSSL_TLS13 */
		}
	}
#endif /* !NO_PSK */

#if defined(ZTLS_WOLFSSL_MAX_FRAGMENT)
	/* Only a client offers a max fragment length (RFC 6066). */
	if (!is_server) {
		mfl = tls_wolfssl_mfl_code(context);

		if (mfl != WOLFSSL_MFL_DISABLED &&
		    wolfSSL_CTX_UseMaxFragment(context->ctx, mfl) != WOLFSSL_SUCCESS) {
			ret = -EINVAL;
			goto err_cleanup;
		}
	}
#endif /* ZTLS_WOLFSSL_MAX_FRAGMENT */

#if defined(CONFIG_NET_SOCKETS_TLS_WOLFSSL_OCSP_STAPLING)
	/* Client-only: the extension asks the peer for a status response, and
	 * wolfSSL gates the request API on !NO_WOLFSSL_CLIENT.
	 */
	if (!is_server) {
		if (wolfSSL_CTX_EnableOCSPStapling(context->ctx) != WOLFSSL_SUCCESS ||
		    wolfSSL_CTX_UseOCSPStapling(context->ctx, WOLFSSL_CSR_OCSP,
						0) != WOLFSSL_SUCCESS) {
			NET_ERR("Failed to enable OCSP stapling");
			ret = -EINVAL;
			goto err_cleanup;
		}
	}
#endif /* CONFIG_NET_SOCKETS_TLS_WOLFSSL_OCSP_STAPLING */

	ret = tls_wolfssl_set_session_cache_mode(context);
	if (ret != 0) {
		goto err_cleanup;
	}

	ret = tls_wolfssl_session_init(context->active_session, context,
				       is_server);
	if (ret != 0) {
		goto err_cleanup;
	}

	context->is_initialized = true;

	return 0;

err_cleanup:
	{
		WOLFSSL_CTX *wolf_ctx;

		k_mutex_lock(&context_lock, K_FOREVER);
		wolf_ctx = context->ctx;
		context->ctx = NULL;
		k_mutex_unlock(&context_lock);

		if (wolf_ctx != NULL) {
			wolfSSL_CTX_free(wolf_ctx);
		}
	}

	/* Nothing is left to reuse, so the next connect() or accept() sets up again */
	context->is_initialized = false;

	return ret;
}
#endif /* CONFIG_WOLFSSL */

static int tls_check_cert(struct tls_credential *cert)
{
#if defined(CONFIG_WOLFSSL)
	/* Parse the cert here so setsockopt(TLS_SEC_TAG_LIST) returns EINVAL
	 * on malformed credentials (mbedTLS-parity contract exercised by
	 * test_tls_bad_cred). DecodedCert keeps this off the OpenSSL
	 * compatibility layer, which a wolfSSL build need not include.
	 */
	DecodedCert *dcert;
	const byte *der = cert->buf;
	word32 der_len = cert->len;
	byte *pem_der = NULL;
	int ret;

	if (crt_is_pem(cert->buf, cert->len)) {
#if defined(WOLFSSL_PEM_TO_DER)
		/* DER of a PEM body is always shorter than the PEM itself. */
		pem_der = XMALLOC(cert->len, NULL, DYNAMIC_TYPE_TMP_BUFFER);
		if (pem_der == NULL) {
			return -ENOMEM;
		}

		ret = wc_CertPemToDer(cert->buf, (int)cert->len, pem_der,
				      (int)cert->len, CERT_TYPE);
		if (ret <= 0) {
			XFREE(pem_der, NULL, DYNAMIC_TYPE_TMP_BUFFER);
			NET_ERR("Failed to parse %s on tag %d",
				"certificate", cert->tag);
			return -EINVAL;
		}

		der = pem_der;
		der_len = (word32)ret;
#else
		NET_ERR("PEM %s on tag %d needs WOLFSSL_PEM_TO_DER",
			"certificate", cert->tag);
		return -EINVAL;
#endif /* WOLFSSL_PEM_TO_DER */
	}

	/* Several KB, more than a socket thread's stack wants to carry. */
	dcert = XMALLOC(sizeof(*dcert), NULL, DYNAMIC_TYPE_TMP_BUFFER);
	if (dcert == NULL) {
		XFREE(pem_der, NULL, DYNAMIC_TYPE_TMP_BUFFER);
		return -ENOMEM;
	}

	wc_InitDecodedCert(dcert, der, der_len, NULL);
	ret = wc_ParseCert(dcert, CERT_TYPE, NO_VERIFY, NULL);
	wc_FreeDecodedCert(dcert);

	XFREE(dcert, NULL, DYNAMIC_TYPE_TMP_BUFFER);
	XFREE(pem_der, NULL, DYNAMIC_TYPE_TMP_BUFFER);

	if (ret != 0) {
		NET_ERR("Failed to parse %s on tag %d",
			"certificate", cert->tag);
		return -EINVAL;
	}

	return 0;
#else
#if defined(CONFIG_MBEDTLS_X509_CRT_PARSE_C)
	mbedtls_x509_crt cert_ctx;
	int err;

	mbedtls_x509_crt_init(&cert_ctx);

	if (crt_is_pem(cert->buf, cert->len)) {
		err = mbedtls_x509_crt_parse(&cert_ctx, cert->buf, cert->len);
	} else {
		/* For DER case, use the no copy version of the parsing function
		 * to avoid unnecessary heap allocations.
		 */
		err = mbedtls_x509_crt_parse_der_nocopy(&cert_ctx, cert->buf,
							cert->len);
	}

	if (err != 0) {
		NET_ERR("Failed to parse %s on tag %d, err: -0x%x",
			"certificate", cert->tag, -err);
		return -EINVAL;
	}

	mbedtls_x509_crt_free(&cert_ctx);

	return err;
#else
	NET_ERR("TLS with certificates disabled. "
		"Reconfigure mbed TLS to support certificate based key exchange.");

	return -ENOTSUP;
#endif /* CONFIG_MBEDTLS_X509_CRT_PARSE_C */
#endif /* CONFIG_WOLFSSL */
}

static int tls_check_priv_key(struct tls_credential *priv_key)
{
#if defined(CONFIG_WOLFSSL)
	WOLFSSL_CTX *tmp_ctx;
	int fmt;
	int ret;

	/* Without OPENSSL_EXTRA, wolfSSL parses a key only through a CTX */
#ifndef NO_WOLFSSL_CLIENT
	tmp_ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());
#else
	tmp_ctx = wolfSSL_CTX_new(wolfSSLv23_server_method());
#endif
	if (tmp_ctx == NULL) {
		return -ENOMEM;
	}

	fmt = key_is_pem(priv_key->buf, priv_key->len) ?
	      WOLFSSL_FILETYPE_PEM : WOLFSSL_FILETYPE_ASN1;

	ret = wolfSSL_CTX_use_PrivateKey_buffer(tmp_ctx, priv_key->buf,
						(long)priv_key->len, fmt);
	wolfSSL_CTX_free(tmp_ctx);

	if (ret != WOLFSSL_SUCCESS) {
		NET_ERR("Failed to parse %s on tag %d",
			"private key", priv_key->tag);
		return -EINVAL;
	}

	return 0;
#elif defined(CONFIG_MBEDTLS_X509_CRT_PARSE_C)
	mbedtls_pk_context key_ctx;
	int err;

	mbedtls_pk_init(&key_ctx);

	err = mbedtls_pk_parse_key(&key_ctx, priv_key->buf,
				   priv_key->len, NULL, 0);
	if (err != 0) {
		NET_ERR("Failed to parse %s on tag %d, err: -0x%x",
			"private key", priv_key->tag, -err);
		err = -EINVAL;
	}

	mbedtls_pk_free(&key_ctx);

	return err;
#else
	NET_ERR("TLS with certificates disabled. "
		"Reconfigure mbed TLS to support certificate based key exchange.");

	return -ENOTSUP;
#endif /* CONFIG_MBEDTLS_X509_CRT_PARSE_C */
}

static int tls_check_private_key_psa(struct tls_credential *priv_key)
{
#if defined(CONFIG_MBEDTLS_X509_CRT_PARSE_C) && defined(TLS_PRIV_KEY_PSA_ENABLED)
	psa_key_id_t key_id;
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
	psa_status_t status;

	if (priv_key->len != sizeof(key_id)) {
		NET_ERR("Bad PSA key id length on tag %d", priv_key->tag);
		return -EINVAL;
	}

	memcpy(&key_id, priv_key->buf, sizeof(key_id));

	/* Validate that the referenced key exists and is usable, without
	 * touching the key material.
	 */
	status = psa_get_key_attributes(key_id, &attr);
	if (status != PSA_SUCCESS) {
		NET_ERR("PSA key %u not found for tag %d, status: %d",
			key_id, priv_key->tag, status);
		return -EINVAL;
	}

	psa_reset_key_attributes(&attr);

	return 0;
#else
	NET_ERR("TLS with PSA-resident private keys disabled. "
		"Reconfigure mbed TLS to support PSA crypto.");

	return -ENOTSUP;
#endif /* CONFIG_MBEDTLS_X509_CRT_PARSE_C && TLS_PRIV_KEY_PSA_ENABLED */
}

static int tls_check_psk(struct tls_credential *psk)
{
#if (defined(CONFIG_WOLFSSL) && !defined(NO_PSK)) || \
	defined(MBEDTLS_SSL_HANDSHAKE_WITH_PSK_ENABLED)
	struct tls_credential *psk_id;

	psk_id = credential_get(psk->tag, TLS_CREDENTIAL_PSK_ID);
	if (psk_id == NULL) {
		NET_ERR("No matching PSK ID found for tag %d", psk->tag);
		return -EINVAL;
	}

	if (psk->len == 0 || psk_id->len == 0) {
		NET_ERR("PSK or PSK ID empty on tag %d", psk->tag);
		return -EINVAL;
	}

	return 0;
#else
	NET_ERR("TLS with PSK disabled. "
		"Reconfigure mbed TLS to support PSK based key exchange.");

	return -ENOTSUP;
#endif
}

static int tls_check_credentials(const sec_tag_t *sec_tags, int sec_tag_count)
{
	int err = 0;

	credentials_lock();

	for (int i = 0; i < sec_tag_count; i++) {
		sec_tag_t tag = sec_tags[i];
		struct tls_credential *cred = NULL;
		bool tag_found = false;

		while ((cred = credential_next_get(tag, cred)) != NULL) {
			tag_found = true;

			switch (cred->type) {
			case TLS_CREDENTIAL_CA_CERTIFICATE:
				__fallthrough;
			case TLS_CREDENTIAL_PUBLIC_CERTIFICATE:
				err = tls_check_cert(cred);
				if (err != 0) {
					goto exit;
				}

				break;
			case TLS_CREDENTIAL_PRIVATE_KEY:
				err = tls_check_priv_key(cred);
				if (err != 0) {
					goto exit;
				}

				break;
			case TLS_CREDENTIAL_PRIVATE_KEY_PSA:
				err = tls_check_private_key_psa(cred);
				if (err != 0) {
					goto exit;
				}

				break;
			case TLS_CREDENTIAL_PSK:
				err = tls_check_psk(cred);
				if (err != 0) {
					goto exit;
				}

				break;
			case TLS_CREDENTIAL_PSK_ID:
				/* Ignore PSK ID - it will be verified together
				 * with PSK.
				 */
				break;
			default:
				return -EINVAL;
			}
		}

		/* If no credential is found with such a tag, report an error. */
		if (!tag_found) {
			NET_ERR("No TLS credential found with tag %d", tag);
			err = -ENOENT;
			goto exit;
		}
	}

exit:
	credentials_unlock();

	return err;
}

static int tls_opt_sec_tag_list_set(struct tls_context *context,
				    const void *optval, net_socklen_t optlen)
{
	int sec_tag_cnt;
	int ret;

	if (!optval) {
		return -EINVAL;
	}

	if (optlen % sizeof(sec_tag_t) != 0) {
		return -EINVAL;
	}

	sec_tag_cnt = optlen / sizeof(sec_tag_t);
	if (sec_tag_cnt >
		ARRAY_SIZE(context->options.sec_tag_list.sec_tags)) {
		return -EINVAL;
	}

	ret = tls_check_credentials((const sec_tag_t *)optval, sec_tag_cnt);
	if (ret < 0) {
		return ret;
	}

	memcpy(context->options.sec_tag_list.sec_tags, optval, optlen);
	context->options.sec_tag_list.sec_tag_count = sec_tag_cnt;

	return 0;
}

static int sock_opt_protocol_get(struct tls_context *context,
				 void *optval, net_socklen_t *optlen)
{
	int protocol = (int)context->tls_version;

	if (*optlen != sizeof(protocol)) {
		return -EINVAL;
	}

	*(int *)optval = protocol;

	return 0;
}

static int tls_opt_sec_tag_list_get(struct tls_context *context,
				    void *optval, net_socklen_t *optlen)
{
	int len;

	if (*optlen % sizeof(sec_tag_t) != 0 || *optlen == 0) {
		return -EINVAL;
	}

	len = MIN(context->options.sec_tag_list.sec_tag_count *
		  sizeof(sec_tag_t), *optlen);

	memcpy(optval, context->options.sec_tag_list.sec_tags, len);
	*optlen = len;

	return 0;
}

static int tls_opt_hostname_set(struct tls_context *context,
				const void *optval, net_socklen_t optlen)
{
#if defined(CONFIG_WOLFSSL)
	char *host_name;

	if (optval == NULL) {
		if (context->host_name != NULL) {
			XFREE(context->host_name, NULL, DYNAMIC_TYPE_TMP_BUFFER);
			context->host_name = NULL;
			context->host_len = 0;
		}
		context->options.is_hostname_set = false;
		return 0;
	}

	/* Stop at the first NUL, as the mbedTLS backend reads optval as a C string. */
	optlen = strnlen((const char *)optval, optlen);

	/* An empty name matches no certificate and would turn the name check off */
	if (optlen == 0) {
		return -EINVAL;
	}

	/* RFC 6066 caps a HostName at 2^16 - 1, which keeps optlen + 1 from wrapping */
	if (optlen > UINT16_MAX) {
		return -EINVAL;
	}

	/* Keep the old name until the new one is stored, as mbedTLS does */

	/* +1 for NUL - wolfSSL APIs require C strings. */
	host_name = XMALLOC(optlen + 1, NULL, DYNAMIC_TYPE_TMP_BUFFER);
	if (host_name == NULL) {
		return -ENOMEM;
	}

	XMEMCPY(host_name, optval, optlen);
	host_name[optlen] = '\0';

	if (context->host_name != NULL) {
		XFREE(context->host_name, NULL, DYNAMIC_TYPE_TMP_BUFFER);
	}

	context->host_name = host_name;
	context->host_len = optlen;
	context->options.is_hostname_set = true;

	return tls_wolfssl_apply_all_sessions(context,
					      tls_wolfssl_set_hostname);
#else
	ARG_UNUSED(optlen);

#if defined(CONFIG_MBEDTLS_X509_CRT_PARSE_C)
	if (mbedtls_ssl_set_hostname(&context->active_session->ssl, optval) != 0) {
		return -EINVAL;
	}
#else
	return -ENOPROTOOPT;
#endif

	context->options.is_hostname_set = true;

	return 0;
#endif /* CONFIG_WOLFSSL */
}

static int tls_opt_ciphersuite_list_set(struct tls_context *context,
					const void *optval, net_socklen_t optlen)
{
	int cipher_cnt;

	if (!optval) {
		return -EINVAL;
	}

	if (optlen % sizeof(int) != 0) {
		return -EINVAL;
	}

	cipher_cnt = optlen / sizeof(int);

	/* + 1 for 0-termination. */
	if (cipher_cnt + 1 > ARRAY_SIZE(context->options.ciphersuites)) {
		return -EINVAL;
	}

#if defined(CONFIG_WOLFSSL)
	/* Validate before storing, since tls_wolfssl_apply_all_sessions is best effort */
	for (int i = 0; i < cipher_cnt; i++) {
		int id = ((const int *)optval)[i];

		/* All ciphersuite IDs fit in 16 bits */
		if (id < 0 || id > 0xFFFF) {
			return -EINVAL;
		}
	}

	XMEMCPY(context->options.ciphersuites, optval, optlen);
	context->options.ciphersuites[cipher_cnt] = 0;

	return tls_wolfssl_apply_all_sessions(context,
					      tls_wolfssl_set_ciphersuites);
#else
	memcpy(context->options.ciphersuites, optval, optlen);
	context->options.ciphersuites[cipher_cnt] = 0;

	mbedtls_ssl_conf_ciphersuites(&context->config,
				      context->options.ciphersuites);
	return 0;
#endif /* CONFIG_WOLFSSL */
}

static int tls_opt_ciphersuite_list_get(struct tls_context *context,
					void *optval, net_socklen_t *optlen)
{
	const int *selected_ciphers;
	int cipher_cnt, i = 0;
	int *ciphers = optval;

	if (*optlen % sizeof(int) != 0 || *optlen == 0) {
		return -EINVAL;
	}

#if defined(CONFIG_WOLFSSL)
	if (context->options.ciphersuites[0] != 0) {
		/* Return user-configured ciphersuites */
		selected_ciphers = context->options.ciphersuites;
		cipher_cnt = *optlen / sizeof(int);
		while (selected_ciphers[i] != 0) {
			ciphers[i] = selected_ciphers[i];
			if (++i == cipher_cnt) {
				break;
			}
		}
		*optlen = i * sizeof(int);
		return 0;
	} else {
		const char *cipherName;
		int numCipherSuites = 0;
		byte b1, b2;
		int flags = 0;

		cipher_cnt = *optlen / sizeof(int);

		while ((cipherName = wolfSSL_get_cipher_list(numCipherSuites)) != NULL) {
			/* Aliases repeat a suite, and 0x00FF is a signalling value */
			if (wolfSSL_get_cipher_suite_from_name(cipherName,
							       &b1, &b2,
							       &flags) != 0 ||
			    (flags & WOLFSSL_CIPHER_SUITE_FLAG_NAMEALIAS) != 0 ||
			    (b1 == 0x00 && b2 == 0xFF)) {
				numCipherSuites++;
				continue;
			}

			byte cs_arr[2] = { b1, b2 };

			ciphers[i] = (int)sys_get_be16(cs_arr);

			if (++i == cipher_cnt) {
				break;
			}
			numCipherSuites++;
		}

		*optlen = i * sizeof(int);
		return 0;
	}
#else
	if (context->options.ciphersuites[0] == 0) {
		/* No specific ciphersuites configured, return all available. */
		selected_ciphers = mbedtls_ssl_list_ciphersuites();
	} else {
		selected_ciphers = context->options.ciphersuites;
	}

	cipher_cnt = *optlen / sizeof(int);
	while (selected_ciphers[i] != 0) {
		ciphers[i] = selected_ciphers[i];

		if (++i == cipher_cnt) {
			break;
		}
	}

	*optlen = i * sizeof(int);

	return 0;
#endif /* CONFIG_WOLFSSL */
}

static struct tls_session_context *get_latest_session(struct tls_context *context)
{
	struct tls_session_context *session_ctx = NULL;
	struct tls_session_context *latest_session_ctx = NULL;

	SYS_SLIST_FOR_EACH_CONTAINER(&context->sessions, session_ctx, node) {
		if ((latest_session_ctx == NULL) ||
		    (session_ctx->handshake_timestamp >
		     latest_session_ctx->handshake_timestamp)) {
			latest_session_ctx = session_ctx;
		}
	}

	return latest_session_ctx;
}

static int tls_opt_ciphersuite_used_get(struct tls_context *context,
					void *optval, net_socklen_t *optlen)
{
	struct tls_session_context *session_ctx;
	const char *ciph;

	if (*optlen != sizeof(int)) {
		return -EINVAL;
	}

	session_ctx = get_latest_session(context);
	if (session_ctx == NULL) {
		return -ENOTCONN;
	}

#if defined(CONFIG_WOLFSSL)
	{
		byte b1, b2;
		int flags = 0;

		if (session_ctx->wssl == NULL) {
			return -ENOTCONN;
		}

		ciph = wolfSSL_get_cipher_name(session_ctx->wssl);
		if (ciph == NULL) {
			return -ENOTCONN;
		}

		if (wolfSSL_get_cipher_suite_from_name(ciph, &b1, &b2, &flags) != 0) {
			/* Not a connection-state error: the session is up but
			 * the cipher name didn't resolve back to a known ID.
			 */
			return -ENOENT;
		}

		byte cs_arr[2] = { b1, b2 };
		*(int *)optval = (int)sys_get_be16(cs_arr);
	}
#else
	ciph = mbedtls_ssl_get_ciphersuite(&session_ctx->ssl);
	if (ciph == NULL) {
		return -ENOTCONN;
	}

	*(int *)optval = mbedtls_ssl_get_ciphersuite_id(ciph);
#endif /* CONFIG_WOLFSSL */

	return 0;
}

static int tls_opt_alpn_list_set(struct tls_context *context,
				 const void *optval, net_socklen_t optlen)
{
	int alpn_cnt;
#if defined(CONFIG_WOLFSSL) && defined(HAVE_ALPN)
	char *joined;
	int ret;
#endif

#if defined(CONFIG_WOLFSSL) && !defined(HAVE_ALPN)
	/* A settings file without HAVE_ALPN, where Kconfig cannot hide the option */
	return -EINVAL;
#endif

	if (!ALPN_MAX_PROTOCOLS) {
		return -EINVAL;
	}

	if (!optval) {
		return -EINVAL;
	}

	if (optlen % sizeof(const char *) != 0) {
		return -EINVAL;
	}

	alpn_cnt = optlen / sizeof(const char *);
	/* + 1 for NULL-termination. */
	if (alpn_cnt + 1 > ARRAY_SIZE(context->options.alpn_list)) {
		return -EINVAL;
	}

#if defined(CONFIG_WOLFSSL) && defined(HAVE_ALPN)
	/* Built before anything changes, so a failure keeps the previous list */
	ret = tls_wolfssl_alpn_join((const char * const *)optval, alpn_cnt, &joined);
	if (ret != 0) {
		return ret;
	}

	XFREE(context->alpn_joined, NULL, DYNAMIC_TYPE_TMP_BUFFER);
	context->alpn_joined = joined;
#endif

	memcpy(context->options.alpn_list, optval, optlen);
	context->options.alpn_list[alpn_cnt] = NULL;

#if defined(CONFIG_WOLFSSL) && defined(HAVE_ALPN)
	return tls_wolfssl_apply_all_sessions(context, tls_wolfssl_set_alpn);
#else
	return 0;
#endif /* CONFIG_WOLFSSL && HAVE_ALPN */
}

#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
static int tls_opt_dtls_handshake_timeout_get(struct tls_context *context,
					      void *optval, net_socklen_t *optlen,
					      bool is_max)
{
	uint32_t *val = (uint32_t *)optval;

	if (sizeof(uint32_t) != *optlen) {
		return -EINVAL;
	}

	if (is_max) {
		*val = context->options.dtls_handshake_timeout_max;
	} else {
		*val = context->options.dtls_handshake_timeout_min;
	}

	return 0;
}

static int tls_opt_dtls_handshake_timeout_set(struct tls_context *context,
					      const void *optval,
					      net_socklen_t optlen, bool is_max)
{
	uint32_t *val = (uint32_t *)optval;

	if (!optval) {
		return -EINVAL;
	}

	if (sizeof(uint32_t) != optlen) {
		return -EINVAL;
	}

	/* If Mbed TLS context not inited, it will
	 * use these values upon init.
	 */
	if (is_max) {
		context->options.dtls_handshake_timeout_max = *val;
	} else {
		context->options.dtls_handshake_timeout_min = *val;
	}

	/* If context already inited, we need to
	 * update config for it to take effect
	 */
#if defined(CONFIG_WOLFSSL)
	return tls_wolfssl_apply_all_sessions(context,
					      tls_wolfssl_set_dtls_timeouts);
#else
	mbedtls_ssl_conf_handshake_timeout(&context->config,
			context->options.dtls_handshake_timeout_min,
			context->options.dtls_handshake_timeout_max);
#endif /* CONFIG_WOLFSSL */

	return 0;
}

static int tls_opt_dtls_connection_id_set(struct tls_context *context,
					  const void *optval, net_socklen_t optlen)
{
#if defined(CONFIG_MBEDTLS_SSL_DTLS_CONNECTION_ID)
	int value;

	if (optlen > 0 && optval == NULL) {
		return -EINVAL;
	}

	if (optlen != sizeof(int)) {
		return -EINVAL;
	}

	value = *((int *)optval);

	switch (value) {
	case ZSOCK_TLS_DTLS_CID_DISABLED:
		context->options.dtls_cid.enabled = false;
		context->options.dtls_cid.cid_len = 0;
		break;
	case ZSOCK_TLS_DTLS_CID_SUPPORTED:
		context->options.dtls_cid.enabled = true;
		context->options.dtls_cid.cid_len = 0;
		break;
	case ZSOCK_TLS_DTLS_CID_ENABLED:
		context->options.dtls_cid.enabled = true;
		if (context->options.dtls_cid.cid_len == 0) {
			/* generate random self cid */
#if defined(CONFIG_CSPRNG_ENABLED)
			sys_csrand_get(context->options.dtls_cid.cid,
				       MBEDTLS_SSL_CID_OUT_LEN_MAX);
#else
			sys_rand_get(context->options.dtls_cid.cid,
				     MBEDTLS_SSL_CID_OUT_LEN_MAX);
#endif
			context->options.dtls_cid.cid_len = MBEDTLS_SSL_CID_OUT_LEN_MAX;
		}
		break;
	default:
		return -EINVAL;
	}

	return 0;
#else
	return -ENOPROTOOPT;
#endif /* CONFIG_MBEDTLS_SSL_DTLS_CONNECTION_ID */
}

static int tls_opt_dtls_connection_id_value_set(struct tls_context *context,
						const void *optval,
						net_socklen_t optlen)
{
#if defined(CONFIG_MBEDTLS_SSL_DTLS_CONNECTION_ID)
	if (optlen > 0 && optval == NULL) {
		return -EINVAL;
	}

	if (optlen > MBEDTLS_SSL_CID_IN_LEN_MAX) {
		return -EINVAL;
	}

	context->options.dtls_cid.cid_len = optlen;
	memcpy(context->options.dtls_cid.cid, optval, optlen);

	return 0;
#else
	return -ENOPROTOOPT;
#endif /* CONFIG_MBEDTLS_SSL_DTLS_CONNECTION_ID */
}

static int tls_opt_dtls_connection_id_value_get(struct tls_context *context,
						void *optval, net_socklen_t *optlen)
{
#if defined(CONFIG_MBEDTLS_SSL_DTLS_CONNECTION_ID)

	if (*optlen < context->options.dtls_cid.cid_len) {
		return -EINVAL;
	}

	*optlen = context->options.dtls_cid.cid_len;
	memcpy(optval, context->options.dtls_cid.cid, *optlen);

	return 0;
#else
	return -ENOPROTOOPT;
#endif
}

static int tls_opt_dtls_peer_connection_id_value_get(struct tls_context *context,
						     void *optval,
						     net_socklen_t *optlen)
{
#if defined(CONFIG_MBEDTLS_SSL_DTLS_CONNECTION_ID)
	struct tls_session_context *session_ctx;
	int enabled = false;
	int ret;
	size_t optlen_local;

	if (!context->is_initialized) {
		return -ENOTCONN;
	}

	session_ctx = get_latest_session(context);
	if (session_ctx == NULL) {
		return -ENOTCONN;
	}

	if (*optlen < MBEDTLS_SSL_CID_OUT_LEN_MAX) {
		return -EINVAL;
	}

	ret = mbedtls_ssl_get_peer_cid(&session_ctx->ssl, &enabled, optval, &optlen_local);
	if (enabled) {
		*optlen = optlen_local;
	} else {
		*optlen = 0;
	}
	return ret;
#else
	return -ENOPROTOOPT;
#endif
}

static int tls_opt_dtls_connection_id_status_get(struct tls_context *context,
					  void *optval, net_socklen_t *optlen)
{
#if defined(CONFIG_MBEDTLS_SSL_DTLS_CONNECTION_ID)
	struct tls_session_context *session_ctx;
	struct tls_dtls_cid cid;
	int ret;
	int val;
	int enabled;
	bool have_self_cid;
	bool have_peer_cid;

	if (sizeof(int) != *optlen) {
		return -EINVAL;
	}

	if (!context->is_initialized) {
		return -ENOTCONN;
	}

	session_ctx = get_latest_session(context);
	if (session_ctx == NULL) {
		return -ENOTCONN;
	}

	ret = mbedtls_ssl_get_peer_cid(&session_ctx->ssl, &enabled,
				       cid.cid, &cid.cid_len);
	if (ret) {
		/* Handshake is not complete */
		return -EAGAIN;
	}

	cid.enabled = (enabled == MBEDTLS_SSL_CID_ENABLED);
	have_self_cid = (context->options.dtls_cid.cid_len != 0);
	have_peer_cid = (cid.cid_len != 0);

	if (!context->options.dtls_cid.enabled) {
		val = ZSOCK_TLS_DTLS_CID_STATUS_DISABLED;
	} else if (have_self_cid && have_peer_cid) {
		val = ZSOCK_TLS_DTLS_CID_STATUS_BIDIRECTIONAL;
	} else if (have_self_cid) {
		val = ZSOCK_TLS_DTLS_CID_STATUS_DOWNLINK;
	} else if (have_peer_cid) {
		val = ZSOCK_TLS_DTLS_CID_STATUS_UPLINK;
	} else {
		val = ZSOCK_TLS_DTLS_CID_STATUS_DISABLED;
	}

	*((int *)optval) = val;
	return 0;
#else
	return -ENOPROTOOPT;
#endif
}

static int tls_opt_dtls_handshake_on_connect_set(struct tls_context *context,
						 const void *optval,
						 net_socklen_t optlen)
{
	int *val = (int *)optval;

	if (!optval) {
		return -EINVAL;
	}

	if (sizeof(int) != optlen) {
		return -EINVAL;
	}

	context->options.dtls_handshake_on_connect = (bool)*val;

	return 0;
}

static int tls_opt_dtls_handshake_on_connect_get(struct tls_context *context,
						 void *optval,
						 net_socklen_t *optlen)
{
	if (*optlen != sizeof(int)) {
		return -EINVAL;
	}

	*(int *)optval = context->options.dtls_handshake_on_connect;

	return 0;
}
#endif /* CONFIG_NET_SOCKETS_ENABLE_DTLS */

static int tls_opt_alpn_list_get(struct tls_context *context,
				 void *optval, net_socklen_t *optlen)
{
	const char **alpn_list = context->options.alpn_list;
	int alpn_cnt, i = 0;
	const char **ret_list = optval;

	if (!ALPN_MAX_PROTOCOLS) {
		return -EINVAL;
	}

	if (*optlen % sizeof(const char *) != 0 || *optlen == 0) {
		return -EINVAL;
	}

	alpn_cnt = *optlen / sizeof(const char *);
	while (alpn_list[i] != NULL) {
		ret_list[i] = alpn_list[i];

		if (++i == alpn_cnt) {
			break;
		}
	}

	*optlen = i * sizeof(const char *);

	return 0;
}

static int tls_opt_session_cache_set(struct tls_context *context,
				     const void *optval, net_socklen_t optlen)
{
	int *val = (int *)optval;

	if (!optval) {
		return -EINVAL;
	}

	if (sizeof(int) != optlen) {
		return -EINVAL;
	}

	context->options.cache_enabled = (*val == ZSOCK_TLS_SESSION_CACHE_ENABLED);

	return 0;
}

static int tls_opt_session_cache_get(struct tls_context *context,
				     void *optval, net_socklen_t *optlen)
{
	int cache_enabled = context->options.cache_enabled ?
			    ZSOCK_TLS_SESSION_CACHE_ENABLED :
			    ZSOCK_TLS_SESSION_CACHE_DISABLED;

	if (*optlen != sizeof(cache_enabled)) {
		return -EINVAL;
	}

	*(int *)optval = cache_enabled;

	return 0;
}

static int tls_opt_cert_verify_result_get(struct tls_context *context,
					  void *optval, net_socklen_t *optlen)
{
	struct tls_session_context *session_ctx;

	if (*optlen != sizeof(uint32_t)) {
		return -EINVAL;
	}

	session_ctx = get_latest_session(context);
	if (session_ctx == NULL) {
		return -ENOTCONN;
	}

#if defined(CONFIG_WOLFSSL)
	if (session_ctx->wssl == NULL) {
		return -ENOTCONN;
	}

	/* WOLFSSL_ALWAYS_VERIFY_CB runs the callback at every depth, so the flags are complete. */
	*(uint32_t *)optval = session_ctx->verify_result_flags;
#else
	*(uint32_t *)optval = mbedtls_ssl_get_verify_result(&session_ctx->ssl);
#endif /* CONFIG_WOLFSSL */

	return 0;
}

static int tls_opt_session_cache_purge_set(struct tls_context *context,
					   const void *optval, net_socklen_t optlen)
{
	ARG_UNUSED(context);
	ARG_UNUSED(optval);
	ARG_UNUSED(optlen);

#if defined(CONFIG_WOLFSSL) && !defined(NO_SESSION_CACHE)
	/* The server-side session cache is global, so flush it too; the ctx argument is unused. */
	wolfSSL_CTX_flush_sessions(NULL, -1);
#endif
	tls_session_purge();

	return 0;
}

static int tls_opt_peer_verify_set(struct tls_context *context,
				   const void *optval, net_socklen_t optlen)
{
	int *peer_verify;

	if (!optval) {
		return -EINVAL;
	}

	if (optlen != sizeof(int)) {
		return -EINVAL;
	}

	peer_verify = (int *)optval;

	if (*peer_verify != ZSOCK_TLS_PEER_VERIFY_NONE &&
	    *peer_verify != ZSOCK_TLS_PEER_VERIFY_OPTIONAL &&
	    *peer_verify != ZSOCK_TLS_PEER_VERIFY_REQUIRED) {
		return -EINVAL;
	}

	context->options.verify_level = *peer_verify;

	return 0;
}

static int tls_opt_cert_nocopy_set(struct tls_context *context,
				   const void *optval, net_socklen_t optlen)
{
	int *cert_nocopy;

	if (!optval) {
		return -EINVAL;
	}

	if (optlen != sizeof(int)) {
		return -EINVAL;
	}

	cert_nocopy = (int *)optval;

	if (*cert_nocopy != ZSOCK_TLS_CERT_NOCOPY_NONE &&
	    *cert_nocopy != ZSOCK_TLS_CERT_NOCOPY_OPTIONAL) {
		return -EINVAL;
	}

	context->options.cert_nocopy = *cert_nocopy;

	return 0;
}

#if defined(CONFIG_NET_SOCKETS_TLS_SET_MAX_FRAGMENT_LENGTH) && \
	(!defined(CONFIG_WOLFSSL) || defined(ZTLS_WOLFSSL_MAX_FRAGMENT))
static int tls_opt_mfl_set(struct tls_context *context,
			   const void *optval, net_socklen_t optlen)
{
	const int *mfl;

	if (optval == NULL) {
		return -EINVAL;
	}

	if (optlen != sizeof(int)) {
		return -EINVAL;
	}

	mfl = (const int *)optval;
	if (*mfl < ZSOCK_TLS_MFL_DEFAULT || *mfl > ZSOCK_TLS_MFL_4096) {
		return -EINVAL;
	}

	context->options.mfl_code = (int8_t)*mfl;

	return 0;
}
#endif /* CONFIG_NET_SOCKETS_TLS_SET_MAX_FRAGMENT_LENGTH */

static int tls_opt_dtls_role_set(struct tls_context *context,
				 const void *optval, net_socklen_t optlen)
{
	int *role;

	if (!optval) {
		return -EINVAL;
	}

	if (optlen != sizeof(int)) {
		return -EINVAL;
	}

	role = (int *)optval;
	if (*role != ZTLS_IS_CLIENT &&
	    *role != ZTLS_IS_SERVER) {
		return -EINVAL;
	}

	context->options.role = *role;
#if defined(CONFIG_WOLFSSL)
	context->role_set = true;
#endif

	return 0;
}

#if defined(CONFIG_NET_SOCKETS_TLS_CERT_VERIFY_CALLBACK)
#if defined(CONFIG_WOLFSSL)
/* wolfSSL consumers should use TLS_CERT_VERIFY_CALLBACK_WOLFSSL. */
static int tls_opt_cert_verify_callback_set(struct tls_context *context,
					    const void *optval,
					    net_socklen_t optlen)
{
	ARG_UNUSED(context);
	ARG_UNUSED(optval);
	ARG_UNUSED(optlen);

	NET_ERR("TLS_CERT_VERIFY_CALLBACK is not supported by the wolfSSL "
		"backend; use TLS_CERT_VERIFY_CALLBACK_WOLFSSL");

	return -ENOTSUP;
}
#else /* CONFIG_WOLFSSL (mbedTLS backend) */
static int tls_opt_cert_verify_callback_set(struct tls_context *context,
					    const void *optval,
					    net_socklen_t optlen)
{
	struct zsock_tls_cert_verify_cb *cert_verify;

	if (!optval) {
		return -EINVAL;
	}

	if (optlen != sizeof(struct zsock_tls_cert_verify_cb)) {
		return -EINVAL;
	}

	cert_verify = (struct zsock_tls_cert_verify_cb *)optval;
	if (cert_verify->cb == NULL) {
		return -EINVAL;
	}

	context->options.cert_verify = *cert_verify;

	return 0;
}
#endif /* CONFIG_WOLFSSL */
#else /* CONFIG_NET_SOCKETS_TLS_CERT_VERIFY_CALLBACK */
static int tls_opt_cert_verify_callback_set(struct tls_context *context,
					    const void *optval,
					    net_socklen_t optlen)
{
	ARG_UNUSED(context);
	ARG_UNUSED(optval);
	ARG_UNUSED(optlen);

#if defined(CONFIG_WOLFSSL)
	NET_ERR("TLS_CERT_VERIFY_CALLBACK is not supported by the wolfSSL "
		"backend; use TLS_CERT_VERIFY_CALLBACK_WOLFSSL");
	return -ENOTSUP;
#else
	NET_ERR("TLS_CERT_VERIFY_CALLBACK option requires "
		"CONFIG_NET_SOCKETS_TLS_CERT_VERIFY_CALLBACK enabled");

	return -ENOPROTOOPT;
#endif
}
#endif /* CONFIG_NET_SOCKETS_TLS_CERT_VERIFY_CALLBACK */

#if defined(CONFIG_WOLFSSL)
#if defined(CONFIG_NET_SOCKETS_TLS_WOLFSSL_VERIFY_CALLBACK)
static int tls_opt_cert_verify_callback_wolfssl_set(struct tls_context *context,
						    const void *optval,
						    net_socklen_t optlen)
{
	struct zsock_tls_cert_verify_cb_wolfssl *wolfssl_cb;

	if (!optval) {
		return -EINVAL;
	}

	if (optlen != sizeof(struct zsock_tls_cert_verify_cb_wolfssl)) {
		return -EINVAL;
	}

	wolfssl_cb = (struct zsock_tls_cert_verify_cb_wolfssl *)optval;
	if (wolfssl_cb->cb == NULL) {
		return -EINVAL;
	}

	context->options.cert_verify_wolfssl = *wolfssl_cb;

	return tls_wolfssl_apply_all_sessions(context, tls_wolfssl_set_verify);
}
#else
static int tls_opt_cert_verify_callback_wolfssl_set(struct tls_context *context,
						    const void *optval,
						    net_socklen_t optlen)
{
	ARG_UNUSED(context);
	ARG_UNUSED(optval);
	ARG_UNUSED(optlen);

	return -ENOPROTOOPT;
}
#endif /* CONFIG_NET_SOCKETS_TLS_WOLFSSL_VERIFY_CALLBACK */
#endif /* CONFIG_WOLFSSL */

static int protocol_check(int family, int type, int *proto)
{
	if (family != NET_AF_INET && family != NET_AF_INET6) {
		return -EAFNOSUPPORT;
	}

	if (*proto >= NET_IPPROTO_TLS_1_0 && *proto <= NET_IPPROTO_TLS_1_3) {
		if (type != NET_SOCK_STREAM) {
			return -EPROTOTYPE;
		}

		*proto = NET_IPPROTO_TCP;
	} else if (*proto >= NET_IPPROTO_DTLS_1_0 && *proto <= NET_IPPROTO_DTLS_1_2) {
		if (!IS_ENABLED(CONFIG_NET_SOCKETS_ENABLE_DTLS)) {
			return -EPROTONOSUPPORT;
		}

		if (type != NET_SOCK_DGRAM) {
			return -EPROTOTYPE;
		}

		*proto = NET_IPPROTO_UDP;
	} else {
		return -EPROTONOSUPPORT;
	}

	return 0;
}

static int ztls_socket(int family, int type, int proto)
{
	enum net_ip_protocol_secure tls_proto = proto;
	int fd = zvfs_reserve_fd();
	int sock = -1;
	int ret;
	struct tls_context *ctx;

	if (fd < 0) {
		return -1;
	}

	ret = protocol_check(family, type, &proto);
	if (ret < 0) {
		errno = -ret;
		goto free_fd;
	}

	ctx = tls_alloc();
	if (ctx == NULL) {
		errno = ENOMEM;
		goto free_fd;
	}

	sock = zsock_socket(family, type, proto);
	if (sock < 0) {
		goto release_tls;
	}

	ctx->tls_version = tls_proto;
	ctx->type = (proto == NET_IPPROTO_TCP) ? NET_SOCK_STREAM : NET_SOCK_DGRAM;
	ctx->sock = sock;

	zvfs_finalize_typed_fd(fd, ctx, (const struct fd_op_vtable *)&tls_sock_fd_op_vtable,
			    ZVFS_MODE_IFSOCK);

	return fd;

release_tls:
	(void)tls_release(ctx);

free_fd:
	zvfs_free_fd(fd);

	return -1;
}

int ztls_close_ctx(struct tls_context *ctx, int sock)
{
	struct tls_session_context *session_ctx = NULL;
	int ret, err = 0;

	/* Try to send close notification. */
	ctx->flags = 0;

#if defined(CONFIG_WOLFSSL)
	/* Close-notify is sent per session in tls_session_free, via tls_release */
	ARG_UNUSED(session_ctx);
#else
	SYS_SLIST_FOR_EACH_CONTAINER(&ctx->sessions, session_ctx, node) {
		(void)mbedtls_ssl_close_notify(&session_ctx->ssl);
	}
#endif /* CONFIG_WOLFSSL */

	err = tls_release(ctx);
	ret = zsock_close(ctx->sock);

	if (ret == 0) {
		(void)sock_obj_core_dealloc(sock);
	}

	/* In case close fails, we propagate errno value set by close.
	 * In case close succeeds, but tls_release fails, set errno
	 * according to tls_release return value.
	 */
	if (ret == 0 && err < 0) {
		errno = -err;
		ret = -1;
	}

	return ret;
}

int ztls_connect_ctx(struct tls_context *ctx, const struct net_sockaddr *addr,
		     net_socklen_t addrlen)
{
	int ret;
	int sock_flags;
	bool is_non_block;

	sock_flags = zsock_fcntl(ctx->sock, ZVFS_F_GETFL, 0);
	if (sock_flags < 0) {
		return -EIO;
	}

	is_non_block = sock_flags & ZVFS_O_NONBLOCK;
	if (is_non_block) {
		(void)zsock_fcntl(ctx->sock, ZVFS_F_SETFL,
				  sock_flags & ~ZVFS_O_NONBLOCK);
	}

	ret = zsock_connect(ctx->sock, addr, addrlen);
	if (ret < 0) {
		return ret;
	}

	if (is_non_block) {
		(void)zsock_fcntl(ctx->sock, ZVFS_F_SETFL, sock_flags);
	}

#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
	if (ctx->type == NET_SOCK_DGRAM) {
		dtls_peer_address_set(ctx->active_session, addr, addrlen);
	}
#endif

	if (ctx->type == NET_SOCK_STREAM
#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
	    || (ctx->type == NET_SOCK_DGRAM && ctx->options.dtls_handshake_on_connect)
#endif
	    ) {
#if defined(CONFIG_WOLFSSL)
		ret = tls_wolfssl_init(ctx, false);
		if (ret < 0) {
			goto error;
		}

		/* Do not use any socket flags during the handshake. */
		ctx->flags = 0;

		tls_session_restore(ctx, addr, addrlen);

		/* TODO For simplicity, TLS handshake blocks the socket
		 * even for non-blocking socket.
		 */
		ret = tls_wolfssl_handshake(
			ctx, K_MSEC(CONFIG_NET_SOCKETS_TLS_CONNECT_TIMEOUT));
		if (ret < 0) {
			if ((ret == -EAGAIN) && !is_non_block) {
				ret = -ETIMEDOUT;
			}

			goto error;
		}

		tls_session_store(ctx, addr, addrlen);
#else
		ret = tls_mbedtls_init(ctx, false);
		if (ret < 0) {
			goto error;
		}

		/* Do not use any socket flags during the handshake. */
		ctx->flags = 0;

		tls_session_restore(ctx, addr, addrlen);

		/* TODO For simplicity, TLS handshake blocks the socket
		 * even for non-blocking socket.
		 */
		ret = tls_mbedtls_handshake(
			ctx, K_MSEC(CONFIG_NET_SOCKETS_TLS_CONNECT_TIMEOUT));
		if (ret < 0) {
			if ((ret == -EAGAIN) && !is_non_block) {
				ret = -ETIMEDOUT;
			}

			goto error;
		}

		/* TLS 1.3 tickets arrive after the handshake. */
		if (mbedtls_ssl_get_version_number(&ctx->active_session->ssl) !=
		    MBEDTLS_SSL_VERSION_TLS1_3) {
			tls_session_store(ctx, addr, addrlen);
		}
#endif /* CONFIG_WOLFSSL */
	}

	return 0;

error:
	errno = -ret;
	return -1;
}

int ztls_accept_ctx(struct tls_context *parent, struct net_sockaddr *addr,
		    net_socklen_t *addrlen)
{
	struct tls_context *child = NULL;
	int ret, err, fd, sock;

	fd = zvfs_reserve_fd();
	if (fd < 0) {
		return -1;
	}


	k_mutex_unlock(parent->lock);
	sock = zsock_accept(parent->sock, addr, addrlen);
	k_mutex_lock(parent->lock, K_FOREVER);
	if (sock < 0) {
		ret = -errno;
		goto error;
	}

	child = tls_clone(parent);
	if (child == NULL) {
		ret = -ENOMEM;
		goto error;
	}

	zvfs_finalize_typed_fd(fd, child, (const struct fd_op_vtable *)&tls_sock_fd_op_vtable,
			    ZVFS_MODE_IFSOCK);

	child->sock = sock;

#if defined(CONFIG_WOLFSSL)
	ret = tls_wolfssl_init(child, true);
	if (ret < 0) {
		goto error;
	}

	/* Do not use any socket flags during the handshake. */
	child->flags = 0;

	/* TODO For simplicity, TLS handshake blocks the socket even for
	 * non-blocking socket.
	 */
	ret = tls_wolfssl_handshake(
		child, K_MSEC(CONFIG_NET_SOCKETS_TLS_CONNECT_TIMEOUT));
	if (ret < 0) {
		if ((ret == -EAGAIN) && is_blocking(parent->sock, 0)) {
			ret = -ETIMEDOUT;
		}

		goto error;
	}

	return fd;
#else
	ret = tls_mbedtls_init(child, true);
	if (ret < 0) {
		goto error;
	}

	/* Do not use any socket flags during the handshake. */
	child->flags = 0;

	/* TODO For simplicity, TLS handshake blocks the socket even for
	 * non-blocking socket.
	 */
	ret = tls_mbedtls_handshake(
		child, K_MSEC(CONFIG_NET_SOCKETS_TLS_CONNECT_TIMEOUT));
	if (ret < 0) {
		if ((ret == -EAGAIN) && is_blocking(parent->sock, 0)) {
			ret = -ETIMEDOUT;
		}

		goto error;
	}

	return fd;
#endif /* CONFIG_WOLFSSL */

error:
	if (child != NULL) {
		err = tls_release(child);
		__ASSERT(err == 0, "TLS context release failed");
	}

	if (sock >= 0) {
		err = zsock_close(sock);
		__ASSERT(err == 0, "Child socket close failed");
	}

	zvfs_free_fd(fd);

	errno = -ret;
	return -1;
}

#if defined(CONFIG_WOLFSSL)
static ssize_t send_tls_wolfssl(struct tls_context *ctx, const void *buf,
				size_t len, int flags)
{
	const bool is_block = is_blocking(ctx->sock, flags);
	int ret = 0;
	int err = 0;
	k_timeout_t timeout;
	k_timepoint_t end;

	if (ctx->error != 0) {
		errno = ctx->error;
		return -1;
	}

	if (ctx->active_session->session_closed) {
		errno = ECONNABORTED;
		return -1;
	}

	if (!is_block) {
		timeout = K_NO_WAIT;
	} else {
		timeout = ctx->options.timeout_tx;
	}

	end = sys_timepoint_calc(timeout);

	do {
		ret = wolfSSL_write(ctx->active_session->wssl, buf, len);
		if (ret > 0) {
			return ret;
		}

		err = wolfSSL_get_error(ctx->active_session->wssl, ret);

		/* A zero-length write is a no-op, as on mbedTLS */
		if (ret == 0 && err == WOLFSSL_ERROR_NONE) {
			return 0;
		}

		if (err == WOLFSSL_ERROR_WANT_READ ||
		    err == WOLFSSL_ERROR_WANT_WRITE) {
			int timeout_ms;

			if (!is_block) {
				errno = EAGAIN;
				break;
			}

			/* Blocking timeout. */
			timeout = sys_timepoint_timeout(end);
			if (K_TIMEOUT_EQ(timeout, K_NO_WAIT)) {
				errno = EAGAIN;
				break;
			}

			/* Block. */
			timeout_ms = timeout_to_ms(&timeout);
			ret = wait_for_reason(ctx->sock, timeout_ms, err);
			if (ret < 0) {
				errno = -ret;
				break;
			}
		} else {
			NET_ERR("TLS send error: %x", err);
			/* As on mbedTLS, a failed reset leaves the session unusable */
			if (tls_wolfssl_reset_session(ctx) != 0) {
				ctx->error = ENOMEM;
				errno = ENOMEM;
			} else {
				ctx->error = ECONNABORTED;
				errno = ECONNABORTED;
			}
			break;
		}
	} while (true);

	return -1;
}
#endif /* CONFIG_WOLFSSL */

#if defined(CONFIG_MBEDTLS)
static ssize_t send_tls(struct tls_context *ctx, const void *buf,
			size_t len, int flags)
{
	const bool is_block = is_blocking(ctx->sock, flags);
	k_timeout_t timeout;
	k_timepoint_t end;
	int ret;

	if (ctx->error != 0) {
		errno = ctx->error;
		return -1;
	}

	if (ctx->active_session->session_closed) {
		errno = ECONNABORTED;
		return -1;
	}

	if (!is_block) {
		timeout = K_NO_WAIT;
	} else {
		timeout = ctx->options.timeout_tx;
	}

	end = sys_timepoint_calc(timeout);

	do {
		ret = mbedtls_ssl_write(&ctx->active_session->ssl, buf, len);
		if (ret >= 0) {
			return ret;
		}

		if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
		    ret == MBEDTLS_ERR_SSL_WANT_WRITE ||
		    ret == MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS ||
		    ret ==  MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS) {
			int timeout_ms;

			if (!is_block) {
				errno = EAGAIN;
				break;
			}

			/* Blocking timeout. */
			timeout = sys_timepoint_timeout(end);
			if (K_TIMEOUT_EQ(timeout, K_NO_WAIT)) {
				errno = EAGAIN;
				break;
			}

			/* Block. */
			timeout_ms = timeout_to_ms(&timeout);
			ret = wait_for_reason(ctx->sock, timeout_ms, ret);
			if (ret != 0) {
				errno = -ret;
				break;
			}
		} else {
			NET_ERR("TLS send error: -%x", -ret);

			/* MbedTLS API documentation requires session to
			 * be reset in other error cases
			 */
			ret = tls_mbedtls_reset_session(ctx);
			if (ret != 0) {
				ctx->error = ENOMEM;
				errno = ENOMEM;
			} else {
				ctx->error = ECONNABORTED;
				errno = ECONNABORTED;
			}

			break;
		}
	} while (true);

	return -1;
}
#endif /* CONFIG_MBEDTLS */

#if defined(CONFIG_WOLFSSL) && defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
static ssize_t sendto_dtls_client_wolfssl(struct tls_context *ctx,
					  const void *buf, size_t len,
					  int flags,
					  const struct net_sockaddr *dest_addr,
					  net_socklen_t addrlen)
{
	int ret;

	if (!dest_addr) {
		/* No address provided, check if we have stored one,
		 * otherwise return error.
		 */
		if (ctx->active_session->dtls_peer_addrlen == 0) {
			ret = -EDESTADDRREQ;
			goto error;
		}
	} else if (ctx->active_session->dtls_peer_addrlen == 0) {
		/* Address provided and no peer address stored. */
		dtls_peer_address_set(ctx->active_session, dest_addr, addrlen);
	} else if (!dtls_is_peer_addr_valid(ctx->active_session, dest_addr, addrlen)) {
		/* Address provided but it does not match stored one */
		ret = -EISCONN;
		goto error;
	}

	if (!ctx->is_initialized) {
		ret = tls_wolfssl_init(ctx, false);
		if (ret < 0) {
			goto error;
		}
	}

	if (!is_handshake_complete(ctx->active_session)) {
		tls_session_restore(ctx, net_sad(&ctx->active_session->dtls_peer_addr),
				    ctx->active_session->dtls_peer_addrlen);

		/* TODO For simplicity, TLS handshake blocks the socket even for
		 * non-blocking socket.
		 * DTLS handshake timeout/retransmissions are limited by
		 * wolfSSL, so K_FOREVER is fine here, the function will not
		 * block indefinitely.
		 */
		ret = tls_wolfssl_handshake(ctx, K_FOREVER);
		if (ret < 0) {
			goto error;
		}

		/* Client socket ready to use again. */
		ctx->error = 0;

		tls_session_store(ctx, net_sad(&ctx->active_session->dtls_peer_addr),
				  ctx->active_session->dtls_peer_addrlen);
	}

	return send_tls_wolfssl(ctx, buf, len, flags);

error:
	errno = -ret;
	return -1;
}

static ssize_t sendto_dtls_server_wolfssl(struct tls_context *ctx,
					  const void *buf, size_t len,
					  int flags,
					  const struct net_sockaddr *dest_addr,
					  net_socklen_t addrlen)
{
	int ret;

	if (dest_addr != NULL) {
		/* Verify we have a session with the client. */
		ret = dtls_server_switch_active_session(ctx, dest_addr, addrlen);
		if (ret < 0) {
			NET_DBG("No session found (TX) for [%s]:%d",
				LOG_ADDR_PORT_HELPER(dest_addr));
			errno = ENOTCONN;
			return -1;
		}
	}

	/* For DTLS server, require to have established DTLS connection
	 * in order to send data.
	 */
	if (!is_handshake_complete(ctx->active_session)) {
		errno = ENOTCONN;
		return -1;
	}

	ret = send_tls_wolfssl(ctx, buf, len, flags);
	if (ret < 0 && errno != EAGAIN) {
		(void)dtls_server_free_active_session(ctx);
	}

	return ret;
}
#endif /* CONFIG_WOLFSSL && CONFIG_NET_SOCKETS_ENABLE_DTLS */

#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS) && defined(CONFIG_MBEDTLS)
static ssize_t sendto_dtls_client(struct tls_context *ctx, const void *buf,
				  size_t len, int flags,
				  const struct net_sockaddr *dest_addr,
				  net_socklen_t addrlen)
{
	int ret;

	if (!dest_addr) {
		/* No address provided, check if we have stored one,
		 * otherwise return error.
		 */
		if (ctx->active_session->dtls_peer_addrlen == 0) {
			ret = -EDESTADDRREQ;
			goto error;
		}
	} else if (ctx->active_session->dtls_peer_addrlen == 0) {
		/* Address provided and no peer address stored. */
		dtls_peer_address_set(ctx->active_session, dest_addr, addrlen);
	} else if (!dtls_is_peer_addr_valid(ctx->active_session, dest_addr, addrlen) != 0) {
		/* Address provided but it does not match stored one */
		ret = -EISCONN;
		goto error;
	}

	if (!ctx->is_initialized) {
		ret = tls_mbedtls_init(ctx, false);
		if (ret < 0) {
			goto error;
		}
	}

	if (!is_handshake_complete(ctx->active_session)) {
		tls_session_restore(ctx, net_sad(&ctx->active_session->dtls_peer_addr),
				    ctx->active_session->dtls_peer_addrlen);

		/* TODO For simplicity, TLS handshake blocks the socket even for
		 * non-blocking socket.
		 * DTLS handshake timeout/retransmissions are limited by
		 * mbed TLS, so K_FOREVER is fine here, the function will not
		 * block indefinitely.
		 */
		ret = tls_mbedtls_handshake(ctx, K_FOREVER);
		if (ret < 0) {
			goto error;
		}

		/* Client socket ready to use again. */
		ctx->error = 0;

		tls_session_store(ctx, net_sad(&ctx->active_session->dtls_peer_addr),
				  ctx->active_session->dtls_peer_addrlen);
	}

	return send_tls(ctx, buf, len, flags);

error:
	errno = -ret;
	return -1;
}

static ssize_t sendto_dtls_server(struct tls_context *ctx, const void *buf,
				  size_t len, int flags,
				  const struct net_sockaddr *dest_addr,
				  net_socklen_t addrlen)
{
	int ret;

	if (dest_addr != NULL) {
		/* Verify we have a session with the client. */
		ret = dtls_server_switch_active_session(ctx, dest_addr, addrlen);
		if (ret < 0) {
			NET_DBG("No session found (TX) for [%s]:%d",
				LOG_ADDR_PORT_HELPER(dest_addr));
			errno = ENOTCONN;
			return -1;
		}
	}

	/* For DTLS server, require to have established DTLS connection
	 * in order to send data.
	 */
	if (!is_handshake_complete(ctx->active_session)) {
		errno = ENOTCONN;
		return -1;
	}

	ret = send_tls(ctx, buf, len, flags);
	if (ret < 0 && errno != EAGAIN) {
		(void)dtls_server_free_active_session(ctx);
	}

	return ret;
}
#endif /* CONFIG_NET_SOCKETS_ENABLE_DTLS && CONFIG_MBEDTLS */

ssize_t ztls_sendto_ctx(struct tls_context *ctx, const void *buf, size_t len,
			int flags, const struct net_sockaddr *dest_addr,
			net_socklen_t addrlen)
{
	ctx->flags = flags;

#if defined(CONFIG_WOLFSSL)
	/* TLS */
	if (ctx->type == NET_SOCK_STREAM) {
		return send_tls_wolfssl(ctx, buf, len, flags);
	}

#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
	/* DTLS */
	if (ctx->options.role == ZTLS_IS_SERVER) {
		return sendto_dtls_server_wolfssl(ctx, buf, len, flags,
						  dest_addr, addrlen);
	}

	return sendto_dtls_client_wolfssl(ctx, buf, len, flags,
					  dest_addr, addrlen);
#else
	errno = ENOTSUP;
	return -1;
#endif /* CONFIG_NET_SOCKETS_ENABLE_DTLS */
#else
	/* TLS */
	if (ctx->type == NET_SOCK_STREAM) {
		return send_tls(ctx, buf, len, flags);
	}

#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
	/* DTLS */
	if (ctx->options.role == MBEDTLS_SSL_IS_SERVER) {
		return sendto_dtls_server(ctx, buf, len, flags,
					  dest_addr, addrlen);
	}

	return sendto_dtls_client(ctx, buf, len, flags, dest_addr, addrlen);
#else
	errno = ENOTSUP;
	return -1;
#endif /* CONFIG_NET_SOCKETS_ENABLE_DTLS */
#endif /* CONFIG_WOLFSSL */
}

#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
static ssize_t dtls_sendmsg_merge_and_send(struct tls_context *ctx,
					   const struct net_msghdr *msg,
					   int flags)
{
	ssize_t len = 0;

	k_mutex_lock(&dtls_helper_buf_lock, K_FOREVER);

	for (int i = 0; i < msg->msg_iovlen; i++) {
		struct net_iovec *vec = msg->msg_iov + i;

		if (vec->iov_len > 0) {
			if (len + vec->iov_len > sizeof(dtls_helper_buf)) {
				k_mutex_unlock(&dtls_helper_buf_lock);
				errno = EMSGSIZE;
				return -1;
			}

			memcpy(dtls_helper_buf + len, vec->iov_base, vec->iov_len);
			len += vec->iov_len;
		}
	}

	if (len > 0) {
		len = ztls_sendto_ctx(ctx, dtls_helper_buf, len, flags,
				      msg->msg_name, msg->msg_namelen);
	}

	k_mutex_unlock(&dtls_helper_buf_lock);

	return len;
}
#else
#define dtls_sendmsg_merge_and_send(...) (-1)
#endif

static ssize_t tls_sendmsg_loop_and_send(struct tls_context *ctx,
					 const struct net_msghdr *msg,
					 int flags)
{
	ssize_t len = 0;
	ssize_t ret;

	for (int i = 0; i < msg->msg_iovlen; i++) {
		struct net_iovec *vec = msg->msg_iov + i;
		size_t sent = 0;

		if (vec->iov_len == 0) {
			continue;
		}

		while (sent < vec->iov_len) {
			uint8_t *ptr = (uint8_t *)vec->iov_base + sent;

			ret = ztls_sendto_ctx(ctx, ptr, vec->iov_len - sent,
					      flags, msg->msg_name,
					      msg->msg_namelen);
			if (ret < 0) {
				return ret;
			}
			sent += ret;
		}
		len += sent;
	}

	return len;
}

ssize_t ztls_sendmsg_ctx(struct tls_context *ctx, const struct net_msghdr *msg,
			 int flags)
{
	if (msg == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (IS_ENABLED(CONFIG_NET_SOCKETS_ENABLE_DTLS) &&
	    ctx->type == NET_SOCK_DGRAM) {
		if (DTLS_SENDMSG_BUF_SIZE > 0) {
			/* With one buffer only, there's no need to use
			 * intermediate buffer.
			 */
			if (msghdr_non_empty_iov_count(msg) == 1) {
				goto send_loop;
			}

			return dtls_sendmsg_merge_and_send(ctx, msg, flags);
		}

		/*
		 * Current Mbed TLS API (i.e. mbedtls_ssl_write()) allows only to send a single
		 * contiguous buffer. This means that gather write using sendmsg() can only be
		 * handled correctly if there is a single non-empty buffer in msg->msg_iov.
		 */
		if (msghdr_non_empty_iov_count(msg) > 1) {
			errno = EMSGSIZE;
			return -1;
		}
	}

send_loop:
	return tls_sendmsg_loop_and_send(ctx, msg, flags);
}

#if defined(CONFIG_WOLFSSL)
static ssize_t recv_tls_wolfssl(struct tls_context *ctx, void *buf,
				size_t max_len, int flags)
{
	size_t recv_len = 0;
	const bool waitall = flags & ZSOCK_MSG_WAITALL;
	const bool is_block = is_blocking(ctx->sock, flags);
	k_timeout_t timeout;
	k_timepoint_t end;
	int ret;
	int err;

	if (ctx->error != 0) {
		errno = ctx->error;
		return -1;
	}

	if (ctx->active_session->session_closed || ctx->recv_eof) {
		return 0;
	}

	if (!is_block) {
		timeout = K_NO_WAIT;
	} else {
		timeout = ctx->options.timeout_rx;
	}

	end = sys_timepoint_calc(timeout);

	do {
		size_t read_len = max_len - recv_len;

		ret = wolfSSL_read(ctx->active_session->wssl,
				   (uint8_t *)buf + recv_len, read_len);
		if (ret < 0) {
			/* A local read shutdown racing this recv() is no ZERO_RETURN to wolfSSL;
			 * return what was read so far.
			 */
			if (ctx->recv_eof) {
				return recv_len;
			}

			err = wolfSSL_get_error(ctx->active_session->wssl, ret);
			if (err == WOLFSSL_ERROR_WANT_READ ||
			    err == WOLFSSL_ERROR_WANT_WRITE) {
				int timeout_ms;

				if (!is_block) {
					ret = -EAGAIN;
					goto err;
				}

				/* Blocking timeout. */
				timeout = sys_timepoint_timeout(end);
				if (K_TIMEOUT_EQ(timeout, K_NO_WAIT)) {
					ret = -EAGAIN;
					goto err;
				}

				timeout_ms = timeout_to_ms(&timeout);

				/* Block. */
				k_mutex_unlock(ctx->lock);
				ret = wait_for_reason(ctx->sock, timeout_ms, err);
				k_mutex_lock(ctx->lock, K_FOREVER);

				if (ret >= 0) {
					/* Retry. */
					continue;
				}
			} else if (err == WOLFSSL_ERROR_ZERO_RETURN ||
				   err == SOCKET_PEER_CLOSED_E) {
				ctx->active_session->session_closed = true;
				break;
			} else {
				NET_ERR("TLS recv error: %x", err);
				ret = -EIO;
			}

err:
			errno = -ret;
			return -1;
		}

		if (ret == 0) {
			/* A clean closure reads as 0; send() then fails as on mbedTLS */
			err = wolfSSL_get_error(ctx->active_session->wssl, ret);
			if (err == WOLFSSL_ERROR_ZERO_RETURN ||
			    err == SOCKET_PEER_CLOSED_E) {
				ctx->active_session->session_closed = true;
			}
			break;
		}

		recv_len += ret;
	} while ((recv_len == 0) || (waitall && (recv_len < max_len)));

	return recv_len;
}
#endif /* CONFIG_WOLFSSL */

#if defined(CONFIG_MBEDTLS)
static ssize_t recv_tls(struct tls_context *ctx, void *buf,
			size_t max_len, int flags)
{
	size_t recv_len = 0;
	const bool waitall = flags & ZSOCK_MSG_WAITALL;
	const bool is_block = is_blocking(ctx->sock, flags);
	k_timeout_t timeout;
	k_timepoint_t end;
	int ret;

	if (ctx->error != 0) {
		errno = ctx->error;
		return -1;
	}

	if (ctx->active_session->session_closed) {
		return 0;
	}

	if (!is_block) {
		timeout = K_NO_WAIT;
	} else {
		timeout = ctx->options.timeout_rx;
	}

	end = sys_timepoint_calc(timeout);

	do {
		size_t read_len = max_len - recv_len;

		ret = mbedtls_ssl_read(&ctx->active_session->ssl, (uint8_t *)buf + recv_len,
				       read_len);
		if (ret < 0) {
			if (ret == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) {
				tls_session_store_current(ctx);
			}

			if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
				/* Peer notified that it's closing the
				 * connection.
				 */
				ctx->active_session->session_closed = true;
				break;
			}

			if (ret == MBEDTLS_ERR_SSL_CLIENT_RECONNECT) {
				/* Client reconnect on the same socket is not
				 * supported. See mbedtls_ssl_read API
				 * documentation.
				 */
				ctx->active_session->session_closed = true;
				break;
			}

			if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
			    ret == MBEDTLS_ERR_SSL_WANT_WRITE ||
			    ret == MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS ||
			    ret == MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS ||
			    ret == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) {
				int timeout_ms;

				if (!is_block) {
					ret = -EAGAIN;
					goto err;
				}

				/* Blocking timeout. */
				timeout = sys_timepoint_timeout(end);
				if (K_TIMEOUT_EQ(timeout, K_NO_WAIT)) {
					ret = -EAGAIN;
					goto err;
				}

				timeout_ms = timeout_to_ms(&timeout);

				/* Block. */
				k_mutex_unlock(ctx->lock);
				ret = wait_for_reason(ctx->sock, timeout_ms, ret);
				k_mutex_lock(ctx->lock, K_FOREVER);

				if (ret == 0) {
					/* Retry. */
					continue;
				}
			} else {
				NET_ERR("TLS recv error: -%x", -ret);
				ret = -EIO;
			}

err:
			errno = -ret;
			return -1;
		}

		if (ret == 0) {
			break;
		}

		recv_len += ret;
	} while ((recv_len == 0) || (waitall && (recv_len < max_len)));

	return recv_len;
}

#endif /* CONFIG_MBEDTLS */

#if defined(CONFIG_WOLFSSL) && defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
static ssize_t recvfrom_dtls_common_wolfssl(struct tls_context *ctx, void *buf,
					    size_t max_len, int flags,
					    struct net_sockaddr *src_addr,
					    net_socklen_t *addrlen)
{
	int ret;
	bool is_server = ctx->options.role == ZTLS_IS_SERVER;
	bool is_block = is_blocking(ctx->sock, flags);
	k_timeout_t timeout;
	k_timepoint_t end;
	int remaining;
	bool retry;

	if (ctx->error != 0) {
		return -ctx->error;
	}

	if (ctx->recv_eof) {
		return 0;
	}

	if (!is_block) {
		timeout = K_NO_WAIT;
	} else {
		timeout = ctx->options.timeout_rx;
	}

	end = sys_timepoint_calc(timeout);

	do {
		int timeout_ms;

		retry = false;
		ret = wolfSSL_read(ctx->active_session->wssl, buf, max_len);
		/* wolfSSL_read() returns 0 for a close_notify */
		if (ret <= 0) {
			int err;

			/* A local read shutdown raced this recv(); a DTLS read is one datagram */
			if (ctx->recv_eof) {
				return 0;
			}

			err = wolfSSL_get_error(ctx->active_session->wssl, ret);

			if (err == WOLFSSL_ERROR_WANT_READ ||
			    err == WOLFSSL_ERROR_WANT_WRITE) {
				if (is_server) {
					int err2 = dtls_server_switch_session_on_rx(ctx);

					/* If session swapping is successful, return early
					 * so that recvfrom_dtls_server_wolfssl() can
					 * proceed with another handshake. Otherwise, there
					 * either really was no packet, or we've failed to
					 * allocate a new session, so the packet was
					 * dropped. In either case, just proceed as if
					 * there were no packet.
					 */
					if (err2 == 0) {
						return -EAGAIN;
					}
				}

				if (!is_block) {
					return -EAGAIN;
				}

				timeout = sys_timepoint_timeout(end);
				if (K_TIMEOUT_EQ(timeout, K_NO_WAIT)) {
					return -EAGAIN;
				}

				timeout_ms = timeout_to_ms(&timeout);

				k_mutex_unlock(ctx->lock);
				ret = wait_for_reason(ctx->sock, timeout_ms, err);
				k_mutex_lock(ctx->lock, K_FOREVER);

				if (ret >= 0) {
					retry = true;
					continue;
				}

				return ret;
			}

			if (err == SOCKET_PEER_CLOSED_E ||
			    err == WOLFSSL_ERROR_ZERO_RETURN) {
				return -ENOTCONN;
			}

			if (ret == 0 && err == WOLFSSL_ERROR_NONE) {
				/* An empty datagram is a 0-byte receive, as on mbedTLS */
				return 0;
			}

			/* A peek absorbed a fatal alert and reset the server session */
			if (err == BUFFER_ERROR && is_server) {
				return -EAGAIN;
			}

			return -EIO;
		}

		if (src_addr && addrlen) {
			dtls_peer_address_get(ctx->active_session, src_addr, addrlen);
		}

		remaining = wolfSSL_pending(ctx->active_session->wssl);

		/* No more data in the datagram, or dummy read. */
		if ((remaining == 0) || (max_len == 0)) {
			return ret;
		}

		if (flags & ZSOCK_MSG_TRUNC) {
			ret += remaining;
		}

		/* Always drain remaining datagram data */
		while (remaining > 0) {
			byte dummy[128];
			int to_read = MIN(remaining, sizeof(dummy));
			int r = wolfSSL_read(ctx->active_session->wssl, dummy, to_read);

			if (r <= 0) {
				wc_ForceZero(dummy, sizeof(dummy));
				NET_ERR("Error while flushing the rest of the"
					" datagram, err %d", r);
				ret = -EIO;
				break;
			}
			remaining -= r;
			/* Scrub the plaintext drained into the discard buffer */
			wc_ForceZero(dummy, sizeof(dummy));
		}

		return ret;
	} while (retry);

	return -EAGAIN;
}

static ssize_t recvfrom_dtls_client_wolfssl(struct tls_context *ctx, void *buf,
					    size_t max_len, int flags,
					    struct net_sockaddr *src_addr,
					    net_socklen_t *addrlen)
{
	int ret;

	if (!is_handshake_complete(ctx->active_session)) {
		ret = -ENOTCONN;
		goto error;
	}

	ret = recvfrom_dtls_common_wolfssl(ctx, buf, max_len, flags,
					   src_addr, addrlen);
	if (ret >= 0) {
		return ret;
	}

	if (ret == -ENOTCONN) {
		/* Peer notified that it's closing the connection. */
		if (tls_wolfssl_reset_session(ctx) == 0) {
			ctx->error = ENOTCONN;
		} else {
			ctx->error = ENOMEM;
			ret = -ENOMEM;
		}
		goto error;
	}
	if (ret == -EAGAIN) {
		goto error;
	}

	NET_ERR("DTLS client recv error: %d", ret);

	if (tls_wolfssl_reset_session(ctx) != 0) {
		ctx->error = ENOMEM;
		ret = -ENOMEM;
	} else {
		ctx->error = ECONNABORTED;
		ret = -ECONNABORTED;
	}

error:
	errno = -ret;
	return -1;
}

static ssize_t recvfrom_dtls_server_wolfssl(struct tls_context *ctx, void *buf,
					    size_t max_len, int flags,
					    struct net_sockaddr *src_addr,
					    net_socklen_t *addrlen)
{
	int ret;
	bool repeat;
	k_timeout_t timeout;

	if (!ctx->is_initialized) {
		ret = tls_wolfssl_init(ctx, true);
		if (ret < 0) {
			goto error;
		}
	}

	if (is_blocking(ctx->sock, flags)) {
		timeout = ctx->options.timeout_rx;
	} else {
		timeout = K_NO_WAIT;
	}

	/* Loop to enable DTLS reconnection for servers without closing
	 * a socket.
	 */
	do {
		struct net_sockaddr_storage peer_addr;
		net_socklen_t peer_addrlen = sizeof(peer_addr);

		repeat = false;

		(void)dtls_server_check_expired_sessions(ctx);

		if (!is_handshake_complete(ctx->active_session)) {
			ret = tls_wolfssl_handshake(ctx, timeout);
			if (ret < 0) {
				/* In case of EAGAIN, check if it's needed to swap
				 * sessions, otherwise just exit.
				 */
				if (ret == -EAGAIN) {
					int err = dtls_server_switch_session_on_rx(ctx);

					if (err == 0) {
						/* Switched the session, repeat the loop. */
						continue;
					}

					break;
				}

				ret = dtls_server_free_active_session(ctx);
				if (ret == 0) {
					repeat = true;
				} else {
					ret = -ENOMEM;
				}

				continue;
			}

			/* Server socket ready to use again. */
			ctx->error = 0;
		}

		/* Backup peer address (to verify later if it changed). */
		dtls_peer_address_get(ctx->active_session, net_sad(&peer_addr), &peer_addrlen);

		ret = recvfrom_dtls_common_wolfssl(ctx, buf, max_len, flags,
						   src_addr, addrlen);
		if (ret >= 0) {
			return ret;
		}

		switch (ret) {
		case -ENOTCONN:
			/* The peer closed the session, so free it for the next client */
			ret = dtls_server_free_active_session(ctx);
			if (ret == 0) {
				repeat = true;
			} else {
				ctx->error = ENOMEM;
				ret = -ENOMEM;
			}
			break;

		case -EAGAIN:
			if (peer_addrlen > 0 &&
			    !dtls_is_peer_addr_valid(ctx->active_session, net_sad(&peer_addr),
						     peer_addrlen)) {
				/* Current peer changed, repeat the loop. */
				repeat = true;
			} else {
				(void)dtls_server_check_expired_sessions(ctx);
				/* Otherwise, just return the error. */
				ret = -EAGAIN;
			}

			break;

		default:
			NET_ERR("DTLS server recv error: %d", ret);

			ret = dtls_server_free_active_session(ctx);
			if (ret == 0) {
				repeat = true;
			} else {
				ctx->error = ENOMEM;
				ret = -ENOMEM;
			}

			break;
		}
	} while (repeat);

error:
	errno = -ret;
	return -1;
}
#endif /* CONFIG_WOLFSSL && CONFIG_NET_SOCKETS_ENABLE_DTLS */

#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS) && defined(CONFIG_MBEDTLS)
static ssize_t recvfrom_dtls_common(struct tls_context *ctx, void *buf,
				    size_t max_len, int flags,
				    struct net_sockaddr *src_addr,
				    net_socklen_t *addrlen)
{
	bool is_server = ctx->options.role == MBEDTLS_SSL_IS_SERVER;
	bool is_block = is_blocking(ctx->sock, flags);
	k_timeout_t timeout;
	k_timepoint_t end;
	int ret;

	if (ctx->error != 0) {
		errno = ctx->error;
		return -1;
	}

	if (!is_block) {
		timeout = K_NO_WAIT;
	} else {
		timeout = ctx->options.timeout_rx;
	}

	end = sys_timepoint_calc(timeout);

	do {
		size_t remaining;

		ret = mbedtls_ssl_read(&ctx->active_session->ssl, buf, max_len);
		if (ret < 0) {
			if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
			    ret == MBEDTLS_ERR_SSL_WANT_WRITE ||
			    ret == MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS ||
			    ret ==  MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS) {
				int timeout_dtls, timeout_sock, timeout_ms;

				if (is_server) {
					int err = dtls_server_switch_session_on_rx(ctx);

					/* If session swapping is successful, return early so that
					 * recvfrom_dtls_server() can proceed with another
					 * handshake. Otherwise, there either really was no packet,
					 * or we've failed to allocate a new session, so the packet
					 * was dropped. In either case, just proceed as if there
					 * were no packet.
					 */
					if (err == 0) {
						return ret;
					}
				}

				if (!is_block) {
					return ret;
				}

				/* Blocking timeout. */
				timeout = sys_timepoint_timeout(end);
				if (K_TIMEOUT_EQ(timeout, K_NO_WAIT)) {
					return ret;
				}

				timeout_dtls = dtls_get_remaining_timeout(ctx->active_session);
				timeout_sock = timeout_to_ms(&timeout);
				if (timeout_dtls == SYS_FOREVER_MS ||
				    timeout_sock == SYS_FOREVER_MS) {
					timeout_ms = MAX(timeout_dtls, timeout_sock);
				} else {
					timeout_ms = MIN(timeout_dtls, timeout_sock);
				}

				/* Block. */
				k_mutex_unlock(ctx->lock);
				ret = wait_for_reason(ctx->sock, timeout_ms, ret);
				k_mutex_lock(ctx->lock, K_FOREVER);

				if (ret == 0) {
					/* Retry. */
					continue;
				} else {
					return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
				}
			} else {
				return ret;
			}
		}

		if (src_addr && addrlen) {
			dtls_peer_address_get(ctx->active_session, src_addr, addrlen);
		}

		/* mbedtls_ssl_get_bytes_avail() indicate the data length
		 * remaining in the current datagram.
		 */
		remaining = mbedtls_ssl_get_bytes_avail(&ctx->active_session->ssl);

		/* No more data in the datagram, or dummy read. */
		if ((remaining == 0) || (max_len == 0)) {
			return ret;
		}

		if (flags & ZSOCK_MSG_TRUNC) {
			ret += remaining;
		}

		for (int i = 0; i < remaining; i++) {
			uint8_t byte;
			int err;

			err = mbedtls_ssl_read(&ctx->active_session->ssl, &byte, sizeof(byte));
			if (err <= 0) {
				NET_ERR("Error while flushing the rest of the"
					" datagram, err %d", err);
				ret = MBEDTLS_ERR_SSL_INTERNAL_ERROR;
				break;
			}
		}

		break;
	} while (true);


	return ret;
}

static ssize_t recvfrom_dtls_client(struct tls_context *ctx, void *buf,
				    size_t max_len, int flags,
				    struct net_sockaddr *src_addr,
				    net_socklen_t *addrlen)
{
	int ret;

	if (!is_handshake_complete(ctx->active_session)) {
		ret = -ENOTCONN;
		goto error;
	}

	ret = recvfrom_dtls_common(ctx, buf, max_len, flags, src_addr, addrlen);
	if (ret >= 0) {
		return ret;
	}

	switch (ret) {
	case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
		/* Peer notified that it's closing the connection. */
		ret = tls_mbedtls_reset_session(ctx);
		if (ret == 0) {
			ctx->error = ENOTCONN;
			ret = -ENOTCONN;
		} else {
			ctx->error = ENOMEM;
			ret = -ENOMEM;
		}
		break;

	case MBEDTLS_ERR_SSL_TIMEOUT:
		(void)mbedtls_ssl_close_notify(&ctx->active_session->ssl);
		ctx->error = ETIMEDOUT;
		ret = -ETIMEDOUT;
		break;

	case MBEDTLS_ERR_SSL_WANT_READ:
	case MBEDTLS_ERR_SSL_WANT_WRITE:
	case MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS:
	case MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS:
		ret = -EAGAIN;
		break;

	default:
		NET_ERR("DTLS client recv error: -%x", -ret);

		/* MbedTLS API documentation requires session to
		 * be reset in other error cases
		 */
		ret = tls_mbedtls_reset_session(ctx);
		if (ret != 0) {
			ctx->error = ENOMEM;
			errno = ENOMEM;
		} else {
			ctx->error = ECONNABORTED;
			ret = -ECONNABORTED;
		}

		break;
	}

error:
	errno = -ret;
	return -1;
}

static ssize_t recvfrom_dtls_server(struct tls_context *ctx, void *buf,
				    size_t max_len, int flags,
				    struct net_sockaddr *src_addr,
				    net_socklen_t *addrlen)
{
	int ret;
	bool repeat;
	k_timeout_t timeout;

	if (!ctx->is_initialized) {
		ret = tls_mbedtls_init(ctx, true);
		if (ret < 0) {
			goto error;
		}
	}

	if (is_blocking(ctx->sock, flags)) {
		timeout = ctx->options.timeout_rx;
	} else {
		timeout = K_NO_WAIT;
	}

	/* Loop to enable DTLS reconnection for servers without closing
	 * a socket.
	 */
	do {
		struct net_sockaddr_storage peer_addr;
		net_socklen_t peer_addrlen = sizeof(peer_addr);

		repeat = false;

		(void)dtls_server_check_expired_sessions(ctx);

		if (!is_handshake_complete(ctx->active_session)) {
			ret = tls_mbedtls_handshake(ctx, timeout);
			if (ret < 0) {
				/* In case of EAGAIN, check if it's needed to swap sessions,
				 * otherwise just exit.
				 */
				if (ret == -EAGAIN) {
					int err = dtls_server_switch_session_on_rx(ctx);

					if (err == 0) {
						/* Switched the session, repeat the loop. */
						continue;
					}

					break;
				}

				ret = dtls_server_free_active_session(ctx);
				if (ret == 0) {
					repeat = true;
				} else {
					ret = -ENOMEM;
				}

				continue;
			}

			/* Server socket ready to use again. */
			ctx->error = 0;
		}

		/* Backup peer address (to verify later if it changed). */
		dtls_peer_address_get(ctx->active_session, net_sad(&peer_addr), &peer_addrlen);

		ret = recvfrom_dtls_common(ctx, buf, max_len, flags,
					   src_addr, addrlen);
		if (ret >= 0) {
			return ret;
		}

		switch (ret) {
		case MBEDTLS_ERR_SSL_TIMEOUT:
			(void)mbedtls_ssl_close_notify(&ctx->active_session->ssl);
			__fallthrough;
			/* fallthrough */

		case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
		case MBEDTLS_ERR_SSL_CLIENT_RECONNECT:
			ret = dtls_server_free_active_session(ctx);
			if (ret == 0) {
				repeat = true;
			} else {
				ctx->error = ENOMEM;
				ret = -ENOMEM;
			}
			break;

		case MBEDTLS_ERR_SSL_WANT_READ:
		case MBEDTLS_ERR_SSL_WANT_WRITE:
		case MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS:
		case MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS:
			if (peer_addrlen > 0 &&
			    !dtls_is_peer_addr_valid(ctx->active_session, net_sad(&peer_addr),
						     peer_addrlen)) {
				/* Current peer changed, repeat the loop. */
				repeat = true;
			} else {
				(void)dtls_server_check_expired_sessions(ctx);
				/* Otherwise, just return the error. */
				ret = -EAGAIN;
			}

			break;

		default:
			NET_ERR("DTLS server recv error: -%x", -ret);

			ret = dtls_server_free_active_session(ctx);
			if (ret == 0) {
				repeat = true;
			} else {
				ctx->error = ENOMEM;
				errno = ENOMEM;
			}

			break;
		}
	} while (repeat);

error:
	errno = -ret;
	return -1;
}
#endif /* CONFIG_NET_SOCKETS_ENABLE_DTLS && CONFIG_MBEDTLS */

ssize_t ztls_recvfrom_ctx(struct tls_context *ctx, void *buf, size_t max_len,
			  int flags, struct net_sockaddr *src_addr,
			  net_socklen_t *addrlen)
{
	if (flags & ZSOCK_MSG_PEEK) {
		/* TODO Mbed TLS does not support 'peeking' This could be
		 * bypassed by having intermediate buffer for peeking
		 */
		errno = ENOTSUP;
		return -1;
	}

	ctx->flags = flags;

#if defined(CONFIG_WOLFSSL)
	/* TLS */
	if (ctx->type == NET_SOCK_STREAM) {
		return recv_tls_wolfssl(ctx, buf, max_len, flags);
	}

#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
	/* DTLS */
	if (ctx->options.role == ZTLS_IS_SERVER) {
		return recvfrom_dtls_server_wolfssl(ctx, buf, max_len, flags,
						    src_addr, addrlen);
	}

	return recvfrom_dtls_client_wolfssl(ctx, buf, max_len, flags,
					    src_addr, addrlen);
#else
	errno = ENOTSUP;
	return -1;
#endif /* CONFIG_NET_SOCKETS_ENABLE_DTLS */
#else
	/* TLS */
	if (ctx->type == NET_SOCK_STREAM) {
		return recv_tls(ctx, buf, max_len, flags);
	}

#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
	/* DTLS */
	if (ctx->options.role == MBEDTLS_SSL_IS_SERVER) {
		return recvfrom_dtls_server(ctx, buf, max_len, flags,
					    src_addr, addrlen);
	}

	return recvfrom_dtls_client(ctx, buf, max_len, flags,
				    src_addr, addrlen);
#else
	errno = ENOTSUP;
	return -1;
#endif /* CONFIG_NET_SOCKETS_ENABLE_DTLS */
#endif /* CONFIG_WOLFSSL */
}

static int tls_data_check(struct tls_context *ctx);

static int ztls_poll_prepare_pollin(struct tls_context *ctx)
{
	int ret;

	if (ctx->is_listening) {
		return 0;
	}

	/* If there already is TLS data to read, there is no
	 * need to set the k_poll_event object. Return EALREADY
	 * so we won't block in the k_poll.
	 */
#if defined(CONFIG_WOLFSSL)
	if (ctx->active_session->wssl != NULL &&
	    wolfSSL_pending(ctx->active_session->wssl) > 0) {
		return -EALREADY;
	}
#else
	if (mbedtls_ssl_get_bytes_avail(&ctx->active_session->ssl) > 0) {
		return -EALREADY;
	}
#endif /* CONFIG_WOLFSSL */

	if (!ctx->is_initialized) {
		return 0;
	}

#if defined(CONFIG_WOLFSSL)
	if (wolfSSL_has_pending(ctx->active_session->wssl) != 1) {
		return 0;
	}
#else
	/* Mbed TLS can hold a message that it already read from the underlying
	 * socket but did not process yet, for example a further record of a
	 * datagram that carried several. The socket has no readiness left to
	 * report in that case, so waiting on it alone can sleep while data is
	 * available. Advance such a message here instead.
	 */
	if (mbedtls_ssl_check_pending(&ctx->active_session->ssl) == 0) {
		return 0;
	}
#endif /* CONFIG_WOLFSSL */

	ret = tls_data_check(ctx);
	if (ret == 0) {
		return 0;
	}

	/* Either plaintext is now exposed, or the session was closed or
	 * failed. All three have to wake the poll. Latch the failure so that
	 * the update path can turn it into POLLHUP or POLLERR, as the
	 * underlying socket will never report it.
	 */
	if (ret < 0 && ret != -ENOTCONN) {
		ctx->error = -ret;
	}

	return -EALREADY;
}

static int ztls_poll_prepare_ctx(struct tls_context *ctx,
				 struct zsock_pollfd *pfd,
				 struct k_poll_event **pev,
				 struct k_poll_event *pev_end)
{
	const struct fd_op_vtable *vtable;
	struct k_mutex *lock;
	void *obj;
	int ret;
	short events = pfd->events;

	/* DTLS client should wait for the handshake to complete before
	 * it actually starts to poll for data.
	 */
	if ((pfd->events & ZSOCK_POLLIN) && (ctx->type == NET_SOCK_DGRAM) &&
	    (ctx->options.role == ZTLS_IS_CLIENT) &&
	    !is_handshake_complete(ctx->active_session)) {
		(*pev)->obj = &ctx->active_session->tls_established;
		(*pev)->type = K_POLL_TYPE_SEM_AVAILABLE;
		(*pev)->mode = K_POLL_MODE_NOTIFY_ONLY;
		(*pev)->state = K_POLL_STATE_NOT_READY;
		(*pev)++;

		/* Since k_poll_event is configured by the TLS layer in this
		 * case, do not forward ZSOCK_POLLIN to the underlying socket.
		 */
		pfd->events &= ~ZSOCK_POLLIN;
	}

	obj = zvfs_get_fd_obj_and_vtable(
		ctx->sock, (const struct fd_op_vtable **)&vtable, &lock);
	if (obj == NULL) {
		ret = -EBADF;
		goto exit;
	}

	(void)k_mutex_lock(lock, K_FOREVER);

	ret = zvfs_fdtable_call_ioctl(vtable, obj, ZFD_IOCTL_POLL_PREPARE,
				   pfd, pev, pev_end);
	if (ret != 0) {
		goto exit;
	}

	if (pfd->events & ZSOCK_POLLIN) {
		ret = ztls_poll_prepare_pollin(ctx);
	}

exit:
	/* Restore original events. */
	pfd->events = events;

	k_mutex_unlock(lock);

	return ret;
}

#include <zephyr/net/net_core.h>

static int tls_data_check(struct tls_context *ctx)
{
	int ret;

	if (!ctx->is_initialized) {
		return -ENOTCONN;
	}

	ctx->flags = ZSOCK_MSG_DONTWAIT;

#if defined(CONFIG_WOLFSSL)
	{
		byte dummy[1];

		/* wolfSSL_peek() returns 0 for a clean close and keeps the reason in ssl->error */
		ret = wolfSSL_peek(ctx->active_session->wssl, dummy, sizeof(dummy));
		wc_ForceZero(dummy, sizeof(dummy));
		if (ret <= 0) {
			int err = wolfSSL_get_error(ctx->active_session->wssl, ret);

			if (err == SOCKET_PEER_CLOSED_E ||
			    err == WOLFSSL_ERROR_ZERO_RETURN) {
				/* Don't reset the session for STREAM socket -
				 * the application needs to reopen the socket
				 * anyway, and resetting the session would
				 * result in an error instead of 0 in a
				 * consecutive recv() call.
				 */
				ctx->active_session->session_closed = true;

				return -ENOTCONN;
			}

			if (wolfSSL_want_read(ctx->active_session->wssl) ||
			    wolfSSL_want_write(ctx->active_session->wssl)) {
				return 0;
			}

			NET_ERR("%s data check error: %d", "TLS", err);

			if (tls_wolfssl_reset_session(ctx) != 0) {
				return -ENOMEM;
			}

			return -ECONNABORTED;
		}
	}

	return wolfSSL_pending(ctx->active_session->wssl);
#else
	ret = mbedtls_ssl_read(&ctx->active_session->ssl, NULL, 0);
	if (ret < 0) {
		if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
			/* Don't reset the context for STREAM socket - the
			 * application needs to reopen the socket anyway, and
			 * resetting the context would result in an error instead
			 * of 0 in a consecutive recv() call.
			 */
			ctx->active_session->session_closed = true;

			return -ENOTCONN;
		}

		if (ret == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) {
			tls_session_store_current(ctx);
			return 0;
		}

		if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
		    ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
			return 0;
		}

		NET_ERR("%s data check error: -%x", "TLS", -ret);

		/* MbedTLS API documentation requires session to
		 * be reset in other error cases
		 */
		if (tls_mbedtls_reset_session(ctx) != 0) {
			return -ENOMEM;
		}

		return -ECONNABORTED;
	}

	return mbedtls_ssl_get_bytes_avail(&ctx->active_session->ssl);
#endif /* CONFIG_WOLFSSL */
}

static int tls_update_pollin(int fd, struct tls_context *ctx,
			     struct zsock_pollfd *pfd)
{
	int ret;

	if (!ctx->is_listening) {
		/* Already had TLS data to read on socket. */
#if defined(CONFIG_WOLFSSL)
		if (ctx->active_session->wssl != NULL &&
		    wolfSSL_pending(ctx->active_session->wssl) > 0) {
			pfd->revents |= ZSOCK_POLLIN;
			goto next;
		}
#else
		if (mbedtls_ssl_get_bytes_avail(&ctx->active_session->ssl) > 0) {
			pfd->revents |= ZSOCK_POLLIN;
			goto next;
		}
#endif /* CONFIG_WOLFSSL */
	}

	if ((pfd->revents & ZSOCK_POLLIN) == 0) {
		/* No new data on a socket. A poll prepare probe may still have
		 * left a closed session or a fatal error behind, which the
		 * underlying socket will never report.
		 */
		if (!ctx->is_listening) {
			if (ctx->active_session->session_closed) {
				pfd->revents |= ZSOCK_POLLHUP;
			} else if (ctx->error != 0) {
				pfd->revents |= ZSOCK_POLLERR;
			}
		}

		goto next;
	}

	if (ctx->is_listening) {
		goto next;
	}

	ret = tls_data_check(ctx);
	if (ret == -ENOTCONN || (pfd->revents & ZSOCK_POLLHUP)) {
		pfd->revents |= ZSOCK_POLLHUP;
		goto next;
	} else if (ret < 0) {
		ctx->error = -ret;
		pfd->revents |= ZSOCK_POLLERR;
		goto next;
	} else if (ret == 0) {
		goto again;
	}

next:
	return 0;

again:
	/* Received encrypted data, but still not enough
	 * to decrypt it and return data through socket,
	 * ask for retry if no other events are set.
	 */
	pfd->revents &= ~ZSOCK_POLLIN;

	return -EAGAIN;
}

#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
#if defined(CONFIG_WOLFSSL)
static int dtls_data_check(struct tls_context *ctx)
{
	bool is_server = ctx->options.role == ZTLS_IS_SERVER;
	int ret;

	if (!ctx->is_initialized) {
		ret = tls_wolfssl_init(ctx, is_server);
		if (ret < 0) {
			return -ENOMEM;
		}
	}

again:
	if (is_server && dtls_server_check_expired_sessions(ctx)) {
		return -ENOTCONN;
	}

	if (!is_handshake_complete(ctx->active_session)) {
		ret = tls_wolfssl_handshake(ctx, K_NO_WAIT);
		if (ret < 0) {
			if (ret == -EAGAIN) {
				if (is_server) {
					ret = dtls_server_switch_session_on_rx(ctx);
					if (ret == 0) {
						goto again;
					}
				}

				return 0;
			}

			if (is_server) {
				ret = dtls_server_free_active_session(ctx);
			} else {
				ret = tls_wolfssl_reset_session(ctx);
			}

			if (ret != 0) {
				return -ENOMEM;
			}

			return 0;
		}

		/* Socket ready to use again. */
		ctx->error = 0;

		return 0;
	}

	ctx->flags = ZSOCK_MSG_DONTWAIT;

	{
		byte dummy[1];

		ret = wolfSSL_peek(ctx->active_session->wssl, dummy, sizeof(dummy));
		wc_ForceZero(dummy, sizeof(dummy));
	}
	/* UDP has no FIN, so a close_notify that wolfSSL_peek() misses would leak the session */
	if (ret <= 0) {
		int err = wolfSSL_get_error(ctx->active_session->wssl, ret);

		if (err == SOCKET_PEER_CLOSED_E ||
		    err == WOLFSSL_ERROR_ZERO_RETURN) {
			/* Peer closed the session, free/reset so a new client
			 * can connect.
			 */
			if (is_server) {
				ret = dtls_server_free_active_session(ctx);
			} else {
				ret = tls_wolfssl_reset_session(ctx);
			}

			if (ret != 0) {
				return -ENOMEM;
			}

			return -ENOTCONN;
		}

		if (wolfSSL_want_read(ctx->active_session->wssl) ||
		    wolfSSL_want_write(ctx->active_session->wssl)) {
			if (is_server) {
				ret = dtls_server_switch_session_on_rx(ctx);
				if (ret == 0) {
					goto again;
				}

				if (dtls_server_check_expired_sessions(ctx)) {
					return -ENOTCONN;
				}
			}

			return 0;
		}

		NET_ERR("TLS data check error: %d", err);

		if (is_server) {
			if (dtls_server_free_active_session(ctx) != 0) {
				return -ENOMEM;
			}
		} else {
			if (tls_wolfssl_reset_session(ctx) != 0) {
				return -ENOMEM;
			}
		}

		return -ECONNABORTED;
	}

	return wolfSSL_pending(ctx->active_session->wssl);
}
#else /* CONFIG_WOLFSSL */
static int dtls_data_check(struct tls_context *ctx)
{
	bool is_server = ctx->options.role == MBEDTLS_SSL_IS_SERVER;
	int ret;

	if (!ctx->is_initialized) {
		ret = tls_mbedtls_init(ctx, is_server);
		if (ret < 0) {
			return -ENOMEM;
		}
	}

again:
	if (is_server && dtls_server_check_expired_sessions(ctx)) {
		return -ENOTCONN;
	}

	if (!is_handshake_complete(ctx->active_session)) {
		ret = tls_mbedtls_handshake(ctx, K_NO_WAIT);
		if (ret < 0) {
			if (ret == -EAGAIN) {
				if (is_server) {
					ret = dtls_server_switch_session_on_rx(ctx);
					if (ret == 0) {
						goto again;
					}
				}

				return 0;
			}

			if (is_server) {
				ret = dtls_server_free_active_session(ctx);
			} else {
				ret = tls_mbedtls_reset_session(ctx);
			}

			if (ret != 0) {
				return -ENOMEM;
			}

			return 0;
		}

		/* Socket ready to use again. */
		ctx->error = 0;

		return 0;
	}

	ctx->flags = ZSOCK_MSG_DONTWAIT;

	ret = mbedtls_ssl_read(&ctx->active_session->ssl, NULL, 0);
	if (ret < 0) {
		if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
			/* Don't reset the context for STREAM socket - the
			 * application needs to reopen the socket anyway, and
			 * resetting the context would result in an error instead
			 * of 0 in a consecutive recv() call.
			 */

			if (is_server) {
				ret = dtls_server_free_active_session(ctx);
			} else {
				ret = tls_mbedtls_reset_session(ctx);
			}

			if (ret != 0) {
				return -ENOMEM;
			}

			return -ENOTCONN;
		}

		if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
		    ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
			if (is_server) {
				ret = dtls_server_switch_session_on_rx(ctx);
				if (ret == 0) {
					goto again;
				}

				if (dtls_server_check_expired_sessions(ctx)) {
					return -ENOTCONN;
				}
			}

			return 0;
		}

		NET_ERR("TLS data check error: -%x", -ret);

		if (ret == MBEDTLS_ERR_SSL_TIMEOUT) {
			/* Send close notification before session is released. */
			(void)mbedtls_ssl_close_notify(&ctx->active_session->ssl);
		}

		/* MbedTLS API documentation requires session to
		 * be reset in other error cases
		 */
		if (is_server) {
			if (dtls_server_free_active_session(ctx) != 0) {
				return -ENOMEM;
			}
		} else {
			if (tls_mbedtls_reset_session(ctx) != 0) {
				return -ENOMEM;
			}
		}

		if (ret == MBEDTLS_ERR_SSL_TIMEOUT) {
			/* DTLS timeout interpreted as closing of connection. */
			return -ENOTCONN;
		}

		return -ECONNABORTED;
	}

	return mbedtls_ssl_get_bytes_avail(&ctx->active_session->ssl);
}
#endif /* CONFIG_WOLFSSL */

static int dtls_update_pollin(int fd, struct tls_context *ctx,
			      struct zsock_pollfd *pfd)
{
	int ret;

	/* Already had DTLS data to read on socket. */
#if defined(CONFIG_WOLFSSL)
	if (ctx->active_session->wssl != NULL &&
	    wolfSSL_pending(ctx->active_session->wssl) > 0) {
		pfd->revents |= ZSOCK_POLLIN;
		goto next;
	}
#else
	if (mbedtls_ssl_get_bytes_avail(&ctx->active_session->ssl) > 0) {
		pfd->revents |= ZSOCK_POLLIN;
		goto next;
	}
#endif /* CONFIG_WOLFSSL */

	/* Perform data check without incoming data for completed DTLS connections.
	 * This allows the connections to timeout with CONFIG_NET_SOCKETS_DTLS_TIMEOUT.
	 */
	if (!is_handshake_complete(ctx->active_session) && (pfd->revents & ZSOCK_POLLIN) == 0) {
		goto next;
	}

	ret = dtls_data_check(ctx);
	if (ret == -ENOTCONN || (pfd->revents & ZSOCK_POLLHUP)) {
		/* Datagram does not return 0 on consecutive recv, but an error
		 * code, hence clear POLLIN.
		 */
		pfd->revents &= ~ZSOCK_POLLIN;
		pfd->revents |= ZSOCK_POLLHUP;
		goto next;
	} else if (ret < 0) {
		ctx->error = -ret;
		pfd->revents &= ~ZSOCK_POLLIN;
		pfd->revents |= ZSOCK_POLLERR;
		goto next;
	} else if (ret == 0) {
		goto again;
	}

next:
	return 0;

again:
	/* Received encrypted data, but still not enough
	 * to decrypt it and return data through socket,
	 * ask for retry if no other events are set.
	 */
	pfd->revents &= ~ZSOCK_POLLIN;

	return -EAGAIN;
}
#endif /* CONFIG_NET_SOCKETS_ENABLE_DTLS */

static int ztls_poll_update_pollin(int fd, struct tls_context *ctx,
				   struct zsock_pollfd *pfd)
{
#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
	if (ctx->type == NET_SOCK_DGRAM) {
		return dtls_update_pollin(fd, ctx, pfd);
	}
#endif

	return tls_update_pollin(fd, ctx, pfd);
}

static int ztls_poll_update_ctx(struct tls_context *ctx,
				struct zsock_pollfd *pfd,
				struct k_poll_event **pev)
{
	const struct fd_op_vtable *vtable;
	struct k_mutex *lock;
	void *obj;
	int ret;
	short events = pfd->events;

	obj = zvfs_get_fd_obj_and_vtable(
		ctx->sock, (const struct fd_op_vtable **)&vtable, &lock);
	if (obj == NULL) {
		return -EBADF;
	}

	(void)k_mutex_lock(lock, K_FOREVER);

	/* Check if the socket was waiting for the handshake to complete. */
	if ((pfd->events & ZSOCK_POLLIN) &&
	    ((*pev)->obj == &ctx->active_session->tls_established)) {
		/* In case handshake is complete, reconfigure the k_poll_event
		 * to monitor the underlying socket now.
		 */
		if ((*pev)->state != K_POLL_STATE_NOT_READY) {
			ret = zvfs_fdtable_call_ioctl(vtable, obj,
						   ZFD_IOCTL_POLL_PREPARE,
						   pfd, pev, *pev + 1);
			if (ret != 0 && ret != -EALREADY) {
				goto out;
			}

			/* Return -EAGAIN to signal to poll() that it should
			 * make another iteration with the event reconfigured
			 * above (if needed).
			 */
			ret = -EAGAIN;
			goto out;
		}

		/* Handshake still not ready - skip ZSOCK_POLLIN verification
		 * for the underlying socket.
		 */
		(*pev)++;
		pfd->events &= ~ZSOCK_POLLIN;
	}

	ret = zvfs_fdtable_call_ioctl(vtable, obj, ZFD_IOCTL_POLL_UPDATE,
				   pfd, pev);
	if (ret != 0) {
		goto exit;
	}

	if (pfd->events & ZSOCK_POLLIN) {
		ret = ztls_poll_update_pollin(pfd->fd, ctx, pfd);
		if (ret == -EAGAIN && pfd->revents == 0) {
			(*pev - 1)->state = K_POLL_STATE_NOT_READY;
			goto exit;
		} else {
			ret = 0;
		}
	}
exit:
	/* Restore original events. */
	pfd->events = events;

out:
	k_mutex_unlock(lock);

	return ret;
}

/* Return true if needed to retry rightoff or false otherwise. */
static bool poll_offload_dtls_client_retry(struct tls_context *ctx,
					   struct zsock_pollfd *pfd)
{
	/* DTLS client should wait for the handshake to complete before it
	 * reports that data is ready.
	 */
	if ((ctx->type != NET_SOCK_DGRAM) ||
	    (ctx->options.role != ZTLS_IS_CLIENT)) {
		return false;
	}

	if (ctx->active_session->handshake_in_progress) {
		/* Add some sleep to allow lower priority threads to proceed
		 * with handshake.
		 */
		k_msleep(10);

		pfd->revents &= ~ZSOCK_POLLIN;
		return true;
	} else if (!is_handshake_complete(ctx->active_session)) {
		uint8_t b;
		int ret;

		/* Handshake didn't start yet - just drop the incoming data -
		 * it's the client who should initiate the handshake.
		 */
		ret = zsock_recv(ctx->sock, &b, sizeof(b),
				 ZSOCK_MSG_DONTWAIT);
		if (ret < 0) {
			pfd->revents |= ZSOCK_POLLERR;
		}

		pfd->revents &= ~ZSOCK_POLLIN;
		return true;
	}

	/* Handshake complete, just proceed. */
	return false;
}

static int ztls_poll_offload(struct zsock_pollfd *fds, int nfds, int timeout)
{
	int fd_backup[CONFIG_ZVFS_POLL_MAX];
	const struct fd_op_vtable *vtable;
	void *ctx;
	int ret = 0;
	int result;
	int i;
	bool retry;
	int remaining;
	uint32_t entry = k_uptime_get_32();

	/* Overwrite TLS file descriptors with underlying ones. */
	for (i = 0; i < nfds; i++) {
		fd_backup[i] = fds[i].fd;

		ctx = zvfs_get_fd_obj(fds[i].fd,
				   (const struct fd_op_vtable *)
						     &tls_sock_fd_op_vtable,
				   0);
		if (ctx == NULL) {
			continue;
		}

		if (fds[i].events & ZSOCK_POLLIN) {
			ret = ztls_poll_prepare_pollin(ctx);
			/* In case data is already available in mbedtls,
			 * do not wait in poll.
			 */
			if (ret == -EALREADY) {
				timeout = 0;
			}
		}

		fds[i].fd = ((struct tls_context *)ctx)->sock;
	}

	/* Get offloaded sockets vtable. */
	ctx = zvfs_get_fd_obj_and_vtable(fds[0].fd,
				      (const struct fd_op_vtable **)&vtable,
				      NULL);
	if (ctx == NULL) {
		errno = EINVAL;
		goto exit;
	}

	remaining = timeout;

	do {
		for (i = 0; i < nfds; i++) {
			fds[i].revents = 0;
		}

		ret = zvfs_fdtable_call_ioctl(vtable, ctx, ZFD_IOCTL_POLL_OFFLOAD,
					   fds, nfds, remaining);
		if (ret < 0) {
			goto exit;
		}

		retry = false;
		ret = 0;

		for (i = 0; i < nfds; i++) {
			ctx = zvfs_get_fd_obj(fd_backup[i],
					   (const struct fd_op_vtable *)
							&tls_sock_fd_op_vtable,
					   0);
			if (ctx != NULL) {
				if (fds[i].events & ZSOCK_POLLIN) {
					if (poll_offload_dtls_client_retry(
							ctx, &fds[i])) {
						retry = true;
						continue;
					}

					result = ztls_poll_update_pollin(
						    fd_backup[i], ctx, &fds[i]);
					if (result == -EAGAIN) {
						retry = true;
					}
				}
			}

			if (fds[i].revents != 0) {
				ret++;
			}
		}

		if (retry) {
			if (ret > 0 || timeout == 0) {
				goto exit;
			}

			if (timeout > 0) {
				remaining = time_left(entry, timeout);
				if (remaining <= 0) {
					goto exit;
				}
			}
		}
	} while (retry);

exit:
	/* Restore original fds. */
	for (i = 0; i < nfds; i++) {
		fds[i].fd = fd_backup[i];
	}

	return ret;
}

int ztls_getsockopt_ctx(struct tls_context *ctx, int level, int optname,
			void *optval, net_socklen_t *optlen)
{
	int err;

	if (!optval || !optlen) {
		errno = EINVAL;
		return -1;
	}

	if ((level == ZSOCK_SOL_SOCKET) && (optname == ZSOCK_SO_PROTOCOL)) {
		/* Protocol type is overridden during socket creation. Its
		 * value is restored here to return current value.
		 */
		err = sock_opt_protocol_get(ctx, optval, optlen);
		if (err < 0) {
			errno = -err;
			return -1;
		}
		return err;
	}

	/* In case error was set on a socket at the TLS layer (for example due
	 * to receiving TLS alert), handle SO_ERROR here, and report that error.
	 * Otherwise, forward the SO_ERROR option request to the underlying
	 * TCP/UDP socket to handle.
	 */
	if ((level == ZSOCK_SOL_SOCKET) && (optname == ZSOCK_SO_ERROR) && ctx->error != 0) {
		if (*optlen != sizeof(int)) {
			errno = EINVAL;
			return -1;
		}

		*(int *)optval = ctx->error;

		return 0;
	}

	if (level != ZSOCK_SOL_TLS) {
		return zsock_getsockopt(ctx->sock, level, optname,
					optval, optlen);
	}

	switch (optname) {
	case ZSOCK_TLS_SEC_TAG_LIST:
		err =  tls_opt_sec_tag_list_get(ctx, optval, optlen);
		break;

	case ZSOCK_TLS_CIPHERSUITE_LIST:
		err = tls_opt_ciphersuite_list_get(ctx, optval, optlen);
		break;

	case ZSOCK_TLS_CIPHERSUITE_USED:
		err = tls_opt_ciphersuite_used_get(ctx, optval, optlen);
		break;

	case ZSOCK_TLS_ALPN_LIST:
		err = tls_opt_alpn_list_get(ctx, optval, optlen);
		break;

	case ZSOCK_TLS_SESSION_CACHE:
		err = tls_opt_session_cache_get(ctx, optval, optlen);
		break;

	case ZSOCK_TLS_CERT_VERIFY_RESULT:
		err = tls_opt_cert_verify_result_get(ctx, optval, optlen);
		break;

#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
	case ZSOCK_TLS_DTLS_HANDSHAKE_TIMEOUT_MIN:
		err = tls_opt_dtls_handshake_timeout_get(ctx, optval,
							 optlen, false);
		break;

	case ZSOCK_TLS_DTLS_HANDSHAKE_TIMEOUT_MAX:
		err = tls_opt_dtls_handshake_timeout_get(ctx, optval,
							 optlen, true);
		break;

	case ZSOCK_TLS_DTLS_CID_STATUS:
		err = tls_opt_dtls_connection_id_status_get(ctx, optval,
							    optlen);
		break;

	case ZSOCK_TLS_DTLS_CID_VALUE:
		err = tls_opt_dtls_connection_id_value_get(ctx, optval, optlen);
		break;

	case ZSOCK_TLS_DTLS_PEER_CID_VALUE:
		err = tls_opt_dtls_peer_connection_id_value_get(ctx, optval,
								optlen);
		break;

	case ZSOCK_TLS_DTLS_HANDSHAKE_ON_CONNECT:
		err = tls_opt_dtls_handshake_on_connect_get(ctx, optval, optlen);
		break;
#endif /* CONFIG_NET_SOCKETS_ENABLE_DTLS */

	default:
		/* Unknown or write-only option. */
		err = -ENOPROTOOPT;
		break;
	}

	if (err < 0) {
		errno = -err;
		return -1;
	}

	return 0;
}

static int set_timeout_opt(k_timeout_t *timeout, const void *optval,
			   net_socklen_t optlen)
{
	const struct zsock_timeval *tval = optval;

	if (optlen != sizeof(struct zsock_timeval)) {
		return -EINVAL;
	}

	if (tval->tv_sec == 0 && tval->tv_usec == 0) {
		*timeout = K_FOREVER;
	} else {
		*timeout = K_USEC(tval->tv_sec * 1000000ULL + tval->tv_usec);
	}

	return 0;
}

int ztls_setsockopt_ctx(struct tls_context *ctx, int level, int optname,
			const void *optval, net_socklen_t optlen)
{
	int err;

	/* Underlying socket is used in non-blocking mode, hence implement
	 * timeout at the TLS socket level.
	 */
	if ((level == ZSOCK_SOL_SOCKET) && (optname == ZSOCK_SO_SNDTIMEO)) {
		err = set_timeout_opt(&ctx->options.timeout_tx, optval, optlen);
		goto out;
	}

	if ((level == ZSOCK_SOL_SOCKET) && (optname == ZSOCK_SO_RCVTIMEO)) {
		err = set_timeout_opt(&ctx->options.timeout_rx, optval, optlen);
		goto out;
	}

	if (level != ZSOCK_SOL_TLS) {
		return zsock_setsockopt(ctx->sock, level, optname,
					optval, optlen);
	}

	switch (optname) {
	case ZSOCK_TLS_SEC_TAG_LIST:
		err =  tls_opt_sec_tag_list_set(ctx, optval, optlen);
		break;

	case ZSOCK_TLS_HOSTNAME:
		err = tls_opt_hostname_set(ctx, optval, optlen);
		break;

	case ZSOCK_TLS_CIPHERSUITE_LIST:
		err = tls_opt_ciphersuite_list_set(ctx, optval, optlen);
		break;

	case ZSOCK_TLS_PEER_VERIFY:
		err = tls_opt_peer_verify_set(ctx, optval, optlen);
		break;

	case ZSOCK_TLS_CERT_NOCOPY:
		err = tls_opt_cert_nocopy_set(ctx, optval, optlen);
		break;

	case ZSOCK_TLS_DTLS_ROLE:
		err = tls_opt_dtls_role_set(ctx, optval, optlen);
		break;

	case ZSOCK_TLS_ALPN_LIST:
		err = tls_opt_alpn_list_set(ctx, optval, optlen);
		break;

	case ZSOCK_TLS_SESSION_CACHE:
		err = tls_opt_session_cache_set(ctx, optval, optlen);
		break;

	case ZSOCK_TLS_SESSION_CACHE_PURGE:
		err = tls_opt_session_cache_purge_set(ctx, optval, optlen);
		break;

	case ZSOCK_TLS_CERT_VERIFY_CALLBACK:
		err = tls_opt_cert_verify_callback_set(ctx, optval, optlen);
		break;

#if defined(CONFIG_WOLFSSL)
	case ZSOCK_TLS_CERT_VERIFY_CALLBACK_WOLFSSL:
		err = tls_opt_cert_verify_callback_wolfssl_set(ctx, optval, optlen);
		break;
#endif /* CONFIG_WOLFSSL */

#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
	case ZSOCK_TLS_DTLS_HANDSHAKE_TIMEOUT_MIN:
		err = tls_opt_dtls_handshake_timeout_set(ctx, optval,
							 optlen, false);
		break;

	case ZSOCK_TLS_DTLS_HANDSHAKE_TIMEOUT_MAX:
		err = tls_opt_dtls_handshake_timeout_set(ctx, optval,
							 optlen, true);
		break;

	case ZSOCK_TLS_DTLS_CID:
		err = tls_opt_dtls_connection_id_set(ctx, optval, optlen);
		break;

	case ZSOCK_TLS_DTLS_CID_VALUE:
		err = tls_opt_dtls_connection_id_value_set(ctx, optval, optlen);
		break;

	case ZSOCK_TLS_DTLS_HANDSHAKE_ON_CONNECT:
		err = tls_opt_dtls_handshake_on_connect_set(ctx, optval, optlen);
		break;

#endif /* CONFIG_NET_SOCKETS_ENABLE_DTLS */

	case ZSOCK_TLS_NATIVE:
		/* Option handled at the socket dispatcher level. */
		err = 0;
		break;

#if defined(CONFIG_NET_SOCKETS_TLS_SET_MAX_FRAGMENT_LENGTH) && \
	(!defined(CONFIG_WOLFSSL) || defined(ZTLS_WOLFSSL_MAX_FRAGMENT))
	case ZSOCK_TLS_MAX_FRAGMENT_LENGTH:
		err = tls_opt_mfl_set(ctx, optval, optlen);
		break;
#endif

	default:
		/* Unknown or read-only option. */
		err = -ENOPROTOOPT;
		break;
	}

out:
	if (err < 0) {
		errno = -err;
		return -1;
	}

	return 0;
}

#if defined(CONFIG_NET_TEST)
#if defined(CONFIG_WOLFSSL)
WOLFSSL *ztls_get_wolfssl_context(int fd)
{
	struct tls_context *ctx;

	ctx = zvfs_get_fd_obj(fd, (const struct fd_op_vtable *)
					&tls_sock_fd_op_vtable, EBADF);
	if (ctx == NULL) {
		return NULL;
	}

	return ctx->active_session->wssl;
}
#elif defined(CONFIG_MBEDTLS)
mbedtls_ssl_context *ztls_get_mbedtls_ssl_context(int fd)
{
	struct tls_context *ctx;

	ctx = zvfs_get_fd_obj(fd, (const struct fd_op_vtable *)
					&tls_sock_fd_op_vtable, EBADF);
	if (ctx == NULL) {
		return NULL;
	}

	return &ctx->active_session->ssl;
}
#endif /* CONFIG_WOLFSSL */

#if defined(CONFIG_MBEDTLS)
int ztls_get_cached_session(int fd, mbedtls_ssl_session *session)
{
	struct net_sockaddr_storage peer_addr = { 0 };
	struct tls_context *ctx;
	net_socklen_t peer_addrlen = sizeof(peer_addr);
	int ret;

	ctx = zvfs_get_fd_obj(fd, (const struct fd_op_vtable *)&tls_sock_fd_op_vtable,
			      EBADF);
	if (ctx == NULL) {
		return -EBADF;
	}

	ret = zsock_getpeername(ctx->sock, net_sad(&peer_addr), &peer_addrlen);
	if (ret < 0) {
		return -errno;
	}

	return tls_session_get(net_sad(&peer_addr), session);
}
#endif /* CONFIG_MBEDTLS */

uint32_t ztls_get_session_count(void)
{
	return k_mem_slab_num_used_get(&tls_session_contexts);
}

#endif /* CONFIG_NET_TEST */

static ssize_t tls_sock_read_vmeth(void *obj, void *buffer, size_t count)
{
	return ztls_recvfrom_ctx(obj, buffer, count, 0, NULL, 0);
}

static ssize_t tls_sock_write_vmeth(void *obj, const void *buffer,
				    size_t count)
{
	return ztls_sendto_ctx(obj, buffer, count, 0, NULL, 0);
}

static int tls_sock_ioctl_vmeth(void *obj, unsigned int request, va_list args)
{
	struct tls_context *ctx = obj;

	switch (request) {
	/* fcntl() commands */
	case ZVFS_F_GETFL:
	case ZVFS_F_SETFL: {
		const struct fd_op_vtable *vtable;
		struct k_mutex *lock;
		void *fd_obj;
		int ret;

		fd_obj = zvfs_get_fd_obj_and_vtable(ctx->sock,
				(const struct fd_op_vtable **)&vtable, &lock);
		if (fd_obj == NULL) {
			errno = EBADF;
			return -1;
		}

		(void)k_mutex_lock(lock, K_FOREVER);

		/* Pass the call to the core socket implementation. */
		ret = vtable->ioctl(fd_obj, request, args);

		k_mutex_unlock(lock);

		return ret;
	}

	case ZFD_IOCTL_SET_LOCK: {
		struct k_mutex *lock;

		lock = va_arg(args, struct k_mutex *);

		ctx_set_lock(obj, lock);

		return 0;
	}

	case ZFD_IOCTL_POLL_PREPARE: {
		struct zsock_pollfd *pfd;
		struct k_poll_event **pev;
		struct k_poll_event *pev_end;

		pfd = va_arg(args, struct zsock_pollfd *);
		pev = va_arg(args, struct k_poll_event **);
		pev_end = va_arg(args, struct k_poll_event *);

		return ztls_poll_prepare_ctx(obj, pfd, pev, pev_end);
	}

	case ZFD_IOCTL_POLL_UPDATE: {
		struct zsock_pollfd *pfd;
		struct k_poll_event **pev;

		pfd = va_arg(args, struct zsock_pollfd *);
		pev = va_arg(args, struct k_poll_event **);

		return ztls_poll_update_ctx(obj, pfd, pev);
	}

	case ZFD_IOCTL_POLL_OFFLOAD: {
		struct zsock_pollfd *fds;
		int nfds;
		int timeout;

		fds = va_arg(args, struct zsock_pollfd *);
		nfds = va_arg(args, int);
		timeout = va_arg(args, int);

		return ztls_poll_offload(fds, nfds, timeout);
	}

	default:
		errno = EOPNOTSUPP;
		return -1;
	}
}

static int tls_sock_shutdown_vmeth(void *obj, int how)
{
	struct tls_context *ctx = obj;
	int ret;

	ret = zsock_shutdown(ctx->sock, how);
#if defined(CONFIG_WOLFSSL)
	/* Only a successful shutdown closes the read side; mbedTLS does not read recv_eof */
	if (ret == 0 && (how == ZSOCK_SHUT_RD || how == ZSOCK_SHUT_RDWR)) {
		ctx->recv_eof = true;
	}
#endif

	return ret;
}

static int tls_sock_bind_vmeth(void *obj, const struct net_sockaddr *addr,
			       net_socklen_t addrlen)
{
	struct tls_context *ctx = obj;

	return zsock_bind(ctx->sock, addr, addrlen);
}

static int tls_sock_connect_vmeth(void *obj, const struct net_sockaddr *addr,
				  net_socklen_t addrlen)
{
	return ztls_connect_ctx(obj, addr, addrlen);
}

static int tls_sock_listen_vmeth(void *obj, int backlog)
{
	struct tls_context *ctx = obj;

	ctx->is_listening = true;

	return zsock_listen(ctx->sock, backlog);
}

static int tls_sock_accept_vmeth(void *obj, struct net_sockaddr *addr,
				 net_socklen_t *addrlen)
{
	return ztls_accept_ctx(obj, addr, addrlen);
}

static ssize_t tls_sock_sendto_vmeth(void *obj, const void *buf, size_t len,
				     int flags,
				     const struct net_sockaddr *dest_addr,
				     net_socklen_t addrlen)
{
	return ztls_sendto_ctx(obj, buf, len, flags, dest_addr, addrlen);
}

static ssize_t tls_sock_sendmsg_vmeth(void *obj, const struct net_msghdr *msg,
				      int flags)
{
	return ztls_sendmsg_ctx(obj, msg, flags);
}

static ssize_t tls_sock_recvfrom_vmeth(void *obj, void *buf, size_t max_len,
				       int flags, struct net_sockaddr *src_addr,
				       net_socklen_t *addrlen)
{
	return ztls_recvfrom_ctx(obj, buf, max_len, flags,
				 src_addr, addrlen);
}

static int tls_sock_getsockopt_vmeth(void *obj, int level, int optname,
				     void *optval, net_socklen_t *optlen)
{
	return ztls_getsockopt_ctx(obj, level, optname, optval, optlen);
}

static int tls_sock_setsockopt_vmeth(void *obj, int level, int optname,
				     const void *optval, net_socklen_t optlen)
{
	return ztls_setsockopt_ctx(obj, level, optname, optval, optlen);
}

static int tls_sock_close2_vmeth(void *obj, int sock)
{
	return ztls_close_ctx(obj, sock);
}

static int tls_sock_getpeername_vmeth(void *obj, struct net_sockaddr *addr,
				      net_socklen_t *addrlen)
{
	struct tls_context *ctx = obj;

	return zsock_getpeername(ctx->sock, addr, addrlen);
}

static int tls_sock_getsockname_vmeth(void *obj, struct net_sockaddr *addr,
				      net_socklen_t *addrlen)
{
	struct tls_context *ctx = obj;

	return zsock_getsockname(ctx->sock, addr, addrlen);
}

static const struct socket_op_vtable tls_sock_fd_op_vtable = {
	.fd_vtable = {
		.read = tls_sock_read_vmeth,
		.write = tls_sock_write_vmeth,
		.close2 = tls_sock_close2_vmeth,
		.ioctl = tls_sock_ioctl_vmeth,
	},
	.shutdown = tls_sock_shutdown_vmeth,
	.bind = tls_sock_bind_vmeth,
	.connect = tls_sock_connect_vmeth,
	.listen = tls_sock_listen_vmeth,
	.accept = tls_sock_accept_vmeth,
	.sendto = tls_sock_sendto_vmeth,
	.sendmsg = tls_sock_sendmsg_vmeth,
	.recvfrom = tls_sock_recvfrom_vmeth,
	.getsockopt = tls_sock_getsockopt_vmeth,
	.setsockopt = tls_sock_setsockopt_vmeth,
	.getpeername = tls_sock_getpeername_vmeth,
	.getsockname = tls_sock_getsockname_vmeth,
};

static bool tls_is_supported(int family, int type, int proto)
{
	if (protocol_check(family, type, &proto) == 0) {
		return true;
	}

	return false;
}

/* Since both, TLS sockets and regular ones fall under the same address family,
 * it's required to process TLS first in order to capture socket calls which
 * create sockets for secure protocols. Every other call for NET_AF_INET/NET_AF_INET6
 * will be forwarded to regular socket implementation.
 */
BUILD_ASSERT(CONFIG_NET_SOCKETS_TLS_PRIORITY < CONFIG_NET_SOCKETS_PRIORITY_DEFAULT,
	     "CONFIG_NET_SOCKETS_TLS_PRIORITY have to be smaller than CONFIG_NET_SOCKETS_PRIORITY_DEFAULT");

NET_SOCKET_REGISTER(tls, CONFIG_NET_SOCKETS_TLS_PRIORITY, NET_AF_UNSPEC,
		    tls_is_supported, ztls_socket);
