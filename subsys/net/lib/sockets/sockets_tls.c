/*
 * Copyright (c) 2018 Intel Corporation
 * Copyright (c) 2018 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdbool.h>
#include <zephyr/posix/fcntl.h>

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(net_sock_tls, CONFIG_NET_SOCKETS_LOG_LEVEL);

#include <zephyr/init.h>
#include <zephyr/sys/util.h>
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
#if !defined(CONFIG_MBEDTLS_CFG_FILE)
#include "mbedtls/config.h"
#else
#include CONFIG_MBEDTLS_CFG_FILE
#endif /* CONFIG_MBEDTLS_CFG_FILE */

#include <mbedtls/net_sockets.h>
#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/ssl.h>
#include <mbedtls/ssl_cookie.h>
#include <mbedtls/error.h>
#include <mbedtls/platform.h>
#include <mbedtls/ssl_cache.h>

#define ZTLS_IS_CLIENT        MBEDTLS_SSL_IS_CLIENT
#define ZTLS_IS_SERVER        MBEDTLS_SSL_IS_SERVER
#define ZTLS_ERROR_WANT_READ  MBEDTLS_ERR_SSL_WANT_READ
#define ZTLS_ERROR_WANT_WRITE MBEDTLS_ERR_SSL_WANT_WRITE
#define tls_backend_init      tls_mbedtls_init
#define tls_backend_handshake tls_mbedtls_handshake
#define tls_backend_reset     tls_mbedtls_reset

#endif /* CONFIG_MBEDTLS */

#include "sockets_internal.h"
#include "tls_internal.h"

#if defined(CONFIG_MBEDTLS_DEBUG)
#include <zephyr_mbedtls_priv.h>
#endif

#if defined(CONFIG_WOLFSSL) && defined(CONFIG_MBEDTLS)
#error "wolfSSL and mbedTLS TLS-socket backends are mutually exclusive; " \
       "enable exactly one of CONFIG_WOLFSSL / CONFIG_MBEDTLS."
#endif

#if defined(CONFIG_WOLFSSL)
#ifndef WOLFSSL_USER_SETTINGS
#include <user_settings.h>
#endif /* !WOLFSSL_USER_SETTINGS */
#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/memory.h>
#include <zephyr/net/tls_verify.h>

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
/* Set in a cached verify result when a PSK authenticated the session */
#define ZTLS_WOLFSSL_CACHE_PSK BIT(31)
#endif

#if defined(HAVE_MAX_FRAGMENT) && !defined(NO_WOLFSSL_CLIENT) && \
	defined(CONFIG_NET_SOCKETS_TLS_SET_MAX_FRAGMENT_LENGTH)
#define ZTLS_WOLFSSL_MAX_FRAGMENT
#endif

#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS) && defined(WOLFSSL_DTLS_CID)
#define ZTLS_WOLFSSL_DTLS_CID
/* Size of the CID the socket options keep; wolfSSL may allow fewer bytes */
#define ZTLS_WOLFSSL_CID_LEN_MAX 32
#endif

#define ZTLS_IS_CLIENT        0
#define ZTLS_IS_SERVER        1
#define ZTLS_ERROR_WANT_READ  WOLFSSL_ERROR_WANT_READ
#define ZTLS_ERROR_WANT_WRITE WOLFSSL_ERROR_WANT_WRITE
#define tls_backend_init      tls_wolfssl_init
#define tls_backend_handshake tls_wolfssl_handshake
#define tls_backend_reset     tls_wolfssl_reset

/* DTLS retransmission timer range in milliseconds, from RFC 6347 4.2.4.1 */
#define DTLS_TIMEOUT_DFL_MIN    1000
#define DTLS_TIMEOUT_DFL_MAX   60000
#endif /* CONFIG_WOLFSSL */

#if defined(CONFIG_NET_SOCKETS_TLS_MAX_APP_PROTOCOLS)
#define ALPN_MAX_PROTOCOLS (CONFIG_NET_SOCKETS_TLS_MAX_APP_PROTOCOLS + 1)
#else
#define ALPN_MAX_PROTOCOLS 0
#endif /* CONFIG_NET_SOCKETS_TLS_MAX_APP_PROTOCOLS */

#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
#define DTLS_SENDMSG_BUF_SIZE (CONFIG_NET_SOCKETS_DTLS_SENDMSG_BUF_SIZE)
#else
#define DTLS_SENDMSG_BUF_SIZE 0
#endif /* CONFIG_NET_SOCKETS_ENABLE_DTLS */

#if defined(CONFIG_MBEDTLS_SSL_DTLS_CONNECTION_ID)
#define DTLS_CID_OUT_LEN_MAX MBEDTLS_SSL_CID_OUT_LEN_MAX
#define DTLS_CID_IN_LEN_MAX MBEDTLS_SSL_CID_IN_LEN_MAX
#elif defined(ZTLS_WOLFSSL_DTLS_CID)
#define DTLS_CID_OUT_LEN_MAX MIN(wolfSSL_dtls_cid_max_size(), ZTLS_WOLFSSL_CID_LEN_MAX)
#define DTLS_CID_IN_LEN_MAX DTLS_CID_OUT_LEN_MAX
#endif

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

	/** Intermediate delay value. For details, refer to mbedTLS API
	 *  documentation (mbedtls_ssl_set_timer_t).
	 */
	uint32_t int_ms;

	/** Final delay value. For details, refer to mbedTLS API documentation
	 *  (mbedtls_ssl_set_timer_t).
	 */
	uint32_t fin_ms;
};

/** TLS peer address/session ID mapping. */
struct tls_session_cache {
	/** Creation time. */
	int64_t timestamp;

	/** Peer address. */
	struct sockaddr peer_addr;

	/** Session buffer. */
	uint8_t *session;

	/** Session length. */
	size_t session_len;
};

#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS) && \
	(defined(CONFIG_MBEDTLS) || defined(ZTLS_WOLFSSL_DTLS_CID))
struct tls_dtls_cid {
	bool enabled;
#if defined(CONFIG_MBEDTLS)
	unsigned char cid[MAX(MBEDTLS_SSL_CID_OUT_LEN_MAX,
			      MBEDTLS_SSL_CID_IN_LEN_MAX)];
#else
	unsigned char cid[ZTLS_WOLFSSL_CID_LEN_MAX];
#endif
	size_t cid_len;
};
#endif /* CONFIG_NET_SOCKETS_ENABLE_DTLS && (CONFIG_MBEDTLS || ZTLS_WOLFSSL_DTLS_CID) */

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

	/** Information whether TLS handshake is currently in progress. */
	bool handshake_in_progress : 1;

	/** Session ended at the TLS/DTLS level. */
	bool session_closed : 1;

#if defined(CONFIG_WOLFSSL)
	/** The read side was shut down; send() still works. */
	bool recv_eof : 1;

	/* Set when the application chose TLS_DTLS_ROLE; tls_wolfssl_init() derives it otherwise */
	bool role_set : 1;

	/* ctx is a reference to the listening socket's CTX */
	bool ctx_shared : 1;

	/* An option that ctx was built from has changed since */
	bool ctx_stale : 1;

	/* ctx was built for the server role */
	bool ctx_server : 1;

	/* Returned by accept() */
	bool accepted : 1;
#endif /* CONFIG_WOLFSSL */

	/** Socket type. */
	enum net_sock_type type;

	/** Secure protocol version running on TLS context. */
	enum net_ip_protocol_secure tls_version;

	/** Socket flags passed to a socket call. */
	int flags;

	/* Indicates whether socket is in error state at TLS/DTLS level. */
	int error;

	/** Information whether TLS handshake is complete or not. */
	struct k_sem tls_established;

	/* TLS socket mutex lock. */
	struct k_mutex *lock;

	/** TLS specific option values. */
	struct {
		/** Select which credentials to use with TLS. */
		struct sec_tag_list sec_tag_list;

		/** 0-terminated list of allowed ciphersuites (mbedTLS format).
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

#if defined(ZTLS_WOLFSSL_MAX_FRAGMENT)
		/** Per-socket MFL, TLS_MFL_DEFAULT to derive it. */
		int8_t mfl_code;
#endif

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

#if defined(CONFIG_MBEDTLS) || defined(ZTLS_WOLFSSL_DTLS_CID)
		struct tls_dtls_cid dtls_cid;
#endif

		bool dtls_handshake_on_connect;
#endif /* CONFIG_NET_SOCKETS_ENABLE_DTLS */

#if defined(CONFIG_NET_SOCKETS_TLS_CERT_VERIFY_CALLBACK) && \
	!defined(CONFIG_WOLFSSL)
		struct tls_cert_verify_cb cert_verify;
#endif /* CONFIG_NET_SOCKETS_TLS_CERT_VERIFY_CALLBACK && !CONFIG_WOLFSSL */
#if defined(CONFIG_WOLFSSL_VERIFY_CALLBACK)
		struct tls_cert_verify_cb_wolfssl cert_verify_wolfssl;
#endif /* CONFIG_WOLFSSL_VERIFY_CALLBACK */
	} options;

#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
	/** Context information for DTLS timing. */
	struct dtls_timing_context dtls_timing;

#if defined(CONFIG_MBEDTLS)
	/** mbedTLS cookie context for DTLS */
	mbedtls_ssl_cookie_ctx cookie;
#endif

	/** DTLS peer address. */
	struct sockaddr dtls_peer_addr;

	/** DTLS peer address length. */
	socklen_t dtls_peer_addrlen;
#endif /* CONFIG_NET_SOCKETS_ENABLE_DTLS */

#if defined(CONFIG_WOLFSSL)
	/** The wolfSSL context */
	WOLFSSL_CTX *ctx;

	/** The wolfSSL SSL context */
	WOLFSSL *wssl;

	/** The hostname to use as the SNI */
	byte *host_name;

	/* Length in bytes of the host_name */
	word32 host_len;

#if defined(HAVE_ALPN)
	/* TLS_ALPN_LIST as the comma separated list wolfSSL_UseALPN() takes */
	char *alpn_joined;
#endif /* HAVE_ALPN */

	/* credentials_generation() when ctx was built */
	uint32_t ctx_cred_gen;

	/** Accumulated mbedTLS-compatible verify result flags. */
	uint32_t verify_result_flags;

	/* Verify result saved with the session this handshake tries to resume. */
	uint32_t resumed_verify_result;
	bool resumed_psk;

	bool cert_verify_ran;
	bool psk_used;

	/* An accepted chain certificate failed verification; wolfSSL may keep it as a CTX CA */
	bool chain_error_overridden;

	/* A TCP session kept after a fatal error, which sends no close_notify */
	bool failed;

#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
	/* Lets the handshake tell a sent flight from other wakeups */
	uint32_t dtls_tx_count;
	/* Retransmission deadline, kept across handshake calls */
	k_timepoint_t dtls_rtx_end;
	uint32_t dtls_rtx_tx_count;
	bool dtls_rtx_armed;
	/* A server drops its peer when no record arrives from it before this */
	k_timepoint_t dtls_rx_expiry;
#endif

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

#elif defined(CONFIG_MBEDTLS)
	/** mbedTLS context. */
	mbedtls_ssl_context ssl;

	/** mbedTLS configuration. */
	mbedtls_ssl_config config;

#if defined(MBEDTLS_X509_CRT_PARSE_C)
	/** mbedTLS structure for CA chain. */
	mbedtls_x509_crt ca_chain;

	/** mbedTLS structure for own certificate. */
	mbedtls_x509_crt own_cert;

	/** mbedTLS structure for own private key. */
	mbedtls_pk_context priv_key;
#endif /* MBEDTLS_X509_CRT_PARSE_C */

#endif /* CONFIG_MBEDTLS */
};


/* A global pool of TLS contexts. */
static struct tls_context tls_contexts[CONFIG_NET_SOCKETS_TLS_MAX_CONTEXTS];

/* wolfSSL can fill the client cache only through session export. */
#if defined(CONFIG_MBEDTLS) || \
    (defined(CONFIG_WOLFSSL) && defined(ZTLS_WOLFSSL_EXT_CACHE))
#define TLS_SESSION_CACHE_PRESENT 1
#else
#define TLS_SESSION_CACHE_PRESENT 0
#endif

#if TLS_SESSION_CACHE_PRESENT
static struct tls_session_cache client_cache[CONFIG_NET_SOCKETS_TLS_MAX_CLIENT_SESSION_COUNT];

static inline void *tls_session_buf_alloc(size_t len)
{
#if defined(CONFIG_WOLFSSL)
	return XMALLOC(len, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#else
	return mbedtls_calloc(1, len);
#endif
}

static inline void tls_session_buf_free(void *buf, size_t len)
{
#if defined(CONFIG_WOLFSSL)
	wc_ForceZero(buf, len);
	XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#else
	ARG_UNUSED(len);
	mbedtls_free(buf);
#endif
}
#endif

/* A mutex for protecting access to the client session cache. */
static K_MUTEX_DEFINE(session_cache_lock);

#if defined(MBEDTLS_SSL_CACHE_C)
static mbedtls_ssl_cache_context server_cache;
#endif

/* A mutex for protecting TLS context allocation. */
static struct k_mutex context_lock;

/* Arbitrary delay value to wait if mbedTLS reports it cannot proceed for
 * reasons other than TX/RX block.
 */
#define TLS_WAIT_MS 100

static int tls_release(struct tls_context *tls);
#if defined(CONFIG_WOLFSSL)
static int tls_wolfssl_session_init(struct tls_context *context, bool is_server);
static word32 tls_der_chain_len(const byte *der, word32 der_len);
#endif

#if TLS_SESSION_CACHE_PRESENT
static void tls_session_cache_reset(void)
{
	k_mutex_lock(&session_cache_lock, K_FOREVER);

	for (int i = 0; i < ARRAY_SIZE(client_cache); i++) {
		if (client_cache[i].session != NULL) {
			tls_session_buf_free(client_cache[i].session, client_cache[i].session_len);
		}
	}

	(void)memset(client_cache, 0, sizeof(client_cache));

	k_mutex_unlock(&session_cache_lock);
}
#endif

bool net_socket_is_tls(void *obj)
{
	return PART_OF_ARRAY(tls_contexts, (struct tls_context *)obj);
}

#if defined(CONFIG_MBEDTLS)
static int tls_ctr_drbg_random(void *ctx, unsigned char *buf, size_t len)
{
	ARG_UNUSED(ctx);

#if defined(CONFIG_CSPRNG_ENABLED)
	return sys_csrand_get(buf, len);
#else
	sys_rand_get(buf, len);

	return 0;
#endif
}
#endif /* CONFIG_MBEDTLS */

#if defined(CONFIG_WOLFSSL) && defined(WOLFSSL_TLS13) && !defined(NO_PSK)
/* TLS 1.3 binds a PSK to one hash, so every PSK handshake uses this suite */
static const char tls13_psk_default_ciphersuite[] =
	CONFIG_NET_SOCKETS_TLS_WOLFSSL_PSK_TLS13_CIPHERSUITE;
#endif /* CONFIG_WOLFSSL && WOLFSSL_TLS13 && !NO_PSK */

#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS) && defined(CONFIG_MBEDTLS)
/* mbedTLS-defined function for setting timer. */
static void dtls_timing_set_delay(void *data, uint32_t int_ms, uint32_t fin_ms)
{
	struct dtls_timing_context *ctx = data;

	ctx->int_ms = int_ms;
	ctx->fin_ms = fin_ms;

	if (fin_ms != 0U) {
		ctx->snapshot = k_uptime_get_32();
	}
}

/* mbedTLS-defined function for getting timer status.
 * The return values are specified by mbedTLS. The callback must return:
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

static int dtls_get_remaining_timeout(struct tls_context *ctx)
{
	struct dtls_timing_context *timing = &ctx->dtls_timing;
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
#endif /* CONFIG_NET_SOCKETS_ENABLE_DTLS && CONFIG_MBEDTLS */

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

	k_mutex_init(&context_lock);

#if defined(MBEDTLS_SSL_CACHE_C)
	mbedtls_ssl_cache_init(&server_cache);
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

static inline bool is_handshake_complete(struct tls_context *ctx)
{
	return k_sem_count_get(&ctx->tls_established) != 0;
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
	defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH) &&		\
	(MBEDTLS_TLS_EXT_ADV_CONTENT_LEN < 16384)

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

static inline void tls_set_max_frag_len(mbedtls_ssl_config *config, enum net_sock_type type)
{
	unsigned char mfl_code;
	size_t len = MBEDTLS_TLS_EXT_ADV_CONTENT_LEN;

#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
	if (type == SOCK_DGRAM && len > CONFIG_NET_SOCKETS_DTLS_MAX_FRAGMENT_LENGTH) {
		len = CONFIG_NET_SOCKETS_DTLS_MAX_FRAGMENT_LENGTH;
	}
#endif
	mfl_code = tls_mfl_code_from_content_len(len);

	mbedtls_ssl_conf_max_frag_len(config, mfl_code);
}
#elif defined(CONFIG_MBEDTLS)
static inline void tls_set_max_frag_len(mbedtls_ssl_config *config, enum net_sock_type type) {}
#endif

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
			tls->is_used = true;
			tls->options.verify_level = -1;
#if defined(ZTLS_WOLFSSL_MAX_FRAGMENT)
			tls->options.mfl_code = TLS_MFL_DEFAULT;
#endif
			tls->options.timeout_tx = K_FOREVER;
			tls->options.timeout_rx = K_FOREVER;
			tls->sock = -1;

			NET_DBG("Allocated TLS context, %p", tls);
			break;
		}
	}

	k_mutex_unlock(&context_lock);

	if (tls) {
		k_sem_init(&tls->tls_established, 0, 1);

#if defined(CONFIG_WOLFSSL)
#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
		tls->options.dtls_handshake_timeout_min =
			DTLS_TIMEOUT_DFL_MIN;
		tls->options.dtls_handshake_timeout_max =
			DTLS_TIMEOUT_DFL_MAX;
		tls->options.dtls_handshake_on_connect = true;
#endif /* CONFIG_NET_SOCKETS_ENABLE_DTLS */
#else
		mbedtls_ssl_init(&tls->ssl);
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
#if defined(MBEDTLS_X509_CRT_PARSE_C)
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
#elif defined(MBEDTLS_X509_CRT_PARSE_C)
	if (target_tls->options.is_hostname_set) {
		mbedtls_ssl_set_hostname(&target_tls->ssl,
					 source_tls->ssl.hostname);
	}
#endif /* CONFIG_WOLFSSL */

	return target_tls;
}

#if defined(CONFIG_WOLFSSL)
#ifndef NO_PSK
static void tls_wolfssl_psk_free(struct tls_context *tls)
{
	if (tls->psk != NULL) {
		wc_ForceZero(tls->psk, tls->psk_len);
		XFREE(tls->psk, NULL, DYNAMIC_TYPE_TMP_BUFFER);
		tls->psk = NULL;
		tls->psk_len = 0;
	}
	if (tls->psk_id != NULL) {
		XFREE(tls->psk_id, NULL, DYNAMIC_TYPE_TMP_BUFFER);
		tls->psk_id = NULL;
		tls->psk_id_len = 0;
	}
}
#endif /* !NO_PSK */

static void tls_wolfssl_ctx_release(struct tls_context *context)
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
#endif /* CONFIG_WOLFSSL */

/* Release TLS context. */
static int tls_release(struct tls_context *tls)
{
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
	tls_wolfssl_psk_free(tls);
#endif /* !NO_PSK */
	if (tls->wssl != NULL) {
		/* wolfSSL_shutdown before the handshake completes can corrupt global state */
		if (wolfSSL_is_init_finished(tls->wssl) && !tls->failed &&
		    !(wolfSSL_get_shutdown(tls->wssl) & WOLFSSL_SENT_SHUTDOWN)) {
			(void)wolfSSL_shutdown(tls->wssl);
		}
		wolfSSL_free(tls->wssl);
		tls->wssl = NULL;
	}
	tls_wolfssl_ctx_release(tls);
#else
#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
	mbedtls_ssl_cookie_free(&tls->cookie);
#endif
	mbedtls_ssl_config_free(&tls->config);
	mbedtls_ssl_free(&tls->ssl);
#if defined(MBEDTLS_X509_CRT_PARSE_C)
	mbedtls_x509_crt_free(&tls->ca_chain);
	mbedtls_x509_crt_free(&tls->own_cert);
	mbedtls_pk_free(&tls->priv_key);
#endif
#endif /* CONFIG_WOLFSSL */

	tls->is_used = false;

	return 0;
}

#if TLS_SESSION_CACHE_PRESENT || defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
static bool peer_addr_cmp(const struct sockaddr *addr,
			  const struct sockaddr *peer_addr)
{
	if (addr->sa_family != peer_addr->sa_family) {
		return false;
	}

	if (IS_ENABLED(CONFIG_NET_IPV6) && peer_addr->sa_family == AF_INET6) {
		struct sockaddr_in6 *addr1 = net_sin6(peer_addr);
		struct sockaddr_in6 *addr2 = net_sin6(addr);

		return (addr1->sin6_port == addr2->sin6_port) &&
			net_ipv6_addr_cmp(&addr1->sin6_addr, &addr2->sin6_addr);
	} else if (IS_ENABLED(CONFIG_NET_IPV4) && peer_addr->sa_family == AF_INET) {
		struct sockaddr_in *addr1 = net_sin(peer_addr);
		struct sockaddr_in *addr2 = net_sin(addr);

		return (addr1->sin_port == addr2->sin_port) &&
			net_ipv4_addr_cmp(&addr1->sin_addr, &addr2->sin_addr);
	}

	return false;
}
#endif

#if defined(CONFIG_MBEDTLS)
static int tls_session_save(const struct sockaddr *peer_addr,
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
			if (peer_addr_cmp(&client_cache[i].peer_addr, peer_addr)) {
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

	ret = 0;

out:
	k_mutex_unlock(&session_cache_lock);

	return ret;
}

static int tls_session_get(const struct sockaddr *peer_addr,
			   mbedtls_ssl_session *session)
{
	struct tls_session_cache *entry = NULL;
	int ret = 0;

	k_mutex_lock(&session_cache_lock, K_FOREVER);

	for (int i = 0; i < ARRAY_SIZE(client_cache); i++) {
		if (client_cache[i].session != NULL &&
		    peer_addr_cmp(&client_cache[i].peer_addr, peer_addr)) {
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
			      const struct sockaddr *addr,
			      socklen_t addrlen)
{
	mbedtls_ssl_session session;
	struct sockaddr peer_addr = { 0 };
	int ret;

	if (!context->options.cache_enabled) {
		return;
	}

	if (addrlen > sizeof(peer_addr)) {
		return;
	}

	memcpy(&peer_addr, addr, addrlen);
	mbedtls_ssl_session_init(&session);

	ret = mbedtls_ssl_get_session(&context->ssl, &session);
	if (ret < 0) {
		NET_ERR("Failed to obtain session for %p", context);
		goto exit;
	}

	ret = tls_session_save(&peer_addr, &session);
	if (ret < 0) {
		NET_ERR("Failed to save session for %p", context);
	}

exit:
	mbedtls_ssl_session_free(&session);
}

static void tls_session_restore(struct tls_context *context,
				const struct sockaddr *addr,
				socklen_t addrlen)
{
	mbedtls_ssl_session session;
	struct sockaddr peer_addr = { 0 };
	int ret;

	if (!context->options.cache_enabled) {
		return;
	}

	if (addrlen > sizeof(peer_addr)) {
		return;
	}

	memcpy(&peer_addr, addr, addrlen);
	mbedtls_ssl_session_init(&session);

	ret = tls_session_get(&peer_addr, &session);
	if (ret < 0) {
		NET_DBG("Session not found for %p", context);
		goto exit;
	}

	ret = mbedtls_ssl_set_session(&context->ssl, &session);
	if (ret < 0) {
		NET_ERR("Failed to set session for %p", context);
	}

exit:
	mbedtls_ssl_session_free(&session);
}
#elif defined(CONFIG_WOLFSSL)
/* A skipped client check and a PSK session both report 0 */
static uint32_t tls_wolfssl_verify_result(struct tls_context *context)
{
	bool is_server = context->options.role == ZTLS_IS_SERVER;
	bool verify_none = context->options.verify_level == TLS_PEER_VERIFY_NONE ||
			   (context->options.verify_level == -1 && is_server);

	if (verify_none && !is_server) {
		return 0;
	}

	if (verify_none && !context->psk_used) {
		return MBEDTLS_X509_BADCERT_SKIP_VERIFY;
	}

	if (context->cert_verify_ran) {
		return context->verify_result_flags;
	}

	if (!context->failed && wolfSSL_session_reused(context->wssl)) {
		/* A server session keeps no client certificate result */
		return is_server ? MBEDTLS_X509_BADCERT_SKIP_VERIFY
				 : context->resumed_verify_result;
	}

	if (is_server && !context->psk_used) {
		return MBEDTLS_X509_BADCERT_MISSING;
	}

	return 0;
}

#if defined(ZTLS_WOLFSSL_EXT_CACHE)
/* Caller holds session_cache_lock. */
static struct tls_session_cache *tls_wolfssl_session_entry_reserve(
	const struct sockaddr *peer_addr)
{
	struct tls_session_cache *entry = NULL;

	for (int i = 0; i < ARRAY_SIZE(client_cache); i++) {
		if (client_cache[i].session == NULL) {
			if (entry == NULL || entry->session != NULL) {
				entry = &client_cache[i];
			}
		} else {
			if (peer_addr_cmp(&client_cache[i].peer_addr, peer_addr)) {
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
		tls_session_buf_free(entry->session, entry->session_len);
		entry->session = NULL;
		entry->session_len = 0;
	}

	return entry;
}

/* VERIFY_NONE may skip the certificate callback, and a resumption keeps its cached flag */
static bool tls_wolfssl_psk_authenticated(struct tls_context *context)
{
	if (context->options.verify_level == TLS_PEER_VERIFY_NONE) {
		return false;
	}

	if (wolfSSL_session_reused(context->wssl)) {
		return context->resumed_psk;
	}

	return context->psk_used && !context->cert_verify_ran;
}

static void tls_session_store(struct tls_context *context,
			      const struct sockaddr *addr,
			      socklen_t addrlen)
{
	WOLFSSL_SESSION *session = NULL;
	struct tls_session_cache *entry;
	struct sockaddr peer_addr = { 0 };
	unsigned char *serialized = NULL;
	size_t alloc_len = 0;
	uint32_t verify_result;
	unsigned char *p;
	int size;

	if (!context->options.cache_enabled || context->wssl == NULL) {
		return;
	}

	if (addrlen > sizeof(peer_addr)) {
		return;
	}

	memcpy(&peer_addr, addr, addrlen);

	session = wolfSSL_get1_session(context->wssl);
	if (session == NULL) {
		NET_DBG("No session to save for %p", context);
		return;
	}

	size = wolfSSL_i2d_SSL_SESSION(session, NULL);
	if (size <= 0) {
		NET_ERR("Failed to size session for %p", context);
		goto exit;
	}

	/* The verify result goes first, since a resumption verifies no certificate */
	alloc_len = sizeof(verify_result) + (size_t)size;

	serialized = tls_session_buf_alloc(alloc_len);
	if (serialized == NULL) {
		NET_ERR("Failed to allocate session buffer.");
		goto exit;
	}

	verify_result = tls_wolfssl_verify_result(context);
	/* A VERIFY_NONE client reports 0, which the cache would take for checked */
	if (context->options.verify_level == TLS_PEER_VERIFY_NONE) {
		verify_result = MBEDTLS_X509_BADCERT_SKIP_VERIFY;
	}
	if (tls_wolfssl_psk_authenticated(context)) {
		verify_result |= ZTLS_WOLFSSL_CACHE_PSK;
	}
	memcpy(serialized, &verify_result, sizeof(verify_result));

	p = serialized + sizeof(verify_result);
	size = wolfSSL_i2d_SSL_SESSION(session, &p);
	if (size <= 0) {
		NET_ERR("Failed to serialize session for %p", context);
		goto exit;
	}

	k_mutex_lock(&session_cache_lock, K_FOREVER);
	entry = tls_wolfssl_session_entry_reserve(&peer_addr);
	if (entry == NULL) {
		k_mutex_unlock(&session_cache_lock);
		NET_ERR("No cache slot for %p", context);
		goto exit;
	}

	entry->session = serialized;
	entry->session_len = alloc_len;
	entry->timestamp = k_uptime_get();
	memcpy(&entry->peer_addr, &peer_addr, sizeof(peer_addr));
	serialized = NULL;
	k_mutex_unlock(&session_cache_lock);

exit:
	if (serialized != NULL) {
		/* Also covers a partial serialization when i2d failed */
		tls_session_buf_free(serialized, alloc_len);
	}
	wolfSSL_SESSION_free(session);
}

/* Under REQUIRED, only a session whose server was verified, or a PSK one, resumes */
static bool tls_wolfssl_resume_allowed(struct tls_context *context, uint32_t verify_result,
				       bool psk_session)
{
	return verify_result == 0 || psk_session ||
	       (context->options.verify_level != TLS_PEER_VERIFY_REQUIRED &&
		context->options.verify_level != -1);
}

static void tls_session_restore(struct tls_context *context,
				const struct sockaddr *addr,
				socklen_t addrlen)
{
	struct tls_session_cache *entry = NULL;
	WOLFSSL_SESSION *session = NULL;
	struct sockaddr peer_addr = { 0 };
	const unsigned char *p;
	uint32_t verify_result;
	bool psk_session;

	if (!context->options.cache_enabled || context->wssl == NULL) {
		return;
	}

	if (addrlen > sizeof(peer_addr)) {
		return;
	}

	memcpy(&peer_addr, addr, addrlen);

	k_mutex_lock(&session_cache_lock, K_FOREVER);

	for (int i = 0; i < ARRAY_SIZE(client_cache); i++) {
		if (client_cache[i].session != NULL &&
		    peer_addr_cmp(&client_cache[i].peer_addr, &peer_addr)) {
			entry = &client_cache[i];
			break;
		}
	}

	if (entry == NULL) {
		k_mutex_unlock(&session_cache_lock);
		NET_DBG("Session not found for %p", context);
		return;
	}

	if (entry->session_len > sizeof(verify_result)) {
		memcpy(&verify_result, entry->session, sizeof(verify_result));
		p = entry->session + sizeof(verify_result);
		session = wolfSSL_d2i_SSL_SESSION(NULL, &p,
			(long)(entry->session_len - sizeof(verify_result)));
	}
	if (session == NULL) {
		tls_session_buf_free(entry->session, entry->session_len);
		entry->session = NULL;
		entry->session_len = 0;
	}

	k_mutex_unlock(&session_cache_lock);

	if (session == NULL) {
		NET_ERR("Failed to load TLS session");
		return;
	}

	psk_session = (verify_result & ZTLS_WOLFSSL_CACHE_PSK) != 0;
	verify_result &= ~ZTLS_WOLFSSL_CACHE_PSK;

	if (!tls_wolfssl_resume_allowed(context, verify_result, psk_session)) {
		NET_DBG("Cached session for %p was not verified, not resuming", context);
	} else if (wolfSSL_set_session(context->wssl, session) != WOLFSSL_SUCCESS) {
		NET_DBG("Failed to set session for %p", context);
	} else {
		context->resumed_verify_result = verify_result;
		context->resumed_psk = psk_session;
	}

	wolfSSL_SESSION_free(session);
}
#else
#define tls_session_store(...)
#define tls_session_restore(...)
#define tls_session_cache_reset()
#endif /* ZTLS_WOLFSSL_EXT_CACHE */
#endif /* CONFIG_WOLFSSL */

static void tls_session_purge(void)
{
	tls_session_cache_reset();

#if defined(MBEDTLS_SSL_CACHE_C)
	mbedtls_ssl_cache_free(&server_cache);
	mbedtls_ssl_cache_init(&server_cache);
#endif
}

static inline int time_left(uint32_t start, uint32_t timeout)
{
	uint32_t elapsed = k_uptime_get_32() - start;

	return timeout - elapsed;
}

/* Returns: < 0 = error, 0 = either timed out or data/event is ready. */
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
			socklen_t optlen = sizeof(optval);

			if (zsock_getsockopt(fds.fd, SOL_SOCKET, SO_ERROR,
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
	int sock_flags = zsock_fcntl(sock, F_GETFL, 0);

	if (sock_flags == -1) {
		return false;
	}

	return !((flags & ZSOCK_MSG_DONTWAIT) || (sock_flags & O_NONBLOCK));
}

static int timeout_to_ms(k_timeout_t *timeout)
{
	if (K_TIMEOUT_EQ(*timeout, K_NO_WAIT)) {
		return 0;
	} else if (K_TIMEOUT_EQ(*timeout, K_FOREVER)) {
		return SYS_FOREVER_MS;
	} else {
		return k_ticks_to_ms_floor32(timeout->ticks);
	}
}

static void ctx_set_lock(struct tls_context *ctx, struct k_mutex *lock)
{
	ctx->lock = lock;
}

#if defined(CONFIG_WOLFSSL)
/* Only a close_notify is a clean close; a bare FIN is a recv error */
static bool tls_wolfssl_peer_closed(struct tls_context *context, int err)
{
	return err == WOLFSSL_ERROR_ZERO_RETURN &&
	       (wolfSSL_get_shutdown(context->wssl) & WOLFSSL_RECEIVED_SHUTDOWN) != 0;
}

static int tls_wolfssl_peek(WOLFSSL *wssl)
{
	byte dummy[1];
	int ret = wolfSSL_peek(wssl, dummy, sizeof(dummy));

	wc_ForceZero(dummy, sizeof(dummy));

	return ret;
}
#endif /* CONFIG_WOLFSSL */

#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
static bool dtls_is_peer_addr_valid(struct tls_context *context,
				    const struct sockaddr *peer_addr,
				    socklen_t addrlen)
{
	if (context->dtls_peer_addrlen != addrlen) {
		return false;
	}

	return peer_addr_cmp(&context->dtls_peer_addr, peer_addr);
}

static void dtls_peer_address_set(struct tls_context *context,
				  const struct sockaddr *peer_addr,
				  socklen_t addrlen)
{
	if (addrlen <= sizeof(context->dtls_peer_addr)) {
		memcpy(&context->dtls_peer_addr, peer_addr, addrlen);
		context->dtls_peer_addrlen = addrlen;
	}
}

static void dtls_peer_address_get(struct tls_context *context,
				  struct sockaddr *peer_addr,
				  socklen_t *addrlen)
{
	socklen_t len = MIN(context->dtls_peer_addrlen, *addrlen);

	memcpy(peer_addr, &context->dtls_peer_addr, len);
	*addrlen = len;
}

#if defined(CONFIG_WOLFSSL)
static int dtls_wolf_tx(WOLFSSL *ssl, char *buf, int len, void *ctx)
{
	struct tls_context *tls_ctx = ctx;
	ssize_t sent;

	sent = zsock_sendto(tls_ctx->sock, buf, len, ZSOCK_MSG_DONTWAIT,
			    &tls_ctx->dtls_peer_addr,
			    tls_ctx->dtls_peer_addrlen);

	if (sent < 0) {
		if (errno == EAGAIN) {
			return WOLFSSL_CBIO_ERR_WANT_WRITE;
		}

		return WOLFSSL_CBIO_ERR_GENERAL;
	}

	tls_ctx->dtls_tx_count++;

	return sent;
}

/* A pinned peer only changes while a server still answers statelessly */
static bool dtls_wolf_rx_foreign(struct tls_context *tls_ctx, WOLFSSL *ssl,
				 const struct sockaddr *addr, socklen_t addrlen)
{
	return tls_ctx->dtls_peer_addrlen != 0 &&
	       !dtls_is_peer_addr_valid(tls_ctx, addr, addrlen) &&
	       (tls_ctx->options.role != ZTLS_IS_SERVER || wolfSSL_is_stateful(ssl));
}

static int dtls_wolf_rx(WOLFSSL *ssl, char *buf, int len, void *ctx)
{
	struct tls_context *tls_ctx = ctx;
	socklen_t addrlen;
	struct sockaddr addr;
	ssize_t received;

	/* Dropped datagrams are read past, so a backlog does not hide the peer's records */
	do {
		addrlen = sizeof(struct sockaddr);
		received = zsock_recvfrom(tls_ctx->sock, buf, len,
					  ZSOCK_MSG_DONTWAIT, &addr, &addrlen);

		if (received < 0) {
			if (errno == EAGAIN) {
				return WOLFSSL_CBIO_ERR_WANT_READ;
			}

			return WOLFSSL_CBIO_ERR_GENERAL;
		}

		/* EOF after a local read shutdown; an empty datagram from the network is dropped */
		if (received == 0 && tls_ctx->recv_eof) {
			return WOLFSSL_CBIO_ERR_CONN_CLOSE;
		}
	} while (received == 0 || dtls_wolf_rx_foreign(tls_ctx, ssl, &addr, addrlen));

	if (tls_ctx->dtls_peer_addrlen == 0 ||
	    !dtls_is_peer_addr_valid(tls_ctx, &addr, addrlen)) {
		/* Only allow to store peer address for DTLS servers. */
		if (tls_ctx->options.role == ZTLS_IS_SERVER) {
			dtls_peer_address_set(tls_ctx, &addr, addrlen);

			if (wolfSSL_dtls_set_peer(ssl, (void *)&addr,
					(unsigned int)addrlen) != WOLFSSL_SUCCESS) {
				/* Roll back the stored peer so a retry does not falsely match */
				tls_ctx->dtls_peer_addrlen = 0;
				return WOLFSSL_CBIO_ERR_GENERAL;
			}
		} else {
			/* For clients it's incorrect to receive when no peer has been set up. */
			return WOLFSSL_CBIO_ERR_GENERAL;
		}
	}

	if (tls_ctx->options.role == ZTLS_IS_SERVER) {
		tls_ctx->dtls_rx_expiry = sys_timepoint_calc(
			CONFIG_NET_SOCKETS_DTLS_TIMEOUT == 0 ?
			K_FOREVER : K_MSEC(CONFIG_NET_SOCKETS_DTLS_TIMEOUT));
	}

	return received;
}

/* The read timeout mbedTLS applies to a DTLS server once its handshake is done */
static bool dtls_wolf_peer_expired(struct tls_context *ctx)
{
	return ctx->type == SOCK_DGRAM && ctx->options.role == ZTLS_IS_SERVER &&
	       is_handshake_complete(ctx) && sys_timepoint_expired(ctx->dtls_rx_expiry);
}
#else
static int dtls_tx(void *ctx, const unsigned char *buf, size_t len)
{
	struct tls_context *tls_ctx = ctx;
	ssize_t sent;

	sent = zsock_sendto(tls_ctx->sock, buf, len, ZSOCK_MSG_DONTWAIT,
			    &tls_ctx->dtls_peer_addr,
			    tls_ctx->dtls_peer_addrlen);
	if (sent < 0) {
		if (errno == EAGAIN) {
			return MBEDTLS_ERR_SSL_WANT_WRITE;
		}

		return MBEDTLS_ERR_NET_SEND_FAILED;
	}

	return sent;
}

static int dtls_rx(void *ctx, unsigned char *buf, size_t len)
{
	struct tls_context *tls_ctx = ctx;
	socklen_t addrlen = sizeof(struct sockaddr);
	struct sockaddr addr;
	int err;
	ssize_t received;

	received = zsock_recvfrom(tls_ctx->sock, buf, len,
				  ZSOCK_MSG_DONTWAIT, &addr, &addrlen);
	if (received < 0) {
		if (errno == EAGAIN) {
			return MBEDTLS_ERR_SSL_WANT_READ;
		}

		return MBEDTLS_ERR_NET_RECV_FAILED;
	}

	if (tls_ctx->dtls_peer_addrlen == 0) {
		/* Only allow to store peer address for DTLS servers. */
		if (tls_ctx->options.role == MBEDTLS_SSL_IS_SERVER) {
			dtls_peer_address_set(tls_ctx, &addr, addrlen);

			err = mbedtls_ssl_set_client_transport_id(
				&tls_ctx->ssl,
				(const unsigned char *)&addr, addrlen);
			if (err < 0) {
				return err;
			}
		} else {
			/* For clients it's incorrect to receive when
			 * no peer has been set up.
			 */
			return MBEDTLS_ERR_SSL_PEER_VERIFY_FAILED;
		}
	} else if (!dtls_is_peer_addr_valid(tls_ctx, &addr, addrlen)) {
		return MBEDTLS_ERR_SSL_WANT_READ;
	}

	return received;
}
#endif /* CONFIG_WOLFSSL */
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
#elif defined(CONFIG_WOLFSSL)
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

/* "PRIVATE KEY-----" also matches the RSA, EC and ENCRYPTED variants */
static bool key_is_pem(const unsigned char *buf, size_t buflen)
{
	return (buflen != 0 && buf[buflen - 1] == '\0' &&
		strstr((const char *)buf, "PRIVATE KEY-----") != NULL);
}
#endif /* CONFIG_WOLFSSL */

#if defined(MBEDTLS_X509_CRT_PARSE_C) || defined(CONFIG_WOLFSSL)
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
	int format = crt_is_pem(ca_cert->buf, ca_cert->len) ? WOLFSSL_FILETYPE_PEM :
							       WOLFSSL_FILETYPE_ASN1;
	int ret;

	ret = wolfSSL_CTX_load_verify_buffer(tls->ctx, ca_cert->buf,
					     ca_cert->len, format);

	if (ret != WOLFSSL_SUCCESS) {
		NET_ERR("Failed to install CA certificate into wolfSSL CTX "
			"(wolfSSL_CTX_load_verify_buffer=%d)", ret);
		return -EINVAL;
	}

	return 0;
#elif defined(MBEDTLS_X509_CRT_PARSE_C)
	int err;

	if (tls->options.cert_nocopy == TLS_CERT_NOCOPY_NONE ||
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
#endif /* MBEDTLS_X509_CRT_PARSE_C */

	return -ENOTSUP;
}

static void tls_set_ca_chain(struct tls_context *tls)
{
#if defined(MBEDTLS_X509_CRT_PARSE_C)
	mbedtls_ssl_conf_ca_chain(&tls->config, &tls->ca_chain, NULL);
	mbedtls_ssl_conf_cert_profile(&tls->config,
				      &mbedtls_x509_crt_profile_default);
#endif /* MBEDTLS_X509_CRT_PARSE_C */
}

static int tls_add_own_cert(struct tls_context *tls,
			    struct tls_credential *own_cert)
{
#if defined(CONFIG_WOLFSSL)
	int ret = 0;
	int format = WOLFSSL_FILETYPE_ASN1;

	word32 len = own_cert->len;

	if (crt_is_pem(own_cert->buf, own_cert->len)) {
		format = WOLFSSL_FILETYPE_PEM;
	} else {
		len = tls_der_chain_len(own_cert->buf, own_cert->len);
	}
	ret = wolfSSL_CTX_use_certificate_chain_buffer_format(tls->ctx,
							      own_cert->buf,
							      len,
							      format);
	if (ret != WOLFSSL_SUCCESS) {
		NET_ERR("Failed to parse certificate");
		return -EINVAL;
	}

	return 0;
#elif defined(MBEDTLS_X509_CRT_PARSE_C)
	int err;

	if (tls->options.cert_nocopy == TLS_CERT_NOCOPY_NONE ||
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
#endif /* MBEDTLS_X509_CRT_PARSE_C */

	return -ENOTSUP;
}

static int tls_set_own_cert(struct tls_context *tls)
{
#if defined(MBEDTLS_X509_CRT_PARSE_C)
	int err = mbedtls_ssl_conf_own_cert(&tls->config, &tls->own_cert,
					    &tls->priv_key);
	if (err != 0) {
		err = -ENOMEM;
	}

	return err;
#endif /* MBEDTLS_X509_CRT_PARSE_C */

	return -ENOTSUP;
}

static int tls_set_private_key(struct tls_context *tls,
			       struct tls_credential *priv_key)
{
#if defined(CONFIG_WOLFSSL)
	int format = key_is_pem(priv_key->buf, priv_key->len) ? WOLFSSL_FILETYPE_PEM :
								 WOLFSSL_FILETYPE_ASN1;
	int ret;

	ret = wolfSSL_CTX_use_PrivateKey_buffer(tls->ctx, priv_key->buf,
						priv_key->len, format);
	if (ret != WOLFSSL_SUCCESS) {
		NET_ERR("Failed to parse private key");
		return -EINVAL;
	}

	return 0;
#elif defined(MBEDTLS_X509_CRT_PARSE_C)
	int err;

	err = mbedtls_pk_parse_key(&tls->priv_key, priv_key->buf,
				   priv_key->len, NULL, 0,
				   tls_ctr_drbg_random, NULL);
	if (err != 0) {
		return -EINVAL;
	}

	return 0;
#endif /* MBEDTLS_X509_CRT_PARSE_C */

	return -ENOTSUP;
}

static int tls_set_psk(struct tls_context *tls,
		       struct tls_credential *psk,
		       struct tls_credential *psk_id)
{
#if defined(CONFIG_WOLFSSL) && !defined(NO_PSK)
	tls_wolfssl_psk_free(tls);

	tls->psk = XMALLOC(psk->len, NULL, DYNAMIC_TYPE_TMP_BUFFER);
	if (tls->psk == NULL) {
		return -ENOMEM;
	}

	XMEMCPY(tls->psk, psk->buf, psk->len);
	tls->psk_len = psk->len;

	tls->psk_id = XMALLOC(psk_id->len + 1, NULL, DYNAMIC_TYPE_TMP_BUFFER);
	if (tls->psk_id == NULL) {
		tls_wolfssl_psk_free(tls);
		return -ENOMEM;
	}

	XMEMCPY(tls->psk_id, psk_id->buf, psk_id->len);
	tls->psk_id[psk_id->len] = '\0';
	tls->psk_id_len = psk_id->len;

	return 0;
#endif /* CONFIG_WOLFSSL && !NO_PSK */
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

static int tls_set_credentials(struct tls_context *tls)
{
	struct tls_credential *cred;
	sec_tag_t tag;
	int i, err = 0;
	bool tag_found, ca_cert_present = false, own_cert_present = false;

#if defined(CONFIG_WOLFSSL) && !defined(NO_PSK)
	/* Only the current sec tags may supply a PSK */
	tls_wolfssl_psk_free(tls);
#endif

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

	if (IS_ENABLED(CONFIG_MBEDTLS) && err == 0) {
		if (ca_cert_present) {
			tls_set_ca_chain(tls);
		}
		if (own_cert_present) {
			err = tls_set_own_cert(tls);
		}
	}

	return err;
}

#if defined(CONFIG_MBEDTLS)
static int tls_mbedtls_reset(struct tls_context *context)
{
	int ret;

	ret = mbedtls_ssl_session_reset(&context->ssl);
	if (ret != 0) {
		return ret;
	}

	k_sem_reset(&context->tls_established);

#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
	/* Server role: reset the address so that a new
	 *              client can connect w/o a need to reopen a socket
	 * Client role: keep peer addr so socket can continue to be used
	 *              even on handshake timeout
	 */
	if (context->options.role == MBEDTLS_SSL_IS_SERVER) {
		(void)memset(&context->dtls_peer_addr, 0,
			     sizeof(context->dtls_peer_addr));
		context->dtls_peer_addrlen = 0;
	}
#endif

	return 0;
}

static int tls_mbedtls_handshake(struct tls_context *context,
				 k_timeout_t timeout)
{
	k_timepoint_t end;
	int ret;

	context->handshake_in_progress = true;

	end = sys_timepoint_calc(timeout);

	while ((ret = mbedtls_ssl_handshake(&context->ssl)) != 0) {
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
			if (context->type == SOCK_DGRAM) {
				int timeout_dtls =
					dtls_get_remaining_timeout(context);

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
			ret = tls_mbedtls_reset(context);
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
			ret = tls_mbedtls_reset(context);
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
			ret = tls_mbedtls_reset(context);
			if (ret == 0) {
				context->error = ECONNABORTED;
				ret = -ECONNABORTED;
				break;
			}
		}

		/* Avoid constant loop if tls_mbedtls_reset fails */
		NET_ERR("TLS reset error: -0x%x", -ret);
		context->error = ECONNABORTED;
		ret = -ECONNABORTED;
		break;
	}

	if (ret == 0) {
		k_sem_give(&context->tls_established);
	}

	context->handshake_in_progress = false;

	return ret;
}

static int tls_mbedtls_init(struct tls_context *context, bool is_server)
{
	int role, type, ret;

	role = is_server ? MBEDTLS_SSL_IS_SERVER : MBEDTLS_SSL_IS_CLIENT;

	type = (context->type == SOCK_STREAM) ?
		MBEDTLS_SSL_TRANSPORT_STREAM :
		MBEDTLS_SSL_TRANSPORT_DATAGRAM;

	if (type == MBEDTLS_SSL_TRANSPORT_STREAM) {
		mbedtls_ssl_set_bio(&context->ssl, context,
				    tls_tx, tls_rx, NULL);
	} else {
#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
		mbedtls_ssl_set_bio(&context->ssl, context,
				    dtls_tx, dtls_rx, NULL);
#else
		return -ENOTSUP;
#endif /* CONFIG_NET_SOCKETS_ENABLE_DTLS */
	}

	ret = mbedtls_ssl_config_defaults(&context->config, role, type,
					  MBEDTLS_SSL_PRESET_DEFAULT);
	if (ret != 0) {
		/* According to mbedTLS API documentation,
		 * mbedtls_ssl_config_defaults can fail due to memory
		 * allocation failure
		 */
		return -ENOMEM;
	}
	tls_set_max_frag_len(&context->config, context->type);

#if defined(MBEDTLS_SSL_RENEGOTIATION)
	mbedtls_ssl_conf_legacy_renegotiation(&context->config,
					   MBEDTLS_SSL_LEGACY_BREAK_HANDSHAKE);
	mbedtls_ssl_conf_renegotiation(&context->config,
				       MBEDTLS_SSL_RENEGOTIATION_ENABLED);
#endif

#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
	if (type == MBEDTLS_SSL_TRANSPORT_DATAGRAM) {
		/* DTLS requires timer callbacks to operate */
		mbedtls_ssl_set_timer_cb(&context->ssl,
					 &context->dtls_timing,
					 dtls_timing_set_delay,
					 dtls_timing_get_delay);
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
			ret = mbedtls_ssl_cookie_setup(&context->cookie,
						       tls_ctr_drbg_random,
						       NULL);
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

#if defined(MBEDTLS_X509_CRT_PARSE_C)
	/* For TLS clients, set hostname to empty string to enforce it's
	 * verification - only if hostname option was not set. Otherwise
	 * depend on user configuration.
	 */
	if (!is_server && !context->options.is_hostname_set) {
		mbedtls_ssl_set_hostname(&context->ssl, "");
	}
#endif

	/* If verification level was specified explicitly, set it. Otherwise,
	 * use mbedTLS default values (required for client, none for server)
	 */
	if (context->options.verify_level != -1) {
		mbedtls_ssl_conf_authmode(&context->config,
					  context->options.verify_level);
	}

	mbedtls_ssl_conf_rng(&context->config,
			     tls_ctr_drbg_random,
			     NULL);

	ret = tls_set_credentials(context);
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

	ret = mbedtls_ssl_setup(&context->ssl,
				&context->config);
	if (ret != 0) {
		/* According to mbedTLS API documentation,
		 * mbedtls_ssl_setup can fail due to memory allocation failure
		 */
		return -ENOMEM;
	}

#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS) && defined(CONFIG_MBEDTLS_SSL_DTLS_CONNECTION_ID)
	if (type == MBEDTLS_SSL_TRANSPORT_DATAGRAM) {
		if (context->options.dtls_cid.enabled) {
			ret = mbedtls_ssl_set_cid(&context->ssl, MBEDTLS_SSL_CID_ENABLED,
						  context->options.dtls_cid.cid,
						  context->options.dtls_cid.cid_len);
			if (ret != 0) {
				return -EINVAL;
			}
		}
	}
#endif /* CONFIG_NET_SOCKETS_ENABLE_DTLS && CONFIG_MBEDTLS_SSL_DTLS_CONNECTION_ID */

	context->is_initialized = true;

	return 0;
}
#elif defined(CONFIG_WOLFSSL)
/* Stores in *out the length of the DER SEQUENCE at buf with its header, or returns -EINVAL */
static int tls_der_object_len(const byte *buf, word32 len, word32 *out)
{
	word32 hdr, body, n, i;

	if (len < 2 || buf[0] != (ASN_SEQUENCE | ASN_CONSTRUCTED)) {
		return -EINVAL;
	}

	if (buf[1] < 0x80) {
		body = buf[1];
		hdr = 2;
	} else {
		n = buf[1] & 0x7f;
		if (n == 0 || n > 4 || len < 2 + n) {
			return -EINVAL;
		}

		body = 0;
		for (i = 0; i < n; i++) {
			body = (body << 8) | buf[2 + i];
		}

		hdr = 2 + n;
	}

	if (body > len - hdr) {
		return -EINVAL;
	}

	*out = hdr + body;

	return 0;
}

static int tls_check_der_chain(DecodedCert *dcert, const byte *der, word32 der_len)
{
	int ret;

	do {
		word32 one;

		ret = tls_der_object_len(der, der_len, &one);
		if (ret != 0) {
			return ret;
		}

		wc_InitDecodedCert(dcert, der, one, NULL);
		ret = wc_ParseCert(dcert, CERT_TYPE, NO_VERIFY, NULL);
		wc_FreeDecodedCert(dcert);

		der += one;
		der_len -= one;
	} while (ret == 0 && der_len > 0 && der[0] == (ASN_SEQUENCE | ASN_CONSTRUCTED));

	return ret;
}

/* Bytes taken by the certificates at der, without trailing padding. */
static word32 tls_der_chain_len(const byte *der, word32 der_len)
{
	word32 used = 0;
	word32 one;

	while (used < der_len && der[used] == (ASN_SEQUENCE | ASN_CONSTRUCTED) &&
	       tls_der_object_len(der + used, der_len - used, &one) == 0) {
		used += one;
	}

	return used;
}
#endif /* CONFIG_WOLFSSL */

static int tls_check_cert(struct tls_credential *cert)
{
#if defined(CONFIG_WOLFSSL)
	DecodedCert *dcert;
	byte *pem_der = NULL;
	int ret;

	/* DecodedCert is several KB, too large for a socket thread's stack */
	dcert = XMALLOC(sizeof(*dcert), NULL, DYNAMIC_TYPE_TMP_BUFFER);
	if (dcert == NULL) {
		return -ENOMEM;
	}

	if (crt_is_pem(cert->buf, cert->len)) {
#if defined(WOLFSSL_PEM_TO_DER)
		const char *base = (const char *)cert->buf;
		const char *pem = strstr(base, "-----BEGIN CERTIFICATE-----");

		/* DER of a PEM body is always shorter than the PEM itself. */
		pem_der = XMALLOC(cert->len, NULL, DYNAMIC_TYPE_TMP_BUFFER);
		if (pem_der == NULL) {
			XFREE(dcert, NULL, DYNAMIC_TYPE_TMP_BUFFER);
			return -ENOMEM;
		}

		/* wc_CertPemToDer() decodes one block, so step through the chain a
		 * BEGIN marker at a time. */
		do {
			size_t left = cert->len - (size_t)(pem - base);

			ret = wc_CertPemToDer((const byte *)pem, (int)left, pem_der,
					      (int)cert->len, CERT_TYPE);
			if (ret <= 0) {
				ret = -EINVAL;
				break;
			}

			ret = tls_check_der_chain(dcert, pem_der, (word32)ret);
			pem = strstr(pem + 1, "-----BEGIN CERTIFICATE-----");
		} while (ret == 0 && pem != NULL);
#else
		NET_ERR("PEM %s on tag %d needs WOLFSSL_PEM_TO_DER",
			"certificate", cert->tag);
		XFREE(dcert, NULL, DYNAMIC_TYPE_TMP_BUFFER);
		return -EINVAL;
#endif /* WOLFSSL_PEM_TO_DER */
	} else {
		ret = tls_check_der_chain(dcert, cert->buf, (word32)cert->len);
	}

	XFREE(dcert, NULL, DYNAMIC_TYPE_TMP_BUFFER);
	XFREE(pem_der, NULL, DYNAMIC_TYPE_TMP_BUFFER);

	if (ret != 0) {
		NET_ERR("Failed to parse %s on tag %d",
			"certificate", cert->tag);
		return -EINVAL;
	}

	return 0;
#elif defined(MBEDTLS_X509_CRT_PARSE_C)
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
#endif /* MBEDTLS_X509_CRT_PARSE_C */
}

#if defined(CONFIG_WOLFSSL)
/* Returns 1 if a wolfCrypt decoder accepts the key, 0 if none does, or -ENOMEM */
static int tls_wolfssl_key_decodes(byte *der, word32 der_len)
{
	word32 start = 0;
	word32 idx;
	int ret = 0;

#if defined(HAVE_PKCS8)
	if (wc_GetPkcs8TraditionalOffset(der, &start, der_len) < 0) {
		start = 0;
	}
#endif /* HAVE_PKCS8 */

#if defined(HAVE_ECC)
	{
		ecc_key *ecc = XMALLOC(sizeof(*ecc), NULL, DYNAMIC_TYPE_ECC);

		if (ecc == NULL) {
			return -ENOMEM;
		}

		if (wc_ecc_init(ecc) == 0) {
			idx = start;
			ret = wc_EccPrivateKeyDecode(der, &idx, ecc, der_len) == 0;
			wc_ecc_free(ecc);
		}

		XFREE(ecc, NULL, DYNAMIC_TYPE_ECC);
	}
#endif /* HAVE_ECC */

#if !defined(NO_RSA)
	if (ret == 0) {
		RsaKey *rsa = XMALLOC(sizeof(*rsa), NULL, DYNAMIC_TYPE_RSA);

		if (rsa == NULL) {
			return -ENOMEM;
		}

		if (wc_InitRsaKey(rsa, NULL) == 0) {
			idx = start;
			ret = wc_RsaPrivateKeyDecode(der, &idx, rsa, der_len) == 0;
			wc_FreeRsaKey(rsa);
		}

		XFREE(rsa, NULL, DYNAMIC_TYPE_RSA);
	}
#endif /* !NO_RSA */

#if defined(HAVE_ED25519) && defined(HAVE_ED25519_KEY_IMPORT)
	if (ret == 0) {
		ed25519_key *ed = XMALLOC(sizeof(*ed), NULL, DYNAMIC_TYPE_ED25519);

		if (ed == NULL) {
			return -ENOMEM;
		}

		if (wc_ed25519_init(ed) == 0) {
			idx = 0;
			ret = wc_Ed25519PrivateKeyDecode(der, &idx, ed, der_len) == 0;
			wc_ed25519_free(ed);
		}

		XFREE(ed, NULL, DYNAMIC_TYPE_ED25519);
	}
#endif /* HAVE_ED25519 && HAVE_ED25519_KEY_IMPORT */

	return ret;
}
#endif /* CONFIG_WOLFSSL */

static int tls_check_priv_key(struct tls_credential *priv_key)
{
#if defined(CONFIG_WOLFSSL)
	WOLFSSL_CTX *tmp_ctx;
	byte *der = (byte *)priv_key->buf;
	word32 der_len = (word32)priv_key->len;
	byte *pem_der = NULL;
	int fmt;
	int ret;

	fmt = key_is_pem(priv_key->buf, priv_key->len) ?
	      WOLFSSL_FILETYPE_PEM : WOLFSSL_FILETYPE_ASN1;

	if (fmt == WOLFSSL_FILETYPE_PEM) {
		der = NULL;
#if defined(WOLFSSL_PEM_TO_DER)
		pem_der = XMALLOC(priv_key->len, NULL, DYNAMIC_TYPE_TMP_BUFFER);
		if (pem_der == NULL) {
			return -ENOMEM;
		}

		ret = wc_KeyPemToDer(priv_key->buf, (int)priv_key->len, pem_der,
				     (int)priv_key->len, NULL);
		if (ret > 0) {
			der = pem_der;
			der_len = (word32)ret;
		}
#endif /* WOLFSSL_PEM_TO_DER */
	}

	ret = der != NULL ? tls_wolfssl_key_decodes(der, der_len) : 0;

	if (pem_der != NULL) {
		wc_ForceZero(pem_der, priv_key->len);
		XFREE(pem_der, NULL, DYNAMIC_TYPE_TMP_BUFFER);
	}

	if (ret != 0) {
		return ret < 0 ? ret : 0;
	}

	/* Other key types, and the error report, come from a CTX */
#ifndef NO_WOLFSSL_CLIENT
	tmp_ctx = wolfSSL_CTX_new(wolfSSLv23_client_method());
#else
	tmp_ctx = wolfSSL_CTX_new(wolfSSLv23_server_method());
#endif
	if (tmp_ctx == NULL) {
		return -ENOMEM;
	}

	ret = wolfSSL_CTX_use_PrivateKey_buffer(tmp_ctx, priv_key->buf,
						(long)priv_key->len, fmt);
	wolfSSL_CTX_free(tmp_ctx);

	if (ret != WOLFSSL_SUCCESS) {
		NET_ERR("Failed to parse %s on tag %d",
			"private key", priv_key->tag);
		return -EINVAL;
	}

	return 0;
#elif defined(MBEDTLS_X509_CRT_PARSE_C)
	mbedtls_pk_context key_ctx;
	int err;

	mbedtls_pk_init(&key_ctx);

	err = mbedtls_pk_parse_key(&key_ctx, priv_key->buf,
				   priv_key->len, NULL, 0,
				   tls_ctr_drbg_random, NULL);
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
#endif /* MBEDTLS_X509_CRT_PARSE_C */
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
#endif /* CONFIG_WOLFSSL */
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

#if defined(CONFIG_WOLFSSL)

/* A shared CTX is only unloaded by accept(), which passes the listener and holds its lock */
static void tls_wolfssl_drop_chain_cas(struct tls_context *context, struct tls_context *listener)
{
	struct tls_context *owner = context->ctx_shared ? listener : context;

	if (!context->chain_error_overridden || context->ctx == NULL || owner == NULL) {
		return;
	}

	if (wolfSSL_CertManagerUnloadIntermediateCerts(wolfSSL_CTX_GetCertManager(context->ctx)) !=
	    WOLFSSL_SUCCESS) {
		NET_ERR("Failed to unload the peer's chain CAs");
		owner->ctx_stale = true;
		return;
	}

	context->chain_error_overridden = false;
}

static void tls_wolfssl_clear_session_state(struct tls_context *context, bool failed)
{
	tls_wolfssl_drop_chain_cas(context, NULL);
	context->verify_result_flags = 0;
	context->resumed_verify_result = 0;
	context->resumed_psk = false;
	context->cert_verify_ran = false;
	context->psk_used = false;
	context->failed = failed;
}

static int tls_wolfssl_reset(struct tls_context *context)
{
	if (context->type == SOCK_STREAM) {
		/* A failed TCP session is never used again, and keeps its verify result */
		tls_wolfssl_drop_chain_cas(context, NULL);
		context->failed = true;
	} else if (context->ctx != NULL) {
		bool is_server = context->options.role == ZTLS_IS_SERVER;
		int ret;

		/* wolfSSL_clear() keeps extensions such as ALPN and MFL, so start a new object */
		ret = tls_wolfssl_session_init(context, is_server);
		if (ret != 0) {
			return ret;
		}
	} else {
		tls_wolfssl_clear_session_state(context, false);
	}

	k_sem_reset(&context->tls_established);

#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
	if (context->options.role == ZTLS_IS_SERVER) {
		(void)memset(&context->dtls_peer_addr, 0,
			     sizeof(context->dtls_peer_addr));
		context->dtls_peer_addrlen = 0;
	}
#endif

	return 0;
}

static ssize_t send_tls(struct tls_context *ctx, const void *buf,
			size_t len, int flags)
{
	const bool is_block = is_blocking(ctx->sock, flags);
	int ret = 0;
	int err = 0;
	int max_len;
	k_timeout_t timeout;
	k_timepoint_t end;

	if (ctx->error != 0) {
		errno = ctx->error;
		return -1;
	}

	if (ctx->session_closed) {
		errno = ECONNABORTED;
		return -1;
	}

	if (!is_block) {
		timeout = K_NO_WAIT;
	} else {
		timeout = ctx->options.timeout_tx;
	}

	end = sys_timepoint_calc(timeout);

	/* One record per call, so a short count reports what went out */
	if (ctx->type == SOCK_STREAM) {
		max_len = wolfSSL_GetMaxOutputSize(ctx->wssl);
		if (max_len > 0) {
			len = MIN(len, (size_t)max_len);
		}
	}

	do {
		ret = wolfSSL_write(ctx->wssl, buf, (int)MIN(len, (size_t)INT_MAX));
		if (ret > 0) {
			return ret;
		}

		err = wolfSSL_get_error(ctx->wssl, ret);

		/* A zero-length write is a no-op */
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
			if (tls_wolfssl_reset(ctx) != 0) {
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

static int tls_wolfssl_wait_rx(struct tls_context *ctx, bool is_block, k_timepoint_t end,
			       int err)
{
	k_timeout_t timeout;
	int timeout_ms;
	int ret;

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

	return ret;
}

static ssize_t recv_tls(struct tls_context *ctx, void *buf,
			size_t max_len, int flags)
{
	size_t recv_len = 0;
	const bool waitall = flags & ZSOCK_MSG_WAITALL;
	const bool is_block = is_blocking(ctx->sock, flags);
	k_timeout_t timeout;
	k_timepoint_t end;
	uint8_t zero_len_buf;
	int ret;
	int err;

	/* wolfSSL_read() rejects a NULL buffer even for a zero-length read */
	if (buf == NULL && max_len == 0) {
		buf = &zero_len_buf;
	}

	if (ctx->error != 0) {
		errno = ctx->error;
		return -1;
	}

	if (ctx->session_closed || ctx->recv_eof) {
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

		ret = wolfSSL_read(ctx->wssl, (uint8_t *)buf + recv_len,
				   (int)MIN(read_len, (size_t)INT_MAX));
		if (ret < 0) {
			/* A racing read shutdown is no ZERO_RETURN, so return what was read */
			if (ctx->recv_eof) {
				return recv_len;
			}

			err = wolfSSL_get_error(ctx->wssl, ret);
			if (err == WOLFSSL_ERROR_WANT_READ ||
			    err == WOLFSSL_ERROR_WANT_WRITE) {
				ret = tls_wolfssl_wait_rx(ctx, is_block, end, err);
				if (ret >= 0) {
					continue;
				}
			} else if (tls_wolfssl_peer_closed(ctx, err)) {
				ctx->session_closed = true;
				break;
			} else {
				NET_ERR("TLS recv error: %x", err);
				ret = -EIO;
			}

			errno = -ret;
			return -1;
		}

		if (ret == 0) {
			/* A clean closure reads as 0 */
			err = wolfSSL_get_error(ctx->wssl, ret);
			if ((err == WOLFSSL_ERROR_NONE && max_len == 0) || ctx->recv_eof) {
				break;
			}

			if (!tls_wolfssl_peer_closed(ctx, err)) {
				NET_ERR("TLS recv error: %x", err);
				errno = EIO;
				return -1;
			}

			ctx->session_closed = true;
			break;
		}

		recv_len += ret;
	} while ((recv_len == 0) || (waitall && (recv_len < max_len)));

	return recv_len;
}

#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
/* Returns a negative errno once the handshake has run out of retransmissions */
static int tls_wolfssl_dtls_rtx(struct tls_context *context)
{
	int ret;
	int err;

	/* Only a sent flight starts the retransmission timer */
	if (context->dtls_rtx_tx_count != context->dtls_tx_count) {
		context->dtls_rtx_tx_count = context->dtls_tx_count;
		context->dtls_rtx_armed = true;
		context->dtls_rtx_end = sys_timepoint_calc(
			K_SECONDS(wolfSSL_dtls_get_current_timeout(context->wssl)));
	}

	if (!context->dtls_rtx_armed || !sys_timepoint_expired(context->dtls_rtx_end)) {
		return 0;
	}

	ret = wolfSSL_dtls_got_timeout(context->wssl);
	if (ret != WOLFSSL_SUCCESS) {
		err = wolfSSL_get_error(context->wssl, ret);
		if (err != WOLFSSL_ERROR_WANT_READ && err != WOLFSSL_ERROR_WANT_WRITE) {
			NET_ERR("DTLS handshake timeout");
			if (tls_wolfssl_reset(context) == 0) {
				context->error = ETIMEDOUT;
				return -ETIMEDOUT;
			}

			context->error = ECONNABORTED;
			return -ECONNABORTED;
		}
	}

	/* The backoff goes on even when there was nothing to resend */
	context->dtls_rtx_tx_count = context->dtls_tx_count;
	context->dtls_rtx_end = sys_timepoint_calc(
		K_SECONDS(wolfSSL_dtls_get_current_timeout(context->wssl)));

	return 0;
}
#endif /* CONFIG_NET_SOCKETS_ENABLE_DTLS */

static int tls_wolfssl_handshake(struct tls_context *context, k_timeout_t timeout)
{
	k_timepoint_t end;
	int ret;
	int err;

	context->handshake_in_progress = true;

	end = sys_timepoint_calc(timeout);

	while ((ret = wolfSSL_negotiate(context->wssl)) != WOLFSSL_SUCCESS) {
		err = wolfSSL_get_error(context->wssl, ret);
		if (err == WOLFSSL_ERROR_WANT_READ ||
		    err == WOLFSSL_ERROR_WANT_WRITE) {
			int timeout_ms;

#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
			if (context->type == SOCK_DGRAM) {
				ret = tls_wolfssl_dtls_rtx(context);
				if (ret < 0) {
					break;
				}
			}
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
			if (context->type == SOCK_DGRAM && context->dtls_rtx_armed) {
				k_timeout_t rtx_left = sys_timepoint_timeout(context->dtls_rtx_end);
				int timeout_dtls = timeout_to_ms(&rtx_left);

				if (timeout_ms == SYS_FOREVER_MS) {
					timeout_ms = timeout_dtls;
				} else {
					timeout_ms = MIN(timeout_dtls, timeout_ms);
				}
			}
#endif /* CONFIG_NET_SOCKETS_ENABLE_DTLS */

			ret = wait_for_reason(context->sock, timeout_ms, err);
			if (ret < 0) {
				break;
			}

			continue;
		} else {
			NET_ERR("TLS handshake error: %d", err);
			ret = tls_wolfssl_reset(context);
			if (ret == 0) {
				context->error = ECONNABORTED;
				ret = -ECONNABORTED;
				break;
			}

			/* Avoid constant loop if tls_wolfssl_reset fails */
			NET_ERR("TLS reset error: %d", ret);
			context->error = ECONNABORTED;
			ret = -ECONNABORTED;
			break;
		}
	}

	/* A client keeps the chain CAs until its handshake ends, for a stapled OCSP response */
	if (ret != -EAGAIN) {
		tls_wolfssl_drop_chain_cas(context, NULL);
	}

	if (ret == WOLFSSL_SUCCESS) {
		ret = 0;
		k_sem_give(&context->tls_established);
	}

	context->handshake_in_progress = false;

	return ret;
}

#ifndef NO_PSK
static struct tls_context *tls_wolfssl_psk_context(WOLFSSL *ssl, unsigned int key_max_len)
{
	struct tls_context *context = wolfSSL_get_psk_callback_ctx(ssl);

	if (context == NULL || context->psk == NULL || context->psk_id == NULL ||
	    context->psk_len == 0 || context->psk_len > key_max_len) {
		return NULL;
	}

	return context;
}

static unsigned int tls_wolfssl_psk_copy(struct tls_context *context, unsigned char *key)
{
	XMEMCPY(key, context->psk, context->psk_len);
	context->psk_used = true;

	return context->psk_len;
}

static unsigned int tls_psk_server_cb(WOLFSSL *ssl, const char *identity,
				      unsigned char *key,
				      unsigned int key_max_len)
{
	struct tls_context *context = tls_wolfssl_psk_context(ssl, key_max_len);

	if (context == NULL) {
		return 0;
	}

	/* The PSK ID is length-delimited, so a prefix of it must not match */
	if (XSTRLEN(identity) != context->psk_id_len ||
	    XMEMCMP(identity, context->psk_id, context->psk_id_len) != 0) {
		return 0;
	}

	return tls_wolfssl_psk_copy(context, key);
}

static unsigned int tls_psk_client_cb(WOLFSSL *ssl, const char *hint,
				      char *identity,
				      unsigned int id_max_len,
				      unsigned char *key,
				      unsigned int key_max_len)
{
	struct tls_context *context = tls_wolfssl_psk_context(ssl, key_max_len);

	if (context == NULL || context->psk_id_len == 0 || context->psk_id_len > id_max_len) {
		return 0;
	}

	XMEMCPY(identity, context->psk_id, context->psk_id_len);
	identity[context->psk_id_len] = '\0';

	return tls_wolfssl_psk_copy(context, key);
}

#ifdef WOLFSSL_TLS13
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

static int tls_wolfssl_set_session_cache_mode(struct tls_context *context)
{
	bool is_server = context->options.role == ZTLS_IS_SERVER;
#if !defined(NO_SESSION_CACHE)
	long mode = WOLFSSL_SESS_CACHE_OFF;
#endif

	if (is_server && context->options.cache_enabled) {
		return 0;
	}

#if !defined(NO_SESSION_CACHE)
#if defined(ZTLS_WOLFSSL_EXT_CACHE)
	/* The socket cache keeps client sessions itself */
	if (!is_server) {
		mode = WOLFSSL_SESS_CACHE_NO_INTERNAL;
	}
#endif
	if (wolfSSL_CTX_set_session_cache_mode(context->ctx, mode) != WOLFSSL_SUCCESS) {
		return -EINVAL;
	}
#endif /* !NO_SESSION_CACHE */

	if (!is_server) {
		return 0;
	}

#if defined(HAVE_SESSION_TICKET) && !defined(NO_WOLFSSL_SERVER)
	/* Tickets resume a session too, so they follow the cache setting */
	if (wolfSSL_CTX_NoTicketTLSv12(context->ctx) != WOLFSSL_SUCCESS) {
		return -EINVAL;
	}
#if defined(WOLFSSL_TLS13)
	/* Fails only on a context limited to TLS 1.2, which sends no TLS 1.3 ticket */
	(void)wolfSSL_CTX_no_ticket_TLSv13(context->ctx);
#endif
#endif /* HAVE_SESSION_TICKET && !NO_WOLFSSL_SERVER */

	return 0;
}

/* Runs once per accept on a server, so warn only once */
static atomic_t tls_wolfssl_server_hostname_warned;

static int tls_wolfssl_set_hostname(struct tls_context *context)
{
	if (context->options.role != ZTLS_IS_CLIENT) {
		if (context->options.is_hostname_set &&
		    atomic_cas(&tls_wolfssl_server_hostname_warned, 0, 1)) {
			NET_WARN("TLS_HOSTNAME set on a server socket is "
				 "ignored; no CN/SAN match is performed "
				 "against client certs.");
		}
		return 0;
	}

#if defined(HAVE_SNI)
	if (context->host_name != NULL) {
		if (wolfSSL_UseSNI(context->wssl, WOLFSSL_SNI_HOST_NAME,
				   (const char *)context->host_name,
				   context->host_len) != WOLFSSL_SUCCESS) {
			return -EINVAL;
		}
	}
#endif /* HAVE_SNI */

#if !defined(OPENSSL_EXTRA) && !defined(OPENSSL_EXTRA_X509_SMALL)
	/* No current_cert without the compat layer, so wolfSSL matches the name itself. */
	if (context->host_name != NULL &&
	    context->options.verify_level != TLS_PEER_VERIFY_NONE &&
	    wolfSSL_check_domain_name(context->wssl,
				      (const char *)context->host_name) !=
	    WOLFSSL_SUCCESS) {
		if (context->options.verify_level != TLS_PEER_VERIFY_OPTIONAL) {
			return -EINVAL;
		}
		context->verify_result_flags |= MBEDTLS_X509_BADCERT_CN_MISMATCH;
	}
#endif /* !OPENSSL_EXTRA && !OPENSSL_EXTRA_X509_SMALL */

	return 0;
}

/* Flags BADCERT_CN_MISMATCH and clears *effective_ok when the leaf misses TLS_HOSTNAME */
static void tls_wolfssl_apply_leaf_hostname_check(struct tls_context *context,
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
	if (context->options.verify_level == TLS_PEER_VERIFY_NONE) {
		return;
	}
	/* No name set matches no certificate */
	if (!context->options.is_hostname_set) {
		context->verify_result_flags |= MBEDTLS_X509_BADCERT_CN_MISMATCH;
		*effective_ok = 0;
		return;
	}
	if (context->host_name == NULL) {
		return;
	}
#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
	if (store->current_cert != NULL &&
	    wolfSSL_X509_check_host(store->current_cert, (const char *)context->host_name,
				    context->host_len, 0, NULL) == WOLFSSL_SUCCESS) {
		return;
	}

	context->verify_result_flags |= MBEDTLS_X509_BADCERT_CN_MISMATCH;
	*effective_ok = 0;
#endif /* OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL */
}

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

/* Returns preverify_ok with the hostname check applied */
static int tls_wolfssl_verify_record(struct tls_context *context, int preverify_ok,
				     WOLFSSL_X509_STORE_CTX *store)
{
	int effective_ok = preverify_ok;

	/* wolfSSL also calls this for an empty Certificate message */
	if (store->totalCerts > 0) {
		context->cert_verify_ran = true;
	}

	if (!preverify_ok && store->error != 0) {
		context->verify_result_flags |=
			tls_wolfssl_error_to_mbedtls_flags(store->error);
	}

	tls_wolfssl_apply_leaf_hostname_check(context, store, &effective_ok);

	return effective_ok;
}

static int tls_wolfssl_chain_override(struct tls_context *context, int preverify_ok,
				      WOLFSSL_X509_STORE_CTX *store, int ret)
{
	if (ret == 0 || preverify_ok || store->error_depth == 0) {
		return ret;
	}

#if defined(HAVE_SECURE_RENEGOTIATION)
	/* A renegotiation runs outside the paths that unload the CAs an override lets in */
	if (wolfSSL_SSL_renegotiate_pending(context->wssl)) {
		return preverify_ok;
	}
#endif /* HAVE_SECURE_RENEGOTIATION */

	context->chain_error_overridden = true;

	return ret;
}

static int tls_wolfssl_verify_accumulate_cb(int preverify_ok,
					     WOLFSSL_X509_STORE_CTX *store)
{
	struct tls_context *context;
	int effective_ok;

	if (store == NULL || store->userCtx == NULL) {
		return preverify_ok;
	}

	context = (struct tls_context *)store->userCtx;
	effective_ok = tls_wolfssl_verify_record(context, preverify_ok, store);

	if (context->options.verify_level == TLS_PEER_VERIFY_OPTIONAL) {
		/* The leaf comes last, so this warns once per handshake */
		if (store->error_depth == 0 && context->verify_result_flags != 0) {
			NET_WARN("TLS_PEER_VERIFY_OPTIONAL: accepting chain with "
				 "verify_result_flags=0x%x; application should "
				 "read TLS_CERT_VERIFY_RESULT before trusting the peer",
				 context->verify_result_flags);
		}
		return tls_wolfssl_chain_override(context, preverify_ok, store, 1);
	}

	return effective_ok;
}

#if defined(CONFIG_WOLFSSL_VERIFY_CALLBACK)
static int tls_wolfssl_verify_cb_wrapper(int preverify_ok,
					 WOLFSSL_X509_STORE_CTX *store)
{
	struct tls_context *context;
	tls_wolfssl_verify_cb_t user_cb;
	void *user_ctx;
	int effective_ok;
	int ret;

	if (store == NULL || store->userCtx == NULL) {
		return preverify_ok;
	}

	context = (struct tls_context *)store->userCtx;
	effective_ok = tls_wolfssl_verify_record(context, preverify_ok, store);

	user_cb = context->options.cert_verify_wolfssl.cb;
	user_ctx = context->options.cert_verify_wolfssl.ctx;
	__ASSERT(user_cb != NULL,
		 "verify wrapper installed without a user callback");

	/* The application's ctx travels in store->userCtx for this synchronous call only */
	store->userCtx = user_ctx;
	ret = user_cb(effective_ok, store);
	store->userCtx = context;

	return tls_wolfssl_chain_override(context, preverify_ok, store, ret);
}
#endif /* CONFIG_WOLFSSL_VERIFY_CALLBACK */

static int tls_wolfssl_set_verify(struct tls_context *context)
{
	int verifyLevel = -1;
	VerifyCallback cb = NULL;

	if (context->options.verify_level != -1) {
		switch (context->options.verify_level) {
		case TLS_PEER_VERIFY_NONE:
			verifyLevel = WOLFSSL_VERIFY_NONE;
			break;
		case TLS_PEER_VERIFY_OPTIONAL:
			verifyLevel = WOLFSSL_VERIFY_PEER;
			break;
		case TLS_PEER_VERIFY_REQUIRED:
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

	wolfSSL_SetCertCbCtx(context->wssl, context);

#if defined(CONFIG_WOLFSSL_VERIFY_CALLBACK)
	if (context->options.cert_verify_wolfssl.cb != NULL) {
		cb = tls_wolfssl_verify_cb_wrapper;
	} else {
		cb = tls_wolfssl_verify_accumulate_cb;
	}
#else
	cb = tls_wolfssl_verify_accumulate_cb;
#endif /* CONFIG_WOLFSSL_VERIFY_CALLBACK */

	if (verifyLevel == -1) {
		if (context->options.role == ZTLS_IS_SERVER) {
			verifyLevel = WOLFSSL_VERIFY_NONE;
		} else {
			verifyLevel = WOLFSSL_VERIFY_PEER;
		}
	}
	wolfSSL_set_verify(context->wssl, verifyLevel, cb);

	return 0;
}

static int tls_wolfssl_set_ciphersuites(struct tls_context *context)
{
	/* mbedTLS-style suite IDs are ints; wolfSSL takes big-endian byte pairs */
	byte cs_bytes[CONFIG_NET_SOCKETS_TLS_MAX_CIPHERSUITES * 2];
	int cipher_cnt = 0;

	if (context->options.ciphersuites[0] == 0) {
		return 0;
	}

	for (int i = 0; i < CONFIG_NET_SOCKETS_TLS_MAX_CIPHERSUITES &&
			context->options.ciphersuites[i] != 0; i++) {
		sys_put_be16((uint16_t)context->options.ciphersuites[i], &cs_bytes[cipher_cnt * 2]);
		cipher_cnt++;
	}

	if (wolfSSL_set_cipher_list_bytes(context->wssl, cs_bytes,
					  cipher_cnt * 2) != WOLFSSL_SUCCESS) {
		return -EINVAL;
	}

	return 0;
}

#ifdef HAVE_ALPN
static int tls_wolfssl_set_alpn(struct tls_context *context)
{
	if (context->alpn_joined != NULL &&
	    wolfSSL_UseALPN(context->wssl, context->alpn_joined,
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

	/* The list ends at the first NULL */
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

	*(iter - 1) = '\0';

	return 0;
}
#endif /* HAVE_ALPN */

#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
static int tls_wolfssl_set_dtls_timeouts(struct tls_context *context)
{
	if (context->type == SOCK_DGRAM) {
		int init_s;
		int max_s;

		/* wolfSSL takes whole seconds; round up so a sub-second value does not become 0. */
		init_s = (int)DIV_ROUND_UP((uint64_t)context->options.dtls_handshake_timeout_min,
					   MSEC_PER_SEC);
		if (init_s < 1) {
			init_s = 1;
		}
		max_s = (int)DIV_ROUND_UP((uint64_t)context->options.dtls_handshake_timeout_max,
					  MSEC_PER_SEC);
		if (max_s < init_s) {
			max_s = init_s;
		}

		/* Lower init first: wolfSSL rejects a max below the current init. */
		if (wolfSSL_dtls_set_timeout_init(context->wssl, 1) != WOLFSSL_SUCCESS ||
		    wolfSSL_dtls_set_timeout_max(context->wssl, max_s) != WOLFSSL_SUCCESS ||
		    wolfSSL_dtls_set_timeout_init(context->wssl, init_s) != WOLFSSL_SUCCESS) {
			return -EINVAL;
		}

		/* Underlying socket always acts like non-blocking due to IO callback overrides */
		wolfSSL_dtls_set_using_nonblock(context->wssl, 1);
	}

	return 0;
}
#endif

static int tls_wolfssl_set_options(struct tls_context *context)
{
	int ret = 0;
	bool is_server = FALSE;

	if (context->options.role == ZTLS_IS_SERVER) {
		is_server = TRUE;
	}

	ret = tls_wolfssl_set_verify(context);
	if (ret != 0) {
		return ret;
	}

	ret = tls_wolfssl_set_hostname(context);
	if (ret != 0) {
		return ret;
	}

	ret = tls_wolfssl_set_ciphersuites(context);
	if (ret != 0) {
		return ret;
	}

#ifdef HAVE_ALPN
	ret = tls_wolfssl_set_alpn(context);
	if (ret != 0) {
		return ret;
	}
#endif /* HAVE_ALPN */

#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
	ret = tls_wolfssl_set_dtls_timeouts(context);
	if (ret != 0) {
		return ret;
	}
#endif /* CONFIG_NET_SOCKETS_ENABLE_DTLS */

#if defined(ZTLS_WOLFSSL_DTLS_CID)
	if (context->type == SOCK_DGRAM && context->options.dtls_cid.enabled &&
	    (wolfSSL_dtls_cid_use(context->wssl) != WOLFSSL_SUCCESS ||
	     wolfSSL_dtls_cid_set(context->wssl, context->options.dtls_cid.cid,
				  (unsigned int)context->options.dtls_cid.cid_len) !=
		     WOLFSSL_SUCCESS)) {
		return -EINVAL;
	}
#endif /* ZTLS_WOLFSSL_DTLS_CID */

	return 0;
}

#if defined(ZTLS_WOLFSSL_MAX_FRAGMENT)
/* Round down to an RFC 6066 length; a full record needs no extension. */
static inline int tls_wolfssl_mfl_code(struct tls_context *context)
{
	size_t len;

	/* TLS_MFL_* and WOLFSSL_MFL_* both hold the RFC 6066 codes. */
	if (context->options.mfl_code != TLS_MFL_DEFAULT) {
		return context->options.mfl_code;
	}

	len = CONFIG_NET_SOCKETS_TLS_WOLFSSL_MAX_FRAGMENT_LENGTH;

#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
	if (context->type == SOCK_DGRAM &&
	    len > CONFIG_NET_SOCKETS_DTLS_MAX_FRAGMENT_LENGTH) {
		len = CONFIG_NET_SOCKETS_DTLS_MAX_FRAGMENT_LENGTH;
	}
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

/* Gives the context a new WOLFSSL object, so no state of an earlier handshake survives. */
static int tls_wolfssl_session_init(struct tls_context *context, bool is_server)
{
	int ret;
#if defined(ZTLS_WOLFSSL_MAX_FRAGMENT)
	int mfl;
#endif

	if (context->wssl != NULL) {
		wolfSSL_free(context->wssl);
	}

	tls_wolfssl_clear_session_state(context, false);
#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
	context->dtls_rtx_armed = false;
	context->dtls_rtx_tx_count = context->dtls_tx_count;
#endif
	context->wssl = wolfSSL_new(context->ctx);
	if (context->wssl == NULL) {
		return -ENOMEM;
	}

#if defined(HAVE_SECURE_RENEGOTIATION)
	if (wolfSSL_UseSecureRenegotiation(context->wssl) != WOLFSSL_SUCCESS) {
		ret = -EINVAL;
		goto err_cleanup;
	}
#endif /* HAVE_SECURE_RENEGOTIATION */

#if defined(ZTLS_WOLFSSL_MAX_FRAGMENT)
	/* Only a client offers a max fragment length (RFC 6066). */
	if (!is_server) {
		mfl = tls_wolfssl_mfl_code(context);

		if (mfl != WOLFSSL_MFL_DISABLED &&
		    wolfSSL_UseMaxFragment(context->wssl, mfl) != WOLFSSL_SUCCESS) {
			ret = -EINVAL;
			goto err_cleanup;
		}
	}
#else
	ARG_UNUSED(is_server);
#endif /* ZTLS_WOLFSSL_MAX_FRAGMENT */

	if (wolfSSL_set_fd(context->wssl, context->sock) != WOLFSSL_SUCCESS) {
		ret = -EINVAL;
		goto err_cleanup;
	}

	wolfSSL_SetIOReadCtx(context->wssl, (void *)context);
	wolfSSL_SetIOWriteCtx(context->wssl, (void *)context);

#ifndef NO_PSK
	if (NULL != context->psk) {
		wolfSSL_set_psk_callback_ctx(context->wssl, (void *)context);
	}
#endif /* !NO_PSK */

	ret = tls_wolfssl_set_options(context);
	if (ret != 0) {
		goto err_cleanup;
	}

	return 0;

err_cleanup:
	wolfSSL_free(context->wssl);
	context->wssl = NULL;

	return ret;
}

#if defined(NO_WOLFSSL_SERVER)
#define TLS_WOLFSSL_METHOD(is_server, ver) ((is_server) ? NULL : ver##_client_method())
#elif defined(NO_WOLFSSL_CLIENT)
#define TLS_WOLFSSL_METHOD(is_server, ver) ((is_server) ? ver##_server_method() : NULL)
#else
#define TLS_WOLFSSL_METHOD(is_server, ver) \
	((is_server) ? ver##_server_method() : ver##_client_method())
#endif

static WOLFSSL_METHOD *tls_wolfssl_get_method(struct tls_context *context,
					      bool is_server)
{
	if (context->type == SOCK_STREAM) {
		switch (context->tls_version) {
#ifdef WOLFSSL_TLS13
		case IPPROTO_TLS_1_3:
			return TLS_WOLFSSL_METHOD(is_server, wolfTLSv1_3);
#endif /* WOLFSSL_TLS13 */
#ifndef WOLFSSL_NO_TLS12
		case IPPROTO_TLS_1_2:
		case IPPROTO_TLS_1_1:
		case IPPROTO_TLS_1_0:
			return TLS_WOLFSSL_METHOD(is_server, wolfTLSv1_2);
#endif /* !WOLFSSL_NO_TLS12 */
		default:
			return NULL;
		}
	}
#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS) && defined(WOLFSSL_DTLS)
	else if (context->type == SOCK_DGRAM) {
		switch (context->tls_version) {
#ifndef WOLFSSL_NO_TLS12
		case IPPROTO_DTLS_1_2:
		case IPPROTO_DTLS_1_0:
			return TLS_WOLFSSL_METHOD(is_server, wolfDTLSv1_2);
#endif /* !WOLFSSL_NO_TLS12 */
		default:
			return NULL;
		}
	}
#endif /* CONFIG_NET_SOCKETS_ENABLE_DTLS && WOLFSSL_DTLS */
	return NULL;
}

#if defined(CONFIG_NET_SOCKETS_TLS_WOLFSSL_OCSP_STAPLING)
static int tls_wolfssl_ocsp_status_cb(WOLFSSL *ssl, int err, byte *resp, word32 resp_len,
				      word32 idx, void *arg)
{
	struct tls_context *context = arg;

	ARG_UNUSED(resp);
	ARG_UNUSED(resp_len);
	ARG_UNUSED(idx);

	if (err == 0 || context->wssl != ssl) {
		return err;
	}

	if (context->options.verify_level == TLS_PEER_VERIFY_OPTIONAL) {
		NET_WARN("TLS_PEER_VERIFY_OPTIONAL: accepting a failed OCSP check (%d); "
			 "application should read TLS_CERT_VERIFY_RESULT", err);
	}

	context->verify_result_flags |= tls_wolfssl_error_to_mbedtls_flags(err);

	if (context->options.verify_level == TLS_PEER_VERIFY_OPTIONAL ||
	    context->options.verify_level == TLS_PEER_VERIFY_NONE) {
		return 0;
	}

	return err;
}
#endif /* CONFIG_NET_SOCKETS_TLS_WOLFSSL_OCSP_STAPLING */

static void tls_wolfssl_role_set(struct tls_context *context, bool is_server)
{
	/* connect() must not demote a socket configured as a DTLS server */
	if (!context->role_set) {
		context->options.role = is_server ? ZTLS_IS_SERVER : ZTLS_IS_CLIENT;
	}
}

/* Builds the CTX, which accept() children share with their listening socket */
static int tls_wolfssl_ctx_setup(struct tls_context *context, bool is_server)
{
	WOLFSSL_METHOD *method;
	int ret;

	method = tls_wolfssl_get_method(context, is_server);
	if (method == NULL) {
		return -ENOTSUP;
	}

	context->ctx = wolfSSL_CTX_new(method);
	if (context->ctx == NULL) {
		return -ENOMEM;
	}

	context->ctx_cred_gen = credentials_generation();
	context->ctx_stale = false;
	context->ctx_server = is_server;

	if (context->type == SOCK_STREAM) {
		wolfSSL_CTX_SetIORecv(context->ctx, tls_wolf_rx);
		wolfSSL_CTX_SetIOSend(context->ctx, tls_wolf_tx);
	}
#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
	else if (context->type == SOCK_DGRAM) {
		wolfSSL_CTX_SetIORecv(context->ctx, dtls_wolf_rx);
		wolfSSL_CTX_SetIOSend(context->ctx, dtls_wolf_tx);
	}
#endif /* CONFIG_NET_SOCKETS_ENABLE_DTLS */
	else {
		return -EINVAL;
	}

	ret = tls_set_credentials(context);
	if (ret != 0) {
		return ret;
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

#if defined(CONFIG_NET_SOCKETS_TLS_WOLFSSL_OCSP_STAPLING)
	if (!is_server) {
		bool must_staple = IS_ENABLED(CONFIG_NET_SOCKETS_TLS_WOLFSSL_OCSP_MUST_STAPLE) &&
			context->options.verify_level != TLS_PEER_VERIFY_OPTIONAL &&
			context->options.verify_level != TLS_PEER_VERIFY_NONE;

		if (wolfSSL_CTX_EnableOCSPStapling(context->ctx) != WOLFSSL_SUCCESS ||
		    wolfSSL_CTX_UseOCSPStapling(context->ctx, WOLFSSL_CSR_OCSP,
						0) != WOLFSSL_SUCCESS) {
			NET_ERR("Failed to enable OCSP stapling");
			return -EINVAL;
		}

		wolfSSL_CTX_set_ocsp_status_verify_cb(context->ctx, tls_wolfssl_ocsp_status_cb,
						      context);

		if ((must_staple ? wolfSSL_CTX_EnableOCSPMustStaple(context->ctx) :
				   wolfSSL_CTX_DisableOCSPMustStaple(context->ctx)) !=
		    WOLFSSL_SUCCESS) {
			NET_ERR("Failed to set the OCSP must-staple policy");
			return -EINVAL;
		}
	}
#endif /* CONFIG_NET_SOCKETS_TLS_WOLFSSL_OCSP_STAPLING */

	/* wolfSSL_new() copies the cache and ticket settings, so they go on the CTX first */
	return tls_wolfssl_set_session_cache_mode(context);
}

/* Keeps ctx only while the role, options and credentials it was built from are unchanged */
static int tls_wolfssl_ctx_get(struct tls_context *context, bool is_server)
{
	int ret;

	if (context->ctx != NULL &&
	    (context->ctx_stale || context->ctx_server != is_server ||
	     context->ctx_cred_gen != credentials_generation())) {
		tls_wolfssl_ctx_release(context);
	}

	if (context->ctx != NULL) {
		return 0;
	}

	ret = tls_wolfssl_ctx_setup(context, is_server);
	if (ret != 0) {
		tls_wolfssl_ctx_release(context);
	}

	return ret;
}

static int tls_wolfssl_init(struct tls_context *context, bool is_server)
{
	int ret;

	tls_wolfssl_role_set(context, is_server);

#if defined(CONFIG_WOLFSSL_DEBUG)
	wolfSSL_Debugging_ON();
#endif /* CONFIG_WOLFSSL_DEBUG */

	if (!context->ctx_shared) {
		ret = tls_wolfssl_ctx_get(context, is_server);
		if (ret != 0) {
			goto err_cleanup;
		}
	}

	ret = tls_wolfssl_session_init(context, is_server);
	if (ret != 0) {
		goto err_cleanup;
	}

	/* connect() on a used DTLS socket must not inherit the last handshake */
	k_sem_reset(&context->tls_established);
	context->error = 0;

	context->is_initialized = true;

	return 0;

err_cleanup:
	if (context->wssl != NULL) {
		wolfSSL_free(context->wssl);
		context->wssl = NULL;
	}

	tls_wolfssl_ctx_release(context);
	context->ctx_shared = false;

	/* Nothing is left to reuse, so the next connect() or accept() sets up again */
	context->is_initialized = false;

	return ret;
}

#ifndef SINGLE_THREADED
/* The listening socket builds the CTX once; every accepted child takes a reference */
static int tls_wolfssl_ctx_share(struct tls_context *parent, struct tls_context *child)
{
	int ret;

	tls_wolfssl_role_set(parent, true);
	ret = tls_wolfssl_ctx_get(parent, true);
	if (ret != 0) {
		return ret;
	}

#ifndef NO_PSK
	if (parent->psk != NULL) {
		struct tls_credential psk = { .buf = parent->psk, .len = parent->psk_len };
		struct tls_credential psk_id = { .buf = parent->psk_id, .len = parent->psk_id_len };

		ret = tls_set_psk(child, &psk, &psk_id);
		if (ret != 0) {
			return ret;
		}
	}
#endif /* !NO_PSK */

	if (wolfSSL_CTX_up_ref(parent->ctx) != WOLFSSL_SUCCESS) {
		return -ENOMEM;
	}

	child->ctx = parent->ctx;
	child->ctx_shared = true;

	return 0;
}
#endif /* !SINGLE_THREADED */
#endif /* CONFIG_WOLFSSL */

static int tls_opt_sec_tag_list_set(struct tls_context *context,
				    const void *optval, socklen_t optlen)
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
#if defined(CONFIG_WOLFSSL)
	context->ctx_stale = true;
#endif

	return 0;
}

static int sock_opt_protocol_get(struct tls_context *context,
				 void *optval, socklen_t *optlen)
{
	int protocol = (int)context->tls_version;

	if (*optlen != sizeof(protocol)) {
		return -EINVAL;
	}

	*(int *)optval = protocol;

	return 0;
}

static int tls_opt_sec_tag_list_get(struct tls_context *context,
				    void *optval, socklen_t *optlen)
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
				const void *optval, socklen_t optlen)
{
#if defined(CONFIG_WOLFSSL)
	char *host_name = NULL;

	/* A NULL name turns the name check off */
	if (optval != NULL) {
		/* optval is a C string, so stop at the first NUL */
		optlen = strnlen((const char *)optval, optlen);

		/* An empty name matches no certificate and would turn the name check off */
		if (optlen == 0) {
			return -EINVAL;
		}

		/* RFC 6066 caps a HostName at 2^16 - 1, which keeps optlen + 1 from wrapping */
		if (optlen > UINT16_MAX) {
			return -EINVAL;
		}

		/* +1 for NUL - wolfSSL APIs require C strings. */
		host_name = XMALLOC(optlen + 1, NULL, DYNAMIC_TYPE_TMP_BUFFER);
		if (host_name == NULL) {
			return -ENOMEM;
		}

		XMEMCPY(host_name, optval, optlen);
		host_name[optlen] = '\0';
	}

	if (context->host_name != NULL) {
		XFREE(context->host_name, NULL, DYNAMIC_TYPE_TMP_BUFFER);
	}

	context->host_name = host_name;
	context->host_len = host_name != NULL ? optlen : 0;
	context->options.is_hostname_set = true;

	if (host_name != NULL && context->wssl != NULL) {
		return tls_wolfssl_set_hostname(context);
	}

	return 0;
#else
	ARG_UNUSED(optlen);

#if defined(MBEDTLS_X509_CRT_PARSE_C)
	if (mbedtls_ssl_set_hostname(&context->ssl, optval) != 0) {
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
					const void *optval, socklen_t optlen)
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
	for (int i = 0; i < cipher_cnt; i++) {
		int id = ((const int *)optval)[i];

		/* All ciphersuite IDs fit in 16 bits */
		if (id < 0 || id > 0xFFFF) {
			return -EINVAL;
		}
	}
#endif /* CONFIG_WOLFSSL */

	memcpy(context->options.ciphersuites, optval, optlen);
	context->options.ciphersuites[cipher_cnt] = 0;

#if defined(CONFIG_WOLFSSL)
	if (context->wssl != NULL) {
		return tls_wolfssl_set_ciphersuites(context);
	}
#else
	mbedtls_ssl_conf_ciphersuites(&context->config,
				      context->options.ciphersuites);
#endif /* CONFIG_WOLFSSL */
	return 0;
}

#if defined(CONFIG_WOLFSSL)
/* Fills ciphers with the suite IDs wolfSSL supports and returns how many it wrote */
static int tls_wolfssl_ciphersuites_all(int *ciphers, int cipher_cnt)
{
	const char *name;
	byte b1, b2;
	int flags = 0;
	int i = 0;

	for (int n = 0; (name = wolfSSL_get_cipher_list(n)) != NULL; n++) {
		/* Aliases repeat a suite, and 0x00FF is a signalling value */
		if (wolfSSL_get_cipher_suite_from_name(name, &b1, &b2, &flags) != 0 ||
		    (flags & WOLFSSL_CIPHER_SUITE_FLAG_NAMEALIAS) != 0 ||
		    (b1 == 0x00 && b2 == 0xFF)) {
			continue;
		}

		ciphers[i] = (b1 << 8) | b2;

		if (++i == cipher_cnt) {
			break;
		}
	}

	return i;
}
#endif /* CONFIG_WOLFSSL */

static int tls_opt_ciphersuite_list_get(struct tls_context *context,
					void *optval, socklen_t *optlen)
{
	const int *selected_ciphers;
	int cipher_cnt, i = 0;
	int *ciphers = optval;

	if (*optlen % sizeof(int) != 0 || *optlen == 0) {
		return -EINVAL;
	}

	if (context->options.ciphersuites[0] == 0) {
		/* No specific ciphersuites configured, return all available. */
#if defined(CONFIG_WOLFSSL)
		i = tls_wolfssl_ciphersuites_all(ciphers, *optlen / sizeof(int));
		*optlen = i * sizeof(int);
		return 0;
#else
		selected_ciphers = mbedtls_ssl_list_ciphersuites();
#endif /* CONFIG_WOLFSSL */
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
}

static int tls_opt_ciphersuite_used_get(struct tls_context *context,
					void *optval, socklen_t *optlen)
{
#if defined(CONFIG_MBEDTLS)
	const char *ciph;
#endif

	if (*optlen != sizeof(int)) {
		return -EINVAL;
	}

#if defined(CONFIG_WOLFSSL)
	if (context->wssl == NULL || !is_handshake_complete(context)) {
		return -ENOTCONN;
	}

	*(int *)optval = wolfSSL_get_current_cipher_suite(context->wssl);
#else
	ciph = mbedtls_ssl_get_ciphersuite(&context->ssl);
	if (ciph == NULL) {
		return -ENOTCONN;
	}

	*(int *)optval = mbedtls_ssl_get_ciphersuite_id(ciph);
#endif /* CONFIG_WOLFSSL */

	return 0;
}

static int tls_opt_alpn_list_set(struct tls_context *context,
				 const void *optval, socklen_t optlen)
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

	return 0;
}

#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
static int tls_opt_dtls_handshake_timeout_get(struct tls_context *context,
					      void *optval, socklen_t *optlen,
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
					      socklen_t optlen, bool is_max)
{
	uint32_t *val = (uint32_t *)optval;

	if (!optval) {
		return -EINVAL;
	}

	if (sizeof(uint32_t) != optlen) {
		return -EINVAL;
	}

	/* If mbedTLS context not inited, it will
	 * use these values upon init.
	 */
	if (is_max) {
		context->options.dtls_handshake_timeout_max = *val;
	} else {
		context->options.dtls_handshake_timeout_min = *val;
	}

	/* If the TLS context is already initialized, we need to
	 * update its config for it to take effect
	 */
#if defined(CONFIG_WOLFSSL)
	if (context->wssl != NULL) {
		return tls_wolfssl_set_dtls_timeouts(context);
	}
#else
	mbedtls_ssl_conf_handshake_timeout(&context->config,
			context->options.dtls_handshake_timeout_min,
			context->options.dtls_handshake_timeout_max);
#endif /* CONFIG_WOLFSSL */

	return 0;
}

static int tls_opt_dtls_connection_id_set(struct tls_context *context,
					  const void *optval, socklen_t optlen)
{
#if defined(CONFIG_MBEDTLS_SSL_DTLS_CONNECTION_ID) || defined(ZTLS_WOLFSSL_DTLS_CID)
	int value;

	if (optlen > 0 && optval == NULL) {
		return -EINVAL;
	}

	if (optlen != sizeof(int)) {
		return -EINVAL;
	}

	value = *((int *)optval);

	switch (value) {
	case TLS_DTLS_CID_DISABLED:
		context->options.dtls_cid.enabled = false;
		context->options.dtls_cid.cid_len = 0;
		break;
	case TLS_DTLS_CID_SUPPORTED:
		context->options.dtls_cid.enabled = true;
		context->options.dtls_cid.cid_len = 0;
		break;
	case TLS_DTLS_CID_ENABLED:
		context->options.dtls_cid.enabled = true;
		if (context->options.dtls_cid.cid_len == 0) {
			/* generate random self cid */
#if defined(CONFIG_CSPRNG_ENABLED)
			sys_csrand_get(context->options.dtls_cid.cid,
				       DTLS_CID_OUT_LEN_MAX);
#else
			sys_rand_get(context->options.dtls_cid.cid,
				     DTLS_CID_OUT_LEN_MAX);
#endif
			context->options.dtls_cid.cid_len = DTLS_CID_OUT_LEN_MAX;
		}
		break;
	default:
		return -EINVAL;
	}

	return 0;
#else
	return -ENOPROTOOPT;
#endif /* CONFIG_MBEDTLS_SSL_DTLS_CONNECTION_ID || ZTLS_WOLFSSL_DTLS_CID */
}

static int tls_opt_dtls_connection_id_value_set(struct tls_context *context,
						const void *optval,
						socklen_t optlen)
{
#if defined(CONFIG_MBEDTLS_SSL_DTLS_CONNECTION_ID) || defined(ZTLS_WOLFSSL_DTLS_CID)
	if (optlen > 0 && optval == NULL) {
		return -EINVAL;
	}

	if (optlen > DTLS_CID_IN_LEN_MAX) {
		return -EINVAL;
	}

	context->options.dtls_cid.cid_len = optlen;
	memcpy(context->options.dtls_cid.cid, optval, optlen);

	return 0;
#else
	return -ENOPROTOOPT;
#endif /* CONFIG_MBEDTLS_SSL_DTLS_CONNECTION_ID || ZTLS_WOLFSSL_DTLS_CID */
}

static int tls_opt_dtls_connection_id_value_get(struct tls_context *context,
						void *optval, socklen_t *optlen)
{
#if defined(CONFIG_MBEDTLS_SSL_DTLS_CONNECTION_ID) || defined(ZTLS_WOLFSSL_DTLS_CID)

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
						     socklen_t *optlen)
{
#if defined(CONFIG_MBEDTLS_SSL_DTLS_CONNECTION_ID)
	int enabled = false;
	int ret;
	size_t optlen_local;

	if (!context->is_initialized) {
		return -ENOTCONN;
	}

	if (*optlen < MBEDTLS_SSL_CID_OUT_LEN_MAX) {
		return -EINVAL;
	}

	ret = mbedtls_ssl_get_peer_cid(&context->ssl, &enabled, optval, &optlen_local);
	if (enabled) {
		*optlen = optlen_local;
	} else {
		*optlen = 0;
	}
	return ret;
#elif defined(ZTLS_WOLFSSL_DTLS_CID)
	unsigned int cid_len = 0;

	if (!context->is_initialized || context->wssl == NULL) {
		return -ENOTCONN;
	}

	if (!wolfSSL_is_init_finished(context->wssl)) {
		return -EAGAIN;
	}

	if (wolfSSL_dtls_cid_is_enabled(context->wssl) &&
	    wolfSSL_dtls_cid_get_tx_size(context->wssl, &cid_len) != WOLFSSL_SUCCESS) {
		return -EINVAL;
	}

	if (*optlen < cid_len) {
		return -EINVAL;
	}

	if (cid_len > 0 &&
	    wolfSSL_dtls_cid_get_tx(context->wssl, optval, *optlen) != WOLFSSL_SUCCESS) {
		return -EINVAL;
	}

	*optlen = cid_len;
	return 0;
#else
	return -ENOPROTOOPT;
#endif
}

static int tls_opt_dtls_connection_id_status_get(struct tls_context *context,
					  void *optval, socklen_t *optlen)
{
#if defined(CONFIG_MBEDTLS_SSL_DTLS_CONNECTION_ID)
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

	ret = mbedtls_ssl_get_peer_cid(&context->ssl, &enabled,
				       cid.cid,
				       &cid.cid_len);
	if (ret) {
		/* Handshake is not complete */
		return -EAGAIN;
	}

	cid.enabled = (enabled == MBEDTLS_SSL_CID_ENABLED);
	have_self_cid = (context->options.dtls_cid.cid_len != 0);
	have_peer_cid = (cid.cid_len != 0);

	if (!context->options.dtls_cid.enabled) {
		val = TLS_DTLS_CID_STATUS_DISABLED;
	} else if (have_self_cid && have_peer_cid) {
		val = TLS_DTLS_CID_STATUS_BIDIRECTIONAL;
	} else if (have_self_cid) {
		val = TLS_DTLS_CID_STATUS_DOWNLINK;
	} else if (have_peer_cid) {
		val = TLS_DTLS_CID_STATUS_UPLINK;
	} else {
		val = TLS_DTLS_CID_STATUS_DISABLED;
	}

	*((int *)optval) = val;
	return 0;
#elif defined(ZTLS_WOLFSSL_DTLS_CID)
	unsigned int self_len = 0;
	unsigned int peer_len = 0;
	int val;

	if (sizeof(int) != *optlen) {
		return -EINVAL;
	}

	if (!context->is_initialized || context->wssl == NULL) {
		return -ENOTCONN;
	}

	if (!wolfSSL_is_init_finished(context->wssl)) {
		return -EAGAIN;
	}

	/* wolfSSL drops the CID state when the peer did not negotiate it */
	if (context->options.dtls_cid.enabled && wolfSSL_dtls_cid_is_enabled(context->wssl)) {
		(void)wolfSSL_dtls_cid_get_rx_size(context->wssl, &self_len);
		(void)wolfSSL_dtls_cid_get_tx_size(context->wssl, &peer_len);
	}

	if (self_len != 0 && peer_len != 0) {
		val = TLS_DTLS_CID_STATUS_BIDIRECTIONAL;
	} else if (self_len != 0) {
		val = TLS_DTLS_CID_STATUS_DOWNLINK;
	} else if (peer_len != 0) {
		val = TLS_DTLS_CID_STATUS_UPLINK;
	} else {
		val = TLS_DTLS_CID_STATUS_DISABLED;
	}

	*((int *)optval) = val;
	return 0;
#else
	return -ENOPROTOOPT;
#endif
}

static int tls_opt_dtls_handshake_on_connect_set(struct tls_context *context,
						 const void *optval,
						 socklen_t optlen)
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
						 socklen_t *optlen)
{
	if (*optlen != sizeof(int)) {
		return -EINVAL;
	}

	*(int *)optval = context->options.dtls_handshake_on_connect;

	return 0;
}
#endif /* CONFIG_NET_SOCKETS_ENABLE_DTLS */

static int tls_opt_alpn_list_get(struct tls_context *context,
				 void *optval, socklen_t *optlen)
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
				     const void *optval, socklen_t optlen)
{
	int *val = (int *)optval;

	if (!optval) {
		return -EINVAL;
	}

	if (sizeof(int) != optlen) {
		return -EINVAL;
	}

	context->options.cache_enabled = (*val == TLS_SESSION_CACHE_ENABLED);
#if defined(CONFIG_WOLFSSL)
	context->ctx_stale = true;
#endif

	return 0;
}

static int tls_opt_session_cache_get(struct tls_context *context,
				     void *optval, socklen_t *optlen)
{
	int cache_enabled = context->options.cache_enabled ?
			    TLS_SESSION_CACHE_ENABLED :
			    TLS_SESSION_CACHE_DISABLED;

	if (*optlen != sizeof(cache_enabled)) {
		return -EINVAL;
	}

	*(int *)optval = cache_enabled;

	return 0;
}

static int tls_opt_cert_verify_result_get(struct tls_context *context,
					  void *optval, socklen_t *optlen)
{
	if (*optlen != sizeof(uint32_t)) {
		return -EINVAL;
	}

#if defined(CONFIG_WOLFSSL)
	if (context->wssl == NULL) {
		return -ENOTCONN;
	}

	*(uint32_t *)optval = tls_wolfssl_verify_result(context);
	return 0;
#else
	*(uint32_t *)optval = mbedtls_ssl_get_verify_result(&context->ssl);

	return 0;
#endif /* CONFIG_WOLFSSL */
}

static int tls_opt_session_cache_purge_set(struct tls_context *context,
					   const void *optval, socklen_t optlen)
{
#if defined(CONFIG_WOLFSSL) && !defined(NO_SESSION_CACHE)
	static atomic_t wolfssl_ready;
#endif

	ARG_UNUSED(optval);
	ARG_UNUSED(optlen);

#if defined(CONFIG_WOLFSSL) && !defined(NO_SESSION_CACHE)
	/* wolfSSL's server-side session cache is global; its lock needs wolfSSL_Init() */
	if (atomic_get(&wolfssl_ready) == 0 && wolfSSL_Init() == WOLFSSL_SUCCESS) {
		atomic_set(&wolfssl_ready, 1);
	}
	if (atomic_get(&wolfssl_ready) != 0) {
		wolfSSL_CTX_flush_sessions(NULL, -1);
	}
#endif
#if defined(CONFIG_WOLFSSL) && defined(HAVE_SESSION_TICKET)
	/* A new CTX has a new ticket key, so tickets the old one issued no longer resume */
	context->ctx_stale = true;
#endif
	tls_session_purge();

	return 0;
}

static int tls_opt_peer_verify_set(struct tls_context *context,
				   const void *optval, socklen_t optlen)
{
	int *peer_verify;

	if (!optval) {
		return -EINVAL;
	}

	if (optlen != sizeof(int)) {
		return -EINVAL;
	}

	peer_verify = (int *)optval;

	if (*peer_verify != TLS_PEER_VERIFY_NONE &&
	    *peer_verify != TLS_PEER_VERIFY_OPTIONAL &&
	    *peer_verify != TLS_PEER_VERIFY_REQUIRED) {
		return -EINVAL;
	}

	context->options.verify_level = *peer_verify;
#if defined(CONFIG_WOLFSSL)
	context->ctx_stale = true;
#endif

	return 0;
}

static int tls_opt_cert_nocopy_set(struct tls_context *context,
				   const void *optval, socklen_t optlen)
{
	int *cert_nocopy;

	if (!optval) {
		return -EINVAL;
	}

	if (optlen != sizeof(int)) {
		return -EINVAL;
	}

	cert_nocopy = (int *)optval;

	if (*cert_nocopy != TLS_CERT_NOCOPY_NONE &&
	    *cert_nocopy != TLS_CERT_NOCOPY_OPTIONAL) {
		return -EINVAL;
	}

	context->options.cert_nocopy = *cert_nocopy;

	return 0;
}

#if defined(ZTLS_WOLFSSL_MAX_FRAGMENT)
static int tls_opt_mfl_set(struct tls_context *context,
			   const void *optval, socklen_t optlen)
{
	const int *mfl;

	if (!optval) {
		return -EINVAL;
	}

	if (optlen != sizeof(int)) {
		return -EINVAL;
	}

	mfl = (const int *)optval;

	if (*mfl < TLS_MFL_DEFAULT || *mfl > TLS_MFL_4096) {
		return -EINVAL;
	}

	context->options.mfl_code = (int8_t)*mfl;

	return 0;
}
#endif /* ZTLS_WOLFSSL_MAX_FRAGMENT */

static int tls_opt_dtls_role_set(struct tls_context *context,
				 const void *optval, socklen_t optlen)
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
	context->ctx_stale = true;
#endif

	return 0;
}

#if defined(CONFIG_WOLFSSL)
static int tls_opt_cert_verify_callback_set(struct tls_context *context,
					    const void *optval,
					    socklen_t optlen)
{
	ARG_UNUSED(context);
	ARG_UNUSED(optval);
	ARG_UNUSED(optlen);

	NET_ERR("TLS_CERT_VERIFY_CALLBACK is not supported by the wolfSSL "
		"backend; use TLS_CERT_VERIFY_CALLBACK_WOLFSSL");

	return -ENOTSUP;
}
#elif defined(CONFIG_NET_SOCKETS_TLS_CERT_VERIFY_CALLBACK)
static int tls_opt_cert_verify_callback_set(struct tls_context *context,
					    const void *optval,
					    socklen_t optlen)
{
	struct tls_cert_verify_cb *cert_verify;

	if (!optval) {
		return -EINVAL;
	}

	if (optlen != sizeof(struct tls_cert_verify_cb)) {
		return -EINVAL;
	}

	cert_verify = (struct tls_cert_verify_cb *)optval;
	if (cert_verify->cb == NULL) {
		return -EINVAL;
	}

	context->options.cert_verify = *cert_verify;

	return 0;
}
#else /* CONFIG_NET_SOCKETS_TLS_CERT_VERIFY_CALLBACK */
static int tls_opt_cert_verify_callback_set(struct tls_context *context,
					    const void *optval,
					    socklen_t optlen)
{
	NET_ERR("TLS_CERT_VERIFY_CALLBACK option requires "
		"CONFIG_NET_SOCKETS_TLS_CERT_VERIFY_CALLBACK enabled");

	return -ENOPROTOOPT;
}
#endif /* CONFIG_NET_SOCKETS_TLS_CERT_VERIFY_CALLBACK */

#if defined(CONFIG_WOLFSSL_VERIFY_CALLBACK)
static int tls_opt_cert_verify_callback_wolfssl_set(struct tls_context *context,
						    const void *optval,
						    socklen_t optlen)
{
	struct tls_cert_verify_cb_wolfssl *wolfssl_cb;

	if (!optval) {
		return -EINVAL;
	}

	if (optlen != sizeof(struct tls_cert_verify_cb_wolfssl)) {
		return -EINVAL;
	}

	wolfssl_cb = (struct tls_cert_verify_cb_wolfssl *)optval;
	if (wolfssl_cb->cb == NULL) {
		return -EINVAL;
	}

	context->options.cert_verify_wolfssl = *wolfssl_cb;

	if (context->wssl != NULL) {
		return tls_wolfssl_set_verify(context);
	}

	return 0;
}
#endif /* CONFIG_WOLFSSL_VERIFY_CALLBACK */

static int protocol_check(int family, int type, int *proto)
{
	if (family != AF_INET && family != AF_INET6) {
		return -EAFNOSUPPORT;
	}

	if (*proto >= IPPROTO_TLS_1_0 && *proto <= IPPROTO_TLS_1_3) {
		if (type != SOCK_STREAM) {
			return -EPROTOTYPE;
		}

		*proto = IPPROTO_TCP;
	} else if (*proto >= IPPROTO_DTLS_1_0 && *proto <= IPPROTO_DTLS_1_2) {
		if (!IS_ENABLED(CONFIG_NET_SOCKETS_ENABLE_DTLS)) {
			return -EPROTONOSUPPORT;
		}

		if (type != SOCK_DGRAM) {
			return -EPROTOTYPE;
		}

		*proto = IPPROTO_UDP;
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
	ctx->type = (proto == IPPROTO_TCP) ? SOCK_STREAM : SOCK_DGRAM;
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
	int ret, err = 0;

	/* Try to send close notification. */
	ctx->flags = 0;

#if defined(CONFIG_MBEDTLS)
	(void)mbedtls_ssl_close_notify(&ctx->ssl);
#endif /* CONFIG_MBEDTLS */

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

int ztls_connect_ctx(struct tls_context *ctx, const struct sockaddr *addr,
		     socklen_t addrlen)
{
	int ret;
	int sock_flags;
	bool is_non_block;

#if defined(CONFIG_WOLFSSL)
	if (ctx->accepted) {
		errno = EISCONN;
		return -1;
	}
#endif /* CONFIG_WOLFSSL */

	sock_flags = zsock_fcntl(ctx->sock, F_GETFL, 0);
	if (sock_flags < 0) {
		return -EIO;
	}

	is_non_block = sock_flags & O_NONBLOCK;
	if (is_non_block) {
		(void)zsock_fcntl(ctx->sock, F_SETFL,
				  sock_flags & ~O_NONBLOCK);
	}

	ret = zsock_connect(ctx->sock, addr, addrlen);
	if (ret < 0) {
		return ret;
	}

	if (is_non_block) {
		(void)zsock_fcntl(ctx->sock, F_SETFL, sock_flags);
	}

#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
	if (ctx->type == SOCK_DGRAM) {
		dtls_peer_address_set(ctx, addr, addrlen);
	}
#endif

	if (ctx->type == SOCK_STREAM
#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
	    || (ctx->type == SOCK_DGRAM && ctx->options.dtls_handshake_on_connect)
#endif
	    ) {
		ret = tls_backend_init(ctx, false);
		if (ret < 0) {
			goto error;
		}

		/* Do not use any socket flags during the handshake. */
		ctx->flags = 0;

		tls_session_restore(ctx, addr, addrlen);

		/* TODO For simplicity, TLS handshake blocks the socket
		 * even for non-blocking socket.
		 */
		ret = tls_backend_handshake(
			ctx, K_MSEC(CONFIG_NET_SOCKETS_CONNECT_TIMEOUT));
		if (ret < 0) {
			if ((ret == -EAGAIN) && !is_non_block) {
				ret = -ETIMEDOUT;
			}

			goto error;
		}

		tls_session_store(ctx, addr, addrlen);
	}

	return 0;

error:
	errno = -ret;
	return -1;
}

int ztls_accept_ctx(struct tls_context *parent, struct sockaddr *addr,
		    socklen_t *addrlen)
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
	child->accepted = true;
#endif /* CONFIG_WOLFSSL */

#if defined(CONFIG_WOLFSSL) && !defined(SINGLE_THREADED)
	/* Without locking, wolfSSL cannot count references across threads */
	ret = tls_wolfssl_ctx_share(parent, child);
	if (ret < 0) {
		goto error;
	}
#endif /* CONFIG_WOLFSSL && !SINGLE_THREADED */

	ret = tls_backend_init(child, true);
	if (ret < 0) {
		goto error;
	}

	/* Do not use any socket flags during the handshake. */
	child->flags = 0;

	/* TODO For simplicity, TLS handshake blocks the socket even for
	 * non-blocking socket.
	 */
	ret = tls_backend_handshake(
		child, K_MSEC(CONFIG_NET_SOCKETS_CONNECT_TIMEOUT));
#if defined(CONFIG_WOLFSSL)
	tls_wolfssl_drop_chain_cas(child, parent);
#endif /* CONFIG_WOLFSSL */
	if (ret < 0) {
		goto error;
	}

	return fd;

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

	if (ctx->session_closed) {
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
		ret = mbedtls_ssl_write(&ctx->ssl, buf, len);
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
			ret = tls_mbedtls_reset(ctx);
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

#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
static ssize_t sendto_dtls_client(struct tls_context *ctx, const void *buf,
				  size_t len, int flags,
				  const struct sockaddr *dest_addr,
				  socklen_t addrlen)
{
	int ret;

	if (!dest_addr) {
		/* No address provided, check if we have stored one,
		 * otherwise return error.
		 */
		if (ctx->dtls_peer_addrlen == 0) {
			ret = -EDESTADDRREQ;
			goto error;
		}
	} else if (ctx->dtls_peer_addrlen == 0) {
		/* Address provided and no peer address stored. */
		dtls_peer_address_set(ctx, dest_addr, addrlen);
	} else if (!dtls_is_peer_addr_valid(ctx, dest_addr, addrlen) != 0) {
		/* Address provided but it does not match stored one */
		ret = -EISCONN;
		goto error;
	}

	if (!ctx->is_initialized) {
		ret = tls_backend_init(ctx, false);
		if (ret < 0) {
			goto error;
		}
	}

	if (!is_handshake_complete(ctx)) {
		tls_session_restore(ctx, &ctx->dtls_peer_addr,
				    ctx->dtls_peer_addrlen);

		/* TODO For simplicity, TLS handshake blocks the socket even for
		 * non-blocking socket.
		 * DTLS handshake timeout/retransmissions are limited by
		 * the TLS library, so K_FOREVER is fine here, the function will not
		 * block indefinitely.
		 */
		ret = tls_backend_handshake(ctx, K_FOREVER);
		if (ret < 0) {
			goto error;
		}

		/* Client socket ready to use again. */
		ctx->error = 0;

		tls_session_store(ctx, &ctx->dtls_peer_addr,
				  ctx->dtls_peer_addrlen);
	}

	return send_tls(ctx, buf, len, flags);

error:
	errno = -ret;
	return -1;
}

static ssize_t sendto_dtls_server(struct tls_context *ctx, const void *buf,
				  size_t len, int flags,
				  const struct sockaddr *dest_addr,
				  socklen_t addrlen)
{
	/* For DTLS server, require to have established DTLS connection
	 * in order to send data.
	 */
	if (!is_handshake_complete(ctx)) {
		errno = ENOTCONN;
		return -1;
	}

	/* Verify we are sending to a peer that we have connection with. */
	if (dest_addr &&
	    !dtls_is_peer_addr_valid(ctx, dest_addr, addrlen) != 0) {
		errno = EISCONN;
		return -1;
	}

	return send_tls(ctx, buf, len, flags);
}
#endif /* CONFIG_NET_SOCKETS_ENABLE_DTLS */

ssize_t ztls_sendto_ctx(struct tls_context *ctx, const void *buf, size_t len,
			int flags, const struct sockaddr *dest_addr,
			socklen_t addrlen)
{
	ctx->flags = flags;

	/* TLS */
	if (ctx->type == SOCK_STREAM) {
		return send_tls(ctx, buf, len, flags);
	}

#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
	/* DTLS */
	if (ctx->options.role == ZTLS_IS_SERVER) {
		return sendto_dtls_server(ctx, buf, len, flags,
					  dest_addr, addrlen);
	}

	return sendto_dtls_client(ctx, buf, len, flags, dest_addr, addrlen);
#else
	errno = ENOTSUP;
	return -1;
#endif /* CONFIG_NET_SOCKETS_ENABLE_DTLS */
}

static ssize_t dtls_sendmsg_merge_and_send(struct tls_context *ctx,
					   const struct msghdr *msg,
					   int flags)
{
	static K_MUTEX_DEFINE(sendmsg_lock);
	static uint8_t sendmsg_buf[DTLS_SENDMSG_BUF_SIZE];
	ssize_t len = 0;

	k_mutex_lock(&sendmsg_lock, K_FOREVER);

	for (int i = 0; i < msg->msg_iovlen; i++) {
		struct iovec *vec = msg->msg_iov + i;

		if (vec->iov_len > 0) {
			if (len + vec->iov_len > sizeof(sendmsg_buf)) {
				k_mutex_unlock(&sendmsg_lock);
				errno = EMSGSIZE;
				return -1;
			}

			memcpy(sendmsg_buf + len, vec->iov_base, vec->iov_len);
			len += vec->iov_len;
		}
	}

	if (len > 0) {
		len = ztls_sendto_ctx(ctx, sendmsg_buf, len, flags,
				      msg->msg_name, msg->msg_namelen);
	}

	k_mutex_unlock(&sendmsg_lock);

	return len;
}

static ssize_t tls_sendmsg_loop_and_send(struct tls_context *ctx,
					 const struct msghdr *msg,
					 int flags)
{
	ssize_t len = 0;
	ssize_t ret;

	for (int i = 0; i < msg->msg_iovlen; i++) {
		struct iovec *vec = msg->msg_iov + i;
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

ssize_t ztls_sendmsg_ctx(struct tls_context *ctx, const struct msghdr *msg,
			 int flags)
{
	if (msg == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (IS_ENABLED(CONFIG_NET_SOCKETS_ENABLE_DTLS) &&
	    ctx->type == SOCK_DGRAM) {
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
		 * Current mbedTLS API (i.e. mbedtls_ssl_write()) allows only to send a single
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

	if (ctx->session_closed) {
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

		ret = mbedtls_ssl_read(&ctx->ssl, (uint8_t *)buf + recv_len,
				       read_len);
		if (ret < 0) {
			if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
				/* Peer notified that it's closing the
				 * connection.
				 */
				ctx->session_closed = true;
				break;
			}

			if (ret == MBEDTLS_ERR_SSL_CLIENT_RECONNECT) {
				/* Client reconnect on the same socket is not
				 * supported. See mbedtls_ssl_read API
				 * documentation.
				 */
				ctx->session_closed = true;
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
static ssize_t recvfrom_dtls_common(struct tls_context *ctx, void *buf,
				    size_t max_len, int flags,
				    struct sockaddr *src_addr,
				    socklen_t *addrlen)
{
	int ret;
	bool is_block = is_blocking(ctx->sock, flags);
	k_timeout_t timeout;
	k_timepoint_t end;
	int remaining;
	uint8_t zero_len_buf;

	if (ctx->error != 0) {
		return -ctx->error;
	}

	if (ctx->recv_eof) {
		return 0;
	}

	if (buf == NULL && max_len == 0) {
		buf = &zero_len_buf;
	}

	if (!is_block) {
		timeout = K_NO_WAIT;
	} else {
		timeout = ctx->options.timeout_rx;
	}

	end = sys_timepoint_calc(timeout);

	do {
		byte dummy[128];

		ret = wolfSSL_read(ctx->wssl, buf,
				   (int)MIN(max_len, (size_t)INT_MAX));
		/* wolfSSL_read() returns 0 for a close_notify */
		if (ret <= 0) {
			int err;

			/* A local read shutdown raced this recv(); a DTLS read is one datagram */
			if (ctx->recv_eof) {
				return 0;
			}

			err = wolfSSL_get_error(ctx->wssl, ret);

			if (err == WOLFSSL_ERROR_WANT_READ ||
			    err == WOLFSSL_ERROR_WANT_WRITE) {
				k_timepoint_t wait_end = end;

				if (dtls_wolf_peer_expired(ctx)) {
					return -ETIMEDOUT;
				}

				if (ctx->options.role == ZTLS_IS_SERVER &&
				    sys_timepoint_cmp(ctx->dtls_rx_expiry, end) < 0) {
					wait_end = ctx->dtls_rx_expiry;
				}

				ret = tls_wolfssl_wait_rx(ctx, is_block, wait_end, err);
				if (ret >= 0 || (ret == -EAGAIN && !sys_timepoint_expired(end))) {
					continue;
				}

				return ret;
			}

			if (tls_wolfssl_peer_closed(ctx, err)) {
				return -ENOTCONN;
			}

			if (ret == 0 && err == WOLFSSL_ERROR_NONE) {
				/* An empty datagram is a 0-byte receive */
				return 0;
			}

			/* A peek absorbed a fatal alert and reset the server session */
			if (err == BUFFER_ERROR &&
			    ctx->options.role == ZTLS_IS_SERVER) {
				return -EAGAIN;
			}

			return -EIO;
		}

		if (src_addr && addrlen) {
			dtls_peer_address_get(ctx, src_addr, addrlen);
		}

		remaining = wolfSSL_pending(ctx->wssl);

		/* No more data in the datagram, or dummy read. */
		if ((remaining == 0) || (max_len == 0)) {
			return ret;
		}

		if (flags & ZSOCK_MSG_TRUNC) {
			ret += remaining;
		}

		/* Always drain remaining datagram data */
		while (remaining > 0) {
			int to_read = MIN(remaining, sizeof(dummy));
			int r = wolfSSL_read(ctx->wssl, dummy, to_read);

			if (r <= 0) {
				NET_ERR("Error while flushing the rest of the"
					" datagram, err %d", r);
				ret = -EIO;
				break;
			}
			remaining -= r;
		}
		wc_ForceZero(dummy, sizeof(dummy));

		return ret;
	} while (true);
}

static ssize_t recvfrom_dtls_client(struct tls_context *ctx, void *buf,
				    size_t max_len, int flags,
				    struct sockaddr *src_addr,
				    socklen_t *addrlen)
{
	int ret;

	if (!is_handshake_complete(ctx)) {
		ret = -ENOTCONN;
		goto error;
	}

	ret = recvfrom_dtls_common(ctx, buf, max_len, flags, src_addr, addrlen);
	if (ret >= 0) {
		return ret;
	}

	if (ret == -EAGAIN) {
		goto error;
	}

	if (ret != -ENOTCONN) {
		NET_ERR("DTLS client recv error: %d", ret);
		ret = -ECONNABORTED;
	}

	if (tls_wolfssl_reset(ctx) != 0) {
		ret = -ENOMEM;
	}

	ctx->error = -ret;

error:
	errno = -ret;
	return -1;
}

static ssize_t recvfrom_dtls_server(struct tls_context *ctx, void *buf,
				    size_t max_len, int flags,
				    struct sockaddr *src_addr,
				    socklen_t *addrlen)
{
	int ret;
	bool repeat;
	k_timeout_t timeout;

	/* A handshake would only read the same EOF again */
	if (ctx->recv_eof) {
		return 0;
	}

	if (!is_blocking(ctx->sock, flags)) {
		timeout = K_NO_WAIT;
	} else {
		timeout = ctx->options.timeout_rx;
	}

	do {
		repeat = false;

		if (!ctx->is_initialized) {
			ret = tls_wolfssl_init(ctx, true);
			if (ret < 0) {
				goto error;
			}
		}

		if (!is_handshake_complete(ctx)) {
			ret = tls_wolfssl_handshake(ctx, timeout);
			if (ret < 0) {
				/* In case of EAGAIN, just exit. */
				if (ret == -EAGAIN) {
					break;
				}

				ret = tls_wolfssl_reset(ctx);
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

		ret = recvfrom_dtls_common(ctx, buf, max_len, flags,
					   src_addr, addrlen);
		if (ret >= 0) {
			return ret;
		}

		if (ret == -ETIMEDOUT) {
			(void)wolfSSL_shutdown(ctx->wssl);
		}

		if (ret == -ENOTCONN || ret == -ETIMEDOUT) {
			ret = tls_wolfssl_reset(ctx);
			if (ret == 0) {
				repeat = true;
			} else {
				ctx->error = ENOMEM;
				ret = -ENOMEM;
			}
			continue;
		}
		if (ret == -EAGAIN) {
			break;
		}

		NET_ERR("DTLS server recv error: %d", ret);

		if (tls_wolfssl_reset(ctx) != 0) {
			ctx->error = ENOMEM;
			ret = -ENOMEM;
		} else {
			ctx->error = ECONNABORTED;
			ret = -ECONNABORTED;
		}
		break;
	} while (repeat);

error:
	errno = -ret;
	return -1;
}
#endif /* CONFIG_WOLFSSL && CONFIG_NET_SOCKETS_ENABLE_DTLS */

#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS) && defined(CONFIG_MBEDTLS)
static ssize_t recvfrom_dtls_common(struct tls_context *ctx, void *buf,
				    size_t max_len, int flags,
				    struct sockaddr *src_addr,
				    socklen_t *addrlen)
{
	int ret;
	bool is_block = is_blocking(ctx->sock, flags);
	k_timeout_t timeout;
	k_timepoint_t end;

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

		ret = mbedtls_ssl_read(&ctx->ssl, buf, max_len);
		if (ret < 0) {
			if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
			    ret == MBEDTLS_ERR_SSL_WANT_WRITE ||
			    ret == MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS ||
			    ret ==  MBEDTLS_ERR_SSL_CRYPTO_IN_PROGRESS) {
				int timeout_dtls, timeout_sock, timeout_ms;

				if (!is_block) {
					return ret;
				}

				/* Blocking timeout. */
				timeout = sys_timepoint_timeout(end);
				if (K_TIMEOUT_EQ(timeout, K_NO_WAIT)) {
					return ret;
				}

				timeout_dtls = dtls_get_remaining_timeout(ctx);
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
			dtls_peer_address_get(ctx, src_addr, addrlen);
		}

		/* mbedtls_ssl_get_bytes_avail() indicate the data length
		 * remaining in the current datagram.
		 */
		remaining = mbedtls_ssl_get_bytes_avail(&ctx->ssl);

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

			err = mbedtls_ssl_read(&ctx->ssl, &byte, sizeof(byte));
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
				    struct sockaddr *src_addr,
				    socklen_t *addrlen)
{
	int ret;

	if (!is_handshake_complete(ctx)) {
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
		ret = tls_mbedtls_reset(ctx);
		if (ret == 0) {
			ctx->error = ENOTCONN;
			ret = -ENOTCONN;
		} else {
			ctx->error = ENOMEM;
			ret = -ENOMEM;
		}
		break;

	case MBEDTLS_ERR_SSL_TIMEOUT:
		(void)mbedtls_ssl_close_notify(&ctx->ssl);
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
		ret = tls_mbedtls_reset(ctx);
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
				    struct sockaddr *src_addr,
				    socklen_t *addrlen)
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
		repeat = false;

		if (!is_handshake_complete(ctx)) {
			ret = tls_mbedtls_handshake(ctx, timeout);
			if (ret < 0) {
				/* In case of EAGAIN, just exit. */
				if (ret == -EAGAIN) {
					break;
				}

				ret = tls_mbedtls_reset(ctx);
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

		ret = recvfrom_dtls_common(ctx, buf, max_len, flags,
					   src_addr, addrlen);
		if (ret >= 0) {
			return ret;
		}

		switch (ret) {
		case MBEDTLS_ERR_SSL_TIMEOUT:
			(void)mbedtls_ssl_close_notify(&ctx->ssl);
			__fallthrough;
			/* fallthrough */

		case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
		case MBEDTLS_ERR_SSL_CLIENT_RECONNECT:
			ret = tls_mbedtls_reset(ctx);
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
			ret = -EAGAIN;
			break;

		default:
			NET_ERR("DTLS server recv error: -%x", -ret);

			ret = tls_mbedtls_reset(ctx);
			if (ret != 0) {
				ctx->error = ENOMEM;
				errno = ENOMEM;
			} else {
				ctx->error = ECONNABORTED;
				ret = -ECONNABORTED;
			}

			break;
		}
	} while (repeat);

error:
	errno = -ret;
	return -1;
}
#endif /* CONFIG_NET_SOCKETS_ENABLE_DTLS */

ssize_t ztls_recvfrom_ctx(struct tls_context *ctx, void *buf, size_t max_len,
			  int flags, struct sockaddr *src_addr,
			  socklen_t *addrlen)
{
	if (flags & ZSOCK_MSG_PEEK) {
		/* TODO mbedTLS does not support 'peeking' This could be
		 * bypassed by having intermediate buffer for peeking
		 */
		errno = ENOTSUP;
		return -1;
	}

	ctx->flags = flags;

	/* TLS */
	if (ctx->type == SOCK_STREAM) {
		return recv_tls(ctx, buf, max_len, flags);
	}

#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
	/* DTLS */
	if (ctx->options.role == ZTLS_IS_SERVER) {
		return recvfrom_dtls_server(ctx, buf, max_len, flags,
					    src_addr, addrlen);
	}

	return recvfrom_dtls_client(ctx, buf, max_len, flags,
				    src_addr, addrlen);
#else
	errno = ENOTSUP;
	return -1;
#endif /* CONFIG_NET_SOCKETS_ENABLE_DTLS */
}

static size_t tls_bytes_avail(struct tls_context *ctx)
{
#if defined(CONFIG_WOLFSSL)
	return ctx->wssl != NULL ? wolfSSL_pending(ctx->wssl) : 0;
#else
	return mbedtls_ssl_get_bytes_avail(&ctx->ssl);
#endif
}

static int ztls_poll_prepare_pollin(struct tls_context *ctx)
{
	/* If there already is TLS data to read, there is no
	 * need to set the k_poll_event object. Return EALREADY
	 * so we won't block in the k_poll.
	 */
	if (!ctx->is_listening) {
		if (tls_bytes_avail(ctx) > 0) {
			return -EALREADY;
		}
	}

	return 0;
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
	if ((pfd->events & ZSOCK_POLLIN) && (ctx->type == SOCK_DGRAM) &&
	    (ctx->options.role == ZTLS_IS_CLIENT) &&
	    !is_handshake_complete(ctx)) {
		(*pev)->obj = &ctx->tls_established;
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

static int ztls_socket_data_check(struct tls_context *ctx)
{
	int ret;

#if defined(CONFIG_WOLFSSL)
	/* A peek would read the EOF as an error, while recv() reports it as 0 */
	if (ctx->recv_eof) {
		return -ENOTCONN;
	}
#endif

	if (ctx->type == SOCK_STREAM) {
		if (!ctx->is_initialized) {
			return -ENOTCONN;
		}
	}
#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
	else {
		if (!ctx->is_initialized) {
			bool is_server = ctx->options.role == ZTLS_IS_SERVER;

			ret = tls_backend_init(ctx, is_server);
			if (ret < 0) {
				return -ENOMEM;
			}
		}

		if (!is_handshake_complete(ctx)) {
			ret = tls_backend_handshake(ctx, K_NO_WAIT);
			if (ret < 0) {
				if (ret == -EAGAIN) {
					return 0;
				}

				ret = tls_backend_reset(ctx);
				if (ret != 0) {
					return -ENOMEM;
				}

				return 0;
			}

			/* Socket ready to use again. */
			ctx->error = 0;

			return 0;
		}
	}
#endif /* CONFIG_NET_SOCKETS_ENABLE_DTLS */

	ctx->flags = ZSOCK_MSG_DONTWAIT;

#if defined(CONFIG_WOLFSSL)
	/* wolfSSL_peek() returns 0 for a clean close and keeps the reason in ssl->error */
	ret = tls_wolfssl_peek(ctx->wssl);
	if (ret <= 0) {
		int err = wolfSSL_get_error(ctx->wssl, ret);

		if (tls_wolfssl_peer_closed(ctx, err)) {
			if (ctx->type == SOCK_DGRAM) {
				if (tls_wolfssl_reset(ctx) != 0) {
					return -ENOMEM;
				}
			} else {
				ctx->session_closed = true;
			}
			return -ENOTCONN;
		}

		if (err == WOLFSSL_ERROR_WANT_READ ||
		    err == WOLFSSL_ERROR_WANT_WRITE) {
#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
			if (dtls_wolf_peer_expired(ctx)) {
				return tls_wolfssl_reset(ctx) == 0 ? -ENOTCONN : -ENOMEM;
			}
#endif
			return 0;
		}

		NET_ERR("TLS data check error: %d", err);
		if (tls_wolfssl_reset(ctx) != 0) {
			return -ENOMEM;
		}

		return -ECONNABORTED;
	}

	return tls_bytes_avail(ctx);
#else
	ret = mbedtls_ssl_read(&ctx->ssl, NULL, 0);
	if (ret < 0) {
		if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
			/* Don't reset the context for STREAM socket - the
			 * application needs to reopen the socket anyway, and
			 * resetting the context would result in an error instead
			 * of 0 in a consecutive recv() call.
			 */
			if (ctx->type == SOCK_DGRAM) {
				ret = tls_mbedtls_reset(ctx);
				if (ret != 0) {
					return -ENOMEM;
				}
			} else {
				ctx->session_closed = true;
			}

			return -ENOTCONN;
		}

		if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
		    ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
			return 0;
		}

		NET_ERR("TLS data check error: -%x", -ret);

		/* MbedTLS API documentation requires session to
		 * be reset in other error cases
		 */
		if (tls_mbedtls_reset(ctx) != 0) {
			return -ENOMEM;
		}

#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
		if (ret == MBEDTLS_ERR_SSL_TIMEOUT && ctx->type == SOCK_DGRAM) {
			/* DTLS timeout interpreted as closing of connection. */
			return -ENOTCONN;
		}
#endif
		return -ECONNABORTED;
	}

	return mbedtls_ssl_get_bytes_avail(&ctx->ssl);
#endif /* CONFIG_WOLFSSL */
}

static int ztls_poll_update_pollin(int fd, struct tls_context *ctx,
				   struct zsock_pollfd *pfd)
{
	int ret;

	if (!ctx->is_listening) {
		/* Already had TLS data to read on socket. */
		if (tls_bytes_avail(ctx) > 0) {
			pfd->revents |= ZSOCK_POLLIN;
			goto next;
		}
	}

	if (ctx->type == SOCK_STREAM) {
		if (!(pfd->revents & ZSOCK_POLLIN)) {
			/* No new data on a socket. */
			goto next;
		}

		if (ctx->is_listening) {
			goto next;
		}
	}
#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
	else {
		/* Perform data check without incoming data for completed DTLS connections.
		 * This allows the connections to timeout with CONFIG_NET_SOCKETS_DTLS_TIMEOUT.
		 */
		if (!is_handshake_complete(ctx) && !(pfd->revents & ZSOCK_POLLIN)) {
			goto next;
		}
	}
#endif
	ret = ztls_socket_data_check(ctx);

	if (ret == -ENOTCONN || (pfd->revents & ZSOCK_POLLHUP)) {
		/* Datagram does not return 0 on consecutive recv, but an error
		 * code, hence clear POLLIN.
		 */
		if (ctx->type == SOCK_DGRAM) {
			pfd->revents &= ~ZSOCK_POLLIN;
		}
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
	    ((*pev)->obj == &ctx->tls_established)) {
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
	if ((ctx->type != SOCK_DGRAM) ||
	    (ctx->options.role != ZTLS_IS_CLIENT)) {
		return false;
	}

	if (ctx->handshake_in_progress) {
		/* Add some sleep to allow lower priority threads to proceed
		 * with handshake.
		 */
		k_msleep(10);

		pfd->revents &= ~ZSOCK_POLLIN;
		return true;
	} else if (!is_handshake_complete(ctx)) {
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
			void *optval, socklen_t *optlen)
{
	int err;

	if (!optval || !optlen) {
		errno = EINVAL;
		return -1;
	}

	if ((level == SOL_SOCKET) && (optname == SO_PROTOCOL)) {
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
	if ((level == SOL_SOCKET) && (optname == SO_ERROR) && ctx->error != 0) {
		if (*optlen != sizeof(int)) {
			errno = EINVAL;
			return -1;
		}

		*(int *)optval = ctx->error;

		return 0;
	}

	if (level != SOL_TLS) {
		return zsock_getsockopt(ctx->sock, level, optname,
					optval, optlen);
	}

	switch (optname) {
	case TLS_SEC_TAG_LIST:
		err =  tls_opt_sec_tag_list_get(ctx, optval, optlen);
		break;

	case TLS_CIPHERSUITE_LIST:
		err = tls_opt_ciphersuite_list_get(ctx, optval, optlen);
		break;

	case TLS_CIPHERSUITE_USED:
		err = tls_opt_ciphersuite_used_get(ctx, optval, optlen);
		break;

	case TLS_ALPN_LIST:
		err = tls_opt_alpn_list_get(ctx, optval, optlen);
		break;

	case TLS_SESSION_CACHE:
		err = tls_opt_session_cache_get(ctx, optval, optlen);
		break;

	case TLS_CERT_VERIFY_RESULT:
		err = tls_opt_cert_verify_result_get(ctx, optval, optlen);
		break;

#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
	case TLS_DTLS_HANDSHAKE_TIMEOUT_MIN:
		err = tls_opt_dtls_handshake_timeout_get(ctx, optval,
							 optlen, false);
		break;

	case TLS_DTLS_HANDSHAKE_TIMEOUT_MAX:
		err = tls_opt_dtls_handshake_timeout_get(ctx, optval,
							 optlen, true);
		break;

	case TLS_DTLS_CID_STATUS:
		err = tls_opt_dtls_connection_id_status_get(ctx, optval,
							    optlen);
		break;

	case TLS_DTLS_CID_VALUE:
		err = tls_opt_dtls_connection_id_value_get(ctx, optval, optlen);
		break;

	case TLS_DTLS_PEER_CID_VALUE:
		err = tls_opt_dtls_peer_connection_id_value_get(ctx, optval,
								optlen);
		break;

	case TLS_DTLS_HANDSHAKE_ON_CONNECT:
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
			   socklen_t optlen)
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
			const void *optval, socklen_t optlen)
{
	int err;

	/* Underlying socket is used in non-blocking mode, hence implement
	 * timeout at the TLS socket level.
	 */
	if ((level == SOL_SOCKET) && (optname == SO_SNDTIMEO)) {
		err = set_timeout_opt(&ctx->options.timeout_tx, optval, optlen);
		goto out;
	}

	if ((level == SOL_SOCKET) && (optname == SO_RCVTIMEO)) {
		err = set_timeout_opt(&ctx->options.timeout_rx, optval, optlen);
		goto out;
	}

	if (level != SOL_TLS) {
		return zsock_setsockopt(ctx->sock, level, optname,
					optval, optlen);
	}

	switch (optname) {
	case TLS_SEC_TAG_LIST:
		err =  tls_opt_sec_tag_list_set(ctx, optval, optlen);
		break;

	case TLS_HOSTNAME:
		err = tls_opt_hostname_set(ctx, optval, optlen);
		break;

	case TLS_CIPHERSUITE_LIST:
		err = tls_opt_ciphersuite_list_set(ctx, optval, optlen);
		break;

	case TLS_PEER_VERIFY:
		err = tls_opt_peer_verify_set(ctx, optval, optlen);
		break;

	case TLS_CERT_NOCOPY:
		err = tls_opt_cert_nocopy_set(ctx, optval, optlen);
		break;

	case TLS_DTLS_ROLE:
		err = tls_opt_dtls_role_set(ctx, optval, optlen);
		break;

	case TLS_ALPN_LIST:
		err = tls_opt_alpn_list_set(ctx, optval, optlen);
		break;

	case TLS_SESSION_CACHE:
		err = tls_opt_session_cache_set(ctx, optval, optlen);
		break;

	case TLS_SESSION_CACHE_PURGE:
		err = tls_opt_session_cache_purge_set(ctx, optval, optlen);
		break;

	case TLS_CERT_VERIFY_CALLBACK:
		err = tls_opt_cert_verify_callback_set(ctx, optval, optlen);
		break;

#if defined(ZTLS_WOLFSSL_MAX_FRAGMENT)
	case TLS_MAX_FRAGMENT_LENGTH:
		err = tls_opt_mfl_set(ctx, optval, optlen);
		break;
#endif /* ZTLS_WOLFSSL_MAX_FRAGMENT */

#if defined(CONFIG_WOLFSSL_VERIFY_CALLBACK)
	case TLS_CERT_VERIFY_CALLBACK_WOLFSSL:
		err = tls_opt_cert_verify_callback_wolfssl_set(ctx, optval, optlen);
		break;
#endif /* CONFIG_WOLFSSL_VERIFY_CALLBACK */

#if defined(CONFIG_NET_SOCKETS_ENABLE_DTLS)
	case TLS_DTLS_HANDSHAKE_TIMEOUT_MIN:
		err = tls_opt_dtls_handshake_timeout_set(ctx, optval,
							 optlen, false);
		break;

	case TLS_DTLS_HANDSHAKE_TIMEOUT_MAX:
		err = tls_opt_dtls_handshake_timeout_set(ctx, optval,
							 optlen, true);
		break;

	case TLS_DTLS_CID:
		err = tls_opt_dtls_connection_id_set(ctx, optval, optlen);
		break;

	case TLS_DTLS_CID_VALUE:
		err = tls_opt_dtls_connection_id_value_set(ctx, optval, optlen);
		break;

	case TLS_DTLS_HANDSHAKE_ON_CONNECT:
		err = tls_opt_dtls_handshake_on_connect_set(ctx, optval, optlen);
		break;

#endif /* CONFIG_NET_SOCKETS_ENABLE_DTLS */

	case TLS_NATIVE:
		/* Option handled at the socket dispatcher level. */
		err = 0;
		break;

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

	return ctx->wssl;
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

	return &ctx->ssl;
}
#endif /* CONFIG_WOLFSSL */
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
	case F_GETFL:
	case F_SETFL: {
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
	/* Only a successful shutdown closes the read side */
	if (ret == 0 && (how == ZSOCK_SHUT_RD || how == ZSOCK_SHUT_RDWR)) {
		ctx->recv_eof = true;
	}
#endif

	return ret;
}

static int tls_sock_bind_vmeth(void *obj, const struct sockaddr *addr,
			       socklen_t addrlen)
{
	struct tls_context *ctx = obj;

	return zsock_bind(ctx->sock, addr, addrlen);
}

static int tls_sock_connect_vmeth(void *obj, const struct sockaddr *addr,
				  socklen_t addrlen)
{
	return ztls_connect_ctx(obj, addr, addrlen);
}

static int tls_sock_listen_vmeth(void *obj, int backlog)
{
	struct tls_context *ctx = obj;

	ctx->is_listening = true;

	return zsock_listen(ctx->sock, backlog);
}

static int tls_sock_accept_vmeth(void *obj, struct sockaddr *addr,
				 socklen_t *addrlen)
{
	return ztls_accept_ctx(obj, addr, addrlen);
}

static ssize_t tls_sock_sendto_vmeth(void *obj, const void *buf, size_t len,
				     int flags,
				     const struct sockaddr *dest_addr,
				     socklen_t addrlen)
{
	return ztls_sendto_ctx(obj, buf, len, flags, dest_addr, addrlen);
}

static ssize_t tls_sock_sendmsg_vmeth(void *obj, const struct msghdr *msg,
				      int flags)
{
	return ztls_sendmsg_ctx(obj, msg, flags);
}

static ssize_t tls_sock_recvfrom_vmeth(void *obj, void *buf, size_t max_len,
				       int flags, struct sockaddr *src_addr,
				       socklen_t *addrlen)
{
	return ztls_recvfrom_ctx(obj, buf, max_len, flags,
				 src_addr, addrlen);
}

static int tls_sock_getsockopt_vmeth(void *obj, int level, int optname,
				     void *optval, socklen_t *optlen)
{
	return ztls_getsockopt_ctx(obj, level, optname, optval, optlen);
}

static int tls_sock_setsockopt_vmeth(void *obj, int level, int optname,
				     const void *optval, socklen_t optlen)
{
	return ztls_setsockopt_ctx(obj, level, optname, optval, optlen);
}

static int tls_sock_close2_vmeth(void *obj, int sock)
{
	return ztls_close_ctx(obj, sock);
}

static int tls_sock_getpeername_vmeth(void *obj, struct sockaddr *addr,
				      socklen_t *addrlen)
{
	struct tls_context *ctx = obj;

	return zsock_getpeername(ctx->sock, addr, addrlen);
}

static int tls_sock_getsockname_vmeth(void *obj, struct sockaddr *addr,
				      socklen_t *addrlen)
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
 * create sockets for secure protocols. Every other call for AF_INET/AF_INET6
 * will be forwarded to regular socket implementation.
 */
BUILD_ASSERT(CONFIG_NET_SOCKETS_TLS_PRIORITY < CONFIG_NET_SOCKETS_PRIORITY_DEFAULT,
	     "CONFIG_NET_SOCKETS_TLS_PRIORITY have to be smaller than CONFIG_NET_SOCKETS_PRIORITY_DEFAULT");

NET_SOCKET_REGISTER(tls, CONFIG_NET_SOCKETS_TLS_PRIORITY, AF_UNSPEC,
		    tls_is_supported, ztls_socket);
