#include "internal.h"

#include <stdio.h>
#include <errno.h>
#include <string.h>

#include <exec/types.h>
#include <exec/libraries.h>

#include <proto/exec.h>
#include <proto/utility.h>
#include <proto/alib.h>

static struct Library *AmiAPIUtilityBase = NULL;
static struct Library *AmiAPISocketBase = NULL;
#define BSDSOCKET_BASE_NAME AmiAPISocketBase
#include <proto/bsdsocket.h>

#include <proto/amisslmaster.h>
#include <proto/amissl.h>

#include <libraries/amisslmaster.h>
#include <amissl/tags.h>

#include <netdb.h>
#include <sys/socket.h>
#include <sys/filio.h>
#include <netinet/in.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>

#ifndef AMIAPI_TLS_DEBUG
#define AMIAPI_TLS_DEBUG 0
#endif

#if AMIAPI_TLS_DEBUG
#define TLS_DEBUG(...) printf(__VA_ARGS__)
#else
#define TLS_DEBUG(...) ((void)0)
#endif

static const char amiga_stack_cookie[]
    __attribute__((used)) = "$STACK:65536";

static struct Library *AmiAPIMasterBase = NULL;
static struct Library *AmiAPIAmiSSLBase = NULL;

struct Library *AmiSSLMasterBase = NULL;
struct Library *AmiSSLBase = NULL;

/*
 * AmiSSL is initialized lazily.  This lets plain HTTP continue to use
 * only bsdsocket.library.
 */
static int amiapi_amissl_initialized = 0;

static void generate_random_seed(
    unsigned char *buffer,
    int size)
{
    int i;

    for (i = 0; i < size / 2; ++i) {
        ((UWORD *)buffer)[i] = RangeRand(65535);
    }
}

static enum AmiAPIError open_socket_library(void)
{
    if (AmiAPISocketBase)
        return AMIAPI_OK;

    AmiAPISocketBase = OpenLibrary("bsdsocket.library", 4);

    return AmiAPISocketBase
        ? AMIAPI_OK
        : AMIAPI_ERR_SOCKET_LIBRARY;
}

static enum AmiAPIError open_amissl(void)
{
    enum AmiAPIError err;

    if (amiapi_amissl_initialized)
        return AMIAPI_OK;

    if (!AmiAPIUtilityBase) {
        AmiAPIUtilityBase = OpenLibrary(
            "utility.library",
            0
        );

        if (!AmiAPIUtilityBase)
            return AMIAPI_ERR_CONNECT;
    }

    err = open_socket_library();
    if (err != AMIAPI_OK)
        return err;

    AmiAPIMasterBase = OpenLibrary(
        "amisslmaster.library",
        AMISSLMASTER_MIN_VERSION
    );

    if (!AmiAPIMasterBase)
        return AMIAPI_ERR_CONNECT;

    /*
     * AmiSSL inline/stub interfaces expect these conventional globals.
     */
    AmiSSLMasterBase = AmiAPIMasterBase;

    if (!InitAmiSSLMaster(
            AMISSL_CURRENT_VERSION,
            TRUE))
        goto fail;

    AmiAPIAmiSSLBase = OpenAmiSSL();

    if (!AmiAPIAmiSSLBase)
        goto fail;

    AmiSSLBase = AmiAPIAmiSSLBase;

    if (InitAmiSSL(
            AmiSSL_ErrNoPtr, (ULONG)&errno,
            AmiSSL_SocketBase, (ULONG)AmiAPISocketBase,
            TAG_DONE) != 0)
        goto fail;

    if (!OPENSSL_init_ssl(
            OPENSSL_INIT_SSL_DEFAULT |
            OPENSSL_INIT_ADD_ALL_CIPHERS |
            OPENSSL_INIT_ADD_ALL_DIGESTS,
            NULL))
        goto fail_initialized;

    {
        unsigned char seed[128];

        generate_random_seed(
            seed,
            (int)sizeof(seed)
        );

        RAND_seed(
            seed,
            (int)sizeof(seed)
        );

        memset(seed, 0, sizeof(seed));
    }

    amiapi_amissl_initialized = 1;
    return AMIAPI_OK;

fail_initialized:
    CleanupAmiSSLA(NULL);

fail:
    if (AmiAPIAmiSSLBase) {
        CloseAmiSSL();
        AmiAPIAmiSSLBase = NULL;
        AmiSSLBase = NULL;
    }

    if (AmiAPIMasterBase) {
        CloseLibrary(AmiAPIMasterBase);
        AmiAPIMasterBase = NULL;
        AmiSSLMasterBase = NULL;
    }

    return AMIAPI_ERR_CONNECT;
}

enum AmiAPIError amiapi_transport_prepare_tls(void)
{
    return open_amissl();
}

static int wait_socket_ready(
    struct AmiAPITransport *t,
    int want_read,
    int want_write)
{
    fd_set read_fds;
    fd_set write_fds;
    struct __timeval timeout;
    struct __timeval *timeout_ptr;
    LONG rc;

    if (!t || t->fd < 0)
        return -1;

    FD_ZERO(&read_fds);
    FD_ZERO(&write_fds);

    if (want_read)
        FD_SET(t->fd, &read_fds);

    if (want_write)
        FD_SET(t->fd, &write_fds);

    if (t->timeout_seconds != 0) {
        timeout.tv_sec = (LONG)t->timeout_seconds;
        timeout.tv_usec = 0;
        timeout_ptr = &timeout;
    }
    else {
        timeout_ptr = NULL;
    }

    rc = WaitSelect(
        t->fd + 1,
        want_read ? (APTR)&read_fds : NULL,
        want_write ? (APTR)&write_fds : NULL,
        NULL,
        timeout_ptr,
        NULL
    );

    if (rc < 0)
        return -1;

    if (rc == 0)
        return 0;

    return 1;
}


static int socket_would_block(void)
{
    LONG error;

    error = Errno();

#ifdef EWOULDBLOCK
    if (error == EWOULDBLOCK)
        return 1;
#endif

#ifdef EAGAIN
    if (error == EAGAIN)
        return 1;
#endif

    return 0;
}


static int wait_for_ssl(
    struct AmiAPITransport *t,
    int ssl_error)
{
    if (!t)
        return -1;

    if (ssl_error == SSL_ERROR_WANT_READ) {
        return wait_socket_ready(
            t,
            1,
            0
        );
    }

    if (ssl_error == SSL_ERROR_WANT_WRITE) {
        return wait_socket_ready(
            t,
            0,
            1
        );
    }

    return -1;
}


static enum AmiAPIError set_socket_nonblocking(
    struct AmiAPITransport *t)
{
    LONG enabled;

    if (!t || t->fd < 0)
        return AMIAPI_ERR_INVALID_ARGUMENT;

    enabled = 1;

    if (IoctlSocket(
            t->fd,
            FIONBIO,
            &enabled) != 0)
    {
        return AMIAPI_ERR_CONNECT;
    }

    return AMIAPI_OK;
}


enum AmiAPIError amiapi_transport_connect(
    struct AmiAPITransport *t,
    const char *host,
    unsigned short port)
{
    struct hostent *h;
    struct sockaddr_in a;
    enum AmiAPIError e;
    int fd;

    if (!t || !host)
        return AMIAPI_ERR_CONNECT;

    t->fd = -1;
    t->tls_ctx = NULL;
    t->tls_ssl = NULL;
    t->use_tls = 0;

    e = open_socket_library();
    if (e != AMIAPI_OK)
        return e;

    h = (struct hostent *)gethostbyname((STRPTR)host);
    if (!h || !h->h_addr_list || !h->h_addr_list[0])
        return AMIAPI_ERR_DNS;

    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(port);

    memcpy(
        &a.sin_addr,
        h->h_addr_list[0],
        sizeof(a.sin_addr)
    );

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return AMIAPI_ERR_CONNECT;

    /*
     * A blocking connect() can otherwise stall for the TCP stack's
     * own timeout, ignoring AmiAPI's configured request timeout.
     *
     * Put the socket into nonblocking mode before connect(), then
     * use WaitSelect() to enforce the AmiAPI timeout.
     */
    t->fd = fd;

    e = set_socket_nonblocking(t);
    if (e != AMIAPI_OK) {
        CloseSocket(fd);
        t->fd = -1;
        return e;
    }

    if (connect(
            fd,
            (struct sockaddr *)&a,
            sizeof(a)) < 0)
    {
        LONG error;

        error = Errno();

        if (error != EINPROGRESS &&
            error != EWOULDBLOCK &&
            error != EAGAIN &&
            error != EALREADY)
        {
            CloseSocket(fd);
            t->fd = -1;
            return AMIAPI_ERR_CONNECT;
        }

        /*
         * A nonblocking connect completes by making the socket
         * writable.  Writability alone does not mean success:
         * SO_ERROR must be checked afterwards.
         */
        if (wait_socket_ready(
                t,
                0,
                1) <= 0)
        {
            CloseSocket(fd);
            t->fd = -1;
            return AMIAPI_ERR_CONNECT;
        }

        {
            LONG socket_error;
            socklen_t socket_error_size;

            socket_error = 0;
            socket_error_size = sizeof(socket_error);

            if (getsockopt(
                    fd,
                    SOL_SOCKET,
                    SO_ERROR,
                    &socket_error,
                    &socket_error_size) != 0 ||
                socket_error != 0)
            {
                CloseSocket(fd);
                t->fd = -1;
                return AMIAPI_ERR_CONNECT;
            }
        }
    }

    return AMIAPI_OK;
}

enum AmiAPIError amiapi_transport_start_tls(
    struct AmiAPITransport *t,
    const char *host)
{
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    enum AmiAPIError err;
    int rc;

    if (!t || t->fd < 0 || !host)
        return AMIAPI_ERR_CONNECT;

    TLS_DEBUG("TLS: initializing AmiSSL\n");

    err = open_amissl();
    if (err != AMIAPI_OK) {
        printf("TLS: open_amissl failed: %d\n", (int)err);
        return err;
    }

    TLS_DEBUG("TLS: SSL_CTX_new\n");

    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        unsigned long e = ERR_get_error();
        printf("TLS: SSL_CTX_new failed ERR=%08lx\n", e);
        return AMIAPI_ERR_CONNECT;
    }

    rc = SSL_CTX_set_default_verify_paths(ctx);
    TLS_DEBUG("TLS: default verify paths rc=%d\n", rc);

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    TLS_DEBUG("TLS: SSL_new\n");

    ssl = SSL_new(ctx);
    if (!ssl) {
        unsigned long e = ERR_get_error();
        printf("TLS: SSL_new failed ERR=%08lx\n", e);
        SSL_CTX_free(ctx);
        return AMIAPI_ERR_CONNECT;
    }

    rc = SSL_set_fd(ssl, t->fd);
    TLS_DEBUG("TLS: SSL_set_fd rc=%d\n", rc);

    if (rc != 1)
        goto fail;

    rc = SSL_set_tlsext_host_name(ssl, host);
    TLS_DEBUG("TLS: SNI rc=%d\n", rc);

    if (rc != 1)
        goto fail;

    /*
     * SSL_VERIFY_PEER only checks the chain.  Also require the certificate
     * to be valid for this hostname, as transport_posix.c does.
     */
    {
        X509_VERIFY_PARAM *param = SSL_get0_param(ssl);

        if (param == NULL)
            goto fail;

        X509_VERIFY_PARAM_set_hostflags(
            param,
            X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS
        );

        if (X509_VERIFY_PARAM_set1_host(param, host, 0) != 1)
            goto fail;
    }

    TLS_DEBUG("TLS: SSL_connect\n");

    for (;;) {
        int ssl_err;
        int ready;

        rc = SSL_connect(ssl);

        TLS_DEBUG("TLS: SSL_connect rc=%d\n", rc);

        if (rc == 1)
            break;

        ssl_err = SSL_get_error(ssl, rc);

        if (ssl_err == SSL_ERROR_WANT_READ ||
            ssl_err == SSL_ERROR_WANT_WRITE)
        {
            ready = wait_for_ssl(
                t,
                ssl_err
            );

            if (ready > 0)
                continue;
        }

        {
            unsigned long e = ERR_get_error();

            printf(
                "TLS: handshake failed "
                "SSL_get_error=%d ERR=%08lx errno=%d\n",
                ssl_err,
                e,
                errno
            );
        }

        goto fail;
    }

    TLS_DEBUG(
        "TLS: connected %s / %s\n",
        SSL_get_version(ssl),
        SSL_get_cipher(ssl)
    );

    t->tls_ctx = ctx;
    t->tls_ssl = ssl;
    t->use_tls = 1;

    return AMIAPI_OK;

fail:
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return AMIAPI_ERR_CONNECT;
}

enum AmiAPIError amiapi_transport_send_all(
    struct AmiAPITransport *t,
    const void *data,
    size_t size)
{
    const unsigned char *p;
    size_t done;

    if (!t || t->fd < 0 || !data)
        return AMIAPI_ERR_CONNECT;

    p = (const unsigned char *)data;
    done = 0;

    while (done < size) {
        if (t->use_tls) {
            SSL *ssl = (SSL *)t->tls_ssl;
            int n;
            int ssl_err;

            n = SSL_write(
                ssl,
                p + done,
                size - done
            );

            if (n > 0) {
                done += (size_t)n;
                continue;
            }

            ssl_err = SSL_get_error(ssl, n);

            if (ssl_err == SSL_ERROR_WANT_READ ||
                ssl_err == SSL_ERROR_WANT_WRITE)
            {
                int ready;

                ready = wait_for_ssl(
                    t,
                    ssl_err
                );

                if (ready > 0)
                    continue;
            }

            {
                unsigned long errcode = ERR_get_error();

                fprintf(
                    stderr,
                    "AmiAPI TLS write failed: "
                    "SSL_write=%d SSL_get_error=%d "
                    "ERR=%08lx errno=%d\n",
                    n,
                    ssl_err,
                    errcode,
                    errno
                );
            }

            return AMIAPI_ERR_CONNECT;
        }
        else {
            long n;
            int ready;

            ready = wait_socket_ready(
                t,
                0,
                1
            );

            if (ready <= 0)
                return AMIAPI_ERR_CONNECT;

            /*
             * bsdsocket's prototype is not const-correct on this SDK.
             */
            n = send(
                t->fd,
                (void *)(p + done),
                size - done,
                0
            );

            if (n < 0) {
                if (socket_would_block())
                    continue;

                return AMIAPI_ERR_CONNECT;
            }

            if (n == 0)
                return AMIAPI_ERR_CONNECT;

            done += (size_t)n;
        }
    }

    return AMIAPI_OK;
}

long amiapi_transport_receive(
    struct AmiAPITransport *t,
    void *buf,
    size_t size)
{
    if (!t || t->fd < 0 || !buf || size == 0)
        return -1;

    if (t->use_tls) {
        SSL *ssl = (SSL *)t->tls_ssl;

        for (;;) {
            int n;
            int ssl_err;

            n = SSL_read(
                ssl,
                buf,
                size
            );

            if (n > 0)
                return (long)n;

            ssl_err = SSL_get_error(ssl, n);

            if (ssl_err == SSL_ERROR_ZERO_RETURN)
                return 0;

            if (ssl_err == SSL_ERROR_WANT_READ ||
                ssl_err == SSL_ERROR_WANT_WRITE)
            {
                int ready;

                ready = wait_for_ssl(
                    t,
                    ssl_err
                );

                if (ready > 0)
                    continue;
            }

            return -1;
        }
    }

    for (;;) {
        int ready;
        long n;

        ready = wait_socket_ready(
            t,
            1,
            0
        );

        if (ready <= 0)
            return -1;

        n = recv(
            t->fd,
            buf,
            size,
            0
        );

        if (n < 0 && socket_would_block())
            continue;

        return n;
    }
}

void amiapi_transport_close(struct AmiAPITransport *t)
{
    if (!t)
        return;

    if (t->tls_ssl) {
        SSL_shutdown((SSL *)t->tls_ssl);
        SSL_free((SSL *)t->tls_ssl);
        t->tls_ssl = NULL;
    }

    if (t->fd >= 0) {
        CloseSocket(t->fd);
        t->fd = -1;
    }

    if (t->tls_ctx) {
        SSL_CTX_free((SSL_CTX *)t->tls_ctx);
        t->tls_ctx = NULL;
    }

    t->use_tls = 0;
}

void amiapi_transport_platform_cleanup(void)
{
    if (amiapi_amissl_initialized) {
        CleanupAmiSSLA(NULL);
        amiapi_amissl_initialized = 0;
    }

    if (AmiAPIAmiSSLBase) {
        CloseAmiSSL();
        AmiAPIAmiSSLBase = NULL;
        AmiSSLBase = NULL;
    }

    if (AmiAPIMasterBase) {
        CloseLibrary(AmiAPIMasterBase);
        AmiAPIMasterBase = NULL;
        AmiSSLMasterBase = NULL;
    }

    if (AmiAPISocketBase) {
        CloseLibrary(AmiAPISocketBase);
        AmiAPISocketBase = NULL;
    }

    if (AmiAPIUtilityBase) {
        CloseLibrary(AmiAPIUtilityBase);
        AmiAPIUtilityBase = NULL;
    }
}
