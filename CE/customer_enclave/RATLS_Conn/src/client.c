/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *               2020, Intel Labs
 */

/*
 * SSL client demonstration program (with RA-TLS).
 * This program is originally based on an mbedTLS example ssl_client1.c but uses RA-TLS flows (SGX
 * Remote Attestation flows) if RA-TLS library is required by user.
 * Note that this program builds against mbedTLS 3.x.
 */

#include "mbedtls/build_info.h"

#include <assert.h>
#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define mbedtls_fprintf fprintf
#define mbedtls_printf printf

#define MBEDTLS_EXIT_SUCCESS EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE EXIT_FAILURE

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"

/* CMD definitions */
#define REQ_CERT "REQ_CERT"
#define VERIFY_CERT "VERIFY_CERT"

/* RA-TLS: on client, only need to register ra_tls_verify_callback_der() for cert verification */
int (*ra_tls_verify_callback_der_f)(uint8_t* der_crt, size_t der_crt_size);

/* RA-TLS: if specified in command-line options, use our own callback to verify SGX measurements */
void (*ra_tls_set_measurement_callback_f)(int (*f_cb)(const char* mrenclave, const char* mrsigner,
                                          const char* isv_prod_id, const char* isv_svn));

/* RA-TLS: on server, only need ra_tls_create_key_and_crt_der() to create keypair and X.509 cert */
int (*ra_tls_create_key_and_crt_der_f)(uint8_t** der_key, size_t* der_key_size, uint8_t** der_crt,
                                       size_t* der_crt_size);

#define DEBUG_LEVEL 0

/* mbedTLS global variables */
static void* ra_tls_attest_lib = NULL;
static void* ra_tls_verify_lib = NULL;
static uint8_t* der_key = NULL;
static uint8_t* der_crt = NULL;

static mbedtls_net_context server_fd;
static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context ctr_drbg;
static mbedtls_ssl_context ssl;
static mbedtls_ssl_config conf;
static mbedtls_x509_crt cacert;
static mbedtls_x509_crt cltcert;
static mbedtls_pk_context pkey;

static int exit_code = MBEDTLS_EXIT_FAILURE;
static bool in_sgx = false;
static bool connection_established = false;

static void my_debug(void* ctx, int level, const char* file, int line, const char* str) {
    ((void)level);

    mbedtls_fprintf((FILE*)ctx, "%s:%04d: %s\n", file, line, str);
    fflush((FILE*)ctx);
}

/* RA-TLS: mbedTLS-specific callback to verify the x509 certificate */
static int my_verify_callback(void* data, mbedtls_x509_crt* crt, int depth, uint32_t* flags) {
    (void)data;

    if (depth != 0) {
        /* the cert chain in RA-TLS consists of single self-signed cert, so we expect depth 0 */
        return MBEDTLS_ERR_X509_INVALID_FORMAT;
    }
    if (flags) {
        /* mbedTLS sets flags to signal that the cert is not to be trusted (e.g., it is not
         * correctly signed by a trusted CA; since RA-TLS uses self-signed certs, we don't care
         * what mbedTLS thinks and ignore internal cert verification logic of mbedTLS */
        *flags = 0;
    }
    return ra_tls_verify_callback_der_f(crt->raw.p, crt->raw.len);
}

static ssize_t file_read(const char* path, char* buf, size_t count) {
    FILE* f = fopen(path, "r");
    if (!f)
        return -errno;

    ssize_t bytes = fread(buf, 1, count, f);
    if (bytes <= 0) {
        int errsv = errno;
        fclose(f);
        return -errsv;
    }

    int close_ret = fclose(f);
    if (close_ret < 0)
        return -errno;

    return bytes;
}

static bool getenv_client_inside_sgx() {
    char* str = getenv("RA_TLS_CLIENT_INSIDE_SGX");
    if (!str)
        return false;

    return !strcmp(str, "1") || !strcmp(str, "true") || !strcmp(str, "TRUE");
}

/* ==================== Initialize and cleanup ==================== */

/* initialize client */
int client_init() {
    int ret;
    const char* pers = "ssl_client1";
    
    in_sgx = getenv_client_inside_sgx();

    mbedtls_net_init(&server_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_x509_crt_init(&cacert);
    mbedtls_x509_crt_init(&cltcert);
    mbedtls_pk_init(&pkey);
    mbedtls_entropy_init(&entropy);

#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif

    /* check RA-TLS type */
    char attestation_type_str[32] = {0};
    ret = file_read("/dev/attestation/attestation_type", attestation_type_str,
                    sizeof(attestation_type_str) - 1);
    
    if (ret < 0 && ret != -ENOENT) {
        mbedtls_printf("User requested RA-TLS attestation but cannot read SGX-specific file "
                       "/dev/attestation/attestation_type\n");
        return -1;
    }

    if (ret == -ENOENT || !strcmp(attestation_type_str, "none")) {
        ra_tls_attest_lib = NULL;
        ra_tls_create_key_and_crt_der_f = NULL;
    } else if (!strcmp(attestation_type_str, "epid") || !strcmp(attestation_type_str, "dcap")) {
        ra_tls_attest_lib = dlopen("libra_tls_attest.so", RTLD_LAZY);
        if (!ra_tls_attest_lib) {
            mbedtls_printf("User requested RA-TLS attestation but cannot find lib\n");
            return -1;
        }

        char* error;
        ra_tls_create_key_and_crt_der_f = dlsym(ra_tls_attest_lib, "ra_tls_create_key_and_crt_der");
        if ((error = dlerror()) != NULL) {
            mbedtls_printf("%s\n", error);
            dlclose(ra_tls_attest_lib);
            return -1;
        }
    } else {
        mbedtls_printf("Unrecognized remote attestation type: %s\n", attestation_type_str);
        return -1;
    }

    /* initialize random number generator */
    mbedtls_printf("  . Seeding the random number generator...");
    fflush(stdout);

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                (const unsigned char*)pers, strlen(pers));
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        return -1;
    }
    mbedtls_printf(" ok\n");

    /* generate RA-TLS certificate */
    if (ra_tls_attest_lib) {
        mbedtls_printf("\n  . Creating the RA-TLS client cert and key (using \"%s\" as "
                       "attestation type)...", attestation_type_str);
        fflush(stdout);

        size_t der_key_size;
        size_t der_crt_size;

        ret = (*ra_tls_create_key_and_crt_der_f)(&der_key, &der_key_size, &der_crt, &der_crt_size);
        if (ret != 0) {
            mbedtls_printf(" failed\n  ! ra_tls_create_key_and_crt_der returned %d\n", ret);
            return -1;
        }
        ret = mbedtls_x509_crt_parse(&cltcert, (unsigned char*)der_crt, der_crt_size);
        if (ret != 0) {
            mbedtls_printf(" failed\n  ! mbedtls_x509_crt_parse returned %d\n", ret);
            return -1;
        }

        ret = mbedtls_pk_parse_key(&pkey, (unsigned char*)der_key, der_key_size, NULL, 0,
                                   mbedtls_ctr_drbg_random, &ctr_drbg);
        if (ret != 0) {
            mbedtls_printf(" failed\n  ! mbedtls_pk_parse_key returned %d\n", ret);
            return -1;
        }
        mbedtls_printf(" ok\n");
    }

    return 0;
}

/* connect to server */
int client_connect(const char* hostname, const char* port) {
    int ret;

    mbedtls_printf("  . Connecting to tcp/%s/%s...", hostname, port);
    fflush(stdout);

    ret = mbedtls_net_connect(&server_fd, hostname, port, MBEDTLS_NET_PROTO_TCP);
    if (ret != 0) {
        mbedtls_printf(" failed  ! mbedtls_net_connect returned %d\n", ret);
        return -1;
    }
    mbedtls_printf(" ok\n");

    connection_established = 1;
    return 0;
}

/* load verify library */
int client_load_verify_lib() {
    char* error;

    if (in_sgx) {
        ra_tls_verify_lib = dlopen("libra_tls_verify_dcap_gramine.so", RTLD_LAZY);
        if (!ra_tls_verify_lib) {
            mbedtls_printf("%s\n", dlerror());
            mbedtls_printf("User requested RA-TLS verification with DCAP inside SGX but cannot find lib\n");
            return -1;
        }
    } else {
        ra_tls_verify_lib = dlopen("libra_tls_verify_dcap.so", RTLD_LAZY);
        if (!ra_tls_verify_lib) {
            mbedtls_printf("%s\n", dlerror());
            mbedtls_printf("User requested RA-TLS verification with DCAP but cannot find lib\n");
            return -1;
        }
    }

    ra_tls_verify_callback_der_f = dlsym(ra_tls_verify_lib, "ra_tls_verify_callback_der");
    if ((error = dlerror()) != NULL) {
        mbedtls_printf("%s\n", error);
        dlclose(ra_tls_verify_lib);
        return -1;
    }

    ra_tls_set_measurement_callback_f = dlsym(ra_tls_verify_lib, "ra_tls_set_measurement_callback");
    if ((error = dlerror()) != NULL) {
        mbedtls_printf("%s\n", error);
        dlclose(ra_tls_verify_lib);
        return -1;
    }
    
    return 0;
}

/* configure SSL */
int client_configure_ssl() {
    int ret;

    mbedtls_printf("  . Setting up the SSL configuration...");
    fflush(stdout);

    ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, 
                                      MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_config_defaults returned %d\n", ret);
        return -1;
    }

    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);

    /* load verify library and set callback */
    if (client_load_verify_lib() != 0) {
        return -1;
    }

    mbedtls_printf("[ using default SGX-measurement verification callback"
                    " (via RA_TLS_* environment variables) ]\n");
    (*ra_tls_set_measurement_callback_f)(NULL);

    /* use RA-TLS verification callback */
    mbedtls_printf("  . Installing RA-TLS callback ...");
    mbedtls_ssl_conf_verify(&conf, &my_verify_callback, NULL);
    mbedtls_printf(" ok\n");

    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);

    /* set client certificate */
    ret = mbedtls_ssl_conf_own_cert(&conf, &cltcert, &pkey);
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n", ret);
        return -1;
    }
    
    ret = mbedtls_ssl_setup(&ssl, &conf);
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_setup returned %d\n", ret);
        return -1;
    }

    return 0;
}

/* set hostname and start SSL */
int client_start_ssl(const char* hostname) {
    int ret;

    ret = mbedtls_ssl_set_hostname(&ssl, hostname);
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_set_hostname returned %d\n", ret);
        return -1;
    }

    mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);
    
    return 0;
}

/* perform handshake */
int client_perform_handshake() {
    int ret;

    mbedtls_printf("  . Performing the SSL/TLS handshake...");
    fflush(stdout);

    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", -ret);
            return -1;
        }
    }

    mbedtls_printf(" ok\n");
    return 0;
}

/* send data */
int client_send_data(const char* data, size_t len) {
    int ret;

    mbedtls_printf("  > Sending %lu bytes...", len);
    fflush(stdout);

    while ((ret = mbedtls_ssl_write(&ssl, (unsigned char*)data, len)) <= 0) {
        if (ret == MBEDTLS_ERR_NET_CONN_RESET) {
            mbedtls_printf(" failed\n  ! peer closed the connection\n\n");
            return -1;
        }
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n  ! mbedtls_ssl_write returned %d\n\n", ret);
            return -1;
        }
    }

    mbedtls_printf(" ok (%d bytes)\n", ret);
    mbedtls_printf("  > Content: %s\n", data);
    return ret;
}

/* receive data */
int client_receive_data(char* buffer, size_t buffer_size) {
    int ret;
    
    mbedtls_printf("  < Receiving data...");
    fflush(stdout);
    
    do {
        ret = mbedtls_ssl_read(&ssl, (unsigned char*)buffer, buffer_size - 1);
        
        if (ret > 0) {
            buffer[ret] = '\0';
            mbedtls_printf(" ok (%d bytes)\n", ret);
            mbedtls_printf("  < Content: %s\n", buffer);
            return ret;
        }
        else if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            continue; /* need retry */
        }
        else if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
            mbedtls_printf(" connection closed by peer\n");
            return 0;
        }
        else if (ret < 0) {
            mbedtls_printf(" failed\n  ! mbedtls_ssl_read returned %d\n\n", ret);
            return ret;
        }
        else {
            mbedtls_printf(" connection closed\n");
            return 0;
        }
    } while (1);
}

/* close connection */
void client_close_connection() {
    if (!connection_established)
        return;
        
    mbedtls_printf("  . Closing connection...\n");
    mbedtls_ssl_close_notify(&ssl);
    
    mbedtls_net_free(&server_fd);
    mbedtls_ssl_session_reset(&ssl);
    connection_established = 0;
}

/* cleanup client resources */
void client_cleanup() {
    mbedtls_printf("  . Cleaning up client resources...\n");

    if (ra_tls_verify_lib)
        dlclose(ra_tls_verify_lib);
    if (ra_tls_attest_lib)
        dlclose(ra_tls_attest_lib);

    mbedtls_x509_crt_free(&cacert);
    mbedtls_x509_crt_free(&cltcert);
    mbedtls_pk_free(&pkey);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    free(der_key);
    free(der_crt);
}

int ra_tls_client() {
    if (client_init() != 0) {
        return -1;
    }

    if (client_configure_ssl() != 0) {
        return -1;
    }

    return 0;
}

char *get_cert_from_rpe(const char * hostname, const char * port, const char * ce_id) {
    int ret;
    if (client_connect(hostname, port) != 0) {
        mbedtls_printf(" Connect RPE failed\n");
        return NULL;
    }

    if (client_start_ssl(hostname) != 0 || client_perform_handshake() != 0) {
        mbedtls_printf(" Setup SSL failed\n");
        client_close_connection();
        return NULL;
    }

    /* send REQ_CERT cmd */
    ret = client_send_data(REQ_CERT, strlen(REQ_CERT));
    if (ret < 0) {
        mbedtls_printf(" Failed to send REQ_CERT cmd\n");
        client_close_connection();
        return NULL;
    }

    /* send ce id */
    ret = client_send_data(ce_id, strlen(ce_id));
    if (ret < 0) {
        mbedtls_printf(" Failed to send ce id\n");
        client_close_connection();
        return NULL;
    }

    /* obtain certificate from rpe */
    char data_len_str[32];
    ret = client_receive_data(data_len_str, sizeof(data_len_str));
    if (ret < 0) {
        mbedtls_printf(" Failed to obtain certificate length from RPE\n");
        client_close_connection();
        return NULL;
    }
    int data_len = atoi(data_len_str);
    if (data_len <=0 || data_len > 8192) {
        mbedtls_printf(" Invalid certificate length: %d\n", data_len);
        client_close_connection();
        return NULL;
    }
    char *certificate = malloc(data_len + 1);
    if (certificate == NULL) {
        mbedtls_printf(" Failed to allocate memory for certificate\n");
        client_close_connection();
        return NULL;
    }
    ret = client_receive_data(certificate, data_len + 1);
    if (ret <= 0) {
        free(certificate);
        client_close_connection();
        return NULL;
    }
    /* close connection */
    client_close_connection();
    return certificate;
}
    


int veritfy_peer_cert(const char * hostname, const char * port, const char * peer_cert, char * verification_result, size_t verification_result_size) {
    int ret;
    if (client_connect(hostname, port) != 0) {
        mbedtls_printf(" Connect RPE failed\n");
        return -1;
    }

    if (client_start_ssl(hostname) != 0 || client_perform_handshake() != 0) {
        mbedtls_printf(" Setup SSL failed\n");
        client_close_connection();
        return -1;
    }

    /* send VERIFY_CERT cmd */
    ret = client_send_data(VERIFY_CERT, strlen(VERIFY_CERT));
    if (ret < 0) {
        mbedtls_printf(" Failed to send VERIFY_CERT cmd\n");
        client_close_connection();
        return -1;
    }

    /* send peer cert */
    int peer_cert_len = strlen(peer_cert);
    char peer_cert_len_str[32];
    snprintf(peer_cert_len_str, sizeof(peer_cert_len_str), "%d", peer_cert_len);
    mbedtls_printf("  > Peer cert length: %d ", peer_cert_len);
    fflush(stdout);
    ret = client_send_data(peer_cert_len_str, strlen(peer_cert_len_str));
    if (ret < 0) {
        client_close_connection();
        return -1;
    }

    mbedtls_printf("  > Sending peer cert to RPE:");
    fflush(stdout);
    ret = client_send_data(peer_cert, peer_cert_len);
    if (ret < 0) {
        client_close_connection();
        return -1;
    }

    /* obtain verication result from rpe */
    ret = client_receive_data(verification_result, verification_result_size);
    if (ret < 0) {
        mbedtls_printf(" Failed to obtain verification result from RPE\n");
        client_close_connection();
        return -1;
    }
    
    /* close connection */
    client_close_connection();
    return 0;    
}