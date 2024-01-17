/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *               2020, Intel Labs
 */

/*
 * SSL server demonstration program (with RA-TLS)
 * This program is originally based on an mbedTLS example ssl_server.c but uses RA-TLS flows (SGX
 * Remote Attestation flows) if RA-TLS library is required by user.
 * Note that this program builds against mbedTLS 3.x.
 */

#define _GNU_SOURCE
#include "mbedtls/build_info.h"

#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define mbedtls_fprintf fprintf
#define mbedtls_printf printf

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509.h"
// #include "ra_tls.h"

#include "sgx_quote_3.h"

static char collaborative_data[1024];

static uint8_t * client_cert = NULL;
static size_t client_cert_size = 0;

// /* RA-TLS: on client, only need to register ra_tls_verify_callback_der() for cert verification */
// int (*ra_tls_verify_callback_der_f)(uint8_t* der_crt, size_t der_crt_size);

// /* RA-TLS: if specified in command-line options, use our own callback to verify SGX measurements */
// void (*ra_tls_set_measurement_callback_f)(int (*f_cb)(const char* mrenclave, const char* mrsigner,
//                                           const char* isv_prod_id, const char* isv_svn));

/* RA-TLS: on server, only need ra_tls_create_key_and_crt_der() to create keypair and X.509 cert */
int (*ra_tls_create_key_and_crt_der_f)(uint8_t** der_key, size_t* der_key_size, uint8_t** der_crt,
                                       size_t* der_crt_size);

void server_free_mbedtls(int ret);

#define HTTP_RESPONSE      \
    "    hello world\r\n"      \
    "    Successful connection using: %s\r\n"


#define HTTP_RESPONSE1                                    \
    "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n" \
    "<h2>mbed TLS Test Server</h2>\r\n"                  \
    "<p>Successful connection using: %s</p>\r\n"

#define DEBUG_LEVEL 0

#define MALICIOUS_STR "MALICIOUS DATA"

// #define CA_CRT_PATH "ssl/ca.crt"
// #define SRV_CRT_PATH "ssl/server.crt"
// #define SRV_KEY_PATH "ssl/server.key"


/*! searches for specific \p oid among \p exts and returns pointer to its value in \p out_val;
 *  tailored for SGX quotes with size strictly from 128 to 65535 bytes (fails on other sizes) */
// static int find_oid(const uint8_t* exts, size_t exts_size, const uint8_t* oid, size_t oid_size,
//                     uint8_t** out_val, size_t* out_size) {
//     /* TODO: searching with memmem is not robust (what if some extension contains exactly these
//      *       chars?), but mbedTLS has nothing generic enough for our purposes; this is still
//      *       secure because this func is used for extracting the SGX quote which is verified
//      *       later, but may lead to unexpected failures (hardly possible in real world though) */
//     uint8_t* p = memmem(exts, exts_size, oid, oid_size);
//     if (!p)
//         return MBEDTLS_ERR_X509_INVALID_EXTENSIONS;

//     const uint8_t* exts_end = exts + exts_size;

//     /* move pointer past OID string and to the OID value (which is encoded in ASN.1 DER) */
//     p += oid_size;

//     if (p >= exts_end)
//         return MBEDTLS_ERR_X509_INVALID_EXTENSIONS;

//     if (*p == 0x01) {
//         /* some TLS libs generate a BOOLEAN (ASN.1 tag 1) for the criticality of the extension
//          * before the extension value itself; check its value and skip it */
//         p++;
//         if (p >= exts_end || *p++ != 0x01) {
//             /* BOOLEAN length must be 0x01 */
//             return MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
//         }
//         if (p >= exts_end || *p++ != 0x00) {
//             /* BOOLEAN value must be 0x00 (non-critical extension) */
//             return MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
//         }
//     }

//     /* now comes the octet string containing the SGX quote (ASN.1 tag 4) */
//     if (p >= exts_end || *p++ != 0x04) {
//         return MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
//     }
//     if (p >= exts_end || *p++ != 0x82) {
//         /* length of octet string must be 0x82 = 0b10000010 (the long form, with bit 8 set and bits
//          * 7-0 indicating how many more bytes are in the length field); SGX quotes always have
//          * lengths of 128 to 65535 bytes, so length must be encoded in exactly two bytes */
//         return MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
//     }
//     static_assert(sizeof(sgx_quote_t) >= 128, "need to change ASN.1 length-of-octet-string limit");
//     static_assert(SGX_QUOTE_MAX_SIZE <= 65535, "need to change ASN.1 length-of-octet-string limit");

//     if (p + 2 > exts_end)
//         return MBEDTLS_ERR_X509_INVALID_EXTENSIONS;

//     size_t val_size;
//     val_size = *p++;
//     val_size <<= 8;
//     val_size += *p++;

//     uint8_t* val = p;

//     assert(val <= exts_end);
//     if (val_size < 128 || val_size > SGX_QUOTE_MAX_SIZE || val_size > (size_t)(exts_end - val))
//         return MBEDTLS_ERR_X509_INVALID_EXTENSIONS;

//     *out_size = val_size;
//     *out_val  = val;
//     return 0;
// }

static int parse_hex(uint8_t* hex, size_t hex_size, uint8_t* buffer, size_t buffer_size) {
    if (hex_size != (buffer_size * 2+1))
        return -1;

    for (size_t i = 0; i < buffer_size; i++) {
        sprintf(hex + i * 2, "%02hhx", buffer[i]);
    }
    return 0;
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

    int ret;
    mbedtls_x509_crt raw;
    mbedtls_x509_crt_init(&raw);

    ret = mbedtls_x509_crt_parse(&raw, crt->raw.p, crt->raw.len);
    if (ret < 0){
        mbedtls_x509_crt_free(&raw);
        mbedtls_printf("Parse client cert failed!");
    }

     if(client_cert==NULL || client_cert_size<1){
        client_cert = (uint8_t *)malloc(crt->raw.len*2+1);
        if(client_cert == NULL){
            mbedtls_printf("Malloc memory failed!\n");
            return -1;
        }
        memset(client_cert,0,crt->raw.len*2+1);
        client_cert_size = crt->raw.len*2+1;
        if(parse_hex(client_cert, client_cert_size, crt->raw.p, crt->raw.len) <0){
            mbedtls_printf("Parse certificate to hex failed!\n");
            return -1;
        }
    }else{
        if(client_cert_size!=(crt->raw.len*2+1)){
            client_cert = (uint8_t *)realloc(client_cert, crt->raw.len*2+1);
            if(client_cert == NULL){
                mbedtls_printf("Realloc memory failed!\n");
                return -1;
            }
            memset(client_cert,0,crt->raw.len*2+1);
            client_cert_size = crt->raw.len*2+1;
            if(parse_hex(client_cert, client_cert_size, crt->raw.p, crt->raw.len)<0){
                mbedtls_printf("Parse certificate to hex failed!\n");
                return -1;
            }
        }else{
            assert(client_cert_size==(crt->raw.len*2+1));
            memset(client_cert,0,crt->raw.len*2+1);
            if(parse_hex(client_cert, client_cert_size, crt->raw.p, crt->raw.len)<0){
                mbedtls_printf("Parse certificate to hex failed!\n");
                return -1;
            }
        }
    }
  
    return ret;
}

uint8_t *get_ce_server_cert(void){
    return client_cert;
}

static void my_debug(void* ctx, int level, const char* file, int line, const char* str) {
    ((void)level);

    mbedtls_fprintf((FILE*)ctx, "%s:%04d: %s\n", file, line, str);
    fflush((FILE*)ctx);
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

// int ra_verify_init(){
//     char* error;
//     void* ra_tls_verify_lib           = NULL;
//     ra_tls_verify_callback_der_f      = NULL;
//     ra_tls_set_measurement_callback_f = NULL;
//     bool in_sgx = getenv_client_inside_sgx();

//     if (in_sgx) {
//         /*
//         * RA-TLS verification with DCAP inside SGX enclave uses dummies instead of real
//         * functions from libsgx_urts.so, thus we don't need to load this helper library.
//         */
//         ra_tls_verify_lib = dlopen("libra_tls_verify_dcap_gramine.so", RTLD_LAZY);
//         if (!ra_tls_verify_lib) {
//             mbedtls_printf("%s\n", dlerror());
//             mbedtls_printf("User requested RA-TLS verification with DCAP inside SGX but cannot find lib\n");
//             mbedtls_printf("Please make sure that you are using client_dcap.manifest\n");
//             return 1;
//         }
//     } else {
//         void* helper_sgx_urts_lib = dlopen("libsgx_urts.so", RTLD_NOW | RTLD_GLOBAL);
//         if (!helper_sgx_urts_lib) {
//             mbedtls_printf("%s\n", dlerror());
//             mbedtls_printf("User requested RA-TLS verification with DCAP but cannot find helper"
//                             " libsgx_urts.so lib\n");
//             return 1;
//         }

//         ra_tls_verify_lib = dlopen("libra_tls_verify_dcap.so", RTLD_LAZY);
//         if (!ra_tls_verify_lib) {
//             mbedtls_printf("%s\n", dlerror());
//             mbedtls_printf("User requested RA-TLS verification with DCAP but cannot find lib\n");
//             return 1;
//         }
//     }

//     ra_tls_verify_callback_der_f = dlsym(ra_tls_verify_lib, "ra_tls_verify_callback_der");
//     if ((error = dlerror()) != NULL) {
//         mbedtls_printf("%s\n", error);
//         return 1;
//     }
//     ra_tls_set_measurement_callback_f = dlsym(ra_tls_verify_lib, "ra_tls_set_measurement_callback");
//     if ((error = dlerror()) != NULL) {
//         mbedtls_printf("%s\n", error);
//         return 1;
//     }

//     (*ra_tls_set_measurement_callback_f)(set_CE_measurements);

//     return 0;
// }


void* server_ra_tls_attest_lib;
mbedtls_net_context server_listen_fd;
mbedtls_net_context server_client_fd;

mbedtls_entropy_context server_entropy;
mbedtls_ctr_drbg_context server_ctr_drbg;
mbedtls_ssl_context server_ssl;
mbedtls_ssl_config server_conf;
mbedtls_x509_crt server_srvcert;
mbedtls_pk_context server_pkey;

int ce_server_init(uint8_t* der_crt, uint8_t* der_key, const char * port) {
    int ret;
    size_t len;
    const char* pers = "ssl_server";
    

    mbedtls_net_init(&server_listen_fd);
    mbedtls_net_init(&server_client_fd);
    mbedtls_ssl_init(&server_ssl);
    mbedtls_ssl_config_init(&server_conf);
    mbedtls_x509_crt_init(&server_srvcert);
    mbedtls_pk_init(&server_pkey);
    mbedtls_entropy_init(&server_entropy);
    mbedtls_ctr_drbg_init(&server_ctr_drbg);

    // ra_tls_verify_callback_der_f      = NULL;

#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif

    char attestation_type_str[32] = {0};
    ret = file_read("/dev/attestation/attestation_type", attestation_type_str,
                    sizeof(attestation_type_str) - 1);
    
    if (ret < 0 && ret != -ENOENT) {
        mbedtls_printf("User requested RA-TLS attestation but cannot read SGX-specific file "
                       "/dev/attestation/attestation_type\n");
        return -1;
    }

    if (ret == -ENOENT || !strcmp(attestation_type_str, "none")) {
        server_ra_tls_attest_lib = NULL;
        ra_tls_create_key_and_crt_der_f = NULL;
    } else if (!strcmp(attestation_type_str, "epid") || !strcmp(attestation_type_str, "dcap")) {
        server_ra_tls_attest_lib = dlopen("libra_tls_attest.so", RTLD_LAZY);
        if (!server_ra_tls_attest_lib) {
            mbedtls_printf("User requested RA-TLS attestation but cannot find lib\n");
            return -1;
        }

        char* error;
        ra_tls_create_key_and_crt_der_f = dlsym(server_ra_tls_attest_lib, "ra_tls_create_key_and_crt_der");
        if ((error = dlerror()) != NULL) {
            mbedtls_printf("%s\n", error);
            return -1;
        }
    } else {
        mbedtls_printf("Unrecognized remote attestation type: %s\n", attestation_type_str);
        return -1;
    }

    //====================================================================================
    // ret = ra_verify_init();
    // if (ret != 0) {
    //     mbedtls_printf(" Failed to initial the ra verification function handler!\n");
    //     goto exit;
    // }
    //====================================================================================

    mbedtls_printf("  . Seeding the random number generator...");
    fflush(stdout);

    ret = mbedtls_ctr_drbg_seed(&server_ctr_drbg, mbedtls_entropy_func, &server_entropy,
                                (const unsigned char*)pers, strlen(pers));
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        server_free_mbedtls(ret);
        return -1;
    }

    mbedtls_printf(" ok\n");

    if (server_ra_tls_attest_lib) {
        mbedtls_printf("\n  . Parsing the TLS server CE cert and key ...");
        fflush(stdout);

        size_t der_key_size = strlen(der_key)+1;
        size_t der_crt_size = strlen(der_crt)+1;

        // ret = (*ra_tls_create_key_and_crt_der_f)(&der_key, &der_key_size, &der_crt, &der_crt_size);
        // if (ret != 0) {
        //     mbedtls_printf(" failed\n  !  ra_tls_create_key_and_crt_der returned %d\n\n", ret);
        //     server_free_mbedtls(ret);
        //     return -1;
        // }

        ret = mbedtls_x509_crt_parse(&server_srvcert, (unsigned char*)der_crt, der_crt_size);
        if (ret != 0) {
            mbedtls_printf(" failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret);
            server_free_mbedtls(ret);
            return -1;
        }

        ret = mbedtls_pk_parse_key(&server_pkey, (unsigned char*)der_key, der_key_size, /*pwd=*/NULL, 0,
                                   mbedtls_ctr_drbg_random, &server_ctr_drbg);
        if (ret != 0) {
            mbedtls_printf(" failed\n  !  mbedtls_pk_parse_key returned %d\n\n", ret);
            server_free_mbedtls(ret);
            return -1;
        }

        mbedtls_printf(" ok\n");

    } else {
        // mbedtls_printf("\n  . Creating normal server cert and key...");
        // fflush(stdout);

        // ret = mbedtls_x509_crt_parse_file(&server_srvcert, SRV_CRT_PATH);
        // if (ret != 0) {
        //     mbedtls_printf(" failed\n  !  mbedtls_x509_crt_parse_file returned %d\n\n", ret);
        //     server_free_mbedtls(ret);
        //     return -1;
        // }

        // ret = mbedtls_x509_crt_parse_file(&server_srvcert, CA_CRT_PATH);
        // if (ret != 0) {
        //     mbedtls_printf(" failed\n  !  mbedtls_x509_crt_parse_file returned %d\n\n", ret);
        //     server_free_mbedtls(ret);
        //     return -1;
        // }

        // ret = mbedtls_pk_parse_keyfile(&server_pkey, SRV_KEY_PATH, /*password=*/NULL,
        //                                mbedtls_ctr_drbg_random, &server_ctr_drbg);
        // if (ret != 0) {
        //     mbedtls_printf(" failed\n  !  mbedtls_pk_parse_keyfile returned %d\n\n", ret);
        //     server_free_mbedtls(ret);
        //     return -1;
        // }

        // mbedtls_printf(" ok\n");
    }

    mbedtls_printf("  . Bind on https://localhost:%s/ ...", port);
    fflush(stdout);

    ret = mbedtls_net_bind(&server_listen_fd, NULL, port, MBEDTLS_NET_PROTO_TCP);
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_net_bind returned %d\n\n", ret);
        server_free_mbedtls(ret);
        return -1;
    }

    mbedtls_printf(" ok\n");

    mbedtls_printf("  . Setting up the default SSL configuration....");
    fflush(stdout);

    ret = mbedtls_ssl_config_defaults(&server_conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
        server_free_mbedtls(ret);
        return -1;
    }
    mbedtls_printf(" ok\n");

    mbedtls_ssl_conf_authmode(&server_conf, MBEDTLS_SSL_VERIFY_OPTIONAL); 
    mbedtls_printf("  . Installing TLS callback ...");
    mbedtls_ssl_conf_verify(&server_conf, &my_verify_callback, NULL);
    mbedtls_printf(" ok\n");

    mbedtls_ssl_conf_rng(&server_conf, mbedtls_ctr_drbg_random, &server_ctr_drbg);
    mbedtls_ssl_conf_dbg(&server_conf, my_debug, stdout);

    // if (!server_ra_tls_attest_lib) {
    //     /* no RA-TLS attest library present, use embedded CA chain */
    //     mbedtls_ssl_conf_ca_chain(&server_conf, server_srvcert.next, NULL);
    // }

    mbedtls_printf("  . Setting up the SSL data....");
    ret = mbedtls_ssl_conf_own_cert(&server_conf, &server_srvcert, &server_pkey);
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret);
        server_free_mbedtls(ret);
        return -1;
    }

    ret = mbedtls_ssl_setup(&server_ssl, &server_conf);
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret);
        server_free_mbedtls(ret);
        return -1;
    }
    mbedtls_printf(" ok\n");

reset:
#ifdef MBEDTLS_ERROR_C
    if (ret != 0) {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        mbedtls_printf("Last error was: %d - %s\n\n", ret, error_buf);
    }
#endif

    mbedtls_net_free(&server_client_fd);

    mbedtls_ssl_session_reset(&server_ssl);

    mbedtls_printf("  . Waiting for a remote connection ...");
    fflush(stdout);

    ret = mbedtls_net_accept(&server_listen_fd, &server_client_fd, NULL, 0, NULL);
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_net_accept returned %d\n\n", ret);
        server_free_mbedtls(ret);
        return -1;
    }

    mbedtls_ssl_set_bio(&server_ssl, &server_client_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    mbedtls_printf(" ok\n");

    mbedtls_printf("  . Performing the SSL/TLS handshake...");
    fflush(stdout);

    while ((ret = mbedtls_ssl_handshake(&server_ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n  ! mbedtls_ssl_handshake returned %d\n\n", ret);
            goto reset;
        }
    }

    mbedtls_printf(" ...ok\n");

    mbedtls_printf("  . Verifying peer X.509 certificate...");
    uint32_t flags;
    flags = mbedtls_ssl_get_verify_result(&server_ssl);
    if (flags != 0) {
        char vrfy_buf[512];
        mbedtls_printf(" failed\n");
        mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);
        mbedtls_printf("%s\n", vrfy_buf);

        /* verification failed for whatever reason, fail loudly */
        server_free_mbedtls(ret);
        return -1;
    } else {
        mbedtls_printf(" ok\n");
    }

    return 0; 
}

char *ce_server_exchange_data(void){
    size_t len;
    int ret;

    /* Read CE id */
    mbedtls_printf("  < Read data from client:");
    fflush(stdout);

    do {
        len = sizeof(collaborative_data) - 1;
        memset(collaborative_data, 0, sizeof(collaborative_data));
        ret = mbedtls_ssl_read(&server_ssl, (unsigned char *)collaborative_data, len);

        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
            continue;

        if (ret <= 0) {
            switch (ret) {
                case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                    mbedtls_printf(" connection was closed gracefully\n");
                    break;

                case MBEDTLS_ERR_NET_CONN_RESET:
                    mbedtls_printf(" connection was reset by peer\n");
                    break;

                default:
                    mbedtls_printf(" mbedtls_ssl_read returned -0x%x\n", ret);
                    break;
            }

            break;
        }

        len = ret;
        mbedtls_printf(" %lu bytes read\n\n  %s\n\n", len, (char*)collaborative_data);

        if (ret > 0)
            break;
    } while (1);

    return collaborative_data;
}

void server_free_mbedtls(int ret){
#ifdef MBEDTLS_ERROR_C
    if (ret != 0) {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        mbedtls_printf("Last error was: %d - %s\n\n", ret, error_buf);
    }
#endif

    if (server_ra_tls_attest_lib)
        dlclose(server_ra_tls_attest_lib);

    mbedtls_net_free(&server_client_fd);
    mbedtls_net_free(&server_listen_fd);

    mbedtls_x509_crt_free(&server_srvcert);
    mbedtls_pk_free(&server_pkey);
    mbedtls_ssl_free(&server_ssl);
    mbedtls_ssl_config_free(&server_conf);
    mbedtls_ctr_drbg_free(&server_ctr_drbg);
    mbedtls_entropy_free(&server_entropy);
}

int waiting(const char* data){
    char *buffer;
    buffer = (char *)malloc(strlen(data)+1);
    memset(buffer,0,strlen(data)+1);
    strcpy(buffer, data);

    int ret;
    size_t len;
    unsigned char buf[1024];

    mbedtls_printf("  > Write to client:");
    fflush(stdout);

    //len = sprintf((char*)buffer, HTTP_RESPONSE, mbedtls_ssl_get_ciphersuite(&server_ssl));
    len = strlen(buffer);

    while ((ret = mbedtls_ssl_write(&server_ssl, (unsigned char *)buffer, len)) <= 0) {
        if (ret == MBEDTLS_ERR_NET_CONN_RESET) {
            mbedtls_printf(" failed\n  ! peer closed the connection\n\n");
            free(buffer);
            goto reset;
        }

        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n  ! mbedtls_ssl_write returned %d\n\n", ret);
            free(buffer);
            server_free_mbedtls(ret);
            return -1;
        }
    }

    len = ret;
    mbedtls_printf(" %lu bytes written\n\n%s\n", len, buffer);
    free(buffer);

    mbedtls_printf("  . Closing the connection...");

    while ((ret = mbedtls_ssl_close_notify(&server_ssl)) < 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n  ! mbedtls_ssl_close_notify returned %d\n\n", ret);
            goto reset;
        }
    }

    mbedtls_printf(" ok\n");

    ret = 0;
    goto reset;


reset:
#ifdef MBEDTLS_ERROR_C
    if (ret != 0) {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        mbedtls_printf("Last error was: %d - %s\n\n", ret, error_buf);
    }
#endif
    mbedtls_net_free(&server_client_fd);

    mbedtls_ssl_session_reset(&server_ssl);

    mbedtls_printf("  . Waiting for a remote connection ...");
    fflush(stdout);

    ret = mbedtls_net_accept(&server_listen_fd, &server_client_fd, NULL, 0, NULL);
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_net_accept returned %d\n\n", ret);
        server_free_mbedtls(ret);
        return -1;
    }

    mbedtls_ssl_set_bio(&server_ssl, &server_client_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    mbedtls_printf(" ok\n");

    mbedtls_printf("  . Performing the SSL/TLS handshake...");
    fflush(stdout);

    while ((ret = mbedtls_ssl_handshake(&server_ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n  ! mbedtls_ssl_handshake returned %d\n\n", ret);
            goto reset;
        }
    }

    mbedtls_printf(" ...ok\n");

    mbedtls_printf("  . Verifying peer X.509 certificate...");
    uint32_t flags;
    flags = mbedtls_ssl_get_verify_result(&server_ssl);
    if (flags != 0) {
        char vrfy_buf[512];
        mbedtls_printf(" failed\n");
        mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);
        mbedtls_printf("%s\n", vrfy_buf);

        /* verification failed for whatever reason, fail loudly */
        server_free_mbedtls(ret);
        return -1;
    } else {
        mbedtls_printf(" ok\n");
    }

    return 0; 
}
