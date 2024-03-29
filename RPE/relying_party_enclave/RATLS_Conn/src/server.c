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
#include "ra_tls.h"

#include "sgx_quote_3.h"

char ce_mrenclave[65];
char ce_mrsigner[65];
static char ce_isv_prod_id[3];
static char ce_isv_svn[3];
char *ce_tcbinfos = NULL;
static char userData[20];
static char ce_id[10];
char *tcb_id = NULL;

static char signing_key_buf[375];
static char encryption_keys_buf[651];

// /* RA-TLS: on client, only need to register ra_tls_verify_callback_der() for cert verification */
// int (*ra_tls_verify_callback_der_f)(uint8_t* der_crt, size_t der_crt_size);

// /* RA-TLS: if specified in command-line options, use our own callback to verify SGX measurements */
// void (*ra_tls_set_measurement_callback_f)(int (*f_cb)(const char* mrenclave, const char* mrsigner,
//                                           const char* isv_prod_id, const char* isv_svn));

/* RA-TLS: on server, only need ra_tls_create_key_and_crt_der() to create keypair and X.509 cert */
int (*ra_tls_create_key_and_crt_der_f)(uint8_t** der_key, size_t* der_key_size, uint8_t** der_crt,
                                       size_t* der_crt_size);

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
static int find_oid(const uint8_t* exts, size_t exts_size, const uint8_t* oid, size_t oid_size,
                    uint8_t** out_val, size_t* out_size) {
    /* TODO: searching with memmem is not robust (what if some extension contains exactly these
     *       chars?), but mbedTLS has nothing generic enough for our purposes; this is still
     *       secure because this func is used for extracting the SGX quote which is verified
     *       later, but may lead to unexpected failures (hardly possible in real world though) */
    uint8_t* p = memmem(exts, exts_size, oid, oid_size);
    if (!p)
        return MBEDTLS_ERR_X509_INVALID_EXTENSIONS;

    const uint8_t* exts_end = exts + exts_size;

    /* move pointer past OID string and to the OID value (which is encoded in ASN.1 DER) */
    p += oid_size;

    if (p >= exts_end)
        return MBEDTLS_ERR_X509_INVALID_EXTENSIONS;

    if (*p == 0x01) {
        /* some TLS libs generate a BOOLEAN (ASN.1 tag 1) for the criticality of the extension
         * before the extension value itself; check its value and skip it */
        p++;
        if (p >= exts_end || *p++ != 0x01) {
            /* BOOLEAN length must be 0x01 */
            return MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
        }
        if (p >= exts_end || *p++ != 0x00) {
            /* BOOLEAN value must be 0x00 (non-critical extension) */
            return MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
        }
    }

    /* now comes the octet string containing the SGX quote (ASN.1 tag 4) */
    if (p >= exts_end || *p++ != 0x04) {
        return MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
    }
    if (p >= exts_end || *p++ != 0x82) {
        /* length of octet string must be 0x82 = 0b10000010 (the long form, with bit 8 set and bits
         * 7-0 indicating how many more bytes are in the length field); SGX quotes always have
         * lengths of 128 to 65535 bytes, so length must be encoded in exactly two bytes */
        return MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
    }
    static_assert(sizeof(sgx_quote_t) >= 128, "need to change ASN.1 length-of-octet-string limit");
    static_assert(SGX_QUOTE_MAX_SIZE <= 65535, "need to change ASN.1 length-of-octet-string limit");

    if (p + 2 > exts_end)
        return MBEDTLS_ERR_X509_INVALID_EXTENSIONS;

    size_t val_size;
    val_size = *p++;
    val_size <<= 8;
    val_size += *p++;

    uint8_t* val = p;

    assert(val <= exts_end);
    if (val_size < 128 || val_size > SGX_QUOTE_MAX_SIZE || val_size > (size_t)(exts_end - val))
        return MBEDTLS_ERR_X509_INVALID_EXTENSIONS;

    *out_size = val_size;
    *out_val  = val;
    return 0;
}

char *get_ce_mr(){
    return ce_mrenclave; 
}

char *get_ce_mrsigner(){
    return ce_mrsigner;
}

char *get_ce_isvprodid(){
    return ce_isv_prod_id;
}

char *get_ce_isvsvn(){
    return ce_isv_svn;
}

char *get_ce_qeid(){
    return userData;
}

char *get_ce_id(){
    return ce_id;
}

char* get_tcb_id() {
    return tcb_id;
}

void init_tcb_info(const char* tcbinfo){
    ce_tcbinfos = (char *)malloc(strlen(tcbinfo)+1);
    strcpy(ce_tcbinfos, tcbinfo);
    // mbedtls_printf("TODO: +++++++ :   %s \n",ce_tcbinfos);  
}

static int rpe_server_parse_hex(char* hex, size_t hex_size, char* buffer, size_t buffer_size) {
    if (hex_size != (buffer_size * 2+1))
        return -1;

    for (size_t i = 0; i < buffer_size; i++) {
        sprintf(hex + i * 2, "%02hhx", buffer[i]);
    }
    return 0;
}

static int set_CE_measurements(const char* mrenclave, const char* mrsigner,
                                   const char* isv_prod_id, const char* isv_svn){
    assert(mrenclave && mrsigner && isv_prod_id && isv_svn);

    if (sizeof(ce_isv_prod_id) - 1 < strlen(isv_prod_id)) {
        mbedtls_printf("\n length of ce_isv_prod_id is less than isv_prod_id");
        return -1;
    }
    if (sizeof(ce_isv_svn) - 1 < strlen(isv_svn)) {
        mbedtls_printf("\n length of ce_isv_svn is less than isv_svn");
        return -1;
    }

    
    if(rpe_server_parse_hex(ce_mrenclave, sizeof(ce_mrenclave), mrenclave, 32)<0){
        mbedtls_printf("Parse ce mr to hex failed!\n");
        return -1;
    }
    if(rpe_server_parse_hex(ce_mrsigner, sizeof(ce_mrsigner), mrsigner, 32)<0){
        mbedtls_printf("Parse ce signer to hex failed!\n");
        return -1;
    }
    strncpy(ce_isv_prod_id,isv_prod_id,sizeof(ce_isv_prod_id) - 1);
    strncpy(ce_isv_svn,isv_svn, sizeof(ce_isv_svn) - 1);

    // TODO: verify RPE measurement
//     if (memcmp(mrenclave, rpe_mrenclave, sizeof(rpe_mrenclave)))
//         return -1;

//     if (memcmp(mrsigner, rpe_mrsigner, sizeof(rpe_mrsigner)))
//         return -1;

//     if (memcmp(isv_prod_id, rpe_isv_prod_id, sizeof(rpe_isv_prod_id)))
//         return -1;

//     if (memcmp(isv_svn, rpe_isv_svn, sizeof(rpe_isv_svn)))
//         return -1;

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
    sgx_quote3_t* quote;
    size_t quote_size;
    ret = find_oid(raw.v3_ext.p, raw.v3_ext.len, g_quote_oid, g_quote_oid_size,
                       (uint8_t**)&quote, &quote_size);
    if (ret < 0)
        return ret;
    
    strcpy(userData,(char *)quote->header.user_data);

    ret = ra_tls_verify_callback_der(crt->raw.p, crt->raw.len);
    if (ret < 0) {
        mbedtls_printf("CE quote verification failed!");
        return ret;
    }
    set_CE_measurements((const char*)&quote->report_body.mr_enclave,
                                       (const char*)&quote->report_body.mr_signer,
                                       (const char*)&quote->report_body.isv_prod_id,
                                       (const char*)&quote->report_body.isv_svn);
    return ret;
}

/* for test */
static int my_verify_callback_test(void* data, mbedtls_x509_crt* crt, int depth, uint32_t* flags) {
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
   
    return ret;
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


void* ra_tls_attest_lib;
mbedtls_net_context listen_fd;
mbedtls_net_context client_fd;

uint8_t* der_key = NULL;
uint8_t* der_crt = NULL;

mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_ssl_context ssl;
mbedtls_ssl_config conf;
mbedtls_x509_crt srvcert;
mbedtls_pk_context pkey;

int ra_tls_server_init(const char * port) {
    int ret;
    size_t len;
    const char* pers = "ssl_server";
    

    mbedtls_net_init(&listen_fd);
    mbedtls_net_init(&client_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt_init(&srvcert);
    mbedtls_pk_init(&pkey);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

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

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                (const unsigned char*)pers, strlen(pers));
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n");

    if (ra_tls_attest_lib) {
        mbedtls_printf("\n  . Creating the RA-TLS server cert and key (using \"%s\" as "
                       "attestation type)...", attestation_type_str);
        fflush(stdout);

        size_t der_key_size;
        size_t der_crt_size;

        ret = (*ra_tls_create_key_and_crt_der_f)(&der_key, &der_key_size, &der_crt, &der_crt_size);
        if (ret != 0) {
            mbedtls_printf(" failed\n  !  ra_tls_create_key_and_crt_der returned %d\n\n", ret);
            goto exit;
        }

        ret = mbedtls_x509_crt_parse(&srvcert, (unsigned char*)der_crt, der_crt_size);
        if (ret != 0) {
            mbedtls_printf(" failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret);
            goto exit;
        }

        ret = mbedtls_pk_parse_key(&pkey, (unsigned char*)der_key, der_key_size, /*pwd=*/NULL, 0,
                                   mbedtls_ctr_drbg_random, &ctr_drbg);
        if (ret != 0) {
            mbedtls_printf(" failed\n  !  mbedtls_pk_parse_key returned %d\n\n", ret);
            goto exit;
        }

        mbedtls_printf(" ok\n");

        // if (argc > 1) {
        //     if (strcmp(argv[1], "--test-malicious-quote") != 0) {
        //         mbedtls_printf("Unrecognized command-line argument `%s` (only "
        //                        "`--test-malicious-quote` is recognized)\n", argv[1]);
        //         return 1;
        //     }

        //     /* user asks to maliciously modify the embedded SGX quote (for testing purposes) */
        //     mbedtls_printf("  . Maliciously modifying SGX quote embedded in RA-TLS cert...");
        //     fflush(stdout);

        //     uint8_t oid[] = {0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF8, 0x4D, 0x8A, 0x39, 0x06};
        //     uint8_t* p = memmem(srvcert.v3_ext.p, srvcert.v3_ext.len, oid, sizeof(oid));
        //     if (!p) {
        //         mbedtls_printf(" failed\n  !  No embedded SGX quote found\n\n");
        //         goto exit;
        //     }

        //     p += sizeof(oid);
        //     p += 5; /* jump somewhere in the middle of the SGX quote */
        //     if (p + sizeof(MALICIOUS_STR) > srvcert.v3_ext.p + srvcert.v3_ext.len) {
        //         mbedtls_printf(" failed\n  !  Size of embedded SGX quote is too small\n\n");
        //         goto exit;
        //     }

        //     memcpy(p, MALICIOUS_STR, sizeof(MALICIOUS_STR));
        //     mbedtls_printf(" ok\n");
        // }
    } else {
        // mbedtls_printf("\n  . Creating normal server cert and key...");
        // fflush(stdout);

        // ret = mbedtls_x509_crt_parse_file(&srvcert, SRV_CRT_PATH);
        // if (ret != 0) {
        //     mbedtls_printf(" failed\n  !  mbedtls_x509_crt_parse_file returned %d\n\n", ret);
        //     goto exit;
        // }

        // ret = mbedtls_x509_crt_parse_file(&srvcert, CA_CRT_PATH);
        // if (ret != 0) {
        //     mbedtls_printf(" failed\n  !  mbedtls_x509_crt_parse_file returned %d\n\n", ret);
        //     goto exit;
        // }

        // ret = mbedtls_pk_parse_keyfile(&pkey, SRV_KEY_PATH, /*password=*/NULL,
        //                                mbedtls_ctr_drbg_random, &ctr_drbg);
        // if (ret != 0) {
        //     mbedtls_printf(" failed\n  !  mbedtls_pk_parse_keyfile returned %d\n\n", ret);
        //     goto exit;
        // }

        // mbedtls_printf(" ok\n");
    }

    mbedtls_printf("  . Bind on https://localhost:%s/ ...", port);
    fflush(stdout);

    ret = mbedtls_net_bind(&listen_fd, NULL, port, MBEDTLS_NET_PROTO_TCP);
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_net_bind returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n");

    mbedtls_printf("  . Setting up the default SSL configuration....");
    fflush(stdout);

    ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
        goto exit;
    }
    mbedtls_printf(" ok\n");


    //====================================================================================

    
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_printf("  . Installing RA-TLS callback ...");
    mbedtls_ssl_conf_verify(&conf, &my_verify_callback, NULL);
    mbedtls_printf(" ok\n");


    //=====================================================================================



    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);

    // if (!ra_tls_attest_lib) {
    //     /* no RA-TLS attest library present, use embedded CA chain */
    //     mbedtls_ssl_conf_ca_chain(&conf, srvcert.next, NULL);
    // }

    mbedtls_printf("  . Setting up the SSL data....");
    ret = mbedtls_ssl_conf_own_cert(&conf, &srvcert, &pkey);
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret);
        goto exit;
    }

    ret = mbedtls_ssl_setup(&ssl, &conf);
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret);
        goto exit;
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

    mbedtls_net_free(&client_fd);

    mbedtls_ssl_session_reset(&ssl);

    mbedtls_printf("  . Waiting for a remote connection ...");
    fflush(stdout);

    ret = mbedtls_net_accept(&listen_fd, &client_fd, NULL, 0, NULL);
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_net_accept returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_ssl_set_bio(&ssl, &client_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    mbedtls_printf(" ok\n");

    mbedtls_printf("  . Performing the SSL/TLS handshake...");
    fflush(stdout);

    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n  ! mbedtls_ssl_handshake returned %d\n\n", ret);
            goto reset;
        }
    }

    mbedtls_printf(" ...ok\n");


    //================================================================
    mbedtls_printf("  . Verifying peer (rpe) X.509 certificate...");
    uint32_t flags;
    flags = mbedtls_ssl_get_verify_result(&ssl);
    if (flags != 0) {
        char vrfy_buf[512];
        mbedtls_printf(" failed\n");
        mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);
        mbedtls_printf("%s\n", vrfy_buf);

        /* verification failed for whatever reason, fail loudly */
        goto exit;
    } else {
        mbedtls_printf(" ok\n");
    }
    //================================================================

    /* Read CE id */
    mbedtls_printf("  < Read id from client:");
    fflush(stdout);

    do {
        len = sizeof(ce_id) - 1;
        memset(ce_id, 0, sizeof(ce_id));
        ret = mbedtls_ssl_read(&ssl, (unsigned char *)ce_id, len);

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
                    mbedtls_printf(" mbedtls_ssl_read returned -0x%x\n", -ret);
                    break;
            }

            break;
        }

        len = ret;
        mbedtls_printf(" %lu bytes read\n\n  %s\n\n", len, (char*)ce_id);

        if (ret > 0)
            break;
    } while (1);

    /* Read CE public signing keys */
    mbedtls_printf("  < Read keys from client:");
    fflush(stdout);

    do {
        len = sizeof(signing_key_buf) - 1;
        memset(encryption_keys_buf, 0, sizeof(signing_key_buf));
        ret = mbedtls_ssl_read(&ssl, (unsigned char *)signing_key_buf, len);

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
                    mbedtls_printf(" mbedtls_ssl_read returned -0x%x\n", -ret);
                    break;
            }

            break;
        }

        len = ret;
        mbedtls_printf(" %lu bytes read\n\n%s", len, (char*)signing_key_buf);

        if (ret > 0)
            break;
    } while (1);

    /* Read CE encryption keys */
    mbedtls_printf("  < Read keys from client:");
    fflush(stdout);

    do {
        len = sizeof(encryption_keys_buf) - 1;
        memset(encryption_keys_buf, 0, sizeof(encryption_keys_buf));
        ret = mbedtls_ssl_read(&ssl, (unsigned char *)encryption_keys_buf, len);

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
                    mbedtls_printf(" mbedtls_ssl_read returned -0x%x\n", -ret);
                    break;
            }

            break;
        }

        len = ret;
        mbedtls_printf(" %lu bytes read\n\n%s", len, (char*)encryption_keys_buf);

        if (ret > 0)
            break;
    } while (1);
    
    return 1; 

exit:
#ifdef MBEDTLS_ERROR_C
    if (ret != 0) {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        mbedtls_printf("Last error was: %d - %s\n\n", ret, error_buf);
    }
#endif

    if (ra_tls_attest_lib)
        dlclose(ra_tls_attest_lib);

    mbedtls_net_free(&client_fd);
    mbedtls_net_free(&listen_fd);

    mbedtls_x509_crt_free(&srvcert);
    mbedtls_pk_free(&pkey);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    free(der_key);
    free(der_crt);

    return -1;
}

char *get_ce_signingkey(){
    return signing_key_buf;
}
char *get_ce_encryptionkey(){
    return encryption_keys_buf;
}

unsigned char buf[2048];
int pass_data(const char* data){
    char *buffer;
    buffer = (char *)malloc(strlen(data)+1);
    memset(buffer,0,strlen(data)+1);
    strcpy(buffer, data);

    int ret;
    size_t len;
    
    mbedtls_printf("  > Write to ce:");
    fflush(stdout);

    //len = sprintf((char*)buffer, HTTP_RESPONSE, mbedtls_ssl_get_ciphersuite(&ssl));
    len = strlen(buffer);

    while ((ret = mbedtls_ssl_write(&ssl, (unsigned char *)buffer, len)) <= 0) {
        if (ret == MBEDTLS_ERR_NET_CONN_RESET) {
            mbedtls_printf(" failed\n  ! peer closed the connection\n\n");
            free(buffer);
            goto exit;
        }

        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n  ! mbedtls_ssl_write returned %d\n\n", ret);
            free(buffer);
            goto exit;
        }
    }

    len = ret;
    mbedtls_printf(" %lu bytes written\n\n%s\n", len, buffer);
    free(buffer);

    mbedtls_printf("  < Read data from client:");
    fflush(stdout);

    do {
        len = sizeof(buf) - 1;
        memset(buf, 0, sizeof(buf));
        ret = mbedtls_ssl_read(&ssl, buf, len);

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
                    mbedtls_printf(" mbedtls_ssl_read returned -0x%x\n", -ret);
                    break;
            }

            break;
        }

        len = ret;
        mbedtls_printf(" %lu bytes read\n\n%s\n", len, (char*)buf);

        if (ret > 0)
            break;
    } while (1);

    return 3; 

exit:
#ifdef MBEDTLS_ERROR_C
    if (ret != 0) {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        mbedtls_printf("Last error was: %d - %s\n\n", ret, error_buf);
    }
#endif

    if (ra_tls_attest_lib)
        dlclose(ra_tls_attest_lib);

    mbedtls_net_free(&client_fd);
    mbedtls_net_free(&listen_fd);

    mbedtls_x509_crt_free(&srvcert);
    mbedtls_pk_free(&pkey);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    free(der_key);
    free(der_crt);

    return ret;
}

int wait(const char* data){
    int ret;
    size_t len;

    mbedtls_printf("  > Write to client:");
    fflush(stdout);

    //len = sprintf((char*)buffer, HTTP_RESPONSE, mbedtls_ssl_get_ciphersuite(&ssl));
    len = strlen(data);

    while ((ret = mbedtls_ssl_write(&ssl, data, len)) <= 0) {
        if (ret == MBEDTLS_ERR_NET_CONN_RESET) {
            mbedtls_printf(" failed\n  ! peer closed the connection\n\n");
            goto reset;
        }

        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n  ! mbedtls_ssl_write returned %d\n\n", ret);
            goto exit;
        }
    }

    len = ret;
    mbedtls_printf(" %lu bytes written\n\n%s\n", len, (char*)data);

    mbedtls_printf("  . Closing the connection...");

    while ((ret = mbedtls_ssl_close_notify(&ssl)) < 0) {
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
    mbedtls_net_free(&client_fd);

    mbedtls_ssl_session_reset(&ssl);

    mbedtls_printf("  . Waiting for a remote connection ...");
    fflush(stdout);

    ret = mbedtls_net_accept(&listen_fd, &client_fd, NULL, 0, NULL);
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_net_accept returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_ssl_set_bio(&ssl, &client_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    mbedtls_printf(" ok\n");

    mbedtls_printf("  . Performing the SSL/TLS handshake...");
    fflush(stdout);

    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n  ! mbedtls_ssl_handshake returned %d\n\n", ret);
            goto reset;
        }
    }

    mbedtls_printf(" ...ok\n");


    //================================================================
    mbedtls_printf("  . Verifying peer (rpe) X.509 certificate...");
    uint32_t flags;
    flags = mbedtls_ssl_get_verify_result(&ssl);
    if (flags != 0) {
        char vrfy_buf[512];
        mbedtls_printf(" failed\n");
        mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);
        mbedtls_printf("%s\n", vrfy_buf);

        /* verification failed for whatever reason, fail loudly */
        goto exit;
    } else {
        mbedtls_printf(" ok\n");
    }
    //================================================================

    mbedtls_printf("  < Read from ce:");
    fflush(stdout);

    do {
        len = sizeof(buf) - 1;
        memset(buf, 0, sizeof(buf));
        ret = mbedtls_ssl_read(&ssl, buf, len);

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
                    mbedtls_printf(" mbedtls_ssl_read returned -0x%x\n", -ret);
                    break;
            }

            break;
        }

        len = ret;
        mbedtls_printf(" %lu bytes read\n\n%s", len, (char*)buf);

        if (ret > 0)
            break;
    } while (1);

    return 3; 


exit:
#ifdef MBEDTLS_ERROR_C
    if (ret != 0) {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        mbedtls_printf("Last error was: %d - %s\n\n", ret, error_buf);
    }
#endif

    if (ra_tls_attest_lib)
        dlclose(ra_tls_attest_lib);

    mbedtls_net_free(&client_fd);
    mbedtls_net_free(&listen_fd);

    mbedtls_x509_crt_free(&srvcert);
    mbedtls_pk_free(&pkey);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    free(der_key);
    free(der_crt);

    return ret;
}

char *get_ce_data(){
    return (char *)buf;
}