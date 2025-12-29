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

static char rpe_mrenclave[65];
static char rpe_mrsigner[65];
static char rpe_isv_prod_id[2];
static char rpe_isv_svn[2];
char *rpe_qeids = NULL;
char *rpe_tcbinfo = NULL;
char hexqeid[40];

/* RA-TLS: on server, only need ra_tls_create_key_and_crt_der() to create keypair and X.509 cert */
int (*ra_tls_create_key_and_crt_der_f)(uint8_t** der_key, size_t* der_key_size, uint8_t** der_crt,
                                       size_t* der_crt_size);

#define DEBUG_LEVEL 0
#define MEASUREMENTS_LENGTH 32
#define CA_CRT_PATH "./relying_party_owner/RATLS_Conn/ssl/ca.crt"
#define SRV_CRT_PATH "./relying_party_owner/RATLS_Conn/ssl/server.crt"
#define SRV_KEY_PATH "./relying_party_owner/RATLS_Conn/ssl/server.key"

static int find_oid(const uint8_t* exts, size_t exts_size, const uint8_t* oid, size_t oid_size,
                    uint8_t** out_val, size_t* out_size);
static int verify_RPE_qeid(void);
static int verify_RPE_measurements(const char* mrenclave, const char* mrsigner,
                                   const char* isv_prod_id, const char* isv_svn);
static int my_verify_callback(void* data, mbedtls_x509_crt* crt, int depth, uint32_t* flags);
static void my_debug(void* ctx, int level, const char* file, int line, const char* str);
static ssize_t file_read(const char* path, char* buf, size_t count);

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

/* ==================== Initialize and clear ==================== */

/* Initialize the measurements */
void init_measurements(const char* mrenclave, const char* mrsigner,
                       const char* isv_prod_id, const char* isv_svn){
    assert(strlen(mrenclave)<=64);
    assert(strlen(mrsigner)<=64);
    assert(strlen(isv_prod_id)<=2);
    assert(strlen(isv_svn)<=2);

    strncpy(rpe_mrenclave, mrenclave, sizeof(rpe_mrenclave) - 1);
    strncpy(rpe_mrsigner, mrsigner, sizeof(rpe_mrsigner) - 1);
    strncpy(rpe_isv_prod_id, isv_prod_id, sizeof(rpe_isv_prod_id) - 1);
    strncpy(rpe_isv_svn, isv_svn, sizeof(rpe_isv_svn) - 1);
}

void init_qeid(const char* qeid){
    rpe_qeids = (char *)malloc(strlen(qeid)+1);
    strcpy(rpe_qeids, qeid);
}

void init_tcb_info(const char* tcbinfo){
    rpe_tcbinfo = (char *)malloc(strlen(tcbinfo)+1);
    strcpy(rpe_tcbinfo, tcbinfo);
}

void hex_qeid(const unsigned char* qeid){
    size_t i;
    for (i = 0; i < strlen((char*)qeid); i++){
        sprintf(&hexqeid[i*2], "%02x", *(qeid+i));
    }
}

void hex_measurements(char* dest, const char* src){
    size_t i;
    for (i = 0; i < MEASUREMENTS_LENGTH; i++){
        sprintf(dest+i*2, "%02x", *((unsigned char *)(src+i)));
    }
}

static int verify_RPE_qeid() {
    if (rpe_qeids == NULL) {
        mbedtls_printf("verify_RPE_qeid failed: rpe_qeids is NULL\n");
        return -1;
    }
    char *token; 
    char *s = strdup(rpe_qeids);
    if (s == NULL) {
        mbedtls_printf("verify_RPE_qeid failed: strdup for rpe_qeids error\n");
        return -1;
    }
    char* s1 = s;
    for (token = strsep(&s, " "); token != NULL; token = strsep(&s, " ")){  
        if(strcmp(hexqeid, token)==0) {
            free(s1);
            return 1;
        }
    }
    free(s1);
    return -1;
}

static int verify_RPE_measurements(const char* mrenclave, const char* mrsigner,
                                   const char* isv_prod_id, const char* isv_svn){
    assert(mrenclave && mrsigner && isv_prod_id && isv_svn);

    char tmpmr[65];
    hex_measurements(tmpmr, mrenclave);
    if (memcmp(tmpmr, rpe_mrenclave, sizeof(rpe_mrenclave))){
        mbedtls_printf("mrenclave verification failed !\n");
        return -1;
    }
    
    char tmpmrsigner[65];
    hex_measurements(tmpmrsigner, mrsigner);
    if (memcmp(tmpmrsigner, rpe_mrsigner, sizeof(rpe_mrsigner))){
        mbedtls_printf("mrsigner verification failed !\n");
        return -1;
    }

    if (memcmp(isv_prod_id, rpe_isv_prod_id, sizeof(rpe_isv_prod_id))){
        if(memcmp("0",rpe_isv_prod_id, sizeof(rpe_isv_prod_id))){
            mbedtls_printf("isv_prod_id verification failed !\n");
            return -1;
        }
    }

    if (memcmp(isv_svn, rpe_isv_svn, sizeof(rpe_isv_svn))){
        if(memcmp("0",rpe_isv_svn, sizeof(rpe_isv_svn))){
            mbedtls_printf("isv_svn verification failed !\n");
            return -1;
        }
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
    sgx_quote3_t* quote;
    size_t quote_size;
    ret = find_oid(raw.v3_ext.p, raw.v3_ext.len, g_quote_oid, g_quote_oid_size,
                       (uint8_t**)&quote, &quote_size);
    if (ret < 0)
        return ret;
    
    /* verify RPE qeid */
    hex_qeid(quote->header.user_data);
    if(verify_RPE_qeid()<0){
        mbedtls_printf("RPE QEID verification failed !");
        return -1;
    }

    ret = ra_tls_verify_callback_der(crt->raw.p, crt->raw.len);
    if (ret < 0) {
        mbedtls_printf("RPE quote verification failed !");
        return ret;
    }

    ret = verify_RPE_measurements((const char*)&quote->report_body.mr_enclave,
                                       (const char*)&quote->report_body.mr_signer,
                                       (const char*)&quote->report_body.isv_prod_id,
                                       (const char*)&quote->report_body.isv_svn);

    return ret;
}

static void my_debug(void* ctx, int level, const char* file, int line, const char* str) {
    ((void)level);

    mbedtls_fprintf((FILE*)ctx, "%s:%04d: %s\n", file, line, str);
    fflush((FILE*)ctx);
}

static ssize_t file_read(const char* path, char* buf, size_t count) {
    FILE* f = fopen(path, "r");
    if (!f) return -errno;

    ssize_t bytes = fread(buf, 1, count, f);
    int close_ret = fclose(f);
    if (close_ret < 0) return -errno;
    
    return (bytes <= 0) ? -errno : bytes;
}

/* ==================== SSL/TLS context ==================== */
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

/* has the connection been established */
static int connection_established = 0;

/* send response */
static int send_response(const char* response) {
    int ret;
    size_t len = strlen(response);
    
    mbedtls_printf("  > Sending response: %s\n", response);
    fflush(stdout);
    
    while ((ret = mbedtls_ssl_write(&ssl, (unsigned char*)response, len)) <= 0) {
        if (ret == MBEDTLS_ERR_NET_CONN_RESET) {
            mbedtls_printf(" failed\n  ! peer closed the connection\n\n");
            return -1;
        }
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n  ! mbedtls_ssl_write returned %d\n\n", ret);
            return -1;
        }
    }
    
    mbedtls_printf(" %lu bytes sent\n", (long unsigned int)ret);
    return 0;
}

/* receive message */
int receive_message(char* buffer, size_t buffer_size) {
    int ret;
    
    memset(buffer, 0, buffer_size);
    
    do {
        ret = mbedtls_ssl_read(&ssl, (unsigned char*)buffer, buffer_size - 1);
        
        if (ret > 0) {
            buffer[ret] = '\0';
            mbedtls_printf("  < Received: %s\n", buffer);
            return ret;
        }
        else if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            continue; /* need retry */
        }
        else {
            mbedtls_printf("  ! receive_message failed: %d\n", ret);
            return ret;
        }
    } while (1);
}

/* initialize server */
int server_init(const char *port) {
    int ret;
    const char* pers = "ssl_server";
    
    /* initialize all mbedTLS structure */
    mbedtls_net_init(&listen_fd);
    mbedtls_net_init(&client_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt_init(&srvcert);
    mbedtls_pk_init(&pkey);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

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
            return -1;
        }
    } else {
        mbedtls_printf("Unrecognized remote attestation type: %s\n", attestation_type_str);
        return -1;
    }

    /* initialize random */
    mbedtls_printf("  . Seeding the random number generator...");
    fflush(stdout);

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                (const unsigned char*)pers, strlen(pers));
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        return -1;
    }
    mbedtls_printf(" ok\n");

    /* load certificate and key */
    if (ra_tls_attest_lib) {
        mbedtls_printf("  . Creating the RA-TLS server cert and key...");
        fflush(stdout);

        size_t der_key_size;
        size_t der_crt_size;

        ret = (*ra_tls_create_key_and_crt_der_f)(&der_key, &der_key_size, &der_crt, &der_crt_size);
        if (ret != 0) {
            mbedtls_printf(" failed\n  ! ra_tls_create_key_and_crt_der returned %d\n", ret);
            return -1;
        }

        ret = mbedtls_x509_crt_parse(&srvcert, (unsigned char*)der_crt, der_crt_size);
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
    } else {
        mbedtls_printf("  . Creating normal server cert and key...");
        fflush(stdout);

        ret = mbedtls_x509_crt_parse_file(&srvcert, SRV_CRT_PATH);
        if (ret != 0) {
            mbedtls_printf(" failed\n  ! mbedtls_x509_crt_parse_file returned %d\n", ret);
            return -1;
        }

        ret = mbedtls_x509_crt_parse_file(&srvcert, CA_CRT_PATH);
        if (ret != 0) {
            mbedtls_printf(" failed\n  ! mbedtls_x509_crt_parse_file returned %d\n", ret);
            return -1;
        }

        ret = mbedtls_pk_parse_keyfile(&pkey, SRV_KEY_PATH, NULL,
                                       mbedtls_ctr_drbg_random, &ctr_drbg);
        if (ret != 0) {
            mbedtls_printf(" failed\n  ! mbedtls_pk_parse_keyfile returned %d\n", ret);
            return -1;
        }
        mbedtls_printf(" ok\n");
    }

    /* bind port */
    mbedtls_printf("  . Bind on https://localhost:%s/ ...", port);
    fflush(stdout);

    ret = mbedtls_net_bind(&listen_fd, NULL, port, MBEDTLS_NET_PROTO_TCP);
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_net_bind returned %d\n", ret);
        return -1;
    }
    mbedtls_printf(" ok\n");

    /* SSL configuration */
    mbedtls_printf("  . Setting up SSL configuration...");
    fflush(stdout);

    ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_config_defaults returned %d\n", ret);
        return -1;
    }

    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_verify(&conf, &my_verify_callback, NULL);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);

    if (!ra_tls_attest_lib) {
        mbedtls_ssl_conf_ca_chain(&conf, srvcert.next, NULL);
    }

    ret = mbedtls_ssl_conf_own_cert(&conf, &srvcert, &pkey);
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n", ret);
        return -1;
    }

    ret = mbedtls_ssl_setup(&ssl, &conf);
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_setup returned %d\n", ret);
        return -1;
    }
    mbedtls_printf(" ok\n");

    return 0;
}

/* wait and accept client connection */
int server_accept_connection() {
    int ret;
    
    mbedtls_printf("  . Waiting for a remote connection ...\n");
    fflush(stdout);
    
    ret = mbedtls_net_accept(&listen_fd, &client_fd, NULL, 0, NULL);
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_net_accept returned %d\n", ret);
        return -1;
    }
    mbedtls_printf("  . Client connected\n");
    
    /* set SSL BIO */
    mbedtls_ssl_set_bio(&ssl, &client_fd, mbedtls_net_send, mbedtls_net_recv, NULL);
    connection_established = 1;
    
    return 0;
}

/* perform SSL/TLS handshake */
int server_perform_handshake() {
    int ret;
    
    mbedtls_printf("  . Performing SSL/TLS handshake...");
    fflush(stdout);
    
    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n  ! mbedtls_ssl_handshake returned %d\n", ret);
            return -1;
        }
    }
    mbedtls_printf(" ok\n");
    return 0;
}

/* verify client certificate */
int server_verify_peer() {
    mbedtls_printf("  . Verifying peer X.509 certificate...");
    uint32_t flags = mbedtls_ssl_get_verify_result(&ssl);
    if (flags != 0) {
        char vrfy_buf[512];
        mbedtls_printf(" failed\n");
        mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);
        mbedtls_printf("%s\n", vrfy_buf);
        return -1;
    }
    mbedtls_printf(" ok\n");
    return 0;
}

/* close current connection */
void server_close_connection() {
    if (!connection_established)
        return;
        
    mbedtls_printf("  . Closing connection...\n");
    mbedtls_ssl_close_notify(&ssl);
    
    mbedtls_net_free(&client_fd);
    mbedtls_ssl_session_reset(&ssl);
    connection_established = 0;
}

/* final cleanup */
void server_cleanup() {
    mbedtls_printf("  . Cleaning up server resources...\n");
    
    if (ra_tls_attest_lib)
        dlclose(ra_tls_attest_lib);
    
    mbedtls_net_free(&listen_fd);
    mbedtls_x509_crt_free(&srvcert);
    mbedtls_pk_free(&pkey);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    
    free(der_key);
    free(der_crt);
    
    if (rpe_qeids) {
        free(rpe_qeids);
        rpe_qeids = NULL;
    }
    if (rpe_tcbinfo) {
        free(rpe_tcbinfo);
        rpe_tcbinfo = NULL;
    }
}

/* ==================== core operation functions ==================== */

/* handle receive key command */
int handle_get_keys(char* signing_key_buf, size_t signing_key_buf_size,
                    char* encryption_keys_buf, size_t encryption_keys_buf_size) {
    int ret;
    
    mbedtls_printf("  . Processing GET_KEYS command...\n");
    
    ret = receive_message(signing_key_buf, signing_key_buf_size);
    if (ret <= 0) return ret;
    
    ret = receive_message(encryption_keys_buf, encryption_keys_buf_size);
    if (ret <= 0) return ret;
    
    mbedtls_printf("  . Keys received successfully\n");
    return 0;
}

/* send policy to client */
int pass_policy_data(const char* data, const char* verification_result) {
    char *buffer;
    char *buffer1;
    int ret;
    size_t len;

    buffer = (char *)malloc(strlen(data) + 1);
    memset(buffer, 0, strlen(data) + 1);
    strcpy(buffer, data);
    
    mbedtls_printf("  > Sending policy data to client:");
    fflush(stdout);
    
    len = strlen(buffer);
    while ((ret = mbedtls_ssl_write(&ssl, (unsigned char *)buffer, len)) <= 0) {
        if (ret == MBEDTLS_ERR_NET_CONN_RESET) {
            mbedtls_printf(" failed\n  ! peer closed the connection\n\n");
            free(buffer);
            return -1;
        }
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n  ! mbedtls_ssl_write returned %d\n\n", ret);
            free(buffer);
            return -1;
        }
    }
    len = ret;
    mbedtls_printf(" %lu bytes sent\n\n%s\n", len, (char*)buffer);
    free(buffer);

    /* send verification results */
    buffer1 = (char *)malloc(strlen(verification_result) + 1);
    memset(buffer1, 0, strlen(verification_result) + 1);
    strcpy(buffer1, verification_result);
    
    mbedtls_printf("  > Sending verification result to client:");
    fflush(stdout);
    
    len = strlen(buffer1);
    while ((ret = mbedtls_ssl_write(&ssl, (unsigned char *)buffer1, len)) <= 0) {
        if (ret == MBEDTLS_ERR_NET_CONN_RESET) {
            mbedtls_printf(" failed\n  ! peer closed the connection\n\n");
            free(buffer1);
            return -1;
        }
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n  ! mbedtls_ssl_write returned %d\n\n", ret);
            free(buffer1);
            return -1;
        }
    }
    len = ret;
    mbedtls_printf(" %lu bytes sent\n\n%s\n", len, (char*)buffer1);
    free(buffer1);

    return 0;
}