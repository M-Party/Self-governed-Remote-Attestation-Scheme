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

#include "mbedtls/x509.h"

/* RA-TLS: on client, only need to register ra_tls_verify_callback_der() for cert verification */
int (*ra_tls_verify_callback_der_f)(uint8_t* der_crt, size_t der_crt_size);

/* RA-TLS: if specified in command-line options, use our own callback to verify SGX measurements */
void (*ra_tls_set_measurement_callback_f)(int (*f_cb)(const char* mrenclave, const char* mrsigner,
                                          const char* isv_prod_id, const char* isv_svn));

/* RA-TLS: on server, only need ra_tls_create_key_and_crt_der() to create keypair and X.509 cert */
int (*ra_tls_create_key_and_crt_der_f)(uint8_t** der_key, size_t* der_key_size, uint8_t** der_crt,
                                       size_t* der_crt_size);

void client_free_mbedtls(int ret);                      

// #define SERVER_PORT "4433"
// #define SERVER_NAME "192.168.122.54"
#define GET_REQUEST "  Hello RPE\r\n\r\n"

#define DEBUG_LEVEL 0

// #define CA_CRT_PATH "ssl/ca.crt"
// #define SRV_CRT_PATH "ssl/server.crt"
// #define SRV_KEY_PATH "ssl/server.key"

static uint8_t * server_cert = NULL;
static size_t server_cert_size = 0;

static void my_debug(void* ctx, int level, const char* file, int line, const char* str) {
    ((void)level);

    mbedtls_fprintf((FILE*)ctx, "%s:%04d: %s\n", file, line, str);
    fflush((FILE*)ctx);
}

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

    if(server_cert==NULL || server_cert_size<1){
        server_cert = (uint8_t *)malloc(crt->raw.len*2+1);
        if(server_cert == NULL){
            mbedtls_printf("Malloc memory failed!\n");
            return -1;
        }
        memset(server_cert,0,crt->raw.len*2+1);
        server_cert_size = crt->raw.len*2+1;
        if(parse_hex(server_cert, server_cert_size, crt->raw.p, crt->raw.len) <0){
            mbedtls_printf("Parse certificate to hex failed!\n");
            return -1;
        }
    }else{
        if(server_cert_size!=(crt->raw.len*2+1)){
            server_cert = (uint8_t *)realloc(server_cert, crt->raw.len*2+1);
            if(server_cert == NULL){
                mbedtls_printf("Realloc memory failed!\n");
                return -1;
            }
            memset(server_cert,0,crt->raw.len*2+1);
            server_cert_size = crt->raw.len*2+1;
            if(parse_hex(server_cert, server_cert_size, crt->raw.p, crt->raw.len)<0){
                mbedtls_printf("Parse certificate to hex failed!\n");
                return -1;
            }
        }else{
            assert(server_cert_size==(crt->raw.len*2+1));
            memset(server_cert,0,crt->raw.len*2+1);
            if(parse_hex(server_cert, server_cert_size, crt->raw.p, crt->raw.len)<0){
                mbedtls_printf("Parse certificate to hex failed!\n");
                return -1;
            }
        }
    }

    return ret;
}

uint8_t *get_ce_client_cert(void){
    return server_cert;
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


mbedtls_net_context client_server_fd;
mbedtls_entropy_context client_entropy;
mbedtls_ctr_drbg_context client_ctr_drbg;
mbedtls_ssl_context client_ssl;
mbedtls_ssl_config client_conf;
mbedtls_x509_crt client_cacert;
mbedtls_x509_crt client_cltcert;
mbedtls_pk_context client_pkey;

void* client_ra_tls_verify_lib           = NULL;

void* client_ra_tls_attest_lib;
// uint8_t* client_der_key = NULL;
// uint8_t* client_der_crt = NULL;

int client_exit_code = MBEDTLS_EXIT_FAILURE;

int ce_client_init(uint8_t* client_der_crt, uint8_t* client_der_key, const char * hostname, const char * port) {
    int ret;
    
    uint32_t flags;
    const char* pers = "ssl_client1";
    bool in_sgx = getenv_client_inside_sgx();

    char* error;

    ra_tls_verify_callback_der_f      = NULL;
    ra_tls_set_measurement_callback_f = NULL;

#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif

    mbedtls_net_init(&client_server_fd);
    mbedtls_ssl_init(&client_ssl);
    mbedtls_ssl_config_init(&client_conf);
    mbedtls_ctr_drbg_init(&client_ctr_drbg);
    mbedtls_x509_crt_init(&client_cacert);
    mbedtls_x509_crt_init(&client_cltcert);
    mbedtls_pk_init(&client_pkey);
    mbedtls_entropy_init(&client_entropy);

    char attestation_type_str[32] = {0};
    ret = file_read("/dev/attestation/attestation_type", attestation_type_str,
                    sizeof(attestation_type_str) - 1);
    if (ret < 0 && ret != -ENOENT) {
        mbedtls_printf("User requested RA-TLS attestation but cannot read SGX-specific file "
                       "/dev/attestation/attestation_type\n");
        return -1;
    }

    if (ret == -ENOENT || !strcmp(attestation_type_str, "none")) {
        client_ra_tls_attest_lib = NULL;
        ra_tls_create_key_and_crt_der_f = NULL;
    } else if (!strcmp(attestation_type_str, "epid") || !strcmp(attestation_type_str, "dcap")) {
        client_ra_tls_attest_lib = dlopen("libra_tls_attest.so", RTLD_LAZY);
        if (!client_ra_tls_attest_lib) {
            mbedtls_printf("User requested RA-TLS attestation but cannot find lib\n");
            return -1;
        }

        char* error;
        ra_tls_create_key_and_crt_der_f = dlsym(client_ra_tls_attest_lib, "ra_tls_create_key_and_crt_der");
        if ((error = dlerror()) != NULL) {
            mbedtls_printf("%s\n", error);
            dlclose(client_ra_tls_attest_lib);
            return -1;
        }
    } else {
        mbedtls_printf("Unrecognized remote attestation type: %s\n", attestation_type_str);
        return -1;
    }

    mbedtls_printf("\n  . Seeding the random number generator...");
    fflush(stdout);

    ret = mbedtls_ctr_drbg_seed(&client_ctr_drbg, mbedtls_entropy_func, &client_entropy,
                                (const unsigned char*)pers, strlen(pers));
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        client_free_mbedtls(ret);
        return -1;
    }

    mbedtls_printf(" ok\n");

    if (client_ra_tls_attest_lib) {
        mbedtls_printf("\n  . Parsing the TLS client CE cert and key ...");
        fflush(stdout);

        size_t der_key_size = strlen(client_der_key)+1;
        size_t der_crt_size = strlen(client_der_crt)+1;

        // uint8_t* der_key1 = NULL;
        // uint8_t* der_crt1 = NULL;
        // size_t der_key_size1;
        // size_t der_crt_size1;

        // ret = (*ra_tls_create_key_and_crt_der_f)(&der_key1, &der_key_size1, &der_crt1, &der_crt_size1);
        // if (ret != 0) {
        //     mbedtls_printf(" failed\n  !  ra_tls_create_key_and_crt_der returned %d\n\n", ret);
        //     client_free_mbedtls(ret);
        //     return -1;
        // }

        ret = mbedtls_x509_crt_parse(&client_cltcert, (unsigned char*)client_der_crt, der_crt_size);
        if (ret != 0) {
            mbedtls_printf(" failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret);
            client_free_mbedtls(ret);
            return -1;
        }

        ret = mbedtls_pk_parse_key(&client_pkey, (unsigned char*)client_der_key, der_key_size, /*pwd=*/NULL, 0,
                                   mbedtls_ctr_drbg_random, &client_ctr_drbg);
        if (ret != 0) {
            mbedtls_printf(" failed\n  !  mbedtls_pk_parse_key returned %d\n\n", ret);
            client_free_mbedtls(ret);
            return -1;
        }

        mbedtls_printf(" ok\n");
        dlclose(client_ra_tls_attest_lib);
    }

    mbedtls_printf("  . Connecting to tcp/%s/%s...", hostname, port);
    fflush(stdout);

    while (true)
    {
        ret = mbedtls_net_connect(&client_server_fd, hostname, port, MBEDTLS_NET_PROTO_TCP);
        if (ret != 0) {
            mbedtls_printf(" failed\n  ! mbedtls_net_connect returned %d\n Try again ", ret);
            sleep(3);
        }else{
            break;
        }
    }

    mbedtls_printf(" ok\n");

    mbedtls_printf("  . Setting up the default SSL configuration...");
    fflush(stdout);

    ret = mbedtls_ssl_config_defaults(&client_conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
        client_free_mbedtls(ret);
        return -1;
    }

    mbedtls_printf(" ok\n");

    // mbedtls_printf("  . Loading the CA root certificate ...");
    // fflush(stdout);

    // ret = mbedtls_x509_crt_parse_file(&client_cltcert, CA_CRT_PATH);
    // if (ret < 0) {
    //     mbedtls_printf( " client_cacert failed\n  !  mbedtls_x509_crt_parse_file returned -0x%x\n\n", -ret );
    //     client_free_mbedtls(ret);
    //     return -1;
    // }

    //=====================================================================================
        // mbedtls_printf("\n  . Creating normal server cert and key...");
        // fflush(stdout);
        // ret = mbedtls_x509_crt_parse_file(&client_cltcert, SRV_CRT_PATH);
        // if (ret != 0) {
        //     mbedtls_printf(" client_cltcert failed\n  !  mbedtls_x509_crt_parse_file returned %d\n\n", ret);
        //     client_free_mbedtls(ret);
        //     return -1;
        // }
        // ret = mbedtls_pk_parse_keyfile(&client_pkey, SRV_KEY_PATH, /*password=*/NULL,
        //                                mbedtls_ctr_drbg_random, &client_ctr_drbg);
        // if (ret != 0) {
        //     mbedtls_printf(" failed\n  !  mbedtls_pk_parse_keyfile returned %d\n\n", ret);
        //     client_free_mbedtls(ret);
        //     return -1;
        // }

        // mbedtls_printf(" ok\n");

    //=====================================================================================

    //MBEDTLS_SSL_VERIFY_OPTIONAL, MBEDTLS_SSL_VERIFY_NONE
    mbedtls_ssl_conf_authmode(&client_conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    // mbedtls_ssl_conf_ca_chain(&client_conf, &client_cacert, NULL);
    // mbedtls_printf(" ok\n");

    if (in_sgx) {
        /*
            * RA-TLS verification with DCAP inside SGX enclave uses dummies instead of real
            * functions from libsgx_urts.so, thus we don't need to load this helper library.
            */
        client_ra_tls_verify_lib = dlopen("libra_tls_verify_dcap_gramine.so", RTLD_LAZY);
        if (!client_ra_tls_verify_lib) {
            mbedtls_printf("%s\n", dlerror());
            mbedtls_printf("User requested RA-TLS verification with DCAP inside SGX but cannot find lib\n");
            mbedtls_printf("Please make sure that you are using client_dcap.manifest\n");
            return -1;
        }
    } else {
        client_ra_tls_verify_lib = dlopen("libra_tls_verify_dcap.so", RTLD_LAZY);
        if (!client_ra_tls_verify_lib) {
            mbedtls_printf("%s\n", dlerror());
            mbedtls_printf("User requested RA-TLS verification with DCAP but cannot find lib\n");
            return -1;
        }
    }


    if (client_ra_tls_verify_lib) {
        ra_tls_verify_callback_der_f = dlsym(client_ra_tls_verify_lib, "ra_tls_verify_callback_der");
        if ((error = dlerror()) != NULL) {
            mbedtls_printf("%s\n", error);
            dlclose(client_ra_tls_verify_lib);
            return -1;
        }

        ra_tls_set_measurement_callback_f = dlsym(client_ra_tls_verify_lib, "ra_tls_set_measurement_callback");
        if ((error = dlerror()) != NULL) {
            mbedtls_printf("%s\n", error);
            dlclose(client_ra_tls_verify_lib);
            return -1;
        }
    }

    // mbedtls_printf("[ using default SGX-measurement verification callback"
    //                 " (via RA_TLS_* environment variables) ]\n");
    // (*ra_tls_set_measurement_callback_f)(NULL); /* just to test RA-TLS code */

   
    /* use RA-TLS verification callback; this will overwrite CA chain set up above */
    mbedtls_printf("  . Installing TLS callback ...");
    mbedtls_ssl_conf_verify(&client_conf, &my_verify_callback, NULL);
    mbedtls_printf(" ok\n");
    dlclose(client_ra_tls_verify_lib);
    

    mbedtls_ssl_conf_rng(&client_conf, mbedtls_ctr_drbg_random, &client_ctr_drbg);
    mbedtls_ssl_conf_dbg(&client_conf, my_debug, stdout);

    mbedtls_printf("  . Setting up the SSL data....");
    
    ret = mbedtls_ssl_conf_own_cert(&client_conf, &client_cltcert, &client_pkey);
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret);
        client_free_mbedtls(ret);
        return -1;
    }


    ret = mbedtls_ssl_setup(&client_ssl, &client_conf);
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret);
        client_free_mbedtls(ret);
        return -1;
    }

    ret = mbedtls_ssl_set_hostname(&client_ssl, hostname);
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret);
        client_free_mbedtls(ret);
        return -1;
    }
    mbedtls_printf(" ok\n");

    mbedtls_ssl_set_bio(&client_ssl, &client_server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    mbedtls_printf("  . Performing the SSL/TLS handshake...");
    fflush(stdout);

    while ((ret = mbedtls_ssl_handshake(&client_ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", -ret);
            client_free_mbedtls(ret);
            return -1;
        }
    }

    mbedtls_printf(" ...ok\n");

    mbedtls_printf("  . Verifying peer X.509 certificate...");

    flags = mbedtls_ssl_get_verify_result(&client_ssl);
    if (flags != 0) {
        char vrfy_buf[512];
        mbedtls_printf(" failed\n");
        mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);
        mbedtls_printf("%s\n", vrfy_buf);

        /* verification failed for whatever reason, fail loudly */
        client_free_mbedtls(ret);
        return -1;
    } else {
        mbedtls_printf(" ok\n");
    }

    // mbedtls_ssl_close_notify(&client_ssl);
    // exit_code = MBEDTLS_EXIT_SUCCESS;

    return 0;
}

int ce_client_exchange_data(const char *data){
    size_t len;
    int ret;

    char *buffer;
    buffer = (char *)malloc(strlen(data)+1);
    memset(buffer,0,strlen(data)+1);
    strcpy(buffer, data);

    /* write data to counterpart */
    mbedtls_printf("  > Write data to server:");
    fflush(stdout);
    len = strlen(buffer);
    while ((ret = mbedtls_ssl_write(&client_ssl, (unsigned char *)buffer, len)) <= 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n  ! mbedtls_ssl_write returned %d\n\n", ret);
            client_free_mbedtls(ret);
            return -1;
        }
    }
    len = ret;
    mbedtls_printf(" %lu bytes written\n\n  %s\n\n", len, buffer);
    free(buffer);

    return 0;
}

void client_free_mbedtls(int ret){
#ifdef MBEDTLS_ERROR_C
    if (client_exit_code != MBEDTLS_EXIT_SUCCESS) {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        mbedtls_printf("Last error was: %d - %s\n\n", ret, error_buf);
    }
#endif

    if (client_ra_tls_verify_lib)
        dlclose(client_ra_tls_verify_lib);
    if (client_ra_tls_attest_lib)
        dlclose(client_ra_tls_attest_lib);

    mbedtls_net_free(&client_server_fd);

    mbedtls_x509_crt_free(&client_cltcert);
    mbedtls_pk_free(&client_pkey);
    mbedtls_x509_crt_free(&client_cacert);
    mbedtls_ssl_free(&client_ssl);
    mbedtls_ssl_config_free(&client_conf);
    mbedtls_ctr_drbg_free(&client_ctr_drbg);
    mbedtls_entropy_free(&client_entropy);

    // free(client_der_key);
    // free(client_der_crt);
}