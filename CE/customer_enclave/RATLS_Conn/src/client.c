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

/* RA-TLS: on client, only need to register ra_tls_verify_callback_der() for cert verification */
int (*ra_tls_verify_callback_der_f)(uint8_t* der_crt, size_t der_crt_size);

/* RA-TLS: if specified in command-line options, use our own callback to verify SGX measurements */
void (*ra_tls_set_measurement_callback_f)(int (*f_cb)(const char* mrenclave, const char* mrsigner,
                                          const char* isv_prod_id, const char* isv_svn));

/* RA-TLS: on server, only need ra_tls_create_key_and_crt_der() to create keypair and X.509 cert */
int (*ra_tls_create_key_and_crt_der_f)(uint8_t** der_key, size_t* der_key_size, uint8_t** der_crt,
                                       size_t* der_crt_size);
                            
void free_mbedtls(int ret);    
void exchange_data_for_verification(void); 
// #define SERVER_PORT "4433"
// #define SERVER_NAME "192.168.122.54"
#define GET_REQUEST "  Hello RPE\r\n\r\n"

#define DEBUG_LEVEL 0

// #define CA_CRT_PATH "ssl/ca.crt"
// #define SRV_CRT_PATH "ssl/server.crt"
// #define SRV_KEY_PATH "ssl/server.key"

static char signing_key_buf[375];
static char encryption_keys_buf[651];
static char ce_id_buf[10];

static void my_debug(void* ctx, int level, const char* file, int line, const char* str) {
    ((void)level);

    mbedtls_fprintf((FILE*)ctx, "%s:%04d: %s\n", file, line, str);
    fflush((FILE*)ctx);
}

/* expected SGX measurements in binary form */
// static char g_expected_mrenclave[32];
// static char g_expected_mrsigner[32];
// static char g_expected_isv_prod_id[2];
// static char g_expected_isv_svn[2];

// static bool g_verify_mrenclave   = false;
// static bool g_verify_mrsigner    = false;
// static bool g_verify_isv_prod_id = false;
// static bool g_verify_isv_svn     = false;

/* RA-TLS: our own callback to verify SGX measurements */
// static int my_verify_measurements(const char* mrenclave, const char* mrsigner,
//                                   const char* isv_prod_id, const char* isv_svn) {
//     assert(mrenclave && mrsigner && isv_prod_id && isv_svn);

//     if (g_verify_mrenclave &&
//             memcmp(mrenclave, g_expected_mrenclave, sizeof(g_expected_mrenclave)))
//         return -1;

//     if (g_verify_mrsigner &&
//             memcmp(mrsigner, g_expected_mrsigner, sizeof(g_expected_mrsigner)))
//         return -1;

//     if (g_verify_isv_prod_id &&
//             memcmp(isv_prod_id, g_expected_isv_prod_id, sizeof(g_expected_isv_prod_id)))
//         return -1;

//     if (g_verify_isv_svn &&
//             memcmp(isv_svn, g_expected_isv_svn, sizeof(g_expected_isv_svn)))
//         return -1;

//     return 0;
// }

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


bool init_pubkeys(const char * signing_key, const char * encryption_keys){
    if (sizeof(signing_key_buf) - 1 < strlen(signing_key)) {
        mbedtls_printf("\n length of signing_key_buf is less than signing_key");
        return false;
    }
    if (sizeof(encryption_keys_buf) - 1 < strlen(encryption_keys)) {
        mbedtls_printf("\n length of encryption_keys_buf is less than encryption_keys");
        return false;
    }
    strncpy(signing_key_buf, signing_key, sizeof(signing_key_buf) - 1);
    strncpy(encryption_keys_buf, encryption_keys, sizeof(encryption_keys_buf) - 1);
    return true;
}

void init_ce_id(const char * ce_id){
    if (sizeof(ce_id_buf) - 1 < strlen(ce_id)) {
        mbedtls_printf("\n length of ce_id_buf is less than ce_id");
        exit(0);
    }
    strncpy(ce_id_buf, ce_id, sizeof(ce_id_buf) - 1);
}


mbedtls_net_context server_fd;
mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_ssl_context ssl;
mbedtls_ssl_config conf;
mbedtls_x509_crt cacert;
mbedtls_x509_crt cltcert;
mbedtls_pk_context pkey;
void* ra_tls_verify_lib = NULL;
void* ra_tls_attest_lib;
uint8_t* der_key = NULL;
uint8_t* der_crt = NULL;

int exit_code = MBEDTLS_EXIT_FAILURE;

unsigned char data[2048];
char *ra_tls_client(const char * hostname, const char * port) {
    int ret;
    size_t len;

    uint32_t flags;
    const char* pers = "ssl_client1";
    bool in_sgx = getenv_client_inside_sgx();

    char* error;

    ra_tls_verify_callback_der_f      = NULL;
    ra_tls_set_measurement_callback_f = NULL;

#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif

    mbedtls_net_init(&server_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_x509_crt_init(&cacert);
    mbedtls_x509_crt_init(&cltcert);
    mbedtls_pk_init(&pkey);
    mbedtls_entropy_init(&entropy);


    // if (argc < 2 ||
    //         (strcmp(argv[1], "native") && strcmp(argv[1], "epid") && strcmp(argv[1], "dcap"))) {
    //     mbedtls_printf("USAGE: %s native|epid|dcap [SGX measurements]\n", argv[0]);
    //     return 1;
    // }

    // if (!strcmp(argv[1], "epid")) {
    //     ra_tls_verify_lib = dlopen("libra_tls_verify_epid.so", RTLD_LAZY);
    //     if (!ra_tls_verify_lib) {
    //         mbedtls_printf("%s\n", dlerror());
    //         mbedtls_printf("User requested RA-TLS verification with EPID but cannot find lib\n");
    //         if (in_sgx) {
    //             mbedtls_printf("Please make sure that you are using client_epid.manifest\n");
    //         }
    //         return 1;
    //     }
    // } else if (!strcmp(argv[1], "dcap")) 
    // {

    //=====================================================================================

    char attestation_type_str[32] = {0};
    ret = file_read("/dev/attestation/attestation_type", attestation_type_str,
                    sizeof(attestation_type_str) - 1);
    if (ret < 0 && ret != -ENOENT) {
        mbedtls_printf("User requested RA-TLS attestation but cannot read SGX-specific file "
                       "/dev/attestation/attestation_type\n");
        return NULL;
    }

    if (ret == -ENOENT || !strcmp(attestation_type_str, "none")) {
        ra_tls_attest_lib = NULL;
        ra_tls_create_key_and_crt_der_f = NULL;
    } else if (!strcmp(attestation_type_str, "epid") || !strcmp(attestation_type_str, "dcap")) {
        ra_tls_attest_lib = dlopen("libra_tls_attest.so", RTLD_LAZY);
        if (!ra_tls_attest_lib) {
            mbedtls_printf("User requested RA-TLS attestation but cannot find lib\n");
            return NULL;
        }

        char* error;
        ra_tls_create_key_and_crt_der_f = dlsym(ra_tls_attest_lib, "ra_tls_create_key_and_crt_der");
        if ((error = dlerror()) != NULL) {
            mbedtls_printf("%s\n", error);
            dlclose(ra_tls_attest_lib);
            return NULL;
        }
    } else {
        mbedtls_printf("Unrecognized remote attestation type: %s\n", attestation_type_str);
        return NULL;
    }

    mbedtls_printf("\n  . Seeding the random number generator...");
    fflush(stdout);

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                (const unsigned char*)pers, strlen(pers));
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        free_mbedtls(ret);
        return NULL;
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
            free_mbedtls(ret);
            return NULL;
        }

        ret = mbedtls_x509_crt_parse(&cltcert, (unsigned char*)der_crt, der_crt_size);
        if (ret != 0) {
            mbedtls_printf(" failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret);
            free_mbedtls(ret);
            return NULL;
        }

        ret = mbedtls_pk_parse_key(&pkey, (unsigned char*)der_key, der_key_size, /*pwd=*/NULL, 0,
                                   mbedtls_ctr_drbg_random, &ctr_drbg);
        if (ret != 0) {
            mbedtls_printf(" failed\n  !  mbedtls_pk_parse_key returned %d\n\n", ret);
            free_mbedtls(ret);
            return NULL;
        }

        mbedtls_printf(" ok\n");
        dlclose(ra_tls_attest_lib);
    }

    mbedtls_printf("  . Connecting to tcp/%s/%s...", hostname, port);
    fflush(stdout);

    while(true){
        ret = mbedtls_net_connect(&server_fd, hostname, port, MBEDTLS_NET_PROTO_TCP);
        if (ret != 0) {
            mbedtls_printf(" failed\n  ! mbedtls_net_connect returned %d\n\n", ret);
            sleep(3);
        }
        else{
            break;
        }
    }

    mbedtls_printf(" ok\n");

    mbedtls_printf("  . Setting up the default SSL configuration...");
    fflush(stdout);

    ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
        free_mbedtls(ret);
        return NULL;
    }

    mbedtls_printf(" ok\n");

    // mbedtls_printf("  . Loading the CA root certificate ...");
    // fflush(stdout);

    // ret = mbedtls_x509_crt_parse_file(&cltcert, CA_CRT_PATH);
    // if (ret < 0) {
    //     mbedtls_printf( " cacert failed\n  !  mbedtls_x509_crt_parse_file returned -0x%x\n\n", -ret );
    //     goto exit;
    // }

    //=====================================================================================
        // mbedtls_printf("\n  . Creating normal server cert and key...");
        // fflush(stdout);
        // ret = mbedtls_x509_crt_parse_file(&cltcert, SRV_CRT_PATH);
        // if (ret != 0) {
        //     mbedtls_printf(" cltcert failed\n  !  mbedtls_x509_crt_parse_file returned %d\n\n", ret);
        //     goto exit;
        // }
        // ret = mbedtls_pk_parse_keyfile(&pkey, SRV_KEY_PATH, /*password=*/NULL,
        //                                mbedtls_ctr_drbg_random, &ctr_drbg);
        // if (ret != 0) {
        //     mbedtls_printf(" failed\n  !  mbedtls_pk_parse_keyfile returned %d\n\n", ret);
        //     goto exit;
        // }

        // mbedtls_printf(" ok\n");

    //=====================================================================================




    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
    // mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    // mbedtls_printf(" ok\n");

    if (in_sgx) {
        /*
            * RA-TLS verification with DCAP inside SGX enclave uses dummies instead of real
            * functions from libsgx_urts.so, thus we don't need to load this helper library.
            */
        ra_tls_verify_lib = dlopen("libra_tls_verify_dcap_gramine.so", RTLD_LAZY);
        if (!ra_tls_verify_lib) {
            mbedtls_printf("%s\n", dlerror());
            mbedtls_printf("User requested RA-TLS verification with DCAP inside SGX but cannot find lib\n");
            mbedtls_printf("Please make sure that you are using client_dcap.manifest\n");
            return NULL;
        }
    } else {
        ra_tls_verify_lib = dlopen("libra_tls_verify_dcap.so", RTLD_LAZY);
        if (!ra_tls_verify_lib) {
            mbedtls_printf("%s\n", dlerror());
            mbedtls_printf("User requested RA-TLS verification with DCAP but cannot find lib\n");
            return NULL;
        }
    }


    if (ra_tls_verify_lib) {
        ra_tls_verify_callback_der_f = dlsym(ra_tls_verify_lib, "ra_tls_verify_callback_der");
        if ((error = dlerror()) != NULL) {
            mbedtls_printf("%s\n", error);
            dlclose(ra_tls_verify_lib);
            return NULL;
        }

        ra_tls_set_measurement_callback_f = dlsym(ra_tls_verify_lib, "ra_tls_set_measurement_callback");
        if ((error = dlerror()) != NULL) {
            mbedtls_printf("%s\n", error);
            dlclose(ra_tls_verify_lib);
            return NULL;
        }
    }

    mbedtls_printf("[ using default SGX-measurement verification callback"
                    " (via RA_TLS_* environment variables) ]\n");
    (*ra_tls_set_measurement_callback_f)(NULL); /* just to test RA-TLS code */

    if (ra_tls_verify_lib) {
        /* use RA-TLS verification callback; this will overwrite CA chain set up above */
        mbedtls_printf("  . Installing RA-TLS callback ...");
        mbedtls_ssl_conf_verify(&conf, &my_verify_callback, NULL);
        mbedtls_printf(" ok\n");
        dlclose(ra_tls_verify_lib);
    }

    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);

    mbedtls_printf("  . Setting up the SSL data....");
    
    ret = mbedtls_ssl_conf_own_cert(&conf, &cltcert, &pkey);
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret);
        free_mbedtls(ret);
        return NULL;
    }

    ret = mbedtls_ssl_setup(&ssl, &conf);
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret);
        free_mbedtls(ret);
        return NULL;
    }

    ret = mbedtls_ssl_set_hostname(&ssl, hostname);
    if (ret != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret);
        free_mbedtls(ret);
        return NULL;
    }
    mbedtls_printf(" ok\n");

    mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    mbedtls_printf("  . Performing the SSL/TLS handshake...");
    fflush(stdout);

    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", -ret);
            free_mbedtls(ret);
            return NULL;
        }
    }

    mbedtls_printf(" ...ok\n");

    // CE does not need to verify RPE certificate
    // mbedtls_printf("  . Verifying peer (rpe) X.509 certificate...");

    // flags = mbedtls_ssl_get_verify_result(&ssl);
    // if (flags != 0) {
    //     char vrfy_buf[512];
    //     mbedtls_printf(" failed\n");
    //     mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);
    //     mbedtls_printf("%s\n", vrfy_buf);

    //     /* verification failed for whatever reason, fail loudly */
    //     goto exit;
    // } else {
    //     mbedtls_printf(" ok\n");
    // }

    // get data value.
    exchange_data_for_verification();
    return (char*)data;
}

void exchange_data_for_verification(void){
    size_t len;
    int ret;

    /* write ce id to rpe */
    mbedtls_printf("  > Write ce id to server:");
    fflush(stdout);
    len = sizeof(ce_id_buf) - 1;
    while ((ret = mbedtls_ssl_write(&ssl, (unsigned char *)ce_id_buf, len)) <= 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n  ! mbedtls_ssl_write returned %d\n\n", ret);
            free_mbedtls(ret);
            exit(0);
        }
    }
    len = ret;
    mbedtls_printf(" %lu bytes written\n\n  %s\n\n", len, (char*)ce_id_buf);

    /* write public signing key to rpe */
    mbedtls_printf("  > Write signing key to server:");
    fflush(stdout);
    len = sizeof(signing_key_buf) - 1;
    while ((ret = mbedtls_ssl_write(&ssl, (unsigned char *)signing_key_buf, len)) <= 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n  ! mbedtls_ssl_write returned %d\n\n", ret);
            free_mbedtls(ret);
            exit(0);
        }
    }
    len = ret;
    mbedtls_printf(" %lu bytes written\n\n%s", len, (char*)signing_key_buf);

    /* write public encryption key to rpe */
    mbedtls_printf("  > Write encryption key to server:");
    fflush(stdout);
    len = sizeof(encryption_keys_buf) - 1;
    while ((ret = mbedtls_ssl_write(&ssl, (unsigned char *)encryption_keys_buf, len)) <= 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n  ! mbedtls_ssl_write returned %d\n\n", ret);
            free_mbedtls(ret);
            exit(0);
        }
    }
    len = ret;
    mbedtls_printf(" %lu bytes written\n\n%s", len, (char*)encryption_keys_buf);   

    /* read certificate from rpe */
    mbedtls_printf("  < Read certificate from rpe:");
    fflush(stdout);

    do {
        len = sizeof(data) - 1;
        memset(data, 0, sizeof(data));
        ret = mbedtls_ssl_read(&ssl, data, len);

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
        mbedtls_printf(" %lu bytes read\n\n%s", len, (char*)data);

        if (ret > 0)
            break;

    } while (1);   
}

unsigned char receive_data[2048];
unsigned char *read_write_data_from(const char * exchange_data){
    size_t len;
    int ret;

    
    char *buffer;
    buffer = (char *)malloc(strlen(exchange_data)+1);
    memset(buffer,0,strlen(exchange_data)+1);
    strcpy(buffer, exchange_data);


    /* write ce data to rpe */
    mbedtls_printf("  > Write ce data to rpe:");
    fflush(stdout);
    len = strlen(buffer);
    while ((ret = mbedtls_ssl_write(&ssl, (unsigned char *)buffer, len)) <= 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n  ! mbedtls_ssl_write returned %d\n\n", ret);
            free_mbedtls(ret);
            exit(0);
        }
    }
    len = ret;
    mbedtls_printf(" %lu bytes written\n\n  %s\n\n", len, buffer); 
    free(buffer);

    /* read something from rpe */
    mbedtls_printf("  < Read from rpe:");
    fflush(stdout);
    
    do {
        len = sizeof(receive_data) - 1;
        memset(receive_data, 0, sizeof(receive_data));
        ret = mbedtls_ssl_read(&ssl, receive_data, len);

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
        mbedtls_printf(" %lu bytes read\n\n%s\n", len, (char*)receive_data);

        if (ret > 0)
            break;


    } while (1);   
    return receive_data;
}

void free_mbedtls(int ret){
#ifdef MBEDTLS_ERROR_C
    if (exit_code != MBEDTLS_EXIT_SUCCESS) {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        mbedtls_printf("Last error was: %d - %s\n\n", ret, error_buf);
    }
#endif

    if (ra_tls_verify_lib)
        dlclose(ra_tls_verify_lib);
    if (ra_tls_attest_lib)
        dlclose(ra_tls_attest_lib);

    mbedtls_net_free(&server_fd);

    mbedtls_x509_crt_free(&cltcert);
    mbedtls_pk_free(&pkey);
    mbedtls_x509_crt_free(&cacert);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    free(der_key);
    free(der_crt);

}
