#!/bin/bash

function build()
{
    make clean
    make SGX=1
}

function start()
{
    export RA_TLS_ALLOW_DEBUG_ENCLAVE_INSECURE="1" && \
    export RA_TLS_ALLOW_OUTDATED_TCB_INSECURE="1" && \
    python3 relying_party_owner/rpo.py
}

function sgx()
{
    gramine-sgx python relying_party_owner/rpo.py
}

function echo_help()
{
    echo "Usage: startup.sh [start|build|help]"
}

if [[ $# != 1 ]]; then
        echo_help
        exit
fi

case $1 in
    build) build
            ;;
    start) start
            ;;
    sgx) sgx
	    ;;
    help)  echo_help
            ;;
    *)    echo_help
            ;;
esac
