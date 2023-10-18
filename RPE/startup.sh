#!/bin/bash

function build()
{
    cd relying_party_enclave/quote_verification
    rm -rf build/ 
    swig -c++ -python verify_dcap_quote.i
    python3 setup.py build
    cp build/lib.linux-x86_64-3.*/*.so .
    cd ../..
    
#     cd relying_party_enclave/keys_generation
#     gcc -shared -o generate_key_pair.so generate_key_pair.c -lssl -lcrypto
#     cd ../..
    
    make clean
    make SGX=1
}

function start()
{
    gramine-sgx python relying_party_enclave/rpe.py
}

function echo_help()
{
    echo "Usage: rpe.sh [start|build|help]"
}

if [ $# != 1 ]; then
        echo_help
        exit
fi

case $1 in
    build) build
            ;;
    start) start
            ;;
    stop)  echo_help
            ;;
    *)    echo_help
            ;;
esac
