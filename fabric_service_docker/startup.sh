#!/bin/bash

function start()
{   
    export TCF_HOME=fabric_service
    python3 fabric_service/conductor.py
}

function echo_help()
{
    echo "Usage: startup.sh [start|help]"
}

if [ $# != 1 ]; then
        echo_help
        exit
fi

case $1 in
    start) start
            ;;
    stop)  echo_help
            ;;
    *)    echo_help
            ;;
esac
