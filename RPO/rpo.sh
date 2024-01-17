#!/bin/bash

function build_rpo()
{
    docker-compose -f docker-compose.yaml build
}

function start_rpo()
{
    docker-compose -f docker-compose.yaml up
}

function stop_rpo()
{
    docker-compose -f docker-compose.yaml down
}

function echo_help()
{
    echo "Usage: rpo.sh [start|build|stop|help]"
}

if [[ $# != 1 ]]; then
        echo_help
        exit
fi

case $1 in
    build) build_rpo
            ;;
    start) start_rpo
            ;;
    stop)  stop_rpo
            ;;
    help) echo_help
            ;;
    *)    echo_help
            ;;
esac
