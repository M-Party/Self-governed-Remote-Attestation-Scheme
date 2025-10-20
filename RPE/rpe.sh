#!/bin/bash

function build_rpe()
{
    docker-compose -f docker-compose.yaml build
}

function start_rpe()
{
    docker-compose -f docker-compose.yaml up
}

function stop_rpe()
{
    docker-compose -f docker-compose.yaml down
}

function echo_help()
{
    echo "Usage: rpe.sh [start|build|stop|help]"
}

if [[ $# != 1 ]]; then
        echo_help
        exit
fi

case $1 in
    build) build_rpe
            ;;
    start) start_rpe
            ;;
    stop)  stop_rpe
            ;;
    help) echo_help
            ;;
    *)    echo_help
            ;;
esac
