#!/bin/bash

function build_ce()
{
    docker-compose -f docker-compose.yaml build
}

function start_ce()
{
    docker-compose -f docker-compose.yaml up
}

function stop_ce()
{
    docker-compose -f docker-compose.yaml down
}

function echo_help()
{
    echo "Usage: ce.sh [start|build|stop|help]"
}

if [[ $# != 1 ]]; then
        echo_help
        exit
fi

case $1 in
    build) build_ce
            ;;
    start) start_ce
            ;;
    stop)  stop_ce
            ;;
    help) echo_help
            ;;
    *)    echo_help
            ;;
esac
