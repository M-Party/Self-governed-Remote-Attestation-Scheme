#!/bin/bash

function build_fabric_client()
{
    docker-compose -f docker-compose-fabric-client.yaml build
}

function start_fabric_client()
{
    docker-compose -f docker-compose-fabric-client.yaml up
}

function stop_fabric_client()
{
    docker-compose -f docker-compose-fabric-client.yaml down
}


function echo_help()
{
    echo "$0 [start|stop]"
}

if [[ $# != 1 ]]; then
        echo_help
        exit
fi

case $1 in
    build) build_fabric_client
            ;;
    start) start_fabric_client
            ;;
    stop)  stop_fabric_client
            ;;
    *)    echo_help
            ;;
esac
