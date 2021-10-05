#!/bin/bash

set -eu

source docker_config.sh

ancestor="$(docker ps --filter="ancestor=${IMAGE_NAME}" --latest --quiet)"

if [[ -n "$ancestor" ]]; then
    echo "Found running instance $ancestor, stopping..."
    cmd="docker stop -t 5 $ancestor"
    echo "$cmd"
    $cmd
    cmd="docker rm -f $ancestor"
    echo "$cmd"
    $cmd
else
    echo "No running instance found..."
fi
exit 0
