#!/bin/bash

set -eu

source docker_config.sh

mkdir -p shared
docker build --build-arg USER_UID="$(id -u)" --build-arg USER_GID="$(id -g)" "$@" -t "$IMAGE_NAME" .
