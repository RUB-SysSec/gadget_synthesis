#!/bin/bash

set -eu

source docker_config.sh

function yes_no() {
    if [[ "$1" == "yes" || "$1" == "y" ]]; then
        return 0
    else
        return 1
    fi
}

ancestor="$(docker ps --filter="ancestor=${IMAGE_NAME}" --latest --quiet)"
if [[ -n "$ancestor" ]]; then
    # Connec to already running container
    echo "[+] Found running instance: $ancestor, connecting..."
    cmd="docker exec -it --user "$UID:$(id -g)" $ancestor /usr/bin/zsh"
    echo "$cmd"
    $cmd
    exit 0
fi

touch "$PWD/docker_data/bash_history"
touch "$PWD/docker_data/zsh_history"

echo "[+] Creating new container..."
cmd="docker run -t -d --privileged \
    -v $PWD:/home/user/synthesis/gadget_synthesis \
    -v $PWD/docker_data/zshrc:/home/user/.zshrc \
    -v $PWD/docker_data/zsh_history:/home/user/.zsh_history \
    -v $PWD/docker_data/bash_history:/home/user/.bash_history \
    --net=host --name ${NAME} \
    ${IMAGE_NAME} /home/user/synthesis/gadget_synthesis/docker_data/init.sh"

echo "$cmd"
$cmd

echo "[+] Rerun run.sh to connect to the new container."
