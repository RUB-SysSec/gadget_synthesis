FROM ubuntu:20.04

ARG GHIDRA_VERSION="9.2.2_PUBLIC_20201229"
ARG GHIDRA_SHA256="8cf8806dd5b8b7c7826f04fad8b86fc7e07ea380eae497f3035f8c974de72cf8"

ARG DEBIAN_FRONTEND=noninteractive
ARG TZ=Europe/Berlin

RUN apt update && apt install -y \
    build-essential git \
        z3 libz3-dev \
        curl wget \
        make cmake \
        locales locales-all \
        sudo \
        neovim tree ripgrep \
        rr gdb strace ltrace valgrind \
        htop \
        parallel psmisc \
        zip unzip \
        screen tmux \
        linux-tools-common linux-tools-generic \
        zsh powerline fonts-powerline \
        python3 python3-pip python3-venv \
        default-jre default-jdk

# MISC NOTES
# * psmisc contains killall
# * for rr, user must run
#   echo 1 | sudo tee /proc/sys/kernel/perf_event_paranoid

RUN locale-gen en_US.UTF-8
ARG USER_UID=1000
ARG USER_GID=1000

RUN echo "%sudo ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

WORKDIR /tmp
RUN update-locale LANG=en_US.UTF-8
ENV LANG=en_US.UTF-8

RUN groupadd -g ${USER_GID} user

# add user (-l flag to prevent faillog / lastlog from becoming huge)
RUN useradd -l --shell /bin/bash -c "" -m -u ${USER_UID} -g user -G sudo user

ARG HOME="/home/user"
WORKDIR "/home/user"
USER user

# install GEF (gdb extension)
RUN wget -O ~/.gdbinit-gef.py -q https://tinyurl.com/gef-master   && echo source ~/.gdbinit-gef.py >> ~/.gdbinit

# zsh agnoster
RUN sh -c "$(wget -O- https://raw.githubusercontent.com/deluan/zsh-in-docker/master/zsh-in-docker.sh)" --     -t agnoster


# Install Ghidra
RUN mkdir builds && cd builds && \
    wget -q -O ghidra.zip https://ghidra-sre.org/ghidra_${GHIDRA_VERSION}.zip && \
    echo "${GHIDRA_SHA256} *ghidra.zip" | sha256sum -c && \
    unzip -q ghidra.zip && \
    rm ghidra.zip


WORKDIR /home/user/synthesis
RUN sudo chown user:user .

# Create symbolic links to ghidra and ghidra-analyzeHeadless
RUN ln -s $HOME/builds/ghidra* ghidra && \
    mkdir -p $HOME/.local/bin && \
    ln -s $HOME/builds/ghidra*/support/analyzeHeadless $HOME/.local/bin/ghidra-analyzeHeadless
