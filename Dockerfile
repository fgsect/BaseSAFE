# syntax=docker/dockerfile:1.2
FROM rust:bullseye AS basesafe
LABEL "maintainer"="Dominik Maier <dmaier@sect.tu-berlin.de>"
LABEL "about"="BaseSAFE Docker image"

# install sccache to cache subsequent builds of dependencies
RUN cargo install sccache

ENV HOME=/root
ENV SCCACHE_CACHE_SIZE="1G"
ENV SCCACHE_DIR=$HOME/.cache/sccache
ENV RUSTC_WRAPPER="/usr/local/cargo/bin/sccache"
ENV IS_DOCKER="1"
RUN sh -c 'echo set encoding=utf-8 > /root/.vimrc' \
    echo "export PS1='"'[LibAFL \h] \w$(__git_ps1) \$ '"'" >> ~/.bashrc && \
    mkdir ~/.cargo && \
    echo "[build]\nrustc-wrapper = \"${RUSTC_WRAPPER}\"" >> ~/.cargo/config

RUN rustup component add rustfmt clippy

# Install clang 11, common build tools
RUN apt update && apt install -y build-essential gdb git wget clang clang-tools libc++-11-dev libc++abi-11-dev python3-setuptools

# Copy a dummy.rs and Cargo.toml first, so that dependencies are cached
RUN mkdir /BaseSAFE
WORKDIR /BaseSAFE
RUN git clone https://github.com/AFLplusplus/AFLplusplus.git && \
    cd AFLplusplus && \
    git checkout 89ddd9998c0e955e0277ba077c7186b77615f0e8 && \
    make distrib && \
    make install && \
    cd ..

COPY paper.png README.md ./
COPY examples examples

ENTRYPOINT [ "/bin/bash" ]
