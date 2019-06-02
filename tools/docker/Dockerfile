FROM ubuntu:xenial
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    cmake \
    git \
    libboost-date-time-dev \
    libboost-program-options-dev \
    libboost-system-dev \
    libcrypto++-dev \
    libgeographic-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*
RUN useradd -m build-user
USER build-user
WORKDIR /home/build-user
ENTRYPOINT bash
