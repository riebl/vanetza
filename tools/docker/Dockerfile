FROM ubuntu:xenial
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    cmake \
    git \
    libboost-date-time-dev \
    libboost-program-options-dev \
    libboost-serialization-dev \
    libboost-system-dev \
    libcrypto++-dev \
    libgeographic-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*
COPY setup_workspace.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/setup_workspace.sh
RUN useradd -m build-user
USER build-user
WORKDIR /home/build-user
ENTRYPOINT bash
