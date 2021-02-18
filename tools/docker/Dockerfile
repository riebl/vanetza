FROM ubuntu:xenial
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    git \
    libboost-date-time-dev \
    libboost-program-options-dev \
    libboost-system-dev \
    libcrypto++-dev \
    libgeographic-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*
COPY build_and_run_tests.sh /usr/local/bin/build_and_run_tests.sh
RUN useradd -m build-user
USER build-user
WORKDIR /home/build-user
SHELL ["/bin/bash", "-c"]
ENTRYPOINT ["build_and_run_tests.sh"]
CMD ["/home/build-user/workspace"]
