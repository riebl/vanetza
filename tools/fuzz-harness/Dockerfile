ARG VERSION=latest
FROM aflplusplus/aflplusplus:${VERSION}

# install build dependencies for Vanetza
RUN apt-get update && apt-get install --no-install-recommends -y \
    libboost-all-dev libcrypto++-dev libgeographic-dev libssl-dev

# install casr-afl tool
RUN cargo install --root /usr/local casr

# set up "fuzz" user and mapping of host user
RUN useradd -m -s /bin/bash fuzz
RUN cp /root/.bashrc /home/fuzz/.bashrc && chown fuzz:fuzz /home/fuzz/.bashrc
COPY docker-entrypoint.sh /docker-entrypoint.sh
ENTRYPOINT ["/docker-entrypoint.sh"]
