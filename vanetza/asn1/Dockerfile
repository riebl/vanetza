FROM ubuntu:latest AS base

FROM base AS build
RUN apt-get update && apt-get install -y autoconf automake bison build-essential flex git libtool
ARG ASN1C_REPO=https://github.com/mouse07410/asn1c.git
ARG ASN1C_VERSION=eefc4cfca40e5ee6e0b6506d6d8c93c24d423cec
RUN git clone $ASN1C_REPO /asn1c-source && cd /asn1c-source && git checkout ${ASN1C_VERSION}
WORKDIR /asn1c-source
RUN autoreconf -iv && ./configure --prefix /asn1c && make -j $(nproc) install

FROM build AS test
RUN make -j $(nproc) check
RUN make -j $(nproc) distcheck

FROM base AS runtime
RUN apt-get update && apt-get install -y cmake
COPY --from=build /asn1c/bin /usr/bin
COPY --from=build /asn1c/share /usr/share