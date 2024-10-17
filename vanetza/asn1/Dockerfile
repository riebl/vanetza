FROM alpine:3 AS base

FROM base AS build
ARG ASN1C_REPO=https://github.com/mouse07410/asn1c.git
ARG ASN1C_VERSION=18e5650
RUN apk add --no-cache autoconf automake bison build-base flex gcc git libtool
RUN git clone $ASN1C_REPO /asn1c-source && cd /asn1c-source && git checkout ${ASN1C_VERSION}
WORKDIR /asn1c-source
RUN autoreconf -iv && ./configure --prefix /asn1c && make -j $(nproc) install

FROM base AS runtime
ENV ASN1C_FLAGS="-fcompound-names -fincludes-quoted -no-gen-example"
COPY --from=build /asn1c /asn1c
