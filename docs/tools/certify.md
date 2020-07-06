# Certify

*Certify* is a tool to create and view certificates and can be used to set up a test PKI for secured V2X communication based on TS 103 097 v1.2.1.

## Installation

You need to enable building this tool explicitly.
Run `cmake -D BUILD_CERTIFY=ON ..` in your build directory and rebuild Vanetza.
You should be able to find `bin/certify` in your build directory afterwards.

## PKI Setup

The following section describe how to setup a test PKI.
We will generate a root certificate, an authorization authority certificate and an authorization ticket.

### Generating Keys

New private keys can be generated using `bin/certify generate-key root.key`.
The corresponding public key can be extracted using `bin/certify extract-public-key --private-key root.key root.pub`, but this step usually isn't required.

Please generate a `root.key` for the root certificate, a `aa.key` for the authorization authority and a `ticket.key` for the authorization ticket.

### Generating Root Certificates

A root certificate can be generated using `bin/certify generate-root --subject-key root.key root.cert`.

### Generating Authorization Authorities

An authorization authority certificate can be generated using `bin/certify generate-aa --sign-key root.key --sign-cert root.cert --subject-key aa.key aa.cert`.

### Generating Authorization Tickets

An authorization ticket can be generated using `bin/certify generate-ticket --sign-key aa.key --sign-cert aa.cert --subject-key ticket.key ticket.cert`.

If you're generating a certificate for real V2X hardware, it will likely use a hardware security module (HSM), which will only expose the public key.
You can export the given public key to a file and use `--subject-key` also with public keys.
The public key needs to be encoded according to the rules specified by ETSI in TS 103 097 v1.2.1.

## Other Options

This guide only uses the required options.
Further options may be available for certain commands.
Use `bin/certify <command> --help` for further information.

## Acknowledgement

This application has been initially developed [Niklas Keller](https://github.com/kelunik).
