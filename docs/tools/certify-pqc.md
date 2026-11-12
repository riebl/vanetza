# Certify PQC

`certify-pqc` creates and checks experimental V3 certificate chains. It is a
separate executable so enabling PQC does not change existing `certify` commands
or their V2 output.

Certificate generation accepts `--profile ecc` or `--profile hybrid`. The
default is `hybrid`. The ECC profile exists to test interoperability against a
classical-only V3 chain within the experimental ASN.1 profile, encoded without
the alternative-key and signature fields.

Build it with both options enabled:

```shell
cmake -S . -B build-pqc -DVANETZA_WITH_PQC=ON -DBUILD_CERTIFY=ON
cmake --build build-pqc --target certify-pqc
```

`certify-pqc` requires a build with a proper security module, e.g. backed by OpenSSL.

## Generate a Chain

Generate a key for each certificate.
The command writes the ECC private key to `.key` and the ECC public key to `.pub`.
The default hybrid profile additionally writes an FN-DSA-512 key to `.pqc.key` and
`.pqc.pub`. The ticket needs no FN-DSA key:

```shell
build-pqc/bin/certify-pqc generate-key root
build-pqc/bin/certify-pqc generate-key aa
build-pqc/bin/certify-pqc generate-key ticket --profile ecc
```

Key options refer to a key by the name given to `generate-key`, e.g.
`--sign-key root`. Issuing a certificate requires the issuer's private key,
while the subject's public key suffices.

Generate the Root, AA, and AT in that order:

```shell
build-pqc/bin/certify-pqc generate-root \
  --profile hybrid \
  --output root.cert \
  --subject-key root \
  --subject-pqc-key root

build-pqc/bin/certify-pqc generate-aa \
  --profile hybrid \
  --output aa.cert \
  --sign-key root \
  --sign-cert root.cert \
  --sign-pqc-key root \
  --subject-key aa \
  --subject-pqc-key aa

build-pqc/bin/certify-pqc generate-ticket \
  --profile hybrid \
  --output ticket.cert \
  --sign-key aa \
  --sign-cert aa.cert \
  --sign-pqc-key aa \
  --subject-key ticket
```

Root and AA certificates contain an FN-DSA public key and signature. The AT
contains the FN-DSA signature but no FN-DSA public key.

When `--aid` is omitted, authority certificates retain the established V3
issue-permission defaults for CA, DEN, CP, GN management, and IPv6 routing,
including their SSP ranges. Tickets default to CA and DEN application
permissions. The AA also carries its subject ECC key as the public encryption
key, matching the existing V3 certificate-generation behavior.

### ECC-Only V3 Chain

Use the same ECC keys without generating FN-DSA keys:

```shell
build-pqc/bin/certify-pqc generate-root \
  --profile ecc --output root.cert --subject-key root

build-pqc/bin/certify-pqc generate-aa \
  --profile ecc --output aa.cert \
  --sign-key root --sign-cert root.cert --subject-key aa

build-pqc/bin/certify-pqc generate-ticket \
  --profile ecc --output ticket.cert \
  --sign-key aa --sign-cert aa.cert --subject-key ticket
```

These certificates contain only the standard ECC verification keys and
signatures, but they are still encoded with the experimental ASN.1 profile.
They are intended for ECC/hybrid comparisons between PQC-capable builds. They
are not interchangeable with credentials encoded by a strict build because
the profiles have different OER extension preambles.

## Inspect and Verify

```shell
build-pqc/bin/certify-pqc show ticket.cert

build-pqc/bin/certify-pqc verify-chain \
  --profile hybrid \
  --root root.cert \
  --aa aa.cert \
  --ticket ticket.cert \
  --aid 36
```

`verify-chain` performs existing V3 certificate policy checks, verifies every
outer ECC signature, requires the expected hybrid material, and verifies every
inner FN-DSA signature.

The optional `--aid` selects the ITS-AID checked against the chain's
permissions and defaults to Cooperative Awareness (`36`). Use the same AID
when generating and verifying a chain with custom permissions.

Use `--profile ecc` to verify an ECC-only V3 chain. This additionally rejects
the chain if any alternative PQC material is present.

Use `certify-pqc COMMAND --help` to see optional subject names, validity, and
ITS-AID arguments.
