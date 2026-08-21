# SystemX Hybrid-PQC ASN.1 Profile

This directory keeps the experimental certificate additions separate from
Vanetza's standard ASN.1 inputs. `hybrid-pqc.patch` contains the complete
experimental delta. The unmodified input modules are fetched from pinned
official ETSI Forge revisions during regeneration instead of being duplicated
in the source tree.

The IEEE inputs are from the official `v2025` tag of the ETSI Forge mirror:

* repository: `https://forge.etsi.org/rep/ITS/asn1/ieee1609.2.git`
* commit: `77e2c822a11bf8adbe9848ad3fd4f311925aff30`
* `Ieee1609Dot2.asn` SHA-256:
  `82b5e35cbaadae1c6b2f087626b10d52afc73779c9ac6700c6445830d8824e0b`
* `Ieee1609Dot2BaseTypes.asn` SHA-256:
  `bf2b3d66d394449319323f8a59d8084d963c3ad55d6790e1436ab897221690fe`

The two ETSI TS 103 097 inputs are fetched from the official Release 2
repository:

* repository: `https://forge.etsi.org/rep/ITS/asn1/sec_ts103097.git`
* commit: `65e6d8ea88b2bfb3aca3151dbedf07d89b97fd00`

* `EtsiTs103097Module.asn` SHA-256:
  `245a3c10c176497f658c6a4d9ec804d3226dda2ac10a4351e382ddb5afe9ff72`
* `EtsiTs103097ExtensionModule.asn` SHA-256:
  `b94c9b373567dd9bfb15d61c8c206d5630f6b0c481ef41ddd574c96784a9eb1a`

The patch adds only the certificate material used by this implementation:

* the fixed-size `FnDsa512Key` and `FnDsa512Signature` types;
* FN-DSA-512 choices in `PublicVerificationKey` and `Signature`;
* `altVerificationKey` and `altSignatureValue` in
  `ToBeSignedCertificate`.

## Regeneration

Normal builds compile the committed generated files and do not need network
access, `asn1c`, Docker, or the patch utility. Regeneration is an explicit
maintainer action:

```shell
cmake -S . -B build-asn1 \
  -DVANETZA_WITH_PQC=ON \
  -DVANETZA_ASN1_WITH_ASN1C=ON \
  -DVANETZA_ASN1_WITH_ISO=ON
cmake --build build-asn1 --target generate_asn1c
```

The generation target fetches and verifies the pristine inputs in its build
directory, applies `hybrid-pqc.patch`, invokes `asn1c`, and refreshes the
committed output under `vanetza/asn1/systemx-pqc`.
