The TS 103916 v2.1.1 POIM ASN1 files are copied from its [ETSI repository](https://forge.etsi.org/rep/ITS/asn1/poim_ts103916/-/tree/v2.1.1).
The submodule TS 103916 v2.1.1 PA (Parking Availability) ASN1 files are copied instead from [ETSI repository](https://forge.etsi.org/rep/ITS/asn1/pa_ts103916/-/tree/release2?ref_type=heads), due to a missing bug fix.

Finally, the current ASN1 definition is manually patched to:
- Import GeoPosition field from CDD 2.2.1, instead of redefining it
- Define locally the EngineCharacteristics (renamed EngineCharacteristicsFromIso) field to avoid generation of all fields from ISO17573-3-1.asn 

See [ETSI License](https://forge.etsi.org/rep/ITS/asn1/poim_ts103916/-/blob/v2.1.1/LICENSE) for copyright details.
