# Security

This is the security module of Vanetza. It implements the ETSI C-ITS security extension of the GeoNetworking protocol based on [ETSI TS 103 097 v1.2.1](http://www.etsi.org/deliver/etsi_ts/103000_103099/103097/01.02.01_60/ts_103097v010201p.pdf).

## Implemented Features

Most features are implemented, including:

 - Security profiles including the CAM and DENM profile
 - Certificate requests for unknown certificates of other stations
 - Certificate validation for incoming messages

## Missing Features

There are a few missing features, but the overall implementation is in a working state to send and receive secured messages.
It has been verified to work correctly by interoperability tests with other implementations.

 - Revocation checks for certificate authorities<br>
   Certificates of CAs can be revoked via CRLs. There will be a new standard for the corresponding protocol in May 2018. It will be a new version of [ETSI TS 102 941](http://www.etsi.org/deliver/etsi_ts/102900_102999/102941/01.01.01_60/ts_102941v010101p.pdf).

 - Region checks for polygonal and identified regions<br>
   There are `TODO` notes in the code of `region.cpp` within the `is_within()` functions. Implementing these checks is non-trivial.

 - Region consistency checks for regions other than circular and none region restrictions<br>
   There are `TODO` notes in the code of `region.cpp` within the `is_within()` functions. Implementing these checks is non-trivial.

 - Certificate requests<br>
   Currently there's no support to request authorization tickets from an authorization authority or to do an enrolment.
