Title: Overview


# Vanetza in a nutshell

Vanetza is an open-source implementation of the ETSI C-ITS protocol suite.
Among others, it comprises the following protocols and features:

* GeoNetworking (GN)
* Basic Transport Protocol (BTP)
* Decentralized Congestion Control (DCC)
* Security
* Support for ASN.1 messages (Facilities) such as CAM and DENM

Though originally designed to operate on ITS-G5 channels in a Vehicular Ad Hoc Network (VANET) using IEEE 802.11p, Vanetza and its components can be combined with other communication technologies as well, e.g. GeoNetworking over IP multicast.


## Project layout

In the first place, Vanetza is a conglomerate of C++ libraries, some depending on others.
Sources of these libraries, also known as Vanetza component, are bundled in their respective subdirectories.

| Component | Depends on | Features |
| --------- | ---------- | -------- |
| access | net | Access layer, helpers for IEEE 802.11 PHY and MAC |
| asn1 | - | Generated code and wrappers for ASN.1 based messages, e.g. CAM and DENM |
| btp | geonet | Headers and interfaces for BTP transport layer |
| common | - | General purpose classes used across Vanetza components, including serialization and timing |
| dcc | access, net | Algorithms for DCC cross-layer |
| facilities | asn1, geonet, security | Helpers to generate and evaluate ITS messages |
| geonet | dcc, net, security | GeoNetworking layer featuring geographical routing |
| gnss | - | Satellite navigation integration for positioning |
| net | common | Utilities for socket API and packet handling |
| security | common, net | Security entity to sign and verify packets |

For most of the code unit tests exist. We are using [Googletest](https://github.com/google/googletest) for those.
Compilation of Vanetza unit tests can be enabled via the `BUILD_TESTS` CMake option.
You can the run those tests in your build directory by executing `ctest`.

Additionally, the `tools` directory contains several utilities making use of Vanetza libraries.

| Tool | Purpose | CMake option |
| ---- | ------- | ------------ |
| benchmark | Benchmarking security features, e.g. signing or validating a lot messages in a row | `BUILD_BENCHMARK` |
| certify | Utility for generating and handling security certificates, authorization tickets etc. | `BUILD_CERTIFY` |
| socktap | Example application using most of the Vanetza stack operating on sockets, i.e. either Linux packet sockets or optionally Cohda LLC sockets | `BUILD_SOCKTAP` |


## Deployments

Vanetza has been developed for network simulations and testing on embedded devices at [Technische Hochschule Ingolstadt](https://www.thi.de) initially.
Meanwhile, Vanetza is used by many more parties and for more use cases than anticipated in the beginning.

* [Artery](https://github.com/riebl/artery) is a V2X simulation framework based on [OMNeT++](https://www.omnetpp.org).
   Vanetza is used in this network simulation as (quite detailed) model of ITS-G5 protocols.
* Various communication units (roadside units, vehicles and testbeds) in the [CARISSMA Car2X lab](https://www.thi.de/forschung/carissma/labore/car2x-labor) are powered by Vanetza.
* Prototype motorcycles operated by the [Connected Motorcycle Consortium](https://www.cmc-info.net) use Vanetza for evaluation of novel ITS applications to enhance rider safety.

If you are using Vanetza, we would love to add your project to the list above.
Please write an e-mail to [raphael.riebl@thi.de](mailto:raphael.riebl@thi.de) or open a pull request.
