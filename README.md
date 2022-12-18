# Vanetza

Vanetza is an open-source implementation of the ETSI C-ITS protocol suite.
This comprises the following protocols and features among others:

* GeoNetworking (GN)
* Basic Transport Protocol (BTP)
* Decentralized Congestion Control (DCC)
* Security
* Support for ASN.1 messages (Facilities) such as CAM and DENM

Though originally designed to operate on ITS-G5 channels in a Vehicular Ad Hoc Network (VANET) using IEEE 802.11p, Vanetza and its components can be combined with other communication technologies as well, e.g. GeoNetworking over IP multicast.

## How to build

Building Vanetza is accomplished by the CMake build system. Hence, CMake needs to be available on the build host.
You can find more details on [prerequisites](https://www.vanetza.org/how-to-build/#prerequisites) and [steps for compilation](https://www.vanetza.org/how-to-build/#compilation) on our website.

## Documentation

Please visit our project website at [www.vanetza.org](https://www.vanetza.org) where most documentation about Vanetza can be found.


## Continuous Integration

We strive for quality in our code base.
New commits and pull requests are regularly checked by our unit tests in a container environment.
At the moment, the three latest Ubuntu LTS versions are run on GitHub's Actions infrastructure.

[![Build Status](https://github.com/riebl/vanetza/actions/workflows/docker-ci.yml/badge.svg?branch=master)](https://github.com/riebl/vanetza/actions/workflows/docker-ci.yml)


## Authors

Development of Vanetza is part of ongoing research work at [Technische Hochschule Ingolstadt](https://www.thi.de/forschung/carissma/labore/car2x-labor/).
Maintenance is coordinated by Raphael Riebl. Contributions are happily accepted.

## License

Vanetza is licensed under LGPLv3, see [license file](LICENSE.md) for details.
