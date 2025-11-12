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

## How to generate new ASN1 structs based on ASN1 definitions (last update: 20/10/2025)
Generating new ASN1 structs based on ASN1 definitions is a complex task requiring appropriate ASN1C compilers. The **ASN1C compiler** to use is the [Mouse07410 fork of ](https://github.com/mouse07410/asn1c), based on [this commit](https://github.com/mouse07410/asn1c/commit/18e565032e52af8002c2353be20bdbba9233e700). Therefore, the following steps should be followed to do so:
1. Download, compile & install the right asn1c compiler (on your host machine)
2. Update this repo with the new/updated ASN1 definitions
3. Update the [CMAakelists file](vanetza/asn1/CMakeLists.txt) ( and any other required file) to include & compile the new/updated ASN1 definitions
4. Compile the project as follows:
```bash
# Create a new build folder for asn1 structs
cd ../ && rm -rf build.asn1 && mkdir build.asn1 && cd build.asn1

# To configure build
cmake -DVANETZA_ASN1_WITH_ASN1C=ON -DASN1C_SKELETON_DIR=/media/arslane/DATA/Repos/asn1c_mouse07410/skeletons -DVANETZA_ASN1_WITH_ISO=ON  .. 

# To generate asn1 structs
make generate_asn1c

# To reconfigure build following update of asn1 structs
cmake -DVANETZA_ASN1_WITH_ASN1C=ON -DASN1C_SKELETON_DIR=/media/arslane/DATA/Repos/asn1c_mouse07410/skeletons -DVANETZA_ASN1_WITH_ISO=ON  ..

# To compile Vanetza libraries
cmake --build . -j 7
```


## Authors

Development of Vanetza is part of ongoing research work at [Technische Hochschule Ingolstadt](https://www.thi.de/forschung/carissma/labore/car2x-labor/).
Maintenance is coordinated by Raphael Riebl. Contributions are happily accepted.

## License

Vanetza is licensed under LGPLv3, see [license file](LICENSE.md) for details.
