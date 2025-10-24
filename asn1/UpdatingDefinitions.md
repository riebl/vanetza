# New Update based on REX (20/10/2025)
- Download, compile & install asn1c from https://github.com/mouse07410/asn1c (commit to use: 18e565032e52af8002c2353be20bdbba9233e700)
- In Vanetza, add the required ASN1 files for the new standards
- In Vanetza, update the CMAakelists to include the new standards
- To compile everything:
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
