Title: Generate code from ASN.1

# How to generate code from ASN.1 definitions

Generating new ASN.1 structs based on ASN.1 definitions can be a daunting task requiring the appropriate ASN.1 compiler.
In particular, we use the **asn1c** fork maintained by [mouse07410](https://github.com/mouse07410/asn1c).
At the time of writing, we employ [this particular revision](https://github.com/mouse07410/asn1c/commit/18e565032e52af8002c2353be20bdbba9233e700) of **asn1c**.

Though the Vanetza repository comes with various pre-generated ASN.1 messages, you may want to add further or revised versions of these messages.
In this case, the following steps guide you how to generate code from ASN.1 definitions on your own.

## Prerequisites

1. Install the required build tools and libraries for **asn1c** (e.g. **flex** and **bison**)
2. Download the right version of the **asn1c** compiler
3. Compile and install the **asn1c** compiler on your system

## Generate ASN.1 code

1. Update your copy of Vanetza with the new or updated ASN.1 definitions
2. Update the **CMakeLists.txt** file at **vanetza/asn1** accordingly
3. Create a fresh build directory and configure CMake with enabled ASN.1 targets
4. Invoke **asn1c** and compile Vanetza with newly generated code

```bash
# Create a new build directory at the project's root
mkdir build.asn1 && cd build.asn1

# Configure the build with enabled ASN.1 targets and retrieval of ISO ASN.1 files
cmake -DVANETZA_ASN1_WITH_ASN1C=ON -DVANETZA_ASN1_WITH_ISO=ON ..

# Invoke the target calling asn1c
make generate_asn1c

# Compile Vanetza with newly generated ASN.1 code
cmake --build .
```