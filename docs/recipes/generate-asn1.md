Title: Generate code from ASN.1

# How to generate code from ASN.1 definitions

Generating new ASN.1 structs based on ASN.1 definitions can be a daunting task requiring the appropriate ASN.1 compiler.
In particular, we use the **asn1c** fork maintained by [mouse07410](https://github.com/mouse07410/asn1c).

Though the Vanetza repository comes with various pre-generated ASN.1 messages, you may want to add further or revised versions of these messages.
In this case, the following steps guide you how to generate code from ASN.1 definitions on your own.

## Prerequisites

We have streamlined the process of installing and using **asn1c** by relying on a Docker container.

1. Install Docker on your system
2. Build the Docker container from the `vanetza/asn1/Dockerfile` as `vanetza-asn1c:latest`

```bash
docker build --tag vanetza-asn1c:latest vanetza/asn1
```

## Generate ASN.1 code

Our CMake build environment comes with a `generate_asn1c` code generation target.
This target is available if the the `VANETZA_ASN1_WITH_ASN1C` CMake option is enabled.
When you invoke this target, CMake will run the Docker container for you with suitable arguments.
You can specify a custom image by modifying the `VANETZA_ASN1C_CONTAINER` CMake cache variable.
By default, CMake will use the `vanetza-asn1c:latest` image.

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