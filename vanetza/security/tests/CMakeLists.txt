include(UseGTest)
find_package(Boost COMPONENTS serialization REQUIRED)

set(VANETZA_MODULE_TEST security)
set(SECURITY_ELEMENTS_SOURCES set_elements.cpp test_elements.cpp)
add_gtest(EccPoint ecc_point.cpp ${SECURITY_ELEMENTS_SOURCES})
add_gtest(PublicKey public_key.cpp ${SECURITY_ELEMENTS_SOURCES})
