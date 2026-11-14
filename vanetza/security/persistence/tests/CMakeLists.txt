include(UseGTest)
# persistence headers require file system support of C++17
configure_gtest_directory(LINK_LIBRARIES security security_test COMPILE_FEATURES cxx_std_17)
add_gtest(PersistenceCertificate certificate.cpp)
add_gtest(PersistenceKeyReference key_reference.cpp)
add_gtest(PersistencePublicKey public_key.cpp)
