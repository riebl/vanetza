include(UseGTest)
configure_gtest_directory(LINK_LIBRARIES geodesy security
    COMPILE_DEFINITIONS ASSET_DIR="${SECURITY_TEST_ASSET_DIR}")
add_gtest(FnDsa512Backend fndsa512_backend.cpp)
add_gtest(HybridPqcCertificate hybrid_certificate.cpp)
