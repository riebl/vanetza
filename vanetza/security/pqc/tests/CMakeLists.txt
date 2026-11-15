include(UseGTest)
configure_gtest_directory(LINK_LIBRARIES geodesy security
    COMPILE_DEFINITIONS ASSET_DIR="${SECURITY_TEST_ASSET_DIR}")
add_gtest(FnDsa512Backend fndsa512_backend.cpp)
if(VANETZA_HAS_CRYPTO_PROVIDER AND VANETZA_HAS_SECURITY_MODULE)
    add_gtest(HybridPqcCertificate hybrid_certificate.cpp)
endif()
