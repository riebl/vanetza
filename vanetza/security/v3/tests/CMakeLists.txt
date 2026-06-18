include(UseGTest)
configure_gtest_directory(LINK_LIBRARIES geodesy security
    COMPILE_DEFINITIONS ASSET_DIR="${SECURITY_TEST_ASSET_DIR}")
add_gtest(Distance distance.cpp)
add_gtest(DefaultCertificateValidatorV3 default_certificate_validator_v3.cpp)
