include(UseGTest)
configure_gtest_directory(LINK_LIBRARIES geodesy security
    COMPILE_DEFINITIONS ASSET_DIR="${SECURITY_TEST_ASSET_DIR}")
add_gtest(Distance distance.cpp)
add_gtest(DefaultCertificateValidatorV3 default_certificate_validator_v3.cpp)
add_gtest(MemoryAuthorizationTicketPool memory_authorization_ticket_pool.cpp)
add_gtest(SignServiceV3 sign_service.cpp)
