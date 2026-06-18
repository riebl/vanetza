include(UseGTest)
add_library(security_test STATIC
    serialization.cpp
)
target_include_directories(security_test PUBLIC $<TARGET_PROPERTY:security,INTERFACE_INCLUDE_DIRECTORIES>)
target_link_libraries(security_test PUBLIC ${GTest_LIBRARY})
configure_gtest_directory(LINK_LIBRARIES Boost::boost security security_test
    COMPILE_DEFINITIONS ASSET_DIR="${SECURITY_TEST_ASSET_DIR}")

add_gtest(Backend backend.cpp)
add_gtest(CamServiceSpecificPermissions cam_ssp.cpp)
add_gtest(CertificateV3 certificate_v3.cpp)
add_gtest(DummyVerifyService dummy_verify_service.cpp)
add_gtest(EccPointDecompression ecc_point_decompression.cpp)
add_gtest(Geometry geometry.cpp)
add_gtest(Hmac hmac.cpp)
add_gtest(PeerRequestTracker peer_request_tracker.cpp)
add_gtest(Persistence persistence.cpp)
add_gtest(PublicKey public_key.cpp)
add_gtest(SecuredMessageV3 secured_message_v3.cpp)
