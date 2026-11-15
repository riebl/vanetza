include(UseGTest)
add_library(security_test STATIC
    certificates_v3.cpp
    null_crypto_provider.cpp
    serialization.cpp
)
target_include_directories(security_test PUBLIC $<TARGET_PROPERTY:security,INTERFACE_INCLUDE_DIRECTORIES>)
target_link_libraries(security_test PUBLIC security ${GTest_LIBRARY})
configure_gtest_directory(LINK_LIBRARIES Boost::boost security security_test
    COMPILE_DEFINITIONS ASSET_DIR="${SECURITY_TEST_ASSET_DIR}")

add_gtest(Backend backend.cpp)
add_gtest(CamServiceSpecificPermissions cam_ssp.cpp)
add_gtest(CertificateV3 certificate_v3.cpp)
add_gtest(CredentialStorage credential_storage.cpp)
add_gtest(CryptoProvider crypto_provider.cpp)
add_gtest(CryptoProviderVerifyService crypto_provider_verify_service.cpp)
add_gtest(DecapService decap_service.cpp)
add_gtest(DummyVerifyService dummy_verify_service.cpp)
if(VANETZA_WITH_OPENSSL OR VANETZA_WITH_CRYPTOPP)
    # requires security::Backend currently
    add_gtest(EccPointDecompression ecc_point_decompression.cpp)
endif()
add_gtest(Ecies ecies.cpp)
add_gtest(Geometry geometry.cpp)
add_gtest(Hmac hmac.cpp)
add_gtest(Kdf2 kdf2.cpp)
add_gtest(MemoryCredentialStorage memory_credential_storage.cpp)
add_gtest(PemEncoding pem.cpp)
add_gtest(PeerRequestTracker peer_request_tracker.cpp)
add_gtest(Persistence persistence.cpp)
add_gtest(PublicKey public_key.cpp)
add_gtest(SecuredMessageV3 secured_message_v3.cpp)
add_gtest(SecurityModule security_module.cpp)
add_gtest(SecurityModuleError security_module_error.cpp)
add_gtest(SoftwareSigningKeys software_signing_keys.cpp)

if(VANETZA_WITH_CRYPTOPP)
    add_gtest(CryptoppSecurityModule cryptopp_security_module.cpp LINK_LIBRARIES cryptopp::cryptopp)
endif()

if(VANETZA_WITH_OPENSSL)
    set(_openssl_test_options LINK_LIBRARIES OpenSSL::Crypto COMPILE_DEFINITIONS OPENSSL_API_COMPAT=0x10101000L)
    add_gtest(OpenSslCryptoProvider openssl_crypto_provider.cpp ${_openssl_test_options})
    add_gtest(OpenSslError openssl_error.cpp ${_openssl_test_options})
    add_gtest(OpenSslSecurityModule openssl_security_module.cpp ${_openssl_test_options})
endif()

if(VANETZA_WITH_PSA)
    add_gtest(PsaError psa_error.cpp LINK_LIBRARIES PSACrypto::PSACrypto)
    add_gtest(PsaSecurityModule psa_security_module.cpp LINK_LIBRARIES PSACrypto::PSACrypto)
endif()
