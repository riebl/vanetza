add_vanetza_component(security
    aes.cpp
    backend.cpp
    backend_crypto_provider.cpp
    backend_null.cpp
    cam_ssp.cpp
    credential_storage.cpp
    crypto_provider.cpp
    crypto_provider_verify_service.cpp
    decap_service.cpp
    delegating_security_entity.cpp
    ecc_point.cpp
    ecdsa256.cpp
    ecies.cpp
    encap_service.cpp
    hashed_id.cpp
    hmac.cpp
    kdf2.cpp
    key_type.cpp
    memory_credential_storage.cpp
    public_key.cpp
    persistence.cpp
    pem.cpp
    peer_request_tracker.cpp
    secured_message.cpp
    security_module.cpp
    security_module_error.cpp
    sha.cpp
    signature.cpp
    software_signing_keys.cpp
    straight_verify_service.cpp
    verify_service.cpp
    v2/basic_elements.cpp
    v2/certificate.cpp
    v2/certificate_cache.cpp
    v2/default_certificate_validator.cpp
    v2/ecc_point.cpp
    v2/encryption_parameter.cpp
    v2/header_field.cpp
    v2/int_x.cpp
    v2/length_coding.cpp
    v2/naive_certificate_provider.cpp
    v2/null_certificate_provider.cpp
    v2/null_certificate_validator.cpp
    v2/payload.cpp
    v2/persistence.cpp
    v2/public_key.cpp
    v2/recipient_info.cpp
    v2/region.cpp
    v2/secured_message.cpp
    v2/serialization.cpp
    v2/sign_header_policy.cpp
    v2/signature.cpp
    v2/signer_info.cpp
    v2/sign_service.cpp
    v2/static_certificate_provider.cpp
    v2/static_credential_provider.cpp
    v2/subject_attribute.cpp
    v2/subject_info.cpp
    v2/trailer_field.cpp
    v2/trust_store.cpp
    v2/validity_restriction.cpp
    v2/verification.cpp
    v3/asn1_conversions.cpp
    v3/basic_elements.cpp
    v3/boost_geometry.cpp
    v3/certificate.cpp
    v3/certificate_cache.cpp
    v3/certificate_validator.cpp
    v3/distance.cpp
    v3/geometry.cpp
    v3/hash.cpp
    v3/identity_manager.cpp
    v3/issuer_memory_lookup.cpp
    v3/location_checker.cpp
    v3/memory_authorization_ticket_pool.cpp
    v3/secured_message.cpp
    v3/sign_service.cpp
    v3/naive_certificate_provider.cpp
    v3/naive_credential_provider.cpp
    v3/sign_header_policy.cpp
    v3/static_certificate_provider.cpp
    v3/static_credential_provider.cpp
    v3/persistence.cpp
    v3/revocation_lookup.cpp
    v3/trust_store.cpp
    v3/validity_restriction.cpp
)
target_link_libraries(security PUBLIC Boost::headers asn1 asn1_security common net)
target_link_libraries(security PRIVATE geodesy)

if(VANETZA_WITH_PERSISTENCE)
    set_property(TARGET security APPEND PROPERTY SOURCES
        persistence/certificate.cpp
        persistence/file.cpp
        persistence/key_reference.cpp
        persistence/public_key.cpp)
    target_compile_features(security PRIVATE cxx_std_17)
endif()

if(VANETZA_WITH_PQC)
    set_property(TARGET security APPEND PROPERTY SOURCES
        pqc/fndsa512_oqs.cpp
        pqc/hybrid_certificate.cpp
        pqc/hybrid_certificate_validator.cpp)
    target_link_libraries(security PRIVATE OQS::oqs)
endif()

if(VANETZA_WITH_CRYPTOPP)
    set_property(TARGET security APPEND PROPERTY
        SOURCES backend_cryptopp.cpp cryptopp_crypto_provider.cpp cryptopp_security_module.cpp cryptopp_wrapper.cpp)
    target_link_libraries(security PRIVATE cryptopp::cryptopp)
    target_compile_definitions(security PUBLIC "VANETZA_WITH_CRYPTOPP")
endif()

if(VANETZA_WITH_OPENSSL)
    set_property(TARGET security APPEND PROPERTY
        SOURCES backend_openssl.cpp openssl_crypto_provider.cpp openssl_error.cpp openssl_security_module.cpp
            openssl_wrapper.cpp)
    target_link_libraries(security PRIVATE OpenSSL::Crypto)
    target_compile_definitions(security PUBLIC "VANETZA_WITH_OPENSSL")
    target_compile_definitions(security PRIVATE "OPENSSL_API_COMPAT=0x10101000L")
endif()

if(VANETZA_WITH_PSA)
    set_property(TARGET security APPEND PROPERTY
        SOURCES psa_crypto_provider.cpp psa_error.cpp psa_security_module.cpp psa_wrapper.cpp)
    target_link_libraries(security PRIVATE PSACrypto::PSACrypto)
    target_compile_definitions(security PUBLIC "VANETZA_WITH_PSA")
endif()

if(NOT VANETZA_WITH_CRYPTOPP AND NOT VANETZA_WITH_OPENSSL)
    message(WARNING "Vanetza is built without proper security backend")
endif()

# shared test data for all security tests
set(SECURITY_TEST_ASSET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/tests/assets")
add_test_subdirectory(tests)
add_test_subdirectory(v2/tests)
add_test_subdirectory(v3/tests)
if(VANETZA_WITH_PERSISTENCE)
    add_test_subdirectory(persistence/tests)
endif()
if(VANETZA_WITH_PQC)
    add_test_subdirectory(pqc/tests)
endif()
