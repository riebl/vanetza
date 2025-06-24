add_vanetza_component(security
    backend.cpp
    backend_null.cpp
    cam_ssp.cpp
    decap_service.cpp
    delegating_security_entity.cpp
    ecc_point.cpp
    ecdsa256.cpp
    encap_service.cpp
    hashed_id.cpp
    hmac.cpp
    key_type.cpp
    peer_request_tracker.cpp
    secured_message.cpp
    sha.cpp
    signature.cpp
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
    v2/subject_attribute.cpp
    v2/subject_info.cpp
    v2/trailer_field.cpp
    v2/trust_store.cpp
    v2/validity_restriction.cpp
    v2/verification.cpp
    v3/asn1_conversions.cpp
    v3/basic_elements.cpp
    v3/certificate.cpp
    v3/certificate_cache.cpp
    v3/certificate_validator.cpp
    v3/distance.cpp
    v3/hash.cpp
    v3/location_checker.cpp
    v3/secured_message.cpp
    v3/sign_service.cpp
    v3/naive_certificate_provider.cpp
    v3/sign_header_policy.cpp
    v3/static_certificate_provider.cpp
    v3/persistence.cpp
    v3/trust_store.cpp
    v3/validity_restriction.cpp
)
target_link_libraries(security PUBLIC asn1 asn1_security common net)
target_link_libraries(security PRIVATE GeographicLib::GeographicLib)

# crypto++ is a public mandatory dependency because of "NaiveCertificateProvider"
if(TARGET CryptoPP::CryptoPP)
    set_property(TARGET security APPEND PROPERTY
        SOURCES backend_cryptopp.cpp)
    target_link_libraries(security PUBLIC CryptoPP::CryptoPP)
    target_compile_definitions(security PUBLIC "VANETZA_WITH_CRYPTOPP")
endif()

if(TARGET OpenSSL::Crypto)
    set_property(TARGET security APPEND PROPERTY
        SOURCES backend_openssl.cpp openssl_wrapper.cpp)
    target_link_libraries(security PRIVATE OpenSSL::Crypto)
    target_compile_definitions(security PUBLIC "VANETZA_WITH_OPENSSL")
    if ("${OPENSSL_VERSION}" VERSION_EQUAL 2.0.0)
        # found LibreSSL most likely, should be API compatible to OpenSSL 1.0.1
        target_compile_definitions(security PRIVATE "OPENSSL_API_COMPAT=0x10000000L")
    elseif ("${OPENSSL_VERSION}" VERSION_EQUAL 1.1.1)
        target_compile_definitions(security PRIVATE "OPENSSL_API_COMPAT=0x10101000L")
    elseif ("${OPENSSL_VERSION}" VERSION_LESS 1.1.0)
        target_compile_definitions(security PRIVATE "OPENSSL_API_COMPAT=0x10000000L")
    else()
        target_compile_definitions(security PRIVATE "OPENSSL_API_COMPAT=0x10100000L")
    endif()
endif()

add_test_subdirectory(tests)
add_test_subdirectory(v3/tests)
