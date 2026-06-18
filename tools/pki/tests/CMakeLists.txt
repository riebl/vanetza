include(UseGTest)

configure_gtest_directory(
    INCLUDE_DIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR}/..
    COMPILE_DEFINITIONS OPENSSL_API_COMPAT=0x10101000L
    LINK_LIBRARIES pki_library)
add_gtest(CertificateRevocationList certificate_revocation_list.cpp)
add_gtest(CertificateRole certificate_role.cpp)
add_gtest(CertificateTrustList certificate_trust_list.cpp)
add_gtest(CredentialFilesystemStorage credential_filesystem_storage.cpp)
add_gtest(CrlFilesystemStore crl_store.cpp)
add_gtest(AtRequest at_request.cpp)
add_gtest(AtResponse at_response.cpp)
add_gtest(EaRequest ea_request.cpp)
add_gtest(EaResponse ea_response.cpp)
add_gtest(Ecies ecies.cpp)
add_gtest(HexString hexstring.cpp)
add_gtest(Http http.cpp)
add_gtest(Keys keys.cpp)
add_gtest(Pem pem.cpp)
add_gtest(PkiTime time.cpp)
add_gtest(SecurityModuleNG security_module.cpp)
add_gtest(SignedBuilder signed_builder.cpp)
add_gtest(PruneCommand prune_command.cpp)