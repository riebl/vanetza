find_package(Boost REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Threads)

include(FetchContent)
find_package(CLI11 2.6 QUIET)
if(NOT CLI11_FOUND)
    set(CLI11_PRECOMPILED ON CACHE BOOL "Build CLI11 as a compiled library" FORCE)
    FetchContent_Declare(CLI11
        GIT_REPOSITORY https://github.com/CLIUtils/CLI11.git
        GIT_TAG v2.6.2
        GIT_SHALLOW TRUE)
    FetchContent_MakeAvailable(CLI11)
endif()

add_library(pki_library STATIC
    asn1.cpp
    at_request.cpp
    at_response.cpp
    authorization.cpp
    certificate.cpp
    certificate_filesystem_storage.cpp
    certificate_revocation_list.cpp
    certificate_trust_list.cpp
    config.cpp
    credential_filesystem_storage.cpp
    crl_store.cpp
    dc_command.cpp
    distribution_centre.cpp
    ea_request.cpp
    ea_response.cpp
    ecies.cpp
    encrypted_data.cpp
    filesystem.cpp
    hashed_id8.cpp
    hexstring.cpp
    http.cpp
    keys.cpp
    openssl.cpp
    openssl_security_module.cpp
    pem.cpp
    prune_command.cpp
    psid_ssp.cpp
    response_codes.cpp
    security_module.cpp
    signed_builder.cpp
    signed_data.cpp
    station_config_filesystem.cpp
    time.cpp
    trust_list_filesystem_storage.cpp
    validation.cpp
    xdg.cpp
)
target_link_libraries(pki_library PUBLIC
    OpenSSL::Crypto OpenSSL::SSL
    Boost::headers
    CLI11::CLI11
    asn1 common security)
target_compile_definitions(pki_library PRIVATE OPENSSL_API_COMPAT=0x10101000L)
target_compile_features(pki_library PUBLIC cxx_std_17)

add_executable(pki
    cpoc.cpp
    enrolment.cpp
    main.cpp
    printing.cpp
    station.cpp
)
target_link_libraries(pki PUBLIC pki_library)

add_subdirectory(tests)
