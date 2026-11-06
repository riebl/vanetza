# Find an implementation of the PSA Crypto API, i.e. TF-PSA-Crypto (part of Mbed TLS 4) or Mbed TLS 3.6
# Provides the imported target PSACrypto::PSACrypto
include(FindPackageHandleStandardArgs)

find_package(TF-PSA-Crypto CONFIG QUIET)
if(TF-PSA-Crypto_FOUND)
    set(PSACrypto_CONFIG ${TF-PSA-Crypto_CONFIG})
    set(PSACrypto_VERSION ${TF-PSA-Crypto_VERSION})
    set(_psa_crypto_target TF-PSA-Crypto::tfpsacrypto)
else()
    find_package(MbedTLS 3.6 CONFIG QUIET)
    if(MbedTLS_FOUND)
        set(PSACrypto_CONFIG ${MbedTLS_CONFIG})
        set(PSACrypto_VERSION ${MbedTLS_VERSION})
        set(_psa_crypto_target MbedTLS::mbedcrypto)
    endif()
endif()

find_package_handle_standard_args(PSACrypto
    REQUIRED_VARS PSACrypto_CONFIG
    VERSION_VAR PSACrypto_VERSION)

if(PSACrypto_FOUND AND NOT TARGET PSACrypto::PSACrypto)
    add_library(PSACrypto::PSACrypto INTERFACE IMPORTED)
    set_target_properties(PSACrypto::PSACrypto PROPERTIES INTERFACE_LINK_LIBRARIES ${_psa_crypto_target})
endif()
unset(_psa_crypto_target)
