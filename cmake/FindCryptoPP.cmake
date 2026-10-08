include(FindPackageHandleStandardArgs)

# Prefer CMake package configurations installed by cryptopp-modern or cryptopp-cmake.
foreach(_package IN ITEMS cryptopp-modern cryptopp)
    find_package(${_package} CONFIG QUIET)
    if(${_package}_FOUND)
        set(CryptoPP_CONFIG ${${_package}_CONFIG})
        set(CryptoPP_VERSION_STRING ${${_package}_VERSION})
        find_package_handle_standard_args(CryptoPP
            REQUIRED_VARS CryptoPP_CONFIG
            VERSION_VAR CryptoPP_VERSION_STRING)
        return()
    endif()
endforeach()

# Fall back to our classic lookup code searching for files
find_path(CryptoPP_INCLUDE_DIR NAMES cryptopp/config.h DOC "CryptoPP include directory")
find_library(CryptoPP_LIBRARY NAMES cryptopp DOC "CryptoPP library")

if(CryptoPP_INCLUDE_DIR)
    # CRYPTOPP_VERSION has been moved to config_ver.h starting with Crypto++ 8.3
    if(EXISTS ${CryptoPP_INCLUDE_DIR}/cryptopp/config_ver.h)
        # config_ver.h defines the version components separately, also for calendar versions
        file(STRINGS ${CryptoPP_INCLUDE_DIR}/cryptopp/config_ver.h _config_version
            REGEX "^#define CRYPTOPP_(MAJOR|MINOR|REVISION) [0-9]+")
        set(_version_components)
        foreach(_component IN ITEMS MAJOR MINOR REVISION)
            string(REGEX MATCH "CRYPTOPP_${_component} ([0-9]+)" _match_version "${_config_version}")
            list(APPEND _version_components ${CMAKE_MATCH_1})
        endforeach()
        list(JOIN _version_components "." CryptoPP_VERSION_STRING)
    else()
        file(STRINGS ${CryptoPP_INCLUDE_DIR}/cryptopp/config.h _config_version REGEX "CRYPTOPP_VERSION")
        string(REGEX MATCH "([0-9])([0-9])([0-9])" _match_version "${_config_version}")
        set(CryptoPP_VERSION_STRING "${CMAKE_MATCH_1}.${CMAKE_MATCH_2}.${CMAKE_MATCH_3}")
    endif()
endif()

find_package_handle_standard_args(CryptoPP
    REQUIRED_VARS CryptoPP_INCLUDE_DIR CryptoPP_LIBRARY
    FOUND_VAR CryptoPP_FOUND
    VERSION_VAR CryptoPP_VERSION_STRING)

if(CryptoPP_FOUND AND NOT TARGET CryptoPP::CryptoPP AND NOT TARGET cryptopp::cryptopp)
    add_library(CryptoPP::CryptoPP UNKNOWN IMPORTED)
    set_target_properties(CryptoPP::CryptoPP PROPERTIES
        IMPORTED_LOCATION "${CryptoPP_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${CryptoPP_INCLUDE_DIR}")
    # cryptopp-modern uses cryptopp::cryptopp
    add_library(cryptopp::cryptopp ALIAS CryptoPP::CryptoPP)
endif()

mark_as_advanced(CryptoPP_INCLUDE_DIR CryptoPP_LIBRARY)
set(CryptoPP_INCLUDE_DIRS ${CryptoPP_INCLUDE_DIR})
set(CryptoPP_LIBRARIES ${CryptoPP_LIBRARY})
