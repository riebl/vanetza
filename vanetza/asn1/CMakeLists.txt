set(_its_asn1_source_file "asn1c_its_sources.txt")
set(_its_r2_asn1_source_file "asn1c_its_r2_sources.txt")
set(_sec_asn1_source_file "asn1c_security_sources.txt")
set(_sec_r2_asn1_source_file "asn1c_security_r2_sources.txt")
set(_support_asn1_source_file "asn1c_support_sources.txt")

set(_its_asn1_dir "${CMAKE_CURRENT_SOURCE_DIR}/its")
set(_its_r2_asn1_dir "${CMAKE_CURRENT_SOURCE_DIR}/its/r2")
set(_sec_asn1_dir "${CMAKE_CURRENT_SOURCE_DIR}/security")
set(_sec_r2_asn1_dir "${CMAKE_CURRENT_SOURCE_DIR}/security/r2")
set(_support_asn1_dir "${CMAKE_CURRENT_SOURCE_DIR}/support")

option(VANETZA_ASN1_WITH_ASN1C "Enable asn1c targets" OFF)
if(VANETZA_ASN1_WITH_ASN1C)
    find_package(ASN1C 0.9.29 REQUIRED MODULE)
    set(ASN1C_FLAGS "-fcompound-names -fincludes-quoted -no-gen-example" CACHE STRING "asn1c compiler options")
    mark_as_advanced(ASN1C_FLAGS)
    string(REPLACE " " ";" _asn1c_flags "${ASN1C_FLAGS}")

    set(_its_asn1_files
        ${PROJECT_SOURCE_DIR}/asn1/TS102894-2v131-CDD.asn
        ${PROJECT_SOURCE_DIR}/asn1/EN302637-2v141-CAM.asn
        ${PROJECT_SOURCE_DIR}/asn1/EN302637-3v131-DENM.asn
    )

    set(_its_asn1_files_depending_on_iso
        ${PROJECT_SOURCE_DIR}/asn1/TR103562v211-CPM.asn
        ${PROJECT_SOURCE_DIR}/asn1/TS103301v211-MAPEM.asn
        ${PROJECT_SOURCE_DIR}/asn1/TS103301v211-RTCMEM.asn
        ${PROJECT_SOURCE_DIR}/asn1/TS103301v211-SPATEM.asn
        ${PROJECT_SOURCE_DIR}/asn1/TS103301v211-SREM.asn
        ${PROJECT_SOURCE_DIR}/asn1/TS103301v211-SSEM.asn
        ${PROJECT_SOURCE_DIR}/asn1/TS103301v211-IVIM.asn
    )

    set(_its_r2_asn1_files
        ${PROJECT_SOURCE_DIR}/asn1/release2/TS102894-2v221-CDD.asn
        ${PROJECT_SOURCE_DIR}/asn1/release2/TS103831v221-DENM.asn
        ${PROJECT_SOURCE_DIR}/asn1/release2/TS103900v211-CAM.asn
        ${PROJECT_SOURCE_DIR}/asn1/release2/TS103324v211/CPM-OriginatingStationContainers.asn
        ${PROJECT_SOURCE_DIR}/asn1/release2/TS103324v211/CPM-PDU-Descriptions.asn
        ${PROJECT_SOURCE_DIR}/asn1/release2/TS103324v211/CPM-PerceivedObjectContainer.asn
        ${PROJECT_SOURCE_DIR}/asn1/release2/TS103324v211/CPM-PerceptionRegionContainer.asn
        ${PROJECT_SOURCE_DIR}/asn1/release2/TS103324v211/CPM-SensorInformationContainer.asn
        ${PROJECT_SOURCE_DIR}/asn1/release2/TS103300v221/VAM-PDU-Descriptions.asn
        ${PROJECT_SOURCE_DIR}/asn1/release2/TS103300v221/motorcyclist-special-container.asn
        ${PROJECT_SOURCE_DIR}/asn1/release2/TS103916v211/POIM-PDU-Description.asn
        ${PROJECT_SOURCE_DIR}/asn1/release2/TS103916v211/POIM-ParkingAvailability.asn
        ${PROJECT_SOURCE_DIR}/asn1/release2/TS103916v211/POIM-CommonContainers.asn
    )

    option(VANETZA_ASN1_WITH_ISO "Fetch ISO ASN.1 files for a more complete ITS message set" OFF)
    if(VANETZA_ASN1_WITH_ISO)
        set(_iso_asn1_files
            ISO14816.asn ISO19091.asn ISO24534-3.asn ISO19321.asn
            ISO14906-0-6.asn ISO14906-1-7.asn ISO17419.asn ISO14823.asn)
        list(TRANSFORM _iso_asn1_files PREPEND ${PROJECT_BINARY_DIR}/iso/)
        add_custom_command(OUTPUT ${_iso_asn1_files}
            COMMAND ${CMAKE_COMMAND} -DDIRECTORY=${PROJECT_BINARY_DIR}/iso -P fetch_iso_asn1_files.cmake
            COMMENT "Fetch and patch ISO 19091 ASN.1 file"
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
            VERBATIM)

        set(_its_asn1_files ${_iso_asn1_files} ${_its_asn1_files} ${_its_asn1_files_depending_on_iso})
    endif()

    set(_ieee_2_asn1_files
        IEEE1609dot2.asn IEEE1609dot2BaseTypes.asn IEEE1609dot2crl.asn IEEE1609dot2crlBaseTypes.asn)
    set(_ieee_21_asn1_files
        IEEE1609dot2dot1AcaEeInterface.asn IEEE1609dot2dot1AcaLaInterface.asn IEEE1609dot2dot1AcaMaInterface.asn
        IEEE1609dot2dot1AcaRaInterface.asn IEEE1609dot2dot1Acpc.asn IEEE1609dot2dot1CamRaInterface.asn
        IEEE1609dot2dot1CertManagement.asn IEEE1609dot2dot1EcaEeInterface.asn IEEE1609dot2dot1EeMaInterface.asn
        IEEE1609dot2dot1EeRaInterface.asn IEEE1609dot2dot1LaMaInterface.asn IEEE1609dot2dot1LaRaInterface.asn
        IEEE1609dot2dot1MaRaInterface.asn IEEE1609dot2dot1Protocol.asn)
    list(TRANSFORM _ieee_2_asn1_files PREPEND ${PROJECT_BINARY_DIR}/ieee/)
    list(TRANSFORM _ieee_21_asn1_files PREPEND ${PROJECT_BINARY_DIR}/ieee/)

    set(_ieee_asn1_files ${_ieee_2_asn1_files} ${_ieee_21_asn1_files})
    add_custom_command(OUTPUT ${_ieee_asn1_files}
        COMMAND ${CMAKE_COMMAND} -DDIRECTORY=${PROJECT_BINARY_DIR}/ieee -P fetch_ieee_asn1_files.cmake
        COMMENT "Fetch and patch IEEE1609 ASN.1 file"
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        VERBATIM)

    set(_pki_asn1_files
        ${PROJECT_SOURCE_DIR}/asn1/TS102941v131-BaseTypes.asn
        ${PROJECT_SOURCE_DIR}/asn1/TS102941v131-MessagesCa.asn
        ${PROJECT_SOURCE_DIR}/asn1/TS102941v131-TrustLists.asn
        ${PROJECT_SOURCE_DIR}/asn1/TS102941v131-TypesAuthorization.asn
        ${PROJECT_SOURCE_DIR}/asn1/TS102941v131-TypesAuthorizationValidation.asn
        ${PROJECT_SOURCE_DIR}/asn1/TS102941v131-TypesCaManagement.asn
        ${PROJECT_SOURCE_DIR}/asn1/TS102941v131-TypesEnrolment.asn
    )

    set(_pki_r2_asn1_files
        ${PROJECT_SOURCE_DIR}/asn1/release2/TS102941v221/BaseTypes.asn
        ${PROJECT_SOURCE_DIR}/asn1/release2/TS102941v221/MessagesCa.asn
        ${PROJECT_SOURCE_DIR}/asn1/release2/TS102941v221/MessagesItss-OptionalPrivacy.asn
        ${PROJECT_SOURCE_DIR}/asn1/release2/TS102941v221/MessagesItss.asn
        ${PROJECT_SOURCE_DIR}/asn1/release2/TS102941v221/TrustLists.asn
        ${PROJECT_SOURCE_DIR}/asn1/release2/TS102941v221/TypesAuthorization.asn
        ${PROJECT_SOURCE_DIR}/asn1/release2/TS102941v221/TypesAuthorizationValidation.asn
        ${PROJECT_SOURCE_DIR}/asn1/release2/TS102941v221/TypesCaManagement.asn
        ${PROJECT_SOURCE_DIR}/asn1/release2/TS102941v221/TypesEnrolment.asn
        ${PROJECT_SOURCE_DIR}/asn1/release2/TS102941v221/TypesLinkCertificate.asn
    )
    
    set(_sec_asn1_files
        ${PROJECT_SOURCE_DIR}/asn1/TS103097v131.asn
        ${PROJECT_SOURCE_DIR}/asn1/IEEE1609dot2.asn
        ${PROJECT_SOURCE_DIR}/asn1/IEEE1609dot2BaseTypes.asn
    )

    set(_sec_r2_asn1_files
        ${PROJECT_SOURCE_DIR}/asn1/release2/TS103097v211.asn
        ${PROJECT_SOURCE_DIR}/asn1/release2/TS103097v211-Extension.asn
    )

    add_custom_command(OUTPUT ${_support_asn1_dir}
        DEPENDS "${ASN1C_SKELETON_DIR}"
        COMMAND ${CMAKE_COMMAND} -E make_directory ${_support_asn1_dir}
        COMMAND ${CMAKE_COMMAND} -DDESTINATION=${_support_asn1_dir}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/copy_asn1c_skeleton.cmake
        COMMENT "Copying generic asn1c support code" VERBATIM
        WORKING_DIRECTORY ${ASN1C_SKELETON_DIR})
    add_custom_command(OUTPUT "${_support_asn1_source_file}"
        DEPENDS ${_support_asn1_dir}
        COMMAND ${CMAKE_COMMAND} -DASN1C_OUTPUT_DIR=support -DASN1C_SOURCE_FILE=${_support_asn1_source_file}
            -P collect_asn1c_sources.cmake
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} VERBATIM)

    add_custom_command(OUTPUT ${_its_asn1_dir}
        DEPENDS ${_its_asn1_files}
        COMMAND ${CMAKE_COMMAND} -E make_directory ${_its_asn1_dir}
        COMMAND ${ASN1C_EXECUTABLE} ${_asn1c_flags} -R -D ${_its_asn1_dir} ${_its_asn1_files} test.asn
        COMMENT "Generating code from ITS application ASN.1 modules (CDD, CA, DEN)" VERBATIM
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
    add_custom_command(OUTPUT "${_its_asn1_source_file}"
        DEPENDS ${_its_asn1_dir}
        COMMAND ${CMAKE_COMMAND} -DASN1C_OUTPUT_DIR=its -DASN1C_SOURCE_FILE=${_its_asn1_source_file}
            -P collect_asn1c_sources.cmake
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} VERBATIM)

    add_custom_command(OUTPUT ${_its_r2_asn1_dir}
        DEPENDS ${_its_r2_asn1_files}
        COMMAND ${CMAKE_COMMAND} -E make_directory ${_its_r2_asn1_dir}
        COMMAND ${ASN1C_EXECUTABLE} ${_asn1c_flags} -fprefix=Vanetza_ITS2_ -R -D ${_its_r2_asn1_dir} ${_its_r2_asn1_files}
        COMMAND ${CMAKE_COMMAND} -DASN1C_OUTPUT_DIR=its/r2 -DASN1C_PREFIX=Vanetza_ITS2_
            -P ${CMAKE_CURRENT_SOURCE_DIR}/remove_prefix_from_filename.cmake
        COMMENT "Generating code from ITS Release 2 application ASN.1 modules (CDD, CA, DEN)" VERBATIM
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
    add_custom_command(OUTPUT "${_its_r2_asn1_source_file}"
        DEPENDS ${_its_r2_asn1_dir}
        COMMAND ${CMAKE_COMMAND} -DASN1C_OUTPUT_DIR=its/r2 -DASN1C_SOURCE_FILE=${_its_r2_asn1_source_file}
            -P collect_asn1c_sources.cmake
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} VERBATIM)

    add_custom_command(OUTPUT "${_sec_asn1_dir}"
        DEPENDS ${_sec_asn1_files} ${_pki_asn1_files}
        COMMAND ${CMAKE_COMMAND} -E make_directory ${_sec_asn1_dir}
        COMMAND ${ASN1C_EXECUTABLE} ${_asn1c_flags} -fprefix=Vanetza_Security_ -R -D ${_sec_asn1_dir} ${_sec_asn1_files} ${_pki_asn1_files}
        COMMAND ${CMAKE_COMMAND} -DASN1C_OUTPUT_DIR=security -DASN1C_PREFIX=Vanetza_Security_
            -P ${CMAKE_CURRENT_SOURCE_DIR}/remove_prefix_from_filename.cmake
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMENT "Generating code from Security (1609.2 and TS 103 097, TS 102 941) ASN.1 modules" VERBATIM)
    add_custom_command(OUTPUT "${_sec_asn1_source_file}"
        DEPENDS ${_sec_asn1_dir}
        COMMAND ${CMAKE_COMMAND} -DASN1C_OUTPUT_DIR=security -DASN1C_SOURCE_FILE=${_sec_asn1_source_file}
            -P collect_asn1c_sources.cmake
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} VERBATIM)

    add_custom_command(OUTPUT "${_sec_r2_asn1_dir}"
        DEPENDS ${_sec_r2_asn1_files} ${_pki_r2_asn1_files} ${_ieee_asn1_files}
        COMMAND ${CMAKE_COMMAND} -E make_directory ${_sec_r2_asn1_dir}
        COMMAND ${ASN1C_EXECUTABLE} ${_asn1c_flags} -fprefix=Vanetza_Security2_ -R -D ${_sec_r2_asn1_dir} ${_sec_r2_asn1_files} ${_pki_r2_asn1_files} ${_ieee_asn1_files}
        COMMAND ${CMAKE_COMMAND} -DASN1C_OUTPUT_DIR=security/r2 -DASN1C_PREFIX=Vanetza_Security2_
            -P ${CMAKE_CURRENT_SOURCE_DIR}/remove_prefix_from_filename.cmake
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMENT "Generating code from Security Release 2 (1609.2 and TS 103 097, TS 102 941) ASN.1 modules" VERBATIM)
    add_custom_command(OUTPUT "${_sec_r2_asn1_source_file}"
        DEPENDS ${_sec_r2_asn1_dir}
        COMMAND ${CMAKE_COMMAND} -DASN1C_OUTPUT_DIR=security/r2 -DASN1C_SOURCE_FILE=${_sec_r2_asn1_source_file}
            -P collect_asn1c_sources.cmake
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} VERBATIM)

    add_custom_target(generate_asn1c DEPENDS
        "${_support_asn1_dir}" "${_support_asn1_source_file}"
        "${_its_asn1_dir}" "${_its_asn1_source_file}"
        "${_its_r2_asn1_dir}" "${_its_r2_asn1_source_file}"
        "${_sec_asn1_dir}" "${_sec_asn1_source_file}"
        "${_sec_r2_asn1_dir}" "${_sec_r2_asn1_source_file}"
        VERBATIM)
    add_custom_command(TARGET generate_asn1c POST_BUILD
        COMMAND ${CMAKE_COMMAND} -DPROJECT_SOURCE_DIR=${PROJECT_SOURCE_DIR}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/patch_asn1c_skeleton.cmake
        COMMENT "Patching asn1c support files"
        WORKING_DIRECTORY ${_support_asn1_dir} VERBATIM)
    add_custom_command(TARGET generate_asn1c POST_BUILD
        COMMAND ${CMAKE_COMMAND} -DPROJECT_SOURCE_DIR=${PROJECT_SOURCE_DIR}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/patch_asn1c_generated.cmake
        COMMENT "Patching generated ITS application asn1c files"
        WORKING_DIRECTORY ${_its_asn1_dir} VERBATIM)
    add_custom_command(TARGET generate_asn1c POST_BUILD
        COMMAND ${CMAKE_COMMAND} -DPROJECT_SOURCE_DIR=${PROJECT_SOURCE_DIR} -DASN1C_PREFIX=Vanetza_ITS2_
            -P ${CMAKE_CURRENT_SOURCE_DIR}/patch_asn1c_generated.cmake
        COMMENT "Patching generated ITS Release 2 asn1c files"
        WORKING_DIRECTORY ${_its_r2_asn1_dir} VERBATIM)
    add_custom_command(TARGET generate_asn1c POST_BUILD
        COMMAND ${CMAKE_COMMAND} -DPROJECT_SOURCE_DIR=${PROJECT_SOURCE_DIR} -DASN1C_PREFIX=Vanetza_Security_
            -P ${CMAKE_CURRENT_SOURCE_DIR}/patch_asn1c_generated.cmake
        COMMENT "Patching generated security asn1c files"
        WORKING_DIRECTORY ${_sec_asn1_dir} VERBATIM)
    add_custom_command(TARGET generate_asn1c POST_BUILD
        COMMAND ${CMAKE_COMMAND} -DPROJECT_SOURCE_DIR=${PROJECT_SOURCE_DIR} -DASN1C_PREFIX=Vanetza_Security2_
            -P ${CMAKE_CURRENT_SOURCE_DIR}/patch_asn1c_generated.cmake
        COMMENT "Patching generated security release2 asn1c files"
        WORKING_DIRECTORY ${_sec_r2_asn1_dir} VERBATIM)
    add_custom_command(TARGET generate_asn1c POST_BUILD
        COMMAND ${CMAKE_COMMAND} -DPATCH_DIRECTORY=${CMAKE_CURRENT_SOURCE_DIR}/patches
            -P ${CMAKE_CURRENT_SOURCE_DIR}/apply_patches.cmake
        COMMENT "Applying hot-fixes to generated asn1c files"
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR} VERBATIM)
    if(VANETZA_ASN1_WITH_ISO)
        add_custom_command(TARGET generate_asn1c POST_BUILD
            COMMAND ${CMAKE_COMMAND} -DPATCH_DIRECTORY=${CMAKE_CURRENT_SOURCE_DIR}/patches/iso
                -P ${CMAKE_CURRENT_SOURCE_DIR}/apply_patches.cmake
                COMMENT "Applying hot-fixes to generated asn1c ITS ISO files"
            WORKING_DIRECTORY ${PROJECT_SOURCE_DIR} VERBATIM)
    endif()

    # wipe directory with generated files before generating
    add_custom_target(clean_asn1c
        COMMAND ${CMAKE_COMMAND}
          -DASN1C_OUTPUT_DIR=${_support_asn1_dir}
          -DASN1C_SOURCE_FILE=${_support_asn1_source_file}
          -P clean_asn1c.cmake
        COMMAND ${CMAKE_COMMAND}
          -DASN1C_OUTPUT_DIR=${_its_asn1_dir}
          -DASN1C_SOURCE_FILE=${_its_asn1_source_file}
          -P clean_asn1c.cmake
        COMMAND ${CMAKE_COMMAND}
          -DASN1C_OUTPUT_DIR=${_its_r2_asn1_dir}
          -DASN1C_SOURCE_FILE=${_its_r2_asn1_source_file}
          -P clean_asn1c.cmake
        COMMAND ${CMAKE_COMMAND}
          -DASN1C_OUTPUT_DIR=${_sec_asn1_dir}
          -DASN1C_SOURCE_FILE=${_sec_asn1_source_file}
          -P clean_asn1c.cmake
        COMMAND ${CMAKE_COMMAND}
          -DASN1C_OUTPUT_DIR=${_sec_r2_asn1_dir}
          -DASN1C_SOURCE_FILE=${_sec_r2_asn1_source_file}
          -P clean_asn1c.cmake
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} VERBATIM)
    add_dependencies(generate_asn1c clean_asn1c)
endif()

function(add_asn1_component NAME)
    string(REPLACE "/" "_" NAME_ESCAPED "${NAME}")
    set(_source_file "asn1c_${NAME_ESCAPED}_sources.txt")
    file(STRINGS "${_source_file}" _sources REGEX "^[^#]+")
    if (NOT _sources)
        message(AUTHOR_WARNING "source file ${_source_file} is empty, fix this now!")
        file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/asn1_${NAME}_no_sources.c
            "#error \"generated ${NAME} ASN.1 source files are missing\"")
        set(_sources ${CMAKE_CURRENT_BINARY_DIR}/asn1_${NAME}_no_sources.c)
    endif()
    add_vanetza_component(asn1_${NAME_ESCAPED} ${_sources})
    set_target_properties(asn1_${NAME_ESCAPED} PROPERTIES C_STANDARD 11)

    if ("${NAME}" STREQUAL "support")
        target_include_directories(asn1_support PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/support>
            $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/vanetza/asn1/support>)
        if(UNIX)
            target_compile_definitions(asn1_support PUBLIC HAVE_NETINET_IN_H)
        endif()
    else()
        target_link_libraries(asn1_${NAME_ESCAPED} PUBLIC asn1_support)
    endif()

    # Silence warnings in code generated by asn1c
    if (CMAKE_C_COMPILER_ID STREQUAL "Clang")
        set_property(SOURCE ${_sources} APPEND PROPERTY COMPILE_OPTIONS "-Wno-parentheses-equality")
    endif()

    if(VANETZA_INSTALL)
        install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/${NAME}
            DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/vanetza/asn1
            FILES_MATCHING PATTERN "*.h")
    endif()
endfunction()

add_asn1_component(support)
target_sources(asn1_support PRIVATE memory.c)
add_asn1_component(its)
add_asn1_component(its/r2)
add_asn1_component(security)
add_asn1_component(security/r2)

add_vanetza_component(asn1 asn1c_wrapper.cpp)
target_link_libraries(asn1 PUBLIC asn1_its Boost::boost)

add_test_subdirectory(tests)
