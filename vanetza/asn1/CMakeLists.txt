set(_its_asn1_source_file "asn1c_its_sources.txt")
set(_its_r2_asn1_source_file "asn1c_its_r2_sources.txt")
set(_sec_asn1_source_file "asn1c_security_sources.txt")
set(_sec_r2_asn1_source_file "asn1c_security_r2_sources.txt")
set(_support_asn1_source_file "asn1c_support_sources.txt")

set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
    ${_its_asn1_source_file}
    ${_its_r2_asn1_source_file}
    ${_sec_asn1_source_file}
    ${_sec_r2_asn1_source_file}
    ${_support_asn1_source_file})

set(_its_asn1_dir "${CMAKE_CURRENT_SOURCE_DIR}/its")
set(_its_r2_asn1_dir "${CMAKE_CURRENT_SOURCE_DIR}/its/r2")
set(_sec_asn1_dir "${CMAKE_CURRENT_SOURCE_DIR}/security")
set(_sec_r2_asn1_dir "${CMAKE_CURRENT_SOURCE_DIR}/security/r2")
set(_support_asn1_dir "${CMAKE_CURRENT_SOURCE_DIR}/support")

option(VANETZA_ASN1_WITH_ASN1C "Enable asn1c targets" OFF)
if(VANETZA_ASN1_WITH_ASN1C)
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
        ${PROJECT_SOURCE_DIR}/asn1/release2/TS102894-2v241-CDD.asn
        ${PROJECT_SOURCE_DIR}/asn1/release2/TS103831v231-DENM.asn
        ${PROJECT_SOURCE_DIR}/asn1/release2/TS103900v231-CAM.asn
        ${PROJECT_SOURCE_DIR}/asn1/release2/TS103324v211/CPM-OriginatingStationContainers.asn
        ${PROJECT_SOURCE_DIR}/asn1/release2/TS103324v211/CPM-PDU-Descriptions.asn
        ${PROJECT_SOURCE_DIR}/asn1/release2/TS103324v211/CPM-PerceivedObjectContainer.asn
        ${PROJECT_SOURCE_DIR}/asn1/release2/TS103324v211/CPM-PerceptionRegionContainer.asn
        ${PROJECT_SOURCE_DIR}/asn1/release2/TS103324v211/CPM-SensorInformationContainer.asn
        ${PROJECT_SOURCE_DIR}/asn1/release2/TS103300-3v231/VAM-PDU-Descriptions.asn
        ${PROJECT_SOURCE_DIR}/asn1/release2/TS103300-3v231/motorcyclist-special-container.asn
        ${PROJECT_SOURCE_DIR}/asn1/release2/TS103916v211/POIM-PDU-Description.asn
        ${PROJECT_SOURCE_DIR}/asn1/release2/TS103916v211/POIM-ParkingAvailability.asn
        ${PROJECT_SOURCE_DIR}/asn1/release2/TS103916v211/POIM-CommonContainers.asn
    )

    option(VANETZA_ASN1_WITH_ISO "Fetch ISO ASN.1 files for a more complete ITS message set" OFF)
    if(VANETZA_ASN1_WITH_ISO)
        set(_iso_asn1_files
            ISO14816.asn ISO19091.asn ISO24534-3.asn ISO19321.asn
            ISO14906-0-6.asn ISO14906-1-7.asn ISO17419.asn ISO14823.asn)
        list(TRANSFORM _iso_asn1_files PREPEND ${CMAKE_CURRENT_BINARY_DIR}/iso/)
        add_custom_command(OUTPUT ${_iso_asn1_files}
            COMMAND ${CMAKE_COMMAND} -DDIRECTORY=${CMAKE_CURRENT_BINARY_DIR}/iso -P fetch_iso_asn1_files.cmake
            COMMENT "Fetch and patch ISO ASN.1 files"
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
            VERBATIM)
        list(APPEND _its_asn1_files ${_its_asn1_files_depending_on_iso} ${_iso_asn1_files})
    endif()

    set(_ieee_1609dot2_asn1_files
        Ieee1609Dot2.asn Ieee1609Dot2BaseTypes.asn Ieee1609Dot2Crl.asn Ieee1609Dot2CrlBaseTypes.asn)
    set(_ieee_1609dot2dot1_asn1_files
        Ieee1609Dot2Dot1AcaEeInterface.asn Ieee1609Dot2Dot1AcaLaInterface.asn Ieee1609Dot2Dot1AcaMaInterface.asn
        Ieee1609Dot2Dot1AcaRaInterface.asn Ieee1609Dot2Dot1Acpc.asn Ieee1609Dot2Dot1CamRaInterface.asn
        Ieee1609Dot2Dot1CertManagement.asn Ieee1609Dot2Dot1EcaEeInterface.asn Ieee1609Dot2Dot1EeMaInterface.asn
        Ieee1609Dot2Dot1EeRaInterface.asn Ieee1609Dot2Dot1LaMaInterface.asn Ieee1609Dot2Dot1LaRaInterface.asn
        Ieee1609Dot2Dot1MaRaInterface.asn Ieee1609Dot2Dot1Protocol.asn)
    list(TRANSFORM _ieee_1609dot2_asn1_files PREPEND ${CMAKE_CURRENT_BINARY_DIR}/ieee/)
    list(TRANSFORM _ieee_1609dot2dot1_asn1_files PREPEND ${CMAKE_CURRENT_BINARY_DIR}/ieee/)

    set(_ieee_asn1_files ${_ieee_1609dot2_asn1_files} ${_ieee_1609dot2dot1_asn1_files})
    add_custom_command(OUTPUT ${_ieee_asn1_files}
        COMMAND ${CMAKE_COMMAND} -DDIRECTORY=${CMAKE_CURRENT_BINARY_DIR}/ieee -P fetch_ieee_asn1_files.cmake
        COMMENT "Fetch and patch IEEE 1609 ASN.1 files"
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

    # map host user to container for file permission consistency
    execute_process(COMMAND id -u OUTPUT_VARIABLE USER_ID OUTPUT_STRIP_TRAILING_WHITESPACE)
    execute_process(COMMAND id -g OUTPUT_VARIABLE GROUP_ID OUTPUT_STRIP_TRAILING_WHITESPACE)

    set(VANETZA_ASN1C_CONTAINER_IMAGE "vanetza-asn1c:latest" CACHE STRING "Docker image for asn1c code generation")

    macro(generate_asn1c)
        cmake_parse_arguments(gen_asn1c "" "DESCRIPTION;OUTPUT_DIRECTORY;PREFIX;SOURCE_FILE" "SOURCES" ${ARGN})
        
        if(NOT gen_asn1c_OUTPUT_DIRECTORY)
            message(FATAL_ERROR "Missing output directory for generated ASN.1 code (OUTPUT_DIRECTORY)")
        endif()
        if(NOT gen_asn1c_SOURCES)
            message(FATAL_ERROR "Missing ASN.1 source files to generate code from (SOURCES)")
        endif()

        set(_asn1c_source_filenames "")
        set(_asn1c_source_binds "")
        foreach(_file IN LISTS gen_asn1c_SOURCES)
            get_filename_component(_filename ${_file} NAME)
            list(APPEND _asn1c_source_filenames ${_filename})
            file(REAL_PATH ${_file} _abs_file BASE_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
            list(APPEND _asn1c_source_binds --mount type=bind,src=${_abs_file},dst=/workdir/${_filename},ro)
        endforeach()

        set(_asn1c_exec docker run --rm -it
            -v ${gen_asn1c_OUTPUT_DIRECTORY}:/out ${_asn1c_source_binds} -w /workdir
            -u ${USER_ID}:${GROUP_ID}
            ${VANETZA_ASN1C_CONTAINER_IMAGE}
            asn1c)
        set(_asn1c_flags -fcompound-names -fincludes-quoted -no-gen-example)
        if(gen_asn1c_PREFIX)
            list(APPEND _asn1c_flags -fprefix=${gen_asn1c_PREFIX})
        endif()

        if(NOT gen_asn1c_DESCRIPTION)
            set(_comment "Generating code from ASN.1 modules in ${gen_asn1c_OUTPUT_DIRECTORY}")
        else()
            set(_comment "Generating code from ${gen_asn1c_DESCRIPTION} ASN.1 modules")
        endif()

        add_custom_command(OUTPUT "${gen_asn1c_OUTPUT_DIRECTORY}"
            DEPENDS "${gen_asn1c_SOURCES}"
            COMMAND ${CMAKE_COMMAND} -E make_directory "${gen_asn1c_OUTPUT_DIRECTORY}"
            COMMAND ${_asn1c_exec} ${_asn1c_flags} -R -D /out ${_asn1c_source_filenames}
            COMMAND ${CMAKE_COMMAND}
                -DASN1C_OUTPUT_DIR=${gen_asn1c_OUTPUT_DIRECTORY}
                -DASN1C_PREFIX=${gen_asn1c_PREFIX}
                -P remove_prefix_from_filename.cmake
            COMMENT "${_comment}"
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
            VERBATIM)
        
        if(gen_asn1c_SOURCE_FILE)
            add_custom_command(OUTPUT "${gen_asn1c_SOURCE_FILE}"
                DEPENDS "${gen_asn1c_OUTPUT_DIRECTORY}"
                COMMAND ${CMAKE_COMMAND}
                    -DASN1C_OUTPUT_DIR=${gen_asn1c_OUTPUT_DIRECTORY}
                    -DASN1C_SOURCE_FILE=${gen_asn1c_SOURCE_FILE}
                    -P collect_asn1c_sources.cmake
                COMMENT "Collecting generated sources in ${gen_asn1c_SOURCE_FILE}"
                WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
                VERBATIM)
        endif()
    endmacro()

    add_custom_command(OUTPUT ${_support_asn1_dir}
        COMMAND ${CMAKE_COMMAND} -E rm -rf ${CMAKE_CURRENT_BINARY_DIR}/asn1c_skeleton
        COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_BINARY_DIR}/asn1c_skeleton
        COMMAND docker run --rm -it
            -v ${CMAKE_CURRENT_BINARY_DIR}/asn1c_skeleton:/dest
            -u ${USER_ID}:${GROUP_ID}
            ${VANETZA_ASN1C_CONTAINER_IMAGE}
            bash -c "cp -a /usr/share/asn1c/* /dest/"
        COMMAND ${CMAKE_COMMAND} -E make_directory "${_support_asn1_dir}"
        COMMAND ${CMAKE_COMMAND}
            -DSOURCE=${CMAKE_CURRENT_BINARY_DIR}/asn1c_skeleton
            -DDESTINATION=${_support_asn1_dir}
            -P copy_asn1c_skeleton.cmake
        COMMAND ${CMAKE_COMMAND}
            -DASN1C_OUTPUT_DIR=support
            -DASN1C_SOURCE_FILE=${_support_asn1_source_file}
            -P collect_asn1c_sources.cmake
        COMMENT "Copying generic asn1c support code"
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        VERBATIM)

    generate_asn1c(DESCRIPTION "ITS applications Release 1 (CDD, CA, DEN)"
        OUTPUT_DIRECTORY ${_its_asn1_dir}
        SOURCE_FILE ${_its_asn1_source_file}
        SOURCES ${_its_asn1_files} test.asn)

    generate_asn1c(DESCRIPTION "ITS applications Release 2 (CDD, CA, DEN)"
        OUTPUT_DIRECTORY ${_its_r2_asn1_dir}
        SOURCE_FILE ${_its_r2_asn1_source_file}
        PREFIX Vanetza_ITS2_
        SOURCES ${_its_r2_asn1_files})

    generate_asn1c(DESCRIPTION "Security (Release 1)"
        OUTPUT_DIRECTORY ${_sec_asn1_dir}
        SOURCE_FILE ${_sec_asn1_source_file}
        PREFIX Vanetza_Security_
        SOURCES ${_sec_asn1_files} ${_pki_asn1_files})

    generate_asn1c(DESCRIPTION "Security (Release 2)"
        OUTPUT_DIRECTORY ${_sec_r2_asn1_dir}
        SOURCE_FILE ${_sec_r2_asn1_source_file}
        PREFIX Vanetza_Security2_
        SOURCES ${_sec_r2_asn1_files} ${_pki_r2_asn1_files} ${_ieee_asn1_files})

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
        COMMENT "Patching generated Security asn1c files"
        WORKING_DIRECTORY ${_sec_asn1_dir} VERBATIM)
    add_custom_command(TARGET generate_asn1c POST_BUILD
        COMMAND ${CMAKE_COMMAND} -DPROJECT_SOURCE_DIR=${PROJECT_SOURCE_DIR} -DASN1C_PREFIX=Vanetza_Security2_
            -P ${CMAKE_CURRENT_SOURCE_DIR}/patch_asn1c_generated.cmake
        COMMENT "Patching generated Security Release 2 asn1c files"
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
